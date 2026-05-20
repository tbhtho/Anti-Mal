#pragma once

// Strings + IOC extraction. Pulls human-readable strings (ASCII + UTF-16LE)
// out of arbitrary byte buffers, then mines those strings for indicators
// of compromise: URLs, IPs, domains, registry paths, file paths, possible
// mutex names, and base64-looking blobs.
//
// This is intentionally the cheapest analyzer in the pipeline. It runs on
// every scan without external dependencies and feeds the report's IOC
// side-rail.

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct ExtractedIocs {
  std::vector<std::string> urls;          // http://, https://, ftp://, file:// schemes
  std::vector<std::string> ips;           // IPv4 dotted-quad
  std::vector<std::string> domains;       // looks like *.tld with sane charset
  std::vector<std::string> registryPaths; // HKLM\..., HKCU\..., etc.
  std::vector<std::string> filePaths;     // C:\..., %APPDATA%\..., \\server\share
  std::vector<std::string> mutexHints;    // CreateMutex- / Global\ / Local\ patterns
  std::vector<std::string> base64Blobs;   // >= 48-char runs of base64 charset
  std::vector<std::string> suspiciousApis; // names appearing in strings that suggest malicious capability
};

// Returns ASCII strings of at least `minLength` bytes from `data`. Stops a
// string at the first non-printable byte (anything outside 0x20..0x7E).
std::vector<std::string> ExtractAsciiStrings(const std::vector<uint8_t> &data,
                                             size_t minLength = 6);

// Returns UTF-16LE strings of at least `minLength` *code units* converted
// to UTF-8 for downstream consumers. Same printable-only stop rule.
std::vector<std::string> ExtractUtf16Strings(const std::vector<uint8_t> &data,
                                             size_t minLength = 6);

// Runs both extractors and dedupes the results.
std::vector<std::string> ExtractAllStrings(const std::vector<uint8_t> &data,
                                           size_t minLength = 6);

// Scans `strings` and produces a deduplicated, length-capped IOC set.
ExtractedIocs MineIocs(const std::vector<std::string> &strings);

// Convenience wrapper: ExtractAllStrings + MineIocs in one call.
ExtractedIocs MineIocsFromBytes(const std::vector<uint8_t> &data);

// ExtractDomain (URL -> host) lives in BrowserImpact.h and is reused here.

} // namespace antimal
