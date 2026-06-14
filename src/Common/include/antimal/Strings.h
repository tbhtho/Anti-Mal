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

// A C2/config URL recovered from single-byte-XOR obfuscation (the most common
// malware string-hiding scheme). The plaintext string miner above misses these
// because the bytes aren't printable until XORed back.
struct ObfuscatedIoc {
  std::string value;  // the decoded http(s):// URL
  uint8_t xorKey = 0; // the single-byte XOR key (always non-zero)
};

// Recovers single-byte-XOR-obfuscated http(s) URLs from raw bytes in ONE O(n)
// pass: at each offset, tests whether 4 bytes spell "http" under a consistent
// single-byte key, then decodes forward and requires a valid "://" scheme. The
// "http://"-under-XOR pattern is ~7 specific bytes, so a chance match in random
// data is astronomically unlikely -> a hit is almost certainly real obfuscated
// config. Deduplicated + capped; key 0 (plaintext) is skipped.
std::vector<ObfuscatedIoc>
MineXorObfuscatedUrls(const std::vector<uint8_t> &data);

// A C2/config URL recovered from MULTI-byte (repeating-key) XOR -- the common
// step up from single-byte XOR that the function above misses. Uses the same
// known-plaintext "http" anchor: the 4 known prefix bytes fully reveal every
// byte of a length<=4 repeating key (each prefix char exposes key[(i+m) % L]),
// then the run is decoded under that key and scheme-validated. Degenerate keys
// (all-equal == single-byte, already covered above) are skipped so a URL is
// never double-reported.
struct MultiByteXorIoc {
  std::string value;        // the decoded http(s):// URL
  std::vector<uint8_t> key; // the 2..4 byte repeating XOR key (absolute phase)
};

std::vector<MultiByteXorIoc>
MineMultiByteXorObfuscatedUrls(const std::vector<uint8_t> &data);

// ExtractDomain (URL -> host) lives in BrowserImpact.h and is reused here.

} // namespace antimal
