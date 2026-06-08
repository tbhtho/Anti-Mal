#pragma once

#include "antimal/Types.h"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

// Knobs for the enrichment pipeline. Defaults give cheap-and-offline
// behavior (strings/IOC mining + builtin tags) — every external-tool and
// network feature is opt-in.
struct ScannerOptions {
  bool mineIocs = true;
  bool runYara = true;
  std::filesystem::path yaraRulesDir;   // empty → "rules/yara" near exe
  bool runCapa = true;
  bool runDie = true;
  bool applyTagger = true;
  std::filesystem::path tagsRulesPath;  // empty → "rules/tags.json" near exe, else builtin
  bool intelLookupEnabled = false;      // master switch (network access)
  std::string virusTotalApiKey;         // empty → VT skipped
  bool malwareBazaarEnabled = true;     // free, no key
  std::filesystem::path intelCacheDir;  // empty → workspaceRoot/_intel_cache when set elsewhere
  std::chrono::milliseconds intelTimeout{15000};
};

double CalculateEntropy(const std::vector<uint8_t> &data);

// Magic-byte file-type identification, independent of the file extension. Returns
// a short lowercase label ("pe", "elf", "macho", "pdf", "zip", "ole", "rtf",
// "elf", "script", "lnk", ...) or "" when nothing matches. Used to flag
// extension/content masquerading (e.g. invoice.pdf that is really a PE).
std::string IdentifyFileType(const std::vector<uint8_t> &data);

// Counts PE images embedded at a NON-zero offset (an "MZ" whose e_lfanew points
// at a valid "PE\0\0"). The host file's own header at offset 0 is excluded, so a
// non-zero count means the file carries one or more additional executables --
// the defining trait of a dropper/installer payload. Capped to a sane maximum.
int CountEmbeddedExecutables(const std::vector<uint8_t> &data);

// Maps the import table to coarse behavioral capabilities (anti-debug,
// keylogging, screen capture, clipboard, crypto, process discovery, privilege
// adjustment, runtime API resolution, service control). Pure over the import
// name list (entries shaped "dll!func"), returns one finding per capability
// present. The Any.Run-style "what can this do" row, derived statically.
std::vector<ScanFinding>
DetectImportCapabilities(const std::vector<std::string> &imports);

ScanResult ScanFile(const std::filesystem::path &path);
ScanResult ScanFile(const std::filesystem::path &path,
                    const ScannerOptions &options);

std::vector<ScanResult> ScanPath(const std::filesystem::path &path);
std::vector<ScanResult> ScanPath(const std::filesystem::path &path,
                                 const ScannerOptions &options);

std::string FormatScanText(const ScanResult &result);

} // namespace antimal
