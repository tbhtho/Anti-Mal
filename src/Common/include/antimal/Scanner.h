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

ScanResult ScanFile(const std::filesystem::path &path);
ScanResult ScanFile(const std::filesystem::path &path,
                    const ScannerOptions &options);

std::vector<ScanResult> ScanPath(const std::filesystem::path &path);
std::vector<ScanResult> ScanPath(const std::filesystem::path &path,
                                 const ScannerOptions &options);

std::string FormatScanText(const ScanResult &result);

} // namespace antimal
