#pragma once

// Threat-intel hash lookups. Optional and opt-in: every consumer must
// pass an enabled IntelLookupConfig, and missing API keys produce a clean
// "skipped" result rather than a failure.
//
// Results are cached on disk under workspaceRoot/_intel_cache/<sha256>.json
// so repeat scans don't hammer remote APIs and we stay within free-tier
// quotas (VirusTotal: 500 lookups/day).

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antimal {

enum class IntelSource {
  MalwareBazaar,        // abuse.ch — free, no key required
  VirusTotal,           // virustotal.com — free key, 500/day
};

struct IntelHit {
  IntelSource source = IntelSource::MalwareBazaar;
  std::string sourceName;     // "malwarebazaar" | "virustotal"
  bool known = false;         // true when the hash was recognized by source
  std::string family;         // best-effort family attribution
  std::vector<std::string> tags; // free-form tags from the source
  int detectionRatio = 0;     // VT: positives. MB: 0/1 known indicator.
  int totalScanners = 0;      // VT only.
  std::string firstSeen;      // ISO date when source first saw it
  std::string lastSeen;
  std::string rawJson;        // unparsed source response for archive
  std::string permalink;      // human-clickable URL
  std::string error;          // populated on lookup failure
};

struct IntelLookupConfig {
  bool enabled = false;                  // master switch
  std::string virusTotalApiKey;          // empty disables VT
  bool malwareBazaarEnabled = true;
  std::filesystem::path cacheDir;        // empty = no caching
  std::chrono::seconds maxAgeForCache{60 * 60 * 24}; // 24h freshness
  std::chrono::milliseconds requestTimeout{15000};
};

struct IntelLookupResult {
  bool enabled = false;
  bool fromCache = false;
  std::vector<IntelHit> hits;
};

// Performs all configured lookups for the given SHA-256. Returns immediately
// with enabled=false if config.enabled is false.
IntelLookupResult LookupHash(const std::string &sha256Hex,
                             const IntelLookupConfig &config);

// Exposed for tests + diagnostics — parses the JSON-ish response from a
// given source into an IntelHit without performing a network call.
IntelHit ParseMalwareBazaarResponse(const std::string &json);
IntelHit ParseVirusTotalResponse(const std::string &json);

} // namespace antimal
