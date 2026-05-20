#pragma once

// Rule-based tagger that turns the collected static signals (imports,
// scanner findings, IOCs, YARA matches, capa capabilities, DIE detections)
// into top-level tags like "stealer", "loader", "ransomware", "packed",
// "dotnet", "netreactor" — the equivalent of Any.Run's tracker badges.
//
// Rules are declarative and loaded from a JSON file at runtime (see
// `rules/tags.json` shipped in the repo). Each rule lists a tag name and
// a set of substring needles to search in different categories of
// evidence. Multiple matches across categories raise confidence.

#include "antimal/ExternalTools.h"
#include "antimal/Strings.h"
#include "antimal/Types.h"

#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

struct TagResult {
  std::string tag;             // e.g. "stealer", "loader"
  std::string category;        // "family" | "capability" | "packer" | "language"
  int confidence = 0;          // 0..100; sum of triggered rule weights
  std::vector<std::string> reasons; // human-readable explanations
};

struct TagInputs {
  const ScanResult *scan = nullptr;
  const ExtractedIocs *iocs = nullptr;
  const YaraScanResult *yara = nullptr;
  const CapaScanResult *capa = nullptr;
  const DieScanResult *die = nullptr;
};

class Tagger {
public:
  // Load rules from `rulesPath`. Returns false (and stores reason) when
  // the file is missing or malformed. A Tagger with no rules still
  // functions but always returns empty results.
  bool LoadRulesFromFile(const std::filesystem::path &rulesPath);

  // Load a built-in default rule set covering the common malware-family
  // and capability tags. Used as a fallback when no rules file is present.
  void LoadBuiltinRules();

  // Evaluate the rules against the provided evidence and return all tags
  // that triggered (sorted by descending confidence). Tags with confidence
  // below `minConfidence` are filtered out.
  std::vector<TagResult> Evaluate(const TagInputs &inputs,
                                  int minConfidence = 10) const;

  const std::string &LastError() const noexcept { return lastError_; }

private:
  struct Rule {
    std::string tag;
    std::string category;
    int weight = 0;
    std::vector<std::string> importNeedles;
    std::vector<std::string> findingRuleIds;
    std::vector<std::string> stringNeedles;       // matched against IOCs + paths + domains
    std::vector<std::string> yaraRuleNeedles;     // substring in yara rule name/tags
    std::vector<std::string> capaTechniqueNeedles; // substring in capa technique strings
    std::vector<std::string> dieNeedles;          // substring in DIE detection name
  };

  std::vector<Rule> rules_;
  std::string lastError_;
};

} // namespace antimal
