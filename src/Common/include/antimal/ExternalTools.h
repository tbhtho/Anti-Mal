#pragma once

// External analysis-tool integrations. Each tool is invoked as a redistributable
// binary (yara.exe, capa.exe, diec.exe) via the Subprocess helper. AntiMal does
// not pull these as build-time libraries — they're optional and skip-gracefully
// when absent, the same way TestWhpHelloPartition skips when WHP is disabled.
//
// Drop the binaries next to the AntiMal executable or in `tools\` under it
// (the App vcxproj already copies tools\ to the output dir). tools\
// installation precedence is documented in the private development documentation

#include <filesystem>
#include <string>
#include <vector>

namespace antimal {

// ----- YARA -------------------------------------------------------------

struct YaraMatch {
  std::string ruleName;            // "Win.Trojan.Emotet"
  std::string ruleNamespace;       // "" if default
  std::vector<std::string> tags;   // ["banker", "trojan"]
  std::vector<std::string> meta;   // free-form ["author=Foo", "family=Emotet"]
};

struct YaraScanResult {
  bool available = false;          // Set false when yara.exe is missing.
  bool succeeded = false;          // Set true even when 0 matches (clean scan).
  std::string failureReason;       // Populated when available && !succeeded.
  std::vector<YaraMatch> matches;
};

// Runs yara.exe against `samplePath` using rules from `rulesDir` (recursively
// loading every *.yar/*.yara). Returns a result describing matches. When
// yara.exe is not installed, available == false (not an error).
YaraScanResult RunYara(const std::filesystem::path &samplePath,
                       const std::filesystem::path &rulesDir);

// Parses yara.exe's `-g -m` line output into matches. Exposed for offline
// fixture tests; input is length-capped before any regex runs so a hostile or
// runaway tool cannot OOM/ReDoS the host. Tolerant of malformed lines.
std::vector<YaraMatch> ParseYaraOutput(const std::string &output);

// ----- capa -------------------------------------------------------------

struct CapaCapability {
  std::string name;                       // capability name from capa
  std::vector<std::string> mitreTechniques; // ["T1055.012"]
  std::vector<std::string> mitreTactics;    // ["TA0005"]
  std::vector<std::string> mbcBehaviors;    // Malware Behavior Catalog
  std::string ruleNamespace;              // capa rule namespace
};

struct CapaScanResult {
  bool available = false;
  bool succeeded = false;
  std::string failureReason;
  std::vector<CapaCapability> capabilities;
};

CapaScanResult RunCapa(const std::filesystem::path &samplePath);

// Parses capa's `-j` JSON into capabilities. Exposed for offline fixture tests;
// input is length-capped before any regex runs. Tolerant of malformed JSON.
std::vector<CapaCapability> ParseCapaJson(const std::string &json);

// ----- Detect It Easy ---------------------------------------------------

struct DieDetection {
  std::string type;        // "packer", "protector", "compiler", "linker", "library"
  std::string name;        // "UPX", ".NET Reactor", "Microsoft Visual C++"
  std::string version;     // free-form
  std::string options;     // free-form
};

struct DieScanResult {
  bool available = false;
  bool succeeded = false;
  std::string failureReason;
  std::vector<DieDetection> detections;
};

DieScanResult RunDie(const std::filesystem::path &samplePath);

// Parses diec.exe's `-j` JSON into detections. Exposed for offline fixture
// tests; input is length-capped before any regex runs. Tolerant of malformed JSON.
std::vector<DieDetection> ParseDieJson(const std::string &json);

} // namespace antimal
