#pragma once

#include <string>

namespace antimal {

// Identify a persistence mechanism from a raw telemetry target (a registry key
// path, optionally "KEY = value", or a dropped-file path) WITHOUT relying on the
// in-guest agent to have pre-labeled it. The agent currently tags only a handful
// of Run/Winlogon keys; this recovers the broader autostart surface — services,
// IFEO debuggers, scheduled tasks, COM hijacks, AppInit_DLLs, the Startup folder
// — so the report's persistence panel names the technique even on unlabeled
// telemetry. Conservative (well-known locations only) to keep false positives low.
struct PersistenceMatch {
  bool matched = false;
  std::string mechanism; // human name, e.g. "Registry Run Key"
  std::string mitre;     // ATT&CK technique id, e.g. "T1547.001"
};

// category is the EventRecord category ("registry" | "file" | ...). target is
// the key/value or file path. Returns matched=false when not a known mechanism.
PersistenceMatch ClassifyPersistence(const std::string &category,
                                     const std::string &target);

} // namespace antimal
