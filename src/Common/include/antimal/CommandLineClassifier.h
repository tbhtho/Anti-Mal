#pragma once

#include <string>

namespace antimal {

// Flag a process command line as a known living-off-the-land / abuse pattern, the
// way Any.Run highlights suspicious command lines in its process tree. Display +
// detection-summary use only (the behavioral VERDICT has its own scoring in
// BehaviorScore; this is intentionally separate so enriching the report can never
// move a verdict). Returns the single strongest match.
struct CommandLineThreat {
  bool suspicious = false;
  std::string technique; // ATT&CK id, e.g. "T1059.001"
  std::string reason;    // short human label, e.g. "encoded PowerShell"
};

CommandLineThreat ClassifyCommandLine(const std::string &commandLine);

} // namespace antimal
