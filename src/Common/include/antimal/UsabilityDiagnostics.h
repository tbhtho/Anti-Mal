#pragma once

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

// One desktop-usability dimension and whether a run actually exercised it.
// status: "ok" | "degraded" | "crash-loop" | "not-observed".
struct UsabilityDimension {
  std::string name;
  std::string status;
  std::string detail;
};

// A measured read of how usable the guest desktop was on a run — the analyst
// answer to "did display / input / disk / process-exec / browser / the Windows
// shell actually work?". Critically it detects the known Win11 modern-shell
// (explorer/ShellHost) crash-loop from process.crash telemetry and reports the
// working cmd-shell sidestep, turning the project's hardest wall into a precise,
// surfaced, actionable diagnostic instead of a silent failure.
struct UsabilityReport {
  std::vector<UsabilityDimension> dimensions;
  std::string overall;     // "usable" | "limited" | "shell-degraded" | "no-boot"
  std::string remediation; // actionable next step ("" when fully usable)
  bool shellCrashLoop = false;
};

// Pure: classify desktop usability from a run summary + its events. Never throws.
UsabilityReport ClassifyUsability(const DynamicRunSummary &summary,
                                  const std::vector<EventRecord> &events);

} // namespace antimal
