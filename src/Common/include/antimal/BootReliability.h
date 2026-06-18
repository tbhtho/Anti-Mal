#pragma once

// Boot-reliability aggregation across a workspace of detonation runs.
//
// Scans every run directory under a workspace root and rolls each up via the
// boot-outcome classifier into a reliability picture: how many runs reached the
// desktop / user-mode, the per-stage + per-category histograms, and the
// distribution of remediation hints. Attempted-but-incomplete runs (a job.json
// with no finalized report.json) are NOT dropped -- they'd inflate the numbers;
// instead their reach is recovered from the live events.jsonl (GuestAgent
// telemetry = OS-up / user-mode). Lives in Common so the CLI (`boot-report`) and
// the GUI share one tested implementation. Pure of UI; does its own file I/O.

#include <filesystem>
#include <map>
#include <string>

namespace antimal {

struct BootReliability {
  int runs = 0;            // total attempted runs counted
  int reachedDesktop = 0;  // confirmed a desktop frame
  int reachedUserMode = 0; // reached user-mode (incl. telemetry-recovered)
  int incomplete = 0;      // had a job.json but no finalized report.json
  std::map<std::string, int> byStage;       // furthest stage -> count
  std::map<std::string, int> byCategory;    // outcome category -> count
  std::map<std::string, int> byRemediation; // remediation hint -> count
};

// Aggregate boot reliability over the run dirs directly under `workspaceRoot`.
// Skips `_`-prefixed dirs (_base, _intel_cache, ...). Never throws -- a missing
// workspace yields an all-zero result.
BootReliability AggregateBootReliability(const std::filesystem::path &workspaceRoot);

} // namespace antimal
