#pragma once

#include <string>
#include <vector>

#include "antimal/Types.h"

namespace antimal {

// Result of the explainable behavioral scorer. `score` is the summed weight of
// every signal that fired; `verdict` is that score mapped through thresholds;
// `rationale` is the human-readable "why" -- one line per contributing signal,
// in the order they were evaluated. The rationale is the headline feature: an
// analyst should be able to read it and reconstruct exactly why the verdict is
// what it is, with no access to the raw event stream.
struct BehaviorScore {
  int score = 0;
  Verdict verdict = Verdict::Unknown;
  std::vector<std::string> rationale;
};

// Score a completed detonation purely from what the guest was observed to do.
//
// Pure + deterministic: no I/O, no globals, no clock reads -- it is a function
// of (summary, events) only, which is why it lives here rather than buried in
// the 11k-line orchestrator, and why it is directly unit-testable.
//
// Contract:
//   * If the sample never executed (gated run / healthcheck / no telemetry),
//     the verdict is Unknown -- there is nothing to judge.
//   * It NEVER returns Verdict::Error. Error is reserved for an actual run
//     failure (VM crash, boot failure) and is set by the caller, not here.
//   * Hitting the time budget is, by itself, NOT a malicious signal. A benign
//     sample that idled until timeout scores Clean, and the rationale says so
//     explicitly -- this kills the classic "ran to timeout => Malicious" FP.
//   * The verdict is driven by observed behavior (persistence, drops, egress,
//     privilege escalation, suspicious command lines, crashes), each of which
//     adds weight AND a rationale line.
BehaviorScore ScoreSandboxBehavior(const DynamicRunSummary &summary,
                                   const std::vector<EventRecord> &events);

} // namespace antimal
