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

  // --- Evidence-quality bookkeeping (see the sufficiency contract below). ---
  // True when the verdict had to be WITHHELD because the observation was too
  // thin to judge (interrupted run / no completion signal / telemetry channel
  // never confirmed). When this is set the verdict is Unknown and the rationale
  // says exactly what was missing -- "we did not see" is never reported as
  // "nothing happened".
  bool insufficientEvidence = false;
  // Explicit observation limits that applied to this run, whether or not a
  // verdict was reached ("run ended without a completion signal", "guest
  // telemetry channel unconfirmed", ...). Carried into the report so the UI can
  // label a Clean/Suspicious/Malicious headline as partial-coverage when it is.
  std::vector<std::string> limitations;
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
//     sample that idled to its time budget scores Clean, and the rationale says
//     so explicitly -- this kills the classic "ran to timeout => Malicious" FP.
//   * Evidence sufficiency gate (2026-09 review F1): a reassuring negative
//     (Clean) requires a run that reached a declared end state AND a confirmed
//     guest telemetry channel AND behavioral telemetry beyond the sample launch.
//     When any of those is missing and no positive behavior was observed the
//     verdict is WITHHELD (Unknown + insufficientEvidence) rather than reported
//     as Clean; when positive evidence exists it is kept and the partial
//     coverage is recorded in `limitations`. `sampleExecuted=false` stays
//     Unknown as before.
//   * Elevation is recorded as a FACT, not an exploit: a High/System child of a
//     Medium/Low parent is scored as escalation ONLY when the event does not
//     carry a policy-approval marker (`details["elevationApproved"]`), and
//     even an unexpected elevation never counts as the sample-attributable
//     corroboration required for Malicious (a UAC consent is not a payload).
//   * The verdict is driven by observed behavior (persistence, drops, egress,
//     privilege escalation, side-loaded DLLs, suspicious command lines, crashes),
//     each of which adds weight AND a rationale line.
//   * `sampleSigned` (the static Authenticode-present flag) raises the Malicious
//     threshold -- a present signature is weak evidence of benignity but reduces
//     confidence in a Malicious call, mitigating the benign signed-installer FP.
//     It is NOT a clean-list (signed malware still scores its behavior).
BehaviorScore ScoreSandboxBehavior(const DynamicRunSummary &summary,
                                   const std::vector<EventRecord> &events,
                                   bool sampleSigned = false);

} // namespace antimal
