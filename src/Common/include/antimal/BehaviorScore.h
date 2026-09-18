#pragma once

#include <string>
#include <vector>

#include "antimal/Types.h"

namespace antimal {

// Semantic version of the behavioral scorer. Bump whenever the meaning of a
// scored event, an attribution rule, or a verdict gate changes, so reports can
// state which policy produced them and historical runs can be rescored
// reproducibly.
inline constexpr const char *kBehaviorScorerVersion = "behavior-score-v2";

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
  // never confirmed / no sample-launch anchor / unattributable security-relevant
  // mutation). When this is set the verdict is Unknown and the rationale says
  // exactly what was missing -- "we did not see" is never reported as "nothing
  // happened".
  bool insufficientEvidence = false;
  // Explicit observation limits that applied to this run, whether or not a
  // verdict was reached ("run ended without a completion signal", "guest
  // telemetry channel unconfirmed", "no sample-launch anchor recorded", ...).
  // Carried into the report so the UI can label a Clean/Suspicious/Malicious
  // headline as partial-coverage when it is.
  std::vector<std::string> limitations;
  // The subset of rationale lines that describe a supported observed finding
  // (as opposed to coverage notes / threshold explanations). Consumers can
  // render these as the run's evidence list.
  std::vector<std::string> positiveFindings;
  // Scorer policy identity; equals kBehaviorScorerVersion for scores produced
  // by this implementation. Empty on records produced before versioning.
  std::string scorerVersion = kBehaviorScorerVersion;
};

// Score a completed detonation purely from what the guest was observed to do.
//
// Pure + deterministic: no I/O, no globals, no clock reads -- it is a function
// of (summary, events) only, which is why it lives here rather than buried in
// the 11k-line orchestrator, and why it is directly unit-testable.
//
// Contract (behavior-score-v2):
//   * If the sample never executed (gated run / healthcheck / no telemetry),
//     the verdict is Unknown -- there is nothing to judge.
//   * It NEVER returns Verdict::Error. Error is reserved for an actual run
//     failure (VM crash, boot failure) and is set by the caller, not here.
//   * Hitting the time budget is, by itself, NOT a malicious signal. Timeout,
//     failed launch, incomplete observation, and confirmed harmful behavior are
//     four different facts and are reported as such.
//   * OBSERVATION vs MUTATION. `registry.value` (and every other poll-diff
//     baseline action) is inventory, not a write. Registry/file DELETION is a
//     removal and never "persistence established". Only create/modify actions
//     can be scored as mutations.
//   * ATTRIBUTION. Events are tied to the sample only when the run recorded a
//     sample-launch anchor (`process.create`, or details.sampleExecuted) and the
//     event's owning process instance is in the sample's subtree. A PID alone is
//     not identity: when the root's start time / boot generation was captured,
//     mismatching instances are excluded (PID reuse). When there is no anchor,
//     ownership fails CLOSED -- no PID matches. Poll-diff deltas carry no PID;
//     they are "time-correlated" observations at best and can never unlock the
//     sample-attributable malice gate alone. A MITRE tag describes an
//     interpretation; it cannot manufacture an action or ownership.
//   * CONCLUSIONS. Ordinary application EXE/DLL installation (including the
//     sample installing its own files under Program Files) is a context
//     observation, not malware. A Malicious verdict requires a positive score
//     AND at least one SAMPLE-ATTRIBUTABLE malice signal (staged executable
//     drop, attributed external egress, attributed suspicious command line,
//     attributed side-load, or other attributed MITRE-tagged behavior).
//     Accumulating weak generic signals never becomes categorical malice.
//   * SIGNATURES. `sampleSigned` (the static Authenticode-present flag) raises
//     the Malicious threshold -- it is not a clean-list; signed malware still
//     scores its behavior, and unsigned software is not presumed guilty.
//   * COVERAGE. A reassuring negative requires a run that reached a declared
//     end state, a confirmed guest telemetry channel, a recorded sample-launch
//     anchor, and behavioral telemetry beyond the launch. When any of those is
//     missing and no positive behavior was observed the verdict is WITHHELD
//     (Unknown + insufficientEvidence). An independent well-supported positive
//     finding is KEPT under partial coverage (incomplete does not erase observed
//     harm) and the coverage limits travel with it.
BehaviorScore ScoreSandboxBehavior(const DynamicRunSummary &summary,
                                   const std::vector<EventRecord> &events,
                                   bool sampleSigned = false);

} // namespace antimal
