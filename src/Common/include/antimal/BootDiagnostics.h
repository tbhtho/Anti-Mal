#pragma once

#include "antimal/Types.h"

#include <string>

namespace antimal {

// A single, analyst-facing read of how far a guest boot got and what to do about
// it — derived from the many scattered signals a run records (gates, screen
// state, agent connectivity, blockers). The dynamic console + report capture a
// dozen low-level fields; this collapses them into "stage + why + fix".
struct BootOutcome {
  // Furthest stage reached, coarse: "not-started" | "firmware" | "kernel" |
  // "user-mode" | "desktop".
  std::string stage;
  // Short status label, e.g. "desktop-reached", "user-mode-no-desktop",
  // "kernel-no-usermode", "firmware-only", "no-progress", "not-started".
  std::string category;
  std::string detail;      // human one-liner describing the outcome
  std::string remediation; // actionable next step ("" when the boot succeeded)
  bool reachedUserMode = false;
  bool reachedDesktop = false;
};

// Pure: classify a run's boot outcome from its DynamicRunSummary. Picks the
// furthest-progressed stage supported by the evidence, folds in an explicit
// bootBlocker when present, and attaches a remediation hint. Never throws.
BootOutcome ClassifyBootOutcome(const DynamicRunSummary &summary);

} // namespace antimal
