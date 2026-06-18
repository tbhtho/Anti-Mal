#pragma once

#include "antimal/Types.h"

#include <optional>
#include <string>

namespace antimal {

// The synthetic-detonation scenarios the simulator can model. Each produces a
// distinct, behavior-appropriate process tree, IOC/tag/finding set, MITRE
// technique list, and verdict — so the report renderer is exercised across the
// major malware behavior classes, and report-diff has cross-behavior fixtures.
enum class SimScenario {
  Stealer,    // credential theft: subtree + Run-key persistence + C2 egress
  Ransomware, // shadow-copy deletion + mass file encryption + ransom note
  Loader,     // stage download + process injection / hollowing
  Coinminer,  // resource hijacking: miner + pool C2 + persistence
  Wiper,      // data destruction: file overwrite + shadow/recovery wipe
  Rat,        // remote-access trojan: persistent C2 + keylog + screen capture
};

std::optional<SimScenario> ParseSimScenario(const std::string &name);
const char *SimScenarioName(SimScenario scenario);

// Build a deterministic, clearly-labeled SYNTHETIC AnalysisReport for the given
// scenario. The static hashes (sha256/sha1/md5/ctph) are REAL (computed over a
// fixed per-scenario buffer) so the static half is exercised too.
//
// Purpose: drive the events -> report.json -> report.html (+ filmstrip) pipeline
// end-to-end with NO VM / firmware / hardware dependency — the documented local
// simulation for environments where a live boot isn't available, and a stable
// fixture for report work. Unmistakably labeled as a simulation
// (dynamicSummary.status + the leading verdictRationale line). Pure + deterministic.
AnalysisReport BuildSimulatedReport(const std::string &runId,
                                    SimScenario scenario = SimScenario::Stealer);

} // namespace antimal
