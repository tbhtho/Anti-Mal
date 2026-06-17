#pragma once

#include "antimal/Types.h"

#include <string>

namespace antimal {

// Build a deterministic, clearly-labeled SYNTHETIC AnalysisReport that models a
// credential-stealer detonation: an explorer -> sample.exe -> cmd -> powershell
// process subtree, a Run-key persistence write, two dropped files, a C2 egress,
// tags / IOCs / MITRE techniques, a scored behavioral verdict + rationale, and a
// populated DynamicRunSummary. The static hashes (sha256/sha1/md5/ctph) are REAL
// (computed over a fixed in-memory buffer) so the static half is exercised too.
//
// Purpose: drive the events -> report.json -> report.html (+ filmstrip) pipeline
// end-to-end with NO VM / firmware / hardware dependency — the documented local
// simulation for environments where a live boot isn't available, and a stable
// fixture for report work. It is unmistakably labeled as a simulation
// (dynamicSummary.status + the leading verdictRationale line) so it can never be
// confused with a real detonation. Pure + deterministic -> unit-tested.
AnalysisReport BuildSimulatedReport(const std::string &runId);

} // namespace antimal
