#pragma once

// Suspicious process-ancestry detection.
//
// Individual command lines are classified by CommandLineClassifier; this looks at
// the parent->child *lineage* the process tree encodes, where the relationship is
// the signal: an Office app spawning PowerShell is the textbook maldoc execution
// chain, a browser spawning a script host is a drive-by, a proxy-exec LOLBin
// (mshta/rundll32/regsvr32) spawning a shell is staged execution. Pure: a
// function of the process.start events only. Conservative rule set (the chains
// that are rarely benign) so it can feed the verdict without flooding FPs.

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

struct ProcessChainHit {
  std::string parent; // parent image (base name)
  std::string child;  // child image (base name)
  std::string reason; // analyst-readable why
  std::string mitre;  // primary ATT&CK technique
  int severity = 2;   // 1 info, 2 medium, 3 high
};

// Flag suspicious parent->child execution lineages across the run's
// process.start events. Deterministic; deduplicated by (parent,child,reason).
std::vector<ProcessChainHit> ClassifyProcessChains(
    const std::vector<EventRecord> &events);

} // namespace antimal
