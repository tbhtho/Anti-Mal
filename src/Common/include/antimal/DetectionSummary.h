#pragma once

#include "antimal/Types.h"

#include <string>
#include <vector>

namespace antimal {

// One analyst-facing detection in the Any.Run-style "behavior activities" view.
struct Detection {
  int severity = 0; // 3=high, 2=medium, 1=low, 0=info (sort key)
  std::string severityLabel; // "high" | "medium" | "low" | "info"
  std::string category;      // "static" | "persistence" | "network" | "behavior"
  std::string title;
  std::string mitre; // technique id, "" when not applicable
};

// Pure: aggregate a report's signals into a single severity-ranked detections
// list — static scan findings (score -> severity), persistence writes (named via
// the persistence classifier), and suspicious network endpoints (named via the
// network classifier). Sorted high -> info, then by category, then title. This is
// the top-of-report behavior summary an analyst reads first.
std::vector<Detection> BuildDetections(const AnalysisReport &report);

} // namespace antimal
