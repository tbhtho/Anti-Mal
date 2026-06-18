#pragma once

#include <string>

namespace antimal {

// Map a MITRE ATT&CK technique/sub-technique ID (e.g. "T1547.001") to its human
// name (e.g. "Boot or Logon Autostart Execution: Registry Run Keys / Startup
// Folder"). Returns "" for IDs not in the curated catalog. This lifts the
// report's MITRE chips from bare IDs to analyst-readable labels (Any.Run shows
// names, not codes). The catalog covers the techniques AntiMal's own
// behavior/capa mapping and config extractors actually emit; it is not the full
// ATT&CK corpus. Pure + table-driven -> unit-tested.
std::string MitreTechniqueName(const std::string &id);

// Map a technique/sub-technique ID to its primary ATT&CK tactic (e.g.
// "T1547.001" -> "Persistence"). A sub-technique with no explicit entry falls
// back to its parent technique's tactic. Returns "Other" for IDs not in the
// curated catalog so a grouped view never silently drops an observed technique.
// Enables the report's ATT&CK matrix-style grouping (tactic -> techniques),
// the way Any.Run presents the kill chain. Pure + table-driven -> unit-tested.
std::string MitreTechniqueTactic(const std::string &id);

} // namespace antimal
