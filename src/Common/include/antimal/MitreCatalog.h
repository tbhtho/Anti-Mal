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

} // namespace antimal
