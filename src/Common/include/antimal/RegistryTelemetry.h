#pragma once

// Live registry-persistence telemetry for the dynamic-detonation path — "did the
// sample install persistence?". Same snapshot+diff shape as ProcessTelemetry /
// NetworkTelemetry: the GuestAgent snapshots a fixed set of autostart keys and
// diffs consecutive snapshots into registry.set / registry.delete EventRecords.
//
// Capture wraps the registry (advapi32, already linked everywhere). Diff is pure
// and unit-tested on the host. We watch the classic persistence locations
// (Run / RunOnce / Winlogon) rather than the whole hive — that is the
// high-signal, low-noise subset a sandbox cares about.

#include "antimal/Types.h"

#include <map>
#include <string>
#include <vector>

namespace antimal {

// "HKLM\...\Run\<ValueName>" -> value data (string, or a "<type N, M bytes>"
// placeholder for non-string values).
using RegistrySnapshot = std::map<std::string, std::string>;

// Captures the autostart/persistence keys. Returns {} on a non-Windows build.
RegistrySnapshot CaptureRegistrySnapshot();

// Diffs two snapshots.
//   emitBaseline == true : up to baselineCap "registry.value" events for the
//       entries already present (the first snapshot baseline).
//   emitBaseline == false: "registry.set" for keys that are new OR whose value
//       changed (capped at deltaCap) and "registry.delete" for keys that
//       vanished (uncapped). Each event is source="GuestAgent",
//       category="registry", target=<key>, details["data"]=<value>.
std::vector<EventRecord> DiffRegistrySnapshots(const RegistrySnapshot &prev,
                                               const RegistrySnapshot &cur,
                                               bool emitBaseline,
                                               size_t baselineCap,
                                               size_t deltaCap);

}  // namespace antimal
