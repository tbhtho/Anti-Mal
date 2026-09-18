#pragma once

// Live registry-persistence telemetry for the dynamic-detonation path — "did the
// sample install persistence, and by which technique?". Same snapshot+diff shape
// as ProcessTelemetry / NetworkTelemetry: the GuestAgent snapshots a fixed set of
// autostart/persistence keys and diffs consecutive snapshots into
// registry.set / registry.delete EventRecords. Each event carries the MITRE
// ATT&CK technique id of the persistence location that fired, so the host's
// AggregateMitreTechniques can union them into report.mitreTechniques.
//
// Capture wraps the registry (advapi32, already linked everywhere). Diff +
// location→MITRE mapping are pure and unit-tested on the host. We watch the
// classic persistence locations rather than the whole hive — that is the
// high-signal, low-noise subset a sandbox cares about. Enumeration is bounded
// (see kPerLocationValueCap / the COM-hijack CLSID allow-list) so the ~2s tick
// stays cheap on a single vCPU.

#include "antimal/Types.h"

#include <map>
#include <string>
#include <vector>

namespace antimal {

// "HKLM\...\Run\<ValueName>" -> value data (string, or a "<type N, M bytes>"
// placeholder for non-string values). The display prefix is stable and is what
// the location→MITRE mapping keys off.
using RegistrySnapshot = std::map<std::string, std::string>;

// One watched persistence location: a (hive, subkey) the snapshot collector
// enumerates, the stable display prefix its values are recorded under, and the
// MITRE ATT&CK technique id attributed to a change there.
struct PersistenceLocation {
  const char *displayPrefix;  // e.g. "HKLM\\...\\Run"
  const char *mitre;          // e.g. "T1547.001"
};

// The authoritative watched-location → MITRE table. Maintainable in one place:
// add a location here and (for value-enumerated keys) wire its capture in
// CaptureRegistrySnapshot. Returns a stable view over a static array.
const std::vector<PersistenceLocation> &PersistenceLocations();

// Maps a snapshot key (the diff's event target, e.g.
// "HKLM\\...\\Run\\evil") to its MITRE technique id by longest-prefix match
// against PersistenceLocations(). Returns "" for keys that match no known
// persistence location (so non-persistence registry writes are never tagged).
std::string PersistenceMitreForKey(const std::string &snapshotKey);

// Captures the autostart/persistence keys. Returns {} on a non-Windows build.
//
// `userSid` selects WHICH user's hive the HKCU-family locations are read from:
//   * empty  -> HKEY_CURRENT_USER (the calling process's own hive);
//   * set    -> HKEY_USERS\<sid> (the interactive sample user's loaded hive),
//               so a LocalSystem agent observes the SAMPLE's HKCU persistence
//               instead of SYSTEM's. HKLM locations are always machine-wide.
RegistrySnapshot CaptureRegistrySnapshot(const std::wstring &userSid = {});

// Diffs two snapshots.
//   emitBaseline == true : up to baselineCap "registry.value" events for the
//       entries already present (the first snapshot baseline).
//   emitBaseline == false: "registry.set" for keys that are new OR whose value
//       changed (capped at deltaCap) and "registry.delete" for keys that
//       vanished (uncapped). Each event is source="GuestAgent",
//       category="registry", target=<key>, details["data"]=<value>, and
//       mitre=<technique for the matched persistence location> (or "" if none).
std::vector<EventRecord> DiffRegistrySnapshots(const RegistrySnapshot &prev,
                                               const RegistrySnapshot &cur,
                                               bool emitBaseline,
                                               size_t baselineCap,
                                               size_t deltaCap);

}  // namespace antimal
