#pragma once

// Live image/DLL-load telemetry for the dynamic-detonation path -- "what
// modules did each process load, and were any of them side-loaded / hijacked
// from a non-system, attacker-writable location?".
//
// Side-loaded / search-order-hijacked DLLs are core malware tradecraft (a
// signed, trusted host process is made to load an attacker DLL that sits next
// to it in %TEMP% / %APPDATA% / Downloads), and the rest of the pipeline is
// otherwise blind to them. This collector mirrors the other telemetry
// collectors exactly: a per-process module snapshot, a PURE diff that turns
// consecutive snapshots into image.load / image.unload / image.observed
// EventRecords, and a PURE path-classifier that flags loads from writable,
// non-system directories with the matching MITRE technique.
//
// The capture step (BuildModuleSnapshot, in the GuestAgent) is a thin Toolhelp32
// wrapper; the diff + suspicion classifier here are pure and deterministic so
// they can be unit-tested on the host without a live guest.

#include "antimal/Types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace antimal {

struct LoadedModule {
  std::string path;   // full on-disk module path, e.g. "C:\\Windows\\System32\\ntdll.dll"
  uint64_t base = 0;  // load address (modBaseAddr) -- distinguishes relocated loads
};

// pid -> the modules currently mapped into that process. std::map keeps the diff
// output ordered (stable) so tests and the UI see processes in a deterministic
// pid order.
using ProcessModuleSnapshot = std::map<uint32_t /*pid*/, std::vector<LoadedModule>>;

// PURE. Returns true when `modulePath` is loaded from a NON-system,
// user-writable location -- the kind of place a legitimate DLL is essentially
// never loaded from, but a side-loaded / hijacked DLL almost always is:
//   \Users\...\AppData\, \Temp\, \Downloads\, \ProgramData\, \Public\, or the
//   same directory as the loader's own image when that image itself lives in a
//   writable, non-system location (classic application-directory side-loading).
// Conservative by construction: anything under \Windows\System32, \Windows\
// (incl. \Windows\WinSxS), or \Program Files (incl. (x86)) is NEVER flagged, so
// the normal flood of OS/framework DLL loads produces no noise. Case-insensitive;
// tolerant of "\\?\" extended-length prefixes and forward slashes.
// `loaderImagePath` may be empty (then only the absolute-location rules apply).
bool IsSuspiciousModulePath(const std::string &modulePath,
                            const std::string &loaderImagePath);

// PURE. Diffs two per-process module snapshots into telemetry events.
//   emitBaseline == true : ignore `prev`; emit up to `baselineCap`
//       "image.observed" events across all processes in `cur` (used for the very
//       first snapshot so the host immediately shows the loaded-module baseline).
//   emitBaseline == false: emit "image.load" for a (pid, module path) present in
//       `cur` but not in `prev` for that pid (capped at `deltaCap`), and
//       "image.unload" for one present in `prev` but not `cur` (uncapped --
//       unloads are always reported).
// Every event is source="GuestAgent", category="image", processId=pid,
// target=<module path>, details["base"]=hex load address. A suspicious load
// (IsSuspiciousModulePath) additionally carries ev.mitre and
// details["suspicion"]="dll-from-writable-path" so the scorer + report can
// highlight it without re-deriving the classification.
//
// Truncation is honest: when the baseline / delta cap is hit, the LAST emitted
// event of that batch carries details["truncated"]="true" so a flood is visibly
// bounded rather than silently dropped.
std::vector<EventRecord> DiffModuleSnapshots(const ProcessModuleSnapshot &prev,
                                             const ProcessModuleSnapshot &cur,
                                             bool emitBaseline,
                                             size_t baselineCap,
                                             size_t deltaCap);

}  // namespace antimal
