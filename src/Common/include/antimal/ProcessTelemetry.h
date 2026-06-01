#pragma once

// Live process telemetry for the dynamic-detonation path.
//
// The GuestAgent (running inside the analysis VM) periodically snapshots the
// guest process table and diffs consecutive snapshots into EventRecords that
// stream to the host over COM2 (see HostChannel.h / EventJournal.h). The host
// surfaces them in the Any.Run-style live process panel.
//
// The capture step is a thin Toolhelp32 wrapper (Windows-only). The diff step
// is pure and deterministic so it can be unit-tested on the host without a
// live guest — that is the half that decides what becomes a process.start /
// process.stop / process.running event.

#include "antimal/Types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace antimal {

struct ProcessInfo {
  uint32_t parentPid = 0;
  std::string image; // base image name, e.g. "explorer.exe"
};

// pid -> info. std::map keeps the diff output ordered (stable) so tests and the
// UI see processes in a deterministic pid order.
using ProcessSnapshot = std::map<uint32_t, ProcessInfo>;

// Captures the current guest process table. Returns {} on failure or on a
// non-Windows build (the host unit tests exercise DiffProcessSnapshots
// directly, so they never need a real capture).
ProcessSnapshot CaptureProcessSnapshot();

// Diffs two snapshots into telemetry events.
//   emitBaseline == true : ignore `prev`; emit up to `baselineCap`
//       "process.running" events for the entries in `cur` (used for the very
//       first snapshot so the UI immediately shows what is already running).
//   emitBaseline == false: emit "process.start" for pids present in `cur` but
//       not `prev` (capped at `deltaCap`), and "process.stop" for pids present
//       in `prev` but not `cur` (uncapped — process exits are always reported).
// Every event is stamped source="GuestAgent", category="process", with the
// current UTC timestamp, processId, parentProcessId, imagePath, and target.
std::vector<EventRecord> DiffProcessSnapshots(const ProcessSnapshot &prev,
                                              const ProcessSnapshot &cur,
                                              bool emitBaseline,
                                              size_t baselineCap,
                                              size_t deltaCap);

} // namespace antimal
