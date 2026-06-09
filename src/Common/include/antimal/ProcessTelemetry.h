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

  // Deep telemetry, captured in-guest by the GuestAgent (see its OS-capture
  // path). All optional: DiffProcessSnapshots stays pure and simply copies
  // whatever the caller filled in. Empty/zero means "not captured" (e.g. a
  // protected process the agent couldn't open, or a host unit test that only
  // exercises the diff).
  std::string fullImagePath;   // full on-disk path, e.g. "C:\\Windows\\explorer.exe"
  std::string commandLine;     // process command line (truncated with a marker if long)
  std::string integrityLevel;  // "Low" | "Medium" | "High" | "System" | "Untrusted"
  std::string userName;        // "DOMAIN\\user" of the process token
  std::string userSid;         // SID string, e.g. "S-1-5-18"
  std::string startTimeUtc;    // ISO-8601 UTC process creation time
  uint32_t sessionId = 0;      // Windows session id
  bool hasSessionId = false;   // distinguishes "session 0" from "not captured"
  uint32_t exitCode = 0;       // captured at process exit (GetExitCodeProcess)
  bool hasExitCode = false;    // true only on a process.stop where we read the code
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
