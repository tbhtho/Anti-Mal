#pragma once

// Live filesystem telemetry for the dynamic-detonation path — "what did the
// sample drop / modify?". Same snapshot+diff shape as the other collectors: the
// GuestAgent snapshots a set of high-signal drop directories (Startup, %TEMP%,
// %APPDATA%, %PUBLIC%, Downloads) and diffs consecutive snapshots into
// file.create / file.modify / file.delete EventRecords.
//
// Capture uses std::filesystem + the environment (no extra libraries). Diff is
// pure and unit-tested on the host. We watch specific directories rather than
// the whole volume — that keeps the snapshot cheap and the signal high.

#include "antimal/Types.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace antimal {

struct FileMeta {
  uint64_t size = 0;
  int64_t mtimeTicks = 0;  // last_write_time ticks since the clock epoch
};

// utf-8 path -> metadata.
using FileSnapshot = std::map<std::string, FileMeta>;

// The default drop directories to watch, resolved from the environment.
std::vector<std::filesystem::path> DefaultWatchedDirs();

// Snapshots regular files under `dirs` (recursive, permission-denied skipped),
// capped at maxEntries so a huge %TEMP% can't stall the agent.
FileSnapshot CaptureFileSnapshot(const std::vector<std::filesystem::path> &dirs,
                                 size_t maxEntries = 4096);

// Diffs two snapshots.
//   emitBaseline == true : up to baselineCap "file.observed" events (baseline).
//   emitBaseline == false: "file.create" for new paths and "file.modify" for
//       paths whose size or mtime changed (together capped at deltaCap), and
//       "file.delete" for paths that vanished (uncapped). Each event is
//       source="GuestAgent", category="file", target=<path>, details["size"].
std::vector<EventRecord> DiffFileSnapshots(const FileSnapshot &prev,
                                           const FileSnapshot &cur,
                                           bool emitBaseline, size_t baselineCap,
                                           size_t deltaCap);

}  // namespace antimal
