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
// The default drop-directory watch set. With an empty `userProfile` it resolves
// from the CALLING process's environment (the legacy behavior, correct for a
// session-0 user agent). With `userProfile` set (e.g. C:\Users\antimal) it
// watches THAT user's per-profile drop locations -- temp, roaming/startup,
// downloads, desktop, documents -- which is what a LocalSystem agent must use to
// observe the interactive sample user's files. The Public directory is always
// watched: it is machine-wide.
std::vector<std::filesystem::path> DefaultWatchedDirs(
    const std::wstring &userProfile = {});

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
// Kept pure (no disk I/O / hashing) so it stays host-unit-testable. The content
// enrichment (sha256 + file type) is layered on by the GuestAgent via
// EnrichDroppedFileEvent below, on the new-file path only.
std::vector<EventRecord> DiffFileSnapshots(const FileSnapshot &prev,
                                           const FileSnapshot &cur,
                                           bool emitBaseline, size_t baselineCap,
                                           size_t deltaCap);

// Cap on bytes hashed for one dropped file. A drop larger than this is reported
// with details["hashSkipped"]="size" and fileType="(large, unhashed)" rather
// than silently dropped, so the report still shows the file existed.
constexpr uint64_t kMaxHashBytes = 32ull * 1024ull * 1024ull;  // 32 MiB

// Classifies already-read file bytes: returns the magic-byte type label from the
// static pipeline's IdentifyFileType (e.g. "pe", "zip", "script"), or "data"
// when no signature matches but bytes are present. Pure over its input so the
// classification is host-unit-testable without touching the disk.
std::string ClassifyDroppedFileBytes(const std::vector<uint8_t> &head);

// Enriches a single "file.create" / "file.modify" EventRecord (as produced by
// DiffFileSnapshots) with the high-signal "what did it drop" detail: the file's
// sha256 + magic-byte file type. The GuestAgent calls this in-guest where it can
// read the dropped file directly. Bounded + fail-soft:
//   - files larger than kMaxHashBytes are NOT hashed: details["hashSkipped"]=
//     "size", details["fileType"]="(large, unhashed)";
//   - a locked/unreadable file (sharing violation, ACL) is left WITHOUT a hash:
//     details["hashSkipped"]="locked" -- it never blocks or throws.
// On success it sets details["sha256"] and details["fileType"]. ReadFileHead is
// the seam tested in isolation; on the real agent it is the default disk reader.
void EnrichDroppedFileEvent(EventRecord &event);

}  // namespace antimal
