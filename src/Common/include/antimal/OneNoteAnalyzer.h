#pragma once

// OneNote (.one) maldoc analyzer (heuristic).
//
// OneNote section files were the dominant malspam carrier in 2023-24: the lure
// embeds an attachment (a script/EXE) behind a "double-click to view" graphic,
// and OneNote runs it on click with no macro warning. Embedded files are stored
// as FileDataStoreObjects ([MS-ONESTORE]) — a known GUID followed by the raw
// payload. This analyzer detects the format and sweeps for the embedded-file
// GUID + a payload signature (PE / script). It does NOT parse the full ONESTORE
// object graph (a liability over untrusted bytes); it is a bounded content scan.

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <vector>

namespace antimal {

struct OneNoteAnalysis {
  bool isOneNote = false;
  bool hasEmbeddedFile = false;    // a FileDataStoreObject is present
  bool embeddedExecutable = false; // an embedded PE (DOS-stub anchored)
  bool embeddedScript = false;     // an embedded script signature (e.g. <script>, BAT, WSF)
  std::vector<ScanFinding> findings;
};

// Analyze a OneNote byte buffer. Non-OneNote input (no [MS-ONESTORE] file GUID)
// returns isOneNote=false. Bounds-safe; sweeps a bounded prefix of large files.
OneNoteAnalysis AnalyzeOneNote(const std::vector<uint8_t> &data);

} // namespace antimal
