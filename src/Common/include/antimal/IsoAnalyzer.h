#pragma once

// ISO9660 disk-image analyzer (heuristic).
//
// Mounting a downloaded .iso bypasses Mark-of-the-Web on the files inside, so ISO
// (and IMG) images became a top malware-delivery vector: a tiny image holding a
// lure .lnk that launches a hidden executable/script. This analyzer does NOT
// fully parse the ISO9660 directory tree (sector math over untrusted bytes is a
// liability); it does a bounded content sweep for the high-signal markers --
// an embedded PE, an embedded shell-link (.lnk), and the small-image lure shape.

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <vector>

namespace antimal {

struct IsoAnalysis {
  bool isIso = false;
  bool containsExecutable = false; // an embedded PE (DOS-stub anchored)
  bool containsLnk = false;        // an embedded Windows shell-link header
  bool smallLure = false;          // small image (<= ~5 MB) carrying a payload
  std::vector<ScanFinding> findings;
};

// Analyze an ISO byte buffer. Non-ISO input (no "CD001" at offset 0x8001)
// returns isIso=false. Bounds-safe; sweeps a bounded prefix of large images.
IsoAnalysis AnalyzeIso(const std::vector<uint8_t> &data);

} // namespace antimal
