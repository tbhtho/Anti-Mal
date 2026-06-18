#pragma once

// RTF maldoc analyzer.
//
// RTF is one of the most common malicious-document carriers: it embeds OLE
// objects (\object/\objdata) that auto-run on open (\objupdate), and is the
// classic delivery for the Equation Editor exploits (CVE-2017-11882 /
// CVE-2018-0802) and OLE2Link. The payload sits in a hex stream after \objdata.
// This analyzer flags those structural markers and peeks at the decoded \objdata
// header for the Equation Editor CLSID and an embedded PE/OLE.
//
// Heuristic + bounds-safe over untrusted bytes: it scans control words and
// decodes only a bounded prefix of each \objdata hex blob. No full RTF parse.

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct RtfAnalysis {
  bool isRtf = false;
  int objectCount = 0;          // \object occurrences
  bool hasOleObject = false;    // \objdata / \objemb / \objocx present
  bool hasAutoUpdate = false;   // \objupdate -- object updates (runs) on open
  bool equationEditor = false;  // Equation Editor CLSID/class in a decoded object
  bool embeddedExecutable = false; // \objdata decodes to a PE (MZ) or OLE (D0CF)
  bool remoteLink = false;      // object loads a remote URL (CVE-2017-0199 / OLE2Link)
  std::vector<std::string> urls; // remote URLs recovered from object monikers
  std::vector<ScanFinding> findings;
};

// Analyze an RTF byte buffer. Non-RTF input (no "{\rtf" header in the first
// bytes) returns isRtf=false.
RtfAnalysis AnalyzeRtf(const std::vector<uint8_t> &data);

} // namespace antimal
