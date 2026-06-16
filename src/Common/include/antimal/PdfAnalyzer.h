#pragma once

// PDF maldoc analyzer.
//
// A weaponized PDF is rarely a memory-corruption exploit anymore — it is a
// social-engineering wrapper that runs JavaScript on open, auto-triggers an
// action, launches an external program, or carries an embedded payload the user
// is coaxed into extracting. This analyzer flags those structural markers
// (/JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /URI, /RichMedia),
// de-obfuscating PDF name hex-escapes (/J#61vaScript == /JavaScript) first so a
// trivially-encoded name can't hide.
//
// Heuristic + bounds-safe over untrusted bytes; no PDF object parsing, no
// decompression. Matches complete name tokens to limit false positives.

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct PdfAnalysis {
  bool isPdf = false;
  bool hasJavaScript = false;
  bool hasAutoAction = false;   // /OpenAction or /AA — runs without a click
  bool hasLaunch = false;       // /Launch — runs an external program
  bool hasEmbeddedFile = false; // /EmbeddedFile — carries a payload
  bool nameObfuscation = false; // PDF name hex-escapes used to hide a keyword
  std::vector<std::string> uris; // /URI action targets (best-effort)
  std::vector<ScanFinding> findings;
};

// Analyze a PDF byte buffer. Non-PDF input (no %PDF header in the first 1 KB)
// returns isPdf=false.
PdfAnalysis AnalyzePdf(const std::vector<uint8_t> &data);

} // namespace antimal
