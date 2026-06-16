#pragma once

// Container analyzer: the document/archive side of static triage.
//
// Two container families carry most "open this file" malware:
//   1. OLE compound files (.doc/.xls/.ppt/.msi, magic D0 CF 11 E0) — VBA macros.
//   2. ZIP containers — both OOXML documents (.docm/.xlsm/.pptm, which embed a
//      vbaProject.bin) AND plain archives that smuggle an executable payload.
//
// Without this, AntiMal reports a macro-laden .xlsm or a zip hiding invoice.exe
// as an opaque "zip". This module detects VBA-macro presence + auto-exec
// markers, OLE exploit objects (Equation Editor / OLE2Link), and walks a zip's
// central directory to flag executable / double-extension / password-protected
// entries.
//
// Heuristic + bounds-safe over untrusted bytes; no decompression, no external
// tools. (VBA *source* is MS-OVBA-compressed, so auto-exec name detection is
// best-effort over raw bytes; macro *presence* is detected reliably from the
// OLE storage names / the OOXML vbaProject.bin entry.)

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct ContainerEntry {
  std::string name;            // archive member path
  bool encrypted = false;      // ZIP general-purpose bit 0 (password-protected)
  uint32_t uncompressedSize = 0;
};

struct ContainerAnalysis {
  bool isContainer = false;
  std::string kind;                       // "ole" | "ooxml" | "zip" | ""
  bool hasMacros = false;                 // VBA / OOXML vbaProject detected
  bool hasAutoExecMacro = false;          // AutoOpen/Document_Open/... (best-effort)
  std::vector<std::string> macroSignals;  // which markers matched
  std::vector<ContainerEntry> entries;    // ZIP members (capped)
  std::vector<ScanFinding> findings;
};

// Analyze an OLE or ZIP container. `extensionHint` is the lowercased extension
// including the dot. Non-container inputs return isContainer=false.
ContainerAnalysis AnalyzeContainer(const std::vector<uint8_t> &data,
                                   const std::string &extensionHint);

} // namespace antimal
