#pragma once

// Script analyzer: the non-PE side of static triage.
//
// Most initial-access malware today is a *script* — a PowerShell download
// cradle, a JScript/VBScript dropper, a batch LOLBin chain, an HTA — not a PE.
// The PE pipeline never sees these. This analyzer classifies a script by
// content + extension, flags the behaviours that matter (encoded commands,
// download cradles, AMSI bypass, WScript.Shell exec, certutil/bitsadmin
// abuse, char-code obfuscation), and — crucially — *deobfuscates one layer*:
// it decodes PowerShell -EncodedCommand base64 (UTF-16LE) and recovers the C2
// URLs hidden inside, the same "config/C2 extraction" value the PE side gets
// from the XOR/base64 miners.
//
// Pure over the input bytes, no external tools, bounds-safe.

#include "antimal/Types.h" // ScanFinding

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct ScriptAnalysis {
  bool isScript = false;
  std::string language; // "powershell"|"jscript"|"vbscript"|"batch"|"hta"|"wsf"|"shell"|""
  std::vector<ScanFinding> findings;        // malicious-pattern findings
  std::vector<std::string> decodedCommands; // recovered inner commands (deobfuscated)
  std::vector<std::string> recoveredUrls;   // C2/URLs recovered from decoded layers
};

// Classify + analyze a (possibly script) byte buffer. `extensionHint` is the
// lowercased file extension including the dot (e.g. ".ps1"); it disambiguates
// when the content alone is ambiguous, but content can override it. Binary
// inputs (PE/ELF/archives/etc.) return isScript=false.
ScriptAnalysis AnalyzeScript(const std::vector<uint8_t> &data,
                             const std::string &extensionHint);

// Decode a PowerShell -EncodedCommand argument: base64 -> UTF-16LE -> UTF-8.
// Falls back to interpreting the decoded bytes as ASCII/UTF-8 when that yields
// more printable text (some loaders base64 a plain-ASCII command). Returns ""
// on invalid base64 or non-text output.
std::string DecodePowerShellEncodedCommand(const std::string &base64);

} // namespace antimal
