#pragma once

// Windows shell-link (.lnk) parser (MS-SHLLINK).
//
// .lnk files are a top-tier malware delivery vector: a shortcut whose target is
// a LOLBin (cmd/powershell/mshta/rundll32/...) and whose COMMAND_LINE_ARGUMENTS
// carry the real payload (an encoded PowerShell cradle, a remote mshta URL, ...).
// The on-disk icon makes it look like a document. This parser walks the binary
// structure to recover the embedded command line + target so the scanner can
// surface "this shortcut secretly runs <lolbin> <args>" -- the single most useful
// static signal for a weaponized shortcut.
//
// Everything here is bounds-safe over fully untrusted bytes: any malformed or
// truncated input yields isLnk=false (header gate) or a partial result, never a
// read past the buffer.

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct ShellLinkInfo {
  bool isLnk = false;             // header size + LinkCLSID matched
  bool isUnicode = false;         // IsUnicode LinkFlag (StringData is UTF-16LE)
  std::string name;               // NAME_STRING (description)
  std::string relativePath;       // RELATIVE_PATH (often holds the target exe)
  std::string workingDir;         // WORKING_DIR
  std::string commandLineArgs;    // COMMAND_LINE_ARGUMENTS (the payload)
  std::string iconLocation;       // ICON_LOCATION
  std::string localBasePath;      // LinkInfo LocalBasePath (the resolved target)
  bool runsLolbin = false;        // target/args invoke a known living-off-the-land binary
  std::string lolbin;             // which LOLBin was detected (lowercase, e.g. "powershell")
};

// Parse a Windows shell link. Returns isLnk=false on any input whose header is
// not a valid MS-SHLLINK ShellLinkHeader.
ShellLinkInfo ParseShellLink(const std::vector<uint8_t> &data);

} // namespace antimal
