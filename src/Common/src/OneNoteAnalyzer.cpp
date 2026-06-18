#include "antimal/OneNoteAnalyzer.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace antimal {

namespace {

bool FindBytes(const std::vector<uint8_t> &data, const uint8_t *pat, size_t plen,
               size_t limit) {
  const size_t n = std::min(data.size(), limit);
  if (plen == 0 || n < plen) return false;
  for (size_t i = 0; i + plen <= n; ++i) {
    if (std::memcmp(data.data() + i, pat, plen) == 0) return true;
  }
  return false;
}

bool FindAscii(const std::vector<uint8_t> &data, const char *s, size_t limit) {
  return FindBytes(data, reinterpret_cast<const uint8_t *>(s), std::strlen(s),
                   limit);
}

bool FindAsciiCi(const std::vector<uint8_t> &data, const char *s, size_t limit) {
  const size_t n = std::min(data.size(), limit);
  const size_t plen = std::strlen(s);
  if (plen == 0 || n < plen) return false;
  for (size_t i = 0; i + plen <= n; ++i) {
    bool ok = true;
    for (size_t j = 0; j < plen; ++j) {
      if (std::tolower(data[i + j]) != std::tolower((unsigned char)s[j])) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

} // namespace

OneNoteAnalysis AnalyzeOneNote(const std::vector<uint8_t> &data) {
  OneNoteAnalysis a;
  // [MS-ONESTORE] header guidFileType for a .one section.
  static const uint8_t kMagic[] = {0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8,
                                   0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78,
                                   0xD0, 0x29, 0x96, 0xD3};
  if (data.size() < sizeof(kMagic) ||
      std::memcmp(data.data(), kMagic, sizeof(kMagic)) != 0) {
    return a;
  }
  a.isOneNote = true;

  constexpr size_t kSweep = 64u * 1024u * 1024u;
  // FileDataStoreObject GUID {BDE316E7-2665-4511-A4C8-3D87080A65C9} -- marks an
  // embedded file blob.
  static const uint8_t kFds[] = {0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26,
                                 0x11, 0x45, 0xA4, 0xC8, 0x3D, 0x87,
                                 0x08, 0x0A, 0x65, 0xC9};
  a.hasEmbeddedFile = FindBytes(data, kFds, sizeof(kFds), kSweep);
  a.embeddedExecutable =
      FindAscii(data, "This program cannot be run in DOS mode", kSweep);
  // Common script payloads embedded in OneNote lures.
  a.embeddedScript = FindAsciiCi(data, "<script", kSweep) ||
                     FindAsciiCi(data, "CreateObject(\"WScript", kSweep) ||
                     FindAsciiCi(data, "powershell", kSweep) ||
                     FindAscii(data, "@echo off", kSweep);

  if (a.hasEmbeddedFile) {
    a.findings.push_back(
        {"onenote.embedded_file",
         "OneNote embeds a FileDataStore attachment -- the click-to-run malspam "
         "lure pattern",
         35});
  }
  if (a.embeddedExecutable) {
    a.findings.push_back(
        {"onenote.embedded_exe",
         "OneNote carries an embedded PE executable", 50});
  }
  if (a.embeddedScript) {
    a.findings.push_back(
        {"onenote.embedded_script",
         "OneNote carries an embedded script payload (powershell/wsh/bat/html)",
         40});
  }
  return a;
}

} // namespace antimal
