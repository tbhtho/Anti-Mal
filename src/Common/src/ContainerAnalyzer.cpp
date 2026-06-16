#include "antimal/ContainerAnalyzer.h"

#include "antimal/FileUtil.h" // ToLowerAscii

#include <algorithm>
#include <array>

namespace antimal {
namespace {

constexpr uint32_t kLocalHeaderSig = 0x04034b50;
constexpr uint32_t kCentralDirSig = 0x02014b50;
constexpr uint32_t kEocdSig = 0x06054b50;
constexpr size_t kMaxEntries = 4096;

uint16_t Read16(const std::vector<uint8_t> &d, size_t off) {
  return static_cast<uint16_t>(d[off]) | (static_cast<uint16_t>(d[off + 1]) << 8);
}
uint32_t Read32(const std::vector<uint8_t> &d, size_t off) {
  return static_cast<uint32_t>(d[off]) | (static_cast<uint32_t>(d[off + 1]) << 8) |
         (static_cast<uint32_t>(d[off + 2]) << 16) |
         (static_cast<uint32_t>(d[off + 3]) << 24);
}

bool StartsWith(const std::vector<uint8_t> &d, std::initializer_list<int> sig) {
  if (d.size() < sig.size()) return false;
  size_t i = 0;
  for (int b : sig) {
    if (d[i++] != static_cast<uint8_t>(b)) return false;
  }
  return true;
}

// Search raw bytes for `needle` both as ASCII and as UTF-16LE (OLE directory
// entry names + many in-stream strings are UTF-16LE). Case-sensitive.
bool ContainsAsciiOrUtf16(const std::vector<uint8_t> &d, const std::string &needle) {
  if (needle.empty()) return false;
  // ASCII
  if (d.size() >= needle.size()) {
    const auto it = std::search(d.begin(), d.end(), needle.begin(), needle.end());
    if (it != d.end()) return true;
  }
  // UTF-16LE
  std::vector<uint8_t> w;
  w.reserve(needle.size() * 2);
  for (char c : needle) {
    w.push_back(static_cast<uint8_t>(c));
    w.push_back(0x00);
  }
  if (d.size() >= w.size()) {
    const auto it = std::search(d.begin(), d.end(), w.begin(), w.end());
    if (it != d.end()) return true;
  }
  return false;
}

// Locate the End Of Central Directory record by scanning backward from the end.
size_t FindEocd(const std::vector<uint8_t> &d) {
  if (d.size() < 22) return std::string::npos;
  const size_t maxBack = std::min<size_t>(d.size(), 65557); // 64KB comment + 22
  const size_t start = d.size() - maxBack;
  for (size_t i = d.size() - 22 + 1; i-- > start;) {
    if (Read32(d, i) == kEocdSig) return i;
    if (i == start) break;
  }
  return std::string::npos;
}

bool EndsWithExecExtension(const std::string &nameLower, std::string &outExt) {
  static const std::array<const char *, 22> kExecExts = {
      ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs",
      ".vbe", ".js",  ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".dll",
      ".jar", ".msi", ".cpl", ".ocx", ".sys", ".reg"};
  for (const char *e : kExecExts) {
    const std::string ext(e);
    if (nameLower.size() >= ext.size() &&
        nameLower.compare(nameLower.size() - ext.size(), ext.size(), ext) == 0) {
      outExt = ext;
      return true;
    }
  }
  return false;
}

// A "document-looking" first extension followed by an executable second
// extension is the classic lure (invoice.pdf.exe, photo.jpg.scr).
bool IsDoubleExtension(const std::string &nameLower) {
  // strip any path
  std::string base = nameLower;
  const size_t slash = base.find_last_of("/\\");
  if (slash != std::string::npos) base = base.substr(slash + 1);
  std::string execExt;
  if (!EndsWithExecExtension(base, execExt)) return false;
  const std::string stem = base.substr(0, base.size() - execExt.size());
  const size_t dot = stem.find_last_of('.');
  if (dot == std::string::npos || dot == 0) return false;
  static const std::array<const char *, 14> kDecoyExts = {
      ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".txt",
      ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".csv", ".rtf"};
  const std::string first = stem.substr(dot);
  for (const char *e : kDecoyExts) {
    if (first == e) return true;
  }
  return false;
}

void AnalyzeZip(const std::vector<uint8_t> &d, ContainerAnalysis &out) {
  // Parse the central directory (authoritative) when the EOCD is present;
  // otherwise fall back to scanning local file header signatures.
  std::vector<ContainerEntry> &entries = out.entries;
  const size_t eocd = FindEocd(d);
  bool parsed = false;
  if (eocd != std::string::npos && eocd + 16 + 4 <= d.size()) {
    const uint16_t total = Read16(d, eocd + 10);
    size_t pos = Read32(d, eocd + 16); // central directory offset
    for (uint16_t i = 0; i < total && entries.size() < kMaxEntries; ++i) {
      if (pos + 46 > d.size() || Read32(d, pos) != kCentralDirSig) break;
      const uint16_t gp = Read16(d, pos + 8);
      const uint32_t uncomp = Read32(d, pos + 24);
      const uint16_t nameLen = Read16(d, pos + 28);
      const uint16_t extraLen = Read16(d, pos + 30);
      const uint16_t commentLen = Read16(d, pos + 32);
      const size_t nameOff = pos + 46;
      if (nameOff + nameLen > d.size()) break;
      ContainerEntry e;
      e.name.assign(reinterpret_cast<const char *>(d.data() + nameOff), nameLen);
      e.encrypted = (gp & 0x01) != 0;
      e.uncompressedSize = uncomp;
      entries.push_back(std::move(e));
      pos = nameOff + nameLen + extraLen + commentLen;
      parsed = true;
    }
  }
  if (!parsed) {
    // Fallback: scan for local file header signatures and read each filename.
    for (size_t i = 0; i + 30 <= d.size() && entries.size() < kMaxEntries; ++i) {
      if (Read32(d, i) != kLocalHeaderSig) continue;
      const uint16_t gp = Read16(d, i + 6);
      const uint32_t uncomp = Read32(d, i + 22);
      const uint16_t nameLen = Read16(d, i + 26);
      const size_t nameOff = i + 30;
      if (nameLen == 0 || nameLen > 512 || nameOff + nameLen > d.size()) continue;
      ContainerEntry e;
      e.name.assign(reinterpret_cast<const char *>(d.data() + nameOff), nameLen);
      e.encrypted = (gp & 0x01) != 0;
      e.uncompressedSize = uncomp;
      entries.push_back(std::move(e));
      i = nameOff + nameLen - 1; // advance past this header's name
    }
  }

  // Classify OOXML (Office macro doc) vs a plain archive from the member names.
  bool ooxml = false, vbaProject = false, encrypted = false;
  std::vector<std::string> execNames, doubleExtNames;
  for (const auto &e : entries) {
    const std::string low = ToLowerAscii(e.name);
    if (low == "[content_types].xml" || low.rfind("word/", 0) == 0 ||
        low.rfind("xl/", 0) == 0 || low.rfind("ppt/", 0) == 0) {
      ooxml = true;
    }
    if (low.find("vbaproject.bin") != std::string::npos) vbaProject = true;
    if (e.encrypted) encrypted = true;
    std::string ext;
    if (EndsWithExecExtension(low, ext)) execNames.push_back(e.name);
    if (IsDoubleExtension(low)) doubleExtNames.push_back(e.name);
  }

  out.kind = ooxml ? "ooxml" : "zip";

  if (vbaProject) {
    out.hasMacros = true;
    out.macroSignals.push_back("vbaProject.bin");
    out.findings.push_back(
        {"macro.vba_present",
         "Office document embeds a VBA macro project (vbaProject.bin)", 25});
  }
  if (!execNames.empty()) {
    std::string list;
    for (size_t i = 0; i < execNames.size() && i < 5; ++i) {
      if (i) list += ", ";
      list += execNames[i];
    }
    if (execNames.size() > 5) list += ", +" + std::to_string(execNames.size() - 5) + " more";
    // Modest weight: a bare executable member is extremely common in legitimate
    // software distributions, so on its own (even alongside an encrypted entry)
    // it must stay below the Suspicious bar. The double-extension lure below
    // carries the higher, malice-specific weight.
    out.findings.push_back(
        {"archive.executable_payload",
         "Archive contains executable payload(s): " + list, 20});
  }
  if (!doubleExtNames.empty()) {
    out.findings.push_back(
        {"archive.double_extension",
         "Archive contains a double-extension lure: " + doubleExtNames.front(), 30});
  }
  if (encrypted) {
    out.findings.push_back(
        {"archive.encrypted",
         "Password-protected archive entries (content hidden from inspection / "
         "AV — common evasion)",
         20});
  }
}

void AnalyzeOle(const std::vector<uint8_t> &d, ContainerAnalysis &out) {
  out.kind = "ole";
  // VBA-macro presence: the OLE storage/stream names that always accompany a
  // VBA project. Reliable from the raw directory bytes (UTF-16LE).
  // Specific OLE storage/stream names that accompany a real VBA project. The
  // bare 3-char "VBA" is deliberately excluded — it matches incidental document
  // text (a tutorial that merely mentions VBA) and falsely asserts a macro.
  static const std::array<const char *, 5> kVbaMarkers = {
      "_VBA_PROJECT", "vbaProject", "Macros", "ThisDocument", "Module1"};
  for (const char *m : kVbaMarkers) {
    if (ContainsAsciiOrUtf16(d, m)) {
      out.hasMacros = true;
      out.macroSignals.push_back(m);
    }
  }
  if (out.hasMacros) {
    out.findings.push_back(
        {"macro.vba_present", "OLE document contains a VBA macro project", 25});
  }
  // Auto-executing macro entry points (best-effort: these names live in the
  // MS-OVBA-compressed module source, so this only fires on uncompressed/leaked
  // copies — but a hit is high-signal).
  static const std::array<const char *, 8> kAutoExec = {
      "Document_Open", "Document_Close", "AutoOpen",      "AutoClose",
      "Auto_Open",     "Workbook_Open",  "Workbook_Close", "AutoExec"};
  for (const char *m : kAutoExec) {
    if (ContainsAsciiOrUtf16(d, m)) {
      out.hasAutoExecMacro = true;
      out.macroSignals.push_back(m);
      out.findings.push_back(
          {"macro.auto_exec",
           std::string("Auto-executing macro entry point '") + m +
               "' (runs on open/close)",
           35});
      break;
    }
  }
  // OLE-embedded exploit objects (memory-corruption maldocs). Only specific
  // exploit-associated class names — NOT the generic "Package" (Object Packager)
  // storage that any benign document with an embedded attachment carries.
  static const std::array<const char *, 3> kExploitObjects = {
      "Equation.3", "Microsoft Equation", "OLE2Link"};
  for (const char *m : kExploitObjects) {
    if (ContainsAsciiOrUtf16(d, m)) {
      out.findings.push_back(
          {"ole.exploit_object",
           std::string("Embedded OLE object '") + m +
               "' associated with memory-corruption maldocs (e.g. "
               "Equation Editor CVE-2017-11882)",
           30});
      break;
    }
  }
}

} // namespace

ContainerAnalysis AnalyzeContainer(const std::vector<uint8_t> &data,
                                   const std::string &extensionHint) {
  (void)extensionHint; // type is determined from magic bytes, not the extension
  ContainerAnalysis out;
  if (StartsWith(data, {'P', 'K', 0x03, 0x04}) ||
      StartsWith(data, {'P', 'K', 0x05, 0x06})) {
    out.isContainer = true;
    AnalyzeZip(data, out);
    return out;
  }
  if (StartsWith(data, {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})) {
    out.isContainer = true;
    AnalyzeOle(data, out);
    return out;
  }
  return out;
}

} // namespace antimal
