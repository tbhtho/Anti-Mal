#include "antimal/ShellLinkParser.h"

#include "antimal/FileUtil.h" // WideToUtf8, ToLowerAscii

#include <array>
#include <cstring>

namespace antimal {
namespace {

// MS-SHLLINK ShellLinkHeader: HeaderSize is always 0x4C and the LinkCLSID is the
// fixed {00021401-0000-0000-C000-000000000046} in little-endian byte order.
constexpr size_t kHeaderSize = 0x4C;
constexpr std::array<uint8_t, 16> kLinkClsid = {
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

uint16_t Read16(const std::vector<uint8_t> &d, size_t off) {
  return static_cast<uint16_t>(d[off]) | (static_cast<uint16_t>(d[off + 1]) << 8);
}
uint32_t Read32(const std::vector<uint8_t> &d, size_t off) {
  return static_cast<uint32_t>(d[off]) | (static_cast<uint32_t>(d[off + 1]) << 8) |
         (static_cast<uint32_t>(d[off + 2]) << 16) |
         (static_cast<uint32_t>(d[off + 3]) << 24);
}

// Read a NUL-terminated single-byte (ANSI) string starting at absolute offset,
// bounded by the buffer end. Used best-effort for the LinkInfo LocalBasePath.
std::string ReadCString(const std::vector<uint8_t> &d, size_t off) {
  std::string out;
  for (size_t i = off; i < d.size() && d[i] != 0 && out.size() < 1024; ++i) {
    out.push_back(static_cast<char>(d[i]));
  }
  return out;
}

// Living-off-the-land binaries a weaponized shortcut typically launches. A .lnk
// that resolves to / passes any of these is the classic delivery pattern.
const char *MatchLolbin(const std::string &haystackLower) {
  static const char *const kLolbins[] = {
      "powershell", "pwsh",       "cmd.exe",  "mshta",    "rundll32",
      "regsvr32",   "wscript",    "cscript",  "certutil", "bitsadmin",
      "mshtml",     "msiexec",    "installutil", "regasm", "regsvcs",
      "wmic",       "forfiles",   "schtasks", "curl",     "hh.exe",
      "conhost",    "msbuild",    "scriptrunner"};
  for (const char *needle : kLolbins) {
    if (haystackLower.find(needle) != std::string::npos) {
      // Normalize a couple of multi-token matches to a clean label.
      if (std::strcmp(needle, "cmd.exe") == 0) return "cmd";
      if (std::strcmp(needle, "hh.exe") == 0) return "hh";
      return needle;
    }
  }
  return nullptr;
}

} // namespace

ShellLinkInfo ParseShellLink(const std::vector<uint8_t> &data) {
  ShellLinkInfo info;
  if (data.size() < kHeaderSize) {
    return info; // need a full header to even be a LNK
  }
  if (Read32(data, 0) != kHeaderSize) {
    return info;
  }
  if (std::memcmp(data.data() + 4, kLinkClsid.data(), kLinkClsid.size()) != 0) {
    return info;
  }
  info.isLnk = true;

  const uint32_t flags = Read32(data, 0x14);
  info.isUnicode = (flags & 0x80) != 0; // IsUnicode

  size_t pos = kHeaderSize;

  // HasLinkTargetIDList (bit 0): a 2-byte size prefix then that many bytes.
  if (flags & 0x01) {
    if (pos + 2 > data.size()) return info;
    const uint16_t idListSize = Read16(data, pos);
    pos += 2;
    if (idListSize > data.size() - pos) return info; // bounded
    pos += idListSize;
  }

  // HasLinkInfo (bit 1): a self-sized structure; recover the LocalBasePath
  // (the resolved target path) best-effort, then skip the whole block.
  if (flags & 0x02) {
    if (pos + 4 > data.size()) return info;
    const size_t linkInfoStart = pos;
    const uint32_t linkInfoSize = Read32(data, pos);
    // LinkInfoFlags @ +8; VolumeIDAndLocalBasePath == bit 0 -> LocalBasePath valid.
    if (pos + 0x14 <= data.size()) {
      const uint32_t liFlags = Read32(data, pos + 8);
      if (liFlags & 0x01) {
        const uint32_t lbpOff = Read32(data, pos + 16);
        const size_t abs = linkInfoStart + lbpOff;
        if (lbpOff != 0 && abs < data.size()) {
          info.localBasePath = ReadCString(data, abs);
        }
      }
    }
    if (linkInfoSize == 0 || linkInfoSize > data.size() - linkInfoStart) {
      return info; // malformed/over-long: stop before StringData
    }
    pos += linkInfoSize;
  }

  // StringData blocks, each present iff its flag is set, in this fixed order.
  // Each is a 2-byte CountCharacters followed by CountCharacters code units
  // (1 byte ANSI, 2 bytes UTF-16LE). Any over-long count is clamped to the
  // buffer and ends parsing -- never reads past the end.
  auto readStringData = [&](std::string &out) -> bool {
    if (pos + 2 > data.size()) {
      pos = data.size();
      return false;
    }
    const uint16_t count = Read16(data, pos);
    pos += 2;
    const size_t bytes = info.isUnicode ? static_cast<size_t>(count) * 2 : count;
    if (bytes > data.size() - pos) {
      pos = data.size(); // bounded; leave `out` empty
      return false;
    }
    if (info.isUnicode) {
      std::wstring w;
      w.reserve(count);
      for (size_t i = 0; i < count; ++i) {
        w.push_back(static_cast<wchar_t>(Read16(data, pos + i * 2)));
      }
      out = WideToUtf8(w);
    } else {
      out.assign(reinterpret_cast<const char *>(data.data() + pos), count);
    }
    pos += bytes;
    return true;
  };

  if (flags & 0x04) readStringData(info.name);            // HasName
  if (flags & 0x08) readStringData(info.relativePath);    // HasRelativePath
  if (flags & 0x10) readStringData(info.workingDir);      // HasWorkingDir
  if (flags & 0x20) readStringData(info.commandLineArgs); // HasArguments
  if (flags & 0x40) readStringData(info.iconLocation);    // HasIconLocation

  // Weaponized-LNK detection: the target (relative path / resolved LocalBasePath)
  // or the arguments invoke a LOLBin. Most malicious shortcuts also stamp the
  // interpreter name straight into the arguments (cmd target, powershell args).
  const std::string hay = ToLowerAscii(info.relativePath + "\n" + info.localBasePath +
                                       "\n" + info.commandLineArgs + "\n" +
                                       info.iconLocation);
  if (const char *l = MatchLolbin(hay)) {
    info.runsLolbin = true;
    info.lolbin = l;
  }
  return info;
}

} // namespace antimal
