#include "antimal/IsoAnalyzer.h"

#include <algorithm>
#include <cstring>

namespace antimal {

namespace {

// Search `data` (up to `limit` bytes) for the byte sequence `pat`. Bounds-safe.
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
  return FindBytes(data, reinterpret_cast<const uint8_t *>(s),
                   std::strlen(s), limit);
}

} // namespace

IsoAnalysis AnalyzeIso(const std::vector<uint8_t> &data) {
  IsoAnalysis a;
  // ISO9660 PVD identifier "CD001" at sector 16 (offset 0x8001).
  if (data.size() < 0x8006 ||
      std::memcmp(data.data() + 0x8001, "CD001", 5) != 0) {
    return a;
  }
  a.isIso = true;

  // Bound the content sweep so a multi-GB image can't stall the scan.
  constexpr size_t kSweep = 64u * 1024u * 1024u;
  // Embedded PE: the universal DOS-stub string (near-zero false positives).
  a.containsExecutable =
      FindAscii(data, "This program cannot be run in DOS mode", kSweep);
  // Embedded shell-link: the .lnk header size + LinkCLSID prefix
  // (4C 00 00 00  01 14 02 00) -- same anchor the magic typer uses for .lnk.
  static const uint8_t kLnk[] = {0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00};
  a.containsLnk = FindBytes(data, kLnk, sizeof(kLnk), kSweep);
  // The classic lure is a SMALL image (a few MB) carrying a payload -- a real
  // installer ISO is hundreds of MB.
  a.smallLure = data.size() <= (5u * 1024u * 1024u) &&
                (a.containsExecutable || a.containsLnk);

  if (a.containsLnk && a.containsExecutable) {
    a.findings.push_back(
        {"iso.lnk_plus_exe",
         "ISO image bundles a shell-link (.lnk) and a hidden executable -- the "
         "classic mount-and-run lure (MOTW bypass)",
         55});
  } else if (a.containsExecutable) {
    a.findings.push_back(
        {"iso.embedded_exe",
         "ISO image carries an embedded executable (MOTW-bypass delivery)", 30});
  } else if (a.containsLnk) {
    a.findings.push_back(
        {"iso.embedded_lnk",
         "ISO image carries a shell-link (.lnk) -- common lure component", 20});
  }
  if (a.smallLure) {
    a.findings.push_back(
        {"iso.small_payload_image",
         "Small ISO image (<= 5 MB) carrying a payload -- typical of a malware "
         "delivery lure, not a real installer",
         15});
  }
  return a;
}

} // namespace antimal
