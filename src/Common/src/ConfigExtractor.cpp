#include "antimal/ConfigExtractor.h"

#include <algorithm>
#include <array>

namespace antimal {
namespace {

uint16_t Be16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) << 8 | p[1];
}
uint32_t Be32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 | p[3];
}

std::string Trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' ||
                   s[b - 1] == '\n' || s[b - 1] == '\0')) --b;
  return s.substr(a, b - a);
}

// CS beacon config TLV: index(2 BE) type(2 BE) length(2 BE) value(length).
// type 1 = short, 2 = int, 3 = data/string. Block ends at an index-0 record.
bool ParseTlv(const std::vector<uint8_t> &dec, CobaltStrikeConfig &cfg) {
  size_t p = 0;
  int records = 0, known = 0;
  while (p + 6 <= dec.size() && records < 512) {
    const uint16_t index = Be16(&dec[p]);
    const uint16_t type = Be16(&dec[p + 2]);
    const uint16_t len = Be16(&dec[p + 4]);
    p += 6;
    if (index == 0) break;               // terminator
    if (type != 1 && type != 2 && type != 3) break; // ran off the valid block
    if (len > dec.size() - p) break;     // bounds
    const uint8_t *v = &dec[p];
    switch (index) {
      case 1: if (type == 1 && len >= 2) { cfg.beaconType = Be16(v); ++known; } break;
      case 2: if (type == 1 && len >= 2) { cfg.port = Be16(v); ++known; } break;
      case 3: if (type == 2 && len >= 4) { cfg.sleepMs = Be32(v); ++known; } break;
      case 5: if (type == 1 && len >= 2) { cfg.jitter = Be16(v); ++known; } break;
      case 8:
        if (type == 3) {
          cfg.c2Raw = Trim(std::string(reinterpret_cast<const char *>(v), len));
          ++known;
        }
        break;
      case 9:
        if (type == 3) {
          cfg.userAgent = Trim(std::string(reinterpret_cast<const char *>(v), len));
          ++known;
        }
        break;
      case 37: if (type == 2 && len >= 4) { cfg.watermark = Be32(v); ++known; } break;
      default: break;
    }
    p += len;
    ++records;
  }
  return known > 0;
}

void ParseC2(CobaltStrikeConfig &cfg) {
  // The index-8 string is comma-separated host(s) + request URI(s).
  std::string token;
  auto flush = [&]() {
    const std::string t = Trim(token);
    token.clear();
    if (t.empty()) return;
    if (t[0] == '/') {
      if (std::find(cfg.uris.begin(), cfg.uris.end(), t) == cfg.uris.end())
        cfg.uris.push_back(t);
    } else if (t.find('.') != std::string::npos) {
      if (std::find(cfg.c2Servers.begin(), cfg.c2Servers.end(), t) == cfg.c2Servers.end())
        cfg.c2Servers.push_back(t);
    }
  };
  for (char c : cfg.c2Raw) {
    if (c == ',' || c == '\n' || c == '\t') flush();
    else token.push_back(c);
  }
  flush();
}

} // namespace

CobaltStrikeConfig ExtractCobaltStrikeConfig(const std::vector<uint8_t> &data) {
  if (data.size() < 8) return {};
  // The decoded config opens with index=1,type=1,length=2: bytes 00 01 00 01 00 02.
  // Encoded in-file = those XORed by the single-byte key. Scan for each key's
  // encoded signature, then decode + parse a bounded chunk from that offset.
  for (const uint8_t key : {static_cast<uint8_t>(0x2e), static_cast<uint8_t>(0x69)}) {
    const std::array<uint8_t, 6> sig = {
        static_cast<uint8_t>(0x00 ^ key), static_cast<uint8_t>(0x01 ^ key),
        static_cast<uint8_t>(0x00 ^ key), static_cast<uint8_t>(0x01 ^ key),
        static_cast<uint8_t>(0x00 ^ key), static_cast<uint8_t>(0x02 ^ key)};
    auto it = data.begin();
    while ((it = std::search(it, data.end(), sig.begin(), sig.end())) != data.end()) {
      const size_t off = static_cast<size_t>(it - data.begin());
      const size_t chunk = std::min<size_t>(16384, data.size() - off);
      std::vector<uint8_t> dec(chunk);
      for (size_t i = 0; i < chunk; ++i) dec[i] = data[off + i] ^ key;
      CobaltStrikeConfig cfg;
      // Require real beacon corroboration beyond the 6-byte signature (which is
      // itself the first TLV record): a genuine config always carries a C2 and
      // a port. This makes a chance signature hit in benign data a non-event.
      if (ParseTlv(dec, cfg) && cfg.port != 0 && !cfg.c2Raw.empty()) {
        cfg.found = true;
        cfg.xorKey = key;
        ParseC2(cfg);
        return cfg;
      }
      ++it; // signature matched but no valid config followed: keep scanning
    }
  }
  return {};
}

} // namespace antimal
