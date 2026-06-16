#pragma once

// Malware config / C2 extractor.
//
// The single biggest gap between AntiMal's static layer and a commercial
// sandbox is config extraction: recovering the actual C2 a sample will talk to,
// statically, without detonation. This module starts with the highest-value
// target — the Cobalt Strike beacon, by far the most common C2 framework. A CS
// beacon embeds its settings as an XOR-encoded TLV block (single-byte key 0x2e
// in v3, 0x69 in v4) that begins with a recognizable signature; decoding it
// yields the C2 servers, port, user-agent, sleep/jitter, and watermark — a
// definitive, high-confidence malware verdict with the real IOCs attached.
//
// Pure + bounds-safe over untrusted bytes.

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct CobaltStrikeConfig {
  bool found = false;
  uint8_t xorKey = 0;       // the single-byte key that decoded it (0x2e or 0x69)
  uint16_t beaconType = 0;  // 0=HTTP, 8=HTTPS, 16=DNS, ...
  uint16_t port = 0;
  uint32_t sleepMs = 0;
  uint16_t jitter = 0;
  uint32_t watermark = 0;
  std::string userAgent;
  std::string c2Raw;                 // the raw index-8 C2 string
  std::vector<std::string> c2Servers; // host(s) parsed out of c2Raw
  std::vector<std::string> uris;      // request URIs parsed out of c2Raw
};

// Scan `data` for an embedded Cobalt Strike beacon configuration and decode it.
// Returns found=false when no CS config signature is present.
CobaltStrikeConfig ExtractCobaltStrikeConfig(const std::vector<uint8_t> &data);

} // namespace antimal
