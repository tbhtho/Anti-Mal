#pragma once

// Network-request interpretation for the dynamic-detonation path — turns raw
// guest-transmitted Ethernet frames into high-signal "what is the sample
// requesting" EventRecords: DNS queries, HTTP requests, and TCP connects.
//
// This is the parsing half of network visibility (SP3). A virtual NIC device
// (the multi-week emulation half) captures the guest's outbound frames on its TX
// path and hands each to InspectEthernetFrame; the resulting events stream like
// any other telemetry. Keeping the parser standalone means it is PURE and
// bounds-checked, so it is unit-tested here and is also a hardened surface (it
// parses untrusted guest bytes — every read is length-guarded).

#include "antimal/Types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

struct ParsedIpv4 {
  bool ok = false;
  uint8_t protocol = 0;  // 6 = TCP, 17 = UDP
  std::string srcAddr;
  std::string dstAddr;
  const uint8_t *payload = nullptr;  // points into the caller's buffer
  size_t payloadLen = 0;
};

// Parses an IPv4 packet. Bounds-checked; ok=false on anything malformed.
ParsedIpv4 ParseIpv4(const uint8_t *ip, size_t len);

// Extracts the first DNS question name ("example.com") from a DNS message, or ""
// if absent/malformed. Does not follow compression pointers (questions don't use
// them) and is loop-guarded.
std::string ParseDnsQueryName(const uint8_t *dns, size_t len);

// Parses an HTTP request prefix. Returns true and fills method/path/host when the
// payload begins with a known HTTP method; false otherwise.
bool ParseHttpRequest(const uint8_t *data, size_t len, std::string &method,
                      std::string &path, std::string &host);

// Extracts the SNI host_name from a TLS ClientHello, or "" if the payload is not
// a ClientHello / has no SNI / is malformed. This is the no-MITM way to recover
// an HTTPS C2's hostname: the destination is plaintext in the ClientHello even
// though the rest of the session is encrypted. Strictly bounds-checked (parses
// untrusted guest bytes); does not require completing or decrypting the session.
std::string ParseTlsClientHelloSni(const uint8_t *data, size_t len);

// Inspects one outbound Ethernet frame and returns the network events it implies
// (network.connect for a SYN, network.dns for a port-53 query, network.http for a
// port-80 request). Returns {} for frames it doesn't recognize.
std::vector<EventRecord> InspectEthernetFrame(const uint8_t *frame, size_t len);

}  // namespace antimal
