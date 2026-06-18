#pragma once

#include <cstdint>
#include <string>

namespace antimal {

// Classify a network endpoint ("IP:port" or "host:port") into the service the
// port implies and whether it's noteworthy for triage. The in-guest telemetry is
// 5-tuples only; this adds the analyst-facing "what is this talking to" layer to
// the report's network panel (Any.Run shows a protocol/service per connection).
struct NetworkIndicator {
  uint16_t port = 0;
  std::string service;   // "HTTPS", "DNS", "SMB", "" if unknown
  bool privateAddr = false; // RFC1918 / loopback / link-local remote
  bool bogon = false;       // reserved / non-routable (TEST-NET, CGNAT, 0/8, 224+/4)
  bool suspicious = false;  // known-C2 / Tor / IRC / cleartext-cred / odd-public / bogon
  std::string note;         // why it's suspicious ("" otherwise)
};

// Parse + classify. Tolerant of "host:port", "ip:port", and bare "ip" (port 0).
NetworkIndicator ClassifyEndpoint(const std::string &remote);

} // namespace antimal
