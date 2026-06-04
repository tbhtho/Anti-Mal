#pragma once

// Live network-connection telemetry for the dynamic-detonation path — "what is
// the sample connecting to?". Mirrors ProcessTelemetry: the GuestAgent snapshots
// the guest TCP table and diffs consecutive snapshots into network.connect /
// network.close EventRecords streamed to the host over COM2.
//
// Split across two translation units on purpose:
//   * DiffTcpConnections (NetworkTelemetry.cpp) is PURE + deterministic, so it is
//     unit-tested on the host with no guest and pulls no extra libraries.
//   * CaptureTcpConnections (NetworkCapture.cpp) wraps GetExtendedTcpTable and is
//     the only piece that links iphlpapi — so only the GuestAgent pays for it.
//
// This data path is ready now; it lights up fully once the VM has a virtual NIC
// (SP3). Until then it still captures loopback / local connections.

#include "antimal/Types.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace antimal {

struct TcpConnection {
  uint32_t pid = 0;
  std::string localAddress;   // "10.0.2.15"
  uint16_t localPort = 0;
  std::string remoteAddress;  // "93.184.216.34"
  uint16_t remotePort = 0;
  std::string state;          // "SYN_SENT", "ESTABLISHED", "CLOSE_WAIT", ...
};

// Canonical identity key (pid + 5-tuple, excluding state so a state transition
// is not seen as a close+reopen). Keyed map keeps diff output deterministic.
std::string TcpConnectionKey(const TcpConnection &c);

using TcpSnapshot = std::map<std::string, TcpConnection>;

// Captures the current guest TCP table (IPv4, owner-pid). Listeners are skipped
// (noise). Returns {} on failure. Windows-only; the host tests exercise
// DiffTcpConnections directly.
TcpSnapshot CaptureTcpConnections();

// Diffs two snapshots into telemetry events.
//   emitBaseline == true : emit up to baselineCap "network.connection" events for
//       the entries in `cur` (the first snapshot, so the UI shows what is already
//       connected).
//   emitBaseline == false: "network.connect" for keys in `cur` not in `prev`
//       (capped at deltaCap) and "network.close" for keys in `prev` not in `cur`
//       (uncapped). Each event is source="GuestAgent", category="network",
//       processId=pid, target="remoteAddress:remotePort".
std::vector<EventRecord> DiffTcpConnections(const TcpSnapshot &prev,
                                            const TcpSnapshot &cur,
                                            bool emitBaseline, size_t baselineCap,
                                            size_t deltaCap);

}  // namespace antimal
