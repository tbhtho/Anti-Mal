// CaptureTcpConnections — the iphlpapi-backed half of NetworkTelemetry. This is
// the only translation unit that pulls iphlpapi, so only the GuestAgent (which
// actually captures) links it; host tests use the pure DiffTcpConnections.

#include "antimal/NetworkTelemetry.h"

#include <winsock2.h>
#include <ws2tcpip.h>
// <iphlpapi.h> must follow the winsock2 headers.
#include <iphlpapi.h>

#include <cstdio>

namespace antimal {
namespace {

// dwAddr is IPv4 in network byte order; its low byte is the first octet.
std::string Ipv4(DWORD addr) {
  const unsigned b0 = addr & 0xFFu;
  const unsigned b1 = (addr >> 8) & 0xFFu;
  const unsigned b2 = (addr >> 16) & 0xFFu;
  const unsigned b3 = (addr >> 24) & 0xFFu;
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b0, b1, b2, b3);
  return buf;
}

// The port lives in the low 16 bits of dwPort, in network byte order.
uint16_t Port(DWORD p) {
  return static_cast<uint16_t>(((p & 0xFFu) << 8) | ((p >> 8) & 0xFFu));
}

const char *StateName(DWORD s) {
  switch (s) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED";
    case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "UNKNOWN";
  }
}

}  // namespace

TcpSnapshot CaptureTcpConnections() {
  TcpSnapshot snap;
  ULONG size = 0;
  DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
  if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
    return snap;
  }
  std::vector<uint8_t> buffer(size);
  rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                           TCP_TABLE_OWNER_PID_ALL, 0);
  if (rc != NO_ERROR) {
    return snap;
  }
  const auto *table =
      reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(buffer.data());
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const MIB_TCPROW_OWNER_PID &row = table->table[i];
    if (row.dwState == MIB_TCP_STATE_LISTEN) {
      continue;  // listeners are noise for "what is it connecting to"
    }
    TcpConnection c;
    c.pid = row.dwOwningPid;
    c.localAddress = Ipv4(row.dwLocalAddr);
    c.localPort = Port(row.dwLocalPort);
    c.remoteAddress = Ipv4(row.dwRemoteAddr);
    c.remotePort = Port(row.dwRemotePort);
    c.state = StateName(row.dwState);
    snap[TcpConnectionKey(c)] = c;
  }
  return snap;
}

}  // namespace antimal
