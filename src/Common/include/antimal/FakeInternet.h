#pragma once

// In-process fake-internet / INetSim-style sink for the contained-network path.
//
// CRITICAL INVARIANT (preserves zero-egress): the sink NEVER opens a host socket
// and never touches real network state. It is a pure function of the guest's
// transmitted Ethernet frame → zero or more synthesized reply frames. The
// orchestrator wires it behind the e1000e NIC: guest TX frame → OnGuestFrame →
// reply frames → E1000Device::DeliverRxFrame (into the guest RX ring). This lets
// a detonated sample resolve DNS, get ARP/ICMP/TCP replies, and exhibit real
// network behavior we can capture — without granting any real internet.
//
// Every parser is bounds-checked against the (untrusted) guest frame length;
// malformed frames yield no reply rather than reading out of bounds. This is a
// §7 escape-audit + fuzz target (TestFakeInternetFuzz).
//
// Scope today: Ethernet framing + ARP (who-has → is-at) + IPv4/ICMP echo
// (ping → reply). DNS (resolve-all) and TCP (SYN→SYN-ACK) handshake follow.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace antimal::net {

using Mac = std::array<uint8_t, 6>;
using Frame = std::vector<uint8_t>;

class FakeInternet {
 public:
  // `sinkMac` is the MAC the sink answers as (the "gateway"); `sinkIpBe` is its
  // IPv4 address in network byte order (big-endian, e.g. 10.0.2.3). The sink
  // answers ARP for ANY requested IP (it is the whole internet) with sinkMac.
  FakeInternet(Mac sinkMac, uint32_t sinkIpBe) : mac_(sinkMac), ip_(sinkIpBe) {}

  // Process one guest-transmitted Ethernet frame; append any reply frames to
  // `out`. Returns the number of replies appended. Pure + bounds-checked.
  size_t OnGuestFrame(const uint8_t *frame, std::size_t len, std::vector<Frame> &out);

  // Diagnostics (cumulative).
  uint64_t ArpReplies() const noexcept { return arpReplies_; }
  uint64_t IcmpReplies() const noexcept { return icmpReplies_; }
  uint64_t DnsReplies() const noexcept { return dnsReplies_; }
  uint64_t TcpReplies() const noexcept { return tcpReplies_; }
  uint64_t HttpReplies() const noexcept { return httpReplies_; }
  uint64_t DhcpReplies() const noexcept { return dhcpReplies_; }
  uint64_t FramesSeen() const noexcept { return framesSeen_; }
  uint64_t FramesDropped() const noexcept { return framesDropped_; }

  const Mac &SinkMac() const noexcept { return mac_; }
  uint32_t SinkIpBe() const noexcept { return ip_; }

 private:
  bool HandleArp(const uint8_t *f, std::size_t len, std::vector<Frame> &out);
  bool HandleIpv4(const uint8_t *f, std::size_t len, std::vector<Frame> &out);
  // UDP/53 DNS query -> resolve-all A response (every name -> the sink IP). `ihl`
  // is the IPv4 header length; `udpOff`/`udpLen` bound the UDP datagram.
  bool HandleDns(const uint8_t *f, std::size_t ihl, std::size_t udpOff,
                 std::size_t udpLen, std::vector<Frame> &out);
  // TCP SYN -> SYN-ACK so the guest's connection to the contacted endpoint
  // establishes (and it sends its first data payload). `ihl` is the IPv4 header
  // length; `tcpOff`/`tcpLen` bound the TCP segment.
  bool HandleTcp(const uint8_t *f, std::size_t ihl, std::size_t tcpOff,
                 std::size_t tcpLen, std::vector<Frame> &out);
  // DHCP DISCOVER -> OFFER / REQUEST -> ACK so the guest auto-configures an IP,
  // gateway, and DNS server all pointing at the sink (the keystone that makes
  // the contained network usable: the guest then resolves + connects).
  bool HandleDhcp(const uint8_t *f, std::size_t ihl, std::size_t udpOff,
                  std::size_t udpLen, std::vector<Frame> &out);

  Mac mac_;
  uint32_t ip_;  // big-endian
  uint64_t arpReplies_ = 0;
  uint64_t icmpReplies_ = 0;
  uint64_t dnsReplies_ = 0;
  uint64_t tcpReplies_ = 0;
  uint64_t httpReplies_ = 0;
  uint64_t dhcpReplies_ = 0;
  uint64_t framesSeen_ = 0;
  uint64_t framesDropped_ = 0;
};

// Ones-complement Internet checksum (RFC 1071) over `len` bytes. Exposed for
// reuse + unit testing.
uint16_t InternetChecksum(const uint8_t *data, std::size_t len);

}  // namespace antimal::net
