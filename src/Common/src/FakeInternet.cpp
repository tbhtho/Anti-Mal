#include "antimal/FakeInternet.h"

#include <cstring>

namespace antimal::net {

namespace {

constexpr uint16_t kEthArp = 0x0806;
constexpr uint16_t kEthIpv4 = 0x0800;
constexpr uint8_t kIpProtoIcmp = 1;

constexpr std::size_t kEthHdr = 14;   // dst[6] src[6] type[2]
constexpr std::size_t kArpLen = 28;   // ARP packet body
constexpr std::size_t kIpMinHdr = 20; // IPv4 header (no options)
constexpr std::size_t kIcmpHdr = 8;   // type code cksum id seq

uint16_t RdBE16(const uint8_t *p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
void WrBE16(uint8_t *p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}

}  // namespace

uint16_t InternetChecksum(const uint8_t *data, std::size_t len) {
  uint32_t sum = 0;
  for (std::size_t i = 0; i + 1 < len; i += 2) {
    sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
  }
  if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

size_t FakeInternet::OnGuestFrame(const uint8_t *frame, std::size_t len,
                                  std::vector<Frame> &out) {
  if (!frame || len < kEthHdr) {
    ++framesDropped_;
    return 0;
  }
  ++framesSeen_;
  const uint16_t ethType = RdBE16(frame + 12);
  const std::size_t before = out.size();
  if (ethType == kEthArp) {
    HandleArp(frame, len, out);
  } else if (ethType == kEthIpv4) {
    HandleIpv4(frame, len, out);
  } else {
    ++framesDropped_;  // ethertype we don't synthesize for (yet)
  }
  return out.size() - before;
}

bool FakeInternet::HandleArp(const uint8_t *f, std::size_t len,
                             std::vector<Frame> &out) {
  if (len < kEthHdr + kArpLen) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *arp = f + kEthHdr;
  // htype=Ethernet(1), ptype=IPv4(0x0800), hlen=6, plen=4, opcode=request(1).
  if (RdBE16(arp) != 0x0001 || RdBE16(arp + 2) != 0x0800 || arp[4] != 6 ||
      arp[5] != 4) {
    ++framesDropped_;
    return false;
  }
  if (RdBE16(arp + 6) != 1) return false;  // only answer requests
  const uint8_t *senderMac = arp + 8;
  const uint8_t *senderIp = arp + 14;
  const uint8_t *targetIp = arp + 24;  // the IP the guest wants resolved

  Frame r(kEthHdr + kArpLen, 0);
  std::memcpy(r.data(), senderMac, 6);        // Ethernet dst = requester
  std::memcpy(r.data() + 6, mac_.data(), 6);  // Ethernet src = sink
  WrBE16(r.data() + 12, kEthArp);
  uint8_t *a = r.data() + kEthHdr;
  WrBE16(a, 0x0001);      // htype Ethernet
  WrBE16(a + 2, 0x0800);  // ptype IPv4
  a[4] = 6;
  a[5] = 4;
  WrBE16(a + 6, 2);                       // opcode = reply
  std::memcpy(a + 8, mac_.data(), 6);     // sender MAC = sink (we are this IP)
  std::memcpy(a + 14, targetIp, 4);       // sender IP = the asked-about IP
  std::memcpy(a + 18, senderMac, 6);      // target MAC = requester
  std::memcpy(a + 24, senderIp, 4);       // target IP = requester
  out.push_back(std::move(r));
  ++arpReplies_;
  return true;
}

bool FakeInternet::HandleIpv4(const uint8_t *f, std::size_t len,
                              std::vector<Frame> &out) {
  if (len < kEthHdr + kIpMinHdr) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *ip = f + kEthHdr;
  const uint8_t ver = ip[0] >> 4;
  const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
  if (ver != 4 || ihl < kIpMinHdr || kEthHdr + ihl > len) {
    ++framesDropped_;
    return false;
  }
  const uint16_t totalLen = RdBE16(ip + 2);
  if (totalLen < ihl || kEthHdr + totalLen > len) {
    ++framesDropped_;  // truncated / lying length — don't trust it
    return false;
  }
  if (ip[9] != kIpProtoIcmp) return false;  // TCP/UDP/DNS in later slices

  const std::size_t icmpOff = kEthHdr + ihl;
  const std::size_t icmpLen = static_cast<std::size_t>(totalLen) - ihl;
  if (icmpLen < kIcmpHdr || icmpOff + icmpLen > len) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *icmp = f + icmpOff;
  if (icmp[0] != 8) return false;  // only echo request (8) -> echo reply (0)

  // Reply = the request frame up to the IP total length, with addresses swapped.
  Frame r(f, f + kEthHdr + totalLen);
  std::memcpy(r.data(), f + 6, 6);            // Ethernet dst = guest src
  std::memcpy(r.data() + 6, mac_.data(), 6);  // Ethernet src = sink

  uint8_t *rip = r.data() + kEthHdr;
  uint8_t srcIp[4], dstIp[4];
  std::memcpy(srcIp, rip + 12, 4);
  std::memcpy(dstIp, rip + 16, 4);
  std::memcpy(rip + 12, dstIp, 4);  // src <- dst
  std::memcpy(rip + 16, srcIp, 4);  // dst <- src (reply goes back to the guest)
  rip[10] = rip[11] = 0;            // IP checksum field -> 0 before recompute
  WrBE16(rip + 10, InternetChecksum(rip, ihl));

  uint8_t *ricmp = r.data() + icmpOff;
  ricmp[0] = 0;                 // type = echo reply
  ricmp[2] = ricmp[3] = 0;      // ICMP checksum -> 0 before recompute
  WrBE16(ricmp + 2, InternetChecksum(ricmp, icmpLen));

  out.push_back(std::move(r));
  ++icmpReplies_;
  return true;
}

}  // namespace antimal::net
