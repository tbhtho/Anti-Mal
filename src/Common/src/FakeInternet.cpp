#include "antimal/FakeInternet.h"

#include <cstring>
#include <initializer_list>

namespace antimal::net {

namespace {

constexpr uint16_t kEthArp = 0x0806;
constexpr uint16_t kEthIpv4 = 0x0800;
constexpr uint8_t kIpProtoIcmp = 1;
constexpr uint8_t kIpProtoTcp = 6;
constexpr uint8_t kIpProtoUdp = 17;

constexpr std::size_t kEthHdr = 14;   // dst[6] src[6] type[2]
constexpr std::size_t kArpLen = 28;   // ARP packet body
constexpr std::size_t kIpMinHdr = 20; // IPv4 header (no options)
constexpr std::size_t kIcmpHdr = 8;   // type code cksum id seq
constexpr std::size_t kUdpHdr = 8;    // srcPort dstPort length checksum
constexpr std::size_t kDnsHdr = 12;   // id flags qd an ns ar
constexpr std::size_t kTcpHdr = 20;   // TCP header without options

// IPv4 transport checksum over the pseudo-header (srcIP, dstIP, 0, proto, len) +
// the L4 header & data. `seg` points at the L4 header (checksum field zeroed).
uint16_t L4Checksum(const uint8_t *srcIp, const uint8_t *dstIp, uint8_t proto,
                    const uint8_t *seg, std::size_t segLen) {
  uint32_t sum = 0;
  auto add = [&](const uint8_t *p, std::size_t n) {
    for (std::size_t i = 0; i + 1 < n; i += 2)
      sum += static_cast<uint32_t>((p[i] << 8) | p[i + 1]);
    if (n & 1) sum += static_cast<uint32_t>(p[n - 1]) << 8;
  };
  add(srcIp, 4);
  add(dstIp, 4);
  sum += proto;  // leading zero byte + protocol
  sum += static_cast<uint32_t>(segLen & 0xFFFF);
  add(seg, segLen);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

// UDP: a computed checksum of 0 is transmitted as 0xFFFF (0 means "none").
uint16_t UdpChecksum(const uint8_t *srcIp, const uint8_t *dstIp,
                     const uint8_t *udp, std::size_t udpLen) {
  const uint16_t c = L4Checksum(srcIp, dstIp, kIpProtoUdp, udp, udpLen);
  return c == 0 ? 0xFFFF : c;
}

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
  const std::size_t l4Off = kEthHdr + ihl;
  const std::size_t l4Len = static_cast<std::size_t>(totalLen) - ihl;

  // UDP: only DNS (port 53) is synthesized for now — the highest-value sink
  // behavior (C2 domain resolution succeeds so the sample proceeds).
  if (ip[9] == kIpProtoUdp) {
    if (l4Len < kUdpHdr || l4Off + l4Len > len) {
      ++framesDropped_;
      return false;
    }
    const uint16_t dport = RdBE16(f + l4Off + 2);  // UDP dst port
    if (dport == 53) return HandleDns(f, ihl, l4Off, l4Len, out);
    if (dport == 67) return HandleDhcp(f, ihl, l4Off, l4Len, out);
    return false;  // other UDP ports: no reply (yet)
  }
  if (ip[9] == kIpProtoTcp) {
    return HandleTcp(f, ihl, l4Off, l4Len, out);
  }
  if (ip[9] != kIpProtoIcmp) return false;  // unsupported L4 protocol

  const std::size_t icmpOff = l4Off;
  const std::size_t icmpLen = l4Len;
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

bool FakeInternet::HandleDns(const uint8_t *f, std::size_t ihl,
                             std::size_t udpOff, std::size_t udpLen,
                             std::vector<Frame> &out) {
  // The DNS message sits after the 8-byte UDP header.
  const std::size_t dnsOff = udpOff + kUdpHdr;
  const std::size_t dnsLen = udpLen - kUdpHdr;
  if (dnsLen < kDnsHdr) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *dns = f + dnsOff;
  const uint16_t qd = RdBE16(dns + 4);
  if (qd != 1) return false;  // only single-question queries (the common case)
  if (dns[2] & 0x80) return false;  // already a response (QR set) — ignore

  // Parse the single question's name length (labels until a 0 byte or a
  // compression pointer), strictly bounded by the DNS message length.
  std::size_t p = kDnsHdr;  // offset within the DNS message
  bool nameOk = false;
  while (p < dnsLen) {
    const uint8_t l = dns[p];
    if (l == 0) {
      ++p;  // root label terminator
      nameOk = true;
      break;
    }
    if ((l & 0xC0) == 0xC0) {  // compression pointer (2 bytes) ends the name
      p += 2;
      nameOk = (p <= dnsLen);
      break;
    }
    p += static_cast<std::size_t>(l) + 1;  // label length byte + label
  }
  if (!nameOk || p + 4 > dnsLen) {  // need QTYPE(2) + QCLASS(2)
    ++framesDropped_;
    return false;
  }
  const std::size_t questionLen = p + 4;  // name + qtype + qclass
  const uint16_t qtype = RdBE16(dns + p);
  const bool answerA = (qtype == 1);  // A record -> resolve to the sink IP

  // Build the DNS response: echo header (flags = response) + the question +
  // (for an A query) one answer pointing the name back at offset 12 (0xC00C).
  std::vector<uint8_t> resp;
  resp.reserve(questionLen + 16);
  resp.insert(resp.end(), dns, dns + questionLen);  // header + question verbatim
  WrBE16(resp.data(), RdBE16(dns));                 // transaction id (echo)
  WrBE16(resp.data() + 2, 0x8180);  // QR=1, RD=1, RA=1, rcode=0 (no error)
  WrBE16(resp.data() + 4, 1);       // qdcount
  WrBE16(resp.data() + 6, answerA ? 1 : 0);  // ancount
  WrBE16(resp.data() + 8, 0);       // nscount
  WrBE16(resp.data() + 10, 0);      // arcount
  if (answerA) {
    const uint8_t answer[16] = {
        0xC0, 0x0C,             // name: pointer to offset 12 (the question name)
        0x00, 0x01,             // type A
        0x00, 0x01,             // class IN
        0x00, 0x00, 0x00, 0x3C, // TTL 60s
        0x00, 0x04,             // rdlength 4
        static_cast<uint8_t>((ip_ >> 24) & 0xFF),
        static_cast<uint8_t>((ip_ >> 16) & 0xFF),
        static_cast<uint8_t>((ip_ >> 8) & 0xFF),
        static_cast<uint8_t>(ip_ & 0xFF)};  // rdata = sink IP (big-endian)
    resp.insert(resp.end(), answer, answer + sizeof(answer));
  }

  // Assemble Ethernet + IPv4 + UDP + DNS reply.
  const std::size_t udpTotal = kUdpHdr + resp.size();
  const std::size_t ipTotal = ihl + udpTotal;  // reuse the request's IHL (no options assumed past 20 is fine to copy)
  Frame r(kEthHdr + ipTotal, 0);
  // Ethernet: dst = guest src, src = sink.
  std::memcpy(r.data(), f + 6, 6);
  std::memcpy(r.data() + 6, mac_.data(), 6);
  WrBE16(r.data() + 12, kEthIpv4);
  // IPv4 header: copy the request's header (preserves IHL/options), then fix up.
  uint8_t *rip = r.data() + kEthHdr;
  std::memcpy(rip, f + kEthHdr, ihl);
  WrBE16(rip + 2, static_cast<uint16_t>(ipTotal));  // total length
  WrBE16(rip + 4, 0);                               // id 0
  WrBE16(rip + 6, 0x4000);                          // flags = DF, no frag
  rip[8] = 64;                                      // TTL
  rip[9] = kIpProtoUdp;
  // src <- sink IP, dst <- the guest's source IP (from the request).
  uint8_t reqSrc[4];
  std::memcpy(reqSrc, f + kEthHdr + 12, 4);
  rip[12] = static_cast<uint8_t>((ip_ >> 24) & 0xFF);
  rip[13] = static_cast<uint8_t>((ip_ >> 16) & 0xFF);
  rip[14] = static_cast<uint8_t>((ip_ >> 8) & 0xFF);
  rip[15] = static_cast<uint8_t>(ip_ & 0xFF);
  std::memcpy(rip + 16, reqSrc, 4);
  rip[10] = rip[11] = 0;
  WrBE16(rip + 10, InternetChecksum(rip, ihl));
  // UDP header: src port 53, dst port = the query's src port.
  uint8_t *rudp = rip + ihl;
  WrBE16(rudp, 53);
  std::memcpy(rudp + 2, f + udpOff, 2);  // dst port = request's src port
  WrBE16(rudp + 4, static_cast<uint16_t>(udpTotal));
  rudp[6] = rudp[7] = 0;  // checksum 0 before recompute
  std::memcpy(rudp + kUdpHdr, resp.data(), resp.size());
  WrBE16(rudp + 6, UdpChecksum(rip + 12, rip + 16, rudp, udpTotal));

  out.push_back(std::move(r));
  ++dnsReplies_;
  return true;
}

bool FakeInternet::HandleDhcp(const uint8_t *f, std::size_t ihl,
                              std::size_t udpOff, std::size_t udpLen,
                              std::vector<Frame> &out) {
  // BOOTP/DHCP message starts after the UDP header. Need at least the fixed
  // 236-byte BOOTP region + 4-byte magic cookie before options.
  const std::size_t bootpOff = udpOff + kUdpHdr;
  const std::size_t bootpLen = udpLen - kUdpHdr;
  constexpr std::size_t kBootpFixed = 236;
  if (bootpLen < kBootpFixed + 4) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *bootp = f + bootpOff;
  if (bootp[0] != 1) return false;  // op must be BOOTREQUEST
  // Magic cookie 0x63825363 precedes the options.
  if (!(bootp[236] == 0x63 && bootp[237] == 0x82 && bootp[238] == 0x53 &&
        bootp[239] == 0x63)) {
    ++framesDropped_;
    return false;
  }
  // Walk options for the DHCP message type (option 53), strictly bounded.
  uint8_t msgType = 0;
  for (std::size_t o = 240; o < bootpLen;) {
    const uint8_t code = bootp[o++];
    if (code == 0) continue;       // pad
    if (code == 255) break;        // end
    if (o >= bootpLen) break;      // truncated (no length byte)
    const uint8_t l = bootp[o++];
    if (o + l > bootpLen) break;   // truncated option data
    if (code == 53 && l >= 1) msgType = bootp[o];
    o += l;
  }
  uint8_t replyType = 0;
  if (msgType == 1) replyType = 2;       // DISCOVER -> OFFER
  else if (msgType == 3) replyType = 5;  // REQUEST  -> ACK
  else return false;                     // ignore RELEASE/INFORM/etc. for now

  // The guest gets sink_ip with the host octet replaced by .15, mask /24, and
  // the sink as both router and DNS — so DNS queries land back on the sink.
  const uint32_t offeredIp = (ip_ & 0xFFFFFF00u) | 0x0Fu;  // x.x.x.15
  auto put4 = [](uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
  };

  // Build the BOOTREPLY: 236 fixed + cookie + options + end.
  std::vector<uint8_t> dhcp(kBootpFixed + 4, 0);
  dhcp[0] = 2;            // op = BOOTREPLY
  dhcp[1] = bootp[1];     // htype (echo)
  dhcp[2] = bootp[2];     // hlen
  std::memcpy(&dhcp[4], bootp + 4, 4);    // xid (echo)
  std::memcpy(&dhcp[10], bootp + 10, 2);  // flags (echo)
  put4(&dhcp[16], offeredIp);             // yiaddr = offered address
  put4(&dhcp[20], ip_);                   // siaddr = sink (next server)
  std::memcpy(&dhcp[28], bootp + 28, 16); // chaddr (echo client hw addr)
  dhcp[236] = 0x63; dhcp[237] = 0x82; dhcp[238] = 0x53; dhcp[239] = 0x63;  // cookie
  auto opt = [&](uint8_t code, std::initializer_list<uint8_t> data) {
    dhcp.push_back(code);
    dhcp.push_back(static_cast<uint8_t>(data.size()));
    for (uint8_t b : data) dhcp.push_back(b);
  };
  opt(53, {replyType});  // DHCP message type (offer/ack)
  uint8_t sip[4]; put4(sip, ip_);
  opt(54, {sip[0], sip[1], sip[2], sip[3]});           // server id
  opt(51, {0x00, 0x01, 0x51, 0x80});                   // lease time 86400s
  opt(1, {0xFF, 0xFF, 0xFF, 0x00});                    // subnet mask /24
  opt(3, {sip[0], sip[1], sip[2], sip[3]});            // router = sink
  opt(6, {sip[0], sip[1], sip[2], sip[3]});            // DNS = sink
  dhcp.push_back(255);                                 // end

  // Wrap: Ethernet (to client MAC) + IPv4 (sink -> broadcast) + UDP (67 -> 68).
  const std::size_t udpTotal = kUdpHdr + dhcp.size();
  const std::size_t ipTotal = ihl + udpTotal;
  Frame r(kEthHdr + ipTotal, 0);
  std::memcpy(r.data(), f + 6, 6);            // dst = the requesting client
  std::memcpy(r.data() + 6, mac_.data(), 6);  // src = sink
  WrBE16(r.data() + 12, kEthIpv4);
  uint8_t *rip = r.data() + kEthHdr;
  std::memcpy(rip, f + kEthHdr, ihl);
  WrBE16(rip + 2, static_cast<uint16_t>(ipTotal));
  WrBE16(rip + 4, 0);
  WrBE16(rip + 6, 0x0000);  // allow fragmentation flags cleared
  rip[8] = 64;
  rip[9] = kIpProtoUdp;
  put4(rip + 12, ip_);          // src = sink
  rip[16] = rip[17] = rip[18] = rip[19] = 0xFF;  // dst = 255.255.255.255
  rip[10] = rip[11] = 0;
  WrBE16(rip + 10, InternetChecksum(rip, ihl));
  uint8_t *rudp = rip + ihl;
  WrBE16(rudp, 67);       // src port (server)
  WrBE16(rudp + 2, 68);   // dst port (client)
  WrBE16(rudp + 4, static_cast<uint16_t>(udpTotal));
  rudp[6] = rudp[7] = 0;
  std::memcpy(rudp + kUdpHdr, dhcp.data(), dhcp.size());
  WrBE16(rudp + 6, UdpChecksum(rip + 12, rip + 16, rudp, udpTotal));

  out.push_back(std::move(r));
  ++dhcpReplies_;
  return true;
}

bool FakeInternet::HandleTcp(const uint8_t *f, std::size_t ihl,
                             std::size_t tcpOff, std::size_t tcpLen,
                             std::vector<Frame> &out) {
  if (tcpLen < kTcpHdr || tcpOff + tcpLen > 0xFFFFFFFFu) {
    ++framesDropped_;
    return false;
  }
  const uint8_t *tcp = f + tcpOff;
  const uint8_t flags = tcp[13];
  const bool syn = (flags & 0x02) != 0;
  const bool ack = (flags & 0x10) != 0;
  // Only complete the handshake on a bare SYN (SYN, no ACK). A SYN-ACK back lets
  // the guest's connection to the (resolved) C2 establish so it sends its first
  // data payload — the high-value capture. Subsequent data is captured on TX;
  // an application responder (HTTP/etc.) is a later slice.
  if (!syn || ack) return false;

  const uint16_t srcPort = RdBE16(tcp);      // client's source port
  const uint16_t dstPort = RdBE16(tcp + 2);  // server port (the contacted port)
  uint32_t clientSeq = 0;
  for (int i = 0; i < 4; ++i) clientSeq = (clientSeq << 8) | tcp[4 + i];

  // Build a 20-byte (no options) SYN-ACK over a fresh IPv4 datagram.
  const std::size_t synAckTcp = kTcpHdr;
  const std::size_t ipTotal = ihl + synAckTcp;
  Frame r(kEthHdr + ipTotal, 0);
  std::memcpy(r.data(), f + 6, 6);            // Ethernet dst = guest src
  std::memcpy(r.data() + 6, mac_.data(), 6);  // Ethernet src = sink
  WrBE16(r.data() + 12, kEthIpv4);

  uint8_t *rip = r.data() + kEthHdr;
  std::memcpy(rip, f + kEthHdr, ihl);  // copy the request IP header (keeps IHL)
  WrBE16(rip + 2, static_cast<uint16_t>(ipTotal));
  WrBE16(rip + 4, 0);
  WrBE16(rip + 6, 0x4000);  // DF
  rip[8] = 64;
  rip[9] = kIpProtoTcp;
  uint8_t reqSrcIp[4], reqDstIp[4];
  std::memcpy(reqSrcIp, f + kEthHdr + 12, 4);
  std::memcpy(reqDstIp, f + kEthHdr + 16, 4);
  std::memcpy(rip + 12, reqDstIp, 4);  // src = the server the guest dialed
  std::memcpy(rip + 16, reqSrcIp, 4);  // dst = the guest
  rip[10] = rip[11] = 0;
  WrBE16(rip + 10, InternetChecksum(rip, ihl));

  uint8_t *rtcp = rip + ihl;
  WrBE16(rtcp, dstPort);      // src port = the contacted server port
  WrBE16(rtcp + 2, srcPort);  // dst port = the client's source port
  // Server ISN (deterministic; arbitrary). ack = client seq + 1 (SYN consumes 1).
  const uint32_t serverIsn = 0x10000000u;
  const uint32_t ackNum = clientSeq + 1u;
  for (int i = 0; i < 4; ++i) rtcp[4 + i] = static_cast<uint8_t>((serverIsn >> (24 - i * 8)) & 0xFF);
  for (int i = 0; i < 4; ++i) rtcp[8 + i] = static_cast<uint8_t>((ackNum >> (24 - i * 8)) & 0xFF);
  rtcp[12] = 0x50;  // data offset = 5 (20 bytes), no options
  rtcp[13] = 0x12;  // flags = SYN | ACK
  WrBE16(rtcp + 14, 0xFFFF);  // window
  rtcp[16] = rtcp[17] = 0;    // checksum (zeroed before recompute)
  rtcp[18] = rtcp[19] = 0;    // urgent pointer
  WrBE16(rtcp + 16, L4Checksum(rip + 12, rip + 16, kIpProtoTcp, rtcp, synAckTcp));

  out.push_back(std::move(r));
  ++tcpReplies_;
  return true;
}

}  // namespace antimal::net
