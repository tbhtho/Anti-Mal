#include "antimal/PacketInspector.h"

#include "antimal/FileUtil.h"  // UtcNowIso8601

#include <cstring>

namespace antimal {

namespace {

std::string Ipv4Str(const uint8_t *p) {
  return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
         std::to_string(p[2]) + "." + std::to_string(p[3]);
}

uint16_t Be16(const uint8_t *p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

EventRecord MakeNetEvent(std::string action, std::string target) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "vm-network";
  ev.category = "network";
  ev.action = std::move(action);
  ev.target = std::move(target);
  return ev;
}

}  // namespace

ParsedIpv4 ParseIpv4(const uint8_t *ip, size_t len) {
  ParsedIpv4 r;
  if (!ip || len < 20) return r;
  if ((ip[0] >> 4) != 4) return r;  // version must be 4
  const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
  if (ihl < 20 || ihl > len) return r;
  size_t total = Be16(ip + 2);
  if (total < ihl || total > len) {
    total = len;  // clamp to what was actually captured
  }
  r.protocol = ip[9];
  r.srcAddr = Ipv4Str(ip + 12);
  r.dstAddr = Ipv4Str(ip + 16);
  r.payload = ip + ihl;
  r.payloadLen = total - ihl;
  r.ok = true;
  return r;
}

std::string ParseDnsQueryName(const uint8_t *dns, size_t len) {
  if (!dns || len < 12) return {};
  size_t pos = 12;  // skip the fixed DNS header
  std::string name;
  for (int guard = 0; guard < 128 && pos < len; ++guard) {
    const size_t labelLen = dns[pos++];
    if (labelLen == 0) break;          // end of name
    if (labelLen > 63) return {};      // compression / malformed in a question
    if (pos + labelLen > len) return {};
    if (!name.empty()) name.push_back('.');
    for (size_t i = 0; i < labelLen; ++i) {
      const char c = static_cast<char>(dns[pos + i]);
      name.push_back((c >= 32 && c < 127) ? c : '?');
    }
    pos += labelLen;
  }
  return name;
}

bool ParseHttpRequest(const uint8_t *data, size_t len, std::string &method,
                      std::string &path, std::string &host) {
  if (!data || len < 5) return false;
  const std::string s(reinterpret_cast<const char *>(data),
                      len < 2048 ? len : 2048);
  static const char *kMethods[] = {"GET ",     "POST ",  "HEAD ",
                                   "PUT ",      "DELETE ", "OPTIONS ",
                                   "PATCH ",    "TRACE "};
  size_t methodLen = 0;
  for (const char *m : kMethods) {
    const size_t l = std::strlen(m);
    if (s.size() >= l && s.compare(0, l, m) == 0) {
      method.assign(m, l - 1);  // without the trailing space
      methodLen = l;
      break;
    }
  }
  if (methodLen == 0) return false;
  const size_t pathEnd = s.find(' ', methodLen);
  if (pathEnd == std::string::npos) return false;
  path = s.substr(methodLen, pathEnd - methodLen);

  // Host header (case-insensitive on the header name).
  size_t h = s.find("\r\nHost:");
  if (h == std::string::npos) h = s.find("\r\nhost:");
  if (h != std::string::npos) {
    size_t vs = h + 7;
    while (vs < s.size() && s[vs] == ' ') ++vs;
    const size_t ve = s.find("\r\n", vs);
    if (ve != std::string::npos) host = s.substr(vs, ve - vs);
  }
  return true;
}

std::vector<EventRecord> InspectEthernetFrame(const uint8_t *frame, size_t len) {
  std::vector<EventRecord> out;
  if (!frame || len < 14) return out;
  if (Be16(frame + 12) != 0x0800) return out;  // IPv4 only for now

  const ParsedIpv4 ip = ParseIpv4(frame + 14, len - 14);
  if (!ip.ok) return out;

  if (ip.protocol == 6) {  // TCP
    if (ip.payloadLen < 20) return out;
    const uint8_t *tcp = ip.payload;
    const uint16_t dstPort = Be16(tcp + 2);
    const uint8_t flags = tcp[13];
    size_t tcpHeader = static_cast<size_t>(tcp[12] >> 4) * 4;
    if (tcpHeader < 20 || tcpHeader > ip.payloadLen) tcpHeader = 20;
    const uint8_t *data = tcp + tcpHeader;
    const size_t dataLen = ip.payloadLen - tcpHeader;

    // SYN without ACK == a fresh connection attempt.
    if ((flags & 0x02) && !(flags & 0x10)) {
      out.push_back(MakeNetEvent("network.connect",
                                 ip.dstAddr + ":" + std::to_string(dstPort)));
    }
    if (dstPort == 80 && dataLen > 0) {
      std::string method, path, host;
      if (ParseHttpRequest(data, dataLen, method, path, host)) {
        EventRecord ev = MakeNetEvent(
            "network.http", (host.empty() ? ip.dstAddr : host) + path);
        ev.details["method"] = method;
        ev.details["host"] = host;
        ev.details["path"] = path;
        out.push_back(std::move(ev));
      }
    }
  } else if (ip.protocol == 17) {  // UDP
    if (ip.payloadLen < 8) return out;
    const uint8_t *udp = ip.payload;
    const uint16_t dstPort = Be16(udp + 2);
    const uint8_t *data = udp + 8;
    const size_t dataLen = ip.payloadLen - 8;
    if (dstPort == 53) {
      const std::string q = ParseDnsQueryName(data, dataLen);
      if (!q.empty()) {
        out.push_back(MakeNetEvent("network.dns", q));
      }
    }
  }
  return out;
}

}  // namespace antimal
