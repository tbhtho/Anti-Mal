#include "antimal/NetworkClassifier.h"

namespace antimal {
namespace {

bool StartsWith(const std::string &s, const char *p) {
  return s.rfind(p, 0) == 0;
}

// RFC1918 / loopback / link-local / IPv6 local.
bool IsPrivateHost(const std::string &h) {
  if (h == "localhost" || h == "::1" || StartsWith(h, "fe80") ||
      StartsWith(h, "127.") || StartsWith(h, "10.") ||
      StartsWith(h, "192.168.") || StartsWith(h, "169.254.")) {
    return true;
  }
  if (StartsWith(h, "172.")) {
    // 172.16.0.0 - 172.31.255.255
    const size_t dot = h.find('.', 4);
    const std::string oct = h.substr(4, dot == std::string::npos ? std::string::npos : dot - 4);
    int n = 0;
    for (char c : oct) {
      if (c < '0' || c > '9') return false;
      n = n * 10 + (c - '0');
    }
    return n >= 16 && n <= 31;
  }
  return false;
}

// Reserved / non-routable IPv4 that a real C2 should never be (excludes the
// RFC1918 private ranges, which IsPrivateHost handles): 0.0.0.0/8, 100.64/10
// (CGNAT), the RFC5737 TEST-NET blocks, 198.18/15 (benchmark), 224/4 (multicast)
// and 240/4 (reserved/broadcast). A C2 pointing here is anomalous -- a sinkhole,
// a doc/placeholder address, or misconfiguration.
bool IsBogonHost(const std::string &h) {
  size_t dot = h.find('.');
  if (dot == std::string::npos || dot == 0) return false; // hostname, not a quad
  int o1 = 0;
  for (size_t i = 0; i < dot; ++i) {
    if (h[i] < '0' || h[i] > '9') return false;
    o1 = o1 * 10 + (h[i] - '0');
  }
  if (o1 == 0) return true;     // 0.0.0.0/8
  if (o1 >= 224) return true;   // 224/4 multicast + 240/4 reserved/broadcast
  if (StartsWith(h, "192.0.2.")) return true;    // TEST-NET-1
  if (StartsWith(h, "198.51.100.")) return true; // TEST-NET-2
  if (StartsWith(h, "203.0.113.")) return true;  // TEST-NET-3
  if (StartsWith(h, "198.18.") || StartsWith(h, "198.19.")) return true; // RFC2544
  if (StartsWith(h, "100.")) { // 100.64.0.0/10 CGNAT (second octet 64..127)
    const size_t d2 = h.find('.', dot + 1);
    if (d2 != std::string::npos) {
      int o2 = 0;
      bool ok = d2 > dot + 1;
      for (size_t i = dot + 1; i < d2 && ok; ++i) {
        if (h[i] < '0' || h[i] > '9') ok = false;
        else o2 = o2 * 10 + (h[i] - '0');
      }
      if (ok && o2 >= 64 && o2 <= 127) return true;
    }
  }
  return false;
}

const char *ServiceForPort(uint16_t p) {
  switch (p) {
    case 20: case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 67: case 68: return "DHCP";
    case 80: return "HTTP";
    case 110: return "POP3";
    case 123: return "NTP";
    case 135: return "MS-RPC";
    case 137: case 138: case 139: return "NetBIOS";
    case 143: return "IMAP";
    case 161: return "SNMP";
    case 389: return "LDAP";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 465: return "SMTPS";
    case 587: return "SMTP";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 1080: return "SOCKS";
    case 1433: return "MSSQL";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5985: case 5986: return "WinRM";
    case 6667: return "IRC";
    case 8080: return "HTTP-alt";
    case 8443: return "HTTPS-alt";
    case 9001: case 9030: case 9050: case 9051: return "Tor";
    default: return "";
  }
}

} // namespace

NetworkIndicator ClassifyEndpoint(const std::string &remote) {
  NetworkIndicator ind;
  std::string host = remote;
  const size_t colon = remote.find_last_of(':');
  if (colon != std::string::npos) {
    host = remote.substr(0, colon);
    const std::string portStr = remote.substr(colon + 1);
    uint32_t port = 0;
    bool numeric = !portStr.empty();
    for (char c : portStr) {
      if (c < '0' || c > '9') { numeric = false; break; }
      port = port * 10 + static_cast<uint32_t>(c - '0');
      if (port > 65535) { numeric = false; break; }
    }
    if (numeric) ind.port = static_cast<uint16_t>(port);
  }
  ind.privateAddr = IsPrivateHost(host);
  ind.service = ServiceForPort(ind.port);

  const uint16_t p = ind.port;
  if (p == 4444 || p == 1337 || p == 31337 || p == 12345 || p == 6666) {
    ind.suspicious = true;
    ind.note = "common C2 / backdoor port";
  } else if (p == 9001 || p == 9030 || p == 9050 || p == 9051) {
    ind.suspicious = true;
    ind.note = "Tor port";
  } else if (p == 6667) {
    ind.suspicious = true;
    ind.note = "IRC (classic botnet C2)";
  } else if (p == 23) {
    ind.suspicious = true;
    ind.note = "Telnet (cleartext)";
  } else if (p == 21) {
    ind.suspicious = true;
    ind.note = "FTP (cleartext)";
  } else if (!ind.privateAddr && p == 445) {
    ind.suspicious = true;
    ind.note = "SMB to a public host (lateral/exfil)";
  } else if (!ind.privateAddr && p == 3389) {
    ind.suspicious = true;
    ind.note = "RDP to a public host";
  }
  // A non-routable/reserved C2 endpoint is anomalous regardless of port.
  ind.bogon = !ind.privateAddr && IsBogonHost(host);
  if (ind.bogon) {
    ind.suspicious = true;
    const std::string b = "non-routable/reserved C2 address (bogon)";
    ind.note = ind.note.empty() ? b : ind.note + "; " + b;
  }
  return ind;
}

} // namespace antimal
