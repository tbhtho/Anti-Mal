#include "antimal/IocExport.h"

#include "antimal/Crypto.h"
#include "antimal/Json.h"
#include "antimal/PersistenceClassifier.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace antimal {
namespace {

std::string Lower(std::string v) {
  for (char &c : v) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return v;
}

bool HasSub(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

// Is `targetRaw` an outbound endpoint that is NOT loopback and NOT an RFC1918 /
// link-local / CGN private range? Mirrors BehaviorScore::IsExternalEndpoint so
// the exporter and the verdict scorer agree on what counts as "external" --
// only public indicators are worth shipping to a SOC. Best-effort over an "ip"
// or "ip:port" string.
bool IsExternalIp(const std::string &targetRaw) {
  if (targetRaw.empty()) {
    return false;
  }
  const std::string t = Lower(targetRaw);
  if (HasSub(t, "127.0.0.1") || HasSub(t, "::1") || HasSub(t, "localhost")) {
    return false;
  }
  std::string addr = t;
  if (const auto colon = addr.find_last_of(':'); colon != std::string::npos) {
    const std::string tail = addr.substr(colon + 1);
    const bool allDigits =
        !tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) {
          return std::isdigit(static_cast<unsigned char>(c)) != 0;
        });
    if (allDigits && addr.find("::") == std::string::npos) {
      addr = addr.substr(0, colon);
    }
  }
  static const char *kPrivatePrefixes[] = {
      "10.", "192.168.", "169.254.", "0.0.0.0", "::", "fe80:", "fc00:", "fd",
  };
  for (const char *p : kPrivatePrefixes) {
    if (addr.rfind(p, 0) == 0) {
      return false;
    }
  }
  if (addr.rfind("172.", 0) == 0) {
    const size_t dot2 = addr.find('.', 4);
    if (dot2 != std::string::npos) {
      const int second = std::atoi(addr.substr(4, dot2 - 4).c_str());
      if (second >= 16 && second <= 31) {
        return false;
      }
    }
  }
  if (addr.rfind("100.", 0) == 0) {
    const size_t dot2 = addr.find('.', 4);
    if (dot2 != std::string::npos) {
      const int second = std::atoi(addr.substr(4, dot2 - 4).c_str());
      if (second >= 64 && second <= 127) {
        return false;
      }
    }
  }
  return true;
}

// Strip a trailing :port from "ip:port" / "host:port", leaving an IPv6 literal
// intact. Returns the bare address.
std::string StripPort(const std::string &endpoint) {
  if (endpoint.empty()) {
    return endpoint;
  }
  const auto colon = endpoint.find_last_of(':');
  if (colon == std::string::npos) {
    return endpoint;
  }
  const std::string tail = endpoint.substr(colon + 1);
  const bool allDigits =
      !tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
      });
  if (allDigits && endpoint.find("::") == std::string::npos) {
    return endpoint.substr(0, colon);
  }
  return endpoint;
}

// A dotted-quad IPv4? (so we don't emit a bare hostname as an ipv4-addr).
bool LooksLikeIpv4(const std::string &v) {
  int dots = 0;
  for (char c : v) {
    if (c == '.') {
      ++dots;
    } else if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
      return false;
    }
  }
  return dots == 3;
}

const std::string *Detail(const EventRecord &e, const char *key) {
  const auto it = e.details.find(key);
  return it == e.details.end() ? nullptr : &it->second;
}

// Append `value` (of `type`) to `out` unless we've already seen the (type,value)
// pair. Empty values are dropped.
void Add(std::vector<IocIndicator> &out, std::set<std::string> &seen,
         const char *type, const std::string &value, const std::string &context) {
  if (value.empty()) {
    return;
  }
  const std::string key = std::string(type) + "\x1f" + value;
  if (!seen.insert(key).second) {
    return;
  }
  out.push_back({type, value, context});
}

// Stable hyphenated UUID-shaped id seeded entirely from `seed` (no clock, no
// RNG): SHA-256 the seed and lay 32 hex nibbles out as 8-4-4-4-12. Not a real
// random UUIDv4, but a valid 36-char id string and fully reproducible, which is
// what STIX consumers and our round-trip test require.
std::string DeterministicUuid(const std::string &seed) {
  const std::string h =
      Sha256Hex(std::vector<uint8_t>(seed.begin(), seed.end()));
  std::string hex = h.size() >= 32 ? h.substr(0, 32) : (h + std::string(32, '0'));
  return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) +
         "-" + hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

std::string StixId(const std::string &sdoType, const std::string &seed) {
  return sdoType + "--" + DeterministicUuid(sdoType + "|" + seed);
}

// MISP attribute type + category for each indicator kind.
struct MispMapping {
  const char *type;
  const char *category;
};

MispMapping MispFor(const std::string &iocType) {
  if (iocType == "sha256") return {"sha256", "Payload delivery"};
  if (iocType == "sha1") return {"sha1", "Payload delivery"};
  if (iocType == "md5") return {"md5", "Payload delivery"};
  if (iocType == "domain") return {"domain", "Network activity"};
  if (iocType == "ipv4") return {"ip-dst", "Network activity"};
  if (iocType == "url") return {"url", "Network activity"};
  if (iocType == "regkey") return {"regkey", "Persistence mechanism"};
  if (iocType == "mutex") return {"mutex", "Artifacts dropped"};
  return {"comment", "Other"};
}

// STIX SCO pattern fragment for an indicator kind (the part inside [ ]).
std::string StixPattern(const IocIndicator &ioc) {
  // Single-quote the value with STIX string escaping (\ and ' get backslashed).
  std::string v;
  for (char c : ioc.value) {
    if (c == '\\' || c == '\'') {
      v.push_back('\\');
    }
    v.push_back(c);
  }
  if (ioc.type == "sha256")
    return "[file:hashes.'SHA-256' = '" + v + "']";
  if (ioc.type == "sha1")
    return "[file:hashes.'SHA-1' = '" + v + "']";
  if (ioc.type == "md5")
    return "[file:hashes.'MD5' = '" + v + "']";
  if (ioc.type == "domain")
    return "[domain-name:value = '" + v + "']";
  if (ioc.type == "ipv4")
    return "[ipv4-addr:value = '" + v + "']";
  if (ioc.type == "url")
    return "[url:value = '" + v + "']";
  if (ioc.type == "regkey")
    return "[windows-registry-key:key = '" + v + "']";
  if (ioc.type == "mutex")
    return "[mutex:name = '" + v + "']";
  return "[x-antimal:value = '" + v + "']";
}

} // namespace

std::vector<IocIndicator> CollectIndicators(const AnalysisReport &report) {
  std::vector<IocIndicator> out;
  std::set<std::string> seen;

  // 1) Sample hashes (identification cross-reference keys).
  const auto &scan = report.scannerVerdict;
  Add(out, seen, "sha256", scan.sha256, "sample SHA-256");
  Add(out, seen, "sha1", scan.sha1, "sample SHA-1");
  Add(out, seen, "md5", scan.md5, "sample MD5");

  // 2) Dropped-file SHA-256 from file.* events.
  for (const auto &e : report.events) {
    if (e.category != "file") {
      continue;
    }
    if (const std::string *sha = Detail(e, "sha256")) {
      Add(out, seen, "sha256", *sha,
          "dropped file" + (e.target.empty() ? std::string() : ": " + e.target));
    }
  }

  // 3) Network -- domains (report + scanner IOCs) and public IPv4s
  //    (network event endpoints + scanner IOC ips).
  for (const auto &d : report.networkDomains) {
    Add(out, seen, "domain", d, "contacted domain");
  }
  for (const auto &d : scan.iocs.domains) {
    Add(out, seen, "domain", d, "static IOC domain");
  }
  for (const auto &e : report.events) {
    if (e.category != "network" || e.target.empty()) {
      continue;
    }
    if (!IsExternalIp(e.target)) {
      continue;
    }
    const std::string addr = StripPort(e.target);
    if (LooksLikeIpv4(addr)) {
      Add(out, seen, "ipv4", addr, "network endpoint");
    }
  }
  for (const auto &ip : scan.iocs.ips) {
    if (IsExternalIp(ip) && LooksLikeIpv4(StripPort(ip))) {
      Add(out, seen, "ipv4", StripPort(ip), "static IOC ip");
    }
  }

  // 4) URLs (scanner IOCs).
  for (const auto &u : scan.iocs.urls) {
    Add(out, seen, "url", u, "static IOC url");
  }

  // 5) Registry persistence: any MITRE-tagged registry event, plus registry
  //    writes the persistence classifier recognizes even when the in-guest agent
  //    didn't label them (so the export isn't limited to the agent's handful of
  //    pre-tagged keys).
  for (const auto &e : report.events) {
    const bool isRegistry =
        e.category == "registry" || e.action.find("registry") != std::string::npos;
    if (!isRegistry || e.target.empty()) {
      continue;
    }
    if (!e.mitre.empty()) {
      Add(out, seen, "regkey", e.target, "persistence (" + e.mitre + ")");
      continue;
    }
    const PersistenceMatch pm = ClassifyPersistence(e.category, e.target);
    if (pm.matched) {
      Add(out, seen, "regkey", e.target,
          "persistence: " + pm.mechanism + " (" + pm.mitre + ")");
    }
  }

  // 6) Mutexes (scanner IOC hints).
  for (const auto &m : scan.iocs.mutexHints) {
    Add(out, seen, "mutex", m, "mutex hint");
  }

  // 7) MITRE techniques.
  for (const auto &t : report.mitreTechniques) {
    Add(out, seen, "mitre", t, "ATT&CK technique");
  }

  return out;
}

std::string ExportIocsStix(const AnalysisReport &report) {
  const auto indicators = CollectIndicators(report);

  // Split off MITRE ids -> attack-pattern SDOs; the rest -> indicator SDOs.
  std::vector<IocIndicator> patternIndicators;
  std::vector<std::string> mitreIds;
  for (const auto &ioc : indicators) {
    if (ioc.type == "mitre") {
      mitreIds.push_back(ioc.value);
    } else {
      patternIndicators.push_back(ioc);
    }
  }

  // Deterministic ids for every object so the bundle round-trips identically.
  const std::string reportId = StixId("report", report.runId);
  const std::string bundleId = StixId("bundle", report.runId);

  std::vector<std::string> objectRefs;
  std::ostringstream objects;
  bool first = true;
  auto comma = [&]() {
    if (!first) objects << ",";
    first = false;
  };

  // Indicator SDOs.
  for (const auto &ioc : patternIndicators) {
    const std::string id = StixId("indicator", ioc.type + "|" + ioc.value);
    objectRefs.push_back(id);
    const std::string pattern = StixPattern(ioc);
    JsonObjectBuilder b;
    b.AddString("type", "indicator");
    b.AddString("spec_version", "2.1");
    b.AddString("id", id);
    b.AddString("name", ioc.type + ":" + ioc.value);
    b.AddString("description", ioc.context);
    b.AddString("pattern", pattern);
    b.AddString("pattern_type", "stix");
    b.AddString("valid_from", "1970-01-01T00:00:00Z");
    comma();
    objects << b.Finish();
  }

  // attack-pattern SDOs for MITRE technique ids.
  for (const auto &id : mitreIds) {
    const std::string sdoId = StixId("attack-pattern", id);
    objectRefs.push_back(sdoId);
    JsonObjectBuilder b;
    b.AddString("type", "attack-pattern");
    b.AddString("spec_version", "2.1");
    b.AddString("id", sdoId);
    b.AddString("name", id);
    // external_references carries the canonical MITRE id.
    JsonObjectBuilder ref;
    ref.AddString("source_name", "mitre-attack");
    ref.AddString("external_id", id);
    b.AddRaw("external_references", "[" + ref.Finish() + "]");
    comma();
    objects << b.Finish();
  }

  // The report SDO references everything above.
  {
    std::ostringstream refs;
    refs << "[";
    for (size_t i = 0; i < objectRefs.size(); ++i) {
      if (i) refs << ",";
      refs << JsonQuote(objectRefs[i]);
    }
    refs << "]";
    JsonObjectBuilder b;
    b.AddString("type", "report");
    b.AddString("spec_version", "2.1");
    b.AddString("id", reportId);
    b.AddString("name",
                report.runId.empty() ? std::string("AntiMal detonation report")
                                     : ("AntiMal run " + report.runId));
    b.AddString("published", "1970-01-01T00:00:00Z");
    b.AddRaw("object_refs", refs.str());
    comma();
    objects << b.Finish();
  }

  std::ostringstream bundle;
  bundle << "{\"type\":\"bundle\",\"id\":" << JsonQuote(bundleId)
         << ",\"objects\":[" << objects.str() << "]}";
  return bundle.str();
}

std::string ExportIocsMisp(const AnalysisReport &report) {
  const auto indicators = CollectIndicators(report);

  std::ostringstream attributes;
  std::ostringstream tags;
  bool firstAttr = true;
  bool firstTag = true;

  for (const auto &ioc : indicators) {
    if (ioc.type == "mitre") {
      // MITRE ids become MISP tags (galaxy-style).
      if (!firstTag) tags << ",";
      firstTag = false;
      JsonObjectBuilder t;
      t.AddString("name", "misp-galaxy:mitre-attack-pattern=\"" + ioc.value + "\"");
      tags << t.Finish();
      continue;
    }
    const MispMapping m = MispFor(ioc.type);
    if (!firstAttr) attributes << ",";
    firstAttr = false;
    JsonObjectBuilder a;
    a.AddString("type", m.type);
    a.AddString("category", m.category);
    a.AddString("value", ioc.value);
    a.AddString("comment", ioc.context);
    a.AddBool("to_ids", true);
    attributes << a.Finish();
  }

  std::ostringstream event;
  event << "{\"Event\":{";
  event << "\"info\":"
        << JsonQuote(report.runId.empty()
                         ? std::string("AntiMal detonation report")
                         : ("AntiMal run " + report.runId));
  event << ",\"Attribute\":[" << attributes.str() << "]";
  event << ",\"Tag\":[" << tags.str() << "]";
  event << "}}";
  return event.str();
}

std::string ExportIocsCsv(const AnalysisReport &report, bool defang) {
  const auto indicators = CollectIndicators(report);

  // RFC 4180: quote a field iff it contains comma, quote, CR or LF; double any
  // internal quote. Hostile values can never break the row/column framing.
  auto field = [](const std::string &v) -> std::string {
    const bool needsQuote =
        v.find_first_of(",\"\r\n") != std::string::npos;
    if (!needsQuote) {
      return v;
    }
    std::string out = "\"";
    for (char c : v) {
      if (c == '"') {
        out += "\"\"";
      } else {
        out.push_back(c);
      }
    }
    out.push_back('"');
    return out;
  };

  std::ostringstream csv;
  csv << "type,value,context\r\n";
  for (const auto &ioc : indicators) {
    csv << field(ioc.type) << ","
        << field(defang ? Defang(ioc.value) : ioc.value) << ","
        << field(ioc.context) << "\r\n";
  }
  return csv.str();
}

std::string Defang(const std::string &indicator) {
  std::string s = indicator;
  auto replaceAll = [](std::string &str, const std::string &from,
                       const std::string &to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
      str.replace(pos, from.size(), to);
      pos += to.size();
    }
  };
  // Scheme first (no dots inside the part we rewrite), then dots/@.
  replaceAll(s, "https://", "hxxps://");
  replaceAll(s, "http://", "hxxp://");
  replaceAll(s, "ftp://", "fxp://");
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '.') out += "[.]";
    else if (c == '@') out += "[@]";
    else out += c;
  }
  return out;
}

} // namespace antimal
