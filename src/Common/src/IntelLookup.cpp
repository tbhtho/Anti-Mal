#include "antimal/IntelLookup.h"

#include "antimal/FileUtil.h"
#include "antimal/Http.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <regex>
#include <sstream>

namespace antimal {
namespace {

std::string ReadCacheIfFresh(const std::filesystem::path &cacheDir,
                             const std::string &sha256,
                             std::chrono::seconds maxAge) {
  if (cacheDir.empty()) return {};
  const auto path = cacheDir / (sha256 + ".json");
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return {};
  const auto mtime = std::filesystem::last_write_time(path, ec);
  if (ec) return {};
  const auto age = std::chrono::duration_cast<std::chrono::seconds>(
      std::filesystem::file_time_type::clock::now() - mtime);
  if (age > maxAge) return {};
  try {
    return ReadTextFile(path);
  } catch (...) {
    return {};
  }
}

void WriteCache(const std::filesystem::path &cacheDir, const std::string &sha256,
                const std::string &content) {
  if (cacheDir.empty()) return;
  std::error_code ec;
  std::filesystem::create_directories(cacheDir, ec);
  try {
    WriteTextFile(cacheDir / (sha256 + ".json"), content);
  } catch (...) {
    // Caching is best-effort.
  }
}

std::string FindStringField(const std::string &json, const std::string &key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (std::regex_search(json, m, re)) return m[1].str();
  return {};
}

int FindIntField(const std::string &json, const std::string &key, int fallback) {
  std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
  std::smatch m;
  if (std::regex_search(json, m, re)) return std::atoi(m[1].str().c_str());
  return fallback;
}

std::vector<std::string> FindStringArrayField(const std::string &json,
                                              const std::string &key) {
  std::vector<std::string> out;
  std::regex re("\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch m;
  if (!std::regex_search(json, m, re)) return out;
  const std::string body = m[1].str();
  std::regex item("\"([^\"]*)\"");
  for (auto it = std::sregex_iterator(body.begin(), body.end(), item);
       it != std::sregex_iterator(); ++it) {
    out.push_back((*it)[1].str());
  }
  return out;
}

std::string JsonEscape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x",
                        static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

// One cache line per hit: a compact JSON object carrying the parsed fields
// (including sourceName) rather than the raw API body.
std::string SerializeIntelHitLine(const IntelHit &h) {
  std::string out = "{";
  out += "\"sourceName\":\"" + JsonEscape(h.sourceName) + "\",";
  out += "\"known\":" + std::string(h.known ? "true" : "false") + ",";
  out += "\"family\":\"" + JsonEscape(h.family) + "\",";
  out += "\"detectionRatio\":" + std::to_string(h.detectionRatio) + ",";
  out += "\"totalScanners\":" + std::to_string(h.totalScanners) + ",";
  out += "\"firstSeen\":\"" + JsonEscape(h.firstSeen) + "\",";
  out += "\"lastSeen\":\"" + JsonEscape(h.lastSeen) + "\",";
  out += "\"permalink\":\"" + JsonEscape(h.permalink) + "\",";
  out += "\"error\":\"" + JsonEscape(h.error) + "\",";
  out += "\"tags\":[";
  for (size_t i = 0; i < h.tags.size(); ++i) {
    if (i) out += ",";
    out += "\"" + JsonEscape(h.tags[i]) + "\"";
  }
  out += "]}";
  return out;
}

IntelHit ParseIntelHitLine(const std::string &line) {
  IntelHit hit;
  hit.sourceName = FindStringField(line, "sourceName");
  hit.source = (hit.sourceName == "virustotal") ? IntelSource::VirusTotal
                                                 : IntelSource::MalwareBazaar;
  hit.known = line.find("\"known\":true") != std::string::npos;
  hit.family = FindStringField(line, "family");
  hit.detectionRatio = FindIntField(line, "detectionRatio", 0);
  hit.totalScanners = FindIntField(line, "totalScanners", 0);
  hit.firstSeen = FindStringField(line, "firstSeen");
  hit.lastSeen = FindStringField(line, "lastSeen");
  hit.permalink = FindStringField(line, "permalink");
  hit.error = FindStringField(line, "error");
  hit.tags = FindStringArrayField(line, "tags");
  hit.rawJson = line;
  return hit;
}

} // namespace

std::string SerializeIntelCache(const std::vector<IntelHit> &hits) {
  std::string out;
  for (const auto &h : hits) {
    out += SerializeIntelHitLine(h);
    out += "\n";
  }
  return out;
}

std::vector<IntelHit> ParseIntelCache(const std::string &content) {
  std::vector<IntelHit> hits;
  std::istringstream s(content);
  std::string line;
  while (std::getline(s, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    hits.push_back(ParseIntelHitLine(line));
  }
  return hits;
}

IntelHit ParseMalwareBazaarResponse(const std::string &json) {
  // MalwareBazaar /api/v1/ schema:
  // {"query_status": "ok|hash_not_found|...", "data": [{...}]}
  IntelHit hit;
  hit.source = IntelSource::MalwareBazaar;
  hit.sourceName = "malwarebazaar";
  hit.rawJson = json;

  const auto status = FindStringField(json, "query_status");
  if (status != "ok") {
    if (status == "hash_not_found") {
      hit.known = false;
    } else {
      hit.error = "malwarebazaar status=" + status;
    }
    return hit;
  }
  hit.known = true;
  hit.detectionRatio = 1;
  hit.totalScanners = 1;
  hit.family = FindStringField(json, "signature");
  hit.firstSeen = FindStringField(json, "first_seen");
  hit.lastSeen = FindStringField(json, "last_seen");
  const auto sha = FindStringField(json, "sha256_hash");
  if (!sha.empty()) {
    hit.permalink = "https://bazaar.abuse.ch/sample/" + sha + "/";
  }
  auto tags = FindStringArrayField(json, "tags");
  hit.tags = std::move(tags);
  return hit;
}

IntelHit ParseVirusTotalResponse(const std::string &json) {
  // VT v3 /files/{hash}:
  // {"data": {"attributes": {"last_analysis_stats": {"malicious": N, "harmless": N, ...},
  //                         "popular_threat_classification": {"suggested_threat_label": "..."},
  //                         "names": [...], "first_submission_date": ..., "last_analysis_date": ...,
  //                         "tags": [...]}}}
  IntelHit hit;
  hit.source = IntelSource::VirusTotal;
  hit.sourceName = "virustotal";
  hit.rawJson = json;

  if (json.find("\"error\"") != std::string::npos) {
    const auto msg = FindStringField(json, "message");
    if (!msg.empty()) hit.error = "virustotal: " + msg;
    return hit;
  }

  const int malicious = FindIntField(json, "malicious", -1);
  const int harmless = FindIntField(json, "harmless", 0);
  const int suspicious = FindIntField(json, "suspicious", 0);
  const int undetected = FindIntField(json, "undetected", 0);
  if (malicious < 0) {
    hit.known = false;
    return hit;
  }
  hit.known = malicious + suspicious > 0;
  hit.detectionRatio = malicious;
  hit.totalScanners = malicious + harmless + suspicious + undetected;
  hit.family = FindStringField(json, "suggested_threat_label");
  hit.tags = FindStringArrayField(json, "tags");

  // first_submission_date / last_analysis_date are unix epochs.
  auto epochToIso = [](int seconds) {
    if (seconds <= 0) return std::string{};
    std::time_t t = seconds;
    std::tm tm{};
    if (gmtime_s(&tm, &t) != 0) return std::string{};
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
  };
  hit.firstSeen = epochToIso(FindIntField(json, "first_submission_date", 0));
  hit.lastSeen = epochToIso(FindIntField(json, "last_analysis_date", 0));
  return hit;
}

IntelLookupResult LookupHash(const std::string &sha256Hex,
                             const IntelLookupConfig &config) {
  IntelLookupResult result;
  if (!config.enabled || sha256Hex.size() != 64) return result;
  result.enabled = true;

  const std::string lowerHash = ToLowerAscii(sha256Hex);

  // Check cache first. Each cached line carries its own sourceName, so reads
  // reconstruct the hit directly (no re-dispatch on raw API bodies).
  const auto cached = ReadCacheIfFresh(config.cacheDir, lowerHash,
                                       config.maxAgeForCache);
  if (!cached.empty()) {
    auto cachedHits = ParseIntelCache(cached);
    if (!cachedHits.empty()) {
      result.fromCache = true;
      result.hits = std::move(cachedHits);
      return result;
    }
  }

  if (config.malwareBazaarEnabled) {
    HttpRequest req;
    req.url = "https://mb-api.abuse.ch/api/v1/";
    req.method = "POST";
    req.contentType = "application/x-www-form-urlencoded";
    req.body = "query=get_info&hash=" + UrlEncode(lowerHash);
    req.timeout = config.requestTimeout;
    auto response = HttpRequestSync(req);
    IntelHit hit;
    if (!response.ok) {
      hit.source = IntelSource::MalwareBazaar;
      hit.sourceName = "malwarebazaar";
      hit.error = "transport: " + response.error;
    } else {
      hit = ParseMalwareBazaarResponse(response.body);
    }
    result.hits.push_back(std::move(hit));
  }

  if (!config.virusTotalApiKey.empty()) {
    HttpRequest req;
    req.url = "https://www.virustotal.com/api/v3/files/" + lowerHash;
    req.method = "GET";
    req.headers["x-apikey"] = config.virusTotalApiKey;
    req.timeout = config.requestTimeout;
    auto response = HttpRequestSync(req);
    IntelHit hit;
    if (!response.ok) {
      hit.source = IntelSource::VirusTotal;
      hit.sourceName = "virustotal";
      hit.error = "transport: " + response.error;
    } else if (response.status == 404) {
      hit.source = IntelSource::VirusTotal;
      hit.sourceName = "virustotal";
      hit.known = false;
    } else if (response.status != 200) {
      hit.source = IntelSource::VirusTotal;
      hit.sourceName = "virustotal";
      hit.error = "http " + std::to_string(response.status);
    } else {
      hit = ParseVirusTotalResponse(response.body);
      hit.permalink = "https://www.virustotal.com/gui/file/" + lowerHash;
    }
    result.hits.push_back(std::move(hit));
  }

  // Cache only complete, error-free result sets. Serialize the parsed hits
  // (each line carries its sourceName). Skip caching if any configured source
  // failed (transport error) so the next scan retries instead of serving a
  // stale partial/error result for the cache lifetime.
  if (!result.hits.empty()) {
    bool allOk = true;
    for (const auto &h : result.hits) {
      if (!h.error.empty()) {
        allOk = false;
        break;
      }
    }
    if (allOk) {
      WriteCache(config.cacheDir, lowerHash, SerializeIntelCache(result.hits));
    }
  }
  return result;
}

} // namespace antimal
