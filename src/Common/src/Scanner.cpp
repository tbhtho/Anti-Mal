#include "antimal/Scanner.h"

#include "antimal/Crypto.h"
#include "antimal/ExternalTools.h"
#include "antimal/FileUtil.h"
#include "antimal/IntelLookup.h"
#include "antimal/PeParser.h"
#include "antimal/Strings.h"
#include "antimal/Tagger.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <set>
#include <sstream>

namespace antimal {
namespace {

bool ImportContains(const std::vector<std::string> &imports, std::string needle) {
  needle = ToLowerAscii(std::move(needle));
  return std::any_of(imports.begin(), imports.end(), [&](const std::string &item) {
    return ToLowerAscii(item).find(needle) != std::string::npos;
  });
}

void AddFinding(ScanResult &result, std::string ruleId, std::string message, int score) {
  result.findings.push_back({std::move(ruleId), std::move(message), score});
  result.score += score;
}

bool IsUnusualExecutionPath(const std::filesystem::path &path) {
  const std::string lower = ToLowerAscii(PathToUtf8(path));
  return lower.find("\\downloads\\") != std::string::npos ||
         lower.find("\\temp\\") != std::string::npos ||
         lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
         lower.find("\\users\\public\\") != std::string::npos;
}

bool ContainsAsciiString(const std::vector<uint8_t> &data, std::string_view needle) {
  if (needle.empty() || data.size() < needle.size()) {
    return false;
  }
  return std::search(data.begin(), data.end(), needle.begin(), needle.end()) != data.end();
}

std::filesystem::path ExeRelative(std::string_view rel) {
  wchar_t modulePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
  return std::filesystem::path(modulePath).parent_path() / std::filesystem::path(Utf8ToWide(rel));
}

ScanIocSet ConvertIocs(const ExtractedIocs &src) {
  ScanIocSet dst;
  dst.urls = src.urls;
  dst.ips = src.ips;
  dst.domains = src.domains;
  dst.registryPaths = src.registryPaths;
  dst.filePaths = src.filePaths;
  dst.mutexHints = src.mutexHints;
  dst.base64Blobs = src.base64Blobs;
  dst.suspiciousApis = src.suspiciousApis;
  return dst;
}

std::vector<ScanYaraMatch> ConvertYara(const YaraScanResult &src) {
  std::vector<ScanYaraMatch> out;
  for (const auto &m : src.matches) {
    out.push_back({m.ruleName, m.ruleNamespace, m.tags, m.meta});
  }
  return out;
}

std::vector<ScanCapaCapability> ConvertCapa(const CapaScanResult &src) {
  std::vector<ScanCapaCapability> out;
  for (const auto &c : src.capabilities) {
    out.push_back({c.name, c.mitreTechniques, c.mbcBehaviors, c.ruleNamespace});
  }
  return out;
}

std::vector<ScanDieDetection> ConvertDie(const DieScanResult &src) {
  std::vector<ScanDieDetection> out;
  for (const auto &d : src.detections) {
    out.push_back({d.type, d.name, d.version, d.options});
  }
  return out;
}

ScanIntelHit ConvertIntel(const IntelHit &src) {
  ScanIntelHit dst;
  dst.source = src.sourceName;
  dst.known = src.known;
  dst.family = src.family;
  dst.tags = src.tags;
  dst.detectionRatio = src.detectionRatio;
  dst.totalScanners = src.totalScanners;
  dst.firstSeen = src.firstSeen;
  dst.lastSeen = src.lastSeen;
  dst.permalink = src.permalink;
  dst.error = src.error;
  return dst;
}

void Enrich(ScanResult &result, const std::vector<uint8_t> &data,
            const ScannerOptions &options) {
  // IOC mining is cheapest and runs on every scan unless explicitly off.
  ExtractedIocs minedIocs;
  if (options.mineIocs) {
    minedIocs = MineIocsFromBytes(data);
    result.iocs = ConvertIocs(minedIocs);
    if (!minedIocs.suspiciousApis.empty()) {
      AddFinding(result, "strings.suspicious_apis",
                 "Strings mention suspicious Windows APIs: " +
                     std::to_string(minedIocs.suspiciousApis.size()) + " hit(s)",
                 std::min<int>(15, static_cast<int>(minedIocs.suspiciousApis.size()) * 3));
    }
  }

  // YARA — relies on rule files + yara.exe being present.
  YaraScanResult yaraResult;
  if (options.runYara) {
    auto rulesDir = options.yaraRulesDir;
    if (rulesDir.empty()) rulesDir = ExeRelative("rules/yara");
    yaraResult = RunYara(result.path, rulesDir);
    if (yaraResult.available && yaraResult.succeeded) {
      result.yaraMatches = ConvertYara(yaraResult);
      if (!yaraResult.matches.empty()) {
        AddFinding(result, "yara.match",
                   "YARA matched " + std::to_string(yaraResult.matches.size()) +
                       " rule(s)",
                   std::min<int>(40, static_cast<int>(yaraResult.matches.size()) * 10));
      }
    }
  }

  // capa — MITRE technique discovery.
  CapaScanResult capaResult;
  if (options.runCapa) {
    capaResult = RunCapa(result.path);
    if (capaResult.available && capaResult.succeeded) {
      result.capaCapabilities = ConvertCapa(capaResult);
      if (!capaResult.capabilities.empty()) {
        AddFinding(result, "capa.capabilities",
                   "capa identified " + std::to_string(capaResult.capabilities.size()) +
                       " capability rule(s)",
                   std::min<int>(20, static_cast<int>(capaResult.capabilities.size())));
      }
    }
  }

  // DIE — packer / protector detection.
  DieScanResult dieResult;
  if (options.runDie) {
    dieResult = RunDie(result.path);
    if (dieResult.available && dieResult.succeeded) {
      result.dieDetections = ConvertDie(dieResult);
      for (const auto &d : dieResult.detections) {
        if (d.type == "packer" || d.type == "protector") {
          AddFinding(result, "die." + d.type,
                     d.type + " detected: " + d.name +
                         (d.version.empty() ? "" : " " + d.version),
                     25);
        }
      }
    }
  }

  // Threat intel (opt-in / network-required).
  if (options.intelLookupEnabled && !result.sha256.empty()) {
    IntelLookupConfig cfg;
    cfg.enabled = true;
    cfg.virusTotalApiKey = options.virusTotalApiKey;
    cfg.malwareBazaarEnabled = options.malwareBazaarEnabled;
    cfg.cacheDir = options.intelCacheDir;
    cfg.requestTimeout = options.intelTimeout;
    auto intel = LookupHash(result.sha256, cfg);
    for (const auto &hit : intel.hits) {
      result.intelHits.push_back(ConvertIntel(hit));
      if (hit.known && hit.detectionRatio > 0) {
        AddFinding(result, "intel." + hit.sourceName,
                   hit.sourceName + " known sample" +
                       (hit.family.empty() ? "" : " (" + hit.family + ")"),
                   60);
      }
    }
  }

  // Tagger — runs last so it sees every other signal.
  if (options.applyTagger) {
    Tagger tagger;
    bool loadedFromFile = false;
    auto rulesPath = options.tagsRulesPath;
    if (rulesPath.empty()) rulesPath = ExeRelative("rules/tags.json");
    if (std::filesystem::exists(rulesPath)) {
      loadedFromFile = tagger.LoadRulesFromFile(rulesPath);
    }
    if (!loadedFromFile) tagger.LoadBuiltinRules();

    TagInputs inputs;
    inputs.scan = &result;
    inputs.iocs = options.mineIocs ? &minedIocs : nullptr;
    inputs.yara = (options.runYara && yaraResult.available) ? &yaraResult : nullptr;
    inputs.capa = (options.runCapa && capaResult.available) ? &capaResult : nullptr;
    inputs.die = (options.runDie && dieResult.available) ? &dieResult : nullptr;

    auto tags = tagger.Evaluate(inputs);
    for (auto &tag : tags) {
      result.tags.push_back(ScanTag{tag.tag, tag.category, tag.confidence,
                                    std::move(tag.reasons)});
    }
  }
}

} // namespace

double CalculateEntropy(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return 0.0;
  }

  std::array<size_t, 256> freq{};
  for (uint8_t b : data) {
    ++freq[b];
  }

  double entropy = 0.0;
  const double len = static_cast<double>(data.size());
  for (size_t count : freq) {
    if (!count) {
      continue;
    }
    const double p = static_cast<double>(count) / len;
    entropy -= p * std::log2(p);
  }
  return entropy;
}

ScanResult ScanFile(const std::filesystem::path &path) {
  return ScanFile(path, ScannerOptions{});
}

ScanResult ScanFile(const std::filesystem::path &path,
                    const ScannerOptions &options) {
  ScanResult result;
  result.path = path;

  try {
    const auto data = ReadAllBytes(path);
    result.sha256 = Sha256Hex(data);
    result.md5 = Md5Hex(data);
    result.entropy = CalculateEntropy(data);

    const PeInfo pe = ParsePe(data);
    result.isPe = pe.isPe;
    result.imports = pe.imports;
    result.imphash = pe.imphash;

    if (result.entropy > 7.2) {
      AddFinding(result, "entropy.high", "File entropy is above packed/encrypted threshold", 25);
    }

    if (pe.isPe) {
      result.authenticodeSigned = HasAuthenticodeSignature(path);
      if (!result.authenticodeSigned && IsUnusualExecutionPath(path)) {
        AddFinding(result, "signature.unsigned_unusual_path",
                   "Unsigned PE from a user-writable or transient path", 20);
      } else if (!result.authenticodeSigned) {
        AddFinding(result, "signature.unsigned_pe", "Unsigned PE executable", 10);
      }

      const bool injection =
          ImportContains(result.imports, "WriteProcessMemory") &&
          (ImportContains(result.imports, "CreateRemoteThread") ||
           ImportContains(result.imports, "NtCreateThreadEx") ||
           ImportContains(result.imports, "VirtualAllocEx"));
      if (injection) {
        AddFinding(result, "imports.process_injection",
                   "Imports process memory write and remote-thread primitives", 35);
      }

      if (ImportContains(result.imports, "InternetOpenUrl") ||
          ImportContains(result.imports, "WinHttpConnect") ||
          ImportContains(result.imports, "URLDownloadToFile")) {
        AddFinding(result, "imports.network_loader",
                   "Imports network or downloader APIs often used by droppers", 20);
      }

      if (ImportContains(result.imports, "RegSetValue") ||
          ImportContains(result.imports, "RegCreateKey")) {
        AddFinding(result, "imports.registry_persistence",
                   "Imports registry write APIs that may support persistence", 10);
      }
    }

    const std::string powershell = std::string("power") + "shell";
    const std::string encodedCommand = std::string("-Enc") + "odedCommand";
    const std::string shortEncoded = std::string(" -e") + "nc ";
    const std::string fromBase64 = std::string("From") + "Base64String";
    if (ContainsAsciiString(data, powershell) &&
        (ContainsAsciiString(data, encodedCommand) ||
         ContainsAsciiString(data, shortEncoded) ||
         ContainsAsciiString(data, fromBase64))) {
      AddFinding(result, "strings.encoded_powershell",
                 "Contains PowerShell encoded-command indicators", 25);
    }
    if (ContainsAsciiString(data, "MZ") && ContainsAsciiString(data, "This program cannot be run")) {
      // A low-impact rule that proves the built-in rule engine can emit string hits.
      AddFinding(result, "strings.pe_marker", "Contains PE loader markers", pe.isPe ? 0 : 5);
    }

    // Enrichment pipeline (strings/IOCs, YARA, capa, DIE, intel, tagger).
    Enrich(result, data, options);

    result.score = std::min(result.score, 100);
    result.verdict = VerdictFromScore(result.score);
  } catch (const std::exception &ex) {
    result.verdict = Verdict::Error;
    AddFinding(result, "scanner.error", ex.what(), 0);
  }

  return result;
}

std::vector<ScanResult> ScanPath(const std::filesystem::path &path) {
  return ScanPath(path, ScannerOptions{});
}

std::vector<ScanResult> ScanPath(const std::filesystem::path &path,
                                 const ScannerOptions &options) {
  std::vector<ScanResult> results;
  std::error_code ec;
  if (std::filesystem::is_regular_file(path, ec)) {
    results.push_back(ScanFile(path, options));
    return results;
  }

  std::filesystem::recursive_directory_iterator it(
      path, std::filesystem::directory_options::skip_permission_denied, ec);
  std::filesystem::recursive_directory_iterator end;
  while (it != end) {
    const auto entry = *it;
    it.increment(ec);
    if (ec) {
      ec.clear();
      continue;
    }
    if (!entry.is_regular_file(ec)) {
      ec.clear();
      continue;
    }
    const auto ext = ToLowerAscii(entry.path().extension().string());
    if (ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".sys" ||
        ext == ".bin") {
      results.push_back(ScanFile(entry.path(), options));
    }
  }
  return results;
}

std::string FormatScanText(const ScanResult &result) {
  std::ostringstream out;
  out << PathToUtf8(result.path) << "\n";
  out << "  sha256: " << result.sha256 << "\n";
  if (!result.md5.empty()) {
    out << "  md5: " << result.md5 << "\n";
  }
  if (!result.imphash.empty()) {
    out << "  imphash: " << result.imphash << "\n";
  }
  out << "  score: " << result.score << " (" << ToString(result.verdict) << ")\n";
  out << "  entropy: " << result.entropy << "\n";
  out << "  pe: " << (result.isPe ? "yes" : "no")
      << ", signed: " << (result.authenticodeSigned ? "yes" : "no") << "\n";
  for (const auto &finding : result.findings) {
    out << "  - [" << finding.ruleId << "] +" << finding.score << " "
        << finding.message << "\n";
  }
  if (!result.tags.empty()) {
    out << "  tags:";
    for (const auto &tag : result.tags) {
      out << " " << tag.tag << "(" << tag.confidence << ")";
    }
    out << "\n";
  }
  if (!result.yaraMatches.empty()) {
    out << "  yara: " << result.yaraMatches.size() << " match(es)\n";
  }
  if (!result.capaCapabilities.empty()) {
    out << "  capa: " << result.capaCapabilities.size() << " capabilit(ies)\n";
  }
  if (!result.dieDetections.empty()) {
    out << "  die:";
    for (const auto &d : result.dieDetections) {
      out << " " << d.type << "=" << d.name;
    }
    out << "\n";
  }
  for (const auto &hit : result.intelHits) {
    if (!hit.error.empty()) {
      out << "  intel[" << hit.source << "]: " << hit.error << "\n";
      continue;
    }
    out << "  intel[" << hit.source << "]: "
        << (hit.known ? "KNOWN" : "unknown");
    if (!hit.family.empty()) out << " " << hit.family;
    if (hit.totalScanners > 0) {
      out << " " << hit.detectionRatio << "/" << hit.totalScanners;
    }
    out << "\n";
  }
  if (!result.iocs.urls.empty() || !result.iocs.domains.empty() ||
      !result.iocs.ips.empty()) {
    out << "  iocs: " << result.iocs.urls.size() << " url(s), "
        << result.iocs.domains.size() << " domain(s), "
        << result.iocs.ips.size() << " ip(s)\n";
  }
  return out.str();
}

} // namespace antimal
