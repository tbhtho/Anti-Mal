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
    // Recover single-byte-XOR-obfuscated C2 URLs the plaintext miner can't see.
    const auto xorUrls = MineXorObfuscatedUrls(data);
    if (!xorUrls.empty()) {
      static const char kHex[] = "0123456789ABCDEF";
      std::string msg = "Single-byte-XOR-obfuscated URL(s) decoded: ";
      for (size_t i = 0; i < xorUrls.size(); ++i) {
        result.iocs.urls.push_back(xorUrls[i].value);
        if (i < 3) {
          if (i) msg += ", ";
          msg += xorUrls[i].value + " (XOR 0x";
          msg += kHex[(xorUrls[i].xorKey >> 4) & 0xF];
          msg += kHex[xorUrls[i].xorKey & 0xF];
          msg += ")";
        }
      }
      if (xorUrls.size() > 3) {
        msg += ", +" + std::to_string(xorUrls.size() - 3) + " more";
      }
      // Obfuscated C2 is a strong malware signal (obfuscation + a network IOC).
      AddFinding(result, "strings.xor_obfuscated_url", msg,
                 std::min<int>(30, static_cast<int>(xorUrls.size()) * 15));
    }
    // Step up: recover multi-byte (2-4 byte repeating key) XOR-obfuscated C2
    // URLs that the single-byte pass can't see -- a common real-malware scheme.
    const auto mbXorUrls = MineMultiByteXorObfuscatedUrls(data);
    if (!mbXorUrls.empty()) {
      static const char kHex[] = "0123456789ABCDEF";
      std::string msg = "Multi-byte-XOR-obfuscated URL(s) decoded: ";
      for (size_t i = 0; i < mbXorUrls.size(); ++i) {
        result.iocs.urls.push_back(mbXorUrls[i].value);
        if (i < 3) {
          if (i) msg += ", ";
          msg += mbXorUrls[i].value + " (XOR 0x";
          for (const uint8_t b : mbXorUrls[i].key) {
            msg += kHex[(b >> 4) & 0xF];
            msg += kHex[b & 0xF];
          }
          msg += ")";
        }
      }
      if (mbXorUrls.size() > 3) {
        msg += ", +" + std::to_string(mbXorUrls.size() - 3) + " more";
      }
      // A multi-byte key is a stronger obfuscation signal than single-byte.
      AddFinding(result, "strings.multibyte_xor_obfuscated_url", msg,
                 std::min<int>(35, static_cast<int>(mbXorUrls.size()) * 18));
    }
    // Recover C2/config hidden one base64 layer deep (a very common scheme the
    // plaintext miner only reports as an opaque blob).
    const auto b64 = MineBase64WrappedIocs(data);
    const size_t b64Total = b64.urls.size() + b64.ips.size() + b64.domains.size();
    if (b64Total > 0) {
      for (const auto &u : b64.urls) result.iocs.urls.push_back(u);
      for (const auto &ip : b64.ips) result.iocs.ips.push_back(ip);
      for (const auto &d : b64.domains) result.iocs.domains.push_back(d);
      std::string msg = "Base64-wrapped C2/IOC(s) recovered (" +
                        std::to_string(b64.blobsDecoded) + " blob(s)): ";
      size_t shown = 0;
      for (const auto &u : b64.urls) { if (shown++) msg += ", "; if (shown <= 3) msg += u; }
      for (const auto &ip : b64.ips) { if (shown <= 3) { if (shown++) msg += ", "; msg += ip; } }
      if (b64Total > 3) msg += ", +" + std::to_string(b64Total - 3) + " more";
      // Config hidden behind base64 is a meaningful obfuscation+network signal.
      AddFinding(result, "strings.base64_wrapped_ioc", msg,
                 std::min<int>(30, static_cast<int>(b64Total) * 12));
    }
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

std::string IdentifyFileType(const std::vector<uint8_t> &data) {
  auto has = [&](std::initializer_list<int> sig, size_t at = 0) {
    if (at + sig.size() > data.size()) {
      return false;
    }
    size_t i = at;
    for (int b : sig) {
      if (data[i++] != static_cast<uint8_t>(b)) {
        return false;
      }
    }
    return true;
  };
  if (has({'M', 'Z'})) {
    return "pe";
  }
  if (has({0x7F, 'E', 'L', 'F'})) {
    return "elf";
  }
  if (has({0xFE, 0xED, 0xFA, 0xCE}) || has({0xFE, 0xED, 0xFA, 0xCF}) ||
      has({0xCE, 0xFA, 0xED, 0xFE}) || has({0xCF, 0xFA, 0xED, 0xFE})) {
    return "macho";
  }
  if (has({'%', 'P', 'D', 'F'})) {
    return "pdf";
  }
  if (has({'P', 'K', 0x03, 0x04}) || has({'P', 'K', 0x05, 0x06}) ||
      has({'P', 'K', 0x07, 0x08})) {
    return "zip"; // also office-OOXML / jar / apk (all zip containers)
  }
  if (has({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})) {
    return "ole"; // legacy doc/xls/ppt/msi
  }
  if (has({'{', '\\', 'r', 't', 'f'})) {
    return "rtf";
  }
  if (has({'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})) {
    return "7z";
  }
  if (has({'R', 'a', 'r', '!'})) {
    return "rar";
  }
  if (has({0x1F, 0x8B})) {
    return "gzip";
  }
  if (has({'M', 'S', 'C', 'F'})) {
    return "cab";
  }
  if (has({0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00})) {
    return "lnk"; // Windows shell link header GUID
  }
  if (has({'#', '!'})) {
    return "script";
  }
  if (has({'<', '?', 'p', 'h', 'p'})) {
    return "php";
  }
  return "";
}

int CountEmbeddedExecutables(const std::vector<uint8_t> &data) {
  if (data.size() < 0x40) {
    return 0;
  }
  int count = 0;
  // Start at 1 so the host's own header at offset 0 is not counted.
  for (size_t i = 1; i + 0x40 <= data.size(); ++i) {
    if (data[i] != 'M' || data[i + 1] != 'Z') {
      continue;
    }
    const uint32_t lfanew = static_cast<uint32_t>(data[i + 0x3C]) |
                            (static_cast<uint32_t>(data[i + 0x3D]) << 8) |
                            (static_cast<uint32_t>(data[i + 0x3E]) << 16) |
                            (static_cast<uint32_t>(data[i + 0x3F]) << 24);
    if (lfanew < 0x40) {
      continue; // e_lfanew must clear the DOS header
    }
    const size_t peOff = i + lfanew;
    if (peOff + 4 <= data.size() && data[peOff] == 'P' && data[peOff + 1] == 'E' &&
        data[peOff + 2] == 0 && data[peOff + 3] == 0) {
      if (++count >= 256) {
        break; // cap: enough to say "this is a dropper"
      }
    }
  }
  return count;
}

std::vector<ScanFinding>
DetectImportCapabilities(const std::vector<std::string> &imports) {
  std::vector<ScanFinding> out;
  auto any = [&](std::initializer_list<const char *> names) {
    for (const char *n : names) {
      if (ImportContains(imports, n)) {
        return true;
      }
    }
    return false;
  };
  auto all = [&](std::initializer_list<const char *> names) {
    for (const char *n : names) {
      if (!ImportContains(imports, n)) {
        return false;
      }
    }
    return true;
  };
  auto add = [&](const char *id, const char *msg, int score) {
    out.push_back({id, msg, score});
  };

  if (any({"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
           "NtQueryInformationProcess", "NtSetInformationThread",
           "OutputDebugString"})) {
    add("capability.anti_debug",
        "Imports anti-debugging / debugger-detection APIs", 15);
  }
  if (all({"GetProcAddress", "LoadLibrary"})) {
    add("capability.dynamic_api",
        "Resolves APIs at runtime (GetProcAddress + LoadLibrary), a common way "
        "to hide intent from static analysis",
        10);
  }
  if (any({"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
           "RegisterRawInputDevices"})) {
    add("capability.keylogging", "Imports keyboard input-capture APIs (keylogger)",
        25);
  }
  if (any({"BitBlt", "CreateCompatibleBitmap", "GetDesktopWindow"}) &&
      any({"GetDC", "GetWindowDC"})) {
    add("capability.screen_capture",
        "Imports screen-capture APIs (screenshot / spyware)", 20);
  }
  if (any({"OpenClipboard", "GetClipboardData", "SetClipboardViewer"})) {
    add("capability.clipboard", "Reads or monitors the clipboard", 15);
  }
  if (any({"OpenSCManager", "CreateService", "StartService",
           "ChangeServiceConfig"})) {
    add("capability.service",
        "Imports service-control APIs (persistence / privileged execution)", 15);
  }
  if (any({"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt",
           "CryptGenKey"})) {
    add("capability.crypto",
        "Imports cryptographic APIs (ransomware / config protection)", 10);
  }
  if (any({"CreateToolhelp32Snapshot", "Process32First", "Process32Next",
           "EnumProcesses"})) {
    add("capability.process_discovery",
        "Enumerates running processes (discovery / targeting)", 10);
  }
  if (any({"AdjustTokenPrivileges", "LookupPrivilegeValue"}) &&
      any({"OpenProcessToken"})) {
    add("capability.token_privilege",
        "Adjusts process token privileges (privilege escalation)", 20);
  }
  return out;
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
    result.sha1 = Sha1Hex(data);
    result.md5 = Md5Hex(data);
    result.detectedType = IdentifyFileType(data);
    result.entropy = CalculateEntropy(data);

    // Embedded executables (any host type): a dropper/installer carrying one or
    // more additional PEs. Strong signal even inside a non-PE container.
    result.embeddedExecutables = CountEmbeddedExecutables(data);
    if (result.embeddedExecutables > 0) {
      AddFinding(result, "dropper.embedded_pe",
                 "Carries " + std::to_string(result.embeddedExecutables) +
                     " embedded executable(s) past the file header",
                 30);
    }

    // Masquerade: a PE wearing a document/media/archive extension is a classic
    // delivery trick (invoice.pdf.exe truncated in the UI, or a plain rename).
    if (result.detectedType == "pe") {
      std::string ext = PathToUtf8(path.extension());
      for (char &c : ext) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      static const std::vector<std::string> kDecoyExts = {
          ".pdf", ".doc",  ".docx", ".xls", ".xlsx", ".ppt", ".rtf", ".txt",
          ".jpg", ".jpeg", ".png",  ".gif", ".mp3",  ".mp4", ".csv", ".htm",
          ".html", ".zip", ".rar"};
      if (std::find(kDecoyExts.begin(), kDecoyExts.end(), ext) != kDecoyExts.end()) {
        AddFinding(result, "filetype.masquerade_pe",
                   "Executable (PE) wearing a non-executable '" + ext +
                       "' extension",
                   40);
      }
    }

    const PeInfo pe = ParsePe(data);
    result.isPe = pe.isPe;
    result.imports = pe.imports;
    result.imphash = pe.imphash;
    result.peTimestamp = pe.timeDateStamp;
    result.peSections = pe.sections;
    result.peOverlaySize = pe.overlaySize;
    result.peOverlayEntropy = pe.overlayEntropy;
    result.isDll = pe.isDll;
    result.isDotNet = pe.isDotNet;
    result.dotNetRuntimeVersion = pe.dotNetRuntimeVersion;
    result.exportName = pe.exportName;
    result.peExports = pe.exports;
    result.tlsCallbackCount = pe.tlsCallbackCount;
    result.peVersionInfo = pe.versionInfo;
    result.pdbPath = pe.pdbPath;
    result.richHash = pe.richHash;

    if (result.entropy > 7.2) {
      AddFinding(result, "entropy.high", "File entropy is above packed/encrypted threshold", 25);
    }

    // Evidence-backed packer tell: an executable section whose raw bytes are
    // near-random. Far more specific than whole-file entropy (which a large
    // embedded resource can inflate on a perfectly benign binary).
    for (const auto &sec : pe.sections) {
      if (sec.executable && sec.entropy > 7.0 && sec.rawSize > 0) {
        AddFinding(result, "section.high_entropy_exec",
                   "Executable section '" + sec.name +
                       "' has near-random entropy (likely packed/encrypted code)",
                   30);
        break;
      }
    }

    if (pe.isPe) {
      result.authenticodeSigned = HasAuthenticodeSignature(path);
      if (!result.authenticodeSigned && IsUnusualExecutionPath(path)) {
        AddFinding(result, "signature.unsigned_unusual_path",
                   "Unsigned PE from a user-writable or transient path", 20);
      } else if (!result.authenticodeSigned) {
        AddFinding(result, "signature.unsigned_pe", "Unsigned PE executable", 10);
      }

      // A large, near-random overlay on an UNSIGNED PE is a classic appended-
      // payload / packed-stage tell. Signed PEs are excluded because their
      // Authenticode certificate legitimately lives in the overlay region.
      if (!result.authenticodeSigned && result.peOverlaySize > 4096 &&
          result.peOverlayEntropy > 7.0) {
        AddFinding(result, "pe.overlay_high_entropy",
                   "Large high-entropy overlay appended after the last section "
                   "(possible encrypted/packed payload)",
                   25);
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

      // Coarse capability surfacing from the import table (the "what can this
      // do" row). Modest scores: capabilities inform triage; aggregation drives
      // the verdict.
      for (const auto &cap : DetectImportCapabilities(result.imports)) {
        AddFinding(result, cap.ruleId, cap.message, cap.score);
      }

      // T47 depth findings.
      if (pe.tlsCallbackCount > 0) {
        // A single TLS callback is usually the benign MSVC CRT __dyn_tls_init;
        // multiple callbacks are the stronger anti-analysis / early-exec tell.
        AddFinding(result, "pe.tls_callbacks",
                   "Has " + std::to_string(pe.tlsCallbackCount) +
                       " TLS callback(s) that run before the entry point "
                       "(anti-analysis / early-execution tell)",
                   pe.tlsCallbackCount > 1 ? 20 : 5);
      }
      if (!pe.isDll && !pe.exports.empty()) {
        AddFinding(result, "pe.exe_exports",
                   "Executable (non-DLL) exports " +
                       std::to_string(pe.exports.size()) +
                       " function(s) -- unusual (reflective loader / DLL "
                       "masquerade)",
                   10);
      }
      if (pe.isDotNet) {
        AddFinding(result, "pe.dotnet_managed",
                   "Managed .NET assembly (CLR " + pe.dotNetRuntimeVersion + ")",
                   0);
      }
      if (!pe.pdbPath.empty()) {
        // Score 0: an embedded PDB path is forensic build metadata present in
        // nearly all release binaries -- valuable intel, but not a malice signal,
        // so it must not inflate the verdict (cf. pe.dotnet_managed).
        AddFinding(result, "pe.debug_pdb_path",
                   "Embedded debug PDB path: " + pe.pdbPath, 0);
      }
      // OriginalFilename stem != the on-disk stem is a rename/masquerade tell.
      // Compare extension-insensitively: legit version resources routinely store
      // the name without its extension (kernel32.dll -> "kernel32"), so a
      // full-name compare would false-positive on clean files.
      if (pe.versionInfo.present && !pe.versionInfo.originalFilename.empty()) {
        auto stem = [](std::string s) {
          const size_t slash = s.find_last_of("\\/");
          if (slash != std::string::npos) {
            s = s.substr(slash + 1);
          }
          const size_t dot = s.find_last_of('.');
          if (dot != std::string::npos && dot != 0) {
            s = s.substr(0, dot);
          }
          for (char &c : s) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          return s;
        };
        const std::string origStem = stem(pe.versionInfo.originalFilename);
        if (!origStem.empty() && stem(PathToUtf8(path.filename())) != origStem) {
          AddFinding(result, "filetype.versioninfo_mismatch",
                     "On-disk name '" + PathToUtf8(path.filename()) +
                         "' differs from the embedded OriginalFilename '" +
                         pe.versionInfo.originalFilename +
                         "' (possible rename/masquerade)",
                     15);
        }
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
  if (!result.sha1.empty()) {
    out << "  sha1: " << result.sha1 << "\n";
  }
  if (!result.md5.empty()) {
    out << "  md5: " << result.md5 << "\n";
  }
  if (!result.imphash.empty()) {
    out << "  imphash: " << result.imphash << "\n";
  }
  out << "  score: " << result.score << " (" << ToString(result.verdict) << ")\n";
  out << "  entropy: " << result.entropy << "\n";
  if (!result.detectedType.empty()) {
    out << "  type: " << result.detectedType << " (by magic bytes)\n";
  }
  out << "  pe: " << (result.isPe ? "yes" : "no")
      << ", signed: " << (result.authenticodeSigned ? "yes" : "no") << "\n";
  for (const auto &sec : result.peSections) {
    out << "  section " << sec.name << ": entropy " << sec.entropy
        << (sec.executable ? " X" : "") << (sec.writable ? " W" : "") << "\n";
  }
  if (result.peOverlaySize > 0) {
    out << "  overlay: " << result.peOverlaySize << " bytes, entropy "
        << result.peOverlayEntropy << "\n";
  }
  if (result.embeddedExecutables > 0) {
    out << "  embedded executables: " << result.embeddedExecutables << "\n";
  }
  if (result.isDotNet) {
    out << "  .NET: yes (CLR " << result.dotNetRuntimeVersion << ")\n";
  }
  if (!result.peExports.empty()) {
    out << "  exports: " << result.peExports.size();
    if (!result.exportName.empty()) {
      out << " (" << result.exportName << ")";
    }
    out << "\n";
  }
  if (result.tlsCallbackCount > 0) {
    out << "  tls callbacks: " << result.tlsCallbackCount << "\n";
  }
  if (!result.pdbPath.empty()) {
    out << "  pdb: " << result.pdbPath << "\n";
  }
  if (result.peVersionInfo.present) {
    out << "  version: " << result.peVersionInfo.companyName;
    if (!result.peVersionInfo.productName.empty()) {
      out << " / " << result.peVersionInfo.productName;
    }
    if (!result.peVersionInfo.originalFilename.empty()) {
      out << " (" << result.peVersionInfo.originalFilename << ")";
    }
    out << "\n";
  }
  if (!result.richHash.empty()) {
    out << "  richhash: " << result.richHash << "\n";
  }
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
