#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/FileUtil.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/IocExport.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/Version.h"
#include "antimal/hv/BlockDevice.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using antimal::Utf8ToWide;
using antimal::WideToUtf8;

// Defense-in-depth hardening for the detonation worker process (opt-in via
// ANTIMAL_VMM_LOWPRIV=1). If a malicious guest ever escaped the WHP boundary into
// THIS host process, these reduce what it can do from inside it. Safe to apply
// because the detonation path spawns NO child process (HyperVOrchestrator has no
// CreateProcess/system call) and the VM has no NIC. Default OFF so it never
// perturbs the desktop-reach boots; the live detonation VM already runs in its own
// HostCli process, isolated from the UI. Best-effort: each step logs + continues.
void ApplyDetonationWorkerHardening() {
  wchar_t buf[8]{};
  const DWORD n = GetEnvironmentVariableW(L"ANTIMAL_VMM_LOWPRIV", buf, 8);
  if (n != 1 || buf[0] != L'1') {
    return;
  }
  int applied = 0, unavailable = 0;

  // 1) No child processes: an escaped guest cannot spawn cmd.exe / powershell /
  //    rundll32 / etc. from this process.
  PROCESS_MITIGATION_CHILD_PROCESS_POLICY cp{};
  cp.NoChildProcessCreation = 1;
  if (SetProcessMitigationPolicy(ProcessChildProcessPolicy, &cp, sizeof(cp)))
    ++applied;
  else
    ++unavailable;

  // 2) Block legacy extension-point DLL injection (AppInit_DLLs, SetWindowsHookEx,
  //    IME, Winsock LSPs) -- classic in-process code-injection vectors.
  PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep{};
  ep.DisableExtensionPoints = 1;
  if (SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ep,
                                 sizeof(ep)))
    ++applied;
  else
    ++unavailable;

  // 3) Refuse to load images over the network or with a low mandatory label --
  //    deny a remote/dropped-DLL load primitive. Safe: the VMM's DLLs (WinHvPlatform,
  //    gdiplus, ...) load from System32, locally.
  PROCESS_MITIGATION_IMAGE_LOAD_POLICY il{};
  il.NoRemoteImages = 1;
  il.NoLowMandatoryLabelImages = 1;
  if (SetProcessMitigationPolicy(ProcessImageLoadPolicy, &il, sizeof(il)))
    ++applied;
  else
    ++unavailable;

  // 4) Permanently REMOVE dangerous token privileges (so they can't be re-enabled).
  //    Matters when detonate is run elevated; a normal user holds few of these.
  //    SeChangeNotifyPrivilege (normal file traversal) is deliberately kept.
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(),
                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    static const wchar_t *kDangerous[] = {
        SE_DEBUG_NAME,         SE_TCB_NAME,
        SE_LOAD_DRIVER_NAME,   SE_BACKUP_NAME,
        SE_RESTORE_NAME,       SE_TAKE_OWNERSHIP_NAME,
        SE_IMPERSONATE_NAME,   SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_CREATE_TOKEN_NAME,  SE_SECURITY_NAME,
        SE_SYSTEMTIME_NAME,    SE_SHUTDOWN_NAME,
        SE_MANAGE_VOLUME_NAME, SE_CREATE_PAGEFILE_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME};
    for (const wchar_t *priv : kDangerous) {
      LUID luid{};
      if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
        continue;
      }
      TOKEN_PRIVILEGES tp{};
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
      if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr,
                                nullptr) &&
          GetLastError() == ERROR_SUCCESS) {
        ++applied;
      }
    }
    CloseHandle(token);
  } else {
    ++unavailable;
  }

  std::cout << "[hardening] low-priv detonation worker: " << applied
            << " mitigations applied, " << unavailable << " unavailable\n";
}

std::string Arg(int argc, wchar_t **argv, int index) {
  if (index < 0 || index >= argc) {
    return {};
  }
  return WideToUtf8(argv[index]);
}

std::optional<std::string> OptionValue(int argc, wchar_t **argv, std::string_view name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (Arg(argc, argv, i) == name) {
      return Arg(argc, argv, i + 1);
    }
  }
  return std::nullopt;
}

bool HasFlag(int argc, wchar_t **argv, std::string_view name) {
  for (int i = 0; i < argc; ++i) {
    if (Arg(argc, argv, i) == name) {
      return true;
    }
  }
  return false;
}

void PrintUsage() {
  std::cout
      << "AntiMal Host CLI\n\n"
      << "Commands:\n"
      << "  antimal init\n"
      << "  antimal scan <path> [--threshold 70]\n"
      << "                    [--no-yara] [--no-capa] [--no-die] [--no-tagger]\n"
      << "                    [--intel] [--vt-key <KEY>] [--json <out.json>]\n"
      << "  antimal detonate <sample> --timeout-sec 180 --network disabled|hostonly|nat\n"
      << "                    [--vcpus 1]   (1 = reliable default; >1 exercises SMP boot)\n"
      << "                    [--allow-execution]  (arms in-guest detonation; needs\n"
      << "                                          dynamic_execution_enabled=true too)\n"
      << "                    [--seed <snapshot.cow>] [--cold]  (default: auto-seed\n"
      << "                                          AntiMalDesktop.cow next to the base)\n"
      << "                    [--nic]  (attach NIC; capture network requests)\n"
      << "  antimal base convert --vhdx <base.vhdx> --raw <AntiMalBase.raw> [--force]\n"
      << "  antimal base inspect --vhdx <base.vhdx> [--overlay <overlay.cow>]\n"
      << "                       [--dump-bcd <out.bcd>] [--dump-system <out.hive>]\n"
      << "  antimal report <run-id-or-report.json> --html\n"
      << "  antimal browser-impact <run-id-or-report.json> --decrypt-browser-secrets\n"
      << "  antimal export <run-id-or-report.json> --format stix|misp|csv [--out <file>]\n";
}

antimal::ScannerOptions BuildScannerOptions(int argc, wchar_t **argv,
                                            const antimal::AppConfig &config) {
  antimal::ScannerOptions opts;
  opts.runYara = config.enrichYara && !HasFlag(argc, argv, "--no-yara");
  opts.runCapa = config.enrichCapa && !HasFlag(argc, argv, "--no-capa");
  opts.runDie = config.enrichDie && !HasFlag(argc, argv, "--no-die");
  opts.applyTagger = config.enrichTagger && !HasFlag(argc, argv, "--no-tagger");
  opts.yaraRulesDir = config.yaraRulesDir;
  opts.tagsRulesPath = config.tagsRulesPath;
  opts.intelLookupEnabled = config.intelEnabled || HasFlag(argc, argv, "--intel");
  opts.malwareBazaarEnabled = config.intelMalwareBazaar;
  opts.virusTotalApiKey =
      OptionValue(argc, argv, "--vt-key").value_or(config.virusTotalApiKey);
  opts.intelCacheDir = config.workspaceRoot.empty()
                           ? std::filesystem::path{}
                           : config.workspaceRoot / "_intel_cache";
  return opts;
}

std::filesystem::path ResolveReportPath(const antimal::AppConfig &config,
                                        const std::filesystem::path &input) {
  if (std::filesystem::exists(input)) {
    return input;
  }
  const auto asRun = config.workspaceRoot / input / "report.json";
  if (std::filesystem::exists(asRun)) {
    return asRun;
  }
  return input;
}

int CommandInit() {
  const auto configPath = antimal::DefaultConfigPath();
  if (std::filesystem::exists(configPath)) {
    std::cout << "Config already exists: " << antimal::PathToUtf8(configPath) << "\n";
    return 0;
  }
  antimal::SaveDefaultConfig(configPath);
  std::cout << "Wrote " << antimal::PathToUtf8(configPath) << "\n";
  return 0;
}

int CommandScan(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  int threshold = 70;
  if (const auto value = OptionValue(argc, argv, "--threshold")) {
    threshold = std::stoi(*value);
  }

  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto scannerOpts = BuildScannerOptions(argc, argv, config);

  const std::filesystem::path target(argv[2]);
  auto results = antimal::ScanPath(target, scannerOpts);
  if (results.empty()) {
    std::cout << "No scan candidates found.\n";
    return 0;
  }

  int flagged = 0;
  for (const auto &result : results) {
    std::cout << antimal::FormatScanText(result);
    if (result.score >= threshold) {
      ++flagged;
      std::cout << "  sandbox: eligible\n";
    }
  }
  std::cout << "Scanned " << results.size() << " file(s), flagged " << flagged << ".\n";

  if (const auto jsonOut = OptionValue(argc, argv, "--json")) {
    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < results.size(); ++i) {
      if (i) json << ",";
      json << antimal::ToJson(results[i]);
    }
    json << "]";
    antimal::WriteTextFile(std::filesystem::path(antimal::Utf8ToWide(*jsonOut)),
                           json.str());
    std::cout << "Wrote scan JSON to " << *jsonOut << "\n";
  }
  return flagged > 0 ? 10 : 0;
}

int CommandDetonate(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }

  auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  uint32_t timeout = config.defaultTimeoutSec;
  if (const auto value = OptionValue(argc, argv, "--timeout-sec")) {
    timeout = static_cast<uint32_t>(std::stoul(*value));
  }
  const auto networkText = OptionValue(argc, argv, "--network").value_or(antimal::ToString(config.networkMode));
  const auto network = antimal::ParseNetworkMode(networkText).value_or(antimal::NetworkMode::Disabled);

  // --vcpus overrides the guest processor count. The orchestrator reads
  // ANTIMAL_VCPU_COUNT, so the flag simply sets it (unless the env var is
  // already present, which takes precedence — explicit env wins over flag).
  if (const auto value = OptionValue(argc, argv, "--vcpus")) {
    if (GetEnvironmentVariableW(L"ANTIMAL_VCPU_COUNT", nullptr, 0) == 0) {
      SetEnvironmentVariableW(L"ANTIMAL_VCPU_COUNT",
                              antimal::Utf8ToWide(*value).c_str());
    }
  }

  // --allow-execution is the per-run half of the two-key execution gate
  // (dynamic_execution_enabled in config is the other). It sets
  // ANTIMAL_AUTHORIZE_EXECUTION, which the orchestrator reads before arming an
  // in-guest detonation. Without BOTH keys the sample is staged but never run.
  if (HasFlag(argc, argv, "--allow-execution")) {
    SetEnvironmentVariableW(L"ANTIMAL_AUTHORIZE_EXECUTION", L"1");
  }

  // --nic attaches an e1000 NIC so the guest's outbound frames are captured and
  // parsed into network.dns/http/connect events (off by default — no NIC).
  if (HasFlag(argc, argv, "--nic")) {
    SetEnvironmentVariableW(L"ANTIMAL_ENABLE_NIC", L"1");
  }

  // Seed/cold boot selection. By default detonation auto-seeds from a desktop
  // snapshot next to the base (reliable). --seed overrides the snapshot path;
  // --cold forces a full cold OOBE boot (intermittent — diagnostics only).
  if (HasFlag(argc, argv, "--cold")) {
    SetEnvironmentVariableW(L"ANTIMAL_COLD_BOOT", L"1");
  }
  if (const auto value = OptionValue(argc, argv, "--seed")) {
    SetEnvironmentVariableW(L"ANTIMAL_SEED_OVERLAY",
                            antimal::Utf8ToWide(*value).c_str());
  }

  antimal::HyperVOrchestrator orchestrator(config);
  auto progress = [](const antimal::DetonationProgress &snap) {
    if (!snap.message.empty()) {
      std::cout << "[" << snap.phase << "] " << snap.message << std::endl;
    }
  };
  // Drop privileges + lock down this worker process before the guest runs
  // (opt-in via ANTIMAL_VMM_LOWPRIV=1; no-op otherwise).
  ApplyDetonationWorkerHardening();
  const auto result = orchestrator.PrepareAndRun(
      std::filesystem::path(argv[2]), timeout, network, true, progress);

  // Machine-readable result for automation / CI / SOAR pipelines. Stable shape;
  // exit code is still 0 (no errors) / 20 (errors) so callers can branch on it.
  if (HasFlag(argc, argv, "--json")) {
    const bool haveReport = std::filesystem::exists(result.reportPath);
    antimal::AnalysisReport report;
    if (haveReport) {
      report = antimal::LoadReportBestEffort(result.reportPath);
      antimal::WriteReportHtml(result.runDir / "report.html", report);
    }
    std::string j = "{";
    j += "\"runId\":" + antimal::JsonQuote(result.runId) + ",";
    j += "\"runDir\":" + antimal::JsonQuote(antimal::PathToUtf8(result.runDir)) + ",";
    j += "\"reportPath\":" +
         antimal::JsonQuote(haveReport ? antimal::PathToUtf8(result.reportPath)
                                       : std::string()) + ",";
    j += "\"status\":" + antimal::JsonQuote(result.status) + ",";
    j += "\"sandboxVerdict\":" +
         antimal::JsonQuote(haveReport ? antimal::ToString(report.sandboxVerdict)
                                       : std::string("error")) + ",";
    j += std::string("\"sampleExecuted\":") +
         ((haveReport && report.dynamicSummary.sampleExecuted) ? "true" : "false") +
         ",";
    j += "\"events\":" +
         std::to_string(haveReport ? report.events.size() : size_t{0}) + ",";
    j += "\"errors\":[";
    for (size_t i = 0; i < result.errors.size(); ++i) {
      if (i) j += ",";
      j += antimal::JsonQuote(result.errors[i]);
    }
    j += "]}";
    std::cout << j << "\n";
    return result.errors.empty() ? 0 : 20;
  }

  std::cout << "Run ID: " << result.runId << "\n";
  std::cout << "Run dir: " << antimal::PathToUtf8(result.runDir) << "\n";
  std::cout << "Job: " << antimal::PathToUtf8(result.jobPath) << "\n";
  if (!result.overlayDiskPath.empty()) {
    std::cout << "Overlay disk: " << antimal::PathToUtf8(result.overlayDiskPath) << "\n";
  }
  const auto inHousePlan = result.runDir / "inhouse-plan.ps1";
  const auto genericPlan = result.runDir / "vm-plan.ps1";
  const auto vmPlan = std::filesystem::exists(inHousePlan)
                          ? inHousePlan
                          : genericPlan;
  std::cout << "VM plan: " << antimal::PathToUtf8(vmPlan) << "\n";
  for (const auto &error : result.errors) {
    std::cout << "error: " << error << "\n";
  }
  if (std::filesystem::exists(result.reportPath)) {
    const auto report = antimal::LoadReportBestEffort(result.reportPath);
    antimal::WriteReportHtml(result.runDir / "report.html", report);
    std::cout << "Report: " << antimal::PathToUtf8(result.reportPath) << "\n";
  }
  return result.errors.empty() ? 0 : 20;
}

uint16_t ReadLe16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadLe32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t *p) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(p[i]) << (i * 8);
  }
  return value;
}

std::string Hex2(uint8_t value) {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
      << static_cast<unsigned>(value);
  return out.str();
}

std::string GuidFromGptBytes(const uint8_t *p) {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setfill('0')
      << std::setw(8) << ReadLe32(p) << "-"
      << std::setw(4) << ReadLe16(p + 4) << "-"
      << std::setw(4) << ReadLe16(p + 6) << "-"
      << Hex2(p[8]) << Hex2(p[9]) << "-"
      << Hex2(p[10]) << Hex2(p[11]) << Hex2(p[12]) << Hex2(p[13])
      << Hex2(p[14]) << Hex2(p[15]);
  return out.str();
}

bool IsZeroGuid(const uint8_t *p) {
  for (size_t i = 0; i < 16; ++i) {
    if (p[i] != 0) {
      return false;
    }
  }
  return true;
}

std::string Utf16LeAsciiName(const uint8_t *p, size_t bytes) {
  std::string out;
  for (size_t i = 0; i + 1 < bytes; i += 2) {
    const uint16_t ch = ReadLe16(p + i);
    if (ch == 0) {
      break;
    }
    out.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?');
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
}

bool ReadDiskBytes(antimal::hv::IBlockDevice &disk, uint64_t byteOffset,
                   uint8_t *out, size_t bytes) {
  size_t done = 0;
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> sector{};
  while (done < bytes) {
    const uint64_t absolute = byteOffset + done;
    const uint64_t lba =
        absolute / antimal::hv::IBlockDevice::kSectorSize;
    const size_t inSector =
        static_cast<size_t>(absolute % antimal::hv::IBlockDevice::kSectorSize);
    const size_t chunk =
        std::min(bytes - done,
                 antimal::hv::IBlockDevice::kSectorSize - inSector);
    if (!disk.ReadSectors(lba, 1, sector.data())) {
      return false;
    }
    std::memcpy(out + done, sector.data() + inSector, chunk);
    done += chunk;
  }
  return true;
}

std::vector<uint8_t> ReadDiskBytes(antimal::hv::IBlockDevice &disk,
                                   uint64_t byteOffset, size_t bytes) {
  std::vector<uint8_t> out(bytes);
  if (!ReadDiskBytes(disk, byteOffset, out.data(), out.size())) {
    out.clear();
  }
  return out;
}

struct GptPartitionInfo {
  uint32_t index = 0;
  std::string typeGuid;
  std::string uniqueGuid;
  uint64_t firstLba = 0;
  uint64_t lastLba = 0;
  std::string name;
};

std::string PartitionKind(const std::string &guid) {
  if (guid == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") {
    return "ESP";
  }
  if (guid == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7") {
    return "Windows/basic-data";
  }
  if (guid == "E3C9E316-0B5C-4DB8-817D-F92DF00215AE") {
    return "MSR";
  }
  if (guid == "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC") {
    return "Windows-recovery";
  }
  return "other";
}

std::vector<GptPartitionInfo> ReadGptPartitions(antimal::hv::IBlockDevice &disk) {
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> header{};
  if (!disk.ReadSectors(1, 1, header.data()) ||
      std::memcmp(header.data(), "EFI PART", 8) != 0) {
    throw std::runtime_error("GPT header not found at LBA 1");
  }

  const uint64_t entriesLba = ReadLe64(header.data() + 72);
  const uint32_t entryCount = ReadLe32(header.data() + 80);
  const uint32_t entrySize = ReadLe32(header.data() + 84);
  if (entrySize < 128 || entrySize > 4096 || entryCount > 4096) {
    throw std::runtime_error("GPT partition array shape is unsupported");
  }

  std::vector<GptPartitionInfo> out;
  const uint64_t entriesOffset =
      entriesLba * antimal::hv::IBlockDevice::kSectorSize;
  for (uint32_t i = 0; i < entryCount; ++i) {
    auto entry = ReadDiskBytes(disk, entriesOffset + i * entrySize, entrySize);
    if (entry.empty()) {
      throw std::runtime_error("failed to read GPT partition entry");
    }
    if (IsZeroGuid(entry.data())) {
      continue;
    }
    GptPartitionInfo part;
    part.index = i + 1;
    part.typeGuid = GuidFromGptBytes(entry.data());
    part.uniqueGuid = GuidFromGptBytes(entry.data() + 16);
    part.firstLba = ReadLe64(entry.data() + 32);
    part.lastLba = ReadLe64(entry.data() + 40);
    part.name = Utf16LeAsciiName(entry.data() + 56, std::min<size_t>(72, entry.size() - 56));
    out.push_back(std::move(part));
  }
  return out;
}

std::string ToUpperAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return value;
}

std::vector<std::string> SplitPathComponents(std::string path) {
  std::replace(path.begin(), path.end(), '/', '\\');
  std::vector<std::string> out;
  size_t start = 0;
  while (start < path.size()) {
    const size_t slash = path.find('\\', start);
    const size_t end = slash == std::string::npos ? path.size() : slash;
    if (end > start) {
      out.push_back(ToUpperAscii(path.substr(start, end - start)));
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }
  return out;
}

std::string ShortNameFromEntry(const uint8_t *entry) {
  std::string name(reinterpret_cast<const char *>(entry), 8);
  std::string ext(reinterpret_cast<const char *>(entry + 8), 3);
  while (!name.empty() && name.back() == ' ') {
    name.pop_back();
  }
  while (!ext.empty() && ext.back() == ' ') {
    ext.pop_back();
  }
  return ext.empty() ? ToUpperAscii(name) : ToUpperAscii(name + "." + ext);
}

std::string FatLongNamePart(const uint8_t *entry) {
  const int offsets[] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
  std::string out;
  for (int offset : offsets) {
    const uint16_t ch = ReadLe16(entry + offset);
    if (ch == 0x0000 || ch == 0xFFFF) {
      break;
    }
    out.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?');
  }
  return out;
}

class Fat32Reader {
public:
  Fat32Reader(antimal::hv::IBlockDevice &disk, uint64_t firstLba)
      : disk_(disk), firstLba_(firstLba) {}

  struct Entry {
    std::string name;
    uint8_t attributes = 0;
    uint32_t firstCluster = 0;
    uint32_t size = 0;
  };

  bool Init() {
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> bs{};
    if (!disk_.ReadSectors(firstLba_, 1, bs.data())) {
      return false;
    }
    if (std::memcmp(bs.data() + 82, "FAT32", 5) != 0) {
      return false;
    }
    bytesPerSector_ = ReadLe16(bs.data() + 11);
    sectorsPerCluster_ = bs[13];
    reservedSectors_ = ReadLe16(bs.data() + 14);
    fatCount_ = bs[16];
    fatSizeSectors_ = ReadLe32(bs.data() + 36);
    rootCluster_ = ReadLe32(bs.data() + 44);
    if (bytesPerSector_ != antimal::hv::IBlockDevice::kSectorSize ||
        sectorsPerCluster_ == 0 || reservedSectors_ == 0 ||
        fatCount_ == 0 || fatSizeSectors_ == 0 || rootCluster_ < 2) {
      return false;
    }
    fatStartLba_ = firstLba_ + reservedSectors_;
    dataStartLba_ = fatStartLba_ + static_cast<uint64_t>(fatCount_) * fatSizeSectors_;
    return true;
  }

  std::optional<Entry> FindPath(std::string path) {
    auto components = SplitPathComponents(std::move(path));
    if (components.empty()) {
      return std::nullopt;
    }
    uint32_t cluster = rootCluster_;
    std::optional<Entry> current;
    for (size_t i = 0; i < components.size(); ++i) {
      const auto entries = ReadDirectory(cluster);
      current.reset();
      for (const auto &entry : entries) {
        if (entry.name == components[i]) {
          current = entry;
          break;
        }
      }
      if (!current) {
        return std::nullopt;
      }
      if (i + 1 < components.size()) {
        if ((current->attributes & 0x10u) == 0 || current->firstCluster < 2) {
          return std::nullopt;
        }
        cluster = current->firstCluster;
      }
    }
    return current;
  }

  std::vector<uint8_t> ReadFile(const Entry &entry, size_t maxBytes) {
    std::vector<uint8_t> out;
    out.reserve(std::min<size_t>(entry.size, maxBytes));
    uint32_t cluster = entry.firstCluster;
    std::vector<uint8_t> clusterBytes(ClusterBytes());
    while (cluster >= 2 && !IsEoc(cluster) && out.size() < maxBytes) {
      if (!ReadCluster(cluster, clusterBytes.data())) {
        break;
      }
      const size_t remainingFile =
          entry.size > out.size() ? entry.size - out.size() : 0;
      const size_t take =
          std::min({clusterBytes.size(), maxBytes - out.size(), remainingFile});
      out.insert(out.end(), clusterBytes.begin(), clusterBytes.begin() + take);
      if (take == 0) {
        break;
      }
      cluster = NextCluster(cluster);
    }
    return out;
  }

  uint16_t BytesPerSector() const noexcept { return bytesPerSector_; }
  uint8_t SectorsPerCluster() const noexcept { return sectorsPerCluster_; }
  uint32_t RootCluster() const noexcept { return rootCluster_; }

private:
  size_t ClusterBytes() const noexcept {
    return static_cast<size_t>(bytesPerSector_) * sectorsPerCluster_;
  }

  bool ReadCluster(uint32_t cluster, uint8_t *out) {
    if (cluster < 2) {
      return false;
    }
    const uint64_t lba =
        dataStartLba_ + static_cast<uint64_t>(cluster - 2) * sectorsPerCluster_;
    return disk_.ReadSectors(lba, sectorsPerCluster_, out);
  }

  uint32_t NextCluster(uint32_t cluster) {
    std::array<uint8_t, 4> bytes{};
    const uint64_t offset =
        (fatStartLba_ * antimal::hv::IBlockDevice::kSectorSize) +
        static_cast<uint64_t>(cluster) * 4ull;
    if (!ReadDiskBytes(disk_, offset, bytes.data(), bytes.size())) {
      return 0x0FFFFFFF;
    }
    return ReadLe32(bytes.data()) & 0x0FFFFFFFu;
  }

  static bool IsEoc(uint32_t cluster) noexcept {
    return cluster >= 0x0FFFFFF8u;
  }

  std::vector<Entry> ReadDirectory(uint32_t startCluster) {
    std::vector<Entry> out;
    uint32_t cluster = startCluster;
    std::vector<uint8_t> bytes(ClusterBytes());
    std::string longName;
    size_t guard = 0;
    while (cluster >= 2 && !IsEoc(cluster) && guard++ < 65536) {
      if (!ReadCluster(cluster, bytes.data())) {
        break;
      }
      for (size_t off = 0; off + 32 <= bytes.size(); off += 32) {
        const uint8_t *entry = bytes.data() + off;
        if (entry[0] == 0x00) {
          return out;
        }
        if (entry[0] == 0xE5 || entry[11] == 0x0F) {
          if (entry[0] != 0xE5 && entry[11] == 0x0F) {
            longName = FatLongNamePart(entry) + longName;
          } else {
            longName.clear();
          }
          continue;
        }
        Entry dir;
        dir.name =
            longName.empty() ? ShortNameFromEntry(entry) : ToUpperAscii(longName);
        dir.attributes = entry[11];
        dir.firstCluster =
            (static_cast<uint32_t>(ReadLe16(entry + 20)) << 16) |
            ReadLe16(entry + 26);
        dir.size = ReadLe32(entry + 28);
        out.push_back(std::move(dir));
        longName.clear();
      }
      cluster = NextCluster(cluster);
    }
    return out;
  }

  antimal::hv::IBlockDevice &disk_;
  uint64_t firstLba_ = 0;
  uint16_t bytesPerSector_ = 0;
  uint8_t sectorsPerCluster_ = 0;
  uint16_t reservedSectors_ = 0;
  uint8_t fatCount_ = 0;
  uint32_t fatSizeSectors_ = 0;
  uint32_t rootCluster_ = 0;
  uint64_t fatStartLba_ = 0;
  uint64_t dataStartLba_ = 0;
};

class NtfsReader {
public:
  NtfsReader(antimal::hv::IBlockDevice &disk, uint64_t firstLba)
      : disk_(disk), firstLba_(firstLba) {}

  struct DataRun {
    uint64_t lcn = 0;
    uint64_t clusters = 0;
  };

  struct Entry {
    uint64_t fileRecord = 0;
    uint64_t size = 0;
    bool directory = false;
    bool dataResident = false;
    std::vector<DataRun> dataRuns;
    std::vector<uint8_t> residentData; // inline $DATA for small (resident) files
  };

  bool Init() {
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> bs{};
    if (!disk_.ReadSectors(firstLba_, 1, bs.data()) ||
        std::memcmp(bs.data() + 3, "NTFS    ", 8) != 0) {
      return false;
    }
    bytesPerSector_ = ReadLe16(bs.data() + 11);
    sectorsPerCluster_ = bs[13];
    mftLcn_ = ReadLe64(bs.data() + 48);
    const int8_t fileRecordClusters =
        static_cast<int8_t>(static_cast<char>(bs[64]));
    if (bytesPerSector_ != antimal::hv::IBlockDevice::kSectorSize ||
        sectorsPerCluster_ == 0 || mftLcn_ == 0) {
      return false;
    }
    if (fileRecordClusters < 0) {
      fileRecordBytes_ = 1ull << static_cast<unsigned>(-fileRecordClusters);
    } else {
      fileRecordBytes_ = static_cast<uint32_t>(fileRecordClusters) *
                         ClusterBytes();
    }
    if (fileRecordBytes_ < 512 || fileRecordBytes_ > 4096) {
      return false;
    }

    std::vector<uint8_t> record0(fileRecordBytes_);
    if (!ReadVolumeBytes(mftLcn_ * ClusterBytes(), record0.data(),
                         record0.size()) ||
        !ApplyFixups(record0, "FILE")) {
      return false;
    }
    for (const auto &attr : Attributes(record0)) {
      if (attr.type == 0x80 && attr.nonResident && !attr.runs.empty()) {
        mftRuns_ = attr.runs;
        mftDataSize_ = attr.realSize;
        break;
      }
    }
    if (mftRuns_.empty()) {
      mftRuns_.push_back({mftLcn_, 1024 * 1024});
      mftDataSize_ = 1024ull * 1024ull * fileRecordBytes_;
    }
    return true;
  }

  std::optional<Entry> FindPath(std::string path) {
    auto components = SplitPathComponents(std::move(path));
    if (components.empty()) {
      return std::nullopt;
    }

    Entry current;
    current.fileRecord = 5; // NTFS root directory.
    current.directory = true;
    for (size_t i = 0; i < components.size(); ++i) {
      if (!current.directory) {
        return std::nullopt;
      }
      const auto entries = ReadDirectory(current.fileRecord);
      std::optional<Entry> next;
      for (const auto &entry : entries) {
        if (entry.nameSpace == 2) {
          continue; // Prefer Win32 names over DOS 8.3 aliases.
        }
        if (entry.name == components[i]) {
          next = Entry{};
          next->fileRecord = entry.fileRecord;
          next->size = entry.size;
          next->directory = entry.directory;
          break;
        }
      }
      if (!next) {
        return std::nullopt;
      }
      current = *next;
    }
    PopulateDataRuns(current);
    return current;
  }

  // Diagnostic: list the immediate children of a directory (name/size/dir).
  struct DirChild {
    std::string name;
    uint64_t size = 0;
    bool directory = false;
  };
  std::vector<DirChild> ListDir(std::string path) {
    std::vector<DirChild> out;
    const auto dir = FindPath(std::move(path));
    if (!dir || !dir->directory) {
      return out;
    }
    for (const auto &e : ReadDirectory(dir->fileRecord)) {
      if (e.nameSpace == 2) continue; // skip DOS 8.3 aliases
      out.push_back({e.name, e.size, e.directory});
    }
    return out;
  }

  uint16_t BytesPerSector() const noexcept { return bytesPerSector_; }
  uint8_t SectorsPerCluster() const noexcept { return sectorsPerCluster_; }
  size_t ClusterBytes() const noexcept {
    return static_cast<size_t>(bytesPerSector_) * sectorsPerCluster_;
  }
  uint64_t MftLcn() const noexcept { return mftLcn_; }
  uint32_t FileRecordBytes() const noexcept { return fileRecordBytes_; }

  std::vector<uint8_t> ReadFile(const Entry &entry, uint64_t maxBytes) {
    if (entry.directory || entry.size == 0) {
      return {};
    }
    const uint64_t bytes = std::min<uint64_t>(entry.size, maxBytes);
    if (bytes > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
      return {};
    }
    // Small files store their $DATA resident (inline in the MFT record); the
    // breadcrumb logs land here. Non-resident files use the data-run path.
    if (entry.dataResident) {
      const size_t n =
          std::min<size_t>(entry.residentData.size(), static_cast<size_t>(bytes));
      return std::vector<uint8_t>(entry.residentData.begin(),
                                  entry.residentData.begin() + n);
    }
    if (entry.dataRuns.empty()) {
      return {};
    }
    std::vector<uint8_t> out(static_cast<size_t>(bytes));
    if (!ReadStreamBytes(entry.dataRuns, 0, out.data(), out.size())) {
      return {};
    }
    return out;
  }

private:
  struct Attribute {
    uint32_t type = 0;
    bool nonResident = false;
    std::vector<uint8_t> residentData;
    std::vector<DataRun> runs;
    uint64_t realSize = 0;
  };

  struct DirectoryEntry {
    std::string name;
    uint8_t nameSpace = 0;
    uint64_t fileRecord = 0;
    uint64_t size = 0;
    bool directory = false;
  };

  bool ReadVolumeBytes(uint64_t volumeOffset, uint8_t *out, size_t bytes) {
    return ReadDiskBytes(disk_,
                         firstLba_ * antimal::hv::IBlockDevice::kSectorSize +
                             volumeOffset,
                         out, bytes);
  }

  static int64_t ReadSignedRunOffset(const uint8_t *p, uint8_t bytes) {
    int64_t value = 0;
    for (uint8_t i = 0; i < bytes; ++i) {
      value |= static_cast<int64_t>(p[i]) << (i * 8);
    }
    if (bytes > 0 && (p[bytes - 1] & 0x80u) != 0) {
      value |= -1ll << (bytes * 8);
    }
    return value;
  }

  static uint64_t ReadUnsignedRunLength(const uint8_t *p, uint8_t bytes) {
    uint64_t value = 0;
    for (uint8_t i = 0; i < bytes; ++i) {
      value |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return value;
  }

  std::vector<DataRun> ParseDataRuns(const uint8_t *p, size_t bytes) const {
    std::vector<DataRun> runs;
    int64_t currentLcn = 0;
    size_t offset = 0;
    while (offset < bytes && p[offset] != 0) {
      const uint8_t header = p[offset++];
      const uint8_t lengthBytes = header & 0x0Fu;
      const uint8_t offsetBytes = (header >> 4) & 0x0Fu;
      if (lengthBytes == 0 || offset + lengthBytes + offsetBytes > bytes) {
        break;
      }
      const uint64_t clusters = ReadUnsignedRunLength(p + offset, lengthBytes);
      offset += lengthBytes;
      const int64_t lcnDelta = ReadSignedRunOffset(p + offset, offsetBytes);
      offset += offsetBytes;
      currentLcn += lcnDelta;
      if (currentLcn >= 0 && clusters != 0) {
        runs.push_back({static_cast<uint64_t>(currentLcn), clusters});
      }
    }
    return runs;
  }

  bool ReadStreamBytes(const std::vector<DataRun> &runs, uint64_t streamOffset,
                       uint8_t *out, size_t bytes) {
    size_t done = 0;
    uint64_t logical = 0;
    const uint64_t clusterBytes = ClusterBytes();
    for (const auto &run : runs) {
      const uint64_t runBytes = run.clusters * clusterBytes;
      if (streamOffset >= logical + runBytes) {
        logical += runBytes;
        continue;
      }
      const uint64_t inRun =
          streamOffset > logical ? streamOffset - logical : 0;
      const uint64_t take =
          std::min<uint64_t>(bytes - done, runBytes - inRun);
      if (!ReadVolumeBytes(run.lcn * clusterBytes + inRun, out + done,
                           static_cast<size_t>(take))) {
        return false;
      }
      done += static_cast<size_t>(take);
      streamOffset += take;
      logical += runBytes;
      if (done == bytes) {
        return true;
      }
    }
    return done == bytes;
  }

  bool ApplyFixups(std::vector<uint8_t> &record, const char *signature) const {
    if (record.size() < 8 || std::memcmp(record.data(), signature, 4) != 0) {
      return false;
    }
    const uint16_t usaOffset = ReadLe16(record.data() + 4);
    const uint16_t usaCount = ReadLe16(record.data() + 6);
    if (usaOffset + usaCount * 2ull > record.size() || usaCount == 0) {
      return false;
    }
    const uint16_t sectors =
        static_cast<uint16_t>(record.size() / bytesPerSector_);
    if (usaCount < sectors + 1) {
      return false;
    }
    const uint16_t updateSequence = ReadLe16(record.data() + usaOffset);
    for (uint16_t i = 0; i < sectors; ++i) {
      const size_t trailer = (i + 1ull) * bytesPerSector_ - 2;
      if (trailer + 2 > record.size() ||
          ReadLe16(record.data() + trailer) != updateSequence) {
        return false;
      }
      const uint16_t replacement =
          ReadLe16(record.data() + usaOffset + (i + 1ull) * 2);
      record[trailer] = static_cast<uint8_t>(replacement & 0xFFu);
      record[trailer + 1] = static_cast<uint8_t>((replacement >> 8) & 0xFFu);
    }
    return true;
  }

  bool ReadFileRecord(uint64_t fileRecord, std::vector<uint8_t> &out) {
    out.assign(fileRecordBytes_, 0);
    const uint64_t offset = fileRecord * fileRecordBytes_;
    if (offset + fileRecordBytes_ > mftDataSize_ ||
        !ReadStreamBytes(mftRuns_, offset, out.data(), out.size())) {
      return false;
    }
    return ApplyFixups(out, "FILE");
  }

  void PopulateDataRuns(Entry &entry) {
    if (entry.directory) {
      return;
    }
    std::vector<uint8_t> record;
    if (!ReadFileRecord(entry.fileRecord, record)) {
      return;
    }
    for (const auto &attr : Attributes(record)) {
      if (attr.type != 0x80) {
        continue;
      }
      entry.dataResident = !attr.nonResident;
      entry.size = attr.nonResident ? attr.realSize : attr.residentData.size();
      entry.dataRuns = attr.runs;
      entry.residentData = attr.residentData;
      return;
    }
  }

  std::vector<Attribute> Attributes(const std::vector<uint8_t> &record) const {
    std::vector<Attribute> out;
    if (record.size() < 24) {
      return out;
    }
    size_t offset = ReadLe16(record.data() + 20);
    while (offset + 16 <= record.size()) {
      const uint32_t type = ReadLe32(record.data() + offset);
      if (type == 0xFFFFFFFFu) {
        break;
      }
      const uint32_t length = ReadLe32(record.data() + offset + 4);
      if (length < 16 || offset + length > record.size()) {
        break;
      }
      Attribute attr;
      attr.type = type;
      attr.nonResident = record[offset + 8] != 0;
      if (!attr.nonResident) {
        if (offset + 24 <= record.size()) {
          const uint32_t valueLength = ReadLe32(record.data() + offset + 16);
          const uint16_t valueOffset = ReadLe16(record.data() + offset + 20);
          if (valueOffset + valueLength <= length) {
            attr.residentData.assign(record.begin() + offset + valueOffset,
                                     record.begin() + offset + valueOffset +
                                         valueLength);
          }
        }
      } else if (offset + 64 <= record.size()) {
        const uint16_t runOffset = ReadLe16(record.data() + offset + 32);
        attr.realSize = ReadLe64(record.data() + offset + 48);
        if (runOffset < length) {
          attr.runs = ParseDataRuns(record.data() + offset + runOffset,
                                    length - runOffset);
        }
      }
      out.push_back(std::move(attr));
      offset += length;
    }
    return out;
  }

  static uint64_t FileReferenceToRecord(uint64_t reference) {
    return reference & 0x0000FFFFFFFFFFFFull;
  }

  static std::string NtfsFileNameToAscii(const uint8_t *p, size_t bytes) {
    if (bytes < 66) {
      return {};
    }
    const uint8_t nameLength = p[64];
    const size_t nameBytes = static_cast<size_t>(nameLength) * 2;
    if (66 + nameBytes > bytes) {
      return {};
    }
    return ToUpperAscii(Utf16LeAsciiName(p + 66, nameBytes));
  }

  std::vector<DirectoryEntry> ParseIndexEntries(const uint8_t *data,
                                                size_t bytes) const {
    std::vector<DirectoryEntry> entries;
    size_t offset = 0;
    size_t guard = 0;
    while (offset + 16 <= bytes && guard++ < 65536) {
      const uint64_t reference = ReadLe64(data + offset);
      const uint16_t entryLength = ReadLe16(data + offset + 8);
      const uint16_t keyLength = ReadLe16(data + offset + 10);
      const uint16_t flags = ReadLe16(data + offset + 12);
      if ((flags & 0x2u) != 0) {
        break;
      }
      if (entryLength < 16 || offset + entryLength > bytes) {
        break;
      }
      if (keyLength >= 66 && 16ull + keyLength <= entryLength) {
        const uint8_t *name = data + offset + 16;
        DirectoryEntry entry;
        entry.name = NtfsFileNameToAscii(name, keyLength);
        entry.nameSpace = name[65];
        entry.fileRecord = FileReferenceToRecord(reference);
        entry.size = ReadLe64(name + 48);
        const uint32_t fileFlags = ReadLe32(name + 56);
        entry.directory = (fileFlags & 0x10000000u) != 0;
        if (!entry.name.empty() && entry.name != "." && entry.name != "$I30") {
          entries.push_back(std::move(entry));
        }
      }
      offset += entryLength;
    }
    return entries;
  }

  std::vector<DirectoryEntry> ReadDirectory(uint64_t fileRecord) {
    std::vector<DirectoryEntry> out;
    std::vector<uint8_t> record;
    if (!ReadFileRecord(fileRecord, record)) {
      return out;
    }
    uint32_t indexBlockSize = 0;
    for (const auto &attr : Attributes(record)) {
      if (attr.type != 0x90 || attr.residentData.size() < 32) {
        continue;
      }
      indexBlockSize = ReadLe32(attr.residentData.data() + 8);
      const size_t indexHeader = 16;
      const uint32_t entryOffset =
          ReadLe32(attr.residentData.data() + indexHeader);
      const uint32_t totalSize =
          ReadLe32(attr.residentData.data() + indexHeader + 4);
      const size_t start = indexHeader + entryOffset;
      const size_t end = std::min<size_t>(indexHeader + totalSize,
                                          attr.residentData.size());
      if (start < end) {
        auto entries =
            ParseIndexEntries(attr.residentData.data() + start, end - start);
        out.insert(out.end(), entries.begin(), entries.end());
      }
    }
    for (const auto &attr : Attributes(record)) {
      if (attr.type != 0xA0 || !attr.nonResident || attr.runs.empty() ||
          indexBlockSize == 0 || attr.realSize == 0 ||
          attr.realSize > 256ull * 1024ull * 1024ull) {
        continue;
      }
      std::vector<uint8_t> stream(static_cast<size_t>(attr.realSize));
      if (!ReadStreamBytes(attr.runs, 0, stream.data(), stream.size())) {
        continue;
      }
      for (size_t offset = 0; offset + indexBlockSize <= stream.size();
           offset += indexBlockSize) {
        std::vector<uint8_t> block(stream.begin() + offset,
                                   stream.begin() + offset + indexBlockSize);
        if (!ApplyFixups(block, "INDX") || block.size() < 0x28) {
          continue;
        }
        const size_t indexHeader = 0x18;
        const uint32_t entryOffset = ReadLe32(block.data() + indexHeader);
        const uint32_t totalSize = ReadLe32(block.data() + indexHeader + 4);
        const size_t start = indexHeader + entryOffset;
        const size_t end =
            std::min<size_t>(indexHeader + totalSize, block.size());
        if (start < end) {
          auto entries = ParseIndexEntries(block.data() + start, end - start);
          out.insert(out.end(), entries.begin(), entries.end());
        }
      }
    }
    return out;
  }

  antimal::hv::IBlockDevice &disk_;
  uint64_t firstLba_ = 0;
  uint16_t bytesPerSector_ = 0;
  uint8_t sectorsPerCluster_ = 0;
  uint64_t mftLcn_ = 0;
  uint32_t fileRecordBytes_ = 0;
  uint64_t mftDataSize_ = 0;
  std::vector<DataRun> mftRuns_;
};

bool ContainsUtf16AsciiNoCase(const std::vector<uint8_t> &bytes,
                              std::string needle) {
  needle = ToUpperAscii(std::move(needle));
  if (needle.empty() || bytes.size() < needle.size() * 2) {
    return false;
  }
  for (size_t i = 0; i + needle.size() * 2 <= bytes.size(); ++i) {
    bool match = true;
    for (size_t j = 0; j < needle.size(); ++j) {
      const auto lo = static_cast<char>(
          std::toupper(static_cast<unsigned char>(bytes[i + j * 2])));
      if (lo != needle[j] || bytes[i + j * 2 + 1] != 0) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

bool ContainsAsciiNoCase(const std::vector<uint8_t> &bytes, std::string needle) {
  needle = ToUpperAscii(std::move(needle));
  if (needle.empty() || bytes.size() < needle.size()) {
    return false;
  }
  for (size_t i = 0; i + needle.size() <= bytes.size(); ++i) {
    bool match = true;
    for (size_t j = 0; j < needle.size(); ++j) {
      if (static_cast<char>(
              std::toupper(static_cast<unsigned char>(bytes[i + j]))) !=
          needle[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

std::string TrimTrailingNulls(std::string value) {
  while (!value.empty() && value.back() == '\0') {
    value.pop_back();
  }
  return value;
}

std::string Utf16LeAsciiString(const std::vector<uint8_t> &bytes) {
  std::string out;
  for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
    const uint16_t ch = ReadLe16(bytes.data() + i);
    if (ch == 0) {
      break;
    }
    out.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?');
  }
  return out;
}

std::vector<std::string> Utf16LeAsciiMultiString(
    const std::vector<uint8_t> &bytes) {
  std::vector<std::string> out;
  std::string current;
  for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
    const uint16_t ch = ReadLe16(bytes.data() + i);
    if (ch == 0) {
      if (!current.empty()) {
        out.push_back(current);
        current.clear();
      }
      continue;
    }
    current.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?');
  }
  if (!current.empty()) {
    out.push_back(current);
  }
  return out;
}

bool EqualNoCase(std::string lhs, std::string rhs) {
  return ToUpperAscii(std::move(lhs)) == ToUpperAscii(std::move(rhs));
}

std::string BcdObjectAlias(const std::string &guid) {
  const auto upper = ToUpperAscii(guid);
  if (upper == "{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}") {
    return "{bootmgr}";
  }
  if (upper == "{B2721D73-1DB4-4C62-BF78-C548A880142D}") {
    return "{memdiag}";
  }
  if (upper == "{4636856E-540F-4170-A130-A84776F4C654}") {
    return "{dbgsettings}";
  }
  if (upper == "{7EA2E1AC-2E61-4728-AAA3-896D9D0A9F0E}") {
    return "{globalsettings}";
  }
  if (upper == "{6EFB52BF-1766-41DB-A6B3-0EE5EFF72BD7}") {
    return "{bootloadersettings}";
  }
  if (upper == "{0CE4991B-E6B3-4B16-B23C-5E0D9250E5D9}") {
    return "{emssettings}";
  }
  if (upper == "{1AFA9C49-16AB-4A5C-901B-212802DA9460}") {
    return "{resumeloadersettings}";
  }
  if (upper == "{1CAE1EB7-A0DF-4D4D-9851-4860E34EF535}") {
    return "{defaultbootentry}";
  }
  return guid;
}

std::string BcdObjectTypeName(uint32_t type) {
  switch (type) {
  case 0x10100002:
    return "Windows Boot Manager";
  case 0x10200003:
    return "Windows Boot Loader";
  case 0x10200004:
    return "Windows Resume Loader";
  case 0x10200005:
    return "Windows Memory Diagnostic";
  case 0x20200003:
    return "Device Options";
  case 0x20200004:
    return "Debugger Settings";
  default:
    return "BCD object";
  }
}

std::string BcdElementName(const std::string &id) {
  const auto upper = ToUpperAscii(id);
  if (upper == "11000001") {
    return "device";
  }
  if (upper == "21000001") {
    return "osdevice";
  }
  if (upper == "12000002") {
    return "path";
  }
  if (upper == "12000004") {
    return "description";
  }
  if (upper == "12000005") {
    return "locale";
  }
  if (upper == "14000006") {
    return "inherit";
  }
  if (upper == "16000009") {
    return "recoveryenabled";
  }
  if (upper == "16000010") {
    return "bootdebug";
  }
  if (upper == "16000020") {
    return "advancedoptions";
  }
  if (upper == "16000040") {
    return "bootlog";
  }
  if (upper == "16000045") {
    return "firstmegabytepolicy";
  }
  if (upper == "16000048") {
    return "nointegritychecks";
  }
  if (upper == "16000049") {
    return "testsigning";
  }
  if (upper == "16000060") {
    return "isolatedcontext";
  }
  if (upper == "16000067") {
    return "ems";
  }
  if (upper == "22000002") {
    return "systemroot";
  }
  if (upper == "23000003") {
    return "default/resumeobject";
  }
  if (upper == "23000006") {
    return "resumeobject";
  }
  if (upper == "24000001") {
    return "displayorder";
  }
  if (upper == "24000010") {
    return "toolsdisplayorder";
  }
  if (upper == "25000004") {
    return "timeout";
  }
  if (upper == "25000020") {
    return "nx";
  }
  if (upper == "25000022") {
    return "debugtype";
  }
  if (upper == "25000023") {
    return "debugport";
  }
  if (upper == "25000024") {
    return "baudrate";
  }
  if (upper == "250000C2") {
    return "bootmenupolicy";
  }
  if (upper == "250000E0") {
    return "bootstatuspolicy";
  }
  if (upper == "26000040") {
    return "debug";
  }
  return upper;
}

std::string PartitionLabelForUniqueGuid(
    const std::vector<GptPartitionInfo> &partitions, const std::string &guid) {
  for (const auto &part : partitions) {
    if (EqualNoCase(part.uniqueGuid, guid)) {
      std::ostringstream out;
      out << PartitionKind(part.typeGuid) << " partition " << part.index;
      if (!part.name.empty()) {
        out << " \"" << part.name << "\"";
      }
      return out.str();
    }
  }
  return "not present in GPT";
}

struct HiveKeyInfo {
  uint32_t index = 0;
  uint16_t flags = 0;
  uint32_t subkeyCounts[2] = {0, 0};
  uint32_t subkeyLists[2] = {0xFFFFFFFFu, 0xFFFFFFFFu};
  uint32_t valueCount = 0;
  uint32_t valueList = 0xFFFFFFFFu;
  std::string name;
};

struct HiveValueInfo {
  std::string name;
  uint32_t type = 0;
  std::vector<uint8_t> data;
};

class RegistryHiveReader {
public:
  explicit RegistryHiveReader(const std::vector<uint8_t> &bytes)
      : bytes_(bytes) {}

  bool IsValid() const {
    return bytes_.size() >= 0x1000 && std::memcmp(bytes_.data(), "regf", 4) == 0;
  }

  std::optional<uint32_t> RootIndex() const {
    if (!IsValid() || bytes_.size() < 0x28) {
      return std::nullopt;
    }
    return ReadLe32(bytes_.data() + 0x24);
  }

  std::optional<HiveKeyInfo> ReadKey(uint32_t index) const {
    const auto cell = CellAbsolute(index);
    if (!cell || *cell + 80 > bytes_.size()) {
      return std::nullopt;
    }
    const size_t data = *cell + 4;
    if (std::memcmp(bytes_.data() + data, "nk", 2) != 0) {
      return std::nullopt;
    }
    HiveKeyInfo key;
    key.index = index;
    key.flags = ReadLe16(bytes_.data() + data + 2);
    key.subkeyCounts[0] = ReadLe32(bytes_.data() + data + 20);
    key.subkeyCounts[1] = ReadLe32(bytes_.data() + data + 24);
    key.subkeyLists[0] = ReadLe32(bytes_.data() + data + 28);
    key.subkeyLists[1] = ReadLe32(bytes_.data() + data + 32);
    key.valueCount = ReadLe32(bytes_.data() + data + 36);
    key.valueList = ReadLe32(bytes_.data() + data + 40);
    const uint16_t nameLen = ReadLe16(bytes_.data() + data + 72);
    if (data + 76 + nameLen > bytes_.size()) {
      return std::nullopt;
    }
    if ((key.flags & 0x20u) != 0) {
      key.name.assign(reinterpret_cast<const char *>(bytes_.data() + data + 76),
                      nameLen);
    } else {
      key.name = Utf16LeAsciiName(bytes_.data() + data + 76, nameLen);
    }
    return key;
  }

  std::vector<uint32_t> SubkeyIndexes(uint32_t index) const {
    std::vector<uint32_t> out;
    const auto key = ReadKey(index);
    if (!key) {
      return out;
    }
    for (size_t i = 0; i < 2; ++i) {
      if (key->subkeyCounts[i] == 0 || key->subkeyLists[i] == 0xFFFFFFFFu) {
        continue;
      }
      ReadSubkeyList(key->subkeyLists[i], key->subkeyCounts[i], out, 0);
    }
    return out;
  }

  std::optional<uint32_t> FindSubkey(uint32_t index,
                                     const std::string &name) const {
    for (const auto child : SubkeyIndexes(index)) {
      const auto key = ReadKey(child);
      if (key && EqualNoCase(key->name, name)) {
        return child;
      }
    }
    return std::nullopt;
  }

  std::vector<HiveValueInfo> Values(uint32_t index) const {
    std::vector<HiveValueInfo> out;
    const auto key = ReadKey(index);
    if (!key || key->valueCount == 0 || key->valueList == 0xFFFFFFFFu) {
      return out;
    }
    const auto listCell = CellAbsolute(key->valueList);
    if (!listCell || *listCell + 4 + key->valueCount * 4ull > bytes_.size()) {
      return out;
    }
    const size_t list = *listCell + 4;
    for (uint32_t i = 0; i < key->valueCount; ++i) {
      auto value = ReadValue(ReadLe32(bytes_.data() + list + i * 4ull));
      if (value) {
        out.push_back(std::move(*value));
      }
    }
    return out;
  }

  std::optional<HiveValueInfo> FindValue(uint32_t index,
                                         const std::string &name) const {
    for (auto value : Values(index)) {
      if (EqualNoCase(value.name, name)) {
        return value;
      }
    }
    return std::nullopt;
  }

private:
  std::optional<size_t> CellAbsolute(uint32_t index) const {
    if (index == 0xFFFFFFFFu) {
      return std::nullopt;
    }
    const uint64_t absolute = 0x1000ull + index;
    if (absolute + 4 > bytes_.size()) {
      return std::nullopt;
    }
    return static_cast<size_t>(absolute);
  }

  void ReadSubkeyList(uint32_t index, uint32_t requestedCount,
                      std::vector<uint32_t> &out, size_t depth) const {
    if (depth > 8) {
      return;
    }
    const auto cell = CellAbsolute(index);
    if (!cell || *cell + 8 > bytes_.size()) {
      return;
    }
    const size_t data = *cell + 4;
    const std::string sig(reinterpret_cast<const char *>(bytes_.data() + data),
                          2);
    const uint16_t storedCount = ReadLe16(bytes_.data() + data + 2);
    const uint32_t count =
        std::min<uint32_t>(requestedCount, storedCount == 0 ? requestedCount
                                                            : storedCount);
    if (sig == "lf" || sig == "lh") {
      for (uint32_t i = 0; i < count; ++i) {
        if (data + 4 + i * 8ull + 4 > bytes_.size()) {
          break;
        }
        out.push_back(ReadLe32(bytes_.data() + data + 4 + i * 8ull));
      }
      return;
    }
    if (sig == "li") {
      for (uint32_t i = 0; i < count; ++i) {
        if (data + 4 + i * 4ull + 4 > bytes_.size()) {
          break;
        }
        out.push_back(ReadLe32(bytes_.data() + data + 4 + i * 4ull));
      }
      return;
    }
    if (sig == "ri") {
      for (uint32_t i = 0; i < count; ++i) {
        if (data + 4 + i * 4ull + 4 > bytes_.size()) {
          break;
        }
        ReadSubkeyList(ReadLe32(bytes_.data() + data + 4 + i * 4ull), 0xFFFFu,
                       out, depth + 1);
      }
    }
  }

  std::optional<HiveValueInfo> ReadValue(uint32_t index) const {
    const auto cell = CellAbsolute(index);
    if (!cell || *cell + 24 > bytes_.size()) {
      return std::nullopt;
    }
    const size_t data = *cell + 4;
    if (std::memcmp(bytes_.data() + data, "vk", 2) != 0) {
      return std::nullopt;
    }
    HiveValueInfo value;
    const uint16_t nameLen = ReadLe16(bytes_.data() + data + 2);
    uint32_t dataLen = ReadLe32(bytes_.data() + data + 4);
    const uint32_t dataField = ReadLe32(bytes_.data() + data + 8);
    value.type = ReadLe32(bytes_.data() + data + 12);
    const uint16_t flags = ReadLe16(bytes_.data() + data + 16);
    if (data + 20 + nameLen > bytes_.size()) {
      return std::nullopt;
    }
    if ((flags & 0x1u) != 0) {
      value.name.assign(reinterpret_cast<const char *>(bytes_.data() + data + 20),
                        nameLen);
    } else {
      value.name = Utf16LeAsciiName(bytes_.data() + data + 20, nameLen);
    }

    const bool isInline = (dataLen & 0x80000000u) != 0;
    dataLen &= 0x7FFFFFFFu;
    if (isInline) {
      std::array<uint8_t, 4> inlineBytes{};
      inlineBytes[0] = static_cast<uint8_t>(dataField & 0xFFu);
      inlineBytes[1] = static_cast<uint8_t>((dataField >> 8) & 0xFFu);
      inlineBytes[2] = static_cast<uint8_t>((dataField >> 16) & 0xFFu);
      inlineBytes[3] = static_cast<uint8_t>((dataField >> 24) & 0xFFu);
      value.data.assign(inlineBytes.begin(),
                        inlineBytes.begin() + std::min<uint32_t>(dataLen, 4));
      return value;
    }
    const auto dataCell = CellAbsolute(dataField);
    if (!dataCell || *dataCell + 4 + dataLen > bytes_.size()) {
      return value;
    }
    value.data.assign(bytes_.begin() + *dataCell + 4,
                      bytes_.begin() + *dataCell + 4 + dataLen);
    return value;
  }

  const std::vector<uint8_t> &bytes_;
};

std::optional<uint32_t>
FindHivePath(const RegistryHiveReader &hive,
             std::initializer_list<std::string> components) {
  auto current = hive.RootIndex();
  if (!current) {
    return std::nullopt;
  }
  for (const auto component : components) {
    current = hive.FindSubkey(*current, component);
    if (!current) {
      return std::nullopt;
    }
  }
  return current;
}

std::optional<uint32_t> HiveDwordValue(const RegistryHiveReader &hive,
                                       uint32_t key,
                                       const std::string &name) {
  const auto value = hive.FindValue(key, name);
  if (!value || value->data.size() < 4) {
    return std::nullopt;
  }
  return ReadLe32(value->data.data());
}

std::string HiveStringValue(const RegistryHiveReader &hive, uint32_t key,
                            const std::string &name) {
  const auto value = hive.FindValue(key, name);
  if (!value || value->data.empty()) {
    return {};
  }
  if (value->type == 1 || value->type == 2) {
    return Utf16LeAsciiString(value->data);
  }
  if (value->type == 4 && value->data.size() >= 4) {
    return std::to_string(ReadLe32(value->data.data()));
  }
  return {};
}

std::string FormatHiveDword(std::optional<uint32_t> value) {
  if (!value) {
    return "(missing)";
  }
  return std::to_string(*value);
}

std::optional<uint32_t>
SelectOfflineControlSet(const RegistryHiveReader &hive) {
  const auto select = FindHivePath(hive, {"Select"});
  if (!select) {
    return std::nullopt;
  }
  const auto current = HiveDwordValue(hive, *select, "Current");
  const auto def = HiveDwordValue(hive, *select, "Default");
  if (current && *current != 0) {
    return *current;
  }
  if (def && *def != 0) {
    return *def;
  }
  return 1u;
}

std::string FormatControlSetName(uint32_t controlSet) {
  std::ostringstream out;
  out << "ControlSet" << std::setw(3) << std::setfill('0') << controlSet;
  return out.str();
}

struct ServiceBootState {
  std::string name;
  bool present = false;
  std::optional<uint32_t> start;
  std::optional<uint32_t> type;
  std::optional<uint32_t> errorControl;
  std::optional<uint32_t> startOverride0;
  std::string group;
  std::string imagePath;
};

ServiceBootState ReadServiceBootState(const RegistryHiveReader &hive,
                                      const std::string &controlSet,
                                      const std::string &service) {
  ServiceBootState state;
  state.name = service;
  const auto serviceKey =
      FindHivePath(hive, {controlSet, "Services", service});
  if (!serviceKey) {
    return state;
  }
  state.present = true;
  state.start = HiveDwordValue(hive, *serviceKey, "Start");
  state.type = HiveDwordValue(hive, *serviceKey, "Type");
  state.errorControl = HiveDwordValue(hive, *serviceKey, "ErrorControl");
  state.group = HiveStringValue(hive, *serviceKey, "Group");
  state.imagePath = HiveStringValue(hive, *serviceKey, "ImagePath");
  if (const auto startOverride =
          hive.FindSubkey(*serviceKey, "StartOverride")) {
    state.startOverride0 = HiveDwordValue(hive, *startOverride, "0");
  }
  return state;
}

bool IsBootStartReady(const ServiceBootState &state) {
  return state.present && state.start && *state.start == 0 &&
         (!state.startOverride0 || *state.startOverride0 == 0);
}

void PrintServiceBootState(const ServiceBootState &state) {
  std::cout << "    " << state.name << ": ";
  if (!state.present) {
    std::cout << "missing\n";
    return;
  }
  std::cout << "Start=" << FormatHiveDword(state.start)
            << " Type=" << FormatHiveDword(state.type)
            << " ErrorControl=" << FormatHiveDword(state.errorControl)
            << " StartOverride\\0="
            << FormatHiveDword(state.startOverride0);
  if (!state.group.empty()) {
    std::cout << " Group=\"" << state.group << "\"";
  }
  if (!state.imagePath.empty()) {
    std::cout << " ImagePath=\"" << state.imagePath << "\"";
  }
  std::cout << " verdict="
            << (IsBootStartReady(state) ? "boot-start-ready"
                                        : "not-boot-start")
            << "\n";
}

struct CriticalDeviceState {
  std::string id;
  bool present = false;
  std::string service;
  std::string classGuid;
};

CriticalDeviceState
ReadCriticalDeviceState(const RegistryHiveReader &hive,
                        const std::string &controlSet,
                        const std::string &deviceId) {
  CriticalDeviceState state;
  state.id = deviceId;
  const auto key = FindHivePath(
      hive, {controlSet, "Control", "CriticalDeviceDatabase", deviceId});
  if (!key) {
    return state;
  }
  state.present = true;
  state.service = HiveStringValue(hive, *key, "Service");
  state.classGuid = HiveStringValue(hive, *key, "ClassGUID");
  return state;
}

void PrintCriticalDeviceState(const CriticalDeviceState &state) {
  std::cout << "    " << state.id << ": ";
  if (!state.present) {
    std::cout << "missing\n";
    return;
  }
  std::cout << "Service=\""
            << (state.service.empty() ? "(missing)" : state.service)
            << "\" ClassGUID=\""
            << (state.classGuid.empty() ? "(missing)" : state.classGuid)
            << "\"\n";
}

void PrintRelatedCriticalDeviceDatabaseEntries(const RegistryHiveReader &hive,
                                               const std::string &controlSet) {
  const auto cdd =
      FindHivePath(hive, {controlSet, "Control", "CriticalDeviceDatabase"});
  if (!cdd) {
    std::cout << "  Related CriticalDeviceDatabase entries: unavailable\n";
    return;
  }
  std::cout << "  Related CriticalDeviceDatabase entries:\n";
  size_t printed = 0;
  for (const auto child : hive.SubkeyIndexes(*cdd)) {
    const auto key = hive.ReadKey(child);
    if (!key) {
      continue;
    }
    const auto upper = ToUpperAscii(key->name);
    const bool relevant =
        upper.find("VEN_8086") != std::string::npos ||
        upper.find("CC_0101") != std::string::npos ||
        upper.find("IDE") != std::string::npos ||
        upper.find("ATAPI") != std::string::npos;
    if (!relevant) {
      continue;
    }
    const auto service = HiveStringValue(hive, child, "Service");
    const auto classGuid = HiveStringValue(hive, child, "ClassGUID");
    std::cout << "    " << key->name << ": Service=\""
              << (service.empty() ? "(missing)" : service)
              << "\" ClassGUID=\""
              << (classGuid.empty() ? "(missing)" : classGuid) << "\"\n";
    if (++printed >= 64) {
      std::cout << "    ... more related entries omitted\n";
      return;
    }
  }
  if (printed == 0) {
    std::cout << "    none\n";
  }
}

void PrintSystemBootStorageSummary(const std::vector<uint8_t> &systemBytes) {
  RegistryHiveReader hive(systemBytes);
  std::cout << "SYSTEM hive boot storage summary:\n";
  if (!hive.IsValid()) {
    std::cout << "  unreadable registry hive\n";
    return;
  }

  const auto select = FindHivePath(hive, {"Select"});
  if (select) {
    std::cout << "  Select: Current="
              << FormatHiveDword(HiveDwordValue(hive, *select, "Current"))
              << " Default="
              << FormatHiveDword(HiveDwordValue(hive, *select, "Default"))
              << " LastKnownGood="
              << FormatHiveDword(
                     HiveDwordValue(hive, *select, "LastKnownGood"))
              << "\n";
  } else {
    std::cout << "  Select: missing\n";
  }

  const auto selected = SelectOfflineControlSet(hive);
  if (!selected) {
    std::cout << "  Boot storage verdict: unknown (no control set)\n";
    return;
  }
  const auto controlSet = FormatControlSetName(*selected);
  std::cout << "  Using " << controlSet << " for offline boot inspection\n";
  std::cout << "  Boot-critical storage services:\n";

  std::vector<ServiceBootState> services;
  for (const auto *name :
       {"pciide", "intelide", "atapi", "disk", "partmgr", "mountmgr"}) {
    services.push_back(ReadServiceBootState(hive, controlSet, name));
    PrintServiceBootState(services.back());
  }

  std::cout << "  CriticalDeviceDatabase entries for emulated PIIX IDE:\n";
  std::vector<CriticalDeviceState> criticalDevices;
  for (const auto *id : {"pci#ven_8086&dev_7111",
                         "pci#ven_8086&dev_7111&cc_0101",
                         "pci#ven_8086&dev_7111&cc_01018a",
                         "pci#cc_0101",
                         "pci#cc_01018a"}) {
    criticalDevices.push_back(ReadCriticalDeviceState(hive, controlSet, id));
    PrintCriticalDeviceState(criticalDevices.back());
  }
  PrintRelatedCriticalDeviceDatabaseEntries(hive, controlSet);

  bool storageCoreReady = true;
  for (const auto &state : services) {
    if (state.name == "disk" || state.name == "partmgr" ||
        state.name == "mountmgr") {
      storageCoreReady = storageCoreReady && IsBootStartReady(state);
    }
  }
  const bool ideServiceReady =
      std::any_of(services.begin(), services.end(), [](const auto &state) {
        return (state.name == "pciide" || state.name == "intelide" ||
                state.name == "atapi") &&
               IsBootStartReady(state);
      });
  const bool piixCriticalReady =
      std::any_of(criticalDevices.begin(), criticalDevices.end(),
                  [](const auto &state) {
                    return state.present && EqualNoCase(state.service, "pciide");
                  });
  std::cout << "  Boot storage verdict: "
            << (storageCoreReady && ideServiceReady && piixCriticalReady
                    ? "piix-ide-ready"
                    : "needs-ide-boot-repair")
            << " storageCore="
            << (storageCoreReady ? "ready" : "needs-repair")
            << " ideService=" << (ideServiceReady ? "ready" : "needs-repair")
            << " criticalDevice="
            << (piixCriticalReady ? "ready" : "needs-repair") << "\n";
  if (!(storageCoreReady && ideServiceReady && piixCriticalReady)) {
    std::cout << "  Repair hint: run elevated PowerShell with "
                 "tools\\Test-AntiMalBaseBoot.ps1 -RepairBootStorage\n";
  }

  std::cout << "  GuestAgent service:\n";
  const auto agent =
      FindHivePath(hive, {controlSet, "Services", "AntiMalGuestAgent"});
  if (!agent) {
    std::cout << "    AntiMalGuestAgent: missing\n";
  } else {
    const auto start = HiveDwordValue(hive, *agent, "Start");
    const auto type = HiveDwordValue(hive, *agent, "Type");
    const auto errorControl = HiveDwordValue(hive, *agent, "ErrorControl");
    const auto imagePath = HiveStringValue(hive, *agent, "ImagePath");
    const auto objectName = HiveStringValue(hive, *agent, "ObjectName");
    const bool ready =
        start && *start == 2 &&
        ToUpperAscii(imagePath).find("ANTIMAL.GUESTAGENT.EXE") !=
            std::string::npos;
    std::cout << "    AntiMalGuestAgent: "
              << (ready ? "ready" : "needs-install")
              << " Start=" << FormatHiveDword(start)
              << " Type=" << FormatHiveDword(type)
              << " ErrorControl=" << FormatHiveDword(errorControl)
              << " ImagePath=\"" << imagePath << "\"";
    if (!objectName.empty()) {
      std::cout << " ObjectName=\"" << objectName << "\"";
    }
    std::cout << "\n";
  }
}

std::optional<uint32_t> BcdObjectType(const RegistryHiveReader &hive,
                                      uint32_t objectKey) {
  const auto description = hive.FindSubkey(objectKey, "Description");
  if (!description) {
    return std::nullopt;
  }
  const auto type = hive.FindValue(*description, "Type");
  if (!type || type->data.size() < 4) {
    return std::nullopt;
  }
  return ReadLe32(type->data.data());
}

std::optional<uint32_t> BcdElementsKey(const RegistryHiveReader &hive,
                                       uint32_t objectKey) {
  return hive.FindSubkey(objectKey, "Elements");
}

std::optional<HiveValueInfo> BcdElementValue(const RegistryHiveReader &hive,
                                             uint32_t objectKey,
                                             const std::string &elementId) {
  const auto elements = BcdElementsKey(hive, objectKey);
  if (!elements) {
    return std::nullopt;
  }
  const auto element = hive.FindSubkey(*elements, elementId);
  if (!element) {
    return std::nullopt;
  }
  return hive.FindValue(*element, "Element");
}

std::string BcdElementString(const RegistryHiveReader &hive, uint32_t objectKey,
                             const std::string &elementId) {
  const auto value = BcdElementValue(hive, objectKey, elementId);
  if (!value) {
    return {};
  }
  if (value->type == 1) {
    return Utf16LeAsciiString(value->data);
  }
  if (value->type == 7) {
    const auto values = Utf16LeAsciiMultiString(value->data);
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
      if (i != 0) {
        out << ", ";
      }
      out << values[i];
    }
    return out.str();
  }
  return {};
}

std::string BcdDeviceDescription(const HiveValueInfo &value,
                                 const std::vector<GptPartitionInfo> &parts) {
  if (value.data.size() >= 48) {
    const auto guid = GuidFromGptBytes(value.data.data() + 32);
    std::ostringstream out;
    out << "partitionGuid=" << guid << " ("
        << PartitionLabelForUniqueGuid(parts, guid) << ")";
    return out.str();
  }
  return "device blob length=" + std::to_string(value.data.size());
}

std::string BcdElementDescription(const std::string &id,
                                  const HiveValueInfo &value,
                                  const std::vector<GptPartitionInfo> &parts) {
  if (id == "11000001" || id == "21000001") {
    return BcdDeviceDescription(value, parts);
  }
  if (value.type == 1) {
    return Utf16LeAsciiString(value.data);
  }
  if (value.type == 7) {
    const auto values = Utf16LeAsciiMultiString(value.data);
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
      if (i != 0) {
        out << ", ";
      }
      out << values[i];
    }
    return out.str();
  }
  if (value.type == 4 && value.data.size() >= 4) {
    std::ostringstream out;
    out << ReadLe32(value.data.data());
    return out.str();
  }
  if (value.type == 3 && value.data.size() == 1) {
    return value.data[0] != 0 ? "true" : "false";
  }
  if (value.type == 3 && value.data.size() == 8) {
    const uint64_t raw = ReadLe64(value.data.data());
    if (ToUpperAscii(id) == "250000E0") {
      switch (raw) {
      case 0:
        return "DisplayAllFailures";
      case 1:
        return "IgnoreAllFailures";
      case 2:
        return "IgnoreShutdownFailures";
      case 3:
        return "IgnoreBootFailures";
      case 4:
        return "IgnoreCheckpointFailures";
      case 5:
        return "DisplayShutdownFailures";
      case 6:
        return "DisplayBootFailures";
      case 7:
        return "DisplayCheckpointFailures";
      default:
        break;
      }
    }
    std::ostringstream out;
    out << raw;
    return out.str();
  }
  std::ostringstream out;
  out << "binary length=" << value.data.size();
  return out.str();
}

bool BcdDeviceMatchesPartitionKind(const RegistryHiveReader &hive,
                                   uint32_t objectKey,
                                   const std::string &elementId,
                                   const std::vector<GptPartitionInfo> &parts,
                                   const std::string &kind) {
  const auto value = BcdElementValue(hive, objectKey, elementId);
  if (!value || value->data.size() < 48) {
    return false;
  }
  const auto guid = GuidFromGptBytes(value->data.data() + 32);
  for (const auto &part : parts) {
    if (EqualNoCase(part.uniqueGuid, guid) &&
        EqualNoCase(PartitionKind(part.typeGuid), kind)) {
      return true;
    }
  }
  return false;
}

void PrintBcdObjectLine(const RegistryHiveReader &hive, uint32_t objectKey,
                        const std::string &guid,
                        const std::vector<GptPartitionInfo> &parts,
                        const std::vector<std::string> &elementIds) {
  const auto type = BcdObjectType(hive, objectKey).value_or(0);
  std::cout << "  " << BcdObjectAlias(guid) << " type=0x" << std::hex
            << std::uppercase << type << std::dec << " "
            << BcdObjectTypeName(type) << "\n";
  for (const auto &id : elementIds) {
    const auto value = BcdElementValue(hive, objectKey, id);
    if (!value) {
      std::cout << "    MISSING " << BcdElementName(id) << " (" << id
                << ")\n";
      continue;
    }
    std::cout << "    " << BcdElementName(id) << " (" << id
              << "): " << BcdElementDescription(id, *value, parts) << "\n";
  }
}

void PrintBcdAllElements(const RegistryHiveReader &hive, uint32_t objectKey,
                         const std::vector<GptPartitionInfo> &partitions) {
  const auto elements = hive.FindSubkey(objectKey, "Elements");
  if (!elements) {
    std::cout << "    (Elements key absent)\n";
    return;
  }
  const auto children = hive.SubkeyIndexes(*elements);
  std::cout << "    full element inventory (" << children.size()
            << " entries):\n";
  for (const auto child : children) {
    const auto key = hive.ReadKey(child);
    if (!key) {
      continue;
    }
    const auto value = hive.FindValue(child, "Element");
    if (!value) {
      std::cout << "      " << key->name << " name=" << BcdElementName(key->name)
                << " (no Element value)\n";
      continue;
    }
    std::cout << "      " << key->name
              << " name=" << BcdElementName(key->name)
              << " type=" << value->type << " size=" << value->data.size()
              << " value=" << BcdElementDescription(key->name, *value, partitions)
              << "\n";
  }
}

void PrintBcdDecodedSummary(const std::vector<uint8_t> &bcdBytes,
                            const std::vector<GptPartitionInfo> &partitions) {
  RegistryHiveReader hive(bcdBytes);
  if (!hive.IsValid()) {
    std::cout << "BCD decoded contract: unavailable (not a registry hive)\n";
    return;
  }
  const auto root = hive.RootIndex();
  if (!root) {
    std::cout << "BCD decoded contract: unavailable (missing root key)\n";
    return;
  }
  const auto objects = hive.FindSubkey(*root, "Objects");
  if (!objects) {
    std::cout << "BCD decoded contract: unavailable (missing Objects key)\n";
    return;
  }

  const std::string bootmgrGuid = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
  const auto bootmgr = hive.FindSubkey(*objects, bootmgrGuid);
  std::optional<uint32_t> defaultObject;
  std::string defaultGuid;
  if (bootmgr) {
    defaultGuid = BcdElementString(hive, *bootmgr, "23000003");
    if (!defaultGuid.empty()) {
      defaultObject = hive.FindSubkey(*objects, defaultGuid);
    }
  }

  std::cout << "BCD decoded boot contract:\n";
  if (bootmgr) {
    PrintBcdObjectLine(hive, *bootmgr, bootmgrGuid, partitions,
                       {"11000001", "12000002", "12000004", "23000003",
                        "24000001", "25000004"});
    PrintBcdAllElements(hive, *bootmgr, partitions);
  } else {
    std::cout << "  MISSING {bootmgr}\n";
  }
  if (defaultObject) {
    PrintBcdObjectLine(hive, *defaultObject, defaultGuid, partitions,
                       {"11000001", "21000001", "12000002", "22000002",
                        "12000004", "23000003", "16000009", "250000E0",
                        "16000060", "25000020", "250000C2"});
    PrintBcdAllElements(hive, *defaultObject, partitions);
  } else if (!defaultGuid.empty()) {
    std::cout << "  MISSING default loader object " << defaultGuid << "\n";
  } else {
    std::cout << "  MISSING {bootmgr} default object reference\n";
  }

  // Walk the rest of the Objects key so settings objects (dbgsettings,
  // globalsettings, bootloadersettings, emssettings, etc.) show up too.
  // Skipping {bootmgr} and the {default} loader since they were already
  // printed above.
  const auto allObjects = hive.SubkeyIndexes(*objects);
  std::cout << "BCD other objects (" << allObjects.size() << " total under Objects):\n";
  for (const auto child : allObjects) {
    const auto key = hive.ReadKey(child);
    if (!key) {
      continue;
    }
    if (EqualNoCase(key->name, bootmgrGuid) ||
        (!defaultGuid.empty() && EqualNoCase(key->name, defaultGuid))) {
      continue;
    }
    PrintBcdObjectLine(hive, child, key->name, partitions, {});
    PrintBcdAllElements(hive, child, partitions);
  }

  const bool bootmgrOnEsp =
      bootmgr &&
      BcdDeviceMatchesPartitionKind(hive, *bootmgr, "11000001", partitions,
                                    "ESP");
  const bool defaultPathOk =
      defaultObject &&
      EqualNoCase(BcdElementString(hive, *defaultObject, "12000002"),
                  "\\Windows\\system32\\winload.efi");
  const bool systemRootOk =
      defaultObject &&
      EqualNoCase(BcdElementString(hive, *defaultObject, "22000002"),
                  "\\Windows");
  const bool loaderDeviceOk =
      defaultObject &&
      BcdDeviceMatchesPartitionKind(hive, *defaultObject, "11000001",
                                    partitions, "Windows/basic-data");
  const bool osDeviceOk =
      defaultObject &&
      BcdDeviceMatchesPartitionKind(hive, *defaultObject, "21000001",
                                    partitions, "Windows/basic-data");
  std::cout << "BCD contract verdict: bootmgrDevice="
            << (bootmgrOnEsp ? "ok" : "bad")
            << " defaultPath=" << (defaultPathOk ? "ok" : "bad")
            << " systemroot=" << (systemRootOk ? "ok" : "bad")
            << " loaderDevice=" << (loaderDeviceOk ? "ok" : "bad")
            << " osDevice=" << (osDeviceOk ? "ok" : "bad") << "\n";
}

void PrintNtfsDataRuns(const std::string &path, const NtfsReader::Entry &entry,
                       uint64_t volumeFirstLba, uint8_t sectorsPerCluster) {
  if (entry.directory) {
    return;
  }
  if (entry.dataResident) {
    std::cout << "    dataRuns: resident size=" << entry.size << "\n";
    return;
  }
  if (entry.dataRuns.empty()) {
    std::cout << "    dataRuns: unavailable\n";
    return;
  }

  uint64_t minLba = std::numeric_limits<uint64_t>::max();
  uint64_t maxLba = 0;
  uint64_t totalSectors = 0;
  for (const auto &run : entry.dataRuns) {
    if (run.clusters == 0) {
      continue;
    }
    const uint64_t first =
        volumeFirstLba + run.lcn * static_cast<uint64_t>(sectorsPerCluster);
    const uint64_t sectors =
        run.clusters * static_cast<uint64_t>(sectorsPerCluster);
    const uint64_t last = first + sectors - 1;
    minLba = std::min(minLba, first);
    maxLba = std::max(maxLba, last);
    totalSectors += sectors;
  }
  if (minLba == std::numeric_limits<uint64_t>::max()) {
    std::cout << "    dataRuns: unavailable\n";
    return;
  }

  std::cout << "    dataRuns: count=" << entry.dataRuns.size()
            << " lbaRange=" << minLba << "-" << maxLba
            << " sectors=" << totalSectors << "\n";
  const size_t limit = std::min<size_t>(entry.dataRuns.size(), 16);
  for (size_t i = 0; i < limit; ++i) {
    const auto &run = entry.dataRuns[i];
    const uint64_t first =
        volumeFirstLba + run.lcn * static_cast<uint64_t>(sectorsPerCluster);
    const uint64_t sectors =
        run.clusters * static_cast<uint64_t>(sectorsPerCluster);
    const uint64_t last = sectors == 0 ? first : first + sectors - 1;
    std::cout << "      [" << i << "] " << path << " lcn=" << run.lcn
              << " clusters=" << run.clusters << " lba=" << first << "-"
              << last << "\n";
  }
  if (entry.dataRuns.size() > limit) {
    std::cout << "      ... " << (entry.dataRuns.size() - limit)
              << " more run(s)\n";
  }
}

// base deploy-agent: offline-install the execute-capable GuestAgent into a COW
// overlay (the saved desktop snapshot or a copy of it) WITHOUT touching the
// base VHDX. Needed because the snapshot carries an older agent build that is
// too small to overwrite in place; this repurposes a large non-critical file
// (a font, by default) and repoints the AntiMalGuestAgent service at it.
int CommandBaseDeployAgent(int argc, wchar_t **argv,
                           const antimal::AppConfig &config) {
  const auto vhdxText = OptionValue(argc, argv, "--vhdx");
  const auto overlayText = OptionValue(argc, argv, "--overlay");
  const auto agentText = OptionValue(argc, argv, "--agent");
  const auto clobberText = OptionValue(argc, argv, "--clobber");
  const auto guestPathText = OptionValue(argc, argv, "--clobber-guest-path");
  const auto serviceText = OptionValue(argc, argv, "--service");
  const std::filesystem::path vhdx =
      vhdxText ? std::filesystem::path(Utf8ToWide(*vhdxText))
               : config.baseVhdxPath;
  if (vhdx.empty()) {
    std::cerr << "base deploy-agent needs --vhdx, or configured base_vhdx_path.\n";
    return 2;
  }
  if (!overlayText) {
    std::cerr << "base deploy-agent needs --overlay <overlay.cow> (the snapshot "
                 "to install into; the base VHDX is never modified).\n";
    return 2;
  }
  const std::filesystem::path overlay(Utf8ToWide(*overlayText));
  std::filesystem::path agent;
  if (agentText) {
    agent = std::filesystem::path(Utf8ToWide(*agentText));
  } else {
    wchar_t modulePath[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    const std::filesystem::path exeDir =
        n > 0 ? std::filesystem::path(modulePath).parent_path()
              : std::filesystem::current_path();
    agent = exeDir / L"AntiMal.GuestAgent.exe";
  }
  const std::string clobberNtfs =
      clobberText ? *clobberText : std::string("Windows\\Fonts\\seguiemj.ttf");
  const std::string clobberGuest =
      guestPathText ? *guestPathText
                    : std::string("C:\\Windows\\Fonts\\seguiemj.ttf");
  const std::string service =
      serviceText ? *serviceText : std::string("AntiMalGuestAgent");

  std::cout << "base deploy-agent:\n";
  std::cout << "  base VHDX (read-only): " << antimal::PathToUtf8(vhdx) << "\n";
  std::cout << "  overlay (written):     " << antimal::PathToUtf8(overlay)
            << "\n";
  std::cout << "  new agent:             " << antimal::PathToUtf8(agent) << "\n";
  std::cout << "  clobber file:          " << clobberNtfs << "\n";
  std::cout << "  service:               " << service << "\n";

  const auto result = antimal::DeployExecuteAgentIntoOverlay(
      vhdx, overlay, agent, clobberNtfs, clobberGuest, service);
  for (const auto &n : result.notes) {
    std::cout << "  " << n << "\n";
  }
  std::cout << "  agent size: " << result.agentSize << " bytes\n";
  std::cout << (result.ok ? "DEPLOY OK\n" : "DEPLOY FAILED\n");
  return result.ok ? 0 : 1;
}

int CommandBaseInspect(int argc, wchar_t **argv,
                       const antimal::AppConfig &config) {
  const auto vhdxText = OptionValue(argc, argv, "--vhdx");
  const auto overlayText = OptionValue(argc, argv, "--overlay");
  const auto dumpBcdText = OptionValue(argc, argv, "--dump-bcd");
  const auto dumpSystemText = OptionValue(argc, argv, "--dump-system");
  const std::filesystem::path vhdx =
      vhdxText ? std::filesystem::path(Utf8ToWide(*vhdxText))
               : config.baseVhdxPath;
  if (vhdx.empty()) {
    std::cerr << "base inspect needs --vhdx, or configured base_vhdx_path.\n";
    return 2;
  }

  antimal::hv::VhdxBlockDevice disk = antimal::hv::VhdxBlockDevice::Open(vhdx);
  std::cout << "Base VHDX: " << antimal::PathToUtf8(vhdx) << "\n";
  std::cout << "Virtual size: " << disk.VirtualSize() << " bytes\n";
  std::cout << "Sectors: " << disk.SectorCount() << "\n";
  std::cout << "Block size: " << disk.BlockSize() << " bytes\n";

  // Optionally chain a disposable run overlay on top of the base. The overlay
  // is read-only here (we never call WriteSectors), so we get the post-patch
  // view of the BCD without mutating the COW file.
  std::optional<antimal::hv::CowOverlayBlockDevice> overlayDevice;
  antimal::hv::IBlockDevice *activeDisk = &disk;
  if (overlayText) {
    const std::filesystem::path overlayPath(Utf8ToWide(*overlayText));
    try {
      overlayDevice.emplace(
          antimal::hv::CowOverlayBlockDevice::Open(&disk, overlayPath));
      activeDisk = &*overlayDevice;
      std::cout << "Overlay COW: " << antimal::PathToUtf8(overlayPath)
                << " sectors=" << overlayDevice->SectorCount()
                << " overlay sectors=" << overlayDevice->OverlaySectorCount()
                << "\n";
    } catch (const std::exception &ex) {
      std::cerr << "error: failed to open overlay COW "
                << antimal::PathToUtf8(overlayPath) << ": " << ex.what()
                << "\n";
      return 1;
    }
  }

  const auto partitions = ReadGptPartitions(*activeDisk);
  std::cout << "GPT partitions: " << partitions.size() << "\n";
  const GptPartitionInfo *esp = nullptr;
  const GptPartitionInfo *windows = nullptr;
  for (const auto &part : partitions) {
    const auto kind = PartitionKind(part.typeGuid);
    std::cout << "  [" << part.index << "] " << kind
              << " firstLba=" << part.firstLba
              << " lastLba=" << part.lastLba
              << " sectors=" << (part.lastLba >= part.firstLba
                                      ? part.lastLba - part.firstLba + 1
                                      : 0)
              << " guid=" << part.uniqueGuid;
    if (!part.name.empty()) {
      std::cout << " name=\"" << part.name << "\"";
    }
    std::cout << "\n";
    if (!esp && kind == "ESP") {
      esp = &part;
    }
    if (!windows && kind == "Windows/basic-data") {
      windows = &part;
    }
  }

  if (!esp) {
    std::cerr << "error: EFI System Partition was not found.\n";
    return 1;
  }

  Fat32Reader fat(*activeDisk, esp->firstLba);
  if (!fat.Init()) {
    std::cerr << "error: ESP is not a readable FAT32 volume.\n";
    return 1;
  }
  std::cout << "ESP FAT32: bytesPerSector=" << fat.BytesPerSector()
            << " sectorsPerCluster=" << static_cast<unsigned>(fat.SectorsPerCluster())
            << " rootCluster=" << fat.RootCluster() << "\n";

  bool ok = true;
  const std::array<const char *, 4> bootFiles = {
      "EFI\\BOOT\\BOOTX64.EFI",
      "EFI\\Microsoft\\Boot\\bootmgfw.efi",
      "EFI\\Microsoft\\Boot\\BCD",
      "EFI\\Microsoft\\Boot\\Fonts\\wgl4_boot.ttf",
  };
  std::optional<Fat32Reader::Entry> bcd;
  for (const char *path : bootFiles) {
    const auto entry = fat.FindPath(path);
    if (!entry) {
      std::cout << "MISSING: " << path << "\n";
      ok = false;
      continue;
    }
    std::cout << "OK: " << path << " size=" << entry->size
              << " firstCluster=" << entry->firstCluster << "\n";
    if (std::string(path) == "EFI\\Microsoft\\Boot\\BCD") {
      bcd = entry;
    }
  }

  if (bcd) {
    const auto bcdBytes = fat.ReadFile(*bcd, 4ull * 1024ull * 1024ull);
    const bool hasWinload = ContainsUtf16AsciiNoCase(bcdBytes, "winload.efi") ||
                            ContainsAsciiNoCase(bcdBytes, "winload.efi");
    const bool hasWindowsRoot =
        ContainsUtf16AsciiNoCase(bcdBytes, "\\Windows") ||
        ContainsAsciiNoCase(bcdBytes, "\\Windows");
    const bool hasBootmgr = ContainsUtf16AsciiNoCase(bcdBytes, "bootmgr") ||
                            ContainsAsciiNoCase(bcdBytes, "bootmgr");
    std::cout << "BCD content hints: bootmgr=" << (hasBootmgr ? "yes" : "no")
              << " winload.efi=" << (hasWinload ? "yes" : "no")
              << " \\Windows=" << (hasWindowsRoot ? "yes" : "no")
              << " bytesRead=" << bcdBytes.size() << "\n";
    PrintBcdDecodedSummary(bcdBytes, partitions);
    if (dumpBcdText) {
      const std::filesystem::path outPath(Utf8ToWide(*dumpBcdText));
      if (!outPath.parent_path().empty()) {
        antimal::EnsureDirectory(outPath.parent_path());
      }
      std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
      out.write(reinterpret_cast<const char *>(bcdBytes.data()),
                static_cast<std::streamsize>(bcdBytes.size()));
      if (!out) {
        std::cerr << "error: failed to write BCD dump: "
                  << antimal::PathToUtf8(outPath) << "\n";
        return 1;
      }
      std::cout << "Wrote BCD dump: " << antimal::PathToUtf8(outPath) << "\n";
    }
    ok = ok && hasWinload && hasWindowsRoot;
  }

  if (!windows) {
    std::cout << "MISSING: Windows/basic-data partition\n";
    ok = false;
  } else {
    NtfsReader ntfs(*activeDisk, windows->firstLba);
    if (!ntfs.Init()) {
      std::cout << "MISSING: readable NTFS Windows partition\n";
      ok = false;
    } else {
      std::cout << "Windows NTFS: bytesPerSector=" << ntfs.BytesPerSector()
                << " sectorsPerCluster="
                << static_cast<unsigned>(ntfs.SectorsPerCluster())
                << " mftLcn=" << ntfs.MftLcn()
                << " fileRecordBytes=" << ntfs.FileRecordBytes() << "\n";
      const auto winload = ntfs.FindPath("Windows\\System32\\winload.efi");
      if (winload) {
        std::cout << "OK: Windows\\System32\\winload.efi size="
                  << winload->size << " fileRecord=" << winload->fileRecord
                  << "\n";
        PrintNtfsDataRuns("Windows\\System32\\winload.efi", *winload,
                          windows->firstLba, ntfs.SectorsPerCluster());
        const auto dumpWinload =
            OptionValue(argc, argv, "--dump-winload");
        if (dumpWinload) {
          const auto bytes = ntfs.ReadFile(*winload, 16ull * 1024ull * 1024ull);
          if (!bytes.empty()) {
            const std::filesystem::path outPath(Utf8ToWide(*dumpWinload));
            std::ofstream of(outPath, std::ios::out | std::ios::binary);
            if (of) {
              of.write(reinterpret_cast<const char *>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
              std::cout << "Dumped winload.efi (" << bytes.size()
                        << " bytes) to " << antimal::PathToUtf8(outPath)
                        << "\n";
            }
          }
        }
      } else {
        std::cout << "MISSING: Windows\\System32\\winload.efi\n";
        ok = false;
      }
      // --list-ntfs-dir <path> lists a directory's immediate children (offline,
      // read-only) -- e.g. enumerate CodeIntegrity\CiPolicies\Active to find an
      // unknown SAC/.cip, or winevt\Logs to confirm which channels exist.
      if (const auto ntfsDir = OptionValue(argc, argv, "--list-ntfs-dir")) {
        std::string rel = *ntfsDir;
        for (auto &ch : rel) {
          if (ch == '/') ch = '\\';
        }
        const auto kids = ntfs.ListDir(rel);
        std::cout << "=== DIR " << rel << " (" << kids.size()
                  << " entries) ===\n";
        for (const auto &k : kids) {
          std::cout << (k.directory ? "  <DIR>  " : "  FILE  ") << k.name
                    << "  size=" << k.size << "\n";
        }
      }
      // --dump-ntfs-file <path> [--dump-ntfs-out <out>] extracts an arbitrary
      // file from the Windows NTFS volume read-only (no OS mount, no admin) for
      // offline disassembly -- e.g. ntoskrnl.exe / hal.dll / a boot driver when
      // diagnosing a kernel-side boot stall. Accepts '/' or '\\' separators.
      if (const auto ntfsFile = OptionValue(argc, argv, "--dump-ntfs-file")) {
        std::string rel = *ntfsFile;
        for (auto &ch : rel) {
          if (ch == '/') {
            ch = '\\';
          }
        }
        const auto entry = ntfs.FindPath(rel);
        if (!entry) {
          std::cout << "MISSING(--dump-ntfs-file): " << rel << "\n";
          ok = false;
        } else {
          std::cout << "OK: " << rel << " size=" << entry->size
                    << " fileRecord=" << entry->fileRecord << "\n";
          PrintNtfsDataRuns(rel, *entry, windows->firstLba,
                            ntfs.SectorsPerCluster());
          const auto bytes = ntfs.ReadFile(*entry, 320ull * 1024ull * 1024ull);
          if (bytes.empty()) {
            std::cout << "error: unreadable file bytes for " << rel << "\n";
            ok = false;
          } else {
            const auto outOpt = OptionValue(argc, argv, "--dump-ntfs-out");
            const std::filesystem::path outPath =
                outOpt ? std::filesystem::path(Utf8ToWide(*outOpt))
                       : std::filesystem::path(L"dumped.bin");
            if (!outPath.parent_path().empty()) {
              antimal::EnsureDirectory(outPath.parent_path());
            }
            std::ofstream of(outPath,
                             std::ios::out | std::ios::binary | std::ios::trunc);
            of.write(reinterpret_cast<const char *>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
            std::cout << "Dumped " << rel << " (" << bytes.size()
                      << " bytes) to " << antimal::PathToUtf8(outPath) << "\n";
          }
        }
      }
      // --dump-bootmgfw lets us inspect the bootmgr image too. The visible
      // WinRE status (0xc0000225, 0xc0430001) is rendered by bootmgfw, not
      // winload; bootmgfw reads the failure status from bootstat and looks
      // it up in its own status -> message table.
      if (const auto dumpBootmgr = OptionValue(argc, argv, "--dump-bootmgfw")) {
        const auto bootmgrEntry =
            fat.FindPath("EFI\\Microsoft\\Boot\\bootmgfw.efi");
        if (bootmgrEntry) {
          const auto bytes = fat.ReadFile(*bootmgrEntry,
                                          16ull * 1024ull * 1024ull);
          if (!bytes.empty()) {
            const std::filesystem::path outPath(Utf8ToWide(*dumpBootmgr));
            std::ofstream of(outPath, std::ios::out | std::ios::binary);
            if (of) {
              of.write(reinterpret_cast<const char *>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
              std::cout << "Dumped bootmgfw.efi (" << bytes.size()
                        << " bytes) to " << antimal::PathToUtf8(outPath)
                        << "\n";
            }
          }
        }
      }
      const auto systemHive =
          ntfs.FindPath("Windows\\System32\\config\\SYSTEM");
      if (systemHive) {
        std::cout << "OK: Windows\\System32\\config\\SYSTEM size="
                  << systemHive->size << " fileRecord="
                  << systemHive->fileRecord << "\n";
        PrintNtfsDataRuns("Windows\\System32\\config\\SYSTEM", *systemHive,
                          windows->firstLba, ntfs.SectorsPerCluster());
        const auto systemBytes =
            ntfs.ReadFile(*systemHive, 64ull * 1024ull * 1024ull);
        if (systemBytes.empty()) {
          std::cout << "SYSTEM hive boot storage summary:\n"
                    << "  unreadable registry hive bytes\n";
          ok = false;
        } else {
          PrintSystemBootStorageSummary(systemBytes);
          if (dumpSystemText) {
            const std::filesystem::path outPath(Utf8ToWide(*dumpSystemText));
            if (!outPath.parent_path().empty()) {
              antimal::EnsureDirectory(outPath.parent_path());
            }
            std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char *>(systemBytes.data()),
                      static_cast<std::streamsize>(systemBytes.size()));
            if (!out) {
              std::cerr << "error: failed to write SYSTEM hive dump: "
                        << antimal::PathToUtf8(outPath) << "\n";
              return 1;
            }
            std::cout << "Wrote SYSTEM hive dump: "
                      << antimal::PathToUtf8(outPath) << "\n";
            const std::array<const char *, 2> systemLogPaths = {
                "Windows\\System32\\config\\SYSTEM.LOG1",
                "Windows\\System32\\config\\SYSTEM.LOG2",
            };
            for (const char *logPath : systemLogPaths) {
              const auto logEntry = ntfs.FindPath(logPath);
              if (!logEntry) {
                std::cout << "MISSING(optional): " << logPath << "\n";
                continue;
              }
              const auto logBytes =
                  ntfs.ReadFile(*logEntry, 64ull * 1024ull * 1024ull);
              if (logBytes.empty() && logEntry->size != 0) {
                std::cout << "UNREADABLE(optional): " << logPath << "\n";
                continue;
              }
              std::filesystem::path logOutPath =
                  outPath.parent_path() /
                  (outPath.filename().wstring() +
                   (std::string(logPath).ends_with("LOG1") ? L".LOG1"
                                                           : L".LOG2"));
              std::ofstream logOut(logOutPath,
                                   std::ios::binary | std::ios::trunc);
              logOut.write(reinterpret_cast<const char *>(logBytes.data()),
                           static_cast<std::streamsize>(logBytes.size()));
              if (!logOut) {
                std::cerr << "error: failed to write SYSTEM log dump: "
                          << antimal::PathToUtf8(logOutPath) << "\n";
                return 1;
              }
              std::cout << "Wrote SYSTEM log dump: "
                        << antimal::PathToUtf8(logOutPath)
                        << " bytes=" << logBytes.size() << "\n";
            }
          }
        }
      } else {
        std::cout << "MISSING: Windows\\System32\\config\\SYSTEM\n";
        ok = false;
      }
      const char *extraBootFiles[] = {
          "Windows\\System32\\ntoskrnl.exe",
          "Windows\\System32\\hal.dll",
          "Windows\\System32\\kdcom.dll",
          "Windows\\System32\\ci.dll",
          "Windows\\System32\\config\\SOFTWARE",
          "Windows\\System32\\drivers\\acpi.sys",
          "Windows\\System32\\drivers\\pci.sys",
          "Windows\\System32\\drivers\\pciide.sys",
          "Windows\\System32\\drivers\\intelide.sys",
          "Windows\\System32\\drivers\\atapi.sys",
          "Windows\\System32\\drivers\\disk.sys",
          "Windows\\System32\\drivers\\partmgr.sys",
          "Windows\\System32\\drivers\\mountmgr.sys",
          "Windows\\System32\\drivers\\classpnp.sys",
          "Windows\\System32\\drivers\\volmgr.sys",
          "Windows\\System32\\drivers\\volmgrx.sys",
          "Windows\\System32\\drivers\\fvevol.sys",
          "Windows\\System32\\drivers\\Wdf01000.sys",
      };
      std::cout << "Optional boot handoff file targets:\n";
      for (const char *path : extraBootFiles) {
        const auto entry = ntfs.FindPath(path);
        if (!entry) {
          std::cout << "  MISSING(optional): " << path << "\n";
          continue;
        }
        std::cout << "  OK(optional): " << path << " size=" << entry->size
                  << " fileRecord=" << entry->fileRecord << "\n";
        PrintNtfsDataRuns(path, *entry, windows->firstLba,
                          ntfs.SectorsPerCluster());
      }
    }
  }

  return ok ? 0 : 1;
}

int CommandBase(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }

  auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto subcommand = Arg(argc, argv, 2);
  if (subcommand == "inspect") {
    return CommandBaseInspect(argc, argv, config);
  }
  if (subcommand == "deploy-agent") {
    return CommandBaseDeployAgent(argc, argv, config);
  }
  if (subcommand != "convert") {
    PrintUsage();
    return 2;
  }

  const auto vhdxText = OptionValue(argc, argv, "--vhdx");
  const auto rawText = OptionValue(argc, argv, "--raw");
  const std::filesystem::path vhdx =
      vhdxText ? std::filesystem::path(Utf8ToWide(*vhdxText))
               : config.baseVhdxPath;
  const std::filesystem::path raw =
      rawText ? std::filesystem::path(Utf8ToWide(*rawText))
              : config.baseDiskPath;
  if (vhdx.empty() || raw.empty()) {
    std::cerr << "base convert needs --vhdx and --raw, or configured base paths.\n";
    return 2;
  }

  const auto result = antimal::ConvertVhdxToRaw(vhdx, raw,
                                                HasFlag(argc, argv, "--force"));
  for (const auto &message : result.messages) {
    std::cout << message << "\n";
  }
  if (!result.errors.empty()) {
    for (const auto &error : result.errors) {
      std::cerr << "error: " << error << "\n";
    }
    return 1;
  }

  config.baseVhdxPath = vhdx;
  config.baseDiskPath = raw;
  config.baseDiskFormat = "raw";
  config.vmProvider = "inhouse";
  antimal::EnsureDirectory(antimal::DefaultConfigPath().parent_path());
  antimal::WriteTextFile(antimal::DefaultConfigPath(),
                         antimal::SerializeConfig(config));

  std::cout << "VHDX: " << antimal::PathToUtf8(vhdx) << "\n";
  std::cout << "Raw:  " << antimal::PathToUtf8(raw) << "\n";
  if (result.converted) {
    std::cout << "Virtual size: " << result.virtualSize << " bytes\n";
    std::cout << "Read: " << result.bytesRead << " bytes\n";
    std::cout << "Wrote non-zero ranges: " << result.bytesWritten << " bytes\n";
  } else if (result.skipped) {
    std::cout << "Conversion skipped; raw output already exists.\n";
  }
  std::cout << "Updated config: "
            << antimal::PathToUtf8(antimal::DefaultConfigPath()) << "\n";
  return 0;
}

int CommandReport(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto reportPath = ResolveReportPath(config, std::filesystem::path(argv[2]));
  auto report = antimal::LoadReportBestEffort(reportPath);
  if (HasFlag(argc, argv, "--html")) {
    const auto htmlPath = reportPath.parent_path() / "report.html";
    antimal::WriteReportHtml(htmlPath, report);
    std::cout << "Wrote " << antimal::PathToUtf8(htmlPath) << "\n";
  } else {
    std::cout << antimal::ReadTextFile(reportPath) << "\n";
  }
  return 0;
}

int CommandBrowserImpact(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto reportPath = ResolveReportPath(config, std::filesystem::path(argv[2]));
  auto report = antimal::LoadReportBestEffort(reportPath);
  const bool decrypt = HasFlag(argc, argv, "--decrypt-browser-secrets");
  report.browserImpact = antimal::AnalyzeBrowserImpact(report.networkDomains, decrypt);

  const auto outPath = reportPath.parent_path() / "browser-impact.json";
  antimal::WriteTextFile(outPath, antimal::ToJson(report));
  antimal::WriteReportHtml(reportPath.parent_path() / "browser-impact.html", report);
  std::cout << "Wrote " << antimal::PathToUtf8(outPath) << "\n";
  std::cout << "Matched " << report.browserImpact.size() << " at-risk browser domain(s).\n";
  return 0;
}

int CommandExport(int argc, wchar_t **argv) {
  if (argc < 3) {
    PrintUsage();
    return 2;
  }
  const auto format = OptionValue(argc, argv, "--format").value_or("stix");
  std::string body;
  if (format == "stix" || format == "misp" || format == "csv") {
    const auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
    const auto reportPath =
        ResolveReportPath(config, std::filesystem::path(argv[2]));
    const auto report = antimal::LoadReportBestEffort(reportPath);
    if (format == "stix") {
      body = antimal::ExportIocsStix(report);
    } else if (format == "misp") {
      body = antimal::ExportIocsMisp(report);
    } else {
      body = antimal::ExportIocsCsv(report);
    }
  } else {
    std::cerr << "Unknown --format '" << format
              << "' (expected stix|misp|csv).\n";
    return 2;
  }

  if (const auto outPath = OptionValue(argc, argv, "--out")) {
    const std::filesystem::path out(antimal::Utf8ToWide(*outPath));
    antimal::WriteTextFile(out, body);
    std::cout << "Wrote " << *outPath << "\n";
  } else {
    std::cout << body << "\n";
  }
  return 0;
}

} // namespace

int CommandDumpHive(int argc, wchar_t **argv) {
  // dump-hive --file <regf-hive> [--path <Sub\Path>] [--filter <substr>]
  //          [--values] [--depth N]
  const auto file = OptionValue(argc, argv, "--file");
  if (!file) {
    std::cerr << "dump-hive: --file <regf-hive> required\n";
    return 2;
  }
  const std::string path = OptionValue(argc, argv, "--path").value_or("");
  const std::string filter = OptionValue(argc, argv, "--filter").value_or("");
  const bool values = HasFlag(argc, argv, "--values");
  int depth = 6;
  if (const auto d = OptionValue(argc, argv, "--depth")) {
    try { depth = std::stoi(*d); } catch (...) {}
  }
  std::cout << antimal::DebugDumpHiveFile(*file, path, filter, values, depth);
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  try {
    if (argc < 2) {
      PrintUsage();
      return 2;
    }
    const std::string command = Arg(argc, argv, 1);
    if (command == "version" || command == "--version" || command == "-v") {
      std::cout << antimal::kProductName << " " << antimal::kVersionString
                << " (" << antimal::kProductTagline << ")\n"
                << "built " << antimal::kBuildDate << "\n";
      return 0;
    }
    if (command == "init") {
      return CommandInit();
    }
    if (command == "dump-hive") {
      return CommandDumpHive(argc, argv);
    }
    if (command == "scan") {
      return CommandScan(argc, argv);
    }
    if (command == "detonate") {
      return CommandDetonate(argc, argv);
    }
    if (command == "base") {
      return CommandBase(argc, argv);
    }
    if (command == "report") {
      return CommandReport(argc, argv);
    }
    if (command == "browser-impact") {
      return CommandBrowserImpact(argc, argv);
    }
    if (command == "export") {
      return CommandExport(argc, argv);
    }
    PrintUsage();
    return 2;
  } catch (const std::exception &ex) {
    std::cerr << "AntiMal error: " << ex.what() << "\n";
    return 1;
  }
}
