#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/FileUtil.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/hv/BlockDevice.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using antimal::Utf8ToWide;
using antimal::WideToUtf8;

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
      << "  antimal base convert --vhdx <base.vhdx> --raw <AntiMalBase.raw> [--force]\n"
      << "  antimal base inspect --vhdx <base.vhdx> [--dump-bcd <out.bcd>]\n"
      << "  antimal report <run-id-or-report.json> --html\n"
      << "  antimal browser-impact <run-id-or-report.json> --decrypt-browser-secrets\n";
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

  antimal::HyperVOrchestrator orchestrator(config);
  auto progress = [](const antimal::DetonationProgress &snap) {
    if (!snap.message.empty()) {
      std::cout << "[" << snap.phase << "] " << snap.message << std::endl;
    }
  };
  const auto result = orchestrator.PrepareAndRun(
      std::filesystem::path(argv[2]), timeout, network, true, progress);

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

int CommandBaseInspect(int argc, wchar_t **argv,
                       const antimal::AppConfig &config) {
  const auto vhdxText = OptionValue(argc, argv, "--vhdx");
  const auto dumpBcdText = OptionValue(argc, argv, "--dump-bcd");
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

  const auto partitions = ReadGptPartitions(disk);
  std::cout << "GPT partitions: " << partitions.size() << "\n";
  const GptPartitionInfo *esp = nullptr;
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
  }

  if (!esp) {
    std::cerr << "error: EFI System Partition was not found.\n";
    return 1;
  }

  Fat32Reader fat(disk, esp->firstLba);
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

} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    if (argc < 2) {
      PrintUsage();
      return 2;
    }
    const std::string command = Arg(argc, argv, 1);
    if (command == "init") {
      return CommandInit();
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
    PrintUsage();
    return 2;
  } catch (const std::exception &ex) {
    std::cerr << "AntiMal error: " << ex.what() << "\n";
    return 1;
  }
}
