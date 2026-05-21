#include "antimal/HyperVOrchestrator.h"

#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/HostChannel.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/Screenshot.h"
#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/HostSerialChannel.h"
#include "antimal/hv/VirtualMachine.h"
#include "antimal/hv/WhpHost.h"

#include <Windows.h>
#include <objbase.h>
#include <virtdisk.h>
#include <winioctl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <type_traits>
#include <vector>

namespace antimal {
namespace {

std::string RequestedProvider(const AppConfig &config) {
  auto provider = ToLowerAscii(config.vmProvider);
  if (provider.empty()) {
    provider = "inhouse";
  }
  return provider;
}

std::string SelectProvider(const AppConfig &config) {
  const auto requested = RequestedProvider(config);
  if (requested == "auto" || requested == "local") {
    return "inhouse";
  }
  return requested;
}

struct BootSignalSummary {
  std::vector<std::string> milestones;
};

struct HostChannelCapture {
  bool guestAgentConnected = false;
  uint32_t guestAgentHeartbeats = 0;
  bool reportComplete = false;
  uint32_t eventsReturned = 0;
  std::vector<std::filesystem::path> artifacts;
  std::vector<std::string> milestones;
};

EventRecord MakeSandboxEvent(const std::string &action,
                             const std::filesystem::path &target,
                             std::map<std::string, std::string> details);
void AppendJournalEvent(const std::filesystem::path &journalPath,
                        const EventRecord &event,
                        std::vector<EventRecord> *events);

bool ContainsTextNoCase(std::string_view haystack, std::string_view needle) {
  const auto lower = [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  };
  std::string h;
  h.reserve(haystack.size());
  for (unsigned char c : haystack) {
    h.push_back(lower(c));
  }
  std::string n;
  n.reserve(needle.size());
  for (unsigned char c : needle) {
    n.push_back(lower(c));
  }
  return h.find(n) != std::string::npos;
}

void AddMilestone(BootSignalSummary *summary, std::string milestone) {
  if (!summary) {
    return;
  }
  if (std::find(summary->milestones.begin(), summary->milestones.end(),
                milestone) == summary->milestones.end()) {
    summary->milestones.push_back(std::move(milestone));
  }
}

void AddMilestone(std::vector<std::string> *milestones,
                  std::string milestone) {
  if (!milestones) {
    return;
  }
  if (std::find(milestones->begin(), milestones->end(), milestone) ==
      milestones->end()) {
    milestones->push_back(std::move(milestone));
  }
}

std::string JoinStrings(const std::vector<std::string> &items,
                        const char *separator) {
  std::ostringstream out;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i) {
      out << separator;
    }
    out << items[i];
  }
  return out.str();
}

uint16_t ReadLe16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) |
         (static_cast<uint16_t>(p[1]) << 8);
}

void WriteLe16(uint8_t *p, uint16_t value) {
  p[0] = static_cast<uint8_t>(value & 0xFFu);
  p[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

uint32_t ReadLe32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t *p) {
  return static_cast<uint64_t>(ReadLe32(p)) |
         (static_cast<uint64_t>(ReadLe32(p + 4)) << 32);
}

void WriteLe32(uint8_t *p, uint32_t value) {
  p[0] = static_cast<uint8_t>(value & 0xFFu);
  p[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  p[2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
  p[3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
}

void WriteLe64(uint8_t *p, uint64_t value) {
  WriteLe32(p, static_cast<uint32_t>(value & 0xFFFFFFFFull));
  WriteLe32(p + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFull));
}

std::string ToUpperAsciiLocal(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::toupper(c));
                 });
  return value;
}

bool EqualNoCaseLocal(std::string lhs, std::string rhs) {
  return ToUpperAsciiLocal(std::move(lhs)) == ToUpperAsciiLocal(std::move(rhs));
}

std::vector<std::string> SplitFatPath(std::string path) {
  std::replace(path.begin(), path.end(), '/', '\\');
  std::vector<std::string> out;
  size_t start = 0;
  while (start < path.size()) {
    const size_t slash = path.find('\\', start);
    const size_t end = slash == std::string::npos ? path.size() : slash;
    if (end > start) {
      out.push_back(ToUpperAsciiLocal(path.substr(start, end - start)));
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }
  return out;
}

bool ReadDiskBytes(hv::IBlockDevice &disk, uint64_t byteOffset, uint8_t *out,
                   size_t bytes) {
  size_t done = 0;
  std::array<uint8_t, hv::IBlockDevice::kSectorSize> sector{};
  while (done < bytes) {
    const uint64_t absolute = byteOffset + done;
    const uint64_t lba = absolute / hv::IBlockDevice::kSectorSize;
    const size_t inSector =
        static_cast<size_t>(absolute % hv::IBlockDevice::kSectorSize);
    const size_t chunk =
        std::min(bytes - done, hv::IBlockDevice::kSectorSize - inSector);
    if (!disk.ReadSectors(lba, 1, sector.data())) {
      return false;
    }
    std::memcpy(out + done, sector.data() + inSector, chunk);
    done += chunk;
  }
  return true;
}

bool WriteDiskBytes(hv::IBlockDevice &disk, uint64_t byteOffset,
                    const uint8_t *bytes, size_t byteCount) {
  size_t done = 0;
  std::array<uint8_t, hv::IBlockDevice::kSectorSize> sector{};
  while (done < byteCount) {
    const uint64_t absolute = byteOffset + done;
    const uint64_t lba = absolute / hv::IBlockDevice::kSectorSize;
    const size_t inSector =
        static_cast<size_t>(absolute % hv::IBlockDevice::kSectorSize);
    const size_t chunk =
        std::min(byteCount - done, hv::IBlockDevice::kSectorSize - inSector);
    if ((inSector != 0 || chunk != sector.size()) &&
        !disk.ReadSectors(lba, 1, sector.data())) {
      return false;
    }
    if (inSector == 0 && chunk == sector.size()) {
      std::memcpy(sector.data(), bytes + done, sector.size());
    } else {
      std::memcpy(sector.data() + inSector, bytes + done, chunk);
    }
    if (!disk.WriteSectors(lba, 1, sector.data())) {
      return false;
    }
    done += chunk;
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

std::string FatShortName(const uint8_t *entry) {
  std::string name(reinterpret_cast<const char *>(entry), 8);
  std::string ext(reinterpret_cast<const char *>(entry + 8), 3);
  while (!name.empty() && name.back() == ' ') {
    name.pop_back();
  }
  while (!ext.empty() && ext.back() == ' ') {
    ext.pop_back();
  }
  return ext.empty() ? ToUpperAsciiLocal(name)
                     : ToUpperAsciiLocal(name + "." + ext);
}

struct GptPartitionLite {
  std::string typeGuid;
  uint64_t firstLba = 0;
  uint64_t lastLba = 0;
};

std::string GuidFromGptBytes(const uint8_t *p) {
  char out[64]{};
  _snprintf_s(out, sizeof(out), _TRUNCATE,
              "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-"
              "%02X%02X%02X%02X%02X%02X",
              p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6], p[8], p[9],
              p[10], p[11], p[12], p[13], p[14], p[15]);
  return out;
}

std::vector<GptPartitionLite> ReadGptPartitionsLite(hv::IBlockDevice &disk) {
  std::array<uint8_t, hv::IBlockDevice::kSectorSize> header{};
  if (!disk.ReadSectors(1, 1, header.data()) ||
      std::memcmp(header.data(), "EFI PART", 8) != 0) {
    return {};
  }
  const uint64_t entriesLba = ReadLe64(header.data() + 72);
  const uint32_t entryCount = ReadLe32(header.data() + 80);
  const uint32_t entrySize = ReadLe32(header.data() + 84);
  if (entrySize < 128 || entrySize > 4096 || entryCount > 4096) {
    return {};
  }
  std::vector<GptPartitionLite> out;
  std::vector<uint8_t> entry(entrySize);
  for (uint32_t i = 0; i < entryCount; ++i) {
    if (!ReadDiskBytes(disk,
                       entriesLba * hv::IBlockDevice::kSectorSize +
                           static_cast<uint64_t>(i) * entrySize,
                       entry.data(), entry.size())) {
      return {};
    }
    bool empty = true;
    for (size_t j = 0; j < 16; ++j) {
      empty = empty && entry[j] == 0;
    }
    if (empty) {
      continue;
    }
    out.push_back({GuidFromGptBytes(entry.data()), ReadLe64(entry.data() + 32),
                   ReadLe64(entry.data() + 40)});
  }
  return out;
}

bool IsEspGuid(const std::string &guid) {
  return EqualNoCaseLocal(guid, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
}

class Fat32OverlayEditor {
public:
  struct Entry {
    std::string name;
    uint8_t attributes = 0;
    uint32_t firstCluster = 0;
    uint32_t size = 0;
  };

  Fat32OverlayEditor(hv::IBlockDevice &disk, uint64_t firstLba)
      : disk_(disk), firstLba_(firstLba) {}

  bool Init() {
    std::array<uint8_t, hv::IBlockDevice::kSectorSize> bs{};
    if (!disk_.ReadSectors(firstLba_, 1, bs.data()) ||
        std::memcmp(bs.data() + 82, "FAT32", 5) != 0) {
      return false;
    }
    bytesPerSector_ = ReadLe16(bs.data() + 11);
    sectorsPerCluster_ = bs[13];
    reservedSectors_ = ReadLe16(bs.data() + 14);
    fatCount_ = bs[16];
    fatSizeSectors_ = ReadLe32(bs.data() + 36);
    rootCluster_ = ReadLe32(bs.data() + 44);
    if (bytesPerSector_ != hv::IBlockDevice::kSectorSize ||
        sectorsPerCluster_ == 0 || reservedSectors_ == 0 ||
        fatCount_ == 0 || fatSizeSectors_ == 0 || rootCluster_ < 2) {
      return false;
    }
    fatStartLba_ = firstLba_ + reservedSectors_;
    dataStartLba_ =
        fatStartLba_ + static_cast<uint64_t>(fatCount_) * fatSizeSectors_;
    return true;
  }

  std::optional<Entry> FindPath(std::string path) {
    const auto components = SplitFatPath(std::move(path));
    if (components.empty()) {
      return std::nullopt;
    }
    uint32_t cluster = rootCluster_;
    std::optional<Entry> current;
    for (size_t i = 0; i < components.size(); ++i) {
      current.reset();
      for (const auto &entry : ReadDirectory(cluster)) {
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
    size_t guard = 0;
    while (cluster >= 2 && !IsEoc(cluster) && out.size() < maxBytes &&
           guard++ < 65536) {
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

  bool WriteFileSameSize(const Entry &entry,
                         const std::vector<uint8_t> &bytes) {
    if (bytes.size() != entry.size) {
      return false;
    }
    uint32_t cluster = entry.firstCluster;
    std::vector<uint8_t> clusterBytes(ClusterBytes());
    size_t offset = 0;
    size_t guard = 0;
    while (cluster >= 2 && !IsEoc(cluster) && offset < bytes.size() &&
           guard++ < 65536) {
      if (!ReadCluster(cluster, clusterBytes.data())) {
        return false;
      }
      const size_t take = std::min(clusterBytes.size(), bytes.size() - offset);
      std::memcpy(clusterBytes.data(), bytes.data() + offset, take);
      if (!WriteCluster(cluster, clusterBytes.data())) {
        return false;
      }
      offset += take;
      cluster = NextCluster(cluster);
    }
    return offset == bytes.size();
  }

  bool ZeroFile(const Entry &entry, size_t maxBytes) {
    if (entry.size == 0 || entry.size > maxBytes) {
      return false;
    }
    std::vector<uint8_t> zeros(entry.size, 0);
    return WriteFileSameSize(entry, zeros);
  }

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

  bool WriteCluster(uint32_t cluster, const uint8_t *bytes) {
    if (cluster < 2) {
      return false;
    }
    const uint64_t lba =
        dataStartLba_ + static_cast<uint64_t>(cluster - 2) * sectorsPerCluster_;
    return disk_.WriteSectors(lba, sectorsPerCluster_, bytes);
  }

  uint32_t NextCluster(uint32_t cluster) {
    std::array<uint8_t, 4> bytes{};
    const uint64_t offset = fatStartLba_ * hv::IBlockDevice::kSectorSize +
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
        if (entry[0] == 0xE5) {
          longName.clear();
          continue;
        }
        if (entry[11] == 0x0F) {
          longName = FatLongNamePart(entry) + longName;
          continue;
        }
        Entry dir;
        dir.name =
            longName.empty() ? FatShortName(entry) : ToUpperAsciiLocal(longName);
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

  hv::IBlockDevice &disk_;
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

struct NtfsRunLite {
  uint64_t lcn = 0;
  uint64_t clusters = 0;
};

struct NtfsEntryLite {
  uint64_t fileRecord = 0;
  uint64_t size = 0;
  bool directory = false;
  std::vector<NtfsRunLite> dataRuns;
};

class NtfsBootFileLocator {
public:
  NtfsBootFileLocator(hv::IBlockDevice &disk, uint64_t firstLba)
      : disk_(disk), firstLba_(firstLba) {}

  bool Init() {
    std::array<uint8_t, hv::IBlockDevice::kSectorSize> bs{};
    if (!disk_.ReadSectors(firstLba_, 1, bs.data()) ||
        std::memcmp(bs.data() + 3, "NTFS    ", 8) != 0) {
      return false;
    }
    bytesPerSector_ = ReadLe16(bs.data() + 11);
    sectorsPerCluster_ = bs[13];
    mftLcn_ = ReadLe64(bs.data() + 48);
    const int8_t fileRecordClusters =
        static_cast<int8_t>(static_cast<char>(bs[64]));
    if (bytesPerSector_ != hv::IBlockDevice::kSectorSize ||
        sectorsPerCluster_ == 0 || mftLcn_ == 0) {
      return false;
    }
    fileRecordBytes_ =
        fileRecordClusters < 0
            ? 1ull << static_cast<unsigned>(-fileRecordClusters)
            : static_cast<uint32_t>(fileRecordClusters) * ClusterBytes();
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

  std::optional<NtfsEntryLite> FindPath(std::string path) {
    std::replace(path.begin(), path.end(), '/', '\\');
    std::vector<std::string> components;
    size_t start = 0;
    while (start < path.size()) {
      const size_t slash = path.find('\\', start);
      const size_t end = slash == std::string::npos ? path.size() : slash;
      if (end > start) {
        components.push_back(ToUpperAsciiLocal(path.substr(start, end - start)));
      }
      if (slash == std::string::npos) {
        break;
      }
      start = slash + 1;
    }
    if (components.empty()) {
      return std::nullopt;
    }

    NtfsEntryLite current;
    current.fileRecord = 5;
    current.directory = true;
    for (const auto &component : components) {
      if (!current.directory) {
        return std::nullopt;
      }
      std::optional<NtfsEntryLite> next;
      for (const auto &entry : ReadDirectory(current.fileRecord)) {
        if (entry.nameSpace == 2) {
          continue;
        }
        if (entry.name == component) {
          next = NtfsEntryLite{};
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

  uint8_t SectorsPerCluster() const noexcept { return sectorsPerCluster_; }

  std::vector<uint8_t> ReadFile(const NtfsEntryLite &entry, size_t maxBytes) {
    if (entry.directory || entry.dataRuns.empty() || entry.size == 0) {
      return {};
    }
    const size_t bytes = static_cast<size_t>(
        std::min<uint64_t>(entry.size, static_cast<uint64_t>(maxBytes)));
    std::vector<uint8_t> out(bytes);
    if (!ReadStreamBytes(entry.dataRuns, 0, out.data(), out.size())) {
      return {};
    }
    return out;
  }

  bool WriteFileSameSize(const NtfsEntryLite &entry,
                         const std::vector<uint8_t> &bytes) {
    return !entry.directory && !entry.dataRuns.empty() &&
           bytes.size() == entry.size &&
           WriteStreamBytes(entry.dataRuns, 0, bytes.data(), bytes.size());
  }

private:
  struct Attribute {
    uint32_t type = 0;
    bool nonResident = false;
    std::vector<uint8_t> residentData;
    std::vector<NtfsRunLite> runs;
    uint64_t realSize = 0;
  };

  struct DirectoryEntry {
    std::string name;
    uint8_t nameSpace = 0;
    uint64_t fileRecord = 0;
    uint64_t size = 0;
    bool directory = false;
  };

  size_t ClusterBytes() const noexcept {
    return static_cast<size_t>(bytesPerSector_) * sectorsPerCluster_;
  }

  bool ReadVolumeBytes(uint64_t volumeOffset, uint8_t *out, size_t bytes) {
    return ReadDiskBytes(disk_, firstLba_ * hv::IBlockDevice::kSectorSize +
                                    volumeOffset,
                         out, bytes);
  }

  bool WriteVolumeBytes(uint64_t volumeOffset, const uint8_t *bytes,
                        size_t byteCount) {
    return WriteDiskBytes(disk_, firstLba_ * hv::IBlockDevice::kSectorSize +
                                     volumeOffset,
                          bytes, byteCount);
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

  std::vector<NtfsRunLite> ParseDataRuns(const uint8_t *p,
                                         size_t bytes) const {
    std::vector<NtfsRunLite> runs;
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

  bool ReadStreamBytes(const std::vector<NtfsRunLite> &runs,
                       uint64_t streamOffset, uint8_t *out, size_t bytes) {
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

  bool WriteStreamBytes(const std::vector<NtfsRunLite> &runs,
                        uint64_t streamOffset, const uint8_t *bytes,
                        size_t byteCount) {
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
          std::min<uint64_t>(byteCount - done, runBytes - inRun);
      if (!WriteVolumeBytes(run.lcn * clusterBytes + inRun, bytes + done,
                            static_cast<size_t>(take))) {
        return false;
      }
      done += static_cast<size_t>(take);
      streamOffset += take;
      logical += runBytes;
      if (done == byteCount) {
        return true;
      }
    }
    return done == byteCount;
  }

  bool ApplyFixups(std::vector<uint8_t> &record,
                   const char *signature) const {
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
      record[trailer + 1] =
          static_cast<uint8_t>((replacement >> 8) & 0xFFu);
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

  void PopulateDataRuns(NtfsEntryLite &entry) {
    if (entry.directory) {
      return;
    }
    std::vector<uint8_t> record;
    if (!ReadFileRecord(entry.fileRecord, record)) {
      return;
    }
    for (const auto &attr : Attributes(record)) {
      if (attr.type == 0x80) {
        entry.size = attr.nonResident ? attr.realSize : attr.residentData.size();
        entry.dataRuns = attr.runs;
        return;
      }
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
          attr.runs =
              ParseDataRuns(record.data() + offset + runOffset,
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
    return ToUpperAsciiLocal(Utf16LeAsciiName(p + 66, nameBytes));
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
      constexpr size_t kIndexHeader = 16;
      const uint32_t entryOffset =
          ReadLe32(attr.residentData.data() + kIndexHeader);
      const uint32_t totalSize =
          ReadLe32(attr.residentData.data() + kIndexHeader + 4);
      const size_t start = kIndexHeader + entryOffset;
      const size_t end = std::min<size_t>(kIndexHeader + totalSize,
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
        constexpr size_t kIndexHeader = 0x18;
        const uint32_t entryOffset = ReadLe32(block.data() + kIndexHeader);
        const uint32_t totalSize =
            ReadLe32(block.data() + kIndexHeader + 4);
        const size_t start = kIndexHeader + entryOffset;
        const size_t end =
            std::min<size_t>(kIndexHeader + totalSize, block.size());
        if (start < end) {
          auto entries = ParseIndexEntries(block.data() + start, end - start);
          out.insert(out.end(), entries.begin(), entries.end());
        }
      }
    }
    return out;
  }

  hv::IBlockDevice &disk_;
  uint64_t firstLba_ = 0;
  uint16_t bytesPerSector_ = 0;
  uint8_t sectorsPerCluster_ = 0;
  uint64_t mftLcn_ = 0;
  uint32_t fileRecordBytes_ = 0;
  uint64_t mftDataSize_ = 0;
  std::vector<NtfsRunLite> mftRuns_;
};

bool IsWindowsBasicDataGuid(const std::string &guid) {
  return EqualNoCaseLocal(guid, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
}

struct BootReadTarget {
  std::string name;
  uint64_t firstLba = 0;
  uint64_t lastLba = 0;
};

struct BootReadObservation {
  BootReadTarget target;
  uint64_t readCommands = 0;
  uint64_t sectorsRead = 0;
};

std::vector<BootReadTarget> DiscoverBootReadTargets(hv::IBlockDevice &disk) {
  std::vector<BootReadTarget> targets;
  const auto partitions = ReadGptPartitionsLite(disk);
  const auto windows =
      std::find_if(partitions.begin(), partitions.end(),
                   [](const GptPartitionLite &partition) {
                     return IsWindowsBasicDataGuid(partition.typeGuid);
                   });
  if (windows == partitions.end()) {
    return targets;
  }

  NtfsBootFileLocator ntfs(disk, windows->firstLba);
  if (!ntfs.Init()) {
    return targets;
  }
  const char *paths[] = {
      "Windows\\System32\\winload.efi",
      "Windows\\System32\\ntoskrnl.exe",
      "Windows\\System32\\hal.dll",
      "Windows\\System32\\kdcom.dll",
      "Windows\\System32\\ci.dll",
      "Windows\\System32\\config\\SYSTEM",
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
  for (const char *path : paths) {
    const auto entry = ntfs.FindPath(path);
    if (!entry || entry->dataRuns.empty()) {
      continue;
    }
    for (const auto &run : entry->dataRuns) {
      const uint64_t first =
          windows->firstLba +
          run.lcn * static_cast<uint64_t>(ntfs.SectorsPerCluster());
      const uint64_t sectors =
          run.clusters * static_cast<uint64_t>(ntfs.SectorsPerCluster());
      if (sectors != 0) {
        targets.push_back({path, first, first + sectors - 1});
      }
    }
  }
  return targets;
}

std::vector<BootReadObservation>
AnalyzeBootReadTargets(const hv::VmRunSummary &vm,
                       const std::vector<BootReadTarget> &targets) {
  std::vector<BootReadObservation> observations;
  observations.reserve(targets.size());
  for (const auto &target : targets) {
    BootReadObservation observation;
    observation.target = target;
    for (const auto &access : vm.ideRecentAccesses) {
      if (access.write || access.count == 0) {
        continue;
      }
      const uint64_t first = access.lba;
      const uint64_t last = access.lba + access.count - 1;
      if (last < target.firstLba || first > target.lastLba) {
        continue;
      }
      ++observation.readCommands;
      const uint64_t overlapFirst = std::max(first, target.firstLba);
      const uint64_t overlapLast = std::min(last, target.lastLba);
      observation.sectorsRead += overlapLast - overlapFirst + 1;
    }
    observations.push_back(observation);
  }
  return observations;
}

std::string FormatBootReadObservations(
    const std::vector<BootReadObservation> &observations) {
  if (observations.empty()) {
    return {};
  }
  std::ostringstream out;
  out << "\nBoot file read targets:\n";
  for (const auto &observation : observations) {
    out << "  " << observation.target.name << " lba="
        << observation.target.firstLba << "-" << observation.target.lastLba
        << " readCommands=" << observation.readCommands
        << " sectorsRead=" << observation.sectorsRead << "\n";
  }
  return out.str();
}

std::string FileNameFromBootPath(const std::string &path) {
  const auto slash = path.find_last_of("\\/");
  if (slash == std::string::npos) {
    return path;
  }
  return path.substr(slash + 1);
}

void AddBootReadMilestones(
    BootSignalSummary *signals,
    const std::vector<BootReadObservation> &observations) {
  if (!signals) {
    return;
  }
  for (const auto &observation : observations) {
    if (observation.readCommands == 0) {
      continue;
    }
    if (ContainsTextNoCase(observation.target.name, "winload.efi")) {
      AddMilestone(signals, "winload.efi data read");
    } else if (ContainsTextNoCase(observation.target.name, "ntoskrnl.exe")) {
      AddMilestone(signals, "ntoskrnl.exe data read");
    } else if (ContainsTextNoCase(observation.target.name, "hal.dll")) {
      AddMilestone(signals, "HAL data read");
    } else if (ContainsTextNoCase(observation.target.name, "\\drivers\\")) {
      AddMilestone(signals,
                   "boot driver data read: " +
                       FileNameFromBootPath(observation.target.name));
    } else if (ContainsTextNoCase(observation.target.name, "SYSTEM")) {
      AddMilestone(signals, "SYSTEM hive data read");
    } else if (ContainsTextNoCase(observation.target.name, "SOFTWARE")) {
      AddMilestone(signals, "SOFTWARE hive data read");
    }
  }
}

std::string BootReadDetails(
    const std::vector<BootReadObservation> &observations) {
  std::vector<std::string> parts;
  for (const auto &observation : observations) {
    std::ostringstream item;
    item << observation.target.name << " lba=" << observation.target.firstLba
         << "-" << observation.target.lastLba
         << " readCommands=" << observation.readCommands
         << " sectorsRead=" << observation.sectorsRead;
    parts.push_back(item.str());
  }
  return JoinStrings(parts, "; ");
}

struct BcdValueLocation {
  uint32_t type = 0;
  uint32_t dataLength = 0;
  size_t dataAbsolute = 0;
  bool inlineData = false;
};

struct HiveKeyLite {
  uint32_t index = 0;
  uint16_t flags = 0;
  uint32_t subkeyCounts[2] = {0, 0};
  uint32_t subkeyLists[2] = {0xFFFFFFFFu, 0xFFFFFFFFu};
  uint32_t valueCount = 0;
  uint32_t valueList = 0xFFFFFFFFu;
  size_t nameAbsolute = 0;
  std::string name;
};

class MutableHiveView {
public:
  explicit MutableHiveView(std::vector<uint8_t> &bytes) : bytes_(bytes) {}

  bool IsValid() const {
    return bytes_.size() >= 0x1000 && std::memcmp(bytes_.data(), "regf", 4) == 0;
  }

  std::optional<uint32_t> RootIndex() const {
    if (!IsValid() || bytes_.size() < 0x28) {
      return std::nullopt;
    }
    return ReadLe32(bytes_.data() + 0x24);
  }

  std::optional<HiveKeyLite> ReadKey(uint32_t index) const {
    const auto cell = CellAbsolute(index);
    if (!cell || *cell + 80 > bytes_.size()) {
      return std::nullopt;
    }
    const size_t data = *cell + 4;
    if (std::memcmp(bytes_.data() + data, "nk", 2) != 0) {
      return std::nullopt;
    }
    HiveKeyLite key;
    key.index = index;
    key.flags = ReadLe16(bytes_.data() + data + 2);
    key.subkeyCounts[0] = ReadLe32(bytes_.data() + data + 20);
    key.subkeyCounts[1] = ReadLe32(bytes_.data() + data + 24);
    key.subkeyLists[0] = ReadLe32(bytes_.data() + data + 28);
    key.subkeyLists[1] = ReadLe32(bytes_.data() + data + 32);
    key.valueCount = ReadLe32(bytes_.data() + data + 36);
    key.valueList = ReadLe32(bytes_.data() + data + 40);
    const uint16_t nameLen = ReadLe16(bytes_.data() + data + 72);
    key.nameAbsolute = data + 76;
    if (key.nameAbsolute + nameLen > bytes_.size()) {
      return std::nullopt;
    }
    if ((key.flags & 0x20u) != 0) {
      key.name.assign(reinterpret_cast<const char *>(bytes_.data() +
                                                     key.nameAbsolute),
                      nameLen);
    } else {
      key.name = Utf16LeAsciiName(bytes_.data() + key.nameAbsolute, nameLen);
    }
    return key;
  }

  std::optional<uint32_t> FindSubkey(uint32_t index,
                                     const std::string &name) const {
    for (const auto child : SubkeyIndexes(index)) {
      const auto key = ReadKey(child);
      if (key && EqualNoCaseLocal(key->name, name)) {
        return child;
      }
    }
    return std::nullopt;
  }

  std::optional<BcdValueLocation> FindValue(uint32_t keyIndex,
                                            const std::string &name) const {
    const auto key = ReadKey(keyIndex);
    if (!key || key->valueCount == 0 || key->valueList == 0xFFFFFFFFu) {
      return std::nullopt;
    }
    const auto listCell = CellAbsolute(key->valueList);
    if (!listCell || *listCell + 4 + key->valueCount * 4ull > bytes_.size()) {
      return std::nullopt;
    }
    const size_t list = *listCell + 4;
    for (uint32_t i = 0; i < key->valueCount; ++i) {
      const auto value = ReadValue(ReadLe32(bytes_.data() + list + i * 4ull));
      if (value && EqualNoCaseLocal(value->name, name)) {
        return value->location;
      }
    }
    return std::nullopt;
  }

  std::vector<uint8_t> ValueBytes(const BcdValueLocation &location) const {
    if (location.dataAbsolute + location.dataLength > bytes_.size()) {
      return {};
    }
    return std::vector<uint8_t>(bytes_.begin() + location.dataAbsolute,
                                bytes_.begin() + location.dataAbsolute +
                                    location.dataLength);
  }

  std::optional<uint32_t> CreateAsciiKey(uint32_t parentIndex,
                                         const std::string &name) {
    const auto parent = ReadKey(parentIndex);
    const auto parentCell = CellAbsolute(parentIndex);
    if (!parent || !parentCell || name.empty() ||
        name.size() > std::numeric_limits<uint16_t>::max()) {
      return std::nullopt;
    }
    const auto keyIndex = AllocateCell(76 + name.size());
    if (!keyIndex) {
      return std::nullopt;
    }
    const auto cell = CellAbsolute(*keyIndex);
    if (!cell) {
      return std::nullopt;
    }
    const size_t data = *cell + 4;
    std::memcpy(bytes_.data() + data, "nk", 2);
    WriteLe16(bytes_.data() + data + 2, 0x20u);
    WriteLe32(bytes_.data() + data + 16, parentIndex);
    WriteLe32(bytes_.data() + data + 28, 0xFFFFFFFFu);
    WriteLe32(bytes_.data() + data + 32, 0xFFFFFFFFu);
    WriteLe32(bytes_.data() + data + 40, 0xFFFFFFFFu);
    WriteLe32(bytes_.data() + data + 44,
              ReadLe32(bytes_.data() + *parentCell + 4 + 44));
    WriteLe32(bytes_.data() + data + 48, 0xFFFFFFFFu);
    WriteLe16(bytes_.data() + data + 72,
              static_cast<uint16_t>(name.size()));
    std::memcpy(bytes_.data() + data + 76, name.data(), name.size());
    if (!AppendSubkey(parentIndex, *keyIndex)) {
      return std::nullopt;
    }
    return keyIndex;
  }

  bool SetAsciiStringValue(uint32_t keyIndex, const std::string &name,
                           const std::wstring &value) {
    const auto key = ReadKey(keyIndex);
    if (!key || name.empty() ||
        name.size() > std::numeric_limits<uint16_t>::max()) {
      return false;
    }
    std::vector<uint8_t> valueBytes((value.size() + 1) * sizeof(wchar_t));
    std::memcpy(valueBytes.data(), value.c_str(), valueBytes.size());
    const auto dataIndex = AllocateCell(valueBytes.size());
    if (!dataIndex) {
      return false;
    }
    const auto dataCell = CellAbsolute(*dataIndex);
    if (!dataCell) {
      return false;
    }
    std::memcpy(bytes_.data() + *dataCell + 4, valueBytes.data(),
                valueBytes.size());

    const auto valueIndex = AllocateCell(20 + name.size());
    if (!valueIndex) {
      return false;
    }
    const auto valueCell = CellAbsolute(*valueIndex);
    if (!valueCell) {
      return false;
    }
    const size_t data = *valueCell + 4;
    std::memcpy(bytes_.data() + data, "vk", 2);
    WriteLe16(bytes_.data() + data + 2,
              static_cast<uint16_t>(name.size()));
    WriteLe32(bytes_.data() + data + 4,
              static_cast<uint32_t>(valueBytes.size()));
    WriteLe32(bytes_.data() + data + 8, *dataIndex);
    WriteLe32(bytes_.data() + data + 12, REG_SZ);
    WriteLe16(bytes_.data() + data + 16, 0x1u);
    std::memcpy(bytes_.data() + data + 20, name.data(), name.size());
    return AppendValue(keyIndex, *valueIndex);
  }

private:
  struct NamedValue {
    std::string name;
    BcdValueLocation location;
  };

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

  std::optional<uint32_t> AllocateCell(size_t dataBytes) {
    constexpr size_t kHiveBase = 0x1000;
    const size_t required = ((dataBytes + 4 + 7) / 8) * 8;
    if (required > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
      return std::nullopt;
    }
    size_t hbin = kHiveBase;
    while (hbin + 32 <= bytes_.size() &&
           std::memcmp(bytes_.data() + hbin, "hbin", 4) == 0) {
      const uint32_t hbinSize = ReadLe32(bytes_.data() + hbin + 8);
      if (hbinSize < 32 || hbin + hbinSize > bytes_.size()) {
        break;
      }
      size_t cell = hbin + 32;
      while (cell + 4 <= hbin + hbinSize) {
        const int32_t signedSize =
            static_cast<int32_t>(ReadLe32(bytes_.data() + cell));
        if (signedSize == 0 ||
            signedSize == std::numeric_limits<int32_t>::min()) {
          break;
        }
        const size_t cellSize =
            static_cast<size_t>(signedSize < 0 ? -signedSize : signedSize);
        if (cellSize < 8 || cell + cellSize > hbin + hbinSize) {
          break;
        }
        if (signedSize > 0 && cellSize >= required) {
          const size_t remainder = cellSize - required;
          const size_t used = remainder >= 8 ? required : cellSize;
          WriteLe32(bytes_.data() + cell,
                    static_cast<uint32_t>(-static_cast<int32_t>(used)));
          std::memset(bytes_.data() + cell + 4, 0, used - 4);
          if (remainder >= 8) {
            WriteLe32(bytes_.data() + cell + used,
                      static_cast<uint32_t>(remainder));
          }
          return static_cast<uint32_t>(cell - kHiveBase);
        }
        cell += cellSize;
      }
      hbin += hbinSize;
    }
    return std::nullopt;
  }

  bool AppendSubkey(uint32_t parentIndex, uint32_t childIndex) {
    auto indexes = SubkeyIndexes(parentIndex);
    indexes.push_back(childIndex);
    if (indexes.size() > std::numeric_limits<uint16_t>::max()) {
      return false;
    }
    const auto listIndex = AllocateCell(4 + indexes.size() * 4);
    const auto parentCell = CellAbsolute(parentIndex);
    const auto listCell = listIndex ? CellAbsolute(*listIndex) : std::nullopt;
    if (!parentCell || !listCell) {
      return false;
    }
    const size_t listData = *listCell + 4;
    std::memcpy(bytes_.data() + listData, "li", 2);
    WriteLe16(bytes_.data() + listData + 2,
              static_cast<uint16_t>(indexes.size()));
    for (size_t i = 0; i < indexes.size(); ++i) {
      WriteLe32(bytes_.data() + listData + 4 + i * 4, indexes[i]);
    }
    const size_t parentData = *parentCell + 4;
    WriteLe32(bytes_.data() + parentData + 20,
              static_cast<uint32_t>(indexes.size()));
    WriteLe32(bytes_.data() + parentData + 28, *listIndex);
    return true;
  }

  bool AppendValue(uint32_t keyIndex, uint32_t valueIndex) {
    const auto key = ReadKey(keyIndex);
    const auto keyCell = CellAbsolute(keyIndex);
    if (!key || !keyCell) {
      return false;
    }
    std::vector<uint32_t> indexes;
    if (key->valueCount != 0 && key->valueList != 0xFFFFFFFFu) {
      const auto oldList = CellAbsolute(key->valueList);
      if (!oldList ||
          *oldList + 4 + key->valueCount * 4ull > bytes_.size()) {
        return false;
      }
      for (uint32_t i = 0; i < key->valueCount; ++i) {
        indexes.push_back(ReadLe32(bytes_.data() + *oldList + 4 + i * 4ull));
      }
    }
    indexes.push_back(valueIndex);
    const auto listIndex = AllocateCell(indexes.size() * 4);
    const auto listCell = listIndex ? CellAbsolute(*listIndex) : std::nullopt;
    if (!listCell) {
      return false;
    }
    for (size_t i = 0; i < indexes.size(); ++i) {
      WriteLe32(bytes_.data() + *listCell + 4 + i * 4, indexes[i]);
    }
    const size_t keyData = *keyCell + 4;
    WriteLe32(bytes_.data() + keyData + 36,
              static_cast<uint32_t>(indexes.size()));
    WriteLe32(bytes_.data() + keyData + 40, *listIndex);
    return true;
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

  std::optional<NamedValue> ReadValue(uint32_t index) const {
    const auto cell = CellAbsolute(index);
    if (!cell || *cell + 24 > bytes_.size()) {
      return std::nullopt;
    }
    const size_t data = *cell + 4;
    if (std::memcmp(bytes_.data() + data, "vk", 2) != 0) {
      return std::nullopt;
    }
    const uint16_t nameLen = ReadLe16(bytes_.data() + data + 2);
    uint32_t dataLen = ReadLe32(bytes_.data() + data + 4);
    const uint32_t dataField = ReadLe32(bytes_.data() + data + 8);
    const uint32_t type = ReadLe32(bytes_.data() + data + 12);
    const uint16_t flags = ReadLe16(bytes_.data() + data + 16);
    if (data + 20 + nameLen > bytes_.size()) {
      return std::nullopt;
    }

    NamedValue value;
    if ((flags & 0x1u) != 0) {
      value.name.assign(reinterpret_cast<const char *>(bytes_.data() + data + 20),
                        nameLen);
    } else {
      value.name = Utf16LeAsciiName(bytes_.data() + data + 20, nameLen);
    }
    value.location.type = type;
    value.location.inlineData = (dataLen & 0x80000000u) != 0;
    value.location.dataLength = dataLen & 0x7FFFFFFFu;
    if (value.location.inlineData) {
      if (value.location.dataLength > 4) {
        return std::nullopt;
      }
      value.location.dataAbsolute = data + 8;
      return value;
    }
    const auto dataCell = CellAbsolute(dataField);
    if (!dataCell ||
        *dataCell + 4 + value.location.dataLength > bytes_.size()) {
      return std::nullopt;
    }
    value.location.dataAbsolute = *dataCell + 4;
    return value;
  }

  std::vector<uint8_t> &bytes_;
};

std::string BcdElementString(MutableHiveView &hive, uint32_t objectKey,
                             const std::string &elementId) {
  const auto elements = hive.FindSubkey(objectKey, "Elements");
  if (!elements) {
    return {};
  }
  const auto elementKey = hive.FindSubkey(*elements, elementId);
  if (!elementKey) {
    return {};
  }
  const auto value = hive.FindValue(*elementKey, "Element");
  if (!value || value->type != 1) {
    return {};
  }
  return Utf16LeAsciiString(hive.ValueBytes(*value));
}

struct BootOverlayPatchResult {
  bool attempted = false;
  bool espFound = false;
  bool bcdFound = false;
  bool bcdPolicyPatched = false;
  bool recoveryPatched = false;
  bool bootstatReset = false;
  bool systemHiveFound = false;
  bool bootStoragePatched = false;
  std::vector<std::string> notes;
};

bool PatchOverlaySystemBootStorage(hv::IBlockDevice &disk,
                                   BootOverlayPatchResult *result);

bool PatchBcdDonorElement(MutableHiveView &hive, std::vector<uint8_t> &bcd,
                          uint32_t elementsKey, const std::string &targetId,
                          const std::string &donorId,
                          uint64_t replacementValue,
                          bool oneByteValue) {
  if (hive.FindSubkey(elementsKey, targetId)) {
    return false;
  }
  const auto donorIndex = hive.FindSubkey(elementsKey, donorId);
  if (!donorIndex) {
    return false;
  }
  const auto donorKey = hive.ReadKey(*donorIndex);
  if (!donorKey || donorKey->name.size() != targetId.size() ||
      donorKey->nameAbsolute + targetId.size() > bcd.size()) {
    return false;
  }
  const auto value = hive.FindValue(*donorIndex, "Element");
  if (!value || value->type != 3) {
    return false;
  }
  if (oneByteValue) {
    if (value->dataLength < 1 || value->dataAbsolute + 4 > bcd.size()) {
      return false;
    }
    WriteLe32(bcd.data() + value->dataAbsolute,
              static_cast<uint32_t>(replacementValue != 0 ? 1 : 0));
  } else {
    if (value->dataLength < 8 || value->dataAbsolute + 8 > bcd.size()) {
      return false;
    }
    WriteLe64(bcd.data() + value->dataAbsolute, replacementValue);
  }
  std::memcpy(bcd.data() + donorKey->nameAbsolute, targetId.data(),
              targetId.size());
  return true;
}

bool PatchBcdBootPolicy(std::vector<uint8_t> &bcd,
                        BootOverlayPatchResult *result) {
  MutableHiveView hive(bcd);
  if (!hive.IsValid()) {
    if (result) {
      result->notes.push_back("BCD is not a registry hive");
    }
    return false;
  }
  const auto root = hive.RootIndex();
  const auto objects = root ? hive.FindSubkey(*root, "Objects") : std::nullopt;
  const auto bootmgr =
      objects ? hive.FindSubkey(*objects,
                                "{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
              : std::nullopt;
  const std::string defaultGuid =
      bootmgr ? BcdElementString(hive, *bootmgr, "23000003") : std::string{};
  const auto defaultObject =
      !defaultGuid.empty() && objects ? hive.FindSubkey(*objects, defaultGuid)
                                      : std::nullopt;
  const auto elements =
      defaultObject ? hive.FindSubkey(*defaultObject, "Elements") : std::nullopt;
  if (!elements) {
    if (result) {
      result->notes.push_back("default BCD loader Elements key not found");
    }
    return false;
  }

  bool changed = false;
  if (PatchBcdDonorElement(hive, bcd, *elements, "16000009", "16000060", 0,
                           true)) {
    changed = true;
    if (result) {
      result->recoveryPatched = true;
    }
  }
  if (PatchBcdDonorElement(hive, bcd, *elements, "250000E0", "25000020", 1,
                           false)) {
    changed = true;
    if (result) {
      result->bcdPolicyPatched = true;
    }
  }
  if (!changed && result) {
    result->notes.push_back("BCD boot policy elements already present or donor "
                            "elements unavailable");
  }
  return changed;
}

bool BootOverlayPatchDisabled() {
  char buf[16]{};
  size_t needed = 0;
  return getenv_s(&needed, buf, sizeof(buf),
                  "ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH") == 0 &&
         needed > 1 && buf[0] != '\0' && std::atoi(buf) != 0;
}

BootOverlayPatchResult ApplyEphemeralBootOverlay(hv::IBlockDevice &disk) {
  BootOverlayPatchResult result;
  result.attempted = true;
  if (BootOverlayPatchDisabled()) {
    result.notes.push_back("disabled by ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH");
    return result;
  }

  const auto partitions = ReadGptPartitionsLite(disk);
  const auto esp = std::find_if(partitions.begin(), partitions.end(),
                                [](const GptPartitionLite &partition) {
                                  return IsEspGuid(partition.typeGuid);
                                });
  if (esp == partitions.end()) {
    result.notes.push_back("ESP not found");
    return result;
  }
  result.espFound = true;
  Fat32OverlayEditor fat(disk, esp->firstLba);
  if (!fat.Init()) {
    result.notes.push_back("ESP is not readable FAT32");
    return result;
  }

  if (const auto bcd = fat.FindPath("EFI\\Microsoft\\Boot\\BCD")) {
    result.bcdFound = true;
    auto bytes = fat.ReadFile(*bcd, 4ull * 1024ull * 1024ull);
    if (bytes.size() == bcd->size && PatchBcdBootPolicy(bytes, &result)) {
      if (!fat.WriteFileSameSize(*bcd, bytes)) {
        result.bcdPolicyPatched = false;
        result.recoveryPatched = false;
        result.notes.push_back("failed to write patched BCD to overlay");
      }
    }
  } else {
    result.notes.push_back("BCD not found on ESP");
  }

  if (const auto bootstat =
          fat.FindPath("EFI\\Microsoft\\Boot\\bootstat.dat")) {
    result.bootstatReset = fat.ZeroFile(*bootstat, 1024ull * 1024ull);
    if (!result.bootstatReset) {
      result.notes.push_back("bootstat.dat was present but not reset");
    }
  } else {
    result.notes.push_back("bootstat.dat not found on ESP");
  }
  PatchOverlaySystemBootStorage(disk, &result);
  return result;
}

std::map<std::string, std::string>
BootOverlayPatchDetails(const BootOverlayPatchResult &patch) {
  std::map<std::string, std::string> details{
      {"attempted", patch.attempted ? "true" : "false"},
      {"espFound", patch.espFound ? "true" : "false"},
      {"bcdFound", patch.bcdFound ? "true" : "false"},
      {"bcdPolicyPatched", patch.bcdPolicyPatched ? "true" : "false"},
      {"recoveryPatched", patch.recoveryPatched ? "true" : "false"},
      {"bootstatReset", patch.bootstatReset ? "true" : "false"},
      {"systemHiveFound", patch.systemHiveFound ? "true" : "false"},
      {"bootStoragePatched", patch.bootStoragePatched ? "true" : "false"},
      {"scope", "overlay-only"}};
  if (!patch.notes.empty()) {
    details["notes"] = JoinStrings(patch.notes, "; ");
  }
  return details;
}

struct BaseBootStorageInspection {
  bool inspected = false;
  bool ready = false;
  std::string details;
};

std::optional<uint32_t>
FindHivePath(MutableHiveView &hive,
             std::initializer_list<std::string> components) {
  auto current = hive.RootIndex();
  if (!current) {
    return std::nullopt;
  }
  for (const auto &component : components) {
    current = hive.FindSubkey(*current, component);
    if (!current) {
      return std::nullopt;
    }
  }
  return current;
}

std::optional<uint32_t> HiveDwordValue(MutableHiveView &hive, uint32_t key,
                                       const std::string &name) {
  const auto value = hive.FindValue(key, name);
  if (!value || value->dataLength < 4) {
    return std::nullopt;
  }
  const auto bytes = hive.ValueBytes(*value);
  if (bytes.size() < 4) {
    return std::nullopt;
  }
  return ReadLe32(bytes.data());
}

std::string HiveStringValue(MutableHiveView &hive, uint32_t key,
                            const std::string &name) {
  const auto value = hive.FindValue(key, name);
  if (!value || value->dataLength == 0) {
    return {};
  }
  const auto bytes = hive.ValueBytes(*value);
  if (bytes.empty()) {
    return {};
  }
  if (value->type == 1 || value->type == 2) {
    return Utf16LeAsciiString(bytes);
  }
  return {};
}

std::string FormatControlSetName(uint32_t controlSet) {
  std::ostringstream out;
  out << "ControlSet" << std::setw(3) << std::setfill('0') << controlSet;
  return out.str();
}

std::optional<std::string> SelectOfflineControlSet(MutableHiveView &hive) {
  const auto select = FindHivePath(hive, {"Select"});
  if (!select) {
    return std::nullopt;
  }
  const auto current = HiveDwordValue(hive, *select, "Current");
  const auto def = HiveDwordValue(hive, *select, "Default");
  if (current && *current != 0) {
    return FormatControlSetName(*current);
  }
  if (def && *def != 0) {
    return FormatControlSetName(*def);
  }
  return FormatControlSetName(1);
}

bool ServiceBootStartReady(MutableHiveView &hive,
                           const std::string &controlSet,
                           const std::string &service) {
  const auto key = FindHivePath(hive, {controlSet, "Services", service});
  if (!key) {
    return false;
  }
  const auto start = HiveDwordValue(hive, *key, "Start");
  if (!start || *start != 0) {
    return false;
  }
  if (const auto startOverride = hive.FindSubkey(*key, "StartOverride")) {
    const auto override0 = HiveDwordValue(hive, *startOverride, "0");
    if (override0 && *override0 != 0) {
      return false;
    }
  }
  return true;
}

bool CriticalIdeDeviceReady(MutableHiveView &hive,
                            const std::string &controlSet) {
  for (const auto *id : {"pci#ven_8086&dev_7111",
                         "pci#ven_8086&dev_7111&cc_0101",
                         "pci#ven_8086&dev_7111&cc_01018a",
                         "pci#cc_0101",
                         "pci#cc_01018a"}) {
    const auto key = FindHivePath(
        hive, {controlSet, "Control", "CriticalDeviceDatabase", id});
    if (!key) {
      continue;
    }
    if (EqualNoCaseLocal(HiveStringValue(hive, *key, "Service"), "pciide")) {
      return true;
    }
  }
  return false;
}

BaseBootStorageInspection InspectBaseBootStorage(hv::IBlockDevice &disk) {
  BaseBootStorageInspection inspection;
  inspection.inspected = true;

  const auto partitions = ReadGptPartitionsLite(disk);
  const auto windows =
      std::find_if(partitions.begin(), partitions.end(),
                   [](const GptPartitionLite &partition) {
                     return IsWindowsBasicDataGuid(partition.typeGuid);
                   });
  if (windows == partitions.end()) {
    inspection.details = "Windows/basic-data partition not found";
    return inspection;
  }

  NtfsBootFileLocator ntfs(disk, windows->firstLba);
  if (!ntfs.Init()) {
    inspection.details = "Windows partition is not readable NTFS";
    return inspection;
  }
  const auto system = ntfs.FindPath("Windows\\System32\\config\\SYSTEM");
  if (!system) {
    inspection.details = "SYSTEM hive not found";
    return inspection;
  }
  auto bytes = ntfs.ReadFile(*system, 64u * 1024u * 1024u);
  MutableHiveView hive(bytes);
  if (bytes.empty() || !hive.IsValid()) {
    inspection.details = "SYSTEM hive is unreadable";
    return inspection;
  }

  const auto controlSet = SelectOfflineControlSet(hive);
  if (!controlSet) {
    inspection.details = "SYSTEM Select key is missing";
    return inspection;
  }
  const bool coreReady =
      ServiceBootStartReady(hive, *controlSet, "disk") &&
      ServiceBootStartReady(hive, *controlSet, "partmgr") &&
      ServiceBootStartReady(hive, *controlSet, "mountmgr");
  const bool ideServiceReady =
      ServiceBootStartReady(hive, *controlSet, "pciide") ||
      ServiceBootStartReady(hive, *controlSet, "intelide") ||
      ServiceBootStartReady(hive, *controlSet, "atapi");
  const bool criticalReady = CriticalIdeDeviceReady(hive, *controlSet);
  inspection.ready = coreReady && ideServiceReady && criticalReady;
  std::ostringstream details;
  details << "controlSet=" << *controlSet
          << ";storageCore=" << (coreReady ? "ready" : "needs-repair")
          << ";ideService=" << (ideServiceReady ? "ready" : "needs-repair")
          << ";criticalDevice="
          << (criticalReady ? "ready" : "needs-repair");
  inspection.details = details.str();
  return inspection;
}

std::optional<uint32_t> EnsureHivePath(MutableHiveView &hive,
                                       std::initializer_list<std::string> path) {
  auto current = hive.RootIndex();
  if (!current) {
    return std::nullopt;
  }
  for (const auto &component : path) {
    if (const auto existing = hive.FindSubkey(*current, component)) {
      current = existing;
      continue;
    }
    current = hive.CreateAsciiKey(*current, component);
    if (!current) {
      return std::nullopt;
    }
  }
  return current;
}

bool PatchSystemHivePiixCriticalDevices(std::vector<uint8_t> &bytes,
                                        BootOverlayPatchResult *result) {
  MutableHiveView hive(bytes);
  const auto controlSet =
      !bytes.empty() && hive.IsValid() ? SelectOfflineControlSet(hive)
                                       : std::nullopt;
  if (!controlSet) {
    if (result) {
      result->notes.push_back("SYSTEM control set not found for overlay patch");
    }
    return false;
  }
  const auto database = EnsureHivePath(
      hive, {*controlSet, "Control", "CriticalDeviceDatabase"});
  if (!database) {
    if (result) {
      result->notes.push_back("CriticalDeviceDatabase allocation failed");
    }
    return false;
  }

  bool ok = true;
  const std::wstring classGuid =
      L"{4D36E96A-E325-11CE-BFC1-08002BE10318}";
  for (const auto *id : {"pci#ven_8086&dev_7111",
                         "pci#ven_8086&dev_7111&cc_0101",
                         "pci#ven_8086&dev_7111&cc_01018a",
                         "pci#cc_0101",
                         "pci#cc_01018a"}) {
    const auto device = hive.FindSubkey(*database, id)
                            ? hive.FindSubkey(*database, id)
                            : hive.CreateAsciiKey(*database, id);
    if (!device) {
      ok = false;
      continue;
    }
    ok = hive.SetAsciiStringValue(*device, "Service", L"pciide") && ok;
    ok = hive.SetAsciiStringValue(*device, "ClassGUID", classGuid) && ok;
  }
  if (!ok && result) {
    result->notes.push_back("SYSTEM CriticalDeviceDatabase mutation failed");
  }
  return ok;
}

bool PatchOverlaySystemBootStorage(hv::IBlockDevice &disk,
                                   BootOverlayPatchResult *result) {
  const auto partitions = ReadGptPartitionsLite(disk);
  const auto windows =
      std::find_if(partitions.begin(), partitions.end(),
                   [](const GptPartitionLite &partition) {
                     return IsWindowsBasicDataGuid(partition.typeGuid);
                   });
  if (windows == partitions.end()) {
    if (result) {
      result->notes.push_back("Windows/basic-data partition not found for "
                              "SYSTEM overlay patch");
    }
    return false;
  }

  NtfsBootFileLocator ntfs(disk, windows->firstLba);
  if (!ntfs.Init()) {
    if (result) {
      result->notes.push_back("Windows NTFS is unreadable for SYSTEM overlay "
                              "patch");
    }
    return false;
  }
  const auto system = ntfs.FindPath("Windows\\System32\\config\\SYSTEM");
  if (!system) {
    if (result) {
      result->notes.push_back("SYSTEM hive not found for overlay patch");
    }
    return false;
  }
  if (result) {
    result->systemHiveFound = true;
  }

  auto bytes = ntfs.ReadFile(*system, 64u * 1024u * 1024u);
  if (!PatchSystemHivePiixCriticalDevices(bytes, result)) {
    return false;
  }
  if (!ntfs.WriteFileSameSize(*system, bytes)) {
    if (result) {
      result->notes.push_back("failed to write SYSTEM hive patch to overlay");
    }
    return false;
  }
  if (result) {
    result->bootStoragePatched = true;
  }
  return true;
}

bool ImageLooksLikeWinload(const hv::VmGuestImageInfo &image) {
  return image.valid && ContainsTextNoCase(image.pdbPath, "winload");
}

void AddImageMilestones(BootSignalSummary *signals,
                        const hv::VmGuestImageInfo &image) {
  if (ImageLooksLikeWinload(image)) {
    AddMilestone(signals, "winload image identified");
  }
}

BootSignalSummary AnalyzeBootSignals(const hv::VmRunSummary &vm) {
  BootSignalSummary signals;
  const auto &serialOutput = vm.serialOutput;
  if (ContainsTextNoCase(serialOutput, "BOOTX64.EFI")) {
    AddMilestone(&signals, "fallback bootloader opened");
  }
  if (ContainsTextNoCase(serialOutput, "bootmgfw.efi")) {
    AddMilestone(&signals, "bootmgfw loaded");
  }
  if (ContainsTextNoCase(serialOutput, "Open 'BCD' Success") ||
      ContainsTextNoCase(serialOutput, "Open 'BCD'")) {
    AddMilestone(&signals, "BCD opened");
  }
  if (ContainsTextNoCase(serialOutput, "CiPolicies")) {
    AddMilestone(&signals, "code-integrity policies opened");
  }
  if (ContainsTextNoCase(serialOutput, "winload.efi") ||
      ContainsTextNoCase(serialOutput, "winload.exe")) {
    AddMilestone(&signals, "winload opened");
  }
  AddImageMilestones(&signals, vm.fatalRipImage);
  for (const auto &image : vm.fatalStackReturnImage) {
    AddImageMilestones(&signals, image);
  }
  for (const auto &hotspot : vm.ripHotspotImages) {
    AddImageMilestones(&signals, hotspot.image);
  }
  for (const auto &image : vm.residentImages) {
    AddImageMilestones(&signals, image);
  }
  for (const auto &image : vm.observedImages) {
    AddImageMilestones(&signals, image);
  }
  if (ContainsTextNoCase(serialOutput, "ResetSystem2") ||
      ContainsTextNoCase(serialOutput, "ResetType Shutdown")) {
    AddMilestone(&signals, "firmware reset/shutdown requested");
    if (vm.pm1SleepEnable && !vm.pm1HostStopRequested &&
        vm.pm1SleepType == 0) {
      AddMilestone(&signals,
                   "ResetSystem shutdown ignored as non-host-stop S0");
    }
  }

  return signals;
}

std::string SanitizedArtifactName(std::string_view name) {
  std::string cleaned(name.begin(), name.end());
  for (char &ch : cleaned) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (!(std::isalnum(c) || ch == '.' || ch == '_' || ch == '-')) {
      ch = '_';
    }
  }
  const auto filename = std::filesystem::path(cleaned).filename().string();
  return filename.empty() ? "artifact.bin" : filename;
}

HostChannelCapture ProcessHostChannelOutput(
    const std::string &hostChannelOutput,
    const std::filesystem::path &journalPath,
    const std::filesystem::path &artifactsDir,
    std::vector<EventRecord> *events) {
  HostChannelCapture capture;
  hv::HostSerialChannel channel;
  channel.PushBytes(reinterpret_cast<const uint8_t *>(hostChannelOutput.data()),
                    hostChannelOutput.size());
  while (const auto frame = channel.PopFrame()) {
    const std::string payload(frame->payload.begin(), frame->payload.end());
    switch (frame->type) {
    case hv::HostChannelMessage::Hello:
      capture.guestAgentConnected = true;
      AddMilestone(&capture.milestones, "GuestAgent hello");
      break;
    case hv::HostChannelMessage::Heartbeat:
      capture.guestAgentConnected = true;
      ++capture.guestAgentHeartbeats;
      AddMilestone(&capture.milestones, "GuestAgent heartbeat");
      break;
    case hv::HostChannelMessage::Event: {
      auto event = ParseEventJsonLine(payload);
      AppendJournalEvent(journalPath, event, events);
      ++capture.eventsReturned;
      break;
    }
    case hv::HostChannelMessage::ArtifactChunk: {
      const auto split = payload.find('\n');
      const std::string name = split == std::string::npos
                                   ? SanitizedArtifactName("artifact.bin")
                                   : SanitizedArtifactName(
                                         std::string_view(payload).substr(0, split));
      const std::string_view bytes =
          split == std::string::npos
              ? std::string_view(payload)
              : std::string_view(payload).substr(split + 1);
      const auto outPath = artifactsDir / name;
      WriteTextFile(outPath, bytes);
      capture.artifacts.push_back(outPath);
      AppendJournalEvent(journalPath,
                         MakeSandboxEvent("artifact.received", outPath,
                                          {{"channel", "COM2"},
                                           {"bytes", std::to_string(bytes.size())}}),
                         events);
      break;
    }
    case hv::HostChannelMessage::ReportComplete:
      capture.guestAgentConnected = true;
      capture.reportComplete = true;
      AddMilestone(&capture.milestones, "GuestAgent report complete");
      break;
    default:
      break;
    }
  }
  return capture;
}

std::vector<uint8_t> BuildHealthcheckJobFrame(const std::string &runId) {
  JsonObjectBuilder job;
  job.AddString("kind", "healthcheck");
  job.AddString("runId", runId);
  job.AddBool("allowSampleExecution", false);
  job.AddString("artifactName", "agent-health.json");
  return hv::HostSerialChannel::EncodeText(hv::HostChannelMessage::JobStart,
                                           job.Finish());
}

std::filesystem::path CurrentExecutableDir() {
  std::wstring buffer(MAX_PATH, L'\0');
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  while (size == buffer.size()) {
    buffer.resize(buffer.size() * 2);
    size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  }
  buffer.resize(size);
  return std::filesystem::path(buffer).parent_path();
}

void WritePlan(const std::filesystem::path &path, const std::vector<std::string> &commands) {
  WriteTextFile(path, [&] {
    std::ostringstream script;
    for (const auto &line : commands) {
      script << line << "\n";
    }
    return script.str();
  }());
}

bool WhpDllPresent() {
  HMODULE module = LoadLibraryW(L"WinHvPlatform.dll");
  if (!module) {
    return false;
  }
  FreeLibrary(module);
  return true;
}

constexpr GUID kMicrosoftVirtualStorageVendor = {
    0xEC984AEC,
    0xA0F9,
    0x47E9,
    {0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B},
};

std::string FormatWin32Error(DWORD error) {
  char buffer[32]{};
  _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x%08lX", error);
  return buffer;
}

VIRTUAL_STORAGE_TYPE StorageTypeForVirtualDisk(
    const std::filesystem::path &path) {
  VIRTUAL_STORAGE_TYPE storage{};
  const auto ext = ToLowerAscii(path.extension().string());
  storage.DeviceId = ext == ".vhd" ? VIRTUAL_STORAGE_TYPE_DEVICE_VHD
                                   : VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;
  return storage;
}

bool IsAllZero(const uint8_t *data, size_t bytes) {
  return std::all_of(data, data + bytes, [](uint8_t b) { return b == 0; });
}

bool SetFilePointerTo(HANDLE handle, uint64_t offset) {
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(offset);
  return SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN) != FALSE;
}

uint64_t QueryVirtualDiskSize(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_SIZE;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    throw std::runtime_error("GetVirtualDiskInformation(size) failed with " +
                             FormatWin32Error(error));
  }
  return info.Size.VirtualSize;
}

bool CreateDifferencingVhdx(const std::filesystem::path &parent,
                            const std::filesystem::path &overlay,
                            std::string *error) {
  EnsureDirectory(overlay.parent_path());
  std::error_code ec;
  std::filesystem::remove(overlay, ec);

  VIRTUAL_STORAGE_TYPE storage{};
  storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;

  CREATE_VIRTUAL_DISK_PARAMETERS params{};
  params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
  CoCreateGuid(&params.Version1.UniqueId);
  params.Version1.MaximumSize = 0;
  params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
  params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
  const auto parentAbsolute = std::filesystem::absolute(parent);
  params.Version1.ParentPath = parentAbsolute.c_str();

  HANDLE handle = INVALID_HANDLE_VALUE;
  const DWORD createError =
      CreateVirtualDisk(&storage, overlay.c_str(), VIRTUAL_DISK_ACCESS_CREATE,
                        nullptr, CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &params,
                        nullptr, &handle);
  if (handle != INVALID_HANDLE_VALUE) {
    CloseHandle(handle);
  }
  if (createError != ERROR_SUCCESS) {
    if (error) {
      *error = "CreateVirtualDisk differencing overlay failed with " +
               FormatWin32Error(createError);
    }
    return false;
  }
  return true;
}

bool CreateRawCowOverlay(const std::filesystem::path &overlay,
                         std::string *error) {
  EnsureDirectory(overlay.parent_path());
  std::error_code ec;
  std::filesystem::remove(overlay, ec);
  try {
    static constexpr char kHeader[] = {'A', 'M', 'C', 'O', 'W', '1', '\r', '\n'};
    std::ofstream out(overlay, std::ios::binary | std::ios::trunc);
    if (!out) {
      if (error) *error = "Unable to create raw COW overlay.";
      return false;
    }
    out.write(kHeader, sizeof(kHeader));
    return out.good();
  } catch (const std::exception &ex) {
    if (error) *error = ex.what();
    return false;
  }
}

std::filesystem::path FindFirmwareBlob() {
  // ANTIMAL_FIRMWARE_NAME lets us point the orchestrator at OVMF-debug.fd (or
  // any other blob in firmware/) without rebuilding. Honors the same search
  // locations as the default path. Empty or unset env var keeps the
  // production default of OVMF.fd.
  std::string firmwareName = "OVMF.fd";
  {
    char buf[260]{};
    size_t needed = 0;
    if (getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_FIRMWARE_NAME") == 0 &&
        needed > 1 && buf[0] != '\0') {
      firmwareName.assign(buf);
    }
  }
  const auto exeDir = CurrentExecutableDir();
  const std::vector<std::filesystem::path> candidates = {
      exeDir / "firmware" / firmwareName,
      exeDir.parent_path().parent_path().parent_path() / "firmware" /
          firmwareName,
      std::filesystem::current_path() / "firmware" / firmwareName,
  };
  for (const auto &candidate : candidates) {
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec)) {
      return candidate;
    }
  }
  return {};
}

std::filesystem::path GuestAgentPath() {
  return CurrentExecutableDir() / "AntiMal.GuestAgent.exe";
}

EventRecord MakeSandboxEvent(const std::string &action,
                             const std::filesystem::path &target,
                             std::map<std::string, std::string> details = {}) {
  EventRecord event;
  event.timestampUtc = UtcNowIso8601();
  event.source = "host-orchestrator";
  event.category = "sandbox";
  event.action = action;
  event.target = PathToUtf8(target);
  event.details = std::move(details);
  return event;
}

void AppendJournalEvent(const std::filesystem::path &journalPath,
                        const EventRecord &event,
                        std::vector<EventRecord> *events) {
  if (events) {
    events->push_back(event);
  }
  try {
    EventJournalWriter writer(journalPath);
    writer.Append(event);
  } catch (...) {
    // The final report still carries the event vector; journal failures should
    // not make staging run host-side code.
  }
}

void WriteErrorReport(const std::filesystem::path &reportPath,
                      const std::string &runId,
                      const std::filesystem::path &samplePath,
                      const std::vector<std::string> &errors,
                      const std::vector<EventRecord> &events = {},
                      const DynamicRunSummary &dynamicSummary = {},
                      const std::vector<std::filesystem::path> &artifacts = {}) {
  AnalysisReport report;
  report.runId = runId;
  report.samplePath = samplePath;
  report.scannerVerdict = ScanFile(samplePath);
  report.sandboxVerdict = Verdict::Error;
  report.dynamicSummary = dynamicSummary;
  report.events = events;
  report.artifacts = artifacts;
  report.errors = errors;
  WriteTextFile(reportPath, ToJson(report));
  WriteReportHtml(reportPath.parent_path() / "report.html", report);
}

void WriteStagedReport(const std::filesystem::path &reportPath,
                       const std::string &runId,
                       const std::filesystem::path &samplePath,
                       const std::vector<EventRecord> &events,
                       const DynamicRunSummary &dynamicSummary = {},
                       const std::vector<std::filesystem::path> &artifacts = {}) {
  AnalysisReport report;
  report.runId = runId;
  report.samplePath = samplePath;
  report.scannerVerdict = ScanFile(samplePath);
  report.sandboxVerdict = Verdict::Error;
  report.dynamicSummary = dynamicSummary;
  report.events = events;
  report.artifacts = artifacts;
  report.errors.push_back(
      "Dynamic execution not started; this run is staged for the in-house VM path.");
  WriteTextFile(reportPath, ToJson(report));
  WriteReportHtml(reportPath.parent_path() / "report.html", report);
}

hv::VmNetworkMode ToHvNetworkMode(NetworkMode mode) {
  switch (mode) {
  case NetworkMode::Disabled:
    return hv::VmNetworkMode::Disabled;
  case NetworkMode::HostOnly:
    return hv::VmNetworkMode::HostOnly;
  case NetworkMode::Nat:
    return hv::VmNetworkMode::Nat;
  }
  return hv::VmNetworkMode::Disabled;
}

DynamicRunSummary ToDynamicSummary(const hv::VmRunSummary &vm,
                                   NetworkMode networkMode,
                                   const std::filesystem::path &serialLogPath,
                                   const std::filesystem::path &summaryPath) {
  DynamicRunSummary summary;
  summary.started = vm.started;
  summary.completed = vm.completed;
  summary.timedOut = vm.timedOut;
  summary.crashed = vm.crashed || vm.fatal;
  summary.sampleExecuted = false;
  summary.firmwareIdle = vm.idleLoop && !summary.timedOut && !summary.crashed;
  summary.guestAgentConnected = false;
  summary.networkMode = networkMode;
  summary.framesCaptured = vm.framesCaptured;
  summary.eventsCaptured = vm.eventsCaptured;
  summary.artifactsCaptured = vm.artifactsCaptured;
  summary.vcpuExits = static_cast<uint32_t>(std::max(0, vm.steps));
  summary.hltCount = static_cast<uint32_t>(std::max(0, vm.totalHlts));
  summary.ideCommandsIssued = vm.ideCommandsIssued;
  summary.ideIdentifyCommands = vm.ideIdentifyCommands;
  summary.ideReadCommands = vm.ideReadCommands;
  summary.ideWriteCommands = vm.ideWriteCommands;
  summary.ideAbortedCommands = vm.ideAbortedCommands;
  summary.ideSectorsRead = vm.ideSectorsRead;
  summary.ideSectorsWritten = vm.ideSectorsWritten;
  summary.ideSawRead = vm.ideSawRead;
  summary.ideSawWrite = vm.ideSawWrite;
  summary.ideMinReadLba = vm.ideMinReadLba;
  summary.ideMaxReadEndLba = vm.ideMaxReadEndLba;
  summary.ideMinWriteLba = vm.ideMinWriteLba;
  summary.ideMaxWriteEndLba = vm.ideMaxWriteEndLba;
  summary.unhandledIo = static_cast<uint32_t>(std::max(0, vm.unhandledIo));
  summary.unhandledMmio = static_cast<uint32_t>(std::max(0, vm.unhandledMmio));
  summary.watchdogCancellations =
      static_cast<uint32_t>(std::max(0, vm.watchdogCancellations));
  summary.ideInterruptsRequested =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsRequested));
  summary.ideInterruptsInjected =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsInjected));
  summary.ideInterruptsFailed =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsFailed));
  summary.ideInterruptsPending =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsPending));
  summary.ideInterruptsIoApic =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsIoApic));
  summary.ideInterruptsPicFallback =
      static_cast<uint32_t>(std::max(0, vm.ideInterruptsPicFallback));
  summary.pitInterruptsPending =
      static_cast<uint32_t>(std::max(0, vm.pitInterruptsPending));
  summary.rtcInterruptsPending =
      static_cast<uint32_t>(std::max(0, vm.rtcInterruptsPending));
  summary.irqIoApicDeliveries =
      static_cast<uint32_t>(std::max(0, vm.irqIoApicDeliveries));
  summary.irqPicFallbackDeliveries =
      static_cast<uint32_t>(std::max(0, vm.irqPicFallbackDeliveries));
  summary.irqDeliveryFailures =
      static_cast<uint32_t>(std::max(0, vm.irqDeliveryFailures));
  summary.masterPicVectorBase = vm.masterPicVectorBase;
  summary.slavePicVectorBase = vm.slavePicVectorBase;
  summary.masterPicMask = vm.masterPicMask;
  summary.slavePicMask = vm.slavePicMask;
  summary.interruptDiagnostics = vm.legacyIrqDiagnostics;
  summary.pm1SleepEnable = vm.pm1SleepEnable;
  summary.pm1HostStopRequested = vm.pm1HostStopRequested;
  summary.pm1SleepType = vm.pm1SleepType;
  summary.pm1ControlValue = vm.pm1ControlValue;
  summary.pm1SleepRequests = vm.pm1SleepRequests;
  summary.serialLogPath = serialLogPath;
  summary.vmSummaryPath = summaryPath;
  if (summary.timedOut) {
    summary.status = "timed out";
  } else if (summary.crashed) {
    summary.status = "boot failed";
  } else if (summary.firmwareIdle) {
    summary.status = "firmware idle before guest";
  } else {
    summary.status = "boot attempted";
  }
  return summary;
}

std::map<uint64_t, std::string>
ParseUefiImageLoadNames(const std::string &serialOutput) {
  std::map<uint64_t, std::string> names;
  std::istringstream lines(serialOutput);
  std::string line;
  while (std::getline(lines, line)) {
    if (line.find("Loading driver at ") == std::string::npos &&
        line.find("Loading PEIM at ") == std::string::npos) {
      continue;
    }
    const auto addressStart = line.find("0x");
    const auto addressEnd =
        addressStart == std::string::npos
            ? std::string::npos
            : line.find_first_not_of("0123456789ABCDEFabcdef",
                                     addressStart + 2);
    const auto nameStart = line.find_last_of(" \t");
    if (addressStart == std::string::npos ||
        addressEnd == std::string::npos ||
        nameStart == std::string::npos ||
        nameStart + 1 >= line.size()) {
      continue;
    }
    try {
      const auto base = std::stoull(
          line.substr(addressStart + 2, addressEnd - addressStart - 2),
          nullptr, 16);
      names[base] = line.substr(nameStart + 1);
    } catch (...) {
      // Serial diagnostics are best-effort. Ignore malformed firmware lines.
    }
  }
  return names;
}

std::string FormatVmDiagnostics(const hv::VmRunSummary &vm) {
  auto topEntries = [](const auto &items, size_t limit) {
    using ContainerT = std::decay_t<decltype(items)>;
    using K = typename ContainerT::key_type;
    using V = typename ContainerT::mapped_type;
    std::vector<std::pair<K, V>> entries(items.begin(), items.end());
    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });
    if (entries.size() > limit) {
      entries.resize(limit);
    }
    return entries;
  };
  auto writeBytes = [](std::ostringstream &out, const char *name,
                       const uint8_t *bytes, size_t count) {
    out << name << ":";
    for (size_t i = 0; i < count; ++i) {
      char hex[8]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, " %02X", bytes[i]);
      out << hex;
    }
    out << "\n";
  };
  const auto uefiImageLoadNames = ParseUefiImageLoadNames(vm.serialOutput);
  auto writeImage = [&uefiImageLoadNames](std::ostringstream &out,
                                          const char *prefix,
                                          const hv::VmGuestImageInfo &image) {
    if (!image.valid) {
      return;
    }
    out << prefix << "ImageBase: 0x" << std::hex << std::uppercase
        << image.base << std::dec << "\n";
    out << prefix << "ImageSize: 0x" << std::hex << std::uppercase
        << image.sizeOfImage << std::dec << "\n";
    out << prefix << "ImageEntryRva: 0x" << std::hex << std::uppercase
        << image.entryPointRva << std::dec << "\n";
    out << prefix << "ImageMachine: 0x" << std::hex << std::uppercase
        << image.machine << std::dec << "\n";
    out << prefix << "ImageSubsystem: 0x" << std::hex << std::uppercase
        << image.subsystem << std::dec << "\n";
    out << prefix << "ImageTimestamp: 0x" << std::hex << std::uppercase
        << image.timeDateStamp << std::dec << "\n";
    if (!image.pdbPath.empty()) {
      out << prefix << "ImagePdb: " << image.pdbPath << "\n";
    }
    if (const auto loaded = uefiImageLoadNames.find(image.base);
        loaded != uefiImageLoadNames.end()) {
      out << prefix << "ImageLoadName: " << loaded->second << "\n";
    }
  };

  std::ostringstream out;
  out << "AntiMal in-house VM diagnostics\n";
  out << "started: " << (vm.started ? "true" : "false") << "\n";
  out << "completed: " << (vm.completed ? "true" : "false") << "\n";
  out << "timedOut: " << (vm.timedOut ? "true" : "false") << "\n";
  out << "fatal: " << (vm.fatal ? "true" : "false") << "\n";
  out << "hostStopRequested: " << (vm.hostStopRequested ? "true" : "false") << "\n";
  out << "guestShutdown: " << (vm.guestShutdown ? "true" : "false") << "\n";
  out << "pm1SleepRequests: " << vm.pm1SleepRequests << "\n";
  out << "pm1ControlValue: 0x" << std::hex << std::uppercase
      << vm.pm1ControlValue << std::dec << "\n";
  out << "pm1SleepEnable: " << (vm.pm1SleepEnable ? "true" : "false") << "\n";
  out << "pm1SleepType: S" << static_cast<int>(vm.pm1SleepType) << "\n";
  out << "pm1HostStopRequested: "
      << (vm.pm1HostStopRequested ? "true" : "false") << "\n";
  if (vm.guestShutdown) {
    out << "guestShutdownSleepType: S"
        << static_cast<int>(vm.guestShutdownSleepType) << "\n";
  }
  const bool hasStopState =
      vm.fatal || vm.timedOut || vm.idleLoop || vm.halted || vm.fatalRip != 0;
  if (hasStopState) {
    if (vm.fatal) {
      out << "fatalReason: " << static_cast<int>(vm.fatalReason) << "\n";
    }
    out << "fatalRip: 0x" << std::hex << std::uppercase << vm.fatalRip
        << std::dec << "\n";
    out << "fatalCsSelector: 0x" << std::hex << std::uppercase
        << vm.fatalCsSelector << std::dec << "\n";
    if (vm.fatalRipBytesValid) {
      writeBytes(out, "fatalRipBytes", vm.fatalRipBytes,
                 sizeof(vm.fatalRipBytes));
    }
    if (vm.fatalRipWindowValid) {
      out << "fatalRipWindowBase: 0x" << std::hex << std::uppercase
          << vm.fatalRipWindowBase << std::dec << "\n";
      writeBytes(out, "fatalRipWindow", vm.fatalRipWindow,
                 sizeof(vm.fatalRipWindow));
    }
    writeImage(out, "fatalRip", vm.fatalRipImage);
    out << "fatalRax: 0x" << std::hex << std::uppercase << vm.fatalRax
        << std::dec << "\n";
    out << "fatalRbx: 0x" << std::hex << std::uppercase << vm.fatalRbx
        << std::dec << "\n";
    out << "fatalRcx: 0x" << std::hex << std::uppercase << vm.fatalRcx
        << std::dec << "\n";
    out << "fatalRdx: 0x" << std::hex << std::uppercase << vm.fatalRdx
        << std::dec << "\n";
    out << "fatalRsi: 0x" << std::hex << std::uppercase << vm.fatalRsi
        << std::dec << "\n";
    out << "fatalRdi: 0x" << std::hex << std::uppercase << vm.fatalRdi
        << std::dec << "\n";
    out << "fatalRbp: 0x" << std::hex << std::uppercase << vm.fatalRbp
        << std::dec << "\n";
    out << "fatalRsp: 0x" << std::hex << std::uppercase << vm.fatalRsp
        << std::dec << "\n";
    out << "fatalR8: 0x" << std::hex << std::uppercase << vm.fatalR8
        << std::dec << "\n";
    out << "fatalR9: 0x" << std::hex << std::uppercase << vm.fatalR9
        << std::dec << "\n";
    out << "fatalR10: 0x" << std::hex << std::uppercase << vm.fatalR10
        << std::dec << "\n";
    out << "fatalR11: 0x" << std::hex << std::uppercase << vm.fatalR11
        << std::dec << "\n";
    out << "fatalR12: 0x" << std::hex << std::uppercase << vm.fatalR12
        << std::dec << "\n";
    out << "fatalR13: 0x" << std::hex << std::uppercase << vm.fatalR13
        << std::dec << "\n";
    out << "fatalR14: 0x" << std::hex << std::uppercase << vm.fatalR14
        << std::dec << "\n";
    out << "fatalR15: 0x" << std::hex << std::uppercase << vm.fatalR15
        << std::dec << "\n";
    if (vm.fatalRdxBytesValid) {
      writeBytes(out, "fatalRdxBytes", vm.fatalRdxBytes,
                 sizeof(vm.fatalRdxBytes));
    }
    if (vm.fatalRsiBytesValid) {
      writeBytes(out, "fatalRsiBytes", vm.fatalRsiBytes,
                 sizeof(vm.fatalRsiBytes));
    }
    if (vm.fatalRdiBytesValid) {
      writeBytes(out, "fatalRdiBytes", vm.fatalRdiBytes,
                 sizeof(vm.fatalRdiBytes));
    }
    if (vm.fatalRspBytesValid) {
      writeBytes(out, "fatalRspBytes", vm.fatalRspBytes,
                 sizeof(vm.fatalRspBytes));
    }
    for (size_t i = 0; i < 4; ++i) {
      if (vm.fatalStackReturn[i] == 0) {
        continue;
      }
      out << "fatalStackReturn" << i << ": 0x" << std::hex
          << std::uppercase << vm.fatalStackReturn[i] << std::dec << "\n";
      if (vm.fatalStackReturnBytesValid[i]) {
        out << "fatalStackReturn" << i << "WindowBase: 0x" << std::hex
            << std::uppercase << vm.fatalStackReturnWindowBase[i] << std::dec
            << "\n";
        std::string name = "fatalStackReturn" + std::to_string(i) + "Bytes";
        writeBytes(out, name.c_str(), vm.fatalStackReturnBytes[i],
                   sizeof(vm.fatalStackReturnBytes[i]));
      }
      std::string prefix = "fatalStackReturn" + std::to_string(i);
      writeImage(out, prefix.c_str(), vm.fatalStackReturnImage[i]);
    }
  }
  out << "idleLoop: " << (vm.idleLoop ? "true" : "false") << "\n";
  out << "steps: " << vm.steps << "\n";
  out << "processorCount: " << vm.processorCount << "\n";
  out << "hltCount: " << vm.totalHlts << "\n";
  out << "apVcpuExits: " << vm.apVcpuExits << "\n";
  out << "apHltExits: " << vm.apHltExits << "\n";
  out << "apCpuidExits: " << vm.apCpuidExits << "\n";
  out << "apUnhandledExits: " << vm.apUnhandledExits << "\n";
  for (const auto &ap : vm.apStates) {
    out << "ap" << ap.index << "Rip: 0x" << std::hex << std::uppercase
        << ap.rip << std::dec << "\n";
    out << "ap" << ap.index << "CsSelector: 0x" << std::hex
        << std::uppercase << ap.csSelector << std::dec << "\n";
    if (ap.ripBytesValid) {
      std::string name = "ap" + std::to_string(ap.index) + "RipBytes";
      writeBytes(out, name.c_str(), ap.ripBytes, sizeof(ap.ripBytes));
    }
  }
  out << "watchdogCancellations: " << vm.watchdogCancellations << "\n";
  out << "timerInterruptsRequested: " << vm.timerInterruptsRequested << "\n";
  out << "timerInterruptsInjected: " << vm.timerInterruptsInjected << "\n";
  out << "keyboardScancodesInjected: " << vm.keyboardScancodesInjected << "\n";
  out << "ideInterruptsRequested: " << vm.ideInterruptsRequested << "\n";
  out << "ideInterruptsInjected: " << vm.ideInterruptsInjected << "\n";
  out << "ideInterruptsFailed: " << vm.ideInterruptsFailed << "\n";
  out << "ideInterruptsPending: " << vm.ideInterruptsPending << "\n";
  out << "ideInterruptsIoApic: " << vm.ideInterruptsIoApic << "\n";
  out << "ideInterruptsPicFallback: " << vm.ideInterruptsPicFallback << "\n";
  out << "ideCommandsIssued: " << vm.ideCommandsIssued << "\n";
  out << "ideIdentifyCommands: " << vm.ideIdentifyCommands << "\n";
  out << "ideReadCommands: " << vm.ideReadCommands << "\n";
  out << "ideWriteCommands: " << vm.ideWriteCommands << "\n";
  out << "ideAbortedCommands: " << vm.ideAbortedCommands << "\n";
  out << "ideSectorsRead: " << vm.ideSectorsRead << "\n";
  out << "ideSectorsWritten: " << vm.ideSectorsWritten << "\n";
  if (vm.ideSawRead) {
    out << "ideReadLbaRange: " << vm.ideMinReadLba << "-"
        << vm.ideMaxReadEndLba << "\n";
  }
  if (vm.ideSawWrite) {
    out << "ideWriteLbaRange: " << vm.ideMinWriteLba << "-"
        << vm.ideMaxWriteEndLba << "\n";
  }
  out << "unhandledIo: " << vm.unhandledIo << "\n";
  out << "unhandledMmio: " << vm.unhandledMmio << "\n";
  out << "unhandledOther: " << vm.unhandledOther << "\n";
  if (vm.lastExceptionType != 0 || vm.lastExceptionErrorCode != 0 ||
      vm.lastExceptionParameter != 0) {
    out << "lastExceptionType: " << static_cast<int>(vm.lastExceptionType)
        << "\n";
    out << "lastExceptionErrorCode: 0x" << std::hex << std::uppercase
        << vm.lastExceptionErrorCode << std::dec << "\n";
    out << "lastExceptionParameter: 0x" << std::hex << std::uppercase
        << vm.lastExceptionParameter << std::dec << "\n";
  }
  if (vm.lastUnhandledMmioGpa != 0 || vm.lastUnhandledMmioGva != 0) {
    out << "lastUnhandledMmioGpa: 0x" << std::hex << std::uppercase
        << vm.lastUnhandledMmioGpa << std::dec << "\n";
    out << "lastUnhandledMmioGva: 0x" << std::hex << std::uppercase
        << vm.lastUnhandledMmioGva << std::dec << "\n";
    out << "lastUnhandledMmioAccess: " << vm.lastUnhandledMmioAccess << "\n";
    out << "lastUnhandledMmioInstructionLength: "
        << static_cast<int>(vm.lastUnhandledMmioInstructionLength) << "\n";
  }
  out << "mmioReads: " << vm.mmioReads << "\n";
  out << "mmioWrites: " << vm.mmioWrites << "\n";
  out << "ioApicRaises: " << vm.ioApicRaises << "\n";
  out << "ioApicDeliveries: " << vm.ioApicDeliveries << "\n";
  out << "ioApicMaskedDrops: " << vm.ioApicMaskedDrops << "\n";
  out << "irqIoApicDeliveries: " << vm.irqIoApicDeliveries << "\n";
  out << "irqPicFallbackDeliveries: " << vm.irqPicFallbackDeliveries << "\n";
  out << "irqDeliveryFailures: " << vm.irqDeliveryFailures << "\n";
  out << "masterPicVectorBase: 0x" << std::hex << std::uppercase
      << static_cast<int>(vm.masterPicVectorBase) << std::dec << "\n";
  out << "slavePicVectorBase: 0x" << std::hex << std::uppercase
      << static_cast<int>(vm.slavePicVectorBase) << std::dec << "\n";
  out << "masterPicMask: 0x" << std::hex << std::uppercase
      << static_cast<int>(vm.masterPicMask) << std::dec << "\n";
  out << "slavePicMask: 0x" << std::hex << std::uppercase
      << static_cast<int>(vm.slavePicMask) << std::dec << "\n";
  out << "hpetReads: " << vm.hpetReads << "\n";
  out << "hpetWrites: " << vm.hpetWrites << "\n";
  out << "pitInterruptsPending: " << vm.pitInterruptsPending << "\n";
  out << "pitInterruptsFailed: " << vm.pitInterruptsFailed << "\n";
  out << "pitInterruptsIoApic: " << vm.pitInterruptsIoApic << "\n";
  out << "pitInterruptsPicFallback: " << vm.pitInterruptsPicFallback << "\n";
  out << "rtcInterruptsPending: " << vm.rtcInterruptsPending << "\n";
  out << "rtcInterruptsFailed: " << vm.rtcInterruptsFailed << "\n";
  out << "rtcInterruptsIoApic: " << vm.rtcInterruptsIoApic << "\n";
  out << "rtcInterruptsPicFallback: " << vm.rtcInterruptsPicFallback << "\n";
  out << "pitIrqsDelivered: " << vm.pitIrqsDelivered << "\n";
  out << "rtcIrqsDelivered: " << vm.rtcIrqsDelivered << "\n";
  out << "fwCfgFileDirBytesRead: " << vm.fwCfgFileDirBytesRead << "\n";
  out << "fwCfgE820BytesRead: " << vm.fwCfgE820BytesRead << "\n";
  out << "fwCfgAcpiTableBytesRead: " << vm.fwCfgAcpiTableBytesRead << "\n";
  out << "fwCfgTableLoaderBytesRead: " << vm.fwCfgTableLoaderBytesRead << "\n";
  out << "fwCfgRsdpBytesRead: " << vm.fwCfgRsdpBytesRead << "\n";
  out << "pageFaultAssists: " << vm.pageFaultAssists << "\n";
  out << "hostChannelBytes: " << vm.hostChannelOutput.size() << "\n";
  if (vm.pageFaultAssists != 0) {
    out << "lastPageFaultAssistGva: 0x" << std::hex << std::uppercase
        << vm.lastPageFaultAssistGva << std::dec << "\n";
    out << "lastPageFaultAssistGpa: 0x" << std::hex << std::uppercase
        << vm.lastPageFaultAssistGpa << std::dec << "\n";
  }
  if (!vm.legacyIrqDiagnostics.empty()) {
    out << "\nLegacy IRQ diagnostics:\n";
    for (const auto &line : vm.legacyIrqDiagnostics) {
      out << "  " << line << "\n";
    }
  }
  out << "\nTop IO ports:\n";
  for (const auto &[port, count] : topEntries(vm.ioPortHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%04X", port);
    out << "  " << hex << ": " << count << "\n";
  }
  out << "\nIDE commands:\n";
  for (const auto &[command, count] : topEntries(vm.ideCommandHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%02X", command);
    out << "  " << hex << ": " << count << "\n";
  }
  if (!vm.ideRecentAccesses.empty()) {
    out << "\nIDE access trace (oldest to newest, captured "
        << vm.ideRecentAccesses.size()
        << " record(s), capped at 4096):\n";
    for (size_t i = 0; i < vm.ideRecentAccesses.size(); ++i) {
      const auto &access = vm.ideRecentAccesses[i];
      char commandHex[16]{};
      _snprintf_s(commandHex, sizeof(commandHex), _TRUNCATE, "0x%02X",
                  static_cast<int>(access.command));
      out << "  " << (access.write ? "write" : "read")
          << " cmd=" << commandHex << " lba=" << access.lba
          << " count=" << access.count << "\n";
    }
  }
  out << "\nCMOS reads:\n";
  for (const auto &[index, count] : topEntries(vm.cmosReadHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%02X", index);
    out << "  " << hex << ": " << count << "\n";
  }
  out << "\nExit reasons:\n";
  for (const auto &[reason, count] : topEntries(vm.exitHistogram, 32)) {
    out << "  " << reason << ": " << count << "\n";
  }
  out << "\nCPUID leaves:\n";
  for (const auto &[leaf, count] : topEntries(vm.cpuidLeafHistogram, 64)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%08X", leaf);
    out << "  " << hex << ": " << count << "\n";
  }
  if (!vm.ripHotspots.empty()) {
    out << "\nTop BSP RIP hotspots (16-byte bucket, hits across whole run):\n";
    for (const auto &[ripBucket, count] : topEntries(vm.ripHotspots, 32)) {
      char hex[24]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%016llX",
                  static_cast<unsigned long long>(ripBucket));
      out << "  " << hex << ": " << count << "\n";
    }
  }
  if (!vm.recentRips.empty()) {
    out << "\nBSP recent RIPs (oldest first, last "
        << vm.recentRips.size() << " exits):\n";
    for (const auto rip : vm.recentRips) {
      char hex[24]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%016llX",
                  static_cast<unsigned long long>(rip));
      out << "  " << hex << "\n";
    }
  }
  if (!vm.recentCmosAccesses.empty()) {
    out << "\nRecent CMOS / RTC accesses (oldest first, last "
        << vm.recentCmosAccesses.size() << "):\n";
    for (const auto &acc : vm.recentCmosAccesses) {
      char line[96]{};
      _snprintf_s(line, sizeof(line), _TRUNCATE,
                  "  %s port=0x%04X idx=0x%02X val=0x%02X",
                  acc.isWrite ? "WR" : "RD",
                  static_cast<unsigned int>(acc.port),
                  static_cast<unsigned int>(acc.index),
                  static_cast<unsigned int>(acc.value));
      out << line << "\n";
    }
  }
  if (!vm.ripHotspotImages.empty()) {
    out << "\nTop BSP RIP hotspot guest images:\n";
    for (size_t i = 0; i < vm.ripHotspotImages.size(); ++i) {
      const auto &hotspot = vm.ripHotspotImages[i];
      if (!hotspot.image.valid) {
        continue;
      }
      out << "hotspot" << i << "RipBucket: 0x" << std::hex
          << std::uppercase << hotspot.ripBucket << std::dec << "\n";
      out << "hotspot" << i << "Hits: " << hotspot.hits << "\n";
      const auto prefix = "hotspot" + std::to_string(i);
      writeImage(out, prefix.c_str(), hotspot.image);
    }
  }
  if (!vm.residentImages.empty()) {
    out << "\nResident low-RAM guest images:\n";
    for (size_t i = 0; i < vm.residentImages.size(); ++i) {
      if (!vm.residentImages[i].valid) {
        continue;
      }
      const auto prefix = "residentImage" + std::to_string(i);
      writeImage(out, prefix.c_str(), vm.residentImages[i]);
    }
  }
  if (!vm.observedImages.empty()) {
    out << "\nObserved low-RAM guest images during boot traffic:\n";
    for (size_t i = 0; i < vm.observedImages.size(); ++i) {
      if (!vm.observedImages[i].valid) {
        continue;
      }
      const auto prefix = "observedImage" + std::to_string(i);
      writeImage(out, prefix.c_str(), vm.observedImages[i]);
    }
  }
  return out.str();
}

} // namespace

VhdxRawConversionResult ConvertVhdxToRaw(const std::filesystem::path &vhdxPath,
                                         const std::filesystem::path &rawPath,
                                         bool force) {
  VhdxRawConversionResult result;
  result.vhdxPath = vhdxPath;
  result.rawPath = rawPath;

  std::error_code ec;
  if (!std::filesystem::exists(vhdxPath, ec)) {
    result.errors.push_back("Base VHDX does not exist: " + PathToUtf8(vhdxPath));
    return result;
  }
  if (std::filesystem::exists(rawPath, ec) && !force) {
    result.skipped = true;
    result.messages.push_back("Raw base already exists; pass --force to replace it.");
    return result;
  }

  HANDLE diskHandle = INVALID_HANDLE_VALUE;
  HANDLE physicalHandle = INVALID_HANDLE_VALUE;
  HANDLE rawHandle = INVALID_HANDLE_VALUE;
  bool attached = false;
  bool removePartialRaw = false;

  try {
    EnsureDirectory(rawPath.parent_path());
    std::filesystem::remove(rawPath, ec);

    auto storage = StorageTypeForVirtualDisk(vhdxPath);
    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    const DWORD openError = OpenVirtualDisk(
        &storage, vhdxPath.c_str(),
        VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_GET_INFO,
        OPEN_VIRTUAL_DISK_FLAG_NONE, &openParams, &diskHandle);
    if (openError != ERROR_SUCCESS) {
      throw std::runtime_error("OpenVirtualDisk failed with " +
                               FormatWin32Error(openError));
    }

    result.virtualSize = QueryVirtualDiskSize(diskHandle);

    ATTACH_VIRTUAL_DISK_PARAMETERS attachParams{};
    attachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    const DWORD attachError = AttachVirtualDisk(
        diskHandle, nullptr,
        ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY |
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
        0, &attachParams, nullptr);
    if (attachError != ERROR_SUCCESS) {
      throw std::runtime_error("AttachVirtualDisk(read-only/no-drive-letter) failed with " +
                               FormatWin32Error(attachError));
    }
    attached = true;

    ULONG pathChars = 0;
    DWORD pathError = GetVirtualDiskPhysicalPath(diskHandle, &pathChars, nullptr);
    if (pathError != ERROR_INSUFFICIENT_BUFFER || pathChars == 0) {
      throw std::runtime_error("GetVirtualDiskPhysicalPath(size) failed with " +
                               FormatWin32Error(pathError));
    }
    std::vector<wchar_t> physicalPath(pathChars + 1);
    pathError = GetVirtualDiskPhysicalPath(diskHandle, &pathChars,
                                           physicalPath.data());
    if (pathError != ERROR_SUCCESS) {
      throw std::runtime_error("GetVirtualDiskPhysicalPath failed with " +
                               FormatWin32Error(pathError));
    }

    physicalHandle =
        CreateFileW(physicalPath.data(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (physicalHandle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("CreateFile(virtual disk physical path) failed with " +
                               FormatWin32Error(GetLastError()));
    }

    rawHandle = CreateFileW(rawPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (rawHandle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("CreateFile(raw output) failed with " +
                               FormatWin32Error(GetLastError()));
    }

    DWORD ignored = 0;
    (void)DeviceIoControl(rawHandle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0,
                          &ignored, nullptr);
    if (!SetFilePointerTo(rawHandle, result.virtualSize) ||
        SetEndOfFile(rawHandle) == FALSE) {
      throw std::runtime_error("Unable to size raw output with " +
                               FormatWin32Error(GetLastError()));
    }

    constexpr DWORD kChunkBytes = 4u * 1024u * 1024u;
    std::vector<uint8_t> buffer(kChunkBytes);
    uint64_t offset = 0;
    while (offset < result.virtualSize) {
      const DWORD want = static_cast<DWORD>(
          std::min<uint64_t>(buffer.size(), result.virtualSize - offset));
      DWORD got = 0;
      if (ReadFile(physicalHandle, buffer.data(), want, &got, nullptr) == FALSE) {
        throw std::runtime_error("ReadFile(virtual disk) failed with " +
                                 FormatWin32Error(GetLastError()));
      }
      if (got == 0) {
        break;
      }
      result.bytesRead += got;
      if (!IsAllZero(buffer.data(), got)) {
        if (!SetFilePointerTo(rawHandle, offset)) {
          throw std::runtime_error("SetFilePointer(raw output) failed with " +
                                   FormatWin32Error(GetLastError()));
        }
        DWORD written = 0;
        if (WriteFile(rawHandle, buffer.data(), got, &written, nullptr) ==
                FALSE ||
            written != got) {
          throw std::runtime_error("WriteFile(raw output) failed with " +
                                   FormatWin32Error(GetLastError()));
        }
        result.bytesWritten += written;
      }
      offset += got;
    }

    FlushFileBuffers(rawHandle);
    result.converted = true;
    result.messages.push_back("Converted VHDX to sparse raw disk.");
  } catch (const std::exception &ex) {
    result.errors.push_back(ex.what());
    removePartialRaw = true;
  }

  if (rawHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(rawHandle);
  }
  if (physicalHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(physicalHandle);
  }
  if (attached) {
    DetachVirtualDisk(diskHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
  }
  if (diskHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(diskHandle);
  }
  if (removePartialRaw) {
    std::filesystem::remove(rawPath, ec);
  }
  return result;
}

InHouseOrchestrator::InHouseOrchestrator(AppConfig config) : config_(std::move(config)) {}

HyperVPreflight InHouseOrchestrator::Preflight() const {
  HyperVPreflight result;
  result.baseVhdxPresent = !config_.baseVhdxPath.empty() &&
                           std::filesystem::exists(config_.baseVhdxPath);
  if (result.baseVhdxPresent) {
    try {
      auto vhdx = hv::VhdxBlockDevice::Open(config_.baseVhdxPath);
      result.baseVhdxReadable = vhdx.SectorCount() > 0;
      if (result.baseVhdxReadable) {
        const auto bootStorage = InspectBaseBootStorage(vhdx);
        result.baseBootStorageInspected = bootStorage.inspected;
        result.baseBootStorageReady = bootStorage.ready;
        result.baseBootStorageDetails = bootStorage.details;
      }
    } catch (const std::exception &ex) {
      result.messages.push_back("Base VHDX is present but unreadable: " +
                                std::string(ex.what()));
    }
  }
  result.baseDiskFormat = ToLowerAscii(config_.baseDiskFormat.empty() ? "raw" : config_.baseDiskFormat);
  result.baseDiskPresent = !config_.baseDiskPath.empty() &&
                           std::filesystem::exists(config_.baseDiskPath);
  result.rawBaseReady = result.baseDiskFormat == "raw" && result.baseDiskPresent;
  result.vhdxConversionRequired =
      result.baseVhdxPresent && !result.baseVhdxReadable && !result.rawBaseReady;
  result.baseVhdxPath = config_.baseVhdxPath;
  result.baseDiskPath = config_.baseDiskPath;
  result.provider = SelectProvider(config_);
  result.inHouseSelected = result.provider == "inhouse";
  result.firmwarePath = FindFirmwareBlob();
  result.firmwarePresent = !result.firmwarePath.empty();
  result.guestAgentPath = GuestAgentPath();
  result.guestAgentPresent = std::filesystem::exists(result.guestAgentPath);
  result.whpDllPresent = WhpDllPresent();
  result.whpAvailable = result.whpDllPresent && hv::WhpHost::IsAvailable();
  result.storageBootReady =
      result.whpAvailable && result.firmwarePresent &&
      (result.rawBaseReady || result.baseVhdxReadable);
  result.displayReady = false;
  result.hostChannelReady = false;
  result.networkReady = config_.networkMode == NetworkMode::Disabled;
  result.dynamicExecutionEnabled = config_.dynamicExecutionEnabled;
  result.safeToExecute = false;
  result.bootCapabilityReady =
      result.inHouseSelected && result.storageBootReady && result.networkReady;

  if (result.provider == "inhouse") {
    if (!result.rawBaseReady && !result.baseVhdxReadable && !result.baseVhdxPresent) {
      result.blockers.push_back(
          "base_disk_path raw runtime disk is missing, and no readable base VHDX is available.");
    } else if (!result.rawBaseReady && !result.baseVhdxReadable) {
      result.blockers.push_back(
          "base_disk_path raw runtime disk is missing, and the configured base VHDX could not be read.");
    }
    if (result.vhdxConversionRequired) {
      result.messages.push_back(
          "Base VHDX is present, but raw conversion is required for the in-house IDE boot path.");
    } else if (!result.rawBaseReady && result.baseVhdxReadable) {
      result.messages.push_back(
          "Base VHDX will be used directly with a disposable COW overlay.");
    }
    if (result.baseBootStorageInspected && !result.baseBootStorageReady) {
      result.messages.push_back(
          "Base SYSTEM hive boot-storage contract needs repair: " +
          result.baseBootStorageDetails);
    }
    if (!result.firmwarePresent) {
      result.blockers.push_back(
          "firmware/OVMF.fd was not found for the in-house WHP backend.");
    }
    if (!result.guestAgentPresent) {
      result.messages.push_back("AntiMal.GuestAgent.exe was not found beside the host executable.");
    }
    if (!result.whpDllPresent) {
      result.blockers.push_back(
          "WinHvPlatform.dll was not found on this Windows installation.");
    } else if (!result.whpAvailable) {
      result.blockers.push_back(
          "Windows Hypervisor Platform is not available/enabled on this host.");
    }
    if (!result.dynamicExecutionEnabled) {
      result.messages.push_back(
          "dynamic_execution_enabled is false; samples will be staged but not executed.");
    }
    if (!result.networkReady) {
      result.blockers.push_back(
          "Only network_mode = \"disabled\" is ready; hostonly/nat NIC backends are not implemented.");
    }
    if (!result.displayReady) {
      result.messages.push_back("Display/framebuffer channel is not implemented; live UI uses journal/screenshot files only.");
    }
    if (!result.hostChannelReady) {
      result.messages.push_back(
          "Host/guest channel is not implemented; staged samples are not launched inside the guest.");
    }
  } else if (result.provider == "hyperv") {
    result.blockers.push_back(
        "Hyper-V VM provider support has been removed. Use vm_provider = \"inhouse\".");
  } else if (result.provider == "virtualbox") {
    result.blockers.push_back(
        "VirtualBox support has been removed. AntiMal will not launch third-party VM apps.");
  } else if (result.provider == "vmware") {
    result.blockers.push_back(
        "VMware support has been removed. AntiMal will not launch third-party VM apps.");
  } else {
    result.blockers.push_back("Unknown vm_provider: " + config_.vmProvider);
  }
  result.messages.insert(result.messages.begin(), result.blockers.begin(),
                         result.blockers.end());
  return result;
}

DetonationResult InHouseOrchestrator::PrepareAndRun(
    const std::filesystem::path &samplePath, uint32_t timeoutSec,
    NetworkMode networkMode, bool executeVmCommands,
    DetonationProgressCallback progressCallback) {
  DetonationResult result;
  result.runId = MakeRunId();
  result.runDir = config_.workspaceRoot / result.runId;
  result.jobPath = result.runDir / "job.json";
  result.journalPath = result.runDir / "events.jsonl";
  result.screenshotsDir = result.runDir / "screenshots";
  result.artifactsDir = result.runDir / "artifacts";
  result.overlayDiskPath = result.runDir / "disk" / "overlay.vhdx";
  result.reportPath = result.runDir / "report.json";
  result.dynamicSummary.networkMode = networkMode;
  result.status = "staging";

  auto fireProgress = [&](const std::string &phase, const std::string &msg) {
    if (!progressCallback) {
      return;
    }
    DetonationProgress progress{};
    progress.runId = result.runId;
    progress.runDir = result.runDir;
    progress.phase = phase;
    progress.message = msg;
    try {
      progressCallback(progress);
    } catch (...) {
      // Progress is best-effort.
    }
  };
  fireProgress("staging", "Staging sample and creating workspace");

  EnsureDirectory(result.runDir / "in");
  EnsureDirectory(result.runDir / "out");
  EnsureDirectory(result.runDir / "disk");
  EnsureDirectory(result.screenshotsDir);
  EnsureDirectory(result.artifactsDir);

  std::vector<EventRecord> events;
  std::vector<std::filesystem::path> returnedArtifacts;
  AppendJournalEvent(result.journalPath,
                     MakeSandboxEvent("run.staged", samplePath,
                                      {{"runId", result.runId},
                                       {"networkMode", ToString(networkMode)}}),
                     &events);

  const auto stagedSample = result.runDir / "in" / samplePath.filename();
  std::error_code ec;
  std::filesystem::copy_file(samplePath, stagedSample,
                             std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    result.errors.push_back("Unable to stage sample: " + ec.message());
  } else {
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("sample.staged", stagedSample),
                       &events);
  }

  const auto agentPath = GuestAgentPath();
  if (std::filesystem::exists(agentPath)) {
    std::filesystem::copy_file(agentPath, result.runDir / "in" / "AntiMal.GuestAgent.exe",
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      result.errors.push_back("Unable to stage GuestAgent: " + ec.message());
      ec.clear();
    } else {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("guest-agent.staged",
                                          result.runDir / "in" / "AntiMal.GuestAgent.exe"),
                         &events);
    }
  } else {
    result.errors.push_back("AntiMal.GuestAgent.exe was not found beside the host CLI.");
  }

  const auto baseDiskFormat = ToLowerAscii(config_.baseDiskFormat.empty() ? "raw" : config_.baseDiskFormat);
  if (baseDiskFormat == "raw" && !config_.baseDiskPath.empty() &&
      std::filesystem::exists(config_.baseDiskPath)) {
    result.overlayDiskPath = result.runDir / "disk" / "overlay.raw";
    std::string overlayError;
    if (CreateRawCowOverlay(result.overlayDiskPath, &overlayError)) {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.created", result.overlayDiskPath,
                                          {{"parent", PathToUtf8(config_.baseDiskPath)},
                                           {"format", "raw-cow"}}),
                         &events);
    } else {
      result.errors.push_back(overlayError);
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.create-failed", result.overlayDiskPath,
                                          {{"error", overlayError},
                                           {"format", "raw-cow"}}),
                         &events);
    }
  } else if (!config_.baseVhdxPath.empty() && std::filesystem::exists(config_.baseVhdxPath)) {
    result.overlayDiskPath = result.runDir / "disk" / "overlay.cow";
    std::string overlayError;
    if (CreateRawCowOverlay(result.overlayDiskPath, &overlayError)) {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.created", result.overlayDiskPath,
                                          {{"parent", PathToUtf8(config_.baseVhdxPath)},
                                           {"format", "vhdx-cow"}}),
                         &events);
    } else {
      result.errors.push_back(overlayError);
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.create-failed", result.overlayDiskPath,
                                          {{"error", overlayError},
                                           {"format", "vhdx-cow"}}),
                         &events);
    }
  }

  JobConfig job;
  job.runId = result.runId;
  job.samplePath = stagedSample;
  job.timeoutMs = timeoutSec * 1000;
  job.networkMode = networkMode;
  job.collectScreenshots = true;
  job.outputDir = result.runDir / "out";
  WriteTextFile(result.jobPath, ToJson(job));

  auto effectiveConfig = config_;
  effectiveConfig.networkMode = networkMode;
  const auto preflight = InHouseOrchestrator(effectiveConfig).Preflight();
  const std::string vmName = config_.vmNamePrefix + "-" + result.runId.substr(0, 8);
  result.commands.push_back("$ErrorActionPreference='Stop'");

  const std::filesystem::path planPath = result.runDir / "inhouse-plan.ps1";
  result.commands.push_back("# AntiMal in-house VM boot plan for " + vmName + ".");
  result.commands.push_back("# This file is documentation only. AntiMal does not execute the submitted sample on the host.");
  result.commands.push_back("# Staged sample: " + PathToUtf8(stagedSample));
  result.commands.push_back("# Journal: " + PathToUtf8(result.journalPath));
  result.commands.push_back("# Screenshots: " + PathToUtf8(result.screenshotsDir));
  result.commands.push_back("# Base disk: " + PathToUtf8(config_.baseDiskPath));
  result.commands.push_back("# Firmware: " + PathToUtf8(preflight.firmwarePath));
  result.commands.push_back("# Sample execution remains blocked until guest boot, host channel, and artifact return are proven.");

  WritePlan(planPath, result.commands);

  AppendJournalEvent(result.journalPath,
                     MakeSandboxEvent("preflight.checked", config_.baseVhdxPath,
                                     {{"baseVhdxPresent", preflight.baseVhdxPresent ? "true" : "false"},
                                      {"baseVhdxReadable", preflight.baseVhdxReadable ? "true" : "false"},
                                      {"baseDiskPresent", preflight.baseDiskPresent ? "true" : "false"},
                                      {"rawBaseReady", preflight.rawBaseReady ? "true" : "false"},
                                      {"vhdxConversionRequired", preflight.vhdxConversionRequired ? "true" : "false"},
                                      {"baseDiskFormat", preflight.baseDiskFormat},
                                      {"firmwarePresent", preflight.firmwarePresent ? "true" : "false"},
                                      {"guestAgentPresent", preflight.guestAgentPresent ? "true" : "false"},
                                      {"whpDllPresent", preflight.whpDllPresent ? "true" : "false"},
                                      {"whpAvailable", preflight.whpAvailable ? "true" : "false"},
                                      {"storageBootReady", preflight.storageBootReady ? "true" : "false"},
                                      {"baseBootStorageInspected", preflight.baseBootStorageInspected ? "true" : "false"},
                                      {"baseBootStorageReady", preflight.baseBootStorageReady ? "true" : "false"},
                                      {"baseBootStorageDetails", preflight.baseBootStorageDetails},
                                      {"bootCapabilityReady", preflight.bootCapabilityReady ? "true" : "false"},
                                      {"hostChannelReady", preflight.hostChannelReady ? "true" : "false"},
                                      {"dynamicExecutionEnabled", preflight.dynamicExecutionEnabled ? "true" : "false"},
                                      {"safeToExecute", preflight.safeToExecute ? "true" : "false"}}),
                      &events);

  result.dynamicSummary.status = "staged";
  result.dynamicSummary.sampleExecuted = false;
  result.dynamicSummary.networkMode = networkMode;

  if (!preflight.blockers.empty()) {
    for (const auto &message : preflight.blockers) {
      result.errors.push_back(message);
    }
    result.status = "blocked";
    result.dynamicSummary.status = "blocked";
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("run.blocked", result.runDir,
                                        {{"reason", "preflight"}}),
                       &events);
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    WriteErrorReport(result.reportPath, result.runId, samplePath, result.errors,
                     events, result.dynamicSummary);
    return result;
  }

  if (executeVmCommands) {
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("vm.boot.started", result.overlayDiskPath,
                                        {{"baseDisk", preflight.rawBaseReady
                                                          ? PathToUtf8(config_.baseDiskPath)
                                                          : PathToUtf8(config_.baseVhdxPath)},
                                         {"firmware", PathToUtf8(preflight.firmwarePath)}}),
                       &events);
    result.started = true;
    result.status = "booting";
    result.dynamicSummary.started = true;
    result.dynamicSummary.status = "booting";

    const auto serialLogPath = result.runDir / "serial.log";
    const auto vmSummaryPath = result.runDir / "vm-summary.json";
    const auto vmDiagnosticsPath = result.runDir / "vm-diagnostics.txt";
    try {
      hv::VmRunRequest request;
      request.networkMode = ToHvNetworkMode(networkMode);
      request.timeout = std::chrono::milliseconds(
          static_cast<int64_t>(std::max<uint32_t>(1, timeoutSec)) * 1000);
      // A Windows boot with CMOS/PM-timer polling spends millions of steps
      // per second of guest time, so the multiplier must be large enough
      // that the timeout — not the step cap — is the binding constraint.
      request.maxSteps = std::numeric_limits<int>::max();
      request.progressInterval = std::chrono::milliseconds{1500};
      {
        char buf[16]{};
        size_t needed = 0;
        if (getenv_s(&needed, buf, sizeof(buf),
                     "ANTIMAL_PROBE_PRESS_ENTER_SEC") == 0 &&
            needed > 1 && buf[0] != '\0') {
          const int seconds = std::atoi(buf);
          if (seconds >= 0 && seconds <= 600) {
            request.keyboardInjectAfter =
                std::chrono::milliseconds{static_cast<int64_t>(seconds) *
                                          1000};
            // Set-1 Enter make/break. This is a boot UI probe only; it does
            // not authorize sample execution.
            request.keyboardScancodes = {0x1C, 0x9C};
          }
        }
      }
      auto stopAfterGuestAgentProbe = std::make_shared<std::atomic_bool>(false);
      request.cancelRequested = stopAfterGuestAgentProbe;
      auto liveHostChannel = std::make_shared<hv::HostSerialChannel>();
      auto liveHeartbeatCount = std::make_shared<std::atomic<uint32_t>>(0);
      const std::string runIdCopy = result.runId;
      const std::filesystem::path runDirCopy = result.runDir;
      const std::filesystem::path screenshotsDirCopy = result.screenshotsDir;
      auto frameCounter = std::make_shared<std::atomic<uint32_t>>(0);
      auto realFrameCounter = std::make_shared<std::atomic<uint32_t>>(0);
      request.progressCallback = [progressCallback, runIdCopy, runDirCopy,
                                  screenshotsDirCopy, frameCounter,
                                  realFrameCounter, liveHostChannel,
                                  liveHeartbeatCount,
                                  stopAfterGuestAgentProbe](
                                     const hv::VmProgressSnapshot &snap) {
          DetonationProgress progress{};
          progress.runId = runIdCopy;
          progress.runDir = runDirCopy;
          progress.phase = "running";
          progress.steps = snap.steps;
          progress.totalHlts = snap.totalHlts;
          progress.ideSectorsRead = snap.ideSectorsRead;
          progress.ideSectorsWritten = snap.ideSectorsWritten;
          progress.ideCommands = snap.ideCommandsIssued;
          progress.mmioReads = snap.mmioReads;
          progress.mmioWrites = snap.mmioWrites;
          progress.ioApicDeliveries = snap.ioApicDeliveries;
          progress.elapsedMs =
              static_cast<uint64_t>(snap.elapsed.count());
          progress.newSerialBytes = snap.newSerialBytes;
          for (size_t i = 0; i < 3; ++i) {
            progress.topPorts[i].port = snap.topPorts[i].port;
            progress.topPorts[i].count = snap.topPorts[i].count;
          }
          progress.currentRip = snap.currentRip;
          progress.currentCsSelector = snap.currentCsSelector;
          progress.framebufferEnabled = snap.framebufferEnabled;
          progress.framebufferWidth = snap.framebufferWidth;
          progress.framebufferHeight = snap.framebufferHeight;
          progress.framebufferBpp = snap.framebufferBpp;
          if (!snap.newHostChannelBytes.empty()) {
            liveHostChannel->PushBytes(
                reinterpret_cast<const uint8_t *>(snap.newHostChannelBytes.data()),
                snap.newHostChannelBytes.size());
            while (const auto frame = liveHostChannel->PopFrame()) {
              if (frame->type == hv::HostChannelMessage::Heartbeat) {
                const uint32_t count =
                    liveHeartbeatCount->fetch_add(1, std::memory_order_relaxed) +
                    1;
                if (count >= 2) {
                  stopAfterGuestAgentProbe->store(true,
                                                  std::memory_order_relaxed);
                }
              } else if (frame->type == hv::HostChannelMessage::ReportComplete) {
                stopAfterGuestAgentProbe->store(true,
                                                std::memory_order_relaxed);
              }
            }
          }
          if (snap.textFramebufferActive) {
            std::string screen;
            screen.reserve(81 * 25);
            for (size_t row = 0; row < 25; ++row) {
              for (size_t col = 0; col < 80; ++col) {
                const uint16_t cell = snap.textFramebuffer[row * 80 + col];
                const auto ch = static_cast<uint8_t>(cell & 0xFFu);
                if (ch >= 32 && ch < 127) {
                  screen.push_back(static_cast<char>(ch));
                } else if (ch == 0) {
                  screen.push_back(' ');
                } else {
                  screen.push_back('?');
                }
              }
              screen.push_back('\n');
            }
            progress.vgaTextScreen = std::move(screen);
          }
          char ripHex[128] = "(unmapped)";
          if (snap.ripBytesValid) {
            std::string acc;
            for (size_t i = 0; i < sizeof(snap.ripBytes); ++i) {
              char b[4];
              _snprintf_s(b, sizeof(b), _TRUNCATE, "%02X", snap.ripBytes[i]);
              acc += b;
              if (i + 1 < sizeof(snap.ripBytes)) {
                acc += ' ';
              }
            }
            _snprintf_s(ripHex, sizeof(ripHex), _TRUNCATE, "%s", acc.c_str());
          }
          char fbDesc[48] = "fb=off";
          if (progress.framebufferEnabled) {
            _snprintf_s(fbDesc, sizeof(fbDesc), _TRUNCATE,
                        "fb=%ux%ux%u", progress.framebufferWidth,
                        progress.framebufferHeight, progress.framebufferBpp);
          }
          char buffer[896]{};
          _snprintf_s(
              buffer, sizeof(buffer), _TRUNCATE,
              "VM running %llus: %d steps, %llu sectors read, "
              "%llu written, %d HLTs, %llu IOAPIC IRQs | %s | top IO: "
              "0x%04X=%llu  0x%04X=%llu  0x%04X=%llu | RIP=%04X:%016llX "
              "| code: %s",
              static_cast<unsigned long long>(progress.elapsedMs / 1000ull),
              progress.steps,
              static_cast<unsigned long long>(progress.ideSectorsRead),
              static_cast<unsigned long long>(progress.ideSectorsWritten),
              progress.totalHlts,
              static_cast<unsigned long long>(progress.ioApicDeliveries),
              fbDesc,
              progress.topPorts[0].port,
              static_cast<unsigned long long>(progress.topPorts[0].count),
              progress.topPorts[1].port,
              static_cast<unsigned long long>(progress.topPorts[1].count),
              progress.topPorts[2].port,
              static_cast<unsigned long long>(progress.topPorts[2].count),
              progress.currentCsSelector,
              static_cast<unsigned long long>(progress.currentRip),
              ripHex);
          progress.message = buffer;

          // Compose a multi-line text panel and render it as a PNG into
          // runDir/screenshots/ so the GUI's filmstrip + latest-frame
          // captions animate live, even before the guest has a real
          // framebuffer to display.
          {
            std::ostringstream frameText;
            frameText << "AntiMal Live VM   run "
                      << runIdCopy.substr(0, 8) << "\n";
            frameText << "phase=" << progress.phase
                      << "   elapsed=" << (progress.elapsedMs / 1000ull)
                      << "s\n\n";
            frameText << "  steps  : " << progress.steps << "\n";
            frameText << "  HLTs   : " << progress.totalHlts << "\n";
            frameText << "  IDE r  : " << progress.ideSectorsRead
                      << "   IDE w: " << progress.ideSectorsWritten << "\n";
            frameText << "  IDE cmd: " << progress.ideCommands << "\n";
            frameText << "  MMIO   : " << progress.mmioReads << " r / "
                      << progress.mmioWrites << " w\n";
            frameText << "  IOAPIC : " << progress.ioApicDeliveries
                      << " delivered\n\n";
            char portLine[256];
            _snprintf_s(portLine, sizeof(portLine), _TRUNCATE,
                        "  top IO : 0x%04X=%llu  0x%04X=%llu  0x%04X=%llu",
                        progress.topPorts[0].port,
                        static_cast<unsigned long long>(progress.topPorts[0].count),
                        progress.topPorts[1].port,
                        static_cast<unsigned long long>(progress.topPorts[1].count),
                        progress.topPorts[2].port,
                        static_cast<unsigned long long>(progress.topPorts[2].count));
            frameText << portLine << "\n";
            char ripLine[256];
            _snprintf_s(ripLine, sizeof(ripLine), _TRUNCATE,
                        "  RIP    : %04X:%016llX",
                        progress.currentCsSelector,
                        static_cast<unsigned long long>(progress.currentRip));
            frameText << ripLine << "\n";
            frameText << "  code   : " << ripHex << "\n";

            const uint32_t frameIdx = frameCounter->fetch_add(1);
            char nameBuf[64];
            _snprintf_s(nameBuf, sizeof(nameBuf), _TRUNCATE,
                        "livevm-%06u.png", frameIdx);
            const auto pngPath = screenshotsDirCopy / nameBuf;
            try {
              (void)RenderTextToPng(pngPath, frameText.str(), 760, 460);
            } catch (...) {
              // Rendering must not break the VM run loop.
            }

            // If the guest has programmed the VBE framebuffer, also capture
            // the actual guest pixels as a PNG so the user can SEE the boot
            // logo / firmware menu / Windows splash. Independent file name
            // so both rolls of frames coexist in screenshots/.
            if (snap.framebufferEnabled && snap.framebufferHost &&
                snap.framebufferWidth > 0 && snap.framebufferHeight > 0 &&
                snap.framebufferBpp == 32) {
              const size_t needed =
                  static_cast<size_t>(snap.framebufferWidth) *
                  static_cast<size_t>(snap.framebufferHeight) * 4ull;
              if (needed <= snap.framebufferBytes) {
                char gpuName[64];
                _snprintf_s(gpuName, sizeof(gpuName), _TRUNCATE,
                            "guest-%06u.png", frameIdx);
                const auto gpuPath = screenshotsDirCopy / gpuName;
                try {
                  if (EncodeFramebufferPng(gpuPath, snap.framebufferHost,
                                           snap.framebufferWidth,
                                           snap.framebufferHeight,
                                           snap.framebufferBpp / 8)) {
                    realFrameCounter->fetch_add(1, std::memory_order_relaxed);
                  }
                } catch (...) {
                  // Encoding must not break the VM run loop.
                }
              }
            }
          }

          if (progressCallback) {
            try {
              progressCallback(progress);
            } catch (...) {
              // Best-effort progress reporting.
            }
          }
        };
      fireProgress("booting", "Booting VM (firmware -> guest)");
      hv::VmRunSummary vmSummary;
      std::vector<BootReadTarget> bootReadTargets;
      hv::VirtualMachineOptions vmOptions;
      vmOptions.processorCount = 2;
      // ANTIMAL_VCPU_COUNT lets us test single-CPU vs multi-CPU boot paths
      // without rebuilding. Useful when chasing AP-bringup synchronization
      // hangs in firmware MP init — drop to 1 to side-step the AP sync
      // entirely.
      {
        char buf[16]{};
        size_t needed = 0;
        if (getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_VCPU_COUNT") == 0 &&
            needed > 1 && buf[0] != '\0') {
          const int requested = std::atoi(buf);
          if (requested >= 1 && requested <= 64) {
            vmOptions.processorCount = static_cast<uint32_t>(requested);
          }
        }
      }
      if (preflight.rawBaseReady) {
        auto cow = hv::CowRawBlockDevice::Open(config_.baseDiskPath,
                                               result.overlayDiskPath);
        const auto bootPatch = ApplyEphemeralBootOverlay(cow);
        bootReadTargets = DiscoverBootReadTargets(cow);
        AppendJournalEvent(
            result.journalPath,
            MakeSandboxEvent("vm.boot-overlay.patched", result.overlayDiskPath,
                             BootOverlayPatchDetails(bootPatch)),
            &events);
        hv::VirtualMachine vm(preflight.firmwarePath, &cow, vmOptions);
        vm.QueueCom2Bytes(BuildHealthcheckJobFrame(result.runId));
        vmSummary = vm.Run(request);
      } else if (preflight.baseVhdxReadable) {
        auto base = hv::VhdxBlockDevice::Open(config_.baseVhdxPath);
        auto cow = hv::CowOverlayBlockDevice::Open(&base, result.overlayDiskPath);
        const auto bootPatch = ApplyEphemeralBootOverlay(cow);
        bootReadTargets = DiscoverBootReadTargets(cow);
        AppendJournalEvent(
            result.journalPath,
            MakeSandboxEvent("vm.boot-overlay.patched", result.overlayDiskPath,
                             BootOverlayPatchDetails(bootPatch)),
            &events);
        hv::VirtualMachine vm(preflight.firmwarePath, &cow, vmOptions);
        vm.QueueCom2Bytes(BuildHealthcheckJobFrame(result.runId));
        vmSummary = vm.Run(request);
      } else {
        throw std::runtime_error("no bootable base disk was available");
      }
      vmSummary.framesCaptured =
          realFrameCounter->load(std::memory_order_relaxed);
      const auto bootReadObservations =
          AnalyzeBootReadTargets(vmSummary, bootReadTargets);
      fireProgress("finishing", "VM run loop returned; writing diagnostics");
      WriteTextFile(serialLogPath, vmSummary.serialOutput);
      WriteTextFile(vmDiagnosticsPath,
                    FormatVmDiagnostics(vmSummary) +
                        FormatBootReadObservations(bootReadObservations));
      result.dynamicSummary =
          ToDynamicSummary(vmSummary, networkMode, serialLogPath, vmSummaryPath);
      auto bootSignals = AnalyzeBootSignals(vmSummary);
      AddBootReadMilestones(&bootSignals, bootReadObservations);
      const auto hostCapture =
          ProcessHostChannelOutput(vmSummary.hostChannelOutput, result.journalPath,
                                   result.artifactsDir, &events);
      result.dynamicSummary.bootMilestones = bootSignals.milestones;
      for (const auto &milestone : hostCapture.milestones) {
        AddMilestone(&result.dynamicSummary.bootMilestones, milestone);
      }
      result.dynamicSummary.guestAgentConnected =
          hostCapture.guestAgentConnected;
      returnedArtifacts.insert(returnedArtifacts.end(),
                               hostCapture.artifacts.begin(),
                               hostCapture.artifacts.end());
      result.dynamicSummary.artifactsCaptured =
          static_cast<uint32_t>(returnedArtifacts.size());
      if (result.dynamicSummary.guestAgentConnected &&
          !result.dynamicSummary.crashed) {
        result.dynamicSummary.status = "guest agent connected";
      }
      if (hostCapture.reportComplete && !result.dynamicSummary.crashed) {
        result.dynamicSummary.status = "guest healthcheck complete";
      }
      result.status = result.dynamicSummary.status;
      result.completed = vmSummary.completed;
      result.dynamicSummary.eventsCaptured =
          static_cast<uint32_t>(events.size());

      if (hostCapture.guestAgentConnected) {
        AppendJournalEvent(result.journalPath,
                           MakeSandboxEvent("guest-agent.connected",
                                            result.overlayDiskPath,
                                            {{"channel", "COM2"}}),
                           &events);
      }
      if (hostCapture.guestAgentHeartbeats != 0) {
        AppendJournalEvent(
            result.journalPath,
            MakeSandboxEvent("guest-agent.heartbeat", result.overlayDiskPath,
                             {{"count", std::to_string(
                                           hostCapture.guestAgentHeartbeats)}}),
            &events);
      }
      if (hostCapture.reportComplete) {
        AppendJournalEvent(result.journalPath,
                           MakeSandboxEvent("guest-agent.report-complete",
                                            result.overlayDiskPath),
                           &events);
      }

      std::map<std::string, std::string> details{
          {"status", result.dynamicSummary.status},
          {"vcpuExits", std::to_string(result.dynamicSummary.vcpuExits)},
          {"ideCommandsIssued",
           std::to_string(result.dynamicSummary.ideCommandsIssued)},
          {"ideIdentifyCommands",
           std::to_string(result.dynamicSummary.ideIdentifyCommands)},
          {"ideReadCommands",
           std::to_string(result.dynamicSummary.ideReadCommands)},
          {"ideSectorsRead",
           std::to_string(result.dynamicSummary.ideSectorsRead)},
          {"ideAbortedCommands",
           std::to_string(result.dynamicSummary.ideAbortedCommands)},
          {"ideInterruptsRequested",
           std::to_string(result.dynamicSummary.ideInterruptsRequested)},
          {"ideInterruptsInjected",
           std::to_string(result.dynamicSummary.ideInterruptsInjected)},
          {"ideInterruptsFailed",
           std::to_string(result.dynamicSummary.ideInterruptsFailed)},
          {"ideInterruptsPending",
           std::to_string(result.dynamicSummary.ideInterruptsPending)},
          {"irqIoApicDeliveries",
           std::to_string(result.dynamicSummary.irqIoApicDeliveries)},
          {"irqPicFallbackDeliveries",
           std::to_string(result.dynamicSummary.irqPicFallbackDeliveries)},
          {"irqDeliveryFailures",
           std::to_string(result.dynamicSummary.irqDeliveryFailures)},
          {"masterPicVectorBase",
           std::to_string(result.dynamicSummary.masterPicVectorBase)},
          {"slavePicVectorBase",
           std::to_string(result.dynamicSummary.slavePicVectorBase)},
          {"masterPicMask", std::to_string(result.dynamicSummary.masterPicMask)},
          {"slavePicMask", std::to_string(result.dynamicSummary.slavePicMask)},
          {"bootMilestones",
           JoinStrings(result.dynamicSummary.bootMilestones, ", ")},
          {"firmwareIdle", result.dynamicSummary.firmwareIdle ? "true" : "false"},
          {"pm1ControlValue",
           std::to_string(result.dynamicSummary.pm1ControlValue)},
          {"pm1SleepEnable",
           result.dynamicSummary.pm1SleepEnable ? "true" : "false"},
          {"pm1SleepType",
           "S" + std::to_string(result.dynamicSummary.pm1SleepType)},
          {"pm1SleepRequests",
           std::to_string(result.dynamicSummary.pm1SleepRequests)},
          {"pm1HostStopRequested",
           result.dynamicSummary.pm1HostStopRequested ? "true" : "false"},
          {"guestAgentConnected",
           result.dynamicSummary.guestAgentConnected ? "true" : "false"},
          {"artifactsCaptured",
           std::to_string(result.dynamicSummary.artifactsCaptured)},
          {"sampleExecuted", "false"}};
      if (result.dynamicSummary.ideSawRead) {
        details["ideReadLbaRange"] =
            std::to_string(result.dynamicSummary.ideMinReadLba) + "-" +
            std::to_string(result.dynamicSummary.ideMaxReadEndLba);
      }
      if (result.dynamicSummary.ideSawWrite) {
        details["ideWriteLbaRange"] =
            std::to_string(result.dynamicSummary.ideMinWriteLba) + "-" +
            std::to_string(result.dynamicSummary.ideMaxWriteEndLba);
      }
      if (!bootReadObservations.empty()) {
        details["bootFileReads"] = BootReadDetails(bootReadObservations);
      }
      if (vmSummary.timedOut) {
        details["reason"] = "timeout";
      } else if (vmSummary.fatal) {
        details["reason"] = "fatal-vcpu-exit";
      } else if (result.dynamicSummary.firmwareIdle) {
        details["reason"] = "firmware-idle-before-guest";
      }
      const bool reachedWinload =
          std::any_of(result.dynamicSummary.bootMilestones.begin(),
                      result.dynamicSummary.bootMilestones.end(),
                      [](const std::string &milestone) {
                        return milestone == "winload opened" ||
                               milestone == "winload image identified";
                      });
      details["winloadReached"] = reachedWinload ? "true" : "false";
      const bool bootReachedGuest =
          reachedWinload || result.dynamicSummary.guestAgentConnected;
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent(bootReachedGuest
                                              ? "vm.boot.completed"
                                              : "vm.boot.incomplete",
                                          result.overlayDiskPath, details),
                         &events);
    } catch (const std::exception &ex) {
      result.status = "boot failed";
      result.dynamicSummary.status = "boot failed";
      result.dynamicSummary.started = true;
      result.dynamicSummary.completed = false;
      result.dynamicSummary.crashed = true;
      result.dynamicSummary.networkMode = networkMode;
      result.dynamicSummary.serialLogPath = serialLogPath;
      result.dynamicSummary.vmSummaryPath = vmSummaryPath;
      WriteTextFile(vmDiagnosticsPath,
                    std::string("VM boot failed before diagnostics: ") +
                        ex.what() + "\n");
      result.errors.push_back(std::string("In-house VM boot failed: ") + ex.what());
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("vm.boot.failed", result.overlayDiskPath,
                                          {{"error", ex.what()}}),
                         &events);
    }

    result.errors.push_back(
        "Sample was staged but not executed; host/guest channel and safe sample execution remain disabled.");
    result.dynamicSummary.sampleExecuted = false;
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    result.dynamicSummary.artifactsCaptured =
        static_cast<uint32_t>(returnedArtifacts.size());
    WriteTextFile(vmSummaryPath, ToJson(result.dynamicSummary));
    WriteErrorReport(result.reportPath, result.runId, samplePath, result.errors,
                     events, result.dynamicSummary, returnedArtifacts);
  } else {
    result.status = "staged";
    result.dynamicSummary.status = "staged";
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    WriteStagedReport(result.reportPath, result.runId, samplePath, events,
                      result.dynamicSummary, returnedArtifacts);
  }

  return result;
}

HyperVOrchestrator::HyperVOrchestrator(AppConfig config) : config_(std::move(config)) {}

HyperVPreflight HyperVOrchestrator::Preflight() const {
  return InHouseOrchestrator(config_).Preflight();
}

DetonationResult HyperVOrchestrator::PrepareAndRun(
    const std::filesystem::path &samplePath, uint32_t timeoutSec,
    NetworkMode networkMode, bool executeVmCommands,
    DetonationProgressCallback progressCallback) {
  return InHouseOrchestrator(config_).PrepareAndRun(
      samplePath, timeoutSec, networkMode, executeVmCommands,
      std::move(progressCallback));
}

} // namespace antimal
