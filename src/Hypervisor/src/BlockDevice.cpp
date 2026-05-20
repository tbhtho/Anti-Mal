#include "antimal/hv/BlockDevice.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace antimal::hv {

namespace {

uint64_t ByteOffset(uint64_t lba) {
  return lba * IBlockDevice::kSectorSize;
}

uint64_t ByteCount(uint16_t sectors) {
  return static_cast<uint64_t>(sectors) * IBlockDevice::kSectorSize;
}

void PutU16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutU32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void PutU64(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

bool ReadExact(std::istream &stream, uint8_t *out, size_t bytes) {
  stream.read(reinterpret_cast<char *>(out),
              static_cast<std::streamsize>(bytes));
  return stream.good();
}

uint16_t ReadU16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) |
         (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadU32(const uint8_t *p) {
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(p[i]) << (i * 8);
  }
  return value;
}

uint64_t ReadU64(const uint8_t *p) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(p[i]) << (i * 8);
  }
  return value;
}

uint32_t ReadU32At(const std::vector<uint8_t> &bytes, size_t offset) {
  if (offset + 4 > bytes.size()) {
    throw std::runtime_error("VHDX metadata is truncated");
  }
  return ReadU32(bytes.data() + offset);
}

uint64_t ReadU64At(const std::vector<uint8_t> &bytes, size_t offset) {
  if (offset + 8 > bytes.size()) {
    throw std::runtime_error("VHDX metadata is truncated");
  }
  return ReadU64(bytes.data() + offset);
}

std::string ReadAscii(const uint8_t *p, size_t bytes) {
  return std::string(reinterpret_cast<const char *>(p),
                     reinterpret_cast<const char *>(p + bytes));
}

std::string GuidString(const uint8_t *p) {
  char out[37]{};
  _snprintf_s(out, sizeof(out), _TRUNCATE,
              "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              ReadU32(p), ReadU16(p + 4), ReadU16(p + 6), p[8], p[9],
              p[10], p[11], p[12], p[13], p[14], p[15]);
  return out;
}

constexpr uint8_t kCowMagic[] = {'A', 'M', 'C', 'O', 'W', '1', '\r', '\n'};
constexpr uint8_t kJobMagic[] = {'A', 'M', 'J', 'O', 'B', '1', '\r', '\n'};
constexpr size_t kCowRecordHeaderBytes = 10; // lba u64 + sector-count u16.

constexpr uint64_t kVhdxRegionTable1 = 192ull * 1024ull;
constexpr uint64_t kVhdxRegionTable2 = 256ull * 1024ull;
constexpr uint32_t kVhdxRegionTableBytes = 64u * 1024u;
constexpr uint64_t kVhdxFileOffsetMask = 0xFFFFFFFFFFF00000ull;
constexpr uint64_t kVhdxFullyPresent = 6;
constexpr uint64_t kVhdxPartiallyPresent = 7;
const char *kVhdxBatGuid = "2dc27766-f623-4200-9d64-115e9bfd4a08";
const char *kVhdxMetadataGuid = "8b7ca206-4790-4b9a-b8fe-575f050f886e";
const char *kVhdxFileParametersGuid = "caa16737-fa36-4d43-b3b6-33f0aa44e76b";
const char *kVhdxVirtualDiskSizeGuid = "2fa54224-cd1b-4876-b211-5dbed83bf4b8";
const char *kVhdxLogicalSectorGuid = "8141bf1d-a96f-4709-ba47-f233a8faab5f";

struct VhdxRegionInfo {
  uint64_t batOffset = 0;
  uint32_t batLength = 0;
  uint64_t metadataOffset = 0;
  uint32_t metadataLength = 0;
};

std::vector<uint8_t> ReadFileBytes(std::ifstream &stream, uint64_t offset,
                                   size_t bytes) {
  std::vector<uint8_t> out(bytes);
  stream.clear();
  stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  stream.read(reinterpret_cast<char *>(out.data()),
              static_cast<std::streamsize>(out.size()));
  if (!stream.good()) {
    throw std::runtime_error("VHDX read failed");
  }
  return out;
}

VhdxRegionInfo ParseVhdxRegionTable(std::ifstream &stream) {
  for (uint64_t regionOffset : {kVhdxRegionTable1, kVhdxRegionTable2}) {
    auto table = ReadFileBytes(stream, regionOffset, kVhdxRegionTableBytes);
    if (ReadAscii(table.data(), 4) != "regi") {
      continue;
    }
    const uint32_t entryCount = ReadU32(table.data() + 8);
    if (entryCount > 2047) {
      continue;
    }
    VhdxRegionInfo info;
    for (uint32_t i = 0; i < entryCount; ++i) {
      const size_t entry = 16ull + static_cast<size_t>(i) * 32ull;
      if (entry + 32 > table.size()) {
        break;
      }
      const auto id = GuidString(table.data() + entry);
      const uint64_t offset = ReadU64(table.data() + entry + 16);
      const uint32_t length = ReadU32(table.data() + entry + 24);
      if (id == kVhdxBatGuid) {
        info.batOffset = offset;
        info.batLength = length;
      } else if (id == kVhdxMetadataGuid) {
        info.metadataOffset = offset;
        info.metadataLength = length;
      }
    }
    if (info.batOffset && info.batLength && info.metadataOffset &&
        info.metadataLength) {
      return info;
    }
  }
  throw std::runtime_error("VHDX region table is missing BAT or metadata");
}

void ParseVhdxMetadata(std::ifstream &stream, const VhdxRegionInfo &regions,
                       uint64_t *virtualSize, uint32_t *blockSize,
                       uint32_t *logicalSectorSize) {
  auto metadata =
      ReadFileBytes(stream, regions.metadataOffset, regions.metadataLength);
  if (metadata.size() < 32 || ReadAscii(metadata.data(), 8) != "metadata") {
    throw std::runtime_error("VHDX metadata table is invalid");
  }
  const uint16_t entryCount = ReadU16(metadata.data() + 10);
  for (uint16_t i = 0; i < entryCount; ++i) {
    const size_t entry = 32ull + static_cast<size_t>(i) * 32ull;
    if (entry + 32 > metadata.size()) {
      break;
    }
    const auto id = GuidString(metadata.data() + entry);
    const uint32_t offset = ReadU32(metadata.data() + entry + 16);
    const uint32_t length = ReadU32(metadata.data() + entry + 20);
    if (static_cast<uint64_t>(offset) + length > metadata.size()) {
      throw std::runtime_error("VHDX metadata item is out of range");
    }
    if (id == kVhdxFileParametersGuid) {
      *blockSize = ReadU32At(metadata, offset);
    } else if (id == kVhdxVirtualDiskSizeGuid) {
      *virtualSize = ReadU64At(metadata, offset);
    } else if (id == kVhdxLogicalSectorGuid) {
      *logicalSectorSize = ReadU32At(metadata, offset);
    }
  }
  if (*virtualSize == 0 || *blockSize == 0 || *logicalSectorSize == 0) {
    throw std::runtime_error("VHDX metadata is missing required values");
  }
  if (*logicalSectorSize != IBlockDevice::kSectorSize) {
    throw std::runtime_error("VHDX logical sector size is not 512 bytes");
  }
}

} // namespace

MemoryBlockDevice::MemoryBlockDevice(uint64_t sectors)
    : bytes_(static_cast<size_t>(sectors * kSectorSize), 0) {}

uint64_t MemoryBlockDevice::SectorCount() const noexcept {
  return bytes_.size() / kSectorSize;
}

bool MemoryBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                    uint8_t *out) {
  if (!out || !RangeValid(lba, count)) {
    return false;
  }
  const auto offset = static_cast<size_t>(ByteOffset(lba));
  const auto bytes = static_cast<size_t>(ByteCount(count));
  std::copy_n(bytes_.data() + offset, bytes, out);
  return true;
}

bool MemoryBlockDevice::WriteSectors(uint64_t lba, uint16_t count,
                                     const uint8_t *data) {
  if (!data || !RangeValid(lba, count)) {
    return false;
  }
  const auto offset = static_cast<size_t>(ByteOffset(lba));
  const auto bytes = static_cast<size_t>(ByteCount(count));
  std::copy_n(data, bytes, bytes_.data() + offset);
  return true;
}

bool MemoryBlockDevice::Flush() {
  return true;
}

bool MemoryBlockDevice::RangeValid(uint64_t lba, uint16_t count) const noexcept {
  return count > 0 && lba <= SectorCount() &&
         static_cast<uint64_t>(count) <= SectorCount() - lba;
}

RawFileBlockDevice RawFileBlockDevice::Create(const std::filesystem::path &path,
                                              uint64_t sectors) {
  if (sectors == 0) {
    throw std::invalid_argument("raw block device must have at least one sector");
  }
  if (!path.parent_path().empty()) {
    std::filesystem::create_directories(path.parent_path());
  }
  {
    std::ofstream create(path, std::ios::binary | std::ios::trunc);
    if (!create) {
      throw std::runtime_error("unable to create raw block device");
    }
    create.seekp(static_cast<std::streamoff>(ByteOffset(sectors) - 1));
    const char zero = 0;
    create.write(&zero, 1);
  }
  return Open(path);
}

RawFileBlockDevice RawFileBlockDevice::Open(const std::filesystem::path &path) {
  const auto size = std::filesystem::file_size(path);
  if (size == 0 || (size % IBlockDevice::kSectorSize) != 0) {
    throw std::runtime_error("raw block device size is not sector aligned");
  }
  std::fstream stream(path, std::ios::binary | std::ios::in | std::ios::out);
  if (!stream) {
    throw std::runtime_error("unable to open raw block device");
  }
  return RawFileBlockDevice(path, size / IBlockDevice::kSectorSize,
                            std::move(stream));
}

RawFileBlockDevice::RawFileBlockDevice(std::filesystem::path path,
                                       uint64_t sectors,
                                       std::fstream stream)
    : path_(std::move(path)), sectors_(sectors), stream_(std::move(stream)) {}

RawFileBlockDevice::RawFileBlockDevice(RawFileBlockDevice &&other) noexcept
    : path_(std::move(other.path_)), sectors_(other.sectors_),
      stream_(std::move(other.stream_)) {
  other.sectors_ = 0;
}

RawFileBlockDevice &
RawFileBlockDevice::operator=(RawFileBlockDevice &&other) noexcept {
  if (this != &other) {
    stream_.close();
    path_ = std::move(other.path_);
    sectors_ = other.sectors_;
    stream_ = std::move(other.stream_);
    other.sectors_ = 0;
  }
  return *this;
}

RawFileBlockDevice::~RawFileBlockDevice() {
  if (stream_.is_open()) {
    stream_.flush();
    stream_.close();
  }
}

uint64_t RawFileBlockDevice::SectorCount() const noexcept {
  return sectors_;
}

bool RawFileBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                     uint8_t *out) {
  if (!out || !stream_ || !RangeValid(lba, count)) {
    return false;
  }
  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(ByteOffset(lba)), std::ios::beg);
  stream_.read(reinterpret_cast<char *>(out),
               static_cast<std::streamsize>(ByteCount(count)));
  return stream_.good();
}

bool RawFileBlockDevice::WriteSectors(uint64_t lba, uint16_t count,
                                      const uint8_t *data) {
  if (!data || !stream_ || !RangeValid(lba, count)) {
    return false;
  }
  stream_.clear();
  stream_.seekp(static_cast<std::streamoff>(ByteOffset(lba)), std::ios::beg);
  stream_.write(reinterpret_cast<const char *>(data),
                static_cast<std::streamsize>(ByteCount(count)));
  return stream_.good();
}

bool RawFileBlockDevice::Flush() {
  if (!stream_) {
    return false;
  }
  stream_.flush();
  return stream_.good();
}

bool RawFileBlockDevice::RangeValid(uint64_t lba, uint16_t count) const noexcept {
  return count > 0 && lba <= sectors_ &&
         static_cast<uint64_t>(count) <= sectors_ - lba;
}

ReadOnlyRawBlockDevice
ReadOnlyRawBlockDevice::Open(const std::filesystem::path &path) {
  const auto size = std::filesystem::file_size(path);
  if (size == 0 || (size % IBlockDevice::kSectorSize) != 0) {
    throw std::runtime_error("read-only raw block device size is not sector aligned");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw std::runtime_error("unable to open read-only raw block device");
  }
  return ReadOnlyRawBlockDevice(path, size / IBlockDevice::kSectorSize,
                                std::move(stream));
}

ReadOnlyRawBlockDevice::ReadOnlyRawBlockDevice(std::filesystem::path path,
                                               uint64_t sectors,
                                               std::ifstream stream)
    : path_(std::move(path)), sectors_(sectors), stream_(std::move(stream)) {}

ReadOnlyRawBlockDevice::ReadOnlyRawBlockDevice(ReadOnlyRawBlockDevice &&other) noexcept
    : path_(std::move(other.path_)), sectors_(other.sectors_),
      stream_(std::move(other.stream_)) {
  other.sectors_ = 0;
}

ReadOnlyRawBlockDevice &
ReadOnlyRawBlockDevice::operator=(ReadOnlyRawBlockDevice &&other) noexcept {
  if (this != &other) {
    stream_.close();
    path_ = std::move(other.path_);
    sectors_ = other.sectors_;
    stream_ = std::move(other.stream_);
    other.sectors_ = 0;
  }
  return *this;
}

ReadOnlyRawBlockDevice::~ReadOnlyRawBlockDevice() {
  if (stream_.is_open()) {
    stream_.close();
  }
}

uint64_t ReadOnlyRawBlockDevice::SectorCount() const noexcept {
  return sectors_;
}

bool ReadOnlyRawBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                         uint8_t *out) {
  if (!out || !stream_ || !RangeValid(lba, count)) {
    return false;
  }
  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(ByteOffset(lba)), std::ios::beg);
  stream_.read(reinterpret_cast<char *>(out),
               static_cast<std::streamsize>(ByteCount(count)));
  return stream_.good();
}

bool ReadOnlyRawBlockDevice::WriteSectors(uint64_t, uint16_t,
                                          const uint8_t *) {
  return false;
}

bool ReadOnlyRawBlockDevice::Flush() {
  return true;
}

bool ReadOnlyRawBlockDevice::RangeValid(uint64_t lba,
                                        uint16_t count) const noexcept {
  return count > 0 && lba <= sectors_ &&
         static_cast<uint64_t>(count) <= sectors_ - lba;
}

VhdxBlockDevice VhdxBlockDevice::Open(const std::filesystem::path &path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw std::runtime_error("unable to open VHDX block device");
  }
  const auto header = ReadFileBytes(stream, 0, 8);
  if (ReadAscii(header.data(), header.size()) != "vhdxfile") {
    throw std::runtime_error("VHDX file identifier is missing");
  }

  const auto regions = ParseVhdxRegionTable(stream);
  uint64_t virtualSize = 0;
  uint32_t blockSize = 0;
  uint32_t logicalSectorSize = 0;
  ParseVhdxMetadata(stream, regions, &virtualSize, &blockSize,
                    &logicalSectorSize);
  if (virtualSize % logicalSectorSize != 0 ||
      blockSize % logicalSectorSize != 0) {
    throw std::runtime_error("VHDX sizes are not sector aligned");
  }

  const uint64_t payloadBlocks =
      (virtualSize + blockSize - 1) / blockSize;
  const uint64_t chunkRatio64 =
      (static_cast<uint64_t>(1) << 23) * logicalSectorSize / blockSize;
  if (chunkRatio64 == 0 || chunkRatio64 > std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("VHDX chunk ratio is unsupported");
  }
  const uint64_t batEntriesNeeded = payloadBlocks +
      ((payloadBlocks + chunkRatio64 - 1) / chunkRatio64);
  const uint64_t batEntriesAvailable = regions.batLength / sizeof(uint64_t);
  if (batEntriesNeeded > batEntriesAvailable ||
      batEntriesNeeded > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
    throw std::runtime_error("VHDX BAT is too small");
  }

  auto batBytes =
      ReadFileBytes(stream, regions.batOffset,
                    static_cast<size_t>(batEntriesNeeded * sizeof(uint64_t)));
  std::vector<uint64_t> bat(static_cast<size_t>(batEntriesNeeded));
  for (size_t i = 0; i < bat.size(); ++i) {
    bat[i] = ReadU64(batBytes.data() + i * sizeof(uint64_t));
  }

  return VhdxBlockDevice(path, virtualSize, blockSize, logicalSectorSize,
                         static_cast<uint32_t>(chunkRatio64), std::move(bat),
                         std::move(stream));
}

VhdxBlockDevice::VhdxBlockDevice(std::filesystem::path path,
                                 uint64_t virtualSize, uint32_t blockSize,
                                 uint32_t logicalSectorSize,
                                 uint32_t chunkRatio,
                                 std::vector<uint64_t> bat,
                                 std::ifstream stream)
    : path_(std::move(path)), virtualSize_(virtualSize),
      blockSize_(blockSize), logicalSectorSize_(logicalSectorSize),
      chunkRatio_(chunkRatio), bat_(std::move(bat)),
      stream_(std::move(stream)) {}

VhdxBlockDevice::VhdxBlockDevice(VhdxBlockDevice &&other) noexcept
    : path_(std::move(other.path_)), virtualSize_(other.virtualSize_),
      blockSize_(other.blockSize_), logicalSectorSize_(other.logicalSectorSize_),
      chunkRatio_(other.chunkRatio_), bat_(std::move(other.bat_)),
      stream_(std::move(other.stream_)) {
  other.virtualSize_ = 0;
  other.blockSize_ = 0;
  other.chunkRatio_ = 0;
}

VhdxBlockDevice &
VhdxBlockDevice::operator=(VhdxBlockDevice &&other) noexcept {
  if (this != &other) {
    stream_.close();
    path_ = std::move(other.path_);
    virtualSize_ = other.virtualSize_;
    blockSize_ = other.blockSize_;
    logicalSectorSize_ = other.logicalSectorSize_;
    chunkRatio_ = other.chunkRatio_;
    bat_ = std::move(other.bat_);
    stream_ = std::move(other.stream_);
    other.virtualSize_ = 0;
    other.blockSize_ = 0;
    other.chunkRatio_ = 0;
  }
  return *this;
}

VhdxBlockDevice::~VhdxBlockDevice() {
  if (stream_.is_open()) {
    stream_.close();
  }
}

uint64_t VhdxBlockDevice::SectorCount() const noexcept {
  return virtualSize_ / logicalSectorSize_;
}

bool VhdxBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                  uint8_t *out) {
  if (!out || !RangeValid(lba, count)) {
    return false;
  }
  return ReadBytes(lba * logicalSectorSize_, out,
                   static_cast<size_t>(count) * logicalSectorSize_);
}

bool VhdxBlockDevice::WriteSectors(uint64_t, uint16_t, const uint8_t *) {
  return false;
}

bool VhdxBlockDevice::Flush() {
  return true;
}

bool VhdxBlockDevice::RangeValid(uint64_t lba, uint16_t count) const noexcept {
  return count > 0 && lba <= SectorCount() &&
         static_cast<uint64_t>(count) <= SectorCount() - lba;
}

bool VhdxBlockDevice::ReadBytes(uint64_t byteOffset, uint8_t *out,
                                size_t bytes) {
  size_t done = 0;
  while (done < bytes) {
    const uint64_t current = byteOffset + done;
    const uint64_t payloadBlock = current / blockSize_;
    const uint64_t inBlock = current % blockSize_;
    const size_t chunk = static_cast<size_t>(
        std::min<uint64_t>(bytes - done, blockSize_ - inBlock));
    const uint64_t batIndex =
        payloadBlock + (payloadBlock / chunkRatio_);
    if (batIndex >= bat_.size()) {
      return false;
    }
    const uint64_t entry = bat_[static_cast<size_t>(batIndex)];
    const uint64_t state = entry & 0x7ull;
    if (state == kVhdxFullyPresent || state == kVhdxPartiallyPresent) {
      const uint64_t fileOffset = entry & kVhdxFileOffsetMask;
      if (fileOffset == 0) {
        std::fill_n(out + done, chunk, 0);
      } else {
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(fileOffset + inBlock),
                      std::ios::beg);
        stream_.read(reinterpret_cast<char *>(out + done),
                     static_cast<std::streamsize>(chunk));
        if (!stream_.good()) {
          return false;
        }
      }
    } else {
      std::fill_n(out + done, chunk, 0);
    }
    done += chunk;
  }
  return true;
}

CowRawBlockDevice
CowRawBlockDevice::Create(const std::filesystem::path &basePath,
                          const std::filesystem::path &overlayPath) {
  if (!overlayPath.parent_path().empty()) {
    std::filesystem::create_directories(overlayPath.parent_path());
  }
  {
    std::ofstream create(overlayPath, std::ios::binary | std::ios::trunc);
    if (!create) {
      throw std::runtime_error("unable to create COW raw overlay");
    }
    create.write(reinterpret_cast<const char *>(kCowMagic), sizeof(kCowMagic));
  }
  return Open(basePath, overlayPath);
}

CowRawBlockDevice
CowRawBlockDevice::Open(const std::filesystem::path &basePath,
                        const std::filesystem::path &overlayPath) {
  auto base = ReadOnlyRawBlockDevice::Open(basePath);
  std::fstream overlay(overlayPath, std::ios::binary | std::ios::in | std::ios::out);
  if (!overlay) {
    throw std::runtime_error("unable to open COW raw overlay");
  }

  uint8_t magic[sizeof(kCowMagic)]{};
  if (!ReadExact(overlay, magic, sizeof(magic)) ||
      std::memcmp(magic, kCowMagic, sizeof(kCowMagic)) != 0) {
    throw std::runtime_error("COW raw overlay has invalid header");
  }

  std::map<uint64_t, Sector> sectors;
  for (;;) {
    uint8_t header[kCowRecordHeaderBytes]{};
    overlay.read(reinterpret_cast<char *>(header), sizeof(header));
    if (overlay.eof()) {
      break;
    }
    if (!overlay.good()) {
      throw std::runtime_error("COW raw overlay truncated in record header");
    }
    const uint64_t lba = ReadU64(header);
    const uint16_t count = ReadU16(header + 8);
    if (count == 0 || lba > base.SectorCount() ||
        static_cast<uint64_t>(count) > base.SectorCount() - lba) {
      throw std::runtime_error("COW raw overlay contains out-of-range sector record");
    }
    for (uint16_t i = 0; i < count; ++i) {
      Sector sector{};
      if (!ReadExact(overlay, sector.data(), sector.size())) {
        throw std::runtime_error("COW raw overlay truncated in sector payload");
      }
      sectors[lba + i] = sector;
    }
  }
  overlay.clear();
  overlay.seekp(0, std::ios::end);
  return CowRawBlockDevice(std::move(base), overlayPath, std::move(overlay),
                           std::move(sectors));
}

CowRawBlockDevice::CowRawBlockDevice(ReadOnlyRawBlockDevice base,
                                     std::filesystem::path overlayPath,
                                     std::fstream overlayStream,
                                     std::map<uint64_t, Sector> overlaySectors)
    : base_(std::move(base)), overlayPath_(std::move(overlayPath)),
      overlayStream_(std::move(overlayStream)),
      overlaySectors_(std::move(overlaySectors)) {}

CowRawBlockDevice::CowRawBlockDevice(CowRawBlockDevice &&other) noexcept
    : base_(std::move(other.base_)), overlayPath_(std::move(other.overlayPath_)),
      overlayStream_(std::move(other.overlayStream_)),
      overlaySectors_(std::move(other.overlaySectors_)) {}

CowRawBlockDevice &
CowRawBlockDevice::operator=(CowRawBlockDevice &&other) noexcept {
  if (this != &other) {
    overlayStream_.close();
    base_ = std::move(other.base_);
    overlayPath_ = std::move(other.overlayPath_);
    overlayStream_ = std::move(other.overlayStream_);
    overlaySectors_ = std::move(other.overlaySectors_);
  }
  return *this;
}

CowRawBlockDevice::~CowRawBlockDevice() {
  if (overlayStream_.is_open()) {
    overlayStream_.flush();
    overlayStream_.close();
  }
}

uint64_t CowRawBlockDevice::SectorCount() const noexcept {
  return base_.SectorCount();
}

bool CowRawBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                    uint8_t *out) {
  if (!out || !RangeValid(lba, count)) {
    return false;
  }
  for (uint16_t i = 0; i < count; ++i) {
    const auto overlay = overlaySectors_.find(lba + i);
    uint8_t *dst = out + static_cast<size_t>(i) * kSectorSize;
    if (overlay != overlaySectors_.end()) {
      std::copy(overlay->second.begin(), overlay->second.end(), dst);
    } else if (!base_.ReadSectors(lba + i, 1, dst)) {
      return false;
    }
  }
  return true;
}

bool CowRawBlockDevice::WriteSectors(uint64_t lba, uint16_t count,
                                     const uint8_t *data) {
  if (!data || !RangeValid(lba, count)) {
    return false;
  }
  for (uint16_t i = 0; i < count; ++i) {
    const uint8_t *src = data + static_cast<size_t>(i) * kSectorSize;
    Sector sector{};
    std::copy_n(src, sector.size(), sector.data());
    overlaySectors_[lba + i] = sector;
    if (!AppendOverlaySector(lba + i, src)) {
      return false;
    }
  }
  return true;
}

bool CowRawBlockDevice::Flush() {
  if (!overlayStream_) {
    return false;
  }
  overlayStream_.flush();
  return overlayStream_.good();
}

bool CowRawBlockDevice::RangeValid(uint64_t lba, uint16_t count) const noexcept {
  return count > 0 && lba <= SectorCount() &&
         static_cast<uint64_t>(count) <= SectorCount() - lba;
}

bool CowRawBlockDevice::AppendOverlaySector(uint64_t lba, const uint8_t *data) {
  if (!overlayStream_ || !data) {
    return false;
  }
  uint8_t header[kCowRecordHeaderBytes]{};
  for (int i = 0; i < 8; ++i) {
    header[i] = static_cast<uint8_t>((lba >> (i * 8)) & 0xFFu);
  }
  header[8] = 1;
  header[9] = 0;
  overlayStream_.clear();
  overlayStream_.seekp(0, std::ios::end);
  overlayStream_.write(reinterpret_cast<const char *>(header), sizeof(header));
  overlayStream_.write(reinterpret_cast<const char *>(data), kSectorSize);
  return overlayStream_.good();
}

CowOverlayBlockDevice
CowOverlayBlockDevice::Create(IBlockDevice *base,
                              const std::filesystem::path &overlayPath) {
  if (!base) {
    throw std::invalid_argument("COW overlay base is null");
  }
  if (!overlayPath.parent_path().empty()) {
    std::filesystem::create_directories(overlayPath.parent_path());
  }
  {
    std::ofstream create(overlayPath, std::ios::binary | std::ios::trunc);
    if (!create) {
      throw std::runtime_error("unable to create COW overlay");
    }
    create.write(reinterpret_cast<const char *>(kCowMagic), sizeof(kCowMagic));
  }
  return Open(base, overlayPath);
}

CowOverlayBlockDevice
CowOverlayBlockDevice::Open(IBlockDevice *base,
                            const std::filesystem::path &overlayPath) {
  if (!base) {
    throw std::invalid_argument("COW overlay base is null");
  }
  std::fstream overlay(overlayPath, std::ios::binary | std::ios::in | std::ios::out);
  if (!overlay) {
    throw std::runtime_error("unable to open COW overlay");
  }

  uint8_t magic[sizeof(kCowMagic)]{};
  if (!ReadExact(overlay, magic, sizeof(magic)) ||
      std::memcmp(magic, kCowMagic, sizeof(kCowMagic)) != 0) {
    throw std::runtime_error("COW overlay has invalid header");
  }

  std::map<uint64_t, Sector> sectors;
  for (;;) {
    uint8_t header[kCowRecordHeaderBytes]{};
    overlay.read(reinterpret_cast<char *>(header), sizeof(header));
    if (overlay.eof()) {
      break;
    }
    if (!overlay.good()) {
      throw std::runtime_error("COW overlay truncated in record header");
    }
    const uint64_t lba = ReadU64(header);
    const uint16_t count = ReadU16(header + 8);
    if (count == 0 || lba > base->SectorCount() ||
        static_cast<uint64_t>(count) > base->SectorCount() - lba) {
      throw std::runtime_error("COW overlay contains out-of-range sector record");
    }
    for (uint16_t i = 0; i < count; ++i) {
      Sector sector{};
      if (!ReadExact(overlay, sector.data(), sector.size())) {
        throw std::runtime_error("COW overlay truncated in sector payload");
      }
      sectors[lba + i] = sector;
    }
  }
  overlay.clear();
  overlay.seekp(0, std::ios::end);
  return CowOverlayBlockDevice(base, overlayPath, std::move(overlay),
                               std::move(sectors));
}

CowOverlayBlockDevice::CowOverlayBlockDevice(
    IBlockDevice *base, std::filesystem::path overlayPath,
    std::fstream overlayStream, std::map<uint64_t, Sector> overlaySectors)
    : base_(base), overlayPath_(std::move(overlayPath)),
      overlayStream_(std::move(overlayStream)),
      overlaySectors_(std::move(overlaySectors)) {}

CowOverlayBlockDevice::CowOverlayBlockDevice(
    CowOverlayBlockDevice &&other) noexcept
    : base_(other.base_), overlayPath_(std::move(other.overlayPath_)),
      overlayStream_(std::move(other.overlayStream_)),
      overlaySectors_(std::move(other.overlaySectors_)) {
  other.base_ = nullptr;
}

CowOverlayBlockDevice &
CowOverlayBlockDevice::operator=(CowOverlayBlockDevice &&other) noexcept {
  if (this != &other) {
    overlayStream_.close();
    base_ = other.base_;
    overlayPath_ = std::move(other.overlayPath_);
    overlayStream_ = std::move(other.overlayStream_);
    overlaySectors_ = std::move(other.overlaySectors_);
    other.base_ = nullptr;
  }
  return *this;
}

CowOverlayBlockDevice::~CowOverlayBlockDevice() {
  if (overlayStream_.is_open()) {
    overlayStream_.flush();
    overlayStream_.close();
  }
}

uint64_t CowOverlayBlockDevice::SectorCount() const noexcept {
  return base_ ? base_->SectorCount() : 0;
}

bool CowOverlayBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                        uint8_t *out) {
  if (!base_ || !out || !RangeValid(lba, count)) {
    return false;
  }
  for (uint16_t i = 0; i < count; ++i) {
    const auto overlay = overlaySectors_.find(lba + i);
    uint8_t *dst = out + static_cast<size_t>(i) * kSectorSize;
    if (overlay != overlaySectors_.end()) {
      std::copy(overlay->second.begin(), overlay->second.end(), dst);
    } else if (!base_->ReadSectors(lba + i, 1, dst)) {
      return false;
    }
  }
  return true;
}

bool CowOverlayBlockDevice::WriteSectors(uint64_t lba, uint16_t count,
                                         const uint8_t *data) {
  if (!data || !RangeValid(lba, count)) {
    return false;
  }
  for (uint16_t i = 0; i < count; ++i) {
    const uint8_t *src = data + static_cast<size_t>(i) * kSectorSize;
    Sector sector{};
    std::copy_n(src, sector.size(), sector.data());
    overlaySectors_[lba + i] = sector;
    if (!AppendOverlaySector(lba + i, src)) {
      return false;
    }
  }
  return true;
}

bool CowOverlayBlockDevice::Flush() {
  if (!overlayStream_) {
    return false;
  }
  overlayStream_.flush();
  return overlayStream_.good() && (!base_ || base_->Flush());
}

bool CowOverlayBlockDevice::RangeValid(uint64_t lba,
                                       uint16_t count) const noexcept {
  return base_ && count > 0 && lba <= base_->SectorCount() &&
         static_cast<uint64_t>(count) <= base_->SectorCount() - lba;
}

bool CowOverlayBlockDevice::AppendOverlaySector(uint64_t lba,
                                                const uint8_t *data) {
  if (!overlayStream_ || !data) {
    return false;
  }
  uint8_t header[kCowRecordHeaderBytes]{};
  for (int i = 0; i < 8; ++i) {
    header[i] = static_cast<uint8_t>((lba >> (i * 8)) & 0xFFu);
  }
  header[8] = 1;
  header[9] = 0;
  overlayStream_.clear();
  overlayStream_.seekp(0, std::ios::end);
  overlayStream_.write(reinterpret_cast<const char *>(header), sizeof(header));
  overlayStream_.write(reinterpret_cast<const char *>(data), kSectorSize);
  overlayStream_.flush();
  return overlayStream_.good();
}

JobMediaBlockDevice
JobMediaBlockDevice::FromEntries(const std::vector<JobMediaEntry> &entries) {
  std::vector<uint8_t> bytes;
  bytes.insert(bytes.end(), std::begin(kJobMagic), std::end(kJobMagic));
  PutU32(bytes, static_cast<uint32_t>(entries.size()));
  for (const auto &entry : entries) {
    if (entry.name.size() > 0xFFFFu) {
      throw std::invalid_argument("job media entry name is too long");
    }
    PutU16(bytes, static_cast<uint16_t>(entry.name.size()));
    PutU64(bytes, static_cast<uint64_t>(entry.bytes.size()));
    bytes.insert(bytes.end(), entry.name.begin(), entry.name.end());
    bytes.insert(bytes.end(), entry.bytes.begin(), entry.bytes.end());
  }
  const size_t remainder = bytes.size() % IBlockDevice::kSectorSize;
  if (remainder != 0) {
    bytes.resize(bytes.size() + (IBlockDevice::kSectorSize - remainder), 0);
  }
  if (bytes.empty()) {
    bytes.resize(IBlockDevice::kSectorSize, 0);
  }
  return JobMediaBlockDevice(std::move(bytes));
}

JobMediaBlockDevice::JobMediaBlockDevice(std::vector<uint8_t> bytes)
    : bytes_(std::move(bytes)) {}

uint64_t JobMediaBlockDevice::SectorCount() const noexcept {
  return bytes_.size() / kSectorSize;
}

bool JobMediaBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                      uint8_t *out) {
  if (!out || !RangeValid(lba, count)) {
    return false;
  }
  const auto offset = static_cast<size_t>(ByteOffset(lba));
  const auto bytes = static_cast<size_t>(ByteCount(count));
  std::copy_n(bytes_.data() + offset, bytes, out);
  return true;
}

bool JobMediaBlockDevice::WriteSectors(uint64_t, uint16_t, const uint8_t *) {
  return false;
}

bool JobMediaBlockDevice::Flush() {
  return true;
}

bool JobMediaBlockDevice::RangeValid(uint64_t lba,
                                     uint16_t count) const noexcept {
  return count > 0 && lba <= SectorCount() &&
         static_cast<uint64_t>(count) <= SectorCount() - lba;
}

} // namespace antimal::hv
