#include "antimal/hv/BlockDevice.h"

#include <algorithm>
#include <array>
#include <Windows.h>
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
// Sector-data cache budget for the COW overlays: 8192 * 512 B = 4 MiB of hot
// sectors. The authoritative data is the overlay file; this only avoids
// re-reading recently touched sectors (boot metadata, directory blocks).
constexpr size_t kCowCacheSectors = 8192;

// ---- Persisted COW index sidecar -------------------------------------------
// Rebuilding the lba->offset index scans the whole append-only overlay, which
// was measured at 218.7 s for a 4.0 GiB overlay. The sidecar caches that index
// next to the overlay (`<overlay>.idx`) so an unchanged overlay opens in the
// time it takes to read 16 bytes per record instead of the whole file.
//
// Validity is deliberately strict: the sidecar only applies when its recorded
// overlay size matches the file EXACTLY (the overlay is append-only, so any
// growth means the index is stale) and its CRC over the payload matches. A
// stale, truncated, corrupt or mismatched sidecar is discarded and the index is
// rebuilt from the records -- recovery never returns unverified data.
constexpr uint8_t kCowIndexMagic[] = {'A', 'M', 'C', 'I', 'X', '1',
                                      '\r', '\n'}; // exactly 8 bytes
// Version 2: the header carries the Windows FILE IDENTITY of the overlay the
// index describes (volume serial + 128-bit file index + creation time) in
// addition to the byte length. Length alone cannot distinguish two different
// overlays of equal size -- a swapped sidecar would then pass every check and
// serve a wrong sector mapping. The CRC covers the identity fields AND the
// entries, so a tampered binding is rejected too.
constexpr uint32_t kCowIndexVersion = 2;
constexpr size_t kCowIndexHeaderBytes =
    8 /*magic*/ + 4 /*version*/ + 4 /*volume serial*/ +
    8 /*file index high*/ + 8 /*file index low*/ + 8 /*creation time*/ +
    8 /*overlay size*/ + 8 /*entry count*/;

// Fixed header offsets (little-endian fields).
constexpr size_t kCowIndexVersionAt = 8;
constexpr size_t kCowIndexVolumeAt = 12;
constexpr size_t kCowIndexFileIndexHighAt = 16;
constexpr size_t kCowIndexFileIndexLowAt = 24;
constexpr size_t kCowIndexCreatedAt = 32;
constexpr size_t kCowIndexSizeAt = 40;
constexpr size_t kCowIndexCountAt = 48;

struct CowFileIdentity {
  bool valid = false;
  uint32_t volumeSerial = 0;
  uint64_t fileIndexHigh = 0;
  uint64_t fileIndexLow = 0;
  uint64_t creationTime = 0;
};

// Windows file identity: stable across opens, distinct for different files
// (including same-length ones) and for delete+recreate on the same path.
CowFileIdentity QueryFileIdentity(const std::filesystem::path &path) {
  CowFileIdentity identity;
  HANDLE handle = CreateFileW(path.c_str(), 0 /*metadata only*/,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return identity;
  }
  BY_HANDLE_FILE_INFORMATION info{};
  if (GetFileInformationByHandle(handle, &info)) {
    identity.valid = true;
    identity.volumeSerial = info.dwVolumeSerialNumber;
    identity.fileIndexHigh = info.nFileIndexHigh;
    identity.fileIndexLow = info.nFileIndexLow;
    identity.creationTime =
        (static_cast<uint64_t>(info.ftCreationTime.dwHighDateTime) << 32) |
        info.ftCreationTime.dwLowDateTime;
  }
  CloseHandle(handle);
  return identity;
}

bool IdentityMatches(const CowFileIdentity &a, const CowFileIdentity &b) {
  return a.valid && b.valid && a.volumeSerial == b.volumeSerial &&
         a.fileIndexHigh == b.fileIndexHigh &&
         a.fileIndexLow == b.fileIndexLow &&
         a.creationTime == b.creationTime;
}

constexpr size_t kCowIndexEntryBytes = 16; // lba u64 + payload offset u64
constexpr uint32_t kCowIndexCrcBytes = 4;

uint32_t Crc32(const uint8_t *data, size_t size) {
  static uint32_t table[256];
  static bool ready = false;
  if (!ready) {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) {
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      }
      table[i] = c;
    }
    ready = true;
  }
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < size; ++i) {
    crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

void PutU64At(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}
void PutU32At(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

// Loads and validates `<overlay>.idx`. Returns true only when the cached index
// provably matches the current overlay bytes.
bool CowIndexDebugEnabled() {
  char buf[8]{};
  size_t needed = 0;
  return getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_COW_INDEX_DEBUG") == 0 &&
         needed > 1 && buf[0] == '1';
}

bool TryLoadCowIndex(const std::filesystem::path &overlayPath,
                     std::map<uint64_t, uint64_t> *index) {
  auto reject = [&](const char *why) {
    if (CowIndexDebugEnabled()) {
      std::fprintf(stderr, "cow-index: reject %s (%s)\n", why,
                   overlayPath.string().c_str());
    }
    return false;
  };
  if (index == nullptr) {
    return reject("null-index");
  }
  std::error_code ec;
  const std::filesystem::path sidecar = overlayPath.wstring() + L".idx";
  const uint64_t sidecarBytes = std::filesystem::file_size(sidecar, ec);
  if (ec || sidecarBytes < kCowIndexHeaderBytes + kCowIndexCrcBytes) {
    return reject("missing-or-tiny");
  }
  const uint64_t overlayBytes = std::filesystem::file_size(overlayPath, ec);
  if (ec) {
    return reject("overlay-size");
  }
  // Identity: the sidecar must describe THIS file, not merely a file of the
  // same length. Fetched from the live handle, never trusted from the sidecar.
  const CowFileIdentity overlayIdentity = QueryFileIdentity(overlayPath);
  if (!overlayIdentity.valid) {
    return reject("overlay-identity-unavailable");
  }
  std::ifstream in(sidecar, std::ios::binary);
  if (!in) {
    return reject("sidecar-open");
  }
  std::vector<uint8_t> blob(static_cast<size_t>(sidecarBytes));
  in.read(reinterpret_cast<char *>(blob.data()),
          static_cast<std::streamsize>(blob.size()));
  if (in.gcount() != static_cast<std::streamsize>(blob.size())) {
    return reject("short-read");
  }
  if (std::memcmp(blob.data(), kCowIndexMagic, sizeof(kCowIndexMagic)) != 0) {
    return reject("bad-magic");
  }
  const uint32_t version = ReadU32(blob.data() + kCowIndexVersionAt);
  const uint64_t recordedSize = ReadU64(blob.data() + kCowIndexSizeAt);
  const uint64_t count = ReadU64(blob.data() + kCowIndexCountAt);
  if (version != kCowIndexVersion) {
    return reject("bad-version");
  }
  if (recordedSize != overlayBytes) {
    return reject("stale-size");
  }
  if (count > overlayBytes / 512ull) {
    return reject("impossible-count");
  }
  const uint64_t expected =
      kCowIndexHeaderBytes + count * kCowIndexEntryBytes + kCowIndexCrcBytes;
  if (sidecarBytes != expected) {
    return reject("truncated-or-oversized");
  }
  const size_t payloadBytes = static_cast<size_t>(count) * kCowIndexEntryBytes;
  // CRC covers everything after the magic: the identity binding, the recorded
  // size/count and every entry -- so tampering with the binding is detected too.
  const uint32_t recordedCrc = ReadU32(
      blob.data() + kCowIndexHeaderBytes + payloadBytes);
  if (Crc32(blob.data() + sizeof(kCowIndexMagic),
            kCowIndexHeaderBytes - sizeof(kCowIndexMagic) + payloadBytes) !=
      recordedCrc) {
    return reject("crc");
  }
  CowFileIdentity recordedIdentity;
  recordedIdentity.valid = true;
  recordedIdentity.volumeSerial = ReadU32(blob.data() + kCowIndexVolumeAt);
  recordedIdentity.fileIndexHigh =
      ReadU64(blob.data() + kCowIndexFileIndexHighAt);
  recordedIdentity.fileIndexLow =
      ReadU64(blob.data() + kCowIndexFileIndexLowAt);
  recordedIdentity.creationTime = ReadU64(blob.data() + kCowIndexCreatedAt);
  if (!IdentityMatches(recordedIdentity, overlayIdentity)) {
    return reject("wrong-overlay-identity");
  }
  // Payload: sorted (lba, offset) pairs with in-file bounds validated.
  uint64_t previousLba = 0;
  bool first = true;
  std::map<uint64_t, uint64_t> loaded;
  const uint8_t *p = blob.data() + kCowIndexHeaderBytes;
  for (uint64_t i = 0; i < count; ++i, p += kCowIndexEntryBytes) {
    const uint64_t lba = ReadU64(p);
    const uint64_t offset = ReadU64(p + 8);
    if (!first && lba <= previousLba) {
      return false; // not strictly increasing -> unusable
    }
    if (offset < kCowRecordHeaderBytes ||
        offset + 512ull > overlayBytes) {
      return false; // out-of-range payload offset
    }
    previousLba = lba;
    first = false;
    loaded.emplace(lba, offset);
  }
  *index = std::move(loaded);
  return true;
}

// Persists the index for the CURRENT overlay file. Best-effort: a failure only
// means the next open pays the rebuild again. Delegates to the identity-bound
// writer below so there is exactly one sidecar format in the codebase.
void SaveCowIndex(const std::filesystem::path &overlayPath,
                  const std::map<uint64_t, uint64_t> &index);

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

// Writes a sidecar for `overlayPath` using a CALLER-SUPPLIED identity. Only the
// seed-copy rebind uses this: the identity is the copy's, the entries came from
// a sidecar that already validated against the byte-identical source.
bool WriteCowIndexWithIdentity(const std::filesystem::path &overlayPath,
                               const CowFileIdentity &identity,
                               const std::map<uint64_t, uint64_t> &index) {
  if (!identity.valid) {
    return false;
  }
  std::error_code ec;
  const uint64_t overlayBytes = std::filesystem::file_size(overlayPath, ec);
  if (ec) {
    return false;
  }
  std::vector<uint8_t> payload;
  payload.reserve(index.size() * kCowIndexEntryBytes);
  for (const auto &[lba, offset] : index) {
    PutU64At(payload, lba);
    PutU64At(payload, offset);
  }
  std::vector<uint8_t> blob;
  blob.reserve(kCowIndexHeaderBytes + payload.size() + kCowIndexCrcBytes);
  blob.insert(blob.end(), std::begin(kCowIndexMagic), std::end(kCowIndexMagic));
  PutU32At(blob, kCowIndexVersion);
  PutU32At(blob, identity.volumeSerial);
  PutU64At(blob, identity.fileIndexHigh);
  PutU64At(blob, identity.fileIndexLow);
  PutU64At(blob, identity.creationTime);
  PutU64At(blob, overlayBytes);
  PutU64At(blob, static_cast<uint64_t>(index.size()));
  blob.insert(blob.end(), payload.begin(), payload.end());
  PutU32At(blob, Crc32(blob.data() + sizeof(kCowIndexMagic),
                       kCowIndexHeaderBytes - sizeof(kCowIndexMagic) +
                           payload.size()));
  const std::filesystem::path sidecar = overlayPath.wstring() + L".idx";
  const std::filesystem::path temp = sidecar.wstring() + L".tmp";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      return false;
    }
    out.write(reinterpret_cast<const char *>(blob.data()),
              static_cast<std::streamsize>(blob.size()));
    if (!out) {
      std::filesystem::remove(temp, ec);
      return false;
    }
  }
  for (int attempt = 0; attempt < 4; ++attempt) {
    if (MoveFileExW(temp.wstring().c_str(), sidecar.wstring().c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      return true;
    }
    const DWORD err = GetLastError();
    if (err != ERROR_SHARING_VIOLATION && err != ERROR_ACCESS_DENIED &&
        err != ERROR_LOCK_VIOLATION) {
      break;
    }
    Sleep(static_cast<DWORD>(25 * (attempt + 1)));
  }
  std::filesystem::remove(temp, ec);
  return false;
}
void SaveCowIndex(const std::filesystem::path &overlayPath,
                  const std::map<uint64_t, uint64_t> &index) {
  // Identity-bound write; see WriteCowIndexWithIdentity.
  (void)WriteCowIndexWithIdentity(overlayPath,
                                  QueryFileIdentity(overlayPath), index);
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

PaddedFileBlockDevice
PaddedFileBlockDevice::Open(const std::filesystem::path &path) {
  const auto size = std::filesystem::file_size(path);
  if (size == 0) {
    throw std::runtime_error("sample disk file is empty");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw std::runtime_error("unable to open sample disk file");
  }
  const uint64_t sectors =
      (size + IBlockDevice::kSectorSize - 1) / IBlockDevice::kSectorSize;
  return PaddedFileBlockDevice(path, size, sectors, std::move(stream));
}

PaddedFileBlockDevice::PaddedFileBlockDevice(std::filesystem::path path,
                                             uint64_t fileBytes,
                                             uint64_t sectors,
                                             std::ifstream stream)
    : path_(std::move(path)), fileBytes_(fileBytes), sectors_(sectors),
      stream_(std::move(stream)) {}

PaddedFileBlockDevice::PaddedFileBlockDevice(
    PaddedFileBlockDevice &&other) noexcept
    : path_(std::move(other.path_)), fileBytes_(other.fileBytes_),
      sectors_(other.sectors_), stream_(std::move(other.stream_)) {
  other.fileBytes_ = 0;
  other.sectors_ = 0;
}

PaddedFileBlockDevice &
PaddedFileBlockDevice::operator=(PaddedFileBlockDevice &&other) noexcept {
  if (this != &other) {
    stream_.close();
    path_ = std::move(other.path_);
    fileBytes_ = other.fileBytes_;
    sectors_ = other.sectors_;
    stream_ = std::move(other.stream_);
    other.fileBytes_ = 0;
    other.sectors_ = 0;
  }
  return *this;
}

PaddedFileBlockDevice::~PaddedFileBlockDevice() {
  if (stream_.is_open()) {
    stream_.close();
  }
}

uint64_t PaddedFileBlockDevice::SectorCount() const noexcept {
  return sectors_;
}

bool PaddedFileBlockDevice::ReadSectors(uint64_t lba, uint16_t count,
                                        uint8_t *out) {
  if (!out || !stream_ || !RangeValid(lba, count)) {
    return false;
  }
  const uint64_t offset = ByteOffset(lba);
  const size_t wanted = static_cast<size_t>(ByteCount(count));
  std::memset(out, 0, wanted);
  if (offset >= fileBytes_) {
    return true; // Entirely inside the sector padding.
  }
  const size_t readable =
      static_cast<size_t>(std::min<uint64_t>(wanted, fileBytes_ - offset));
  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  stream_.read(reinterpret_cast<char *>(out),
               static_cast<std::streamsize>(readable));
  return stream_.gcount() == static_cast<std::streamsize>(readable);
}

bool PaddedFileBlockDevice::WriteSectors(uint64_t, uint16_t,
                                         const uint8_t *) {
  // Black-hole writes and report SUCCESS. The sample disk is delivery media:
  // the file behind it must never change, but ABRT-ing a write makes Windows'
  // storage stack enter an error/retry path (disk-signature / GPT-backup
  // maintenance) that wedges storahci on this emulated port. Discarding the
  // bytes keeps the sample intact while letting the guest's storage stack
  // believe the write completed.
  return true;
}

bool PaddedFileBlockDevice::Flush() {
  return true;
}

bool PaddedFileBlockDevice::RangeValid(uint64_t lba,
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

  std::map<uint64_t, uint64_t> index; // lba -> payload byte offset
  // Fast path: a validated sidecar for THIS exact overlay size means no scan.
  const bool indexLoaded = TryLoadCowIndex(overlayPath, &index);
  if (!indexLoaded) {
  for (;;) {
    uint8_t header[kCowRecordHeaderBytes]{};
    const std::streampos recordStart = overlay.tellg();
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
    // Index the payload offsets and SKIP the data (fetched on demand through
    // the bounded LRU cache; see CowOverlayBlockDevice::Open for rationale).
    const std::streamoff payloadBase =
        static_cast<std::streamoff>(recordStart) +
        static_cast<std::streamoff>(kCowRecordHeaderBytes);
    const std::streamoff payloadEnd =
        payloadBase + static_cast<std::streamoff>(count) * kSectorSize;
    overlay.seekg(0, std::ios::end);
    const std::streamoff fileEnd = overlay.tellg();
    if (fileEnd < payloadEnd) {
      throw std::runtime_error("COW raw overlay truncated in sector payload");
    }
    for (uint16_t i = 0; i < count; ++i) {
      index[lba + i] = static_cast<uint64_t>(
          payloadBase + static_cast<std::streamoff>(i) * kSectorSize);
    }
    overlay.seekg(payloadEnd);
  }
  } // !indexLoaded
  overlay.clear();
  overlay.seekp(0, std::ios::end);
  if (!indexLoaded && overlay.good()) {
    // Cache the freshly built index for the next open (best effort; a failure
    // just means the next open rebuilds).
    SaveCowIndex(overlayPath, index);
  }
  CowRawBlockDevice device(std::move(base), overlayPath, std::move(overlay),
                           std::move(index));
  device.indexFromSidecar_ = indexLoaded;
  return device;
}
CowRawBlockDevice::CowRawBlockDevice(ReadOnlyRawBlockDevice base,
                                     std::filesystem::path overlayPath,
                                     std::fstream overlayStream,
                                     std::map<uint64_t, uint64_t> overlayIndex)
    : base_(std::move(base)), overlayPath_(std::move(overlayPath)),
      overlayStream_(std::move(overlayStream)),
      overlayIndex_(std::move(overlayIndex)) {}

CowRawBlockDevice::CowRawBlockDevice(CowRawBlockDevice &&other) noexcept
    : base_(std::move(other.base_)), overlayPath_(std::move(other.overlayPath_)),
      overlayStream_(std::move(other.overlayStream_)),
      overlayIndex_(std::move(other.overlayIndex_)),
      indexDirty_(other.indexDirty_),
      indexFromSidecar_(other.indexFromSidecar_),
      cache_(std::move(other.cache_)), cacheLru_(std::move(other.cacheLru_)) {}

CowRawBlockDevice &
CowRawBlockDevice::operator=(CowRawBlockDevice &&other) noexcept {
  if (this != &other) {
    overlayStream_.close();
    base_ = std::move(other.base_);
    overlayPath_ = std::move(other.overlayPath_);
    overlayStream_ = std::move(other.overlayStream_);
    overlayIndex_ = std::move(other.overlayIndex_);
    indexDirty_ = other.indexDirty_;
    indexFromSidecar_ = other.indexFromSidecar_;
    cache_ = std::move(other.cache_);
    cacheLru_ = std::move(other.cacheLru_);
  }
  return *this;
}

CowRawBlockDevice::~CowRawBlockDevice() {
  if (overlayStream_.is_open()) {
    overlayStream_.flush();
    overlayStream_.close();
  }
  // Persist the index for the file as it now stands so the next open (offline
  // tools, a later run) skips the full scan. Best effort: a torn/partial file
  // makes the recorded size/bounds check reject the sidecar and rebuild.
  if (indexDirty_) {
    SaveCowIndex(overlayPath_, overlayIndex_);
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
    const auto overlay = overlayIndex_.find(lba + i);
    uint8_t *dst = out + static_cast<size_t>(i) * kSectorSize;
    if (overlay != overlayIndex_.end()) {
      const Sector *sector = CachedSector(lba + i);
      if (sector == nullptr) {
        return false; // overlay read failure: never silently serve base data
      }
      std::copy(sector->begin(), sector->end(), dst);
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
  if (!AppendOverlaySectors(lba, count, data)) {
    return false;
  }
  for (uint16_t i = 0; i < count; ++i) {
    if (cache_.count(lba + i) != 0) {
      Sector sector{};
      std::copy_n(data + static_cast<size_t>(i) * kSectorSize, sector.size(),
                  sector.data());
      PutCache(lba + i, sector);
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

const CowRawBlockDevice::Sector *CowRawBlockDevice::CachedSector(uint64_t lba) {
  if (const auto hit = cache_.find(lba); hit != cache_.end()) {
    cacheLru_.splice(cacheLru_.begin(), cacheLru_, hit->second.lru);
    return &hit->second.data;
  }
  const auto indexIt = overlayIndex_.find(lba);
  if (indexIt == overlayIndex_.end()) {
    return nullptr;
  }
  Sector sector{};
  overlayStream_.clear();
  overlayStream_.seekg(static_cast<std::streamoff>(indexIt->second),
                       std::ios::beg);
  overlayStream_.read(reinterpret_cast<char *>(sector.data()), sector.size());
  if (overlayStream_.gcount() !=
      static_cast<std::streamsize>(sector.size())) {
    return nullptr;
  }
  return PutCache(lba, sector);
}

const CowRawBlockDevice::Sector *CowRawBlockDevice::PutCache(
    uint64_t lba, const Sector &sector) {
  if (const auto existing = cache_.find(lba); existing != cache_.end()) {
    existing->second.data = sector;
    cacheLru_.splice(cacheLru_.begin(), cacheLru_, existing->second.lru);
    return &existing->second.data;
  }
  cacheLru_.push_front(lba);
  auto [it, inserted] =
      cache_.emplace(lba, CacheEntry{sector, cacheLru_.begin()});
  (void)inserted;
  while (cache_.size() > kCowCacheSectors) {
    const uint64_t victim = cacheLru_.back();
    cacheLru_.pop_back();
    cache_.erase(victim);
  }
  return &it->second.data;
}

bool CowRawBlockDevice::AppendOverlaySectors(uint64_t lba, uint16_t count,
                                             const uint8_t *data) {
  if (!overlayStream_ || !data || count == 0) {
    return false;
  }
  // One record per request (the record format already carries a u16 count), a
  // single write and a single flush -- see CowOverlayBlockDevice::
  // AppendOverlaySectors for why the old per-sector append was the dominant
  // COW cost.
  uint8_t header[kCowRecordHeaderBytes]{};
  for (int i = 0; i < 8; ++i) {
    header[i] = static_cast<uint8_t>((lba >> (i * 8)) & 0xFFu);
  }
  header[8] = static_cast<uint8_t>(count & 0xFFu);
  header[9] = static_cast<uint8_t>((count >> 8) & 0xFFu);
  overlayStream_.clear();
  overlayStream_.seekp(0, std::ios::end);
  const std::streamoff recordStart = overlayStream_.tellp();
  overlayStream_.write(reinterpret_cast<const char *>(header), sizeof(header));
  overlayStream_.write(reinterpret_cast<const char *>(data),
                       static_cast<std::streamsize>(count) * kSectorSize);
  if (!overlayStream_.good()) {
    return false;
  }
  const uint64_t payloadBase =
      static_cast<uint64_t>(recordStart) + kCowRecordHeaderBytes;
  for (uint16_t i = 0; i < count; ++i) {
    overlayIndex_[lba + i] = payloadBase + static_cast<uint64_t>(i) * kSectorSize;
  }
  indexDirty_ = true;
  overlayStream_.flush();
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

  std::map<uint64_t, uint64_t> index; // lba -> payload byte offset
  // Fast path: a validated sidecar for THIS exact overlay size means no scan.
  // (Measured: the full scan cost 218.7 s on a 4.0 GiB overlay.)
  const bool indexLoaded = TryLoadCowIndex(overlayPath, &index);
  if (!indexLoaded) {
  for (;;) {
    uint8_t header[kCowRecordHeaderBytes]{};
    const std::streampos recordStart = overlay.tellg();
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
    // Record the payload offset per sector, then SKIP the payload: the data
    // stays on disk and is fetched on demand through a bounded LRU cache. The
    // skip is bounds-checked against the real file size so a truncated overlay
    // is still rejected (seekg alone does not detect a short payload).
    const std::streamoff payloadBase =
        static_cast<std::streamoff>(recordStart) +
        static_cast<std::streamoff>(kCowRecordHeaderBytes);
    const std::streamoff payloadEnd =
        payloadBase + static_cast<std::streamoff>(count) * kSectorSize;
    overlay.seekg(0, std::ios::end);
    const std::streamoff fileEnd = overlay.tellg();
    if (fileEnd < payloadEnd) {
      throw std::runtime_error("COW overlay truncated in sector payload");
    }
    for (uint16_t i = 0; i < count; ++i) {
      index[lba + i] = static_cast<uint64_t>(
          payloadBase + static_cast<std::streamoff>(i) * kSectorSize);
    }
    overlay.seekg(payloadEnd);
  }
  } // !indexLoaded
  overlay.clear();
  overlay.seekp(0, std::ios::end);
  if (!indexLoaded && overlay.good()) {
    SaveCowIndex(overlayPath, index); // best effort; see TryLoadCowIndex
  }
  CowOverlayBlockDevice device(base, overlayPath, std::move(overlay),
                               std::move(index));
  device.indexFromSidecar_ = indexLoaded;
  return device;
}

CowOverlayBlockDevice::CowOverlayBlockDevice(
    IBlockDevice *base, std::filesystem::path overlayPath,
    std::fstream overlayStream, std::map<uint64_t, uint64_t> overlayIndex)
    : base_(base), overlayPath_(std::move(overlayPath)),
      overlayStream_(std::move(overlayStream)),
      overlayIndex_(std::move(overlayIndex)) {}

CowOverlayBlockDevice::CowOverlayBlockDevice(
    CowOverlayBlockDevice &&other) noexcept
    : base_(other.base_), overlayPath_(std::move(other.overlayPath_)),
      overlayStream_(std::move(other.overlayStream_)),
      overlayIndex_(std::move(other.overlayIndex_)),
      indexDirty_(other.indexDirty_),
      indexFromSidecar_(other.indexFromSidecar_),
      cache_(std::move(other.cache_)), cacheLru_(std::move(other.cacheLru_)) {
  other.base_ = nullptr;
}

CowOverlayBlockDevice &
CowOverlayBlockDevice::operator=(CowOverlayBlockDevice &&other) noexcept {
  if (this != &other) {
    overlayStream_.close();
    base_ = other.base_;
    overlayPath_ = std::move(other.overlayPath_);
    overlayStream_ = std::move(other.overlayStream_);
    overlayIndex_ = std::move(other.overlayIndex_);
    indexDirty_ = other.indexDirty_;
    indexFromSidecar_ = other.indexFromSidecar_;
    cache_ = std::move(other.cache_);
    cacheLru_ = std::move(other.cacheLru_);
    other.base_ = nullptr;
  }
  return *this;
}

CowOverlayBlockDevice::~CowOverlayBlockDevice() {
  if (overlayStream_.is_open()) {
    overlayStream_.flush();
    overlayStream_.close();
  }
  if (indexDirty_) {
    SaveCowIndex(overlayPath_, overlayIndex_);
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
  // Fast path: pull the whole range from the base in ONE call, then overlay
  // just the modified sectors that fall inside it. The old per-sector loop did
  // `count` individual base reads (each a file seek) + `count` map lookups,
  // which made multi-megabyte reads through a large overlay (e.g. the second
  // boot after a reboot, once the overlay has accumulated the first boot's
  // writes) crawl -- winload then spends its whole time in tiny reads. A bulk
  // base read + a bounded overlay sweep is orders of magnitude faster and
  // bit-for-bit identical (each sector ends up overlay-if-modified, else base).
  if (!base_->ReadSectors(lba, count, out)) {
    return false;
  }
  for (auto it = overlayIndex_.lower_bound(lba);
       it != overlayIndex_.end() && it->first < lba + count; ++it) {
    const Sector *sector = CachedSector(it->first);
    if (sector == nullptr) {
      return false; // overlay read failure: never silently serve base data
    }
    uint8_t *dst = out + static_cast<size_t>(it->first - lba) * kSectorSize;
    std::copy(sector->begin(), sector->end(), dst);
  }
  return true;
}

bool CowOverlayBlockDevice::WriteSectors(uint64_t lba, uint16_t count,
                                         const uint8_t *data) {
  if (!data || !RangeValid(lba, count)) {
    return false;
  }
  if (!AppendOverlaySectors(lba, count, data)) {
    return false;
  }
  // Keep the cache coherent: a rewritten sector that is cached must reflect
  // the new bytes (the next read may hit the cache before the file). The tail
  // of large writes stays out of the cache (bounded memory), which is fine --
  // a cache miss falls through to the freshly flushed file.
  for (uint16_t i = 0; i < count; ++i) {
    if (cache_.count(lba + i) != 0) {
      Sector sector{};
      std::copy_n(data + static_cast<size_t>(i) * kSectorSize, sector.size(),
                  sector.data());
      PutCache(lba + i, sector);
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

// Bounded LRU: sector data lives on disk; this cache only keeps recently
// touched sectors (kCowCacheSectors * 512 bytes total) so repeated accesses to
// the same hot region -- boot metadata, directory blocks -- stay cheap without
// growing host memory with the size of everything the guest wrote.
const CowOverlayBlockDevice::Sector *CowOverlayBlockDevice::CachedSector(
    uint64_t lba) {
  if (const auto hit = cache_.find(lba); hit != cache_.end()) {
    cacheLru_.splice(cacheLru_.begin(), cacheLru_, hit->second.lru);
    return &hit->second.data;
  }
  const auto indexIt = overlayIndex_.find(lba);
  if (indexIt == overlayIndex_.end()) {
    return nullptr;
  }
  Sector sector{};
  overlayStream_.clear();
  overlayStream_.seekg(static_cast<std::streamoff>(indexIt->second),
                       std::ios::beg);
  overlayStream_.read(reinterpret_cast<char *>(sector.data()), sector.size());
  if (overlayStream_.gcount() !=
      static_cast<std::streamsize>(sector.size())) {
    return nullptr;
  }
  return PutCache(lba, sector);
}

const CowOverlayBlockDevice::Sector *CowOverlayBlockDevice::PutCache(
    uint64_t lba, const Sector &sector) {
  if (const auto existing = cache_.find(lba); existing != cache_.end()) {
    existing->second.data = sector;
    cacheLru_.splice(cacheLru_.begin(), cacheLru_, existing->second.lru);
    return &existing->second.data;
  }
  cacheLru_.push_front(lba);
  auto [it, inserted] =
      cache_.emplace(lba, CacheEntry{sector, cacheLru_.begin()});
  (void)inserted;
  while (cache_.size() > kCowCacheSectors) {
    const uint64_t victim = cacheLru_.back();
    cacheLru_.pop_back();
    cache_.erase(victim);
  }
  return &it->second.data;
}

bool CowOverlayBlockDevice::AppendOverlaySectors(uint64_t lba, uint16_t count,
                                                 const uint8_t *data) {
  if (!overlayStream_ || !data || count == 0) {
    return false;
  }
  // ONE record for the whole request: header + every sector payload in a
  // single write. The previous per-sector append did a seek, a write of 10+512
  // bytes, and a flush PER SECTOR (512 flushes for a 256 KB write), which is
  // the dominant COW cost a large install pays. The on-disk format is
  // unchanged (a record already carries a u16 sector count), so old overlays
  // stay readable.
  uint8_t header[kCowRecordHeaderBytes]{};
  for (int i = 0; i < 8; ++i) {
    header[i] = static_cast<uint8_t>((lba >> (i * 8)) & 0xFFu);
  }
  header[8] = static_cast<uint8_t>(count & 0xFFu);
  header[9] = static_cast<uint8_t>((count >> 8) & 0xFFu);
  overlayStream_.clear();
  overlayStream_.seekp(0, std::ios::end);
  const std::streamoff recordStart = overlayStream_.tellp();
  overlayStream_.write(reinterpret_cast<const char *>(header), sizeof(header));
  overlayStream_.write(reinterpret_cast<const char *>(data),
                       static_cast<std::streamsize>(count) * kSectorSize);
  if (!overlayStream_.good()) {
    return false;
  }
  const uint64_t payloadBase =
      static_cast<uint64_t>(recordStart) + kCowRecordHeaderBytes;
  for (uint16_t i = 0; i < count; ++i) {
    overlayIndex_[lba + i] = payloadBase + static_cast<uint64_t>(i) * kSectorSize;
  }
  indexDirty_ = true;
  // Flush per WriteSectors call (not per sector): the guest's write is durable
  // at the same boundary as before -- only the redundant intermediate flushes
  // are gone.
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

bool BindCowIndexSidecarToCopy(const std::filesystem::path &sourceOverlay,
                               const std::filesystem::path &copyOverlay,
                               std::string *error) {
  auto fail = [&](const std::string &message) {
    if (error != nullptr) {
      *error = message;
    }
    return false;
  };
  std::error_code ec;
  const uint64_t sourceBytes = std::filesystem::file_size(sourceOverlay, ec);
  const uint64_t copyBytes = std::filesystem::file_size(copyOverlay, ec);
  if (ec || sourceBytes != copyBytes) {
    return fail("copy is not byte-identical in length to the source overlay");
  }
  std::map<uint64_t, uint64_t> index;
  if (!TryLoadCowIndex(sourceOverlay, &index)) {
    return fail("the source sidecar is missing, stale or foreign to the source");
  }
  const CowFileIdentity copyIdentity = QueryFileIdentity(copyOverlay);
  if (!copyIdentity.valid) {
    return fail("the copy's file identity is unavailable");
  }
  if (!WriteCowIndexWithIdentity(copyOverlay, copyIdentity, index)) {
    return fail("writing the copy's sidecar failed");
  }
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

} // namespace antimal::hv
