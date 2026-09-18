#pragma once

// Sector-level block devices for the in-house VMM. v1 deliberately fixes the
// sector size at 512 bytes because that is the ATA/IDE path we are bringing up
// first; larger physical-sector VHDX support can layer in after the controller
// is proven with benign media.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <array>
#include <list>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace antimal::hv {

class IBlockDevice {
public:
  static constexpr uint32_t kSectorSize = 512;

  virtual ~IBlockDevice() = default;
  virtual uint64_t SectorCount() const noexcept = 0;
  virtual bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) = 0;
  virtual bool WriteSectors(uint64_t lba, uint16_t count,
                            const uint8_t *data) = 0;
  virtual bool Flush() = 0;
};

class MemoryBlockDevice final : public IBlockDevice {
public:
  explicit MemoryBlockDevice(uint64_t sectors);

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  const std::vector<uint8_t> &Bytes() const noexcept { return bytes_; }

private:
  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;

  std::vector<uint8_t> bytes_;
};

class RawFileBlockDevice final : public IBlockDevice {
public:
  static RawFileBlockDevice Create(const std::filesystem::path &path,
                                   uint64_t sectors);
  static RawFileBlockDevice Open(const std::filesystem::path &path);

  RawFileBlockDevice(RawFileBlockDevice &&) noexcept;
  RawFileBlockDevice &operator=(RawFileBlockDevice &&) noexcept;

  RawFileBlockDevice(const RawFileBlockDevice &) = delete;
  RawFileBlockDevice &operator=(const RawFileBlockDevice &) = delete;

  ~RawFileBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

private:
  RawFileBlockDevice(std::filesystem::path path, uint64_t sectors,
                     std::fstream stream);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;

  std::filesystem::path path_;
  uint64_t sectors_ = 0;
  std::fstream stream_;
};

class ReadOnlyRawBlockDevice final : public IBlockDevice {
public:
  static ReadOnlyRawBlockDevice Open(const std::filesystem::path &path);

  ReadOnlyRawBlockDevice(ReadOnlyRawBlockDevice &&) noexcept;
  ReadOnlyRawBlockDevice &operator=(ReadOnlyRawBlockDevice &&) noexcept;

  ReadOnlyRawBlockDevice(const ReadOnlyRawBlockDevice &) = delete;
  ReadOnlyRawBlockDevice &operator=(const ReadOnlyRawBlockDevice &) = delete;

  ~ReadOnlyRawBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

private:
  ReadOnlyRawBlockDevice(std::filesystem::path path, uint64_t sectors,
                         std::ifstream stream);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;

  std::filesystem::path path_;
  uint64_t sectors_ = 0;
  std::ifstream stream_;
};

// A read-only file presented as a sector device, ZERO-PADDED up to a whole
// sector. Used for disk-backed sample delivery: the sample file is attached as
// a second AHCI disk and the in-guest agent copies it off the raw device. The
// padding lets an unaligned file (an arbitrary .exe/.iso size) be read back
// exactly; the guest truncates to the true byte size carried in the job request.
class PaddedFileBlockDevice final : public IBlockDevice {
public:
  static PaddedFileBlockDevice Open(const std::filesystem::path &path);

  PaddedFileBlockDevice(PaddedFileBlockDevice &&) noexcept;
  PaddedFileBlockDevice &operator=(PaddedFileBlockDevice &&) noexcept;

  PaddedFileBlockDevice(const PaddedFileBlockDevice &) = delete;
  PaddedFileBlockDevice &operator=(const PaddedFileBlockDevice &) = delete;

  ~PaddedFileBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  // Exact on-disk file size (the region the guest actually uses).
  uint64_t FileByteSize() const noexcept { return fileBytes_; }

private:
  PaddedFileBlockDevice(std::filesystem::path path, uint64_t fileBytes,
                        uint64_t sectors, std::ifstream stream);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;

  std::filesystem::path path_;
  uint64_t fileBytes_ = 0;
  uint64_t sectors_ = 0;
  std::ifstream stream_;
};

class VhdxBlockDevice final : public IBlockDevice {
public:
  static VhdxBlockDevice Open(const std::filesystem::path &path);

  VhdxBlockDevice(VhdxBlockDevice &&) noexcept;
  VhdxBlockDevice &operator=(VhdxBlockDevice &&) noexcept;

  VhdxBlockDevice(const VhdxBlockDevice &) = delete;
  VhdxBlockDevice &operator=(const VhdxBlockDevice &) = delete;

  ~VhdxBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  uint64_t VirtualSize() const noexcept { return virtualSize_; }
  uint32_t BlockSize() const noexcept { return blockSize_; }

private:
  VhdxBlockDevice(std::filesystem::path path, uint64_t virtualSize,
                  uint32_t blockSize, uint32_t logicalSectorSize,
                  uint32_t chunkRatio, std::vector<uint64_t> bat,
                  std::ifstream stream);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;
  bool ReadBytes(uint64_t byteOffset, uint8_t *out, size_t bytes);

  std::filesystem::path path_;
  uint64_t virtualSize_ = 0;
  uint32_t blockSize_ = 0;
  uint32_t logicalSectorSize_ = kSectorSize;
  uint32_t chunkRatio_ = 0;
  std::vector<uint64_t> bat_;
  std::ifstream stream_;
};

class CowRawBlockDevice final : public IBlockDevice {
public:
  static CowRawBlockDevice Create(const std::filesystem::path &basePath,
                                  const std::filesystem::path &overlayPath);
  static CowRawBlockDevice Open(const std::filesystem::path &basePath,
                                const std::filesystem::path &overlayPath);

  CowRawBlockDevice(CowRawBlockDevice &&) noexcept;
  CowRawBlockDevice &operator=(CowRawBlockDevice &&) noexcept;

  CowRawBlockDevice(const CowRawBlockDevice &) = delete;
  CowRawBlockDevice &operator=(const CowRawBlockDevice &) = delete;

  ~CowRawBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  size_t OverlaySectorCount() const noexcept { return overlayIndex_.size(); }
  // True when the last Indexed open loaded the validated <overlay>.idx
  // sidecar instead of rescanning the records (observability for tests and
  // diagnostics). CachedSectorCount reports the bounded LRU occupancy.
  bool IndexLoadedFromSidecar() const noexcept { return indexFromSidecar_; }
  size_t CachedSectorCount() const noexcept { return cache_.size(); }

private:
  using Sector = std::array<uint8_t, kSectorSize>;
  struct CacheEntry {
    Sector data{};
    std::list<uint64_t>::iterator lru;
  };

  CowRawBlockDevice(ReadOnlyRawBlockDevice base,
                    std::filesystem::path overlayPath,
                    std::fstream overlayStream,
                    std::map<uint64_t, uint64_t> overlayIndex);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;
  bool AppendOverlaySectors(uint64_t lba, uint16_t count, const uint8_t *data);
  // Sector data is fetched from the overlay file on demand and kept in a
  // bounded LRU (not in an unbounded map -- a large install must not grow the
  // host worker's memory by the size of everything the guest wrote).
  const Sector *CachedSector(uint64_t lba);
  const Sector *PutCache(uint64_t lba, const Sector &sector);

  ReadOnlyRawBlockDevice base_;
  std::filesystem::path overlayPath_;
  std::fstream overlayStream_;
  // lba -> byte offset of that sector's 512-byte payload inside the overlay
  // file. Compact (16 bytes/sector = ~3% of the modified data) and
  // reconstructed from the append-only records on Open (or loaded from the
  // validated `<overlay>.idx` sidecar).
  std::map<uint64_t, uint64_t> overlayIndex_;
  bool indexDirty_ = false; // persisted on close so the next open skips the scan
  bool indexFromSidecar_ = false; // last open loaded a validated sidecar
  std::unordered_map<uint64_t, CacheEntry> cache_;
  std::list<uint64_t> cacheLru_; // front = most recently used
};

class CowOverlayBlockDevice final : public IBlockDevice {
public:
  static CowOverlayBlockDevice Create(IBlockDevice *base,
                                      const std::filesystem::path &overlayPath);
  static CowOverlayBlockDevice Open(IBlockDevice *base,
                                    const std::filesystem::path &overlayPath);

  CowOverlayBlockDevice(CowOverlayBlockDevice &&) noexcept;
  CowOverlayBlockDevice &operator=(CowOverlayBlockDevice &&) noexcept;

  CowOverlayBlockDevice(const CowOverlayBlockDevice &) = delete;
  CowOverlayBlockDevice &operator=(const CowOverlayBlockDevice &) = delete;

  ~CowOverlayBlockDevice();

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  size_t OverlaySectorCount() const noexcept { return overlayIndex_.size(); }
  bool IndexLoadedFromSidecar() const noexcept { return indexFromSidecar_; }
  size_t CachedSectorCount() const noexcept { return cache_.size(); }

private:
  using Sector = std::array<uint8_t, kSectorSize>;
  struct CacheEntry {
    Sector data{};
    std::list<uint64_t>::iterator lru;
  };

  CowOverlayBlockDevice(IBlockDevice *base,
                        std::filesystem::path overlayPath,
                        std::fstream overlayStream,
                        std::map<uint64_t, uint64_t> overlayIndex);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;
  bool AppendOverlaySectors(uint64_t lba, uint16_t count, const uint8_t *data);
  const Sector *CachedSector(uint64_t lba);
  const Sector *PutCache(uint64_t lba, const Sector &sector);

  IBlockDevice *base_ = nullptr;
  std::filesystem::path overlayPath_;
  std::fstream overlayStream_;
  // lba -> payload offset in the overlay file (see CowRawBlockDevice).
  std::map<uint64_t, uint64_t> overlayIndex_;
  bool indexDirty_ = false; // persisted on close so the next open skips the scan
  bool indexFromSidecar_ = false; // last open loaded a validated sidecar
  std::unordered_map<uint64_t, CacheEntry> cache_;
  std::list<uint64_t> cacheLru_; // front = most recently used
};

struct JobMediaEntry {
  std::string name;
  std::vector<uint8_t> bytes;
};

class JobMediaBlockDevice final : public IBlockDevice {
public:
  static JobMediaBlockDevice FromEntries(const std::vector<JobMediaEntry> &entries);

  uint64_t SectorCount() const noexcept override;
  bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override;
  bool WriteSectors(uint64_t lba, uint16_t count,
                    const uint8_t *data) override;
  bool Flush() override;

  const std::vector<uint8_t> &Bytes() const noexcept { return bytes_; }

private:
  explicit JobMediaBlockDevice(std::vector<uint8_t> bytes);

  bool RangeValid(uint64_t lba, uint16_t count) const noexcept;

  std::vector<uint8_t> bytes_;
};

// Re-binds a VALIDATED COW index sidecar to a byte-for-byte copy of the overlay
// it describes (the seed-snapshot carry-over path). The source sidecar must
// validate against the source overlay first -- identity included -- and the copy
// must be the same byte length, which is what makes the mapping transferable.
// The destination sidecar is written with the COPY's file identity so the normal
// loader accepts it for the copy and only for the copy. Returns false with
// `error` set when the source sidecar is missing, stale, foreign, or corrupt;
// callers then simply pay the rebuild.
bool BindCowIndexSidecarToCopy(const std::filesystem::path &sourceOverlay,
                               const std::filesystem::path &copyOverlay,
                               std::string *error);

} // namespace antimal::hv
