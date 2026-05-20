#pragma once

// Local virtual-disk metadata access for the in-house backend. This uses the
// Windows Virtual Disk API directly; it does not attach/mount the disk and does
// not launch any VM manager.

#include <cstdint>
#include <filesystem>

namespace antimal::hv {

struct VirtualDiskInfo {
  uint64_t virtualSize = 0;
  uint64_t physicalSize = 0;
  uint32_t blockSize = 0;
  uint32_t sectorSize = 0;
  uint32_t vhdPhysicalSectorSize = 0;
  uint32_t providerSubtype = 0;
  bool isLoaded = false;
};

class VirtualDisk {
public:
  static VirtualDisk OpenReadOnly(const std::filesystem::path &path);
  static void CreateDifferencing(const std::filesystem::path &parentPath,
                                 const std::filesystem::path &childPath);
  ~VirtualDisk();

  VirtualDisk(VirtualDisk &&other) noexcept;
  VirtualDisk &operator=(VirtualDisk &&other) noexcept;

  VirtualDisk(const VirtualDisk &) = delete;
  VirtualDisk &operator=(const VirtualDisk &) = delete;

  const std::filesystem::path &Path() const noexcept { return path_; }
  VirtualDiskInfo QueryInfo() const;

private:
  VirtualDisk(std::filesystem::path path, void *handle);

  std::filesystem::path path_;
  void *handle_ = nullptr;
};

} // namespace antimal::hv
