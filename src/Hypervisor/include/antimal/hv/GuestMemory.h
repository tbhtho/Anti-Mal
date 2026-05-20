#pragma once

// Owns a host-side buffer that is mapped into the guest's physical address
// space via WHvMapGpaRange. Lifetime is tied to the partition handle passed in
// — caller must keep the WhpHost alive at least as long as this object.

#include "antimal/hv/WhpHost.h"

#include <cstddef>
#include <cstdint>

namespace antimal::hv {

enum class GuestMemoryProt : uint32_t {
  // No-access trap: mapping exists but all accesses generate memory-access
  // VM-exits. Use this for MMIO device ranges (IOAPIC, HPET) so the host
  // can emulate reads/writes without leaving the GPA unmapped (which WHP
  // may handle internally via #PF instead of exiting).
  None = WHvMapGpaRangeFlagNone,
  ReadOnly = WHvMapGpaRangeFlagRead,
  ReadWrite = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite,
  ReadExecute = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute,
  ReadWriteExecute =
      WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
};

class GuestMemoryRegion {
public:
  // Allocates `sizeBytes` of page-aligned host memory and maps it into the
  // partition starting at guest physical address `gpa`. `sizeBytes` must be a
  // multiple of the system page size (4 KiB).
  GuestMemoryRegion(const WhpHost &host, uint64_t gpa, size_t sizeBytes,
                    GuestMemoryProt prot);

  ~GuestMemoryRegion();

  GuestMemoryRegion(const GuestMemoryRegion &) = delete;
  GuestMemoryRegion &operator=(const GuestMemoryRegion &) = delete;

  uint8_t *HostPtr() noexcept { return host_; }
  const uint8_t *HostPtr() const noexcept { return host_; }
  uint64_t Gpa() const noexcept { return gpa_; }
  size_t Size() const noexcept { return size_; }

  // Convenience: copy bytes into the host-side buffer (and thus into the guest
  // view, since the same pages back both). `offset` is into the region, not an
  // absolute GPA.
  void Write(size_t offset, const void *data, size_t length);

private:
  WHV_PARTITION_HANDLE partition_ = nullptr;
  uint8_t *host_ = nullptr;
  uint64_t gpa_ = 0;
  size_t size_ = 0;
};

} // namespace antimal::hv
