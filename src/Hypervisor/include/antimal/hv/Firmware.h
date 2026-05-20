#pragma once

// UEFI firmware loader for the in-house hypervisor. Reads an OVMF.fd blob
// from disk and maps it into the partition at the canonical x86-64 firmware
// location: the top of the 32-bit physical address space, i.e. starting at
// (4 GiB - file_size). With this mapping the architectural CPU reset vector
// at GPA 0xFFFFFFF0 lands inside the OVMF image and the firmware boots
// naturally without any reset-state overrides.
//
// Phase 3a: just load + map the bytes; we don't run a vCPU yet. Phase 3b
// adds the low-RAM region and the minimum device set OVMF needs to print
// its banner to serial.

#include "antimal/hv/GuestMemory.h"
#include "antimal/hv/WhpHost.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

namespace antimal::hv {

class Firmware {
public:
  // 4 GiB. Firmware is mapped so its last byte sits at (kFourGib - 1).
  static constexpr uint64_t kFourGib = 0x1'0000'0000ull;

  // Architectural reset vector — first byte the CPU fetches on power-on
  // when running on a host that mirrors firmware to the top of 32-bit PA.
  static constexpr uint64_t kResetVectorGpa = 0xFFFFFFF0ull;

  // Reasonable upper bound for an OVMF blob. Real-world sizes:
  //   - 2 MiB:  EDK2 default OvmfPkgX64
  //   - 4 MiB:  OvmfPkgX64 with FD_SIZE_4MB=TRUE
  //   - 3 MiB and 3.5 MiB variants exist for specific configurations
  static constexpr size_t kMaxFirmwareBytes = 16ull * 1024ull * 1024ull;

  // Loads `path` from disk and maps it as ReadExecute in the guest. Throws
  // WhpError on missing file, zero / oversize / non-page-aligned content,
  // or partition mapping failure.
  Firmware(const WhpHost &host, const std::filesystem::path &path);

  // Guest physical address of the first byte of the firmware blob.
  uint64_t Gpa() const noexcept;

  // Size of the firmware blob in bytes.
  size_t Size() const noexcept;

  // Returns true if `gpa` falls inside the firmware mapping.
  bool ContainsGpa(uint64_t gpa) const noexcept;

  // Host-side view of the firmware bytes. Read-only externally; used by
  // tests to verify mapping. Length is Size().
  const uint8_t *HostBytes() const noexcept;

private:
  std::unique_ptr<GuestMemoryRegion> region_;
};

} // namespace antimal::hv
