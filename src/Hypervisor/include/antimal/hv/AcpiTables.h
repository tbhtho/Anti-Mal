#pragma once

// Minimal ACPI table builder for the in-house PC profile. OVMF consumes these
// blobs through the QEMU fw_cfg "etc/acpi/*" files and installs them before
// handing control to Windows.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace antimal::hv {

struct AcpiTableOffsets {
  uint32_t facs = 0;
  uint32_t dsdt = 0;
  uint32_t fadt = 0;
  uint32_t madt = 0;
  uint32_t waet = 0;
  uint32_t hpet = 0;
  uint32_t rsdt = 0;
};

struct AcpiBuildArtifacts {
  std::vector<uint8_t> tables;
  std::vector<uint8_t> tableLoader;
  std::vector<uint8_t> rsdp;
  AcpiTableOffsets offsets;
};

AcpiBuildArtifacts BuildPcAcpiTables(uint32_t processorCount = 1);

bool AcpiChecksumValid(const uint8_t *bytes, size_t size);
uint32_t AcpiTableLength(const std::vector<uint8_t> &blob, uint32_t offset);
uint32_t AcpiEisaId(const char id[8]);

} // namespace antimal::hv
