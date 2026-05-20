#pragma once

// QEMU Std VGA / Bochs VBE display device. OVMF's QemuVideoDxe driver scans
// the PCI bus for vendor 0x1234 / device 0x1111 and, when it finds one, wires
// the device's BAR0 framebuffer to the UEFI GOP protocol. From that point
// on the firmware + bootloader + Windows kernel render their graphics into
// this linear framebuffer — which we mirror to host memory and dump as PNG
// frames so the AntiMal GUI filmstrip shows actual guest pixels.
//
// Register protocol (subset implemented):
//   I/O 0x1CE  : VBE_DISPI_INDEX_PORT  (write the index to access)
//   I/O 0x1CF  : VBE_DISPI_DATA_PORT   (x86 read/write data port)
//   I/O 0x1D0  : VBE_DISPI_DATA_PORT   (aligned QEMU/coreboot variant)
//
// Indices we honor:
//   0x0 : DISPI_INDEX_ID         — reads back 0xB0C5 (VBE Bochs extension v5).
//   0x1 : DISPI_INDEX_XRES       — width  in pixels  (write to set).
//   0x2 : DISPI_INDEX_YRES       — height in pixels  (write to set).
//   0x3 : DISPI_INDEX_BPP        — bits per pixel.
//   0x4 : DISPI_INDEX_ENABLE     — bit 0 sets the mode.
//   0x8 : DISPI_INDEX_X_OFFSET
//   0x9 : DISPI_INDEX_Y_OFFSET
//   0xA : DISPI_INDEX_VIDEO_MEMORY_64K — reports framebuffer size / 64 KiB.

#include "antimal/hv/Device.h"

#include <array>
#include <cstdint>

namespace antimal::hv {

class BochsVbeDevice final : public IIoPortDevice {
public:
  // Default linear framebuffer placement. OVMF's i440fx PCI allocator starts
  // the 32-bit MMIO aperture at 2 GiB for our low-RAM profile and assigns the
  // standard VGA BAR there before QemuVideoDxe clears the screen.
  static constexpr uint64_t kFramebufferGpa = 0x80000000ull;
  static constexpr size_t kFramebufferSize = 16ull * 1024ull * 1024ull;

  static constexpr uint16_t kIndexPort = 0x01CE;
  static constexpr uint16_t kDataPort = 0x01CF;
  static constexpr uint16_t kDataPortAligned = 0x01D0;

  // VBE register indices. Names match the upstream Bochs / QEMU defines.
  enum VbeIndex : uint16_t {
    DispiIndexId = 0,
    DispiIndexXres = 1,
    DispiIndexYres = 2,
    DispiIndexBpp = 3,
    DispiIndexEnable = 4,
    DispiIndexBank = 5,
    DispiIndexVirtWidth = 6,
    DispiIndexVirtHeight = 7,
    DispiIndexXOffset = 8,
    DispiIndexYOffset = 9,
    DispiIndexVideoMemory64K = 0xA,
  };

  BochsVbeDevice();

  void SetFramebufferHostBytes(uint8_t *host, size_t size) noexcept;

  // Mode info as last programmed by the guest. Reads are cheap and safe to
  // call from another thread (no synchronization is needed because the
  // register file is a fixed-size array of uint16_t and only ever ratchets
  // forward; readers tolerate transient inconsistency).
  uint16_t Width() const noexcept { return regs_[DispiIndexXres]; }
  uint16_t Height() const noexcept { return regs_[DispiIndexYres]; }
  uint16_t Bpp() const noexcept { return regs_[DispiIndexBpp]; }
  bool Enabled() const noexcept {
    return (regs_[DispiIndexEnable] & 0x01u) != 0;
  }

  const uint8_t *FramebufferHost() const noexcept { return framebufferHost_; }
  uint8_t *FramebufferHost() noexcept { return framebufferHost_; }
  size_t FramebufferBytes() const noexcept { return framebufferSize_; }

  // IIoPortDevice
  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

private:
  uint16_t index_ = 0;
  std::array<uint16_t, 16> regs_{};
  uint8_t *framebufferHost_ = nullptr;
  size_t framebufferSize_ = 0;
};

} // namespace antimal::hv
