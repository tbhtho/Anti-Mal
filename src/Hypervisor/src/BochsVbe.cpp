#include "antimal/hv/BochsVbe.h"

namespace antimal::hv {

namespace {

constexpr uint16_t kVbeBochsVersion = 0xB0C5; // VBE Bochs v5 ID, what OVMF expects.

} // namespace

BochsVbeDevice::BochsVbeDevice() {
  regs_[DispiIndexId] = kVbeBochsVersion;
  // 16 MiB linear framebuffer reported in 64 KiB units.
  regs_[DispiIndexVideoMemory64K] =
      static_cast<uint16_t>(kFramebufferSize / (64ull * 1024ull));
}

void BochsVbeDevice::SetFramebufferHostBytes(uint8_t *host,
                                             size_t size) noexcept {
  framebufferHost_ = host;
  framebufferSize_ = size;
}

void BochsVbeDevice::OnWrite(uint16_t port, uint32_t value,
                             uint8_t /*accessSize*/) {
  if (port == kIndexPort) {
    index_ = static_cast<uint16_t>(value & 0xFFFFu);
    return;
  }
  if (port == kDataPort || port == kDataPortAligned) {
    const uint16_t v = static_cast<uint16_t>(value & 0xFFFFu);
    if (index_ < regs_.size()) {
      // ID register is read-only.
      if (index_ != DispiIndexId) {
        regs_[index_] = v;
      }
    }
    return;
  }
}

uint32_t BochsVbeDevice::OnRead(uint16_t port, uint8_t /*accessSize*/) {
  if (port == kIndexPort) {
    return index_;
  }
  if (port == kDataPort || port == kDataPortAligned) {
    if (index_ < regs_.size()) {
      return regs_[index_];
    }
    return 0;
  }
  return 0;
}

} // namespace antimal::hv
