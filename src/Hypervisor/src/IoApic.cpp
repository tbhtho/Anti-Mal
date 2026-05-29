#include "antimal/hv/IoApic.h"

namespace antimal::hv {

namespace {

constexpr uint32_t kIoApicVersion = 0x11; // 82093AA version field.

constexpr uint64_t kMaskBit = 1ull << 16;

} // namespace

IoApic::IoApic(uint64_t mmioBase) : mmioBase_(mmioBase) {
  // Power-on default: all redirection entries masked.
  for (auto &entry : redirection_) {
    entry = kMaskBit;
  }
}

void IoApic::SetDeliveryCallback(DeliverFn callback, void *context) noexcept {
  deliver_ = callback;
  deliverContext_ = context;
}

uint32_t IoApic::IndirectRead(uint8_t index) const {
  if (index == 0x00) {
    return ioApicId_;
  }
  if (index == 0x01) {
    return kIoApicVersion |
           static_cast<uint32_t>((kRedirectionEntries - 1) << 16);
  }
  if (index == 0x02) {
    return ioApicId_; // Arbitration ID mirrors APIC ID by default.
  }
  if (index >= 0x10 && index < 0x10 + kRedirectionEntries * 2) {
    const uint32_t pair = (index - 0x10) / 2;
    const bool high = ((index - 0x10) & 1) != 0;
    const uint64_t value = redirection_[pair];
    return high ? static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFu)
                : static_cast<uint32_t>(value & 0xFFFFFFFFu);
  }
  return 0;
}

void IoApic::IndirectWrite(uint8_t index, uint32_t value) {
  if (index == 0x00) {
    ioApicId_ = value & 0x0F000000u; // Only bits 24..27 are writable.
    return;
  }
  if (index == 0x01 || index == 0x02) {
    return; // Version + Arbitration are read-only.
  }
  if (index >= 0x10 && index < 0x10 + kRedirectionEntries * 2) {
    const uint32_t pair = (index - 0x10) / 2;
    const bool high = ((index - 0x10) & 1) != 0;
    uint64_t entry = redirection_[pair];
    if (high) {
      entry = (entry & 0x00000000FFFFFFFFull) |
              (static_cast<uint64_t>(value) << 32);
    } else {
      entry = (entry & 0xFFFFFFFF00000000ull) |
              static_cast<uint64_t>(value);
    }
    redirection_[pair] = entry;
    ++writeCount_[pair];
  }
}

bool IoApic::OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) {
  if (!outValue) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  uint32_t value = 0;
  if (offset == 0x00) {
    value = ioRegSel_;
  } else if (offset == 0x10) {
    value = IndirectRead(static_cast<uint8_t>(ioRegSel_ & 0xFFu));
  } else {
    *outValue = 0;
    return true;
  }
  switch (accessSize) {
  case 1:
    *outValue = value & 0xFFu;
    break;
  case 2:
    *outValue = value & 0xFFFFu;
    break;
  default:
    *outValue = value;
    break;
  }
  return true;
}

bool IoApic::OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  const uint64_t offset = gpa - mmioBase_;
  uint32_t mask;
  switch (accessSize) {
  case 1:
    mask = 0xFFu;
    break;
  case 2:
    mask = 0xFFFFu;
    break;
  default:
    mask = 0xFFFFFFFFu;
    break;
  }
  const uint32_t v = static_cast<uint32_t>(value & mask);
  if (offset == 0x00) {
    ioRegSel_ = v;
    return true;
  }
  if (offset == 0x10) {
    IndirectWrite(static_cast<uint8_t>(ioRegSel_ & 0xFFu), v);
    return true;
  }
  return true;
}

bool IoApic::RaiseIrq(uint8_t irq) {
  if (irq >= kRedirectionEntries) {
    return false;
  }
  ++raiseCount_;
  const uint64_t entry = redirection_[irq];
  if ((entry & kMaskBit) != 0) {
    ++maskedDrops_;
    return false;
  }
  if (!deliver_) {
    return false;
  }
  const uint8_t vector = static_cast<uint8_t>(entry & 0xFFu);
  const uint32_t destination =
      static_cast<uint32_t>((entry >> 56) & 0xFFu);
  if (deliver_(deliverContext_, destination, vector)) {
    ++deliveries_;
    return true;
  }
  return false;
}

} // namespace antimal::hv
