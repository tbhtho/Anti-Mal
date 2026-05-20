#include "antimal/hv/Hpet.h"

#include <cstddef>

namespace antimal::hv {

namespace {

constexpr uint64_t kGeneralConfigEnable = 1ull << 0;
constexpr uint64_t kGeneralConfigLegacyRoute = 1ull << 1;
constexpr uint64_t kTimerConfigWritable =
    (1ull << 1) |  // Interrupt type.
    (1ull << 2) |  // Interrupt enable.
    (1ull << 3) |  // Periodic mode.
    (1ull << 6) |  // Set comparator value.
    (1ull << 8) |  // 32-bit mode.
    (0x1Full << 9) | // Interrupt route.
    (1ull << 14); // FSB enable.
constexpr uint64_t kTimerConfigCaps =
    (1ull << 4) |  // Periodic capable.
    (1ull << 5) |  // 64-bit capable.
    (0x0000F0FFull << 32); // IRQ route capability bitmap.

uint64_t AccessMask(uint8_t accessSize) {
  switch (accessSize) {
  case 1:
    return 0xFFull;
  case 2:
    return 0xFFFFull;
  case 4:
    return 0xFFFFFFFFull;
  case 8:
    return 0xFFFFFFFFFFFFFFFFull;
  default:
    return 0;
  }
}

uint64_t CapabilitiesRegister() {
  return (static_cast<uint64_t>(HpetDevice::kClockPeriodFs) << 32) |
         HpetDevice::kEventTimerBlockId;
}

} // namespace

HpetDevice::HpetDevice(uint64_t mmioBase) : mmioBase_(mmioBase) {}

uint64_t HpetDevice::CurrentCounter() const {
  if ((generalConfig_ & kGeneralConfigEnable) == 0) {
    return counterValue_;
  }
  const auto now = std::chrono::steady_clock::now();
  const auto delta =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now - counterEpoch_)
          .count();
  const uint64_t ticks =
      (static_cast<uint64_t>(delta) * kCounterHz) / 1000000000ull;
  return counterValue_ + ticks;
}

bool HpetDevice::RegisterWindow(uint64_t offset, uint8_t accessSize,
                                uint64_t *registerOffset,
                                uint8_t *shiftBytes) {
  if (!registerOffset || !shiftBytes || AccessMask(accessSize) == 0) {
    return false;
  }

  auto match = [&](uint64_t base) {
    if (offset >= base && offset + accessSize <= base + 8) {
      *registerOffset = base;
      *shiftBytes = static_cast<uint8_t>(offset - base);
      return true;
    }
    return false;
  };

  if (match(0x000) || match(0x010) || match(0x020) || match(0x0F0)) {
    return true;
  }
  if (offset >= 0x100 && offset < 0x100 + kTimerCount * 0x20ull) {
    const uint64_t timerBase = 0x100 + ((offset - 0x100) / 0x20ull) * 0x20ull;
    return match(timerBase) || match(timerBase + 0x08) ||
           match(timerBase + 0x10);
  }
  return false;
}

bool HpetDevice::ReadRegister(uint64_t offset, uint64_t *value) const {
  if (!value) {
    return false;
  }
  switch (offset) {
  case 0x000:
    *value = CapabilitiesRegister();
    return true;
  case 0x010:
    *value = generalConfig_ & (kGeneralConfigEnable | kGeneralConfigLegacyRoute);
    return true;
  case 0x020:
    *value = interruptStatus_;
    return true;
  case 0x0F0:
    *value = CurrentCounter();
    return true;
  default:
    break;
  }

  if (offset >= 0x100 && offset < 0x100 + kTimerCount * 0x20ull) {
    const size_t timer =
        static_cast<size_t>((offset - 0x100) / 0x20ull);
    const uint64_t timerReg = (offset - 0x100) % 0x20ull;
    if (timerReg == 0x00) {
      *value = ReadTimerConfig(timer);
      return true;
    }
    if (timerReg == 0x08) {
      *value = timers_[timer].comparator;
      return true;
    }
    if (timerReg == 0x10) {
      *value = timers_[timer].fsbRoute;
      return true;
    }
  }

  *value = 0;
  return true;
}

bool HpetDevice::WriteRegister(uint64_t offset, uint64_t value) {
  switch (offset) {
  case 0x000:
    return true; // Capabilities are read-only.
  case 0x010:
    WriteGeneralConfig(value);
    return true;
  case 0x020:
    interruptStatus_ &= ~value; // Write-one-to-clear.
    return true;
  case 0x0F0:
    WriteMainCounter(value);
    return true;
  default:
    break;
  }

  if (offset >= 0x100 && offset < 0x100 + kTimerCount * 0x20ull) {
    const size_t timer =
        static_cast<size_t>((offset - 0x100) / 0x20ull);
    const uint64_t timerReg = (offset - 0x100) % 0x20ull;
    if (timerReg == 0x00) {
      WriteTimerConfig(timer, value);
      return true;
    }
    if (timerReg == 0x08) {
      timers_[timer].comparator = value;
      return true;
    }
    if (timerReg == 0x10) {
      timers_[timer].fsbRoute = value;
      return true;
    }
  }

  return true;
}

bool HpetDevice::OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) {
  if (!outValue) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  uint64_t regOffset = 0;
  uint8_t shiftBytes = 0;
  if (!RegisterWindow(offset, accessSize, &regOffset, &shiftBytes)) {
    *outValue = AccessMask(accessSize);
    return true;
  }
  uint64_t full = 0;
  if (!ReadRegister(regOffset, &full)) {
    *outValue = AccessMask(accessSize);
    return false;
  }
  ++reads_;
  *outValue = (full >> (shiftBytes * 8u)) & AccessMask(accessSize);
  return true;
}

bool HpetDevice::OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  const uint64_t offset = gpa - mmioBase_;
  uint64_t regOffset = 0;
  uint8_t shiftBytes = 0;
  if (!RegisterWindow(offset, accessSize, &regOffset, &shiftBytes)) {
    return true;
  }
  uint64_t full = 0;
  if (!ReadRegister(regOffset, &full)) {
    return false;
  }
  const uint64_t mask = AccessMask(accessSize);
  const uint8_t shiftBits = static_cast<uint8_t>(shiftBytes * 8u);
  full = (full & ~(mask << shiftBits)) | ((value & mask) << shiftBits);
  ++writes_;
  return WriteRegister(regOffset, full);
}

void HpetDevice::WriteGeneralConfig(uint64_t value) {
  const uint64_t before = CurrentCounter();
  const bool wasEnabled = (generalConfig_ & kGeneralConfigEnable) != 0;
  generalConfig_ = value & (kGeneralConfigEnable | kGeneralConfigLegacyRoute);
  const bool isEnabled = (generalConfig_ & kGeneralConfigEnable) != 0;
  if (isEnabled) {
    counterValue_ = before;
    counterEpoch_ = std::chrono::steady_clock::now();
  } else if (wasEnabled) {
    counterValue_ = before;
  }
}

void HpetDevice::WriteMainCounter(uint64_t value) {
  counterValue_ = value;
  if ((generalConfig_ & kGeneralConfigEnable) != 0) {
    counterEpoch_ = std::chrono::steady_clock::now();
  }
}

uint64_t HpetDevice::ReadTimerConfig(size_t timer) const {
  if (timer >= timers_.size()) {
    return 0;
  }
  return (timers_[timer].config & kTimerConfigWritable) | kTimerConfigCaps;
}

void HpetDevice::WriteTimerConfig(size_t timer, uint64_t value) {
  if (timer >= timers_.size()) {
    return;
  }
  timers_[timer].config = value & kTimerConfigWritable;
}

} // namespace antimal::hv
