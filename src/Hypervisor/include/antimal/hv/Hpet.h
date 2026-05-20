#pragma once

// Minimal HPET block for Windows boot timing. The first version exposes the
// standard MMIO register surface, a free-running 64-bit main counter, and
// writable timer configuration/comparator registers. Timer interrupt delivery
// can layer on top once the guest starts programming HPET comparators.

#include "antimal/hv/Device.h"

#include <array>
#include <chrono>
#include <cstdint>

namespace antimal::hv {

class HpetDevice final : public IMmioDevice {
public:
  static constexpr uint64_t kDefaultMmioBase = 0xFED00000ull;
  static constexpr uint64_t kMmioSize = 0x400ull;
  static constexpr uint32_t kTimerCount = 3;
  static constexpr uint64_t kCounterHz = 10000000ull;
  static constexpr uint32_t kClockPeriodFs = 100000000u;
  static constexpr uint32_t kEventTimerBlockId = 0x8086A201u;

  explicit HpetDevice(uint64_t mmioBase = kDefaultMmioBase);

  uint64_t MmioBase() const noexcept override { return mmioBase_; }
  uint64_t MmioLast() const noexcept override {
    return mmioBase_ + kMmioSize - 1;
  }

  bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) override;
  bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) override;

  uint64_t Reads() const noexcept { return reads_; }
  uint64_t Writes() const noexcept { return writes_; }
  uint64_t CurrentCounter() const;

private:
  struct Timer {
    uint64_t config = 0;
    uint64_t comparator = 0;
    uint64_t fsbRoute = 0;
  };

  bool ReadRegister(uint64_t offset, uint64_t *value) const;
  bool WriteRegister(uint64_t offset, uint64_t value);
  static bool RegisterWindow(uint64_t offset, uint8_t accessSize,
                             uint64_t *registerOffset,
                             uint8_t *shiftBytes);
  void WriteGeneralConfig(uint64_t value);
  void WriteMainCounter(uint64_t value);
  uint64_t ReadTimerConfig(size_t timer) const;
  void WriteTimerConfig(size_t timer, uint64_t value);

  uint64_t mmioBase_;
  uint64_t generalConfig_ = 0;
  uint64_t interruptStatus_ = 0;
  uint64_t counterValue_ = 0;
  mutable std::chrono::steady_clock::time_point counterEpoch_{};
  std::array<Timer, kTimerCount> timers_{};
  uint64_t reads_ = 0;
  uint64_t writes_ = 0;
};

} // namespace antimal::hv
