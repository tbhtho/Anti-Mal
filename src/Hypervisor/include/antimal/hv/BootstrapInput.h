#pragma once
#include <chrono>
#include <cstdint>
#include <utility>
#include <vector>

namespace antimal::hv {
struct BootstrapKeyboardBurst {
  std::chrono::milliseconds delay{0};
  std::vector<uint8_t> scancodes;
};

// Boot UI retries must never resume after application launch or live takeover.
class BootstrapInputSchedule {
public:
  BootstrapInputSchedule(std::vector<uint8_t> initial,
                         std::chrono::milliseconds initialDelay,
                         std::vector<BootstrapKeyboardBurst> bursts)
      : bursts_(std::move(bursts)) {
    if (!initial.empty())
      bursts_.insert(bursts_.begin(), {initialDelay, std::move(initial)});
  }
  template <typename Inject>
  void Tick(std::chrono::milliseconds elapsed, bool cancel, Inject inject) {
    if (cancel) cancelled_ = true;
    if (cancelled_) {
      bursts_.clear();
      return;
    }
    for (auto &burst : bursts_) {
      if (!burst.scancodes.empty() && elapsed >= burst.delay) {
        inject(burst.scancodes);
        burst.scancodes.clear();
      }
    }
  }
private:
  bool cancelled_ = false;
  std::vector<BootstrapKeyboardBurst> bursts_;
};
} // namespace antimal::hv
