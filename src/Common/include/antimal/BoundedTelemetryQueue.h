#pragma once
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace antimal {
// Single bounded handoff; draining transfers the entire current burst. I/O must
// happen after the lock is released so the ETW callback never waits on COM2.
template<class T, size_t Capacity = 2048>
class BoundedTelemetryQueue {
  static_assert(Capacity > 0);
public:
  bool TryPush(T value) {
    std::lock_guard lock(mutex_);
    if (pending_.size() >= Capacity) return false;
    pending_.push_back(std::move(value));
    return true;
  }
  std::vector<T> Drain() {
    std::vector<T> out;
    std::lock_guard lock(mutex_);
    out.reserve(pending_.size());
    while (!pending_.empty()) {
      out.push_back(std::move(pending_.front()));
      pending_.pop_front();
    }
    return out;
  }
private:
  std::mutex mutex_;
  std::deque<T> pending_;
};
}
