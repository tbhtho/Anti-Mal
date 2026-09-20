#pragma once
#include <cstdint>

namespace antimal {
// Host-owned, bounded wait for the guest to flush cached filesystem metadata.
// A missing/old/unresponsive guest must not keep finalization waiting forever.
class GuestFlushGate {
public:
  enum class State { Idle, Waiting, Complete, Failed, TimedOut };
  bool Request(uint64_t nowMs) {
    if (state_ != State::Idle) return false;
    state_ = State::Waiting;
    startedMs_ = nowMs;
    return true;
  }
  void Reply(bool success) {
    if (state_ == State::Waiting)
      state_ = success ? State::Complete : State::Failed;
  }
  bool ShouldStop(uint64_t nowMs) {
    if (state_ == State::Waiting && nowMs >= startedMs_ &&
        nowMs - startedMs_ >= 30000)
      state_ = State::TimedOut;
    return state_ == State::Complete || state_ == State::Failed ||
           state_ == State::TimedOut;
  }
  State GetState() const { return state_; }
private:
  State state_ = State::Idle;
  uint64_t startedMs_ = 0;
};
} // namespace antimal
