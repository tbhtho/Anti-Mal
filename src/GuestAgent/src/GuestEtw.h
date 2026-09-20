#pragma once
#include "antimal/Types.h"
#include <memory>
#include <vector>

// Guest-only real-time ETW. Does not enable a NIC or open outbound sockets.
// Owns one named session; never attaches to or stops somebody else's session.
class GuestEtw {
public:
  GuestEtw();
  ~GuestEtw();
  void Stop();
  GuestEtw(const GuestEtw&) = delete;
  GuestEtw& operator=(const GuestEtw&) = delete;
  std::vector<antimal::EventRecord> Drain();
  std::vector<antimal::EventRecord> Coverage();
private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
