#pragma once

// GPA-range dispatcher for MMIO accesses. Mirrors IoBus but routes by guest
// physical address. The VirtualMachine MMIO exit handler hands each exit to
// MmioBus, which forwards to whichever IMmioDevice claims the address.

#include "antimal/hv/Device.h"

#include <cstdint>
#include <vector>

namespace antimal::hv {

class MmioBus {
public:
  void Attach(IMmioDevice *device);

  bool Read(uint64_t gpa, uint8_t accessSize, uint64_t *outValue);
  bool Write(uint64_t gpa, uint8_t accessSize, uint64_t value);

  // Returns the device that owns `gpa`, or nullptr if no device claims it.
  IMmioDevice *Find(uint64_t gpa) const;

private:
  std::vector<IMmioDevice *> devices_;
};

} // namespace antimal::hv
