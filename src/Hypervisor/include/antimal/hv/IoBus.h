#pragma once

// Port-range dispatcher for IO-port accesses. The host run-loop hands each
// IoPortAccess exit to an IoBus, which forwards to whichever IIoPortDevice
// claims the port. Ports unclaimed by any device get a default "writes
// ignored, reads return 0xFFFFFFFF" treatment — same convention real
// platforms use for unmapped IO ports, so guest probes for absent hardware
// produce a sensible "not present" reply instead of looking like a successful
// read of 0.

#include "antimal/hv/Device.h"

#include <cstdint>
#include <vector>

namespace antimal::hv {

class IoBus {
public:
  // Registers `device` to receive IO accesses to ports in [firstPort, lastPort]
  // (inclusive on both ends). Overlapping registrations are allowed; later
  // attachments take priority over earlier ones for overlapping ports.
  void Attach(IIoPortDevice *device, uint16_t firstPort, uint16_t lastPort);

  // Dispatches a write to the device claiming `port`. Returns true if a
  // device handled it, false if it fell through to the default behavior
  // (no-op for writes). The caller should advance the vCPU RIP regardless.
  bool Write(uint16_t port, uint32_t value, uint8_t accessSize);

  // Dispatches a read from the device claiming `port`. The value is written
  // to `*outValue`. Returns true if a device handled it; if false, fills
  // `*outValue` with the "no device present" sentinel 0xFFFFFFFF (masked to
  // accessSize by the caller as appropriate).
  bool Read(uint16_t port, uint8_t accessSize, uint32_t *outValue);

private:
  struct Registration {
    IIoPortDevice *device;
    uint16_t firstPort;
    uint16_t lastPort;
  };
  std::vector<Registration> registrations_;
};

} // namespace antimal::hv
