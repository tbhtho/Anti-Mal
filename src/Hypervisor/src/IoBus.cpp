#include "antimal/hv/IoBus.h"

namespace antimal::hv {

void IoBus::Attach(IIoPortDevice *device, uint16_t firstPort, uint16_t lastPort) {
  registrations_.push_back({device, firstPort, lastPort});
}

bool IoBus::Write(uint16_t port, uint32_t value, uint8_t accessSize) {
  // Iterate newest-first so later attachments shadow earlier ones for any
  // overlap. Linear scan is fine — single-digit number of devices in a VM.
  for (auto it = registrations_.rbegin(); it != registrations_.rend(); ++it) {
    if (port >= it->firstPort && port <= it->lastPort) {
      it->device->OnWrite(port, value, accessSize);
      return true;
    }
  }
  return false;
}

bool IoBus::Read(uint16_t port, uint8_t accessSize, uint32_t *outValue) {
  for (auto it = registrations_.rbegin(); it != registrations_.rend(); ++it) {
    if (port >= it->firstPort && port <= it->lastPort) {
      *outValue = it->device->OnRead(port, accessSize);
      return true;
    }
  }
  // Unclaimed port: synthesize a "no device present" reply. Real hardware
  // returns all-ones for absent IO ports; lots of guest probes depend on
  // this to distinguish "missing" from "zero".
  *outValue = 0xFFFFFFFFu;
  return false;
}

} // namespace antimal::hv
