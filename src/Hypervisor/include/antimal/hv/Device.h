#pragma once

// Device interfaces for the in-house hypervisor. Devices subscribe to a port
// (or port range) and the host run-loop dispatches IO-port and MMIO exits to
// the matching device.
//
// Phase 2 only models IIoPortDevice (PIO). MMIO comes online in Phase 3
// when we start emulating LAPIC / PIC / framebuffer-style devices.

#include <cstdint>

namespace antimal::hv {

class IIoPortDevice {
public:
  virtual ~IIoPortDevice() = default;

  // Called when the guest executes `out` to a port owned by this device.
  // `value` carries the operand (low `accessSize` bytes are meaningful).
  // `accessSize` is 1, 2, or 4.
  virtual void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) = 0;

  // Called when the guest executes `in` from a port owned by this device.
  // Returns the read value in the low `accessSize` bytes; upper bits ignored.
  virtual uint32_t OnRead(uint16_t port, uint8_t accessSize) = 0;
};

class IMmioDevice {
public:
  virtual ~IMmioDevice() = default;

  // Guest physical address range the device claims, inclusive on both ends.
  virtual uint64_t MmioBase() const noexcept = 0;
  virtual uint64_t MmioLast() const noexcept = 0;

  // Called when the guest reads `accessSize` bytes (1, 2, 4, or 8) at `gpa`.
  // Writes the value to `*outValue`. Returns true on success.
  virtual bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) = 0;

  // Called when the guest writes `accessSize` bytes (1, 2, 4, or 8) to `gpa`
  // with the operand in the low bits of `value`.
  virtual bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) = 0;
};

} // namespace antimal::hv
