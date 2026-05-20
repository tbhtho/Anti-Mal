#pragma once

// Minimal Intel 8042 PS/2 controller stub. v1 is enough to keep OVMF and the
// Windows boot loader from getting stuck on keyboard-controller probes while
// the rest of the VM bring-up matures: ports 0x60 (data) and 0x64 (status /
// command) respond plausibly, RESET/SELF-TEST commands return success, and
// data reads drain the controller's input queue. Host code can also inject
// keyboard scancodes and PS/2 mouse packets; the VM loop maps queued bytes to
// IRQ1 or IRQ12 based on the byte's source.

#include "antimal/hv/Device.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>

namespace antimal::hv {

class Ps2Controller final : public IIoPortDevice {
public:
  static constexpr uint16_t kDataPort = 0x60;
  static constexpr uint16_t kStatusCommandPort = 0x64;

  Ps2Controller();

  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

  // True when the controller has at least one byte ready for the guest to
  // read on port 0x60. Used by the host loop to decide whether to assert
  // IRQ 1 (keyboard) or IRQ 12 (mouse).
  bool HasDataPending() const noexcept { return !outputQueue_.empty(); }
  uint8_t PendingIrqLine() const noexcept;
  void InjectKeyboardScancode(uint8_t scancode);
  void InjectKeyboardScancodes(const uint8_t *data, size_t size);
  void InjectMousePacket(uint8_t buttons, int8_t dx, int8_t dy);

private:
  struct OutputByte {
    uint8_t value = 0;
    bool aux = false;
  };

  void QueueKeyboardByte(uint8_t value);
  void QueueMouseByte(uint8_t value);
  void HandleCommand(uint8_t command);
  void HandleDataWrite(uint8_t value);

  std::deque<OutputByte> outputQueue_;
  uint8_t configurationByte_ = 0x65; // IRQ1 + IRQ12 enabled, translate on.
  uint8_t status_ = 0x14; // System flag set, command/data not pending, no data.
  uint8_t lastCommand_ = 0;
  bool expectingConfigByte_ = false;
  bool expectingAuxOutByte_ = false;
};

} // namespace antimal::hv
