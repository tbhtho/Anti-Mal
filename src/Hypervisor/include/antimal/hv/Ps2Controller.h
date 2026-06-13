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
  bool HasDataPending() const noexcept {
    return !keyboardQueue_.empty() || !mouseQueue_.empty();
  }
  uint8_t PendingIrqLine() const noexcept;
  void InjectKeyboardScancode(uint8_t scancode);
  void InjectKeyboardScancodes(const uint8_t *data, size_t size);
  void InjectMousePacket(uint8_t buttons, int8_t dx, int8_t dy);
  uint64_t StatusReads() const noexcept { return statusReads_; }
  uint64_t DataReads() const noexcept { return dataReads_; }
  uint64_t CommandWrites() const noexcept { return commandWrites_; }
  uint64_t DataWrites() const noexcept { return dataWrites_; }
  uint64_t KeyboardBytesQueued() const noexcept { return keyboardBytesQueued_; }
  uint64_t KeyboardBytesRead() const noexcept { return keyboardBytesRead_; }
  uint64_t MouseBytesQueued() const noexcept { return mouseBytesQueued_; }
  uint64_t MouseBytesRead() const noexcept { return mouseBytesRead_; }
  bool KeyboardPortEnabled() const noexcept { return keyboardPortEnabled_; }
  bool MousePortEnabled() const noexcept { return mousePortEnabled_; }
  bool KeyboardScanningEnabled() const noexcept {
    return keyboardScanningEnabled_;
  }

private:
  // Which device feeds the single 8042 output buffer next. Keyboard and mouse
  // have SEPARATE input queues (so a mouse byte that currently cannot raise its
  // IRQ can never head-of-line-block queued keystrokes, and vice-versa); this
  // selects the byte the guest sees on its next 0x60 read.
  enum class HeadSource { None, Keyboard, Mouse };
  HeadSource SelectHead() const noexcept;

  void QueueKeyboardByte(uint8_t value);
  void QueueMouseByte(uint8_t value);
  void HandleCommand(uint8_t command);
  void HandleDataWrite(uint8_t value);
  // A byte addressed to the AUX (mouse) device (controller command 0xD4). A real
  // PS/2 mouse returns multi-byte replies to several of these; emulate them so
  // mouclass/i8042prt mouse init completes instead of busy-polling 0x64 for the
  // missing bytes (the cold-boot "Getting devices ready" wall).
  void ProcessMouseCommand(uint8_t value);

  std::deque<uint8_t> keyboardQueue_;
  std::deque<uint8_t> mouseQueue_;
  uint8_t configurationByte_ = 0x67; // IRQ1 + IRQ12 enabled, translate on.
  uint8_t status_ = 0x14; // System flag set, command/data not pending, no data.
  uint8_t lastCommand_ = 0;
  bool expectingConfigByte_ = false;
  bool expectingOutputPortByte_ = false;
  bool expectingKeyboardOutByte_ = false;
  bool expectingMouseOutByte_ = false;
  bool expectingMouseCommandByte_ = false;
  uint8_t pendingKeyboardCommand_ = 0;
  // A mouse set-rate/set-resolution command (0xF3/0xE8) awaiting its parameter
  // byte (which arrives as the next 0xD4-prefixed data write).
  uint8_t pendingMouseCommand_ = 0;
  uint8_t mouseResolution_ = 0;
  uint8_t mouseSampleRate_ = 100;
  bool mouseDataReporting_ = false;
  bool mouseScaling21_ = false;
  bool keyboardPortEnabled_ = true;
  bool mousePortEnabled_ = true;
  bool keyboardScanningEnabled_ = true;
  uint8_t keyboardScanCodeSet_ = 1;
  uint64_t statusReads_ = 0;
  uint64_t dataReads_ = 0;
  uint64_t commandWrites_ = 0;
  uint64_t dataWrites_ = 0;
  uint64_t keyboardBytesQueued_ = 0;
  uint64_t keyboardBytesRead_ = 0;
  uint64_t mouseBytesQueued_ = 0;
  uint64_t mouseBytesRead_ = 0;
};

} // namespace antimal::hv
