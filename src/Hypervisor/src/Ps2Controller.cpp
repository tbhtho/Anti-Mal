#include "antimal/hv/Ps2Controller.h"

namespace antimal::hv {

namespace {

constexpr uint8_t kStatusOutputBufferFull = 0x01;
constexpr uint8_t kStatusInputBufferFull = 0x02;
constexpr uint8_t kStatusSystemFlag = 0x04;
constexpr uint8_t kStatusCommandLast = 0x08;
constexpr uint8_t kStatusAuxData = 0x20;

// Standard 8042 reply bytes.
constexpr uint8_t kReplyAck = 0xFA;
constexpr uint8_t kReplyPassedSelfTest = 0x55;
constexpr uint8_t kReplyPassedPortTest = 0x00;
constexpr uint8_t kReplyKeyboardId0 = 0xAB;
constexpr uint8_t kReplyKeyboardId1 = 0x83;

// Cap on each device's input queue. The guest only drains 0x60 once its i8042
// driver is up; live keyboard/mouse injected during the long pre-driver boot
// would otherwise grow the host queue without bound (and later replay seconds of
// stale input in one burst). Past the cap we drop the OLDEST byte, so memory is
// bounded and only the most recent input survives to replay.
constexpr size_t kMaxQueuedBytes = 4096;

} // namespace

Ps2Controller::Ps2Controller() = default;

void Ps2Controller::QueueKeyboardByte(uint8_t value) {
  if (keyboardQueue_.size() >= kMaxQueuedBytes) {
    keyboardQueue_.pop_front();
  }
  keyboardQueue_.push_back(value);
  ++keyboardBytesQueued_;
  status_ = static_cast<uint8_t>(status_ | kStatusOutputBufferFull);
}

void Ps2Controller::QueueMouseByte(uint8_t value) {
  if (mouseQueue_.size() >= kMaxQueuedBytes) {
    mouseQueue_.pop_front();
  }
  mouseQueue_.push_back(value);
  ++mouseBytesQueued_;
  status_ = static_cast<uint8_t>(status_ | kStatusOutputBufferFull);
}

// Pick which device's byte the guest sees next. A keyboard byte whose IRQ is
// deliverable wins (keyboard priority); otherwise a deliverable mouse byte.
// If neither IRQ is enabled (the firmware/init POLLS the status port without
// interrupts) fall back to keyboard-then-mouse so polled drains still work.
// The key property: the two queues are independent, so a mouse byte that cannot
// currently raise IRQ12 never blocks queued keystrokes (and vice-versa).
Ps2Controller::HeadSource Ps2Controller::SelectHead() const noexcept {
  const bool kbdIrq = !keyboardQueue_.empty() && keyboardPortEnabled_ &&
                      keyboardScanningEnabled_ &&
                      (configurationByte_ & 0x01u) != 0;
  if (kbdIrq) {
    return HeadSource::Keyboard;
  }
  const bool mouseIrq = !mouseQueue_.empty() && mousePortEnabled_ &&
                        (configurationByte_ & 0x02u) != 0;
  if (mouseIrq) {
    return HeadSource::Mouse;
  }
  if (!keyboardQueue_.empty()) {
    return HeadSource::Keyboard;
  }
  if (!mouseQueue_.empty()) {
    return HeadSource::Mouse;
  }
  return HeadSource::None;
}

uint8_t Ps2Controller::PendingIrqLine() const noexcept {
  switch (SelectHead()) {
  case HeadSource::Keyboard:
    return (keyboardPortEnabled_ && keyboardScanningEnabled_ &&
            (configurationByte_ & 0x01u) != 0)
               ? 1
               : 0;
  case HeadSource::Mouse:
    return (mousePortEnabled_ && (configurationByte_ & 0x02u) != 0) ? 12 : 0;
  case HeadSource::None:
    break;
  }
  return 0;
}

void Ps2Controller::InjectKeyboardScancode(uint8_t scancode) {
  QueueKeyboardByte(scancode);
}

void Ps2Controller::InjectKeyboardScancodes(const uint8_t *data, size_t size) {
  if (!data || size == 0) {
    return;
  }
  for (size_t i = 0; i < size; ++i) {
    InjectKeyboardScancode(data[i]);
  }
}

void Ps2Controller::InjectMousePacket(uint8_t buttons, int8_t dx, int8_t dy) {
  uint8_t status = static_cast<uint8_t>(0x08u | (buttons & 0x07u));
  if (dx < 0) {
    status = static_cast<uint8_t>(status | 0x10u);
  }
  if (dy < 0) {
    status = static_cast<uint8_t>(status | 0x20u);
  }
  QueueMouseByte(status);
  QueueMouseByte(static_cast<uint8_t>(dx));
  QueueMouseByte(static_cast<uint8_t>(dy));
}

void Ps2Controller::HandleCommand(uint8_t command) {
  ++commandWrites_;
  lastCommand_ = command;
  status_ = static_cast<uint8_t>(status_ | kStatusCommandLast);
  status_ = static_cast<uint8_t>(status_ & ~kStatusInputBufferFull);
  switch (command) {
  case 0x20: // Read configuration byte.
    QueueKeyboardByte(configurationByte_);
    break;
  case 0x60: // Write configuration byte (next data write).
    expectingConfigByte_ = true;
    break;
  case 0xA1: // Get controller version.
    QueueKeyboardByte(0x00);
    break;
  case 0xA7: // Disable mouse port.
    mousePortEnabled_ = false;
    break;
  case 0xA8: // Enable mouse port.
    mousePortEnabled_ = true;
    break;
  case 0xAD: // Disable keyboard port.
    keyboardPortEnabled_ = false;
    break;
  case 0xAE: // Enable keyboard port.
    keyboardPortEnabled_ = true;
    break;
  case 0xA9: // Test mouse port.
  case 0xAB: // Test keyboard port.
    QueueKeyboardByte(kReplyPassedPortTest);
    break;
  case 0xAA: // Self test.
    QueueKeyboardByte(kReplyPassedSelfTest);
    break;
  case 0xC0: // Read input port.
    QueueKeyboardByte(0x00);
    break;
  case 0xD0: // Read output port.
    QueueKeyboardByte(0x01); // A20 enabled.
    break;
  case 0xD1: // Write output port.
    expectingOutputPortByte_ = true;
    break;
  case 0xD2: // Write keyboard output buffer.
    expectingKeyboardOutByte_ = true;
    break;
  case 0xD3: // Write mouse output buffer.
    expectingMouseOutByte_ = true;
    break;
  case 0xD4: // Write next byte to mouse.
    expectingMouseCommandByte_ = true;
    break;
  case 0xFE: // Pulse output line / CPU reset. No-op in the stub.
    break;
  default:
    break;
  }
}

void Ps2Controller::HandleDataWrite(uint8_t value) {
  ++dataWrites_;
  status_ = static_cast<uint8_t>(status_ & ~kStatusInputBufferFull);
  if (expectingConfigByte_) {
    configurationByte_ = value;
    expectingConfigByte_ = false;
    return;
  }
  if (expectingOutputPortByte_) {
    expectingOutputPortByte_ = false;
    return;
  }
  if (expectingKeyboardOutByte_) {
    expectingKeyboardOutByte_ = false;
    QueueKeyboardByte(value);
    return;
  }
  if (expectingMouseOutByte_) {
    expectingMouseOutByte_ = false;
    QueueMouseByte(value);
    return;
  }
  if (expectingMouseCommandByte_) {
    expectingMouseCommandByte_ = false;
    ProcessMouseCommand(value);
    return;
  }
  if (pendingKeyboardCommand_ != 0) {
    const uint8_t command = pendingKeyboardCommand_;
    pendingKeyboardCommand_ = 0;
    QueueKeyboardByte(kReplyAck);
    if (command == 0xF0 && value == 0) {
      QueueKeyboardByte(keyboardScanCodeSet_);
    } else if (command == 0xF0 && value >= 1 && value <= 3) {
      keyboardScanCodeSet_ = value;
    }
    return;
  }
  status_ = static_cast<uint8_t>(status_ & ~kStatusCommandLast);
  switch (value) {
  case 0xED: // Set LEDs (the next byte is the LED state).
  case 0xF0: // Get/set scan code set (next byte is sub-command).
  case 0xF3: // Set typematic rate/delay (next byte is rate value).
    QueueKeyboardByte(kReplyAck);
    pendingKeyboardCommand_ = value;
    break;
  case 0xF2: // Read keyboard ID.
    QueueKeyboardByte(kReplyAck);
    QueueKeyboardByte(kReplyKeyboardId0);
    QueueKeyboardByte(kReplyKeyboardId1);
    break;
  case 0xF4: // Enable scanning.
    keyboardScanningEnabled_ = true;
    QueueKeyboardByte(kReplyAck);
    break;
  case 0xF5: // Disable scanning.
    keyboardScanningEnabled_ = false;
    QueueKeyboardByte(kReplyAck);
    break;
  case 0xFA: // ACK echo.
    QueueKeyboardByte(kReplyAck);
    break;
  case 0xFF: // Reset.
    QueueKeyboardByte(kReplyAck);
    QueueKeyboardByte(0xAA); // Basic Assurance Test passed.
    break;
  default:
    QueueKeyboardByte(kReplyAck);
    break;
  }
}

// A byte the guest addressed to the AUX (mouse) device via controller command
// 0xD4. A real PS/2 mouse returns multi-byte responses to several of these; the
// old stub's ACK-only reply truncated mouse RESET (0xFF -> ACK,BAT,ID) and
// GET-ID (0xF2 -> ACK,ID), so mouclass/i8042prt would busy-poll 0x64 waiting for
// the missing bytes during "Getting devices ready" -- the cold-boot wall. All
// replies go to the mouse queue so they carry the AUX status bit on read.
void Ps2Controller::ProcessMouseCommand(uint8_t value) {
  // A parameter byte for a prior set-sample-rate (0xF3) / set-resolution (0xE8).
  if (pendingMouseCommand_ != 0) {
    const uint8_t cmd = pendingMouseCommand_;
    pendingMouseCommand_ = 0;
    if (cmd == 0xF3) {
      mouseSampleRate_ = value;
    } else if (cmd == 0xE8) {
      mouseResolution_ = value;
    }
    QueueMouseByte(kReplyAck);
    return;
  }
  switch (value) {
  case 0xFF: // Reset: ACK + Basic Assurance Test pass + device ID (0x00 = std).
    mouseDataReporting_ = false;
    mouseScaling21_ = false;
    mouseResolution_ = 0;
    mouseSampleRate_ = 100;
    QueueMouseByte(kReplyAck);
    QueueMouseByte(0xAA);
    QueueMouseByte(0x00);
    break;
  case 0xF2: // Get device ID: ACK + 0x00 (standard PS/2 mouse).
    QueueMouseByte(kReplyAck);
    QueueMouseByte(0x00);
    break;
  case 0xE9: // Status request: ACK + status byte + resolution + sample rate.
    QueueMouseByte(kReplyAck);
    QueueMouseByte(static_cast<uint8_t>((mouseDataReporting_ ? 0x20u : 0u) |
                                        (mouseScaling21_ ? 0x10u : 0u)));
    QueueMouseByte(mouseResolution_);
    QueueMouseByte(mouseSampleRate_);
    break;
  case 0xEB: // Read data (poll): ACK + a 3-byte movement packet (no motion).
    QueueMouseByte(kReplyAck);
    QueueMouseByte(0x08); // bit3 always set, no buttons, no motion.
    QueueMouseByte(0x00);
    QueueMouseByte(0x00);
    break;
  case 0xF3: // Set sample rate -> ACK now; rate value arrives as next AUX byte.
  case 0xE8: // Set resolution  -> ACK now; resolution arrives as next AUX byte.
    pendingMouseCommand_ = value;
    QueueMouseByte(kReplyAck);
    break;
  case 0xF4: // Enable data reporting.
    mouseDataReporting_ = true;
    QueueMouseByte(kReplyAck);
    break;
  case 0xF5: // Disable data reporting.
    mouseDataReporting_ = false;
    QueueMouseByte(kReplyAck);
    break;
  case 0xF6: // Set defaults.
    mouseDataReporting_ = false;
    mouseScaling21_ = false;
    mouseResolution_ = 0;
    mouseSampleRate_ = 100;
    QueueMouseByte(kReplyAck);
    break;
  case 0xE7: // Set scaling 2:1.
    mouseScaling21_ = true;
    QueueMouseByte(kReplyAck);
    break;
  case 0xE6: // Set scaling 1:1.
    mouseScaling21_ = false;
    QueueMouseByte(kReplyAck);
    break;
  default: // Set-wrap (0xEE), reset-wrap (0xEC), and any other: bare ACK.
    QueueMouseByte(kReplyAck);
    break;
  }
}

void Ps2Controller::OnWrite(uint16_t port, uint32_t value,
                            uint8_t /*accessSize*/) {
  const uint8_t byte = static_cast<uint8_t>(value & 0xFFu);
  if (port == kStatusCommandPort) {
    HandleCommand(byte);
    return;
  }
  if (port == kDataPort) {
    HandleDataWrite(byte);
  }
}

uint32_t Ps2Controller::OnRead(uint16_t port, uint8_t /*accessSize*/) {
  if (port == kStatusCommandPort) {
    ++statusReads_;
    // The System Flag (bit 2) is set once the controller passes POST — firmware
    // and i8042prt poll for it during init, and a real controller reports it set
    // by the time the OS runs. Our controller always "passes," so report it set
    // (it was never set before, which can make the init handshake retry —
    // observed: i8042prt busy-polling the status port ~1.5M times, the dominant
    // boot CPU sink after intelppm was disabled).
    return static_cast<uint8_t>(
        (status_ & ~kStatusAuxData) | kStatusSystemFlag |
        (SelectHead() == HeadSource::Mouse ? kStatusAuxData : 0));
  }
  if (port == kDataPort) {
    ++dataReads_;
    const HeadSource head = SelectHead();
    uint8_t value = 0;
    if (head == HeadSource::Mouse) {
      value = mouseQueue_.front();
      mouseQueue_.pop_front();
      ++mouseBytesRead_;
    } else if (head == HeadSource::Keyboard) {
      value = keyboardQueue_.front();
      keyboardQueue_.pop_front();
      ++keyboardBytesRead_;
    } else {
      return 0;
    }
    if (keyboardQueue_.empty() && mouseQueue_.empty()) {
      status_ = static_cast<uint8_t>(status_ & ~kStatusOutputBufferFull);
    }
    return value;
  }
  return 0;
}

} // namespace antimal::hv
