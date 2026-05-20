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

} // namespace

Ps2Controller::Ps2Controller() = default;

void Ps2Controller::QueueKeyboardByte(uint8_t value) {
  outputQueue_.push_back({value, false});
  status_ = static_cast<uint8_t>(status_ | kStatusOutputBufferFull);
}

void Ps2Controller::QueueMouseByte(uint8_t value) {
  outputQueue_.push_back({value, true});
  status_ = static_cast<uint8_t>(status_ | kStatusOutputBufferFull);
}

uint8_t Ps2Controller::PendingIrqLine() const noexcept {
  if (outputQueue_.empty()) {
    return 0;
  }
  return outputQueue_.front().aux ? 12 : 1;
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
  case 0xA8: // Enable mouse port.
  case 0xAD: // Disable keyboard port.
  case 0xAE: // Enable keyboard port.
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
  case 0xD2: // Write keyboard output buffer.
  case 0xD3: // Write mouse output buffer.
  case 0xD4: // Write next byte to mouse.
    expectingAuxOutByte_ = true;
    break;
  case 0xFE: // Pulse output line / CPU reset. No-op in the stub.
    break;
  default:
    break;
  }
}

void Ps2Controller::HandleDataWrite(uint8_t value) {
  status_ = static_cast<uint8_t>(status_ & ~kStatusInputBufferFull);
  if (expectingConfigByte_) {
    configurationByte_ = value;
    expectingConfigByte_ = false;
    return;
  }
  if (expectingAuxOutByte_) {
    expectingAuxOutByte_ = false;
    return;
  }
  status_ = static_cast<uint8_t>(status_ & ~kStatusCommandLast);
  switch (value) {
  case 0xED: // Set LEDs (the next byte is the LED state).
  case 0xF0: // Get/set scan code set (next byte is sub-command).
  case 0xF3: // Set typematic rate/delay (next byte is rate value).
    QueueKeyboardByte(kReplyAck);
    break;
  case 0xF2: // Read keyboard ID.
    QueueKeyboardByte(kReplyAck);
    QueueKeyboardByte(kReplyKeyboardId0);
    QueueKeyboardByte(kReplyKeyboardId1);
    break;
  case 0xF4: // Enable scanning.
  case 0xF5: // Disable scanning.
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
    return static_cast<uint8_t>(
        (status_ & ~kStatusAuxData) |
        (!outputQueue_.empty() && outputQueue_.front().aux ? kStatusAuxData
                                                           : 0));
  }
  if (port == kDataPort) {
    if (outputQueue_.empty()) {
      return 0;
    }
    const uint8_t value = outputQueue_.front().value;
    outputQueue_.pop_front();
    if (outputQueue_.empty()) {
      status_ = static_cast<uint8_t>(status_ & ~kStatusOutputBufferFull);
    }
    return value;
  }
  return 0;
}

} // namespace antimal::hv
