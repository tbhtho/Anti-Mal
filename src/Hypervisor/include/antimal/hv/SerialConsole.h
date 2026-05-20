#pragma once

// Minimal 16550-style UART emulation. COM1 captures firmware/debug output;
// COM2 is also usable as the first host<->guest production channel. The model
// supports TX capture, RX queueing, DLAB divisor registers, line/status bits,
// and receive-data interrupt state.
//
// Bytes written by the guest are captured into a growable in-memory log;
// callers can pull them as a std::string for assertions/logging. This is
// enough for our smoke tests and for capturing OVMF debug output later.
//
// COM1 base port is 0x3F8 by default. The constructor lets us instance a
// secondary console at COM2 / 0x2F8 if we ever want one.

#include "antimal/hv/Device.h"

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace antimal::hv {

class SerialConsole : public IIoPortDevice {
public:
  static constexpr uint16_t kCom1Base = 0x3F8;
  static constexpr uint16_t kCom2Base = 0x2F8;

  explicit SerialConsole(uint16_t baseIoPort = kCom1Base)
      : base_(baseIoPort) {}

  uint16_t BasePort() const noexcept { return base_; }
  uint16_t LastPort() const noexcept {
    return static_cast<uint16_t>(base_ + 7);
  }
  bool Owns(uint16_t port) const noexcept {
    return port >= base_ && port <= LastPort();
  }

  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

  void QueueRxByte(uint8_t value);
  void QueueRxBytes(const uint8_t *data, size_t size);
  void QueueRxBytes(const std::vector<uint8_t> &bytes);
  bool RxDataReady() const noexcept { return !rxQueue_.empty(); }

  // True when the guest has enabled received-data interrupts and unread host
  // bytes are waiting in the RX FIFO. The VM loop routes this to IRQ4/IRQ3
  // for COM1/COM2 respectively.
  bool InterruptPending() const noexcept;

  // Snapshot of all bytes the guest has written to the data register so far.
  std::string Captured() const {
    return std::string(captured_.begin(), captured_.end());
  }

  // Returns up to `maxBytes` of newly-captured bytes since the previous call
  // to PullNew() (or PullSince(0) / Captured() on the first call). Lets the
  // run watcher stream live serial output to the GUI without waiting for the
  // run to finish.
  std::string PullNew();

  // Returns bytes captured starting at byte offset `start`. Returns the empty
  // string if `start` is beyond the captured size.
  std::string PullSince(size_t start) const;

  size_t CapturedBytes() const noexcept { return captured_.size(); }

private:
  uint16_t base_;
  std::vector<uint8_t> captured_;
  std::deque<uint8_t> rxQueue_;
  size_t pullCursor_ = 0;
  uint8_t ier_ = 0;
  uint8_t fcr_ = 0;
  uint8_t lcr_ = 0;
  uint8_t mcr_ = 0;
  uint8_t scr_ = 0;
  uint8_t dll_ = 0;
  uint8_t dlm_ = 0;
};

} // namespace antimal::hv
