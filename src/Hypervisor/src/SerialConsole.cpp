#include "antimal/hv/SerialConsole.h"

namespace antimal::hv {

namespace {

// 16550 register offsets from the base port.
constexpr uint16_t kThr = 0; // Transmitter Holding Register (write) / RBR (read)
constexpr uint16_t kIer = 1; // Interrupt Enable
constexpr uint16_t kFcr = 2; // FIFO Control (write) / IIR (read)
constexpr uint16_t kLcr = 3; // Line Control
constexpr uint16_t kMcr = 4; // Modem Control
constexpr uint16_t kLsr = 5; // Line Status
constexpr uint16_t kMsr = 6; // Modem Status
constexpr uint16_t kScr = 7; // Scratch

constexpr uint8_t kIerReceivedDataAvailable = 1u << 0;
constexpr uint8_t kIerThrEmpty = 1u << 1; // ETBEI: transmitter-empty interrupt
constexpr uint8_t kIirNoInterruptPending = 1u << 0;
constexpr uint8_t kIirThrEmpty = 0x02;
constexpr uint8_t kIirReceivedDataAvailable = 0x04;
constexpr uint8_t kLcrDlab = 1u << 7;
// LSR bits we care about: bit 0 = RX ready, bit 5 = THR empty,
// bit 6 = transmitter idle.
constexpr uint8_t kLsrDataReady = 1u << 0;
constexpr uint8_t kLsrThrEmptyReady = (1u << 5) | (1u << 6);
constexpr uint8_t kMsrCarrierReady = (1u << 4) | (1u << 5) |
                                     (1u << 7);

} // namespace

void SerialConsole::OnWrite(uint16_t port, uint32_t value, uint8_t /*accessSize*/) {
  const uint16_t offset = static_cast<uint16_t>(port - base_);
  const uint8_t byte = static_cast<uint8_t>(value & 0xFFu);
  const bool dlab = (lcr_ & kLcrDlab) != 0;
  ++stats_.registerWrites;
  switch (offset) {
  case kThr:
    if (dlab) {
      dll_ = byte;
      ++stats_.dllWrites;
    } else {
      captured_.push_back(byte);
      ++stats_.dataWrites;
      // THR was just consumed -> empty again (instantly, here). Re-arm the
      // THRE interrupt edge if the guest has it enabled, so the next ISR pass
      // is driven to write the following byte. This is what lets serial.sys
      // stream a whole frame; it self-stops once it has no more to send.
      if ((ier_ & kIerThrEmpty) != 0) {
        threIntActive_ = true;
      }
    }
    break;
  case kIer:
    if (dlab) {
      dlm_ = byte;
      ++stats_.dlmWrites;
    } else {
      const uint8_t previous = ier_;
      ier_ = byte;
      ++stats_.ierWrites;
      // Enabling ETBEI while THR is empty (always) asserts a THRE edge;
      // disabling it deasserts the latch.
      if ((byte & kIerThrEmpty) != 0 && (previous & kIerThrEmpty) == 0) {
        threIntActive_ = true;
      } else if ((byte & kIerThrEmpty) == 0) {
        threIntActive_ = false;
      }
    }
    break;
  case kFcr:
    fcr_ = byte;
    ++stats_.fcrWrites;
    // FCR bit 1 is "RX FIFO reset" — on real hardware it flushes the 16-byte
    // receive FIFO. We deliberately do NOT flush rxQueue_ here: that deque is the
    // host->guest delivery backlog (a JobStart + up to several MB of SampleChunk
    // frames the host queues before the guest opens COM2), not a 16-byte hardware
    // FIFO. serial.sys issues this reset during driver init, so flushing the
    // backlog would silently drop an in-flight authorized sample mid-transfer
    // (the "intermittent detonation" failure mode). We only record that a reset
    // was requested.
    if ((byte & (1u << 1)) != 0) {
      ++stats_.rxFifoResetRequests;
    }
    break;
  case kLcr:
    lcr_ = byte;
    ++stats_.lcrWrites;
    break;
  case kMcr:
    mcr_ = byte;
    ++stats_.mcrWrites;
    break;
  case kScr:
    scr_ = byte;
    ++stats_.scrWrites;
    break;
  default:
    break;
  }
}

void SerialConsole::QueueRxByte(uint8_t value) {
  rxQueue_.push_back(value);
  ++stats_.rxBytesQueued;
}

void SerialConsole::QueueRxBytes(const uint8_t *data, size_t size) {
  if (!data || size == 0) {
    return;
  }
  for (size_t i = 0; i < size; ++i) {
    QueueRxByte(data[i]);
  }
}

void SerialConsole::QueueRxBytes(const std::vector<uint8_t> &bytes) {
  QueueRxBytes(bytes.data(), bytes.size());
}

bool SerialConsole::InterruptPending() const noexcept {
  const bool rxInt =
      !rxQueue_.empty() && ((ier_ & kIerReceivedDataAvailable) != 0);
  // Windows serial.sys is interrupt-driven on transmit: it enables ETBEI and
  // writes bytes only from the THR-empty ISR. We deliver that interrupt via the
  // edge latch (set on ETBEI-enable / THR-write, cleared on IIR read) so a guest
  // write actually drains. Without it every COM2 WriteFile timed out at 1000ms
  // (com2DataWrites=0); modeling it as a level instead storms (serial.pdb wedge,
  // 111M IRQs) because THR is perpetually empty.
  return rxInt || threIntActive_;
}

SerialConsoleStats SerialConsole::Stats() const noexcept {
  SerialConsoleStats out = stats_;
  out.ier = ier_;
  out.fcr = fcr_;
  out.lcr = lcr_;
  out.mcr = mcr_;
  out.scr = scr_;
  out.dll = dll_;
  out.dlm = dlm_;
  out.dlab = (lcr_ & kLcrDlab) != 0;
  out.rxInterruptEnabled = (ier_ & kIerReceivedDataAvailable) != 0;
  out.rxDataReady = !rxQueue_.empty();
  return out;
}

std::string SerialConsole::PullNew() {
  if (pullCursor_ >= captured_.size()) {
    return {};
  }
  std::string out(captured_.begin() + pullCursor_, captured_.end());
  pullCursor_ = captured_.size();
  return out;
}

std::string SerialConsole::PullSince(size_t start) const {
  if (start >= captured_.size()) {
    return {};
  }
  return std::string(captured_.begin() + start, captured_.end());
}

uint32_t SerialConsole::OnRead(uint16_t port, uint8_t /*accessSize*/) {
  const uint16_t offset = static_cast<uint16_t>(port - base_);
  const bool dlab = (lcr_ & kLcrDlab) != 0;
  ++stats_.registerReads;
  switch (offset) {
  case kThr: {
    if (dlab) {
      ++stats_.dllReads;
      return dll_;
    }
    if (rxQueue_.empty()) {
      return 0;
    }
    const uint8_t byte = rxQueue_.front();
    rxQueue_.pop_front();
    ++stats_.dataReads;
    ++stats_.rxBytesRead;
    return byte;
  }
  case kIer:
    if (dlab) {
      ++stats_.dlmReads;
      return dlm_;
    }
    return ier_;
  case kFcr: {
    ++stats_.iirReads;
    // 16550 IIR priority: received-data-available (0x04) outranks
    // transmitter-empty (0x02). serial.sys reads this to pick the ISR path, so
    // a TX interrupt MUST report 0x02 (not 0x04, which would make it try to read
    // a non-existent RX byte). Reading the IIR when THRE is the source CLEARS
    // the THRE interrupt (16550 semantics); a subsequent THR write re-arms it.
    // RX is level (cleared by draining the RX FIFO), so it is not cleared here.
    const bool rxInt =
        !rxQueue_.empty() && ((ier_ & kIerReceivedDataAvailable) != 0);
    if (rxInt) {
      return kIirReceivedDataAvailable;
    }
    if (threIntActive_) {
      threIntActive_ = false;
      return kIirThrEmpty;
    }
    return kIirNoInterruptPending;
  }
  case kLcr:
    return lcr_;
  case kMcr:
    return mcr_;
  case kLsr:
    ++stats_.lsrReads;
    // Always report ready-to-transmit so guest drivers don't busy-wait.
    return kLsrThrEmptyReady | (rxQueue_.empty() ? 0 : kLsrDataReady);
  case kMsr:
    ++stats_.msrReads;
    return kMsrCarrierReady;
  case kScr:
    return scr_;
  default:
    return 0;
  }
}

} // namespace antimal::hv
