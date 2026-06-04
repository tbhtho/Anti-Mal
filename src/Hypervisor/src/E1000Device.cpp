#include "antimal/hv/E1000Device.h"

#include <vector>

namespace antimal::hv {

namespace {

constexpr uint32_t kRegCTRL = 0x0000;
constexpr uint32_t kRegSTATUS = 0x0008;
constexpr uint32_t kRegEERD = 0x0014;
constexpr uint32_t kRegICR = 0x00C0;
constexpr uint32_t kRegIMS = 0x00D0;
constexpr uint32_t kRegIMC = 0x00D8;
constexpr uint32_t kRegRCTL = 0x0100;
constexpr uint32_t kRegTCTL = 0x0400;
constexpr uint32_t kRegTDBAL = 0x3800;
constexpr uint32_t kRegTDBAH = 0x3804;
constexpr uint32_t kRegTDLEN = 0x3808;
constexpr uint32_t kRegTDH = 0x3810;
constexpr uint32_t kRegTDT = 0x3818;
constexpr uint32_t kRegRAL = 0x5400;
constexpr uint32_t kRegRAH = 0x5404;
constexpr uint32_t kRegRDBAL = 0x2800;
constexpr uint32_t kRegRDBAH = 0x2804;
constexpr uint32_t kRegRDLEN = 0x2808;
constexpr uint32_t kRegRDH = 0x2810;
constexpr uint32_t kRegRDT = 0x2818;

constexpr uint32_t kStatusFD = 1u << 0;  // full duplex
constexpr uint32_t kStatusLU = 1u << 1;  // link up
constexpr uint32_t kIntTXDW = 1u << 0;   // transmit descriptor written back
constexpr uint32_t kIntLSC = 1u << 2;    // link status change

constexpr uint8_t kTxCmdEOP = 1u << 0;  // end of packet
constexpr uint8_t kTxCmdRS = 1u << 3;   // report status (write back DD)
constexpr uint8_t kTxStaDD = 1u << 0;   // descriptor done

constexpr uint32_t kEerdStart = 1u << 0;
constexpr uint32_t kEerdDone = 1u << 4;

uint16_t RdU16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint64_t RdU64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
  return v;
}

}  // namespace

E1000Device::E1000Device() {
  Reset();
  // A locally-administered MAC: 02:A1:A1:00:00:01.
  const uint8_t mac[6] = {0x02, 0xA1, 0xA1, 0x00, 0x00, 0x01};
  eeprom_[0] = static_cast<uint16_t>(mac[0] | (mac[1] << 8));
  eeprom_[1] = static_cast<uint16_t>(mac[2] | (mac[3] << 8));
  eeprom_[2] = static_cast<uint16_t>(mac[4] | (mac[5] << 8));
  ral_ = static_cast<uint32_t>(mac[0]) | (static_cast<uint32_t>(mac[1]) << 8) |
         (static_cast<uint32_t>(mac[2]) << 16) |
         (static_cast<uint32_t>(mac[3]) << 24);
  rah_ = static_cast<uint32_t>(mac[4]) | (static_cast<uint32_t>(mac[5]) << 8) |
         (1u << 31);  // Address Valid
}

void E1000Device::Reset() noexcept {
  ctrl_ = 0;
  eerd_ = 0;
  icr_ = 0;
  ims_ = 0;
  tctl_ = 0;
  tdbal_ = tdbah_ = tdlen_ = tdh_ = tdt_ = 0;
  rctl_ = rdbal_ = rdbah_ = rdlen_ = rdh_ = rdt_ = 0;
  linkAnnounced_ = false;
  interruptPending_ = false;
  // MAC (eeprom_ / ral_ / rah_) is retained across a guest reboot.
}

uint32_t E1000Device::ReadReg(uint32_t off) {
  switch (off) {
    case kRegCTRL:
      return ctrl_;
    case kRegSTATUS:
      return kStatusLU | kStatusFD;  // link up, full duplex
    case kRegEERD: {
      const uint32_t addr = (eerd_ >> 8) & 0xFF;
      const uint16_t data =
          addr < eeprom_.size() ? eeprom_[addr] : static_cast<uint16_t>(0);
      if (eerd_ & kEerdStart) {
        return (eerd_ & 0xFF00u) | kEerdDone |
               (static_cast<uint32_t>(data) << 16);
      }
      return eerd_;
    }
    case kRegICR: {
      const uint32_t v = icr_;
      icr_ = 0;  // read clears
      return v;
    }
    case kRegIMS:
      return ims_;
    case kRegTCTL:
      return tctl_;
    case kRegTDBAL:
      return tdbal_;
    case kRegTDBAH:
      return tdbah_;
    case kRegTDLEN:
      return tdlen_;
    case kRegTDH:
      return tdh_;
    case kRegTDT:
      return tdt_;
    case kRegRAL:
      return ral_;
    case kRegRAH:
      return rah_;
    case kRegRCTL:
      return rctl_;
    case kRegRDBAL:
      return rdbal_;
    case kRegRDBAH:
      return rdbah_;
    case kRegRDLEN:
      return rdlen_;
    case kRegRDH:
      return rdh_;
    case kRegRDT:
      return rdt_;
    default:
      return 0;
  }
}

void E1000Device::WriteReg(uint32_t off, uint32_t value) {
  switch (off) {
    case kRegCTRL:
      ctrl_ = value;
      break;
    case kRegEERD:
      eerd_ = value;
      break;
    case kRegICR:
      icr_ &= ~value;  // write 1 to clear
      break;
    case kRegIMS:
      ims_ |= value;
      // The driver enables interrupts (incl. Link Status Change) then waits for
      // an LSC to learn the link is up. Announce link-up once so it brings the
      // interface up and proceeds to TX (STATUS already reports LU=1).
      if ((value & kIntLSC) && !linkAnnounced_) {
        linkAnnounced_ = true;
        icr_ |= kIntLSC;
        interruptPending_ = true;
      }
      break;
    case kRegIMC:
      ims_ &= ~value;
      break;
    case kRegRCTL:
      rctl_ = value;
      break;
    case kRegRDBAL:
      rdbal_ = value & ~0xFu;
      break;
    case kRegRDBAH:
      rdbah_ = value;
      break;
    case kRegRDLEN:
      rdlen_ = value & 0xFFF80u;
      break;
    case kRegRDH:
      rdh_ = value;
      break;
    case kRegRDT:
      rdt_ = value;
      break;
    case kRegTCTL:
      tctl_ = value;
      break;
    case kRegTDBAL:
      tdbal_ = value & ~0xFu;
      break;
    case kRegTDBAH:
      tdbah_ = value;
      break;
    case kRegTDLEN:
      tdlen_ = value & 0xFFF80u;  // 128-byte aligned
      break;
    case kRegTDH:
      tdh_ = value;
      break;
    case kRegTDT:
      tdt_ = value;
      ProcessTx();  // the tail bump is what kicks transmission
      break;
    case kRegRAL:
      ral_ = value;
      break;
    case kRegRAH:
      rah_ = value;
      break;
    default:
      break;
  }
}

void E1000Device::ProcessTx() {
  if (!dmaMemory_ || tdlen_ < 16) return;
  const uint32_t descCount = tdlen_ / 16;
  if (descCount == 0) return;
  if (tdh_ >= descCount) tdh_ = 0;
  const uint64_t base = (static_cast<uint64_t>(tdbah_) << 32) | tdbal_;

  std::vector<uint8_t> frame;
  uint32_t guard = 0;
  while (tdh_ != tdt_ && guard++ <= descCount) {
    uint8_t *desc = dmaMemory_(base + static_cast<uint64_t>(tdh_) * 16, 16);
    if (!desc) break;
    const uint64_t bufAddr = RdU64(desc);
    const uint16_t len = RdU16(desc + 8);
    const uint8_t cmd = desc[11];
    if (len > 0 && len <= 16384) {
      uint8_t *buf = dmaMemory_(bufAddr, len);
      if (buf) frame.insert(frame.end(), buf, buf + len);
    }
    if (cmd & kTxCmdRS) desc[12] |= kTxStaDD;  // status write-back
    tdh_ = (tdh_ + 1) % descCount;
    if (cmd & kTxCmdEOP) {
      if (!frame.empty()) {
        bytesTransmitted_ += frame.size();
        ++framesTransmitted_;
        if (txHandler_) txHandler_(frame.data(), frame.size());
      }
      frame.clear();
    }
    if (frame.size() > 65536) {  // runaway/jumbo guard
      frame.clear();
      break;
    }
  }
  icr_ |= kIntTXDW;
  if (ims_ & kIntTXDW) interruptPending_ = true;
}

bool E1000Device::OnRead(uint64_t gpa, uint8_t /*accessSize*/, uint64_t *out) {
  if (!out || gpa < mmioBase_ || gpa > MmioLast()) return false;
  const uint32_t rel = static_cast<uint32_t>(gpa - mmioBase_);
  uint32_t v = ReadReg(rel & ~0x3u);
  v >>= (rel & 0x3u) * 8;  // sub-dword read
  *out = v;
  return true;
}

bool E1000Device::OnWrite(uint64_t gpa, uint8_t /*accessSize*/, uint64_t value) {
  if (gpa < mmioBase_ || gpa > MmioLast()) return false;
  // e1000 register access is 32-bit dword; drivers don't sub-dword write here.
  WriteReg(static_cast<uint32_t>(gpa - mmioBase_) & ~0x3u,
           static_cast<uint32_t>(value));
  return true;
}

}  // namespace antimal::hv
