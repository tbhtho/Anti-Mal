#include "antimal/hv/E1000Device.h"

#include <cstring>
#include <vector>

namespace antimal::hv {

namespace {

constexpr uint32_t kRegCTRL = 0x0000;
constexpr uint32_t kRegSTATUS = 0x0008;
constexpr uint32_t kRegEERD = 0x0014;
constexpr uint32_t kRegMDIC = 0x0020;
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

// Statistics registers (clear-on-read), offsets per the 82574 datasheet. Only
// the counters that move with traffic are modelled; error/collision counters
// (CRCERRS 0x4000, the PRC*/PTC* size buckets, BPRC/MPRC, etc.) read 0, which is
// realistic for a clean point-to-point contained link.
constexpr uint32_t kRegMPC = 0x4010;    // Missed Packets Count (RX drops)
constexpr uint32_t kRegGPRC = 0x4074;   // Good Packets Received
constexpr uint32_t kRegGPTC = 0x4080;   // Good Packets Transmitted
constexpr uint32_t kRegGORCL = 0x4088;  // Good Octets Received (low/high)
constexpr uint32_t kRegGORCH = 0x408C;
constexpr uint32_t kRegGOTCL = 0x4090;  // Good Octets Transmitted (low/high)
constexpr uint32_t kRegGOTCH = 0x4094;
constexpr uint32_t kRegTORL = 0x40C0;   // Total Octets Received (low/high)
constexpr uint32_t kRegTORH = 0x40C4;
constexpr uint32_t kRegTOTL = 0x40C8;   // Total Octets Transmitted (low/high)
constexpr uint32_t kRegTOTH = 0x40CC;
constexpr uint32_t kRegTPR = 0x40D0;    // Total Packets Received
constexpr uint32_t kRegTPT = 0x40D4;    // Total Packets Transmitted

constexpr uint32_t kStatusFD = 1u << 0;  // full duplex
constexpr uint32_t kStatusLU = 1u << 1;  // link up
constexpr uint32_t kIntTXDW = 1u << 0;   // transmit descriptor written back
constexpr uint32_t kIntLSC = 1u << 2;    // link status change
constexpr uint32_t kIntRXT0 = 1u << 7;   // receive timer (a frame was delivered)

constexpr uint32_t kRctlEN = 1u << 1;  // RCTL.EN — receiver enabled

constexpr uint8_t kTxCmdEOP = 1u << 0;  // end of packet
constexpr uint8_t kTxCmdRS = 1u << 3;   // report status (write back DD)
constexpr uint8_t kTxStaDD = 1u << 0;   // descriptor done
constexpr uint8_t kRxStaDD = 1u << 0;   // RX descriptor done
constexpr uint8_t kRxStaEOP = 1u << 1;  // RX end of packet

// Legacy RX descriptor is 16 bytes: bufAddr(8) length(2) checksum(2) status(1)
// errors(1) special(2). A hard frame cap matching the TX guard.
constexpr uint32_t kMaxFrame = 16384;

// RX buffer size selected by RCTL.BSIZE (bits 16-17) + BSEX (bit 25). We clamp
// every delivered frame to this so a copy can never overrun the guest's posted
// buffer even if `len` is larger.
uint32_t RxBufferSize(uint32_t rctl) {
  const uint32_t bsize = (rctl >> 16) & 0x3u;
  const bool bsex = ((rctl >> 25) & 0x1u) != 0;
  if (!bsex) {
    switch (bsize) { case 0: return 2048; case 1: return 1024; case 2: return 512; default: return 256; }
  }
  switch (bsize) { case 1: return 16384; case 2: return 8192; case 3: return 4096; default: return 2048; }
}

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

// Minimal internal copper-PHY register read for the e1000 driver's link/PHY-ID
// probe via MDIC. Reports a present PHY with the link up and autoneg complete so
// the driver brings the interface up.
uint16_t PhyRead(uint32_t reg) {
  switch (reg) {
    case 0:  return 0x1140;  // control: autoneg enabled, 1000 Mbps full
    case 1:  return 0x796D;  // status: link up + autoneg complete + capabilities
    case 2:  return 0x0141;  // PHY ID high (OUI)
    case 3:  return 0x0CB1;  // PHY ID low (internal copper PHY)
    case 17: return 0x4400;  // M88-specific status: link up, resolved
    default: return 0;
  }
}

// The 82574L statistics registers are clear-on-read: each read returns the count
// accumulated since the previous read, then resets. We model that as the delta of
// a monotonic host counter against a per-register baseline, so a driver polling
// on a timer accumulates the true total without double-counting.
uint32_t StatDelta32(uint64_t total, uint64_t &base) {
  const uint32_t d = static_cast<uint32_t>(total - base);
  base = total;
  return d;
}

// 64-bit octet counters are read as a low/high register pair. Reading the LOW
// register computes the delta, returns its low 32 bits, and latches the high 32
// bits for the immediately-following high-register read (the order real drivers
// use). The high read returns and clears that latch.
uint32_t StatOctetLow(uint64_t total, uint64_t &base, uint32_t &highLatch) {
  const uint64_t d = total - base;
  base = total;
  highLatch = static_cast<uint32_t>(d >> 32);
  return static_cast<uint32_t>(d & 0xFFFFFFFFu);
}

}  // namespace

E1000Device::E1000Device() {
  Reset();
  // A real globally-administered Intel vendor MAC (OUI 00:1B:21 = Intel
  // Corporate). A locally-administered address (U/L bit 0x02 set in the first
  // octet) is a classic VM/sandbox tell — evasive malware checks for it via
  // GetAdaptersAddresses / WMI — so the first octet is 0x00 (U/L + I/G clear).
  const uint8_t mac[6] = {0x00, 0x1B, 0x21, 0x3C, 0x9A, 0x57};
  eeprom_[0] = static_cast<uint16_t>(mac[0] | (mac[1] << 8));
  eeprom_[1] = static_cast<uint16_t>(mac[2] | (mac[3] << 8));
  eeprom_[2] = static_cast<uint16_t>(mac[4] | (mac[5] << 8));
  ral_ = static_cast<uint32_t>(mac[0]) | (static_cast<uint32_t>(mac[1]) << 8) |
         (static_cast<uint32_t>(mac[2]) << 16) |
         (static_cast<uint32_t>(mac[3]) << 24);
  rah_ = static_cast<uint32_t>(mac[4]) | (static_cast<uint32_t>(mac[5]) << 8) |
         (1u << 31);  // Address Valid

  // EEPROM checksum: the Windows e1000 driver validates that the sum of all 64
  // words equals 0xBABA before it will initialize. Without a valid checksum it
  // rejects the EEPROM and never binds (nicRegisterWrites stays 0). Put a
  // plausible device-id word at 0x0D (82540EM) and compute word 0x3F so the
  // sum checks out.
  eeprom_[0x0D] = kPciDeviceId;  // device id word (82574L) some drivers read
  uint16_t sum = 0;
  for (size_t i = 0; i < 0x3F; ++i) sum = static_cast<uint16_t>(sum + eeprom_[i]);
  eeprom_[0x3F] = static_cast<uint16_t>(0xBABA - sum);
}

void E1000Device::Reset() noexcept {
  ctrl_ = 0;
  eerd_ = 0;
  mdic_ = 0;
  icr_ = 0;
  ims_ = 0;
  tctl_ = 0;
  tdbal_ = tdbah_ = tdlen_ = tdh_ = tdt_ = 0;
  rctl_ = rdbal_ = rdbah_ = rdlen_ = rdh_ = rdt_ = 0;
  linkAnnounced_ = false;
  interruptPending_ = false;
  // Guest-visible statistics restart at zero each boot: the monotonic host
  // counters persist for host-side diagnostics, so rebase the clear-on-read
  // baselines to their current values and drop the octet-high latches.
  statBaseGptc_ = statBaseTpt_ = framesTransmitted_;
  statBaseGprc_ = statBaseTpr_ = framesReceived_;
  statBaseGotc_ = statBaseTot_ = bytesTransmitted_;
  statBaseGorc_ = statBaseTor_ = bytesReceived_;
  statBaseMpc_ = framesDropped_;
  statGotcHigh_ = statTotHigh_ = statGorcHigh_ = statTorHigh_ = 0;
  // MAC (eeprom_ / ral_ / rah_) is retained across a guest reboot.
}

std::string E1000Device::DriverProgress() const {
  std::string s;
  auto add = [&](bool reached, const char *name) {
    if (!reached) return;
    if (!s.empty()) s += ',';
    s += name;
  };
  add(sawEepromRead_, "eeprom-read");
  add(sawPhyProbe_, "phy-probe");
  add(linkAnnounced_, "link-up");
  add(sawRxRing_, "rx-ring");
  add(sawRxBuffers_, "rx-buffers");
  add(sawTxRing_, "tx-ring");
  add(sawTxKick_, "tx-kick");
  return s;
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
        sawEepromRead_ = true;
        return (eerd_ & 0xFF00u) | kEerdDone |
               (static_cast<uint32_t>(data) << 16);
      }
      return eerd_;
    }
    case kRegMDIC:
      return mdic_;
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
    // Statistics (clear-on-read). For us good == total (no bad frames) and the
    // good/total registers are independent clear-on-read counters, so each keeps
    // its own baseline against the same monotonic host total.
    case kRegMPC:
      return StatDelta32(framesDropped_, statBaseMpc_);
    case kRegGPRC:
      return StatDelta32(framesReceived_, statBaseGprc_);
    case kRegTPR:
      return StatDelta32(framesReceived_, statBaseTpr_);
    case kRegGPTC:
      return StatDelta32(framesTransmitted_, statBaseGptc_);
    case kRegTPT:
      return StatDelta32(framesTransmitted_, statBaseTpt_);
    case kRegGORCL:
      return StatOctetLow(bytesReceived_, statBaseGorc_, statGorcHigh_);
    case kRegGORCH: {
      const uint32_t v = statGorcHigh_;
      statGorcHigh_ = 0;
      return v;
    }
    case kRegGOTCL:
      return StatOctetLow(bytesTransmitted_, statBaseGotc_, statGotcHigh_);
    case kRegGOTCH: {
      const uint32_t v = statGotcHigh_;
      statGotcHigh_ = 0;
      return v;
    }
    case kRegTORL:
      return StatOctetLow(bytesReceived_, statBaseTor_, statTorHigh_);
    case kRegTORH: {
      const uint32_t v = statTorHigh_;
      statTorHigh_ = 0;
      return v;
    }
    case kRegTOTL:
      return StatOctetLow(bytesTransmitted_, statBaseTot_, statTotHigh_);
    case kRegTOTH: {
      const uint32_t v = statTotHigh_;
      statTotHigh_ = 0;
      return v;
    }
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
    case kRegMDIC: {
      sawPhyProbe_ = true;
      // MDIC: bits16-20 = PHY reg, bits26-27 = opcode (01 write, 10 read).
      // Complete the transaction immediately with the Ready bit (28) set; for a
      // read, splice in the PHY register value so the driver's poll succeeds.
      const uint32_t op = (value >> 26) & 0x3u;
      const uint32_t reg = (value >> 16) & 0x1Fu;
      if (op == 2u) {  // read
        mdic_ = (value & 0x07FF0000u) | PhyRead(reg) | (1u << 28);
      } else {  // write (or other): accept it, set Ready
        mdic_ = value | (1u << 28);
      }
      break;
    }
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
      sawRxRing_ = true;
      break;
    case kRegRDBAH:
      rdbah_ = value;
      break;
    case kRegRDLEN:
      rdlen_ = value & 0xFFF80u;
      sawRxRing_ = true;
      break;
    case kRegRDH:
      rdh_ = value;
      break;
    case kRegRDT:
      rdt_ = value;
      sawRxBuffers_ = true;
      break;
    case kRegTCTL:
      tctl_ = value;
      break;
    case kRegTDBAL:
      tdbal_ = value & ~0xFu;
      sawTxRing_ = true;
      break;
    case kRegTDBAH:
      tdbah_ = value;
      break;
    case kRegTDLEN:
      tdlen_ = value & 0xFFF80u;  // 128-byte aligned
      sawTxRing_ = true;
      break;
    case kRegTDH:
      tdh_ = value;
      break;
    case kRegTDT:
      tdt_ = value;
      sawTxKick_ = true;
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

bool E1000Device::DeliverRxFrame(const uint8_t *frame, std::size_t len) {
  // Host-driven inbound delivery. Every guest-supplied field (RDLEN, RDH/RDT,
  // the descriptor's buffer GPA) is bounds-checked through dmaMemory_ and the
  // copy is length-clamped, so a hostile RX ring can't overrun host or guest
  // memory (the RX ring is new untrusted-guest-pointer handling — see header).
  if (!frame || len == 0 || !dmaMemory_) return false;
  if (!(rctl_ & kRctlEN)) { ++framesDropped_; return false; }  // RX disabled
  if (rdlen_ < 16) { ++framesDropped_; return false; }
  const uint32_t descCount = rdlen_ / 16;
  if (descCount == 0) { ++framesDropped_; return false; }
  if (rdh_ >= descCount) rdh_ = 0;          // defensive wrap
  if (rdt_ >= descCount) rdt_ = 0;          // driver-owned tail; clamp too
  if (rdh_ == rdt_) { ++framesDropped_; return false; }  // no free buffer posted

  const uint64_t base = (static_cast<uint64_t>(rdbah_) << 32) | rdbal_;
  uint8_t *desc = dmaMemory_(base + static_cast<uint64_t>(rdh_) * 16, 16);
  if (!desc) { ++framesDropped_; return false; }
  const uint64_t bufAddr = RdU64(desc);

  // Clamp the copy to the posted RX buffer size AND a hard frame cap.
  uint32_t copyLen = static_cast<uint32_t>(len);
  const uint32_t bufSize = RxBufferSize(rctl_);
  if (copyLen > bufSize) copyLen = bufSize;
  if (copyLen > kMaxFrame) copyLen = kMaxFrame;
  uint8_t *buf = dmaMemory_(bufAddr, copyLen);
  if (!buf) { ++framesDropped_; return false; }  // unbacked descriptor buffer
  std::memcpy(buf, frame, copyLen);

  // Write back the descriptor: length (offset 8, u16) + status DD|EOP (offset 12).
  desc[8] = static_cast<uint8_t>(copyLen & 0xFF);
  desc[9] = static_cast<uint8_t>((copyLen >> 8) & 0xFF);
  desc[10] = 0;  // checksum (unused)
  desc[11] = 0;
  desc[12] = kRxStaDD | kRxStaEOP;
  desc[13] = 0;  // errors

  rdh_ = (rdh_ + 1) % descCount;  // advance head past the consumed descriptor
  ++framesReceived_;
  bytesReceived_ += copyLen;
  icr_ |= kIntRXT0;
  if (ims_ & kIntRXT0) interruptPending_ = true;
  return true;
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
  ++mmioWrites_;
  // e1000 register access is 32-bit dword; drivers don't sub-dword write here.
  WriteReg(static_cast<uint32_t>(gpa - mmioBase_) & ~0x3u,
           static_cast<uint32_t>(value));
  return true;
}

}  // namespace antimal::hv
