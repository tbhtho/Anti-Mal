#include "antimal/hv/AhciController.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace antimal::hv {
namespace {

// Host Capabilities (CAP): S64A (bit31) + ISS=Gen2 (bits23:20=2) + SAM (bit18,
// AHCI-mode only) + NCS=31 (bits12:8, 32 command slots) + NP=0 (bits4:0, 1 port).
constexpr uint32_t kCap = 0x80000000u | 0x00200000u | 0x00040000u | 0x00001F00u;
constexpr uint32_t kVersion = 0x00010300u; // AHCI 1.3.
constexpr uint32_t kPortsImplemented = 0x00000001u; // port 0 only.

uint32_t LoadLe32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}
void StoreLe32(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

} // namespace

AhciController::AhciController(IBlockDevice *disk) : disk_(disk) {
  // Present a ready SATA disk on port 0 from the start: DET=3 (device present +
  // PHY communication established), SPD=2 (Gen2), IPM=1 (interface active).
  pxSsts_ = 0x00000123u;
  pxSig_ = 0x00000101u;  // Non-packet SATA device (a hard disk).
  pxTfd_ = 0x00000050u;  // DRDY | DSC, BSY/DRQ/ERR clear -> ready.
}

std::array<uint8_t, IBlockDevice::kSectorSize>
AhciController::BuildIdentify(const IBlockDevice *disk) {
  std::array<uint8_t, IBlockDevice::kSectorSize> data{};
  auto putWord = [&](int w, uint16_t v) {
    data[static_cast<size_t>(w) * 2] = static_cast<uint8_t>(v & 0xFF);
    data[static_cast<size_t>(w) * 2 + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  };
  auto putStr = [&](int w, int words, const char *s) {
    // ATA identify strings are byte-swapped within each 16-bit word.
    for (int i = 0; i < words; ++i) {
      const char c0 = *s ? *s++ : ' ';
      const char c1 = *s ? *s++ : ' ';
      data[static_cast<size_t>(w + i) * 2] = static_cast<uint8_t>(c1);
      data[static_cast<size_t>(w + i) * 2 + 1] = static_cast<uint8_t>(c0);
    }
  };
  const uint64_t sectors = disk ? disk->SectorCount() : 0;
  putWord(0, 0x0040);                      // Fixed disk.
  // Anti-evasion: present a realistic consumer SSD, NOT a sandbox-identifying
  // name. A sample reading Win32_DiskDrive.Model must not see "AntiMal" and bail.
  putStr(10, 10, "S3Z2NB0K500127T");        // Serial number.
  putStr(23, 4, "RVT04B6Q");                // Firmware revision.
  putStr(27, 20, "Samsung SSD 860 EVO 500GB");
  putWord(47, 0x8000);
  putWord(49, 0x0300);                     // LBA + DMA supported.
  putWord(50, 0x4000);
  putWord(53, 0x0007);                     // Words 64-70 + 88 valid.
  const uint32_t lba28 =
      sectors > 0x0FFFFFFFull ? 0x0FFFFFFFu : static_cast<uint32_t>(sectors);
  putWord(60, static_cast<uint16_t>(lba28 & 0xFFFF));
  putWord(61, static_cast<uint16_t>((lba28 >> 16) & 0xFFFF));
  putWord(63, 0x0007);                     // Multiword DMA 0-2 supported.
  putWord(64, 0x0003);                     // PIO modes 3,4.
  putWord(75, 0x001F);                     // Queue depth 32.
  putWord(76, 0x0300);                     // SATA Gen1 + Gen2 supported.
  putWord(80, 0x007E);                     // ATA-1 .. ATA-6.
  putWord(83, 0x4400);                     // LBA48 supported (bit10) + valid.
  putWord(84, 0x4000);
  putWord(86, 0x0400);                     // LBA48 enabled.
  putWord(87, 0x4000);
  putWord(88, 0x203F);                     // UDMA 0-5 supported, UDMA5 active.
  putWord(93, 0x0000);
  // 48-bit LBA sector count, words 100-103.
  putWord(100, static_cast<uint16_t>(sectors & 0xFFFF));
  putWord(101, static_cast<uint16_t>((sectors >> 16) & 0xFFFF));
  putWord(102, static_cast<uint16_t>((sectors >> 32) & 0xFFFF));
  putWord(103, static_cast<uint16_t>((sectors >> 48) & 0xFFFF));
  return data;
}

uint32_t AhciController::ReadReg32(uint32_t off) const {
  if (off < 0x100) {
    switch (off) {
    case 0x00: return kCap;             // CAP.
    case 0x04: return ghc_;             // GHC.
    case 0x08: return hbaIs_;           // IS.
    case 0x0C: return kPortsImplemented; // PI.
    case 0x10: return kVersion;         // VS.
    default: return 0;                  // CCC/EM/CAP2/BOHC: unimplemented.
    }
  }
  if (off >= 0x100 && off < 0x180) {
    switch (off - 0x100) {
    case 0x00: return pxClb_;
    case 0x04: return pxClbu_;
    case 0x08: return pxFb_;
    case 0x0C: return pxFbu_;
    case 0x10: return pxIs_;
    case 0x14: return pxIe_;
    case 0x18: return pxCmd_;
    case 0x20: return pxTfd_;
    case 0x24: return pxSig_;
    case 0x28: return pxSsts_;
    case 0x2C: return pxSctl_;
    case 0x30: return pxSerr_;
    case 0x34: return pxSact_;
    case 0x38: return pxCi_;
    default: return 0;
    }
  }
  return 0;
}

void AhciController::WriteReg32(uint32_t off, uint32_t value) {
  if (off < 0x100) {
    switch (off) {
    case 0x04: // GHC.
      if (value & 0x1u) {
        // HBA reset (HR): clear state, then self-clear HR. Keep the device
        // present so the OS re-detects it after reset.
        ghc_ = 0;
        hbaIs_ = 0;
        pxClb_ = pxClbu_ = pxFb_ = pxFbu_ = 0;
        pxIs_ = pxIe_ = pxCmd_ = pxSerr_ = pxSact_ = pxCi_ = 0;
        pxTfd_ = 0x50;
        interruptPending_ = false;
        return;
      }
      ghc_ = value & 0x80000003u; // AE | IE | HR.
      return;
    case 0x08: // IS: write-1-to-clear.
      hbaIs_ &= ~value;
      return;
    default:
      return;
    }
  }
  if (off >= 0x100 && off < 0x180) {
    switch (off - 0x100) {
    case 0x00: pxClb_ = value & 0xFFFFFC00u; return;
    case 0x04: pxClbu_ = value; return;
    case 0x08: pxFb_ = value & 0xFFFFFF00u; return;
    case 0x0C: pxFbu_ = value; return;
    case 0x10: // PxIS: write-1-to-clear.
      pxIs_ &= ~value;
      if ((pxIs_ & pxIe_) == 0) {
        hbaIs_ &= ~0x1u;
      }
      return;
    case 0x14: pxIe_ = value; return;
    case 0x18: // PxCMD: reflect ST->CR (bit15) and FRE->FR (bit14).
      ++portCmdWrites_;
      pxCmd_ = (value & ~0x0000C000u) | ((value & 0x1u) ? 0x8000u : 0u) |
               ((value & 0x10u) ? 0x4000u : 0u);
      return;
    case 0x2C: pxSctl_ = value; return;     // SATA control (keep present).
    case 0x30: pxSerr_ &= ~value; return;   // PxSERR: write-1-to-clear.
    case 0x34: pxSact_ = value; return;
    case 0x38: // PxCI: OS sets per-slot issue bits.
      ++ciWrites_;
      pxCi_ |= value;
      ProcessCommandIssue();
      return;
    default:
      return; // PxTFD/PxSIG/PxSSTS are read-only.
    }
  }
}

void AhciController::ProcessCommandIssue() {
  const uint32_t issued = pxCi_;
  for (uint32_t slot = 0; slot < 32; ++slot) {
    if (issued & (1u << slot)) {
      RunCommandSlot(slot);
    }
  }
}

void AhciController::RunCommandSlot(uint32_t slot) {
  if (!dmaMemory_) {
    pxCi_ &= ~(1u << slot);
    return;
  }
  const uint64_t clb =
      static_cast<uint64_t>(pxClb_) | (static_cast<uint64_t>(pxClbu_) << 32);
  uint8_t *hdr = dmaMemory_(clb + static_cast<uint64_t>(slot) * 0x20, 0x20);
  if (!hdr) {
    pxCi_ &= ~(1u << slot);
    return;
  }
  const uint32_t dw0 = LoadLe32(hdr);
  const uint16_t prdtl = static_cast<uint16_t>((dw0 >> 16) & 0xFFFF);
  const uint64_t ctba = static_cast<uint64_t>(LoadLe32(hdr + 8)) |
                        (static_cast<uint64_t>(LoadLe32(hdr + 12)) << 32);
  const size_t ctblLen = 0x80 + static_cast<size_t>(prdtl) * 16;
  uint8_t *ctbl = dmaMemory_(ctba, ctblLen);
  if (!ctbl) {
    pxCi_ &= ~(1u << slot);
    return;
  }

  // The command FIS is a Host-to-Device Register FIS (type 0x27): byte2 is the
  // ATA command, bytes 4-6/8-10 the 48-bit LBA, bytes 12-13 the sector count.
  const uint8_t *cfis = ctbl;
  const uint8_t cmd = cfis[2];
  // LBA/count decoding differs between 48-bit EXT commands and 28-bit commands.
  // EXT (0x24/0x25/0x34/0x35): LBA is bytes 4-6 + 8-10 (48-bit), count is the
  // 16-bit field bytes 12-13 (0 -> 65536). 28-bit (0xC8/0xCA/0x20/0x30): LBA is
  // bytes 4-6 PLUS bits 27:24 in the Device register (byte 7, low nibble), and
  // count is the 8-bit field byte 12 (0 -> 256). Decoding a 28-bit command as
  // 48-bit silently drops LBA bits 27:24 -> any read at LBA >= 16M sectors
  // (>= 8 GiB into the disk, e.g. the SYSTEM hive deep in the Windows partition)
  // returns the wrong sectors -> "registry hive contains errors" (0xc000000f).
  const bool isExt =
      (cmd == 0x25 || cmd == 0x35 || cmd == 0x24 || cmd == 0x34);
  uint64_t lba;
  uint32_t count;
  if (isExt) {
    lba = static_cast<uint64_t>(cfis[4]) |
          (static_cast<uint64_t>(cfis[5]) << 8) |
          (static_cast<uint64_t>(cfis[6]) << 16) |
          (static_cast<uint64_t>(cfis[8]) << 24) |
          (static_cast<uint64_t>(cfis[9]) << 32) |
          (static_cast<uint64_t>(cfis[10]) << 40);
    count = static_cast<uint32_t>(cfis[12]) |
            (static_cast<uint32_t>(cfis[13]) << 8);
    if (count == 0) {
      count = 65536;
    }
  } else {
    lba = static_cast<uint64_t>(cfis[4]) |
          (static_cast<uint64_t>(cfis[5]) << 8) |
          (static_cast<uint64_t>(cfis[6]) << 16) |
          (static_cast<uint64_t>(cfis[7] & 0x0F) << 24);
    count = cfis[12];
    if (count == 0) {
      count = 256;
    }
  }
  uint8_t *prdt = ctbl + 0x80;

  // Scatter `src` across the PRDT (device->host), returning bytes moved.
  auto scatter = [&](const uint8_t *src, size_t srcLen) -> uint32_t {
    uint32_t total = 0;
    size_t off = 0;
    for (uint16_t i = 0; i < prdtl && off < srcLen; ++i) {
      const uint8_t *e = prdt + static_cast<size_t>(i) * 16;
      const uint64_t dba = static_cast<uint64_t>(LoadLe32(e)) |
                           (static_cast<uint64_t>(LoadLe32(e + 4)) << 32);
      const uint32_t dbc = (LoadLe32(e + 12) & 0x3FFFFFu) + 1;
      const size_t n = std::min(static_cast<size_t>(dbc), srcLen - off);
      if (uint8_t *dst = dmaMemory_(dba, n)) {
        std::memcpy(dst, src + off, n);
      }
      off += n;
      total += static_cast<uint32_t>(n);
    }
    return total;
  };
  // Gather from the PRDT into `dst` (host->device), returning bytes moved.
  auto gather = [&](uint8_t *dst, size_t dstLen) -> uint32_t {
    uint32_t total = 0;
    size_t off = 0;
    for (uint16_t i = 0; i < prdtl && off < dstLen; ++i) {
      const uint8_t *e = prdt + static_cast<size_t>(i) * 16;
      const uint64_t dba = static_cast<uint64_t>(LoadLe32(e)) |
                           (static_cast<uint64_t>(LoadLe32(e + 4)) << 32);
      const uint32_t dbc = (LoadLe32(e + 12) & 0x3FFFFFu) + 1;
      const size_t n = std::min(static_cast<size_t>(dbc), dstLen - off);
      if (const uint8_t *srcp = dmaMemory_(dba, n)) {
        std::memcpy(dst + off, srcp, n);
      }
      off += n;
      total += static_cast<uint32_t>(n);
    }
    return total;
  };

  ++commandsIssued_;
  lastCommand_ = cmd;
  uint8_t status = 0x50; // DRDY | DSC.
  uint8_t err = 0;
  uint32_t prdbc = 0;

  switch (cmd) {
  case 0xEC: { // IDENTIFY DEVICE.
    ++identifyCommands_;
    const auto id = BuildIdentify(disk_);
    prdbc = scatter(id.data(), id.size());
    break;
  }
  case 0x25: // READ DMA EXT (48-bit).
  case 0xC8: // READ DMA (28-bit).
  case 0x24: { // READ SECTORS EXT.
    ++readCommands_;
    std::vector<uint8_t> buf(static_cast<size_t>(count) * IBlockDevice::kSectorSize);
    if (disk_ &&
        disk_->ReadSectors(lba, static_cast<uint16_t>(std::min<uint32_t>(count, 0xFFFF)),
                           buf.data())) {
      sectorsRead_ += count;
      RecordAccess(false, cmd, lba, count);
      prdbc = scatter(buf.data(), buf.size());
    } else {
      status = 0x51; // ERR | DRDY.
      err = 0x04;    // ABRT.
    }
    break;
  }
  case 0x35: // WRITE DMA EXT (48-bit).
  case 0xCA: // WRITE DMA (28-bit).
  case 0x34: { // WRITE SECTORS EXT.
    ++writeCommands_;
    std::vector<uint8_t> buf(static_cast<size_t>(count) * IBlockDevice::kSectorSize);
    prdbc = gather(buf.data(), buf.size());
    if (disk_ &&
        disk_->WriteSectors(lba, static_cast<uint16_t>(std::min<uint32_t>(count, 0xFFFF)),
                            buf.data())) {
      sectorsWritten_ += count;
      RecordAccess(true, cmd, lba, count);
    } else {
      status = 0x51;
      err = 0x04;
    }
    break;
  }
  case 0xEA: // FLUSH CACHE EXT.
  case 0xE7: { // FLUSH CACHE.
    if (disk_) {
      disk_->Flush();
    }
    break;
  }
  case 0xEF: // SET FEATURES (transfer mode, write cache, ...).
  case 0xC6: // SET MULTIPLE MODE.
  case 0x91: // INITIALIZE DEVICE PARAMETERS.
  case 0x90: // EXECUTE DEVICE DIAGNOSTIC.
  case 0xE0: // STANDBY IMMEDIATE.
  case 0xE1: // IDLE IMMEDIATE.
  case 0xE5: // CHECK POWER MODE.
  case 0x08: // DEVICE RESET.
    // No persistent state to model in emulation -- report success so the OS's
    // storage init sequence (OVMF AhciBusDxe and Windows storahci both issue
    // SET FEATURES + friends right after IDENTIFY) proceeds instead of treating
    // the device as faulty. Status stays 0x50 (DRDY | DSC), error 0.
    break;
  default:
    ++unknownCommands_;
    status = 0x51; // ERR | DRDY.
    err = 0x04;    // ABRT.
    break;
  }

  // Report bytes transferred in the command header's PRDBC field (DW1).
  StoreLe32(hdr + 4, prdbc);

  // Post a Device-to-Host Register FIS (type 0x34) into the port's FIS-receive
  // area at PxFB + 0x40 so the OS sees the command's completion status.
  const uint64_t fb =
      static_cast<uint64_t>(pxFb_) | (static_cast<uint64_t>(pxFbu_) << 32);
  if (fb != 0) {
    if (uint8_t *rfis = dmaMemory_(fb + 0x40, 0x14)) {
      std::memset(rfis, 0, 0x14);
      rfis[0] = 0x34;            // FIS type: Register Device-to-Host.
      rfis[1] = 0x40;            // I bit (interrupt).
      rfis[2] = status;          // Status.
      rfis[3] = err;             // Error.
      rfis[4] = cfis[4];         // LBA 7:0.
      rfis[5] = cfis[5];         // LBA 15:8.
      rfis[6] = cfis[6];         // LBA 23:16.
      rfis[7] = cfis[7];         // Device.
      rfis[8] = cfis[8];         // LBA 31:24.
      rfis[9] = cfis[9];         // LBA 39:32.
      rfis[10] = cfis[10];       // LBA 47:40.
      rfis[12] = cfis[12];       // Count 7:0.
      rfis[13] = cfis[13];       // Count 15:8.
    }
  }

  pxTfd_ = static_cast<uint32_t>(status) | (static_cast<uint32_t>(err) << 8);
  pxIs_ |= 0x1u;                 // DHRS: Device-to-Host Register FIS interrupt.
  pxCi_ &= ~(1u << slot);        // Command slot complete.
  RaiseInterrupt();
}

void AhciController::RaiseInterrupt() {
  if ((pxIs_ & pxIe_) != 0) {
    hbaIs_ |= 0x1u;              // Port 0 interrupt pending in the HBA.
    if (ghc_ & 0x2u) {          // GHC.IE: global interrupt enable.
      interruptPending_ = true;
    }
  }
}

void AhciController::RecordAccess(bool write, uint8_t cmd, uint64_t lba,
                                 uint32_t count) {
  if (recentAccesses_.size() >= kRecentAccessLimit) {
    // Drop the oldest to stay bounded; a stuck boot's recent accesses are the
    // boot reads the host analysis is looking for.
    recentAccesses_.erase(recentAccesses_.begin());
  }
  IdeAccessRange access;
  access.write = write;
  access.command = cmd;
  access.lba = lba;
  access.count = static_cast<uint16_t>(count > 0xFFFFu ? 0xFFFFu : count);
  recentAccesses_.push_back(access);
}

bool AhciController::OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) {
  const uint32_t off = static_cast<uint32_t>(gpa - abarBase_);
  uint64_t v = 0;
  if (accessSize == 8) {
    v = static_cast<uint64_t>(ReadReg32(off & ~3u)) |
        (static_cast<uint64_t>(ReadReg32((off & ~3u) + 4)) << 32);
  } else {
    const uint32_t dw = ReadReg32(off & ~3u);
    const uint32_t shift = (off & 3u) * 8u;
    v = dw >> shift;
    if (accessSize == 1) {
      v &= 0xFFu;
    } else if (accessSize == 2) {
      v &= 0xFFFFu;
    } else {
      v &= 0xFFFFFFFFu;
    }
  }
  if (outValue) {
    *outValue = v;
  }
  return true;
}

bool AhciController::OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  const uint32_t off = static_cast<uint32_t>(gpa - abarBase_);
  if (accessSize == 8) {
    WriteReg32(off & ~3u, static_cast<uint32_t>(value));
    WriteReg32((off & ~3u) + 4, static_cast<uint32_t>(value >> 32));
  } else if (accessSize == 4) {
    WriteReg32(off & ~3u, static_cast<uint32_t>(value));
  } else {
    const uint32_t dw = ReadReg32(off & ~3u);
    const uint32_t shift = (off & 3u) * 8u;
    const uint32_t mask =
        (accessSize == 1 ? 0xFFu : 0xFFFFu) << shift;
    const uint32_t merged =
        (dw & ~mask) | ((static_cast<uint32_t>(value) << shift) & mask);
    WriteReg32(off & ~3u, merged);
  }
  return true;
}

} // namespace antimal::hv
