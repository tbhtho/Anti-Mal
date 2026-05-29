#include "antimal/hv/StorageController.h"

#include <algorithm>
#include <cstring>
#include <string_view>

namespace antimal::hv {

namespace {

constexpr uint8_t kStatusErr = 0x01;
constexpr uint8_t kStatusDrq = 0x08;
constexpr uint8_t kStatusDsc = 0x10;
constexpr uint8_t kStatusDrdy = 0x40;
constexpr uint8_t kStatusBsy = 0x80;

constexpr uint8_t kErrorAbort = 0x04;

constexpr uint8_t kCmdReadSectors = 0x20;
constexpr uint8_t kCmdReadSectorsExt = 0x24;
constexpr uint8_t kCmdWriteSectors = 0x30;
constexpr uint8_t kCmdWriteSectorsExt = 0x34;
constexpr uint8_t kCmdInitializeDeviceParameters = 0x91;
constexpr uint8_t kCmdExecuteDiagnostic = 0x90;
constexpr uint8_t kCmdSetMultipleMode = 0xC6;
constexpr uint8_t kCmdIdentify = 0xEC;
constexpr uint8_t kCmdSetFeatures = 0xEF;
constexpr uint8_t kCmdFlushCache = 0xE7;
constexpr uint8_t kCmdReadDma = 0xC8;     // READ DMA (28-bit LBA).
constexpr uint8_t kCmdReadDmaExt = 0x25;  // READ DMA EXT (48-bit LBA).
constexpr uint8_t kCmdWriteDma = 0xCA;    // WRITE DMA (28-bit LBA).
constexpr uint8_t kCmdWriteDmaExt = 0x35; // WRITE DMA EXT (48-bit LBA).

uint32_t MaskToAccessSize(uint32_t value, uint8_t accessSize) {
  switch (accessSize) {
  case 1:
    return value & 0xFFu;
  case 2:
    return value & 0xFFFFu;
  default:
    return value;
  }
}

void PutWord(std::array<uint8_t, IBlockDevice::kSectorSize> &data,
             size_t word, uint16_t value) {
  const size_t offset = word * 2;
  data[offset] = static_cast<uint8_t>(value & 0xFFu);
  data[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

void PutAtaString(std::array<uint8_t, IBlockDevice::kSectorSize> &data,
                  size_t firstWord, size_t wordCount, std::string_view text) {
  std::string padded(wordCount * 2, ' ');
  const size_t n = std::min(padded.size(), text.size());
  std::copy_n(text.data(), n, padded.data());
  for (size_t i = 0; i < wordCount; ++i) {
    data[(firstWord + i) * 2] = static_cast<uint8_t>(padded[i * 2 + 1]);
    data[(firstWord + i) * 2 + 1] = static_cast<uint8_t>(padded[i * 2]);
  }
}

} // namespace

IdeController::IdeController(IBlockDevice *masterDisk, uint16_t commandBase,
                             uint16_t controlPort)
    : disk_(masterDisk), commandBase_(commandBase), controlPort_(controlPort) {
  // IRQ 14 (primary) and IRQ 15 (secondary) are the legacy ISA assignments
  // for PIIX-style IDE channels.
  irqLine_ = commandBase == kSecondaryBase ? 15 : 14;
  Reset();
}

void IdeController::Reset() {
  error_ = 0;
  features_ = 0;
  sectorCount_ = 1;
  lbaLow_ = 0;
  lbaMid_ = 0;
  lbaHigh_ = 0;
  driveHead_ = 0xE0;
  status_ = disk_ ? (kStatusDrdy | kStatusDsc) : 0;
  deviceControl_ = 0;
  transferKind_ = TransferKind::None;
  transfer_.clear();
  transferOffset_ = 0;
  pendingWriteLba_ = 0;
  pendingWriteCount_ = 0;
  pendingWriteCommand_ = 0;
  interruptPending_ = false;
}

void IdeController::OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) {
  value = MaskToAccessSize(value, accessSize);
  if (OwnsBmdmaPort(port)) {
    WriteBmdmaRegister(static_cast<uint16_t>(port - bmdmaBase_), value,
                       accessSize);
    return;
  }
  if (port == controlPort_) {
    deviceControl_ = static_cast<uint8_t>(value & 0xFFu);
    if ((deviceControl_ & 0x04u) != 0) {
      Reset();
    }
    // nIEN (bit 1) blocks IRQ assertion. Drop any latched IRQ so the host
    // run loop does not deliver it after the guest masked the line.
    if ((deviceControl_ & 0x02u) != 0) {
      interruptPending_ = false;
    }
    return;
  }

  if (port == commandBase_) {
    const uint8_t bytes = accessSize == 1 ? 1 : accessSize == 2 ? 2 : 4;
    for (uint8_t i = 0; i < bytes; ++i) {
      WriteDataByte(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
    }
    return;
  }

  const uint16_t offset = static_cast<uint16_t>(port - commandBase_);
  switch (offset) {
  case 1:
    features_ = static_cast<uint8_t>(value & 0xFFu);
    break;
  case 2:
    sectorCount_ = static_cast<uint8_t>(value & 0xFFu);
    break;
  case 3:
    lbaLow_ = static_cast<uint8_t>(value & 0xFFu);
    break;
  case 4:
    lbaMid_ = static_cast<uint8_t>(value & 0xFFu);
    break;
  case 5:
    lbaHigh_ = static_cast<uint8_t>(value & 0xFFu);
    break;
  case 6:
    driveHead_ = static_cast<uint8_t>(value & 0xFFu);
    if (transferKind_ == TransferKind::None) {
      status_ = ActiveDisk() ? (kStatusDrdy | kStatusDsc) : 0;
      error_ = 0;
    }
    break;
  case 7:
    ExecuteCommand(static_cast<uint8_t>(value & 0xFFu));
    break;
  default:
    break;
  }
}

uint32_t IdeController::OnRead(uint16_t port, uint8_t accessSize) {
  if (OwnsBmdmaPort(port)) {
    return ReadBmdmaRegister(static_cast<uint16_t>(port - bmdmaBase_),
                             accessSize);
  }
  if (port == controlPort_) {
    // Alternate status register: same value as the main status register but
    // explicitly does not clear the IRQ latch.
    return status_;
  }
  if (port == commandBase_) {
    const uint8_t bytes = accessSize == 1 ? 1 : accessSize == 2 ? 2 : 4;
    uint32_t value = 0;
    for (uint8_t i = 0; i < bytes; ++i) {
      value |= static_cast<uint32_t>(ReadDataByte()) << (i * 8);
    }
    return value;
  }

  const uint16_t offset = static_cast<uint16_t>(port - commandBase_);
  switch (offset) {
  case 1:
    return error_;
  case 2:
    return sectorCount_;
  case 3:
    return lbaLow_;
  case 4:
    return lbaMid_;
  case 5:
    return lbaHigh_;
  case 6:
    return driveHead_;
  case 7:
    // Reading the status register acknowledges any pending IRQ from this
    // channel, matching how real PIIX IDE deasserts the bus IRQ line.
    interruptPending_ = false;
    return status_;
  default:
    return 0xFFu;
  }
}

void IdeController::ExecuteCommand(uint8_t command) {
  ++commandsIssued_;
  commandHistogram_[command]++;
  status_ = kStatusBsy;
  error_ = 0;
  switch (command) {
  case kCmdIdentify:
    ++identifyCommands_;
    StartIdentify();
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdReadSectors:
  case kCmdReadSectorsExt:
    ++readCommands_;
    StartRead(command);
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdWriteSectors:
  case kCmdWriteSectorsExt:
    ++writeCommands_;
    StartWrite(command);
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdReadDma:
  case kCmdReadDmaExt:
    // Bus-master READ DMA: stage the sectors, but do NOT raise the IRQ here.
    // The completion interrupt is asserted by the bus-master engine once the
    // guest writes the BMICX start bit and the PRD transfer runs.
    ++readCommands_;
    StartReadDma(command);
    break;
  case kCmdWriteDma:
  case kCmdWriteDmaExt:
    ++writeCommands_;
    StartWriteDma(command);
    break;
  case kCmdFlushCache:
    status_ = (ActiveDisk() && ActiveDisk()->Flush())
                  ? (kStatusDrdy | kStatusDsc)
                  : (kStatusDrdy | kStatusErr);
    if ((status_ & kStatusErr) != 0) {
      error_ = kErrorAbort;
    }
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdExecuteDiagnostic:
    if (ActiveDisk()) {
      error_ = 0x01u;
      sectorCount_ = 0x01u;
      lbaLow_ = 0x01u;
      lbaMid_ = 0x00u;
      lbaHigh_ = 0x00u;
      status_ = kStatusDrdy | kStatusDsc;
    } else {
      error_ = 0x00u;
      sectorCount_ = 0x00u;
      lbaLow_ = 0x00u;
      lbaMid_ = 0x00u;
      lbaHigh_ = 0x00u;
      status_ = 0;
    }
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdInitializeDeviceParameters:
  case kCmdSetMultipleMode:
  case kCmdSetFeatures:
    status_ = kStatusDrdy | kStatusDsc;
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  default:
    SetError(kErrorAbort);
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  }
}

void IdeController::StartIdentify() {
  auto *disk = ActiveDisk();
  if (!disk) {
    SetError(kErrorAbort);
    return;
  }
  const auto identify = BuildIdentifyData(disk);
  PrepareTransfer(std::vector<uint8_t>(identify.begin(), identify.end()),
                  TransferKind::Identify);
}

void IdeController::StartRead(uint8_t command) {
  auto *disk = ActiveDisk();
  if (!disk) {
    SetError(kErrorAbort);
    return;
  }
  const uint16_t count = RequestedSectorCount();
  const uint64_t lba = CurrentLba();
  std::vector<uint8_t> bytes(static_cast<size_t>(count) * IBlockDevice::kSectorSize);
  if (!disk->ReadSectors(lba, count, bytes.data())) {
    SetError(kErrorAbort);
    return;
  }
  sectorsRead_ += count;
  RecordAccess(false, command, lba, count);
  PrepareTransfer(std::move(bytes), TransferKind::Read);
}

void IdeController::StartReadDma(uint8_t command) {
  auto *disk = ActiveDisk();
  if (!disk) {
    SetError(kErrorAbort);
    return;
  }
  const uint16_t count = RequestedSectorCount();
  const uint64_t lba = CurrentLba();
  std::vector<uint8_t> bytes(static_cast<size_t>(count) *
                             IBlockDevice::kSectorSize);
  if (!disk->ReadSectors(lba, count, bytes.data())) {
    SetError(kErrorAbort);
    return;
  }
  sectorsRead_ += count;
  RecordAccess(false, command, lba, count);
  // Stage the data for the bus-master engine. DMA does not use the PIO data
  // port, so there is no DRQ; the controller is DRDY and waits for BMICX start.
  transfer_ = std::move(bytes);
  transferOffset_ = 0;
  transferKind_ = TransferKind::None;
  dmaKind_ = TransferKind::Read;
  dmaPending_ = true;
  status_ = kStatusDrdy | kStatusDsc;
  error_ = 0;
  // If the guest armed the bus master (BMICX start) before issuing the command,
  // run the transfer now.
  if ((bmCommand_ & 0x01u) != 0) {
    RunBusMasterDma();
  }
}

void IdeController::StartWriteDma(uint8_t command) {
  auto *disk = ActiveDisk();
  if (!disk) {
    SetError(kErrorAbort);
    return;
  }
  dmaWriteCount_ = RequestedSectorCount();
  dmaWriteLba_ = CurrentLba();
  transfer_.assign(static_cast<size_t>(dmaWriteCount_) *
                       IBlockDevice::kSectorSize,
                   0);
  transferOffset_ = 0;
  transferKind_ = TransferKind::None;
  dmaKind_ = TransferKind::Write;
  dmaPending_ = true;
  status_ = kStatusDrdy | kStatusDsc;
  error_ = 0;
  (void)command;
  if ((bmCommand_ & 0x01u) != 0) {
    RunBusMasterDma();
  }
}

void IdeController::RunBusMasterDma() {
  if (!dmaPending_ || dmaKind_ == TransferKind::None || !dmaMemory_) {
    return;
  }
  uint64_t prd = bmPrdAddr_;
  size_t dataOffset = 0;
  // Walk the Physical Region Descriptor table. Each 8-byte entry is
  // [0:3] base physical address, [4:5] byte count (0 => 64 KiB), [6:7] flags
  // (bit 15 = end-of-table). Bound the walk defensively.
  for (int guard = 0; guard < 4096; ++guard) {
    uint8_t *entry = dmaMemory_(prd, 8);
    if (!entry) {
      break;
    }
    const uint32_t addr = static_cast<uint32_t>(entry[0]) |
                          (static_cast<uint32_t>(entry[1]) << 8) |
                          (static_cast<uint32_t>(entry[2]) << 16) |
                          (static_cast<uint32_t>(entry[3]) << 24);
    uint32_t bytes = static_cast<uint32_t>(entry[4]) |
                     (static_cast<uint32_t>(entry[5]) << 8);
    if (bytes == 0) {
      bytes = 0x10000u;
    }
    const bool endOfTable =
        (static_cast<uint16_t>(entry[6] | (entry[7] << 8)) & 0x8000u) != 0;
    uint8_t *mem = dmaMemory_(addr, bytes);
    if (mem && dataOffset < transfer_.size()) {
      const size_t n = std::min<size_t>(bytes, transfer_.size() - dataOffset);
      if (dmaKind_ == TransferKind::Read) {
        std::memcpy(mem, transfer_.data() + dataOffset, n);
      } else {
        std::memcpy(transfer_.data() + dataOffset, mem, n);
      }
    }
    dataOffset += bytes;
    prd += 8;
    if (endOfTable) {
      break;
    }
  }
  if (dmaKind_ == TransferKind::Write) {
    auto *disk = ActiveDisk();
    if (disk && disk->WriteSectors(dmaWriteLba_, dmaWriteCount_,
                                   transfer_.data())) {
      sectorsWritten_ += dmaWriteCount_;
      RecordAccess(true, kCmdWriteDma, dmaWriteLba_, dmaWriteCount_);
    } else {
      SetError(kErrorAbort);
    }
  }
  ++dmaTransfers_;
  dmaSectorsMoved_ += transfer_.size() / IBlockDevice::kSectorSize;
  // Complete: clear bus-master "active", latch the interrupt status bit, ready
  // the drive, and assert the channel IRQ (unless masked via nIEN).
  bmStatus_ = static_cast<uint8_t>((bmStatus_ & ~0x01u) | 0x04u);
  bmCommand_ = static_cast<uint8_t>(bmCommand_ & ~0x01u);
  if ((status_ & kStatusErr) == 0) {
    status_ = kStatusDrdy | kStatusDsc;
    error_ = 0;
  }
  dmaPending_ = false;
  dmaKind_ = TransferKind::None;
  transfer_.clear();
  transferOffset_ = 0;
  if ((deviceControl_ & 0x02u) == 0) {
    interruptPending_ = true;
  }
}

uint32_t IdeController::ReadBmdmaRegister(uint16_t offset,
                                          uint8_t accessSize) const {
  auto byteAt = [&](uint16_t o) -> uint8_t {
    switch (o) {
    case 0:
      return bmCommand_;
    case 2:
      // BMISX status: latched error/interrupt bits plus "both drives DMA
      // capable" (bits 5/6). Never report "active" (bit 0) -- transfers
      // complete synchronously.
      return static_cast<uint8_t>((bmStatus_ & 0x06u) | 0x60u);
    case 4:
      return static_cast<uint8_t>(bmPrdAddr_ & 0xFFu);
    case 5:
      return static_cast<uint8_t>((bmPrdAddr_ >> 8) & 0xFFu);
    case 6:
      return static_cast<uint8_t>((bmPrdAddr_ >> 16) & 0xFFu);
    case 7:
      return static_cast<uint8_t>((bmPrdAddr_ >> 24) & 0xFFu);
    default:
      return 0;
    }
  };
  uint32_t value = 0;
  const uint8_t bytes = accessSize == 1 ? 1 : accessSize == 2 ? 2 : 4;
  for (uint8_t i = 0; i < bytes && (offset + i) < 8; ++i) {
    value |= static_cast<uint32_t>(byteAt(static_cast<uint16_t>(offset + i)))
             << (i * 8);
  }
  return value;
}

void IdeController::WriteBmdmaRegister(uint16_t offset, uint32_t value,
                                       uint8_t accessSize) {
  const uint8_t bytes = accessSize == 1 ? 1 : accessSize == 2 ? 2 : 4;
  for (uint8_t i = 0; i < bytes && (offset + i) < 8; ++i) {
    const uint8_t b = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    switch (static_cast<uint16_t>(offset + i)) {
    case 0: {
      const bool wasStart = (bmCommand_ & 0x01u) != 0;
      bmCommand_ = b;
      if (!wasStart && (bmCommand_ & 0x01u) != 0 && dmaPending_) {
        RunBusMasterDma();
      }
      break;
    }
    case 2:
      // BMISX: bit 1 (error) and bit 2 (interrupt) are write-1-to-clear.
      bmStatus_ = static_cast<uint8_t>(bmStatus_ & ~(b & 0x06u));
      break;
    case 4:
      bmPrdAddr_ = (bmPrdAddr_ & 0xFFFFFF00u) | b;
      break;
    case 5:
      bmPrdAddr_ = (bmPrdAddr_ & 0xFFFF00FFu) | (static_cast<uint32_t>(b) << 8);
      break;
    case 6:
      bmPrdAddr_ =
          (bmPrdAddr_ & 0xFF00FFFFu) | (static_cast<uint32_t>(b) << 16);
      break;
    case 7:
      bmPrdAddr_ =
          (bmPrdAddr_ & 0x00FFFFFFu) | (static_cast<uint32_t>(b) << 24);
      break;
    default:
      break;
    }
  }
}

void IdeController::StartWrite(uint8_t command) {
  if (!ActiveDisk()) {
    SetError(kErrorAbort);
    return;
  }
  pendingWriteLba_ = CurrentLba();
  pendingWriteCount_ = RequestedSectorCount();
  pendingWriteCommand_ = command;
  transfer_.assign(static_cast<size_t>(pendingWriteCount_) *
                       IBlockDevice::kSectorSize,
                   0);
  transferOffset_ = 0;
  transferKind_ = TransferKind::Write;
  status_ = kStatusDrdy | kStatusDsc | kStatusDrq;
}

void IdeController::CompleteWriteIfReady() {
  if (transferKind_ != TransferKind::Write || transferOffset_ < transfer_.size()) {
    return;
  }
  auto *disk = ActiveDisk();
  if (!disk || !disk->WriteSectors(pendingWriteLba_, pendingWriteCount_,
                                   transfer_.data())) {
    SetError(kErrorAbort);
    return;
  }
  sectorsWritten_ += pendingWriteCount_;
  RecordAccess(true, pendingWriteCommand_, pendingWriteLba_,
               pendingWriteCount_);
  transferKind_ = TransferKind::None;
  transfer_.clear();
  transferOffset_ = 0;
  status_ = kStatusDrdy | kStatusDsc;
}

void IdeController::SetError(uint8_t error) {
  error_ = error;
  ++abortedCommands_;
  transferKind_ = TransferKind::None;
  transfer_.clear();
  transferOffset_ = 0;
  status_ = kStatusDrdy | kStatusErr;
}

IBlockDevice *IdeController::ActiveDisk() const noexcept {
  return (driveHead_ & 0x10u) == 0 ? disk_ : nullptr;
}

uint64_t IdeController::CurrentLba() const noexcept {
  return (static_cast<uint64_t>(driveHead_ & 0x0Fu) << 24) |
         (static_cast<uint64_t>(lbaHigh_) << 16) |
         (static_cast<uint64_t>(lbaMid_) << 8) |
         static_cast<uint64_t>(lbaLow_);
}

uint16_t IdeController::RequestedSectorCount() const noexcept {
  return sectorCount_ == 0 ? 256 : sectorCount_;
}

void IdeController::PrepareTransfer(std::vector<uint8_t> bytes,
                                    TransferKind kind) {
  transfer_ = std::move(bytes);
  transferOffset_ = 0;
  transferKind_ = kind;
  status_ = kStatusDrdy | kStatusDsc | kStatusDrq;
}

void IdeController::WriteDataByte(uint8_t value) {
  if (transferKind_ != TransferKind::Write ||
      transferOffset_ >= transfer_.size()) {
    return;
  }
  transfer_[transferOffset_++] = value;
  CompleteWriteIfReady();
}

uint8_t IdeController::ReadDataByte() {
  if ((transferKind_ != TransferKind::Read &&
       transferKind_ != TransferKind::Identify) ||
      transferOffset_ >= transfer_.size()) {
    return 0;
  }
  const uint8_t value = transfer_[transferOffset_++];
  if (transferOffset_ >= transfer_.size()) {
    transferKind_ = TransferKind::None;
    transfer_.clear();
    transferOffset_ = 0;
    status_ = kStatusDrdy | kStatusDsc;
  }
  return value;
}

void IdeController::RecordAccess(bool write, uint8_t command, uint64_t lba,
                                 uint16_t count) {
  if (count == 0) {
    return;
  }
  const uint64_t end = lba + count - 1;
  if (write) {
    if (!sawWrite_) {
      minWriteLba_ = lba;
      maxWriteEndLba_ = end;
      sawWrite_ = true;
    } else {
      minWriteLba_ = std::min(minWriteLba_, lba);
      maxWriteEndLba_ = std::max(maxWriteEndLba_, end);
    }
  } else {
    if (!sawRead_) {
      minReadLba_ = lba;
      maxReadEndLba_ = end;
      sawRead_ = true;
    } else {
      minReadLba_ = std::min(minReadLba_, lba);
      maxReadEndLba_ = std::max(maxReadEndLba_, end);
    }
  }
  recentAccesses_.push_back({write, command, lba, count});
  constexpr size_t kMaxRecentAccesses = 4096;
  if (recentAccesses_.size() > kMaxRecentAccesses) {
    recentAccesses_.erase(recentAccesses_.begin(),
                          recentAccesses_.begin() +
                              (recentAccesses_.size() - kMaxRecentAccesses));
  }
}

std::array<uint8_t, IBlockDevice::kSectorSize>
IdeController::BuildIdentifyData(const IBlockDevice *disk) {
  std::array<uint8_t, IBlockDevice::kSectorSize> data{};
  const uint64_t sectors = disk ? disk->SectorCount() : 0;
  const uint32_t lba28 = sectors > 0x0FFFFFFFull
                             ? 0x0FFFFFFFu
                             : static_cast<uint32_t>(sectors);

  PutWord(data, 0, 0x0040);       // Fixed disk.
  PutWord(data, 1, 16383);        // Logical cylinders.
  PutWord(data, 3, 16);           // Logical heads.
  PutWord(data, 6, 63);           // Logical sectors per track.
  PutAtaString(data, 10, 10, "AM0000000001");
  PutAtaString(data, 23, 4, "0001");
  PutAtaString(data, 27, 20, "AntiMal In-House IDE Disk");
  PutWord(data, 49, 0x0300);      // Capabilities: DMA supported + LBA supported.
  PutWord(data, 53, 0x0007);      // Words 54-58, 64-70, 88 valid.
  PutWord(data, 60, static_cast<uint16_t>(lba28 & 0xFFFFu));
  PutWord(data, 61, static_cast<uint16_t>((lba28 >> 16) & 0xFFFFu));
  // Multiword DMA: modes 0-2 supported (low byte 0x07), mode 2 selected/active
  // (bit 10 = 0x0400). Paired with the controller's bus-master block + prog-if
  // 0x80, this lets pciide/intelide (and OVMF) drive the disk via PRD DMA.
  PutWord(data, 63, 0x0407);
  PutWord(data, 80, 0x007E);      // ATA-1 through ATA-6 supported.
  PutWord(data, 83, 0x4000);      // FLUSH CACHE supported bit area valid.
  return data;
}

} // namespace antimal::hv
