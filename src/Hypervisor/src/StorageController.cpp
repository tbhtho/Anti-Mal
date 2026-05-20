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
  interruptPending_ = false;
}

void IdeController::OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) {
  value = MaskToAccessSize(value, accessSize);
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
    StartRead();
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
    break;
  case kCmdWriteSectors:
  case kCmdWriteSectorsExt:
    ++writeCommands_;
    StartWrite();
    if ((deviceControl_ & 0x02u) == 0) {
      interruptPending_ = true;
    }
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

void IdeController::StartRead() {
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
  PrepareTransfer(std::move(bytes), TransferKind::Read);
}

void IdeController::StartWrite() {
  if (!ActiveDisk()) {
    SetError(kErrorAbort);
    return;
  }
  pendingWriteLba_ = CurrentLba();
  pendingWriteCount_ = RequestedSectorCount();
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
  PutWord(data, 49, 0x0200);      // LBA supported.
  PutWord(data, 53, 0x0007);      // Words 54-58, 64-70, 88 valid.
  PutWord(data, 60, static_cast<uint16_t>(lba28 & 0xFFFFu));
  PutWord(data, 61, static_cast<uint16_t>((lba28 >> 16) & 0xFFFFu));
  PutWord(data, 80, 0x007E);      // ATA-1 through ATA-6 supported.
  PutWord(data, 83, 0x4000);      // FLUSH CACHE supported bit area valid.
  return data;
}

} // namespace antimal::hv
