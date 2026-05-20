#pragma once

// Minimal legacy ATA/IDE PIO controller. This is enough for benign storage
// tests and for OVMF to see a disk on the classic primary channel. It is not a
// complete ATA implementation and intentionally does not model ATAPI/CD-ROM yet.

#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/Device.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace antimal::hv {

class IdeController final : public IIoPortDevice {
public:
  static constexpr uint16_t kPrimaryBase = 0x1F0;
  static constexpr uint16_t kPrimaryLast = 0x1F7;
  static constexpr uint16_t kPrimaryControl = 0x3F6;
  static constexpr uint16_t kSecondaryBase = 0x170;
  static constexpr uint16_t kSecondaryLast = 0x177;
  static constexpr uint16_t kSecondaryControl = 0x376;

  explicit IdeController(IBlockDevice *masterDisk = nullptr,
                         uint16_t commandBase = kPrimaryBase,
                         uint16_t controlPort = kPrimaryControl);

  void SetMasterDisk(IBlockDevice *disk) noexcept { disk_ = disk; Reset(); }
  IBlockDevice *MasterDisk() const noexcept { return disk_; }

  uint32_t CommandsIssued() const noexcept { return commandsIssued_; }
  uint32_t IdentifyCommands() const noexcept { return identifyCommands_; }
  uint32_t ReadCommands() const noexcept { return readCommands_; }
  uint32_t WriteCommands() const noexcept { return writeCommands_; }
  uint32_t AbortedCommands() const noexcept { return abortedCommands_; }
  uint64_t SectorsRead() const noexcept { return sectorsRead_; }
  uint64_t SectorsWritten() const noexcept { return sectorsWritten_; }
  const std::map<uint8_t, uint32_t> &CommandHistogram() const noexcept {
    return commandHistogram_;
  }
  uint8_t Status() const noexcept { return status_; }

  // Returns true when the controller has asserted its IRQ line (IRQ 14 for
  // the primary channel, IRQ 15 for the secondary) since the last call and
  // clears the latch. The host run loop uses this to inject the matching
  // legacy vector through the local APIC after the guest reprograms the PIC.
  bool ConsumeInterrupt() noexcept {
    if (!interruptPending_) {
      return false;
    }
    interruptPending_ = false;
    return true;
  }
  bool InterruptPending() const noexcept { return interruptPending_; }
  uint8_t IrqLine() const noexcept { return irqLine_; }

  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

private:
  enum class TransferKind {
    None,
    Read,
    Write,
    Identify,
  };

  void Reset();
  void ExecuteCommand(uint8_t command);
  void StartIdentify();
  void StartRead();
  void StartWrite();
  void CompleteWriteIfReady();
  void SetError(uint8_t error);
  IBlockDevice *ActiveDisk() const noexcept;
  uint64_t CurrentLba() const noexcept;
  uint16_t RequestedSectorCount() const noexcept;
  void PrepareTransfer(std::vector<uint8_t> bytes, TransferKind kind);
  void WriteDataByte(uint8_t value);
  uint8_t ReadDataByte();

  static std::array<uint8_t, IBlockDevice::kSectorSize>
  BuildIdentifyData(const IBlockDevice *disk);

  IBlockDevice *disk_ = nullptr;
  uint8_t error_ = 0;
  uint8_t features_ = 0;
  uint8_t sectorCount_ = 1;
  uint8_t lbaLow_ = 0;
  uint8_t lbaMid_ = 0;
  uint8_t lbaHigh_ = 0;
  uint8_t driveHead_ = 0xE0;
  uint8_t status_ = 0x40;
  uint8_t deviceControl_ = 0;
  uint32_t commandsIssued_ = 0;
  uint32_t identifyCommands_ = 0;
  uint32_t readCommands_ = 0;
  uint32_t writeCommands_ = 0;
  uint32_t abortedCommands_ = 0;
  uint64_t sectorsRead_ = 0;
  uint64_t sectorsWritten_ = 0;
  std::map<uint8_t, uint32_t> commandHistogram_;
  TransferKind transferKind_ = TransferKind::None;
  std::vector<uint8_t> transfer_;
  size_t transferOffset_ = 0;
  uint64_t pendingWriteLba_ = 0;
  uint16_t pendingWriteCount_ = 0;
  uint16_t commandBase_ = kPrimaryBase;
  uint16_t controlPort_ = kPrimaryControl;
  uint8_t irqLine_ = 14;
  bool interruptPending_ = false;
};

} // namespace antimal::hv
