#pragma once

// Minimal AHCI 1.x HBA with a single SATA port, enough for OVMF's AhciBusDxe
// and Windows' storahci.sys to enumerate and boot from the disk. AHCI is a
// PCI-native device: a single MMIO register block (ABAR / PCI BAR5), a PCI INTx
// interrupt, and DMA driven by an in-memory command list -- NO legacy ISA ports
// or IRQ14/15. That is the whole point of using it: the compat-mode PCI IDE
// channel could not get its InterfaceType=Isa resources arbitrated in PCI scope
// (CM_PROB_NORMAL_CONFLICT), whereas an AHCI port's resources are all PCI-type
// and arbitrate cleanly where the device lives. See ahci_storage_decision memory.
//
// Register model (ABAR):
//   Generic Host Control @ 0x00: CAP, GHC, IS, PI, VS, CAP2, BOHC.
//   Port 0 register set    @ 0x100: PxCLB/CLBU, PxFB/FBU, PxIS, PxIE, PxCMD,
//                                   PxTFD, PxSIG, PxSSTS, PxSCTL, PxSERR,
//                                   PxSACT, PxCI.
// Command model: the guest builds a command list (32 headers) at PxCLB; each
// header points to a command table holding a Host-to-Device Register FIS (the
// ATA command) + a PRDT (scatter/gather list). Setting a bit in PxCI asks the
// HBA to run that slot; we execute the ATA command against the IBlockDevice,
// move bytes through the PRDT via a guest-physical memory accessor, post a
// Device-to-Host Register FIS into the port's FIS-receive area, set PxIS, raise
// the port interrupt, and clear the PxCI bit.

#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/Device.h"

#include <array>
#include <cstdint>
#include <functional>

namespace antimal::hv {

class AhciController final : public IMmioDevice {
public:
  // ABAR spans 0x1000 (4 KiB): Generic Host Control (0x00..0xFF) + port 0
  // (0x100..0x17F). One page is the minimum sane MMIO BAR granularity.
  static constexpr uint64_t kAbarSize = 0x1000;

  explicit AhciController(IBlockDevice *disk = nullptr);

  void SetDisk(IBlockDevice *disk) noexcept { disk_ = disk; }

  // Guest-physical memory accessor (from the VM, wrapping HostPointerForGpa):
  // returns a host pointer to [gpa, gpa+length) in guest RAM, or nullptr if the
  // range is not backed. Used to read command lists / FISes / PRDT entries and
  // to move sector data between the disk and guest RAM.
  using DmaMemoryFn =
      std::function<uint8_t *(uint64_t gpa, std::size_t length)>;
  void SetDmaMemory(DmaMemoryFn fn) { dmaMemory_ = std::move(fn); }

  // ABAR base is PCI BAR5, assigned by the guest's PCI enumeration. The host
  // latches the guest-written base (from PcIoDevices) and calls this; MmioBus
  // queries MmioBase()/MmioLast() per access, so the block relocates live.
  void SetAbarBase(uint64_t base) noexcept { abarBase_ = base & ~0xFULL; }
  uint64_t AbarBase() const noexcept { return abarBase_; }

  // IMmioDevice.
  uint64_t MmioBase() const noexcept override { return abarBase_; }
  uint64_t MmioLast() const noexcept override {
    return abarBase_ + kAbarSize - 1;
  }
  bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) override;
  bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) override;

  // PCI INTx assertion latch, polled by the host run loop (like IdeController).
  bool InterruptPending() const noexcept { return interruptPending_; }
  bool ConsumeInterrupt() noexcept {
    if (!interruptPending_) {
      return false;
    }
    interruptPending_ = false;
    return true;
  }

  // Diagnostics.
  uint64_t CommandsIssued() const noexcept { return commandsIssued_; }
  uint32_t IdentifyCommands() const noexcept { return identifyCommands_; }
  uint32_t ReadCommands() const noexcept { return readCommands_; }
  uint32_t WriteCommands() const noexcept { return writeCommands_; }
  uint64_t SectorsRead() const noexcept { return sectorsRead_; }
  uint64_t SectorsWritten() const noexcept { return sectorsWritten_; }
  uint32_t UnknownCommands() const noexcept { return unknownCommands_; }
  uint8_t LastCommand() const noexcept { return lastCommand_; }
  uint32_t PortCmdWrites() const noexcept { return portCmdWrites_; }
  uint32_t CiWrites() const noexcept { return ciWrites_; }

private:
  // Generic Host Control register indices (byte offsets / 4 not used; we switch
  // on the byte offset directly).
  void WriteReg32(uint32_t off, uint32_t value);
  uint32_t ReadReg32(uint32_t off) const;
  void ProcessCommandIssue();      // walk PxCI, run each set slot.
  void RunCommandSlot(uint32_t slot);
  void RaiseInterrupt();           // set HBA IS + latch INTx if enabled.
  static std::array<uint8_t, IBlockDevice::kSectorSize>
  BuildIdentify(const IBlockDevice *disk);

  IBlockDevice *disk_ = nullptr;
  DmaMemoryFn dmaMemory_;
  uint64_t abarBase_ = 0;

  // Generic Host Control.
  uint32_t ghc_ = 0;               // bit31 AE, bit1 IE, bit0 HR.
  uint32_t hbaIs_ = 0;             // IS: per-port interrupt-pending bits.

  // Port 0 registers.
  uint32_t pxClb_ = 0, pxClbu_ = 0;   // command list base (PA).
  uint32_t pxFb_ = 0, pxFbu_ = 0;     // FIS-receive base (PA).
  uint32_t pxIs_ = 0;                 // port interrupt status.
  uint32_t pxIe_ = 0;                 // port interrupt enable.
  uint32_t pxCmd_ = 0;                // command/status (ST, FRE, FR, CR...).
  uint32_t pxTfd_ = 0x7F;             // task file data (BSY until ready).
  uint32_t pxSig_ = 0xFFFFFFFFu;      // signature (set on present device).
  uint32_t pxSsts_ = 0;               // SATA status (DET/SPD/IPM).
  uint32_t pxSctl_ = 0;               // SATA control.
  uint32_t pxSerr_ = 0;               // SATA error.
  uint32_t pxSact_ = 0;               // SATA active.
  uint32_t pxCi_ = 0;                 // command issue (per-slot).

  bool interruptPending_ = false;

  uint64_t commandsIssued_ = 0;
  uint32_t identifyCommands_ = 0;
  uint32_t readCommands_ = 0;
  uint32_t writeCommands_ = 0;
  uint64_t sectorsRead_ = 0;
  uint64_t sectorsWritten_ = 0;
  uint32_t unknownCommands_ = 0;
  uint8_t lastCommand_ = 0;
  uint32_t portCmdWrites_ = 0;
  uint32_t ciWrites_ = 0;
};

} // namespace antimal::hv
