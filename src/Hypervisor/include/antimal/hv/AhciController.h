#pragma once

// Minimal AHCI 1.x HBA with TWO SATA ports, enough for OVMF's AhciBusDxe and
// Windows' storahci.sys to enumerate and boot from the disk on port 0. AHCI is a
// PCI-native device: a single MMIO register block (ABAR / PCI BAR5), a PCI INTx
// interrupt, and DMA driven by an in-memory command list -- NO legacy ISA ports
// or IRQ14/15. That is the whole point of using it: the compat-mode PCI IDE
// channel could not get its InterfaceType=Isa resources arbitrated in PCI scope
// (CM_PROB_NORMAL_CONFLICT), whereas an AHCI port's resources are all PCI-type
// and arbitrate cleanly where the device lives. See ahci_storage_decision memory.
//
// Port 1 is the disk-backed SAMPLE delivery channel: the detonation sample file
// is exposed as a second read-only SATA disk and the in-guest agent copies it
// off the raw device (no serial size cap, disk-speed transfer). When no sample
// disk is attached, port 1 advertises no device (PxSSTS=0) and the guest never
// enumerates it.
//
// Register model (ABAR):
//   Generic Host Control @ 0x00: CAP, GHC, IS, PI, VS, CAP2, BOHC.
//   Port N register set    @ 0x100 + 0x80*N: PxCLB/CLBU, PxFB/FBU, PxIS, PxIE,
//                                   PxCMD, PxTFD, PxSIG, PxSSTS, PxSCTL, PxSERR,
//                                   PxSACT, PxCI.
// Command model: the guest builds a command list (32 headers) at PxCLB; each
// header points to a command table holding a Host-to-Device Register FIS (the
// ATA command) + a PRDT (scatter/gather list). Setting a bit in PxCI asks the
// HBA to run that slot; we execute the ATA command against the port's
// IBlockDevice, move bytes through the PRDT via a guest-physical memory
// accessor, post a Device-to-Host Register FIS into the port's FIS-receive area,
// set PxIS, raise the (shared) HBA interrupt, and clear the PxCI bit.

#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/Device.h"
#include "antimal/hv/StorageController.h" // IdeAccessRange (shared disk-access record)

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

namespace antimal::hv {

class AhciController final : public IMmioDevice {
public:
  // ABAR spans 0x1000 (4 KiB): Generic Host Control (0x00..0xFF) + port
  // registers (0x100 + 0x80*N). Port 0 = boot disk, port 1 = sample disk.
  static constexpr uint64_t kAbarSize = 0x1000;
  static constexpr uint32_t kPortCount = 2;

  explicit AhciController(IBlockDevice *disk = nullptr);

  // Port 0 is the boot disk (existing single-disk callers).
  void SetDisk(IBlockDevice *disk) noexcept { SetPortDisk(0, disk); }

  // Attach/detach a port's device. A non-null disk presents a ready SATA disk
  // (DET=3/SPD=2/IPM=1, signature 0x101); null presents an empty port so the
  // guest does not enumerate it.
  void SetPortDisk(uint32_t port, IBlockDevice *disk) noexcept {
    if (port >= kPortCount) {
      return;
    }
    PortState &p = ports_[port];
    p.disk = disk;
    if (disk) {
      p.ssts = 0x00000123u;
      p.sig = 0x00000101u;
      p.tfd = 0x00000050u; // DRDY | DSC.
    } else {
      p.ssts = 0;
      p.sig = 0xFFFFFFFFu;
      p.tfd = 0x0000007Fu; // BSY until a device appears.
    }
  }

  IBlockDevice *PortDisk(uint32_t port) const noexcept {
    return port < kPortCount ? ports_[port].disk : nullptr;
  }

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

  // Restore the power-on register state for a guest reboot. Keeps the attached
  // disks, the DMA accessor, the ABAR base (the guest re-assigns BAR5 on the
  // next boot), and the cumulative diagnostic counters; clears the HBA/port
  // registers and the interrupt latch so OVMF's AhciBusDxe re-initializes from
  // scratch.
  void Reset() noexcept;

  // PCI INTx assertion latch, polled by the host run loop (like IdeController).
  // There is ONE INTx for the HBA; either port can assert it.
  bool InterruptPending() const noexcept { return interruptPending_; }
  bool ConsumeInterrupt() noexcept {
    if (!interruptPending_) {
      return false;
    }
    interruptPending_ = false;
    return true;
  }

  // Diagnostics. These report PORT 0 (the boot disk) so the boot-read gates and
  // the existing unit tests keep their exact semantics; the sample port has its
  // own counters below.
  uint64_t CommandsIssued() const noexcept {
    return ports_[0].commandsIssued;
  }
  uint32_t IdentifyCommands() const noexcept {
    return ports_[0].identifyCommands;
  }
  uint32_t ReadCommands() const noexcept { return ports_[0].readCommands; }
  uint32_t WriteCommands() const noexcept { return ports_[0].writeCommands; }
  uint64_t SectorsRead() const noexcept { return ports_[0].sectorsRead; }
  uint64_t SectorsWritten() const noexcept {
    return ports_[0].sectorsWritten;
  }
  uint32_t UnknownCommands() const noexcept {
    return ports_[0].unknownCommands;
  }
  uint8_t LastCommand() const noexcept { return ports_[0].lastCommand; }
  uint32_t PortCmdWrites() const noexcept { return ports_[0].portCmdWrites; }
  uint32_t CiWrites() const noexcept { return ports_[0].ciWrites; }

  // Sample-disk (port 1) diagnostics: sectors the guest copied off the sample
  // disk during disk-backed delivery.
  uint64_t SampleSectorsRead() const noexcept {
    return ports_[1].sectorsRead;
  }
  uint64_t SampleCommandsIssued() const noexcept {
    return ports_[1].commandsIssued;
  }
  uint64_t SampleWriteCommands() const noexcept {
    return ports_[1].writeCommands;
  }

  // Per-command read/write accesses (lba + count), for the host's boot-read
  // analysis (port 0 only, mirroring the pre-two-port behavior). The AHCI port
  // is the actual boot device, so without this the diagnostics' per-file
  // sectorsRead / winloadReached gates (which scan disk accesses) read zero on
  // every AHCI boot and falsely look like a firmware failure. Mirrors
  // IdeController::RecentAccesses().
  const std::vector<IdeAccessRange> &RecentAccesses() const noexcept {
    return ports_[0].recentAccesses;
  }

private:
  struct PortState {
    uint32_t clb = 0, clbu = 0;   // command list base (PA).
    uint32_t fb = 0, fbu = 0;     // FIS-receive base (PA).
    uint32_t is = 0;              // port interrupt status.
    uint32_t ie = 0;              // port interrupt enable.
    uint32_t cmd = 0;             // command/status (ST, FRE, FR, CR...).
    uint32_t tfd = 0x0000007Fu;   // task file data (BSY until ready).
    uint32_t sig = 0xFFFFFFFFu;   // signature (set on present device).
    uint32_t ssts = 0;            // SATA status (DET/SPD/IPM).
    uint32_t sctl = 0;            // SATA control.
    uint32_t serr = 0;            // SATA error.
    uint32_t sact = 0;            // SATA active.
    uint32_t ci = 0;              // command issue (per-slot).
    IBlockDevice *disk = nullptr;

    // Per-port diagnostics.
    uint64_t commandsIssued = 0;
    uint64_t sectorsRead = 0;
    uint64_t sectorsWritten = 0;
    uint32_t identifyCommands = 0;
    uint32_t readCommands = 0;
    uint32_t writeCommands = 0;
    uint32_t unknownCommands = 0;
    uint32_t portCmdWrites = 0;
    uint32_t ciWrites = 0;
    uint8_t lastCommand = 0;
    std::vector<IdeAccessRange> recentAccesses;
  };

  // Generic Host Control register indices (byte offsets / 4 not used; we switch
  // on the byte offset directly).
  void WriteReg32(uint32_t off, uint32_t value);
  uint32_t ReadReg32(uint32_t off) const;
  void ProcessCommandIssue(uint32_t port);   // walk PxCI, run each set slot.
  void RunCommandSlot(uint32_t port, uint32_t slot);
  void RaiseInterrupt(uint32_t port);        // set HBA IS + latch INTx if enabled.
  static std::array<uint8_t, IBlockDevice::kSectorSize>
  BuildIdentify(const IBlockDevice *disk);
  // Append a completed read/write to the port's recent-access list, capped.
  void RecordAccess(uint32_t port, bool write, uint8_t cmd, uint64_t lba,
                    uint32_t count);
  static constexpr size_t kRecentAccessLimit = 8192;

  DmaMemoryFn dmaMemory_;
  uint64_t abarBase_ = 0;

  // Generic Host Control.
  uint32_t ghc_ = 0;    // bit31 AE, bit1 IE, bit0 HR.
  uint32_t hbaIs_ = 0;  // IS: per-port interrupt-pending bits.

  std::array<PortState, kPortCount> ports_{};

  bool interruptPending_ = false;
};

} // namespace antimal::hv
