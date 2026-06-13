#pragma once

// Minimal legacy-PC IO devices used during firmware bring-up. These are not
// full emulations; they provide sane probe/status behavior for OVMF while the
// real device model is still growing.

#include "antimal/hv/AcpiTables.h"
#include "antimal/hv/Device.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace antimal::hv {

// Current VIRTUAL guest clock as a unix epoch (seconds). Decoupled from the
// live host wall-clock: a base epoch is captured exactly once (from the
// ANTIMAL_GUEST_EPOCH env var if set+valid, else a one-time host-time sample)
// and advanced monotonically with steady_clock. The guest RTC (CMOS reads in
// PcIoDevices) is fed from this, so detonation reports never leak the analyst's
// live date and date-triggered samples can be pinned to a chosen day.
std::time_t GuestRtcNowEpoch();

struct PcIoMemoryLayout {
  // Bytes of usable RAM below 4 GiB. Default is intentionally small (128 MiB)
  // so unit tests that compose PcIoDevices directly, without going through
  // VirtualMachine, see a layout that matches the small RAM regions they
  // allocate manually. The real Windows-boot path overrides this through
  // PcIoDevices::SetMemoryLayout from VirtualMachine.
  uint64_t lowRamBytes = 128ull * 1024ull * 1024ull;
  // Bytes of usable RAM above 4 GiB. Keep this at zero until the firmware
  // paging path for high allocations is proven; Windows can boot from the
  // low-memory profile while the VMM matures.
  uint64_t highRamBytes = 0;
};

class PcIoDevices : public IIoPortDevice {
public:
  PcIoDevices();

  void SetIdeControllerPresent(bool present) noexcept {
    ideControllerPresent_ = present;
  }
  void SetAhciControllerPresent(bool present) noexcept {
    ahciControllerPresent_ = present;
  }
  // Advertise the e1000 NIC (PCI dev 4). Off by default; only set when the
  // network-observation path is explicitly enabled, so default boots enumerate
  // exactly as before.
  void SetNicPresent(bool present) noexcept { nicPresent_ = present; }
  void SetVgaControllerPresent(bool present) noexcept {
    vgaControllerPresent_ = present;
  }
  void SetMemoryLayout(const PcIoMemoryLayout &layout) noexcept {
    memory_ = layout;
  }
  void SetAcpiTablesEnabled(bool enabled) noexcept {
    acpiTablesEnabled_ = enabled;
  }
  // Control whether the TPM2 ACPI table is included in the fw_cfg payload.
  // When WHP's LAPIC emulation maps dummy pages over the MMIO gap
  // [0xFEC00000, 0xFEF00000), the TPM CRB device is unreachable even after
  // relocation — OVMF never initializes it because Tcg2Pei uses a hardcoded
  // PCD address that also falls in the dummy zone. Advertising a TPM2 ACPI
  // table for a non-functional device causes winload's SpacebootInitialize
  // to return STATUS_ILLEGAL_FUNCTION (0xC00000B9). Disabling the table
  // makes the OS skip the measured-boot path entirely.
  void SetTpm2TableEnabled(bool enabled) noexcept {
    tpm2TableEnabled_ = enabled;
    RebuildAcpi();
  }
  // Override the MMIO base addresses advertised in the ACPI tables (MADT,
  // HPET, TPM2). VirtualMachine relocates these away from the canonical
  // GPAs (0xFEC00000, 0xFED00000, 0xFED40000) because WHP's Local APIC
  // emulation silently maps dummy pages there, stealing guest accesses
  // from our software IOAPIC/HPET/TPM emulators. Must be called before
  // SetProcessorCount / SetTpmEventLog so the rebuilt tables pick them up.
  void SetMmioBaseAddresses(uint64_t ioApicBase, uint64_t hpetBase,
                            uint64_t tpmCrbBase) {
    ioApicBase_ = ioApicBase;
    hpetBase_ = hpetBase;
    tpmCrbBase_ = tpmCrbBase;
    RebuildAcpi();
  }
  void SetProcessorCount(uint32_t count) {
    processorCount_ = count == 0 ? 1u : count;
    RebuildAcpi();
    cpuHotplugSelectionValid_ = cpuHotplugSelected_ < processorCount_;
  }
  // Set the TPM 2.0 event log advertisement that the ACPI builder feeds into
  // the TPM2 table's LAML/LASA fields. The VirtualMachine populates the
  // buffer before booting; without these the OS measured-boot path can't
  // walk the pre-boot log and aborts in
  // Microsoft.Windows.Kernel.BootEnvironment / SpacebootInitialize.
  void SetTpmEventLog(uint64_t gpa, uint32_t size) {
    tpmEventLogGpa_ = gpa;
    tpmEventLogSize_ = size;
    RebuildAcpi();
  }
  const std::array<uint32_t, 128> &CmosReadHistogram() const noexcept {
    return cmosReadHistogram_;
  }
  // Chronological record of recent CMOS / RTC port accesses. Used to tell
  // whether the firmware is spinning on a single register vs cycling through
  // the date/time fields vs polling status. Returns at most kCmosRecentLimit
  // entries, oldest first.
  struct CmosAccess {
    uint16_t port = 0;     // 0x70 (index) or 0x71 (data)
    uint8_t index = 0;     // active register index when access happened
    uint8_t value = 0;     // value written / value read
    bool isWrite = false;  // false = guest IN, true = guest OUT
  };
  static constexpr size_t kCmosRecentLimit = 64;
  std::vector<CmosAccess> RecentCmosAccesses() const;

  // ACPI S4 / S5 sleep state requested by the guest via PIIX4 PM control
  // register (port 0xB004, SLP_EN bit). OVMF's ResetSystemRuntimeDxe spins
  // in a `pause` loop after writing this register waiting for the host to
  // halt the CPU — VirtualMachine consumes this signal to break the run
  // loop cleanly instead of timing out.
  bool ShutdownRequested() const noexcept { return shutdownRequested_; }
  uint8_t LastSleepType() const noexcept { return lastSleepType_; }
  bool LastPm1SleepEnable() const noexcept { return lastPm1SleepEnable_; }
  bool LastPm1HostStopRequested() const noexcept {
    return lastPm1HostStopRequested_;
  }
  uint16_t LastPm1ControlValue() const noexcept { return pm1Control_; }
  uint16_t LastPm1EnableValue() const noexcept { return pm1Enable_; }
  uint64_t Pm1aStatusReads() const noexcept { return pm1aStatusReads_; }
  uint64_t Pm1SleepRequestCount() const noexcept {
    return pm1SleepRequestCount_;
  }
  uint64_t FwCfgFileDirBytesRead() const noexcept {
    return fwCfgFileDirBytesRead_;
  }
  uint64_t FwCfgE820BytesRead() const noexcept { return fwCfgE820BytesRead_; }
  uint64_t FwCfgAcpiTableBytesRead() const noexcept {
    return fwCfgAcpiTableBytesRead_;
  }
  uint64_t FwCfgTableLoaderBytesRead() const noexcept {
    return fwCfgTableLoaderBytesRead_;
  }
  uint64_t FwCfgRsdpBytesRead() const noexcept { return fwCfgRsdpBytesRead_; }
  uint64_t FwCfgSmbiosTableBytesRead() const noexcept {
    return fwCfgSmbiosTableBytesRead_;
  }
  uint64_t FwCfgSmbiosAnchorBytesRead() const noexcept {
    return fwCfgSmbiosAnchorBytesRead_;
  }
  const std::string &DebugOutput() const noexcept { return debugOutput_; }
  size_t FwCfgFileCount() const noexcept {
    return acpiTablesEnabled_ ? 6 : 1;
  }

  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

  // Bus-master IDE (BMDMA) host integration. BAR4 is OS-relocatable; after each
  // IO exit the host calls ConsumeBmdmaAttachDirty() and, if true, re-attaches
  // the 16-port BMDMA block at IdeBmdmaBase() so the block follows the guest's
  // BAR assignment.
  uint16_t IdeBmdmaBase() const noexcept { return ideBmdmaBase_; }
  bool ConsumeBmdmaAttachDirty() noexcept {
    const bool dirty = ideBmdmaAttachDirty_;
    ideBmdmaAttachDirty_ = false;
    return dirty;
  }
  // Number of times the guest selected the IDE function (bus0/dev1/func1) via
  // the PCI config address port. Stays low (winload only) if the Windows kernel
  // pci.sys never enumerates the device; climbs high once pci.sys + pciide
  // probe it.
  uint32_t IdeConfigSelects() const noexcept { return ideConfigSelects_; }

  // AHCI HBA memory window (PCI BAR5 / ABAR), assigned by the guest's PCI
  // enumeration. After each IO exit the host calls ConsumeAhciAbarDirty() and,
  // if true, points the AhciController's MMIO block at AhciAbarBase() so it
  // follows the guest's BAR5 assignment (MmioBus queries the base per-access).
  uint64_t AhciAbarBase() const noexcept {
    return static_cast<uint64_t>(ahciAbar_ & 0xFFFFF000u);
  }
  bool ConsumeAhciAbarDirty() noexcept {
    const bool dirty = ahciAbarDirty_;
    ahciAbarDirty_ = false;
    return dirty;
  }

  // e1000 NIC memory window (PCI BAR0), assigned by the guest's PCI enumeration.
  // Same dirty-latch dance as the AHCI ABAR.
  uint64_t NicBar0Base() const noexcept {
    return static_cast<uint64_t>(nicBar0_ & 0xFFFE0000u);
  }
  bool ConsumeNicBar0Dirty() noexcept {
    const bool dirty = nicBar0Dirty_;
    nicBar0Dirty_ = false;
    return dirty;
  }

  // Guest-initiated platform reset. Windows/OVMF reboot by writing the ICH9/PIIX
  // reset-control register at port 0xCF9 with the reset bit (bit 2) set
  // (0x06 = warm, 0x0E = cold). The host run loop calls ConsumeResetRequest()
  // each iteration and, if true, performs a VM warm-reset (re-runs OVMF) so the
  // guest's reboot actually happens instead of the UEFI ResetSystem no-op that
  // drops Windows into an int 3 -> 0x7E.
  bool ConsumeResetRequest() noexcept {
    const bool req = resetRequested_;
    resetRequested_ = false;
    return req;
  }

private:
  uint32_t ReadBmdma(uint16_t port, uint8_t accessSize) const;
  void WriteBmdma(uint16_t port, uint32_t value, uint8_t accessSize);
  bool OwnsBmdma(uint16_t port) const noexcept {
    // Bus-master IDE is disabled pending a real PRD DMA engine: advertising it
    // (prog-if 0x80 + BAR4) without performing the DMA made OVMF's own IDE
    // driver hang in BDS. The register helpers stay compiled (ReadBmdma/
    // WriteBmdma) so re-enabling is a one-line change once DMA is implemented,
    // but no IO is routed to them today.
    (void)port;
    return false;
  }
  void RebuildAcpi() {
    acpi_ = BuildPcAcpiTables(processorCount_, /*includeDbgp=*/false,
                              tpmEventLogSize_, tpmEventLogGpa_,
                              ioApicBase_, hpetBase_, tpmCrbBase_,
                              tpm2TableEnabled_);
  }
  uint8_t ReadCmos(uint8_t index) const;
  uint32_t ReadPciConfigDword() const;
  void WritePciAddressWindow(uint16_t port, uint32_t value,
                             uint8_t accessSize);
  uint32_t ReadFwCfgData(uint8_t accessSize);
  uint8_t ReadFwCfgByte();
  uint8_t FwCfgFileDirByte(size_t offset) const;
  uint8_t FwCfgFileDataByte(uint16_t selector, size_t offset);
  uint8_t E820Byte(size_t offset) const;
  size_t E820Size() const noexcept;
  uint32_t ReadPmIo(uint16_t port, uint8_t accessSize);
  uint32_t ReadCpuHotplug(uint16_t port, uint8_t accessSize) const;
  void WriteCpuHotplug(uint16_t port, uint32_t value, uint8_t accessSize);

  std::array<uint8_t, 128> cmos_{};
  std::array<bool, 128> cmosWritten_{};
  std::array<uint32_t, 128> cmosReadHistogram_{};
  uint8_t cmosIndex_ = 0;
  bool nmiMasked_ = false;
  mutable std::array<CmosAccess, kCmosRecentLimit> cmosRecent_{};
  mutable size_t cmosRecentHead_ = 0;
  mutable size_t cmosRecentCount_ = 0;
  void RecordCmosAccess(uint16_t port, uint8_t index, uint8_t value,
                        bool isWrite) const;
  // PM1a control register (PIIX4 port 0xB004) write tracking for ACPI sleep
  // diagnostics. Only S4/S5 requests make the host leave the run loop; other
  // SLP_EN writes are recorded because boot firmware may briefly write S0.
  bool shutdownRequested_ = false;
  uint8_t lastSleepType_ = 0;
  bool lastPm1SleepEnable_ = false;
  bool lastPm1HostStopRequested_ = false;
  uint16_t pm1Control_ = 0;
  uint64_t pm1SleepRequestCount_ = 0;
  // PM1a status (port kPmIoBase+0x00). Bit 0 = TMR_STS, set (sticky) when the
  // ACPI PM timer's MSB (bit 23 of the 24-bit counter) toggles, cleared by a
  // write-1. Modelling it lets OVMF runtime / the OS poll PM1 status (e.g. a
  // PM-timer-overflow wait) and actually see the bit, instead of reading a
  // permanent 0 and spinning forever.
  bool pm1TmrSts_ = false;
  uint32_t pm1TmrLastMsb_ = 0;
  // PM1a_EN (kPmIoBase+0x02): the event-enable register the OS arms before it
  // waits on a PM1 event. Modelled R/W purely so we can OBSERVE what the guest
  // armed (diagnostic only -- we do not yet actuate the enabled events). It is
  // the datum that names which PM1 event the OS waits on if it ever polls.
  uint16_t pm1Enable_ = 0;
  uint64_t pm1aStatusReads_ = 0; // diagnostic: total PM1a_STS reads.

public:
  // Returns the 8-bit vector base the guest programmed into the master 8259
  // PIC via ICW2 — i.e. the vector that IRQ 0 is routed to. Boot firmware
  // typically remaps the PICs from the legacy 0x08-0x0F / 0x70-0x77 ranges to
  // 0x20-0x27 / 0x28-0x2F so they don't collide with CPU exceptions; modern
  // OSes pick their own (Windows often parks legacy IRQs on 0xFD/0xFE).
  // Returns 0 until the guest has written ICW2 — host interrupt injection
  // gates on a non-zero base so no spurious vectors fire before the guest
  // has registered its own handlers.
  uint8_t MasterPicVectorBase() const noexcept { return masterPicVectorBase_; }
  uint8_t SlavePicVectorBase() const noexcept { return slavePicVectorBase_; }
  uint8_t MasterPicMask() const noexcept { return masterPicMask_; }
  uint8_t SlavePicMask() const noexcept { return slavePicMask_; }
  uint32_t MasterPicIcw1Writes() const noexcept { return masterPicIcw1Writes_; }
  uint32_t SlavePicIcw1Writes() const noexcept { return slavePicIcw1Writes_; }
  uint8_t MasterPicIcw2Value() const noexcept { return masterPicIcw2Value_; }
  uint8_t SlavePicIcw2Value() const noexcept { return slavePicIcw2Value_; }
  uint32_t VgaBar0() const noexcept { return vgaBar0_; }
  bool VgaBar0Sizing() const noexcept { return vgaBar0Sizing_; }

private:
  void WritePicCommand(bool master, uint8_t value);
  void WritePicData(bool master, uint8_t value);
  void WritePciConfigData(uint16_t port, uint32_t value, uint8_t accessSize);

  void HandlePitWrite(uint16_t port, uint8_t value);
  uint8_t ReadPitChannel(uint8_t channel);
  uint32_t CurrentPmTimer() const;

  uint8_t masterPicMask_ = 0xFF;
  uint8_t slavePicMask_ = 0xFF;
  uint8_t masterPicVectorBase_ = 0;
  uint8_t slavePicVectorBase_ = 0;
  uint8_t masterPicInitStep_ = 0;
  uint8_t slavePicInitStep_ = 0;
  // Diagnostic counters — how many ICW1 (init) sequences the guest started.
  uint32_t masterPicIcw1Writes_ = 0;
  uint32_t slavePicIcw1Writes_ = 0;
  uint8_t masterPicIcw2Value_ = 0;
  uint8_t slavePicIcw2Value_ = 0;
  uint8_t port92_ = 0x02; // A20 enabled.
  uint32_t pciConfigAddress_ = 0;
  uint16_t ideCommand_ = 0x0001; // IO-space enabled; BMDMA not emulated yet.
  // PIIX4 IDE Timing register (PCI config 0x40-0x43): IDETIM_P @0x40-0x41,
  // IDETIM_S @0x42-0x43. Bit 15 of each is "IDE Decode Enable". intelide's
  // PciIdeChannelEnabled callback reads exactly these bits to decide which
  // channels exist; a channel reading decode-disabled gets NO channel PDO, so
  // ataport never binds, never issues IDENTIFY, the boot disk is never
  // enumerated -> INACCESSIBLE_BOOT_DEVICE (0x7B). A real platform BIOS sets
  // these during POST; OVMF drives ATA via its own legacy path and never
  // touches IDETIM, so we default it to "primary channel decode-enabled"
  // (0x00008000) as if the BIOS had. Secondary stays disabled -- the disk is on
  // the primary channel and the secondary is empty (nullptr controller).
  uint32_t ideTimingReg_ = 0x00008000u;
  std::array<uint32_t, 5> ideBarWriteValues_{0x000001F1u, 0x000003F5u,
                                             0x00000171u, 0x00000375u,
                                             0x0000C001u};
  std::array<bool, 5> ideBarSizing_{};
  // Bus-master IDE (BMDMA / BAR4). Dormant: BAR4 reads 0 (no DMA advertised) so
  // the guest never locates this block; the handlers stay compiled for a future
  // real PRD DMA engine. NOTE: the earlier theory that intelide needs BMDMA to
  // create channels was WRONG -- the channels are gated by IDETIM decode-enable
  // (see ideTimingReg_), not bus-master. BAR4 is OS-relocatable, so the host
  // re-attaches the 16-port block whenever the guest reassigns it.
  uint16_t ideBmdmaBase_ = 0xC000;        // current guest-assigned BMDMA base.
  bool ideBmdmaAttachDirty_ = false;      // base changed -> host must re-attach.
  std::array<uint8_t, 16> bmdmaRegs_{};   // BMICX/BMISX/BMIDTPX, both channels.
  uint32_t ideConfigSelects_ = 0;         // # of CF8 selects of dev 1.1 (IDE).
  uint32_t vgaBar0_ = 0x80000008u;
  uint32_t vgaBar0WriteValue_ = 0x80000008u;
  bool vgaBar0Sizing_ = false;
  std::string debugOutput_;
  bool ideControllerPresent_ = false;
  bool ahciControllerPresent_ = false;
  // AHCI HBA memory window (PCI BAR5 / ABAR). A 32-bit, non-prefetchable memory
  // BAR sized to 4 KiB; the guest's PCI enumeration assigns its base. Default
  // base is a placeholder inside the PCI MMIO window until the guest assigns it.
  uint32_t ahciAbar_ = 0xFEBB0000u;
  bool ahciAbarSizing_ = false;
  bool ahciAbarDirty_ = false;
  // e1000 NIC (PCI dev 4). Present only when explicitly enabled
  // (ANTIMAL_ENABLE_NIC); default boots have no NIC, so PCI config returns
  // all-ones for dev 4 and enumeration is byte-identical to today. BAR0 is a
  // 32-bit non-prefetchable 128 KiB memory BAR.
  bool nicPresent_ = false;
  uint32_t nicBar0_ = 0xFE900000u;
  bool nicBar0Sizing_ = false;
  bool nicBar0Dirty_ = false;
  bool resetRequested_ = false; // guest wrote 0xCF9 reset bit -> warm-reset the VM.
  bool vgaControllerPresent_ = false;
  bool acpiTablesEnabled_ = true;
  uint32_t processorCount_ = 1;
  uint64_t tpmEventLogGpa_ = 0;
  uint32_t tpmEventLogSize_ = 0;
  uint32_t cpuHotplugSelected_ = 0;
  bool cpuHotplugSelectionValid_ = true;
  uint8_t cpuHotplugCommand_ = 0;
  uint16_t fwCfgSelector_ = 0;
  size_t fwCfgOffset_ = 0;
  uint64_t ioApicBase_ = 0xFEC00000ull;
  uint64_t hpetBase_ = 0xFED00000ull;
  uint64_t tpmCrbBase_ = 0xFED40000ull;
  bool tpm2TableEnabled_ = true;
  PcIoMemoryLayout memory_{};
  AcpiBuildArtifacts acpi_;
  std::vector<uint8_t> smbiosTables_;
  std::vector<uint8_t> smbiosAnchor_;
  uint64_t fwCfgFileDirBytesRead_ = 0;
  uint64_t fwCfgE820BytesRead_ = 0;
  uint64_t fwCfgAcpiTableBytesRead_ = 0;
  uint64_t fwCfgTableLoaderBytesRead_ = 0;
  uint64_t fwCfgRsdpBytesRead_ = 0;
  uint64_t fwCfgSmbiosTableBytesRead_ = 0;
  uint64_t fwCfgSmbiosAnchorBytesRead_ = 0;

public:
  bool PitInterruptPending() const noexcept;
  void ConsumePitInterrupt() noexcept;
  bool RtcInterruptPending() const noexcept;
  void ConsumeRtcInterrupt() noexcept;
  uint64_t PitIrqCount() const noexcept { return pitIrqCount_; }
  uint64_t RtcIrqCount() const noexcept { return rtcIrqCount_; }

private:
  // Wall-clock epoch for free-running timers. Set on first read so guest
  // calibration sees timestamps relative to first observation rather than
  // host boot time, which keeps the values inside the 24-bit PM-timer
  // window for a long time.
  mutable std::chrono::steady_clock::time_point timerEpoch_{};
  mutable bool timerEpochSet_ = false;

  // Per-channel PIT state. v1 supports the latched / current-count reads
  // Windows uses to calibrate the TSC. Reload values are 16 bits with 0
  // meaning 65536, decremented at 1.193182 MHz.
  struct PitChannel {
    uint16_t reload = 0xFFFF; // 0 means 65536.
    uint8_t accessMode = 3;   // ICW: 1=lobyte, 2=hibyte, 3=lo/hi.
    uint8_t mode = 2;         // 0..5, mostly mode 2 (rate generator).
    bool bcd = false;
    bool latched = false;
    uint16_t latchedValue = 0;
    bool readingHigh = false;   // For lo/hi access mode toggling.
    bool writingHigh = false;   // Same, for reload writes.
    uint8_t pendingReloadLow = 0;
  };
  mutable std::array<PitChannel, 3> pit_{};

  // RTC status-C latch state. UF (update-ended) is set by hardware each
  // time a second boundary crosses and cleared by a read of register C.
  // Tracking the wall-clock timestamp of the last read of C lets us return
  // UF=1 on the first read after a new boundary, matching real silicon.
  mutable int64_t rtcStatusCLastReadUs_ = 0;

  // PIT IRQ0 delivery state. Channel 0 fires at 1193182/reload Hz. We
  // track the wall-clock time of the last delivered IRQ0 and compare
  // against the programmed period to decide when the next one is due.
  mutable std::chrono::steady_clock::time_point pitLastIrq_{};
  mutable bool pitIrqPending_ = false;
  mutable uint64_t pitIrqCount_ = 0;

  // RTC IRQ8 delivery state. When UIE (bit 4 of Status B) is set by the
  // guest, IRQ8 fires at each second boundary. We track the last
  // delivered second so we fire exactly once per boundary.
  mutable int64_t rtcLastIrqSecond_ = 0;
  mutable bool rtcIrqPending_ = false;
  mutable uint64_t rtcIrqCount_ = 0;
};

} // namespace antimal::hv
