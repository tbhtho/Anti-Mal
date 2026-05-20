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
#include <string>
#include <vector>

namespace antimal::hv {

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
  void SetVgaControllerPresent(bool present) noexcept {
    vgaControllerPresent_ = present;
  }
  void SetMemoryLayout(const PcIoMemoryLayout &layout) noexcept {
    memory_ = layout;
  }
  void SetAcpiTablesEnabled(bool enabled) noexcept {
    acpiTablesEnabled_ = enabled;
  }
  void SetProcessorCount(uint32_t count) {
    processorCount_ = count == 0 ? 1u : count;
    acpi_ = BuildPcAcpiTables(processorCount_);
    cpuHotplugSelectionValid_ = cpuHotplugSelected_ < processorCount_;
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
  const std::string &DebugOutput() const noexcept { return debugOutput_; }
  size_t FwCfgFileCount() const noexcept {
    return acpiTablesEnabled_ ? 4 : 1;
  }

  void OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) override;
  uint32_t OnRead(uint16_t port, uint8_t accessSize) override;

private:
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
  uint8_t port92_ = 0x02; // A20 enabled.
  uint32_t pciConfigAddress_ = 0;
  uint32_t vgaBar0_ = 0x80000008u;
  uint32_t vgaBar0WriteValue_ = 0x80000008u;
  bool vgaBar0Sizing_ = false;
  std::string debugOutput_;
  bool ideControllerPresent_ = false;
  bool vgaControllerPresent_ = false;
  bool acpiTablesEnabled_ = true;
  uint32_t processorCount_ = 1;
  uint32_t cpuHotplugSelected_ = 0;
  bool cpuHotplugSelectionValid_ = true;
  uint8_t cpuHotplugCommand_ = 0;
  uint16_t fwCfgSelector_ = 0;
  size_t fwCfgOffset_ = 0;
  PcIoMemoryLayout memory_{};
  AcpiBuildArtifacts acpi_;
  uint64_t fwCfgFileDirBytesRead_ = 0;
  uint64_t fwCfgE820BytesRead_ = 0;
  uint64_t fwCfgAcpiTableBytesRead_ = 0;
  uint64_t fwCfgTableLoaderBytesRead_ = 0;
  uint64_t fwCfgRsdpBytesRead_ = 0;

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
