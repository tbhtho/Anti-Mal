#include "antimal/hv/PcIoDevices.h"

#include "antimal/hv/BochsVbe.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iterator>
#include <string_view>

namespace antimal::hv {

namespace {

constexpr uint16_t kPic1Command = 0x20;
constexpr uint16_t kPic1Data = 0x21;
constexpr uint16_t kPitChannel0 = 0x40;
constexpr uint16_t kPitMode = 0x43;
constexpr uint16_t kPostPort = 0x80;
constexpr uint16_t kCmosIndex = 0x70;
constexpr uint16_t kCmosData = 0x71;
constexpr uint16_t kPort92 = 0x92;
constexpr uint16_t kPic2Command = 0xA0;
constexpr uint16_t kPic2Data = 0xA1;
constexpr uint16_t kPciConfigAddress = 0xCF8;
constexpr uint16_t kPciConfigData = 0xCFC;
constexpr uint16_t kVgaLegacyBase = 0x3C0;
constexpr uint16_t kVgaLegacyLast = 0x3DF;
constexpr uint16_t kDebugConPort = 0x402;
constexpr uint16_t kFwCfgSelector = 0x510;
constexpr uint16_t kFwCfgData = 0x511;
constexpr uint16_t kCpuHotplugBase = 0xAF00;
constexpr uint16_t kCpuHotplugLast = 0xAF1F;
constexpr uint16_t kPmIoBase = 0xB000;
constexpr uint16_t kPmTimerPort = kPmIoBase + 0x08;

constexpr uint16_t kFwCfgSignature = 0x0000;
constexpr uint16_t kFwCfgId = 0x0001;
constexpr uint16_t kFwCfgRamSize = 0x0003;
constexpr uint16_t kFwCfgNbCpus = 0x0005;
constexpr uint16_t kFwCfgFileDir = 0x0019;
constexpr uint16_t kFwCfgFileFirst = 0x0020;
constexpr uint16_t kFwCfgEtcE820 = kFwCfgFileFirst;
constexpr uint16_t kFwCfgAcpiTables = kFwCfgFileFirst + 1;
constexpr uint16_t kFwCfgTableLoader = kFwCfgFileFirst + 2;
constexpr uint16_t kFwCfgAcpiRsdp = kFwCfgFileFirst + 3;

std::tm UtcNow() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  gmtime_s(&tm, &now);
  return tm;
}

// Returns a wallclock-derived std::tm whose value is guaranteed STABLE
// across consecutive calls within the same wall-clock second. Each call
// only recomputes the std::tm when std::time(nullptr) has actually
// advanced. This is the contract real RTC silicon offers via the UIP bit:
// within a single non-update window, every register read returns the
// same value. OVMF's PcRtcDxe `GetTime` and bootmgr's polling loops rely
// on that contract — without it we observed bootmgr spinning at ~14 kHz
// re-reading the date/time fields when sub-microsecond reads
// occasionally bridged a wall-second boundary and returned mismatched
// seconds across an atomic read sequence.
std::tm UtcNowStable() {
  static thread_local std::time_t cachedSecond = 0;
  static thread_local std::tm cachedTm{};
  static thread_local bool cacheValid = false;
  const std::time_t now = std::time(nullptr);
  if (!cacheValid || cachedSecond != now) {
    gmtime_s(&cachedTm, &now);
    cachedSecond = now;
    cacheValid = true;
  }
  return cachedTm;
}

bool RtcUpdateInProgress() {
  // Real MC146818 RTC asserts UIP for roughly 244 microseconds before each
  // second tick and clears it for the rest of the second.
  constexpr int64_t kVirtualUipWindowUs = 244;
  using namespace std::chrono;
  const auto since =
      duration_cast<microseconds>(system_clock::now().time_since_epoch())
          .count();
  const auto microsInSecond = since % 1000000ll;
  return microsInSecond >= 1000000ll - kVirtualUipWindowUs;
}

uint8_t LowByte(uint16_t value) {
  return static_cast<uint8_t>(value & 0xFFu);
}

uint8_t HighByte(uint16_t value) {
  return static_cast<uint8_t>((value >> 8) & 0xFFu);
}

uint32_t AccessMask(uint8_t accessSize) {
  switch (accessSize) {
  case 1:
    return 0xFFu;
  case 2:
    return 0xFFFFu;
  default:
    return 0xFFFFFFFFu;
  }
}

uint8_t Le16Byte(uint16_t value, size_t offset) {
  if (offset >= 2) {
    return 0;
  }
  return static_cast<uint8_t>((value >> (offset * 8)) & 0xFFu);
}

uint8_t Le32Byte(uint32_t value, size_t offset) {
  if (offset >= 4) {
    return 0;
  }
  return static_cast<uint8_t>((value >> (offset * 8)) & 0xFFu);
}

uint8_t Le64Byte(uint64_t value, size_t offset) {
  if (offset >= 8) {
    return 0;
  }
  return static_cast<uint8_t>((value >> (offset * 8)) & 0xFFu);
}

uint8_t Be16Byte(uint16_t value, size_t offset) {
  if (offset >= 2) {
    return 0;
  }
  return static_cast<uint8_t>((value >> ((1 - offset) * 8)) & 0xFFu);
}

uint8_t Be32Byte(uint32_t value, size_t offset) {
  if (offset >= 4) {
    return 0;
  }
  return static_cast<uint8_t>((value >> ((3 - offset) * 8)) & 0xFFu);
}

uint8_t Bcd(uint8_t value) {
  return static_cast<uint8_t>(((value / 10u) << 4u) | (value % 10u));
}

} // namespace

PcIoDevices::PcIoDevices() : acpi_(BuildPcAcpiTables()) {}

uint8_t PcIoDevices::FwCfgFileDirByte(size_t offset) const {
  struct Entry {
    uint32_t size;
    uint16_t selector;
    std::string_view name;
  };
  const Entry entries[] = {
      {static_cast<uint32_t>(E820Size()), kFwCfgEtcE820, "etc/e820"},
      {static_cast<uint32_t>(acpi_.tables.size()), kFwCfgAcpiTables,
       "etc/acpi/tables"},
      {static_cast<uint32_t>(acpi_.tableLoader.size()), kFwCfgTableLoader,
       "etc/table-loader"},
      {static_cast<uint32_t>(acpi_.rsdp.size()), kFwCfgAcpiRsdp,
       "etc/acpi/rsdp"},
  };
  const size_t entryCount = acpiTablesEnabled_ ? std::size(entries) : 1u;

  if (offset < 4) {
    return Be32Byte(static_cast<uint32_t>(entryCount), offset);
  }

  const size_t entryOffset = offset - 4;
  const size_t entry = entryOffset / 64;
  const size_t field = entryOffset % 64;
  if (entry >= entryCount) {
    return 0;
  }

  const Entry &e = entries[entry];
  if (field < 4) {
    return Be32Byte(e.size, field);
  }
  if (field < 6) {
    return Be16Byte(e.selector, field - 4);
  }
  if (field < 8) {
    return 0;
  }

  const size_t nameOffset = field - 8;
  return nameOffset < e.name.size() ? static_cast<uint8_t>(e.name[nameOffset])
                                    : 0;
}

size_t PcIoDevices::E820Size() const noexcept {
  return (memory_.highRamBytes > 0 ? 2u : 1u) * 20u;
}

uint8_t PcIoDevices::E820Byte(size_t offset) const {
  // QEMU's OVMF-facing etc/e820 is a RAM-range inventory, not the final
  // BIOS/OS e820 map. OVMF treats the first RAM entry at base zero as the
  // complete low-memory size, then publishes the legacy 640K hole, PCI MMIO
  // apertures, LAPIC/IOAPIC/HPET, and firmware reservations itself.
  const uint64_t lowRamBytes =
      memory_.lowRamBytes > 0x100000ull ? memory_.lowRamBytes : 0x100000ull;
  const uint64_t bases[] = {
      0x00000000ull,
      0x100000000ull,
  };
  const uint64_t lengths[] = {
      lowRamBytes,
      memory_.highRamBytes,
  };
  const uint32_t types[] = {
      1u, // usable RAM
      1u, // usable RAM above 4 GiB.
  };

  const size_t entryCount = memory_.highRamBytes > 0 ? 2u : 1u;
  constexpr size_t kEntrySize = 20;
  const size_t entry = offset / kEntrySize;
  const size_t field = offset % kEntrySize;
  if (entry >= entryCount) {
    return 0;
  }
  if (field < 8) {
    return Le64Byte(bases[entry], field);
  }
  if (field < 16) {
    return Le64Byte(lengths[entry], field - 8);
  }
  return Le32Byte(types[entry], field - 16);
}

void PcIoDevices::OnWrite(uint16_t port, uint32_t value, uint8_t accessSize) {
  const uint8_t byte = static_cast<uint8_t>(value & 0xFFu);
  if (port == kFwCfgSelector) {
    fwCfgSelector_ = static_cast<uint16_t>(value & 0x3FFFu);
    fwCfgOffset_ = 0;
    return;
  }
  if (port == kFwCfgData) {
    return;
  }
  if (port == kDebugConPort) {
    debugOutput_.push_back(static_cast<char>(byte));
    return;
  }
  if (port >= kCpuHotplugBase && port <= kCpuHotplugLast) {
    WriteCpuHotplug(port, value, accessSize);
    return;
  }
  if (port >= kPmIoBase && port < kPmIoBase + 0x100) {
    // PIIX4 PM1a control register at PM base + 0x04. SLP_EN (bit 13) +
    // SLP_TYP (bits 10..12) request an ACPI sleep transition. SLP_TYP=5
    // is S5 (soft off / shutdown); SLP_TYP=4 is S4 (hibernate, also acts
    // as shutdown for us). OVMF's ResetSystemRuntimeDxe writes here when
    // RT->ResetSystem(EfiResetShutdown) is invoked, then spins waiting
    // for the host to halt the vCPU.
    if (port == kPmIoBase + 0x04 || port == kPmIoBase + 0x05) {
      const uint32_t pmCntValue =
          port == kPmIoBase + 0x04 ? value : (value << 8);
      if ((pmCntValue & 0x2000u) != 0) {
        lastSleepType_ = static_cast<uint8_t>((pmCntValue >> 10) & 0x7u);
        shutdownRequested_ = true;
      }
    }
    return;
  }
  if (port >= kPciConfigAddress && port < kPciConfigAddress + 4) {
    WritePciAddressWindow(port, value, accessSize);
    return;
  }
  if (port >= kPciConfigData && port < kPciConfigData + 4) {
    return;
  }
  if (port >= kVgaLegacyBase && port <= kVgaLegacyLast) {
    return;
  }
  if (port <= 0x0F || port == kPostPort || port == 0xED) {
    return;
  }

  switch (port) {
  case kPic1Command:
    WritePicCommand(true, byte);
    break;
  case kPic2Command:
    WritePicCommand(false, byte);
    break;
  case kPic1Data:
    WritePicData(true, byte);
    break;
  case kPic2Data:
    WritePicData(false, byte);
    break;
  case kCmosIndex:
    nmiMasked_ = (byte & 0x80u) != 0;
    cmosIndex_ = static_cast<uint8_t>(byte & 0x7Fu);
    RecordCmosAccess(kCmosIndex, cmosIndex_, byte, /*isWrite=*/true);
    break;
  case kCmosData:
    cmos_[cmosIndex_] = byte;
    cmosWritten_[cmosIndex_] = true;
    RecordCmosAccess(kCmosData, cmosIndex_, byte, /*isWrite=*/true);
    break;
  case kPort92:
    port92_ = byte;
    break;
  case kPitChannel0:
  case 0x41:
  case 0x42:
  case kPitMode:
    HandlePitWrite(port, byte);
    break;
  default:
    break;
  }
}

void PcIoDevices::HandlePitWrite(uint16_t port, uint8_t value) {
  if (port == kPitMode) {
    // Mode/command byte: bits [7:6]=channel, [5:4]=access, [3:1]=mode, [0]=BCD.
    const uint8_t channel = static_cast<uint8_t>((value >> 6) & 0x3u);
    if (channel == 3) {
      // Read-back command. Treat as latch for all channels selected by bits
      // [3:1]: bit 1=ch0, bit 2=ch1, bit 3=ch2.
      const auto now = std::chrono::steady_clock::now();
      if (!timerEpochSet_) {
        timerEpoch_ = now;
        timerEpochSet_ = true;
      }
      const auto delta =
          std::chrono::duration_cast<std::chrono::nanoseconds>(now -
                                                                timerEpoch_)
              .count();
      const uint64_t ticks =
          (static_cast<uint64_t>(delta) * 1193182ull) / 1000000000ull;
      for (uint8_t ch = 0; ch < 3; ++ch) {
        if ((value & (1u << (ch + 1))) == 0) {
          continue;
        }
        const uint16_t reload =
            pit_[ch].reload == 0 ? 0xFFFF : pit_[ch].reload;
        const uint16_t current =
            static_cast<uint16_t>(reload - (ticks % (reload + 1)));
        pit_[ch].latched = true;
        pit_[ch].latchedValue = current;
        pit_[ch].readingHigh = false;
      }
      return;
    }
    const uint8_t access = static_cast<uint8_t>((value >> 4) & 0x3u);
    if (access == 0) {
      // Counter latch command for the selected channel.
      const auto now = std::chrono::steady_clock::now();
      if (!timerEpochSet_) {
        timerEpoch_ = now;
        timerEpochSet_ = true;
      }
      const auto delta =
          std::chrono::duration_cast<std::chrono::nanoseconds>(now -
                                                                timerEpoch_)
              .count();
      const uint64_t ticks =
          (static_cast<uint64_t>(delta) * 1193182ull) / 1000000000ull;
      const uint16_t reload =
          pit_[channel].reload == 0 ? 0xFFFF : pit_[channel].reload;
      pit_[channel].latched = true;
      pit_[channel].latchedValue =
          static_cast<uint16_t>(reload - (ticks % (reload + 1)));
      pit_[channel].readingHigh = false;
      return;
    }
    pit_[channel].accessMode = access;
    pit_[channel].mode = static_cast<uint8_t>((value >> 1) & 0x7u);
    pit_[channel].bcd = (value & 0x1u) != 0;
    pit_[channel].latched = false;
    pit_[channel].readingHigh = false;
    pit_[channel].writingHigh = false;
    return;
  }

  // Channel data ports 0x40-0x42.
  const uint8_t channel = static_cast<uint8_t>(port - kPitChannel0);
  if (channel >= 3) {
    return;
  }
  auto &c = pit_[channel];
  if (c.accessMode == 1) {
    c.reload = value;
  } else if (c.accessMode == 2) {
    c.reload = static_cast<uint16_t>(value << 8);
  } else { // lo/hi
    if (!c.writingHigh) {
      c.pendingReloadLow = value;
      c.writingHigh = true;
    } else {
      c.reload = static_cast<uint16_t>(c.pendingReloadLow |
                                       (static_cast<uint16_t>(value) << 8));
      c.writingHigh = false;
    }
  }
  // Reset the latch on a fresh reload write — calibration loops typically
  // reload then latch + read alternating high/low bytes.
  c.latched = false;
  c.readingHigh = false;
}

uint8_t PcIoDevices::ReadPitChannel(uint8_t channel) {
  if (channel >= 3) {
    return 0;
  }
  auto &c = pit_[channel];
  if (!c.latched) {
    const auto now = std::chrono::steady_clock::now();
    if (!timerEpochSet_) {
      timerEpoch_ = now;
      timerEpochSet_ = true;
    }
    const auto delta =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - timerEpoch_)
            .count();
    const uint64_t ticks =
        (static_cast<uint64_t>(delta) * 1193182ull) / 1000000000ull;
    const uint16_t reload = c.reload == 0 ? 0xFFFF : c.reload;
    c.latchedValue =
        static_cast<uint16_t>(reload - (ticks % (reload + 1)));
    // The "latch" flag stays clear here — read-on-the-fly mode returns the
    // current count without an explicit latch; calibration code does a latch
    // first when it wants a coherent snapshot.
  }
  uint8_t byte;
  if (c.accessMode == 1) {
    byte = static_cast<uint8_t>(c.latchedValue & 0xFFu);
  } else if (c.accessMode == 2) {
    byte = static_cast<uint8_t>((c.latchedValue >> 8) & 0xFFu);
  } else {
    byte = c.readingHigh
               ? static_cast<uint8_t>((c.latchedValue >> 8) & 0xFFu)
               : static_cast<uint8_t>(c.latchedValue & 0xFFu);
    c.readingHigh = !c.readingHigh;
    if (!c.readingHigh) {
      // Completed a full 16-bit latched read — drop the latch so the next
      // read picks up the new free-running count.
      c.latched = false;
    }
  }
  return byte;
}

void PcIoDevices::WritePicCommand(bool master, uint8_t value) {
  // ICW1 has bit 4 (0x10) set, signalling the start of the four-step PIC
  // initialization sequence. The remaining writes go to the data port and
  // are ICW2 (vector base), ICW3 (cascade map), ICW4 (mode).
  if ((value & 0x10u) != 0) {
    if (master) {
      masterPicInitStep_ = 1;
    } else {
      slavePicInitStep_ = 1;
    }
  }
}

void PcIoDevices::WritePicData(bool master, uint8_t value) {
  uint8_t &step = master ? masterPicInitStep_ : slavePicInitStep_;
  if (step == 1) {
    if (master) {
      masterPicVectorBase_ = value;
    } else {
      slavePicVectorBase_ = value;
    }
    step = 2;
    return;
  }
  if (step == 2) {
    // ICW3 — cascade configuration. Nothing to track here.
    step = 3;
    return;
  }
  if (step == 3) {
    // ICW4 — operating mode flags. With initialization complete the next
    // writes resume normal OCW1 mask programming.
    step = 0;
    return;
  }
  if (master) {
    masterPicMask_ = value;
  } else {
    slavePicMask_ = value;
  }
}

uint32_t PcIoDevices::OnRead(uint16_t port, uint8_t accessSize) {
  if (port == kFwCfgData) {
    return ReadFwCfgData(accessSize);
  }
  if (port == kDebugConPort) {
    // QEMU debugcon convention: reads return the magic byte 0xE9 so the
    // guest can probe "is the debugcon present?". OVMF's BaseDebugLibIoPort
    // gates ALL DebugPrint() output on this probe — returning the wrong
    // value (or 0) silently disables every DEBUG() macro in the firmware,
    // which is why serial.log was empty in earlier runs despite 374 writes
    // to port 0x402.
    return 0xE9;
  }
  if (port >= kCpuHotplugBase && port <= kCpuHotplugLast) {
    return ReadCpuHotplug(port, accessSize);
  }
  if (port >= kPmIoBase && port < kPmIoBase + 0x100) {
    return ReadPmIo(port, accessSize);
  }
  if (port >= kPciConfigAddress && port < kPciConfigAddress + 4) {
    const uint8_t shift =
        static_cast<uint8_t>((port - kPciConfigAddress) * 8u);
    return pciConfigAddress_ >> shift;
  }
  if (port >= kPciConfigData && port < kPciConfigData + 4) {
    const uint8_t shift = static_cast<uint8_t>((port - kPciConfigData) * 8u);
    return ReadPciConfigDword() >> shift;
  }
  if (port >= kVgaLegacyBase && port <= kVgaLegacyLast) {
    return port == 0x3DA ? 0x08u : 0u;
  }
  if (port <= 0x0F || port == kPostPort || port == 0xED) {
    return 0;
  }

  switch (port) {
  case kPic1Command:
  case kPic2Command:
    return 0; // No IRQ pending/in-service.
  case kPic1Data:
    return masterPicMask_;
  case kPic2Data:
    return slavePicMask_;
  case kPitChannel0:
  case 0x41:
  case 0x42:
    return ReadPitChannel(static_cast<uint8_t>(port - kPitChannel0));
  case kPitMode:
    return 0;
  case kCmosIndex: {
    const uint8_t value =
        static_cast<uint8_t>(cmosIndex_ | (nmiMasked_ ? 0x80u : 0u));
    RecordCmosAccess(kCmosIndex, cmosIndex_, value, /*isWrite=*/false);
    return value;
  }
  case kCmosData: {
    ++cmosReadHistogram_[cmosIndex_ & 0x7Fu];
    const uint8_t value = ReadCmos(cmosIndex_);
    RecordCmosAccess(kCmosData, cmosIndex_, value, /*isWrite=*/false);
    return value;
  }
  case kPort92:
    return port92_;
  default:
    return 0;
  }
}

uint32_t PcIoDevices::ReadFwCfgData(uint8_t accessSize) {
  uint32_t value = 0;
  const uint8_t bytes = accessSize == 1 ? 1 : accessSize == 2 ? 2 : 4;
  for (uint8_t i = 0; i < bytes; ++i) {
    value |= static_cast<uint32_t>(ReadFwCfgByte()) << (i * 8);
  }
  return value;
}

uint8_t PcIoDevices::ReadFwCfgByte() {
  const size_t offset = fwCfgOffset_++;
  switch (fwCfgSelector_) {
  case kFwCfgSignature: {
    constexpr char kSignature[] = {'Q', 'E', 'M', 'U'};
    return offset < sizeof(kSignature)
               ? static_cast<uint8_t>(kSignature[offset])
               : 0;
  }
  case kFwCfgId:
    return Le32Byte(1, offset);
  case kFwCfgRamSize:
    // QEMU's legacy RAM_SIZE item represents contiguous low memory. High RAM
    // is advertised through etc/e820; including it here makes OVMF pick early
    // PEI shadow-copy destinations above 4G before its page tables cover them.
    return Le64Byte(memory_.lowRamBytes, offset);
  case kFwCfgNbCpus:
    return Le16Byte(static_cast<uint16_t>(std::min<uint32_t>(
                        processorCount_, 0xFFFFu)),
                    offset);
  case kFwCfgFileDir:
    ++fwCfgFileDirBytesRead_;
    return FwCfgFileDirByte(offset);
  case kFwCfgEtcE820:
    ++fwCfgE820BytesRead_;
    return E820Byte(offset);
  case kFwCfgAcpiTables:
  case kFwCfgTableLoader:
  case kFwCfgAcpiRsdp:
    if (!acpiTablesEnabled_) {
      return 0;
    }
    return FwCfgFileDataByte(fwCfgSelector_, offset);
  default:
    return 0;
  }
}

uint8_t PcIoDevices::FwCfgFileDataByte(uint16_t selector, size_t offset) {
  const std::vector<uint8_t> *data = nullptr;
  if (selector == kFwCfgAcpiTables) {
    ++fwCfgAcpiTableBytesRead_;
    data = &acpi_.tables;
  } else if (selector == kFwCfgTableLoader) {
    ++fwCfgTableLoaderBytesRead_;
    data = &acpi_.tableLoader;
  } else if (selector == kFwCfgAcpiRsdp) {
    ++fwCfgRsdpBytesRead_;
    data = &acpi_.rsdp;
  }
  if (!data || offset >= data->size()) {
    return 0;
  }
  return (*data)[offset];
}

void PcIoDevices::WriteCpuHotplug(uint16_t port, uint32_t value,
                                  uint8_t accessSize) {
  const uint16_t offset = static_cast<uint16_t>(port - kCpuHotplugBase);
  // OVMF's modern QEMU CPU hotplug probe writes a 32-bit selector at offset
  // 0 and an 8-bit command at offset 5. CPU#N is present/enabled when N is
  // inside the configured static processor count; all larger selectors
  // terminate OVMF's possible-CPU enumeration.
  if (offset == 0 && accessSize == 4) {
    cpuHotplugSelected_ = value;
    cpuHotplugSelectionValid_ = value < processorCount_;
    return;
  }
  if (offset == 5) {
    cpuHotplugCommand_ = static_cast<uint8_t>(value & 0xFFu);
    return;
  }
}

uint32_t PcIoDevices::ReadCpuHotplug(uint16_t port,
                                     uint8_t /*accessSize*/) const {
  const uint16_t offset = static_cast<uint16_t>(port - kCpuHotplugBase);
  switch (offset) {
  case 0:
    // QEMU_CPUHP_R_CMD_DATA2. After GET_PENDING, modern mode exposes zero.
    // A nonzero legacy bitmap would make OVMF skip modern enumeration.
    return 0;
  case 4:
    // QEMU_CPUHP_R_CPU_STAT. CPU#0 is present and enabled.
    return cpuHotplugSelectionValid_ ? 0x01u : 0u;
  case 8:
    // QEMU_CPUHP_RW_CMD_DATA. Returning 0 for an invalid positive selector
    // terminates OVMF's possible-CPU enumeration at one CPU.
    return cpuHotplugSelectionValid_ ? cpuHotplugSelected_ : 0u;
  default:
    return 0;
  }
}

void PcIoDevices::WritePciAddressWindow(uint16_t port, uint32_t value,
                                        uint8_t accessSize) {
  const uint8_t shift =
      static_cast<uint8_t>((port - kPciConfigAddress) * 8u);
  const uint32_t mask = AccessMask(accessSize) << shift;
  pciConfigAddress_ =
      (pciConfigAddress_ & ~mask) | ((value << shift) & mask);
}

uint32_t PcIoDevices::ReadPciConfigDword() const {
  if ((pciConfigAddress_ & 0x80000000u) == 0) {
    return 0xFFFFFFFFu;
  }

  const uint8_t bus = static_cast<uint8_t>((pciConfigAddress_ >> 16) & 0xFFu);
  const uint8_t device =
      static_cast<uint8_t>((pciConfigAddress_ >> 11) & 0x1Fu);
  const uint8_t function =
      static_cast<uint8_t>((pciConfigAddress_ >> 8) & 0x07u);
  const uint8_t reg = static_cast<uint8_t>(pciConfigAddress_ & 0xFCu);

  if (bus != 0) {
    return 0xFFFFFFFFu;
  }

  if (device == 0 && function == 0) {
    switch (reg) {
    case 0x00:
      return 0x12378086u; // Intel 82441FX host bridge.
    case 0x08:
      return 0x06000002u; // Host bridge class code.
    case 0x0C:
      return 0x00000000u; // Type-0 header.
    default:
      return 0;
    }
  }

  if (device == 1 && function == 0) {
    switch (reg) {
    case 0x00:
      return 0x70008086u; // Intel PIIX3 ISA bridge.
    case 0x08:
      return 0x06010000u; // ISA bridge class code.
    case 0x0C:
      return 0x00800000u; // Type-0 multifunction header.
    default:
      return 0;
    }
  }

  if (ideControllerPresent_ && device == 1 && function == 1) {
    switch (reg) {
    case 0x00:
      return 0x71118086u; // Intel PIIX4 IDE controller.
    case 0x04:
      return 0x00000005u; // IO + bus master enabled.
    case 0x08:
      return 0x01018A01u; // IDE storage class, legacy/native capable.
    case 0x0C:
      return 0x00000000u; // Type-0 header.
    default:
      return 0;
    }
  }

  if (device == 1 && function == 3) {
    switch (reg) {
    case 0x00:
      return 0x71138086u; // Intel PIIX4 ACPI PM.
    case 0x04:
      return 0x00000007u; // IO + memory + bus master enabled.
    case 0x08:
      return 0x06800003u; // Bridge/other class, rev 3.
    case 0x0C:
      return 0x00000000u; // Type-0 header.
    case 0x40:
      return kPmIoBase | 0x1u; // PMBA IO base, enabled.
    case 0x80:
      return 0x00000001u; // ACPI enable bit.
    default:
      return 0;
    }
  }

  if (vgaControllerPresent_ && device == 2 && function == 0) {
    // QEMU Standard VGA / Bochs VBE display. OVMF's QemuVideoDxe driver
    // probes this exact (vendor, device) pair and lights up GOP for the
    // firmware + bootloader + Windows kernel as soon as it sees us.
    switch (reg) {
    case 0x00:
      return 0x11111234u; // Vendor 0x1234, Device 0x1111.
    case 0x04:
      return 0x00000003u; // Memory + IO space decoding enabled.
    case 0x08:
      return 0x03000000u; // Class code: VGA controller.
    case 0x0C:
      return 0x00000000u; // Type-0 header.
    case 0x10:
      // BAR0 — linear framebuffer at the configured GPA. Bit 3 set marks
      // the BAR as prefetchable, bits [1:0] = 0 means 32-bit memory.
      return static_cast<uint32_t>(BochsVbeDevice::kFramebufferGpa) | 0x8u;
    case 0x14:
      return 0;          // BAR1 — unused.
    case 0x18:
      return 0;          // BAR2 — unused (we use IO ports for the VBE regs).
    case 0x3C:
      return 0x00000000u; // No interrupt routing.
    default:
      return 0;
    }
  }

  return 0xFFFFFFFFu;
}

uint32_t PcIoDevices::ReadPmIo(uint16_t port, uint8_t /*accessSize*/) {
  if (port >= kPmTimerPort && port < kPmTimerPort + 4) {
    const uint32_t value = CurrentPmTimer();
    const uint8_t shift = static_cast<uint8_t>((port - kPmTimerPort) * 8u);
    return value >> shift;
  }
  return 0;
}

uint32_t PcIoDevices::CurrentPmTimer() const {
  // ACPI PM timer runs at 3.579545 MHz (one third of NTSC color burst).
  // The 24-bit counter wraps every ~4.6 seconds; that's fine — calibration
  // only needs a stable rate between two reads.
  const auto now = std::chrono::steady_clock::now();
  if (!timerEpochSet_) {
    timerEpoch_ = now;
    timerEpochSet_ = true;
  }
  const auto delta =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now - timerEpoch_)
          .count();
  // ticks = delta_ns * 3.579545 MHz / 1e9 Hz
  //       = delta_ns * 3579545 / 1000000000
  //       = delta_ns / 279.36... → exact: delta_ns * 3579545 / 1e9
  const uint64_t ticks =
      (static_cast<uint64_t>(delta) * 3579545ull) / 1000000000ull;
  return static_cast<uint32_t>(ticks & 0x00FFFFFFull);
}

void PcIoDevices::RecordCmosAccess(uint16_t port, uint8_t index, uint8_t value,
                                   bool isWrite) const {
  CmosAccess entry{};
  entry.port = port;
  entry.index = index;
  entry.value = value;
  entry.isWrite = isWrite;
  cmosRecent_[cmosRecentHead_] = entry;
  cmosRecentHead_ = (cmosRecentHead_ + 1) % cmosRecent_.size();
  if (cmosRecentCount_ < cmosRecent_.size()) {
    ++cmosRecentCount_;
  }
}

std::vector<PcIoDevices::CmosAccess> PcIoDevices::RecentCmosAccesses() const {
  std::vector<CmosAccess> out;
  out.reserve(cmosRecentCount_);
  // Replay from oldest to newest. When the ring is full, the oldest entry
  // is at cmosRecentHead_; otherwise the oldest entry is at index 0.
  const size_t cap = cmosRecent_.size();
  const size_t start =
      cmosRecentCount_ == cap ? cmosRecentHead_ : 0;
  for (size_t i = 0; i < cmosRecentCount_; ++i) {
    out.push_back(cmosRecent_[(start + i) % cap]);
  }
  return out;
}

uint8_t PcIoDevices::ReadCmos(uint8_t index) const {
  const std::tm now = UtcNow();
  const uint8_t statusA = cmosWritten_[0x0A] ? cmos_[0x0A] : 0x26;
  const uint8_t statusB = cmosWritten_[0x0B] ? cmos_[0x0B] : 0x06;
  const bool binaryMode = (statusB & 0x04u) != 0;
  const auto encode = [&](int value) {
    const auto byte = static_cast<uint8_t>(value & 0xFF);
    return binaryMode ? byte : Bcd(byte);
  };
  const auto encodeHour = [&]() {
    uint8_t hour = static_cast<uint8_t>(now.tm_hour);
    if ((statusB & 0x02u) != 0) {
      return encode(hour);
    }
    const bool pm = hour >= 12;
    hour = static_cast<uint8_t>(hour % 12);
    if (hour == 0) {
      hour = 12;
    }
    uint8_t encoded = binaryMode ? hour : Bcd(hour);
    if (pm) {
      encoded |= 0x80u;
    }
    return encoded;
  };

  switch (index) {
  case 0x00:
    return encode(now.tm_sec);
  case 0x02:
    return encode(now.tm_min);
  case 0x04:
    return encodeHour();
  case 0x06:
    return encode(now.tm_wday == 0 ? 7 : now.tm_wday);
  case 0x07:
    return encode(now.tm_mday);
  case 0x08:
    return encode(now.tm_mon + 1);
  case 0x09:
    return encode((now.tm_year + 1900) % 100);
  case 0x0A:
    return static_cast<uint8_t>((statusA & 0x7Fu) |
                                (RtcUpdateInProgress() ? 0x80u : 0u));
  case 0x0B:
    return statusB;
  case 0x0C: {
    // Register C — interrupt flags. Set by hardware when each event fires,
    // cleared by this read. We track the wall-clock timestamp of the last
    // read so UF (update-ended) reports correctly on the first read after a
    // new second boundary. Without this the kernel waits forever for a
    // transition it never sees.
    using namespace std::chrono;
    const int64_t nowUs =
        duration_cast<microseconds>(system_clock::now().time_since_epoch())
            .count();
    const int64_t currentBoundary = (nowUs / 1000000ll) * 1000000ll;
    uint8_t result = 0;
    if (currentBoundary > rtcStatusCLastReadUs_) {
      result |= 0x40; // UF — update ended since last read.
      result |= 0x80; // IRQF — at least one event flag pending.
    }
    rtcStatusCLastReadUs_ = nowUs;
    return result;
  }
  case 0x0D:
    return 0x80; // RTC battery/power valid.
  case 0x10:
    return 0; // No floppy drives.
  case 0x14:
    return 0x02; // Equipment byte: FPU present.
  case 0x15:
    return LowByte(640);
  case 0x16:
    return HighByte(640);
  case 0x17:
  case 0x30: {
    // Extended memory between 1 MiB and 16 MiB, in 1-KiB units. Saturate at
    // 15 MiB which is what real BIOSes report regardless of how much RAM is
    // installed; the 0x34/0x35 pair carries everything above 16 MiB.
    const uint64_t kib = memory_.lowRamBytes > 0x100000ull
                             ? (memory_.lowRamBytes - 0x100000ull) / 1024ull
                             : 0;
    const uint16_t value =
        static_cast<uint16_t>(kib > 15u * 1024u ? 15u * 1024u : kib);
    return LowByte(value);
  }
  case 0x18:
  case 0x31: {
    const uint64_t kib = memory_.lowRamBytes > 0x100000ull
                             ? (memory_.lowRamBytes - 0x100000ull) / 1024ull
                             : 0;
    const uint16_t value =
        static_cast<uint16_t>(kib > 15u * 1024u ? 15u * 1024u : kib);
    return HighByte(value);
  }
  case 0x32:
    return encode((now.tm_year + 1900) / 100);
  case 0x34: {
    // Extended memory above 16 MiB, in 64-KiB chunks. Capped at 4 GiB - 16 MiB
    // because the field is only 16 bits wide.
    const uint64_t above16Mb =
        memory_.lowRamBytes > 16ull * 1024ull * 1024ull
            ? memory_.lowRamBytes - 16ull * 1024ull * 1024ull
            : 0;
    const uint64_t chunks = above16Mb / (64ull * 1024ull);
    const uint16_t value =
        static_cast<uint16_t>(chunks > 0xFFFFull ? 0xFFFFull : chunks);
    return LowByte(value);
  }
  case 0x35: {
    const uint64_t above16Mb =
        memory_.lowRamBytes > 16ull * 1024ull * 1024ull
            ? memory_.lowRamBytes - 16ull * 1024ull * 1024ull
            : 0;
    const uint64_t chunks = above16Mb / (64ull * 1024ull);
    const uint16_t value =
        static_cast<uint16_t>(chunks > 0xFFFFull ? 0xFFFFull : chunks);
    return HighByte(value);
  }
  case 0x5B: {
    const uint64_t chunks = memory_.highRamBytes / (64ull * 1024ull);
    return static_cast<uint8_t>(chunks & 0xFFu);
  }
  case 0x5C: {
    const uint64_t chunks = memory_.highRamBytes / (64ull * 1024ull);
    return static_cast<uint8_t>((chunks >> 8) & 0xFFu);
  }
  case 0x5D: {
    const uint64_t chunks = memory_.highRamBytes / (64ull * 1024ull);
    return static_cast<uint8_t>((chunks >> 16) & 0xFFu);
  }
  default:
    return cmos_[index & 0x7Fu];
  }
}

bool PcIoDevices::PitInterruptPending() const noexcept {
  if (pitIrqPending_) {
    return true;
  }
  const auto &ch0 = pit_[0];
  if (ch0.mode != 2 && ch0.mode != 3) {
    return false;
  }
  const auto now = std::chrono::steady_clock::now();
  if (!timerEpochSet_) {
    timerEpoch_ = now;
    timerEpochSet_ = true;
  }
  if (pitLastIrq_ == std::chrono::steady_clock::time_point{}) {
    pitLastIrq_ = now;
    return false;
  }
  const uint32_t reload = ch0.reload == 0 ? 0x10000u : ch0.reload;
  const auto periodNs = std::chrono::nanoseconds(
      static_cast<int64_t>((static_cast<uint64_t>(reload) * 1000000000ull) /
                           1193182ull));
  if (now - pitLastIrq_ >= periodNs) {
    pitIrqPending_ = true;
    return true;
  }
  return false;
}

void PcIoDevices::ConsumePitInterrupt() noexcept {
  pitIrqPending_ = false;
  pitLastIrq_ = std::chrono::steady_clock::now();
  ++pitIrqCount_;
}

bool PcIoDevices::RtcInterruptPending() const noexcept {
  if (rtcIrqPending_) {
    return true;
  }
  const uint8_t statusB = cmosWritten_[0x0B] ? cmos_[0x0B] : 0x06;
  const bool uie = (statusB & 0x10u) != 0;
  const bool pie = (statusB & 0x40u) != 0;
  if (!uie && !pie) {
    return false;
  }
  using namespace std::chrono;
  const int64_t nowUs =
      duration_cast<microseconds>(system_clock::now().time_since_epoch())
          .count();
  const int64_t currentSecond = nowUs / 1000000ll;
  if (rtcLastIrqSecond_ == 0) {
    rtcLastIrqSecond_ = currentSecond;
    return false;
  }
  if (uie && currentSecond > rtcLastIrqSecond_) {
    rtcIrqPending_ = true;
    return true;
  }
  return false;
}

void PcIoDevices::ConsumeRtcInterrupt() noexcept {
  rtcIrqPending_ = false;
  using namespace std::chrono;
  rtcLastIrqSecond_ =
      duration_cast<microseconds>(system_clock::now().time_since_epoch())
          .count() /
      1000000ll;
  ++rtcIrqCount_;
}

} // namespace antimal::hv
