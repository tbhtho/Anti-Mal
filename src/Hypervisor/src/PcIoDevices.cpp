#include "antimal/hv/PcIoDevices.h"

#include "antimal/hv/BochsVbe.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iterator>
#include <string_view>
#include <utility>

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
constexpr uint32_t kIdePrimaryCommandBar = 0x000001F1u;
constexpr uint32_t kIdePrimaryControlBar = 0x000003F5u;
constexpr uint32_t kIdeSecondaryCommandBar = 0x00000171u;
constexpr uint32_t kIdeSecondaryControlBar = 0x00000375u;
constexpr uint32_t kIdeBusMasterBar = 0x0000C001u;
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
constexpr uint16_t kFwCfgSmbiosTables = kFwCfgFileFirst + 4;
constexpr uint16_t kFwCfgSmbiosAnchor = kFwCfgFileFirst + 5;

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

uint32_t IdeBarSizeMask(size_t index) {
  // PCI IO BAR sizing returns all address bits set except the decoded window.
  // Legacy IDE command blocks decode 8 ports, control blocks decode 4, and the
  // bus-master IDE register block decodes 16.
  switch (index) {
  case 0:
  case 2:
    return 0xFFFFFFF9u;
  case 1:
  case 3:
    return 0xFFFFFFFDu;
  case 4:
    return 0xFFFFFFF1u;
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

void PutLe16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutLe32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void PutLe64(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void StoreLe16(std::vector<uint8_t> &out, size_t offset, uint16_t value) {
  if (offset + 2 > out.size()) {
    return;
  }
  out[offset] = static_cast<uint8_t>(value & 0xFFu);
  out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

void StoreLe32(std::vector<uint8_t> &out, size_t offset, uint32_t value) {
  if (offset + 4 > out.size()) {
    return;
  }
  for (int i = 0; i < 4; ++i) {
    out[offset + static_cast<size_t>(i)] =
        static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

uint8_t Checksum8(const uint8_t *bytes, size_t size) {
  uint8_t sum = 0;
  for (size_t i = 0; i < size; ++i) {
    sum = static_cast<uint8_t>(sum + bytes[i]);
  }
  return static_cast<uint8_t>(0u - sum);
}

void AppendAscii(std::vector<uint8_t> &out, std::string_view text) {
  out.insert(out.end(), text.begin(), text.end());
}

void FinishSmbiosRecord(std::vector<uint8_t> &record,
                        std::initializer_list<std::string_view> strings) {
  if (strings.size() == 0) {
    record.push_back(0);
    record.push_back(0);
    return;
  }
  for (std::string_view text : strings) {
    AppendAscii(record, text);
    record.push_back(0);
  }
  record.push_back(0);
}

std::vector<uint8_t> BeginSmbiosRecord(uint8_t type, uint8_t length,
                                       uint16_t handle) {
  std::vector<uint8_t> record;
  record.reserve(length + 64);
  record.push_back(type);
  record.push_back(length);
  PutLe16(record, handle);
  return record;
}

std::vector<uint8_t> BuildSmbiosEntryPoint(uint16_t tableLength,
                                           uint16_t maxStructureSize,
                                           uint16_t structureCount) {
  // OVMF validates the fw_cfg anchor before it reads
  // etc/smbios/smbios-tables. Keep this as a standard SMBIOS 2.8 entry point:
  // DetectSmbiosVersionLib checks the anchors, major version, and table length,
  // while SmbiosDxe later publishes its own relocated EFI configuration table.
  std::vector<uint8_t> anchor(0x1F, 0);
  std::copy_n("_SM_", 4, anchor.begin());
  anchor[0x05] = 0x1F;
  anchor[0x06] = 2;
  anchor[0x07] = 8;
  StoreLe16(anchor, 0x08, maxStructureSize);
  anchor[0x0A] = 0;
  std::copy_n("_DMI_", 5, anchor.begin() + 0x10);
  StoreLe16(anchor, 0x16, tableLength);
  StoreLe32(anchor, 0x18, 0);
  StoreLe16(anchor, 0x1C, structureCount);
  anchor[0x1E] = 0x28;
  anchor[0x15] = Checksum8(anchor.data() + 0x10, 0x0F);
  anchor[0x04] = Checksum8(anchor.data(), anchor.size());
  return anchor;
}

void AppendSmbiosRecord(std::vector<uint8_t> &tables,
                        std::vector<uint8_t> record,
                        uint16_t *structureCount,
                        uint16_t *maxStructureSize) {
  if (record.size() > *maxStructureSize) {
    *maxStructureSize = static_cast<uint16_t>(record.size());
  }
  tables.insert(tables.end(), record.begin(), record.end());
  ++(*structureCount);
}

void BuildPcSmbiosTables(std::vector<uint8_t> *tables,
                         std::vector<uint8_t> *anchor) {
  tables->clear();
  anchor->clear();

  uint16_t count = 0;
  uint16_t maxStructure = 0;

  {
    auto record = BeginSmbiosRecord(0, 0x18, 0x0000);
    record.push_back(1); // Vendor
    record.push_back(2); // BIOS version
    PutLe16(record, 0xE800);
    record.push_back(3); // BIOS release date
    record.push_back(0); // BIOS size, unknown.
    PutLe64(record, 0x0000000000000008ull);
    record.push_back(0x00);
    record.push_back(0x1C); // VM, UEFI, targeted-content distribution.
    record.push_back(1);
    record.push_back(18);
    record.push_back(0xFF);
    record.push_back(0xFF);
    FinishSmbiosRecord(record,
                       {"Dell Inc.", "1.18.0", "09/12/2023"});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  {
    auto record = BeginSmbiosRecord(1, 0x1B, 0x0001);
    record.push_back(1); // Manufacturer
    record.push_back(2); // Product name
    record.push_back(3); // Version
    record.push_back(4); // Serial number
    constexpr uint8_t kUuid[16] = {0x4F, 0x84, 0x37, 0x7B, 0x33, 0x11,
                                   0x4E, 0x72, 0x95, 0x52, 0xC8, 0x71,
                                   0xD9, 0x44, 0x8C, 0x42};
    record.insert(record.end(), std::begin(kUuid), std::end(kUuid));
    record.push_back(0x06); // Power switch wake-up.
    record.push_back(5);    // SKU
    record.push_back(6);    // Family
    FinishSmbiosRecord(record,
                       {"Dell Inc.", "OptiPlex 7080", "Not Specified",
                        "9V7J3R3", "09A1", "OptiPlex"});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  {
    auto record = BeginSmbiosRecord(2, 0x0F, 0x0002);
    record.push_back(1); // Manufacturer
    record.push_back(2); // Product
    record.push_back(3); // Version
    record.push_back(4); // Serial
    record.push_back(5); // Asset tag
    record.push_back(0x0A);
    record.push_back(6); // Location in chassis
    PutLe16(record, 0x0003);
    record.push_back(0x0A); // Motherboard.
    record.push_back(0);
    FinishSmbiosRecord(record,
                       {"Dell Inc.", "0T1D10", "A02", "CN09V7J3R3",
                        "Not Specified", "Not Specified"});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  {
    auto record = BeginSmbiosRecord(3, 0x15, 0x0003);
    record.push_back(1);    // Manufacturer
    record.push_back(0x03); // Desktop chassis.
    record.push_back(2);    // Version
    record.push_back(3);    // Serial
    record.push_back(4);    // Asset tag
    record.push_back(0x03); // Boot-up state: safe.
    record.push_back(0x03); // Power supply state: safe.
    record.push_back(0x03); // Thermal state: safe.
    record.push_back(0x03); // Security status: none.
    PutLe32(record, 0);
    record.push_back(0);
    record.push_back(1);
    record.push_back(0);
    record.push_back(0);
    FinishSmbiosRecord(record,
                       {"Dell Inc.", "Not Specified", "9V7J3R3",
                        "Not Specified"});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  {
    auto record = BeginSmbiosRecord(32, 0x0B, 0x0020);
    for (int i = 0; i < 6; ++i) {
      record.push_back(0);
    }
    record.push_back(0); // No boot error detected.
    FinishSmbiosRecord(record, {});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  {
    auto record = BeginSmbiosRecord(127, 0x04, 0x7F00);
    FinishSmbiosRecord(record, {});
    AppendSmbiosRecord(*tables, std::move(record), &count, &maxStructure);
  }

  *anchor = BuildSmbiosEntryPoint(static_cast<uint16_t>(tables->size()),
                                  maxStructure, count);
}

uint8_t Bcd(uint8_t value) {
  return static_cast<uint8_t>(((value / 10u) << 4u) | (value % 10u));
}

} // namespace

PcIoDevices::PcIoDevices() : acpi_(BuildPcAcpiTables()) {
  BuildPcSmbiosTables(&smbiosTables_, &smbiosAnchor_);
}

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
      {static_cast<uint32_t>(smbiosTables_.size()), kFwCfgSmbiosTables,
       "etc/smbios/smbios-tables"},
      {static_cast<uint32_t>(smbiosAnchor_.size()), kFwCfgSmbiosAnchor,
       "etc/smbios/smbios-anchor"},
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
  if (OwnsBmdma(port)) {
    WriteBmdma(port, value, accessSize);
    return;
  }
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
    if (port >= kPmIoBase && port < kPmIoBase + 0x02) {
      // PM1a status block: write-1-to-clear. Clearing TMR_STS (bit 0) lets the
      // next PM-timer MSB toggle re-arm it, so a poller can wait for the *next*
      // overflow (ACPI write-1-to-clear semantics).
      if (value & 0x0001u) {
        pm1TmrSts_ = false;
      }
      return;
    }
    if (port >= kPmIoBase + 0x04 && port < kPmIoBase + 0x06) {
      const uint8_t offset =
          static_cast<uint8_t>(port - (kPmIoBase + 0x04));
      if (accessSize >= 2 && offset == 0) {
        pm1Control_ = static_cast<uint16_t>(value & 0xFFFFu);
      } else {
        const uint16_t mask =
            static_cast<uint16_t>(0xFFu << (offset * 8u));
        const uint16_t incoming =
            static_cast<uint16_t>((value & 0xFFu) << (offset * 8u));
        pm1Control_ = static_cast<uint16_t>((pm1Control_ & ~mask) | incoming);
      }
      lastPm1SleepEnable_ = (pm1Control_ & 0x2000u) != 0;
      if (lastPm1SleepEnable_) {
        ++pm1SleepRequestCount_;
        lastSleepType_ = static_cast<uint8_t>((pm1Control_ >> 10) & 0x7u);
        lastPm1HostStopRequested_ =
            lastSleepType_ == 4 || lastSleepType_ == 5;
        if (lastPm1HostStopRequested_) {
          shutdownRequested_ = true;
        } else {
          // PIIX4 SLP_EN is auto-clear once the sleep transition is
          // observed. For S0 (working state) the transition is instant; we
          // never actually park the CPU. Leaving SLP_EN asserted in
          // pm1Control_ traps the guest into polling pm1Control until the
          // bit clears, which never happens. Run 6c8c7e7d-... showed
          // winload spinning ~4.4M EFI GetTime calls in this exact state
          // after writing 0x2001 (SCI_EN + SLP_EN, SLP_TYP=0). Clearing
          // SLP_EN here matches the silicon contract: the level remains
          // set only long enough for the host to observe the request.
          pm1Control_ =
              static_cast<uint16_t>(pm1Control_ & ~0x2000u);
          lastPm1SleepEnable_ = false;
        }
      } else {
        lastPm1HostStopRequested_ = false;
      }
    }
    return;
  }
  if (port >= kPciConfigAddress && port < kPciConfigAddress + 4) {
    WritePciAddressWindow(port, value, accessSize);
    return;
  }
  if (port >= kPciConfigData && port < kPciConfigData + 4) {
    WritePciConfigData(port, value, accessSize);
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
      ++masterPicIcw1Writes_;
    } else {
      slavePicInitStep_ = 1;
      ++slavePicIcw1Writes_;
    }
  }
}

void PcIoDevices::WritePicData(bool master, uint8_t value) {
  uint8_t &step = master ? masterPicInitStep_ : slavePicInitStep_;
  if (step == 1) {
    if (master) {
      masterPicVectorBase_ = value;
      masterPicIcw2Value_ = value;
    } else {
      slavePicVectorBase_ = value;
      slavePicIcw2Value_ = value;
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
  if (OwnsBmdma(port)) {
    return ReadBmdma(port, accessSize);
  }
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
  case kFwCfgSmbiosTables:
  case kFwCfgSmbiosAnchor:
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
  } else if (selector == kFwCfgSmbiosTables) {
    ++fwCfgSmbiosTableBytesRead_;
    data = &smbiosTables_;
  } else if (selector == kFwCfgSmbiosAnchor) {
    ++fwCfgSmbiosAnchorBytesRead_;
    data = &smbiosAnchor_;
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
  // Count selects of the IDE function (enable bit set, bus 0, dev 1, func 1).
  // Distinguishes "Windows pci.sys enumerated/probed the IDE" (count climbs
  // well past winload's handful) from "kernel never touched it".
  if ((pciConfigAddress_ & 0x80000000u) != 0 &&
      ((pciConfigAddress_ >> 16) & 0xFFu) == 0 &&
      ((pciConfigAddress_ >> 11) & 0x1Fu) == 1 &&
      ((pciConfigAddress_ >> 8) & 0x07u) == 1) {
    ++ideConfigSelects_;
  }
}

uint32_t PcIoDevices::ReadBmdma(uint16_t port, uint8_t accessSize) const {
  const uint16_t offset = static_cast<uint16_t>(port - ideBmdmaBase_);
  uint32_t result = 0;
  for (uint8_t i = 0; i < accessSize && (offset + i) < 16; ++i) {
    uint8_t b = bmdmaRegs_[offset + i];
    // BMISX (status) lives at channel offsets 2 (primary) and 0x0A (secondary).
    // Report the bus master as idle (bit 0 clear -- we complete transfers
    // synchronously, so the guest never observes "active"), keep latched
    // error/interrupt bits, and advertise both drives as DMA-capable (bits 5/6)
    // so the intelide miniport keeps DMA enabled instead of disabling the
    // channel.
    if (offset + i == 2 || offset + i == 0x0A) {
      b = static_cast<uint8_t>((b & 0x06u) | 0x60u);
    }
    result |= static_cast<uint32_t>(b) << (i * 8);
  }
  return result;
}

void PcIoDevices::WriteBmdma(uint16_t port, uint32_t value, uint8_t accessSize) {
  const uint16_t offset = static_cast<uint16_t>(port - ideBmdmaBase_);
  for (uint8_t i = 0; i < accessSize && (offset + i) < 16; ++i) {
    const uint8_t b = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    const uint16_t off = static_cast<uint16_t>(offset + i);
    if (off == 2 || off == 0x0A) {
      // BMISX: bit 1 (error) and bit 2 (interrupt) are write-1-to-clear.
      bmdmaRegs_[off] = static_cast<uint8_t>(bmdmaRegs_[off] & ~(b & 0x06u));
    } else {
      // BMICX command + BMIDTPX PRD-table pointer are read/write. We do not run
      // a real PRD transfer yet (PIO still serves IDENTIFY/READ); the block
      // exists so intelide accepts the controller and creates the channels.
      bmdmaRegs_[off] = b;
    }
  }
}

void PcIoDevices::WritePciConfigData(uint16_t port, uint32_t value,
                                     uint8_t accessSize) {
  if ((pciConfigAddress_ & 0x80000000u) == 0) {
    return;
  }

  const uint8_t bus = static_cast<uint8_t>((pciConfigAddress_ >> 16) & 0xFFu);
  const uint8_t device =
      static_cast<uint8_t>((pciConfigAddress_ >> 11) & 0x1Fu);
  const uint8_t function =
      static_cast<uint8_t>((pciConfigAddress_ >> 8) & 0x07u);
  const uint8_t reg = static_cast<uint8_t>(pciConfigAddress_ & 0xFCu);
  const uint8_t shift = static_cast<uint8_t>((port - kPciConfigData) * 8u);
  const uint32_t mask = AccessMask(accessSize) << shift;

  if (ideControllerPresent_ && bus == 0 && device == 1 && function == 1) {
    if (reg == 0x04) {
      const uint32_t current = ideCommand_;
      ideCommand_ = static_cast<uint16_t>(
          ((current & ~mask) | ((value << shift) & mask)) & 0x0005u);
      return;
    }
    if (reg >= 0x10 && reg <= 0x20) {
      const size_t index = static_cast<size_t>((reg - 0x10) / 4u);
      if (index < ideBarWriteValues_.size()) {
        ideBarWriteValues_[index] =
            (ideBarWriteValues_[index] & ~mask) | ((value << shift) & mask);
        ideBarSizing_[index] =
            (ideBarWriteValues_[index] & 0xFFFFFFFCu) == 0xFFFFFFFCu;
        // BAR4 (index 4) is the bus-master BMDMA block. When the guest assigns
        // a real base (not the all-ones sizing probe), latch it and flag the
        // host to re-attach the 16 BMDMA ports there.
        if (index == 4 && !ideBarSizing_[4]) {
          const uint16_t base =
              static_cast<uint16_t>(ideBarWriteValues_[4] & 0xFFF0u);
          if (base != 0 && base != ideBmdmaBase_) {
            ideBmdmaBase_ = base;
            ideBmdmaAttachDirty_ = true;
          }
        }
      }
      return;
    }
  }

  if (vgaControllerPresent_ && bus == 0 && device == 2 && function == 0 &&
      reg == 0x10) {
    vgaBar0WriteValue_ =
        (vgaBar0WriteValue_ & ~mask) | ((value << shift) & mask);
    if ((vgaBar0WriteValue_ & 0xFFFFFFF0u) == 0xFFFFFFF0u) {
      vgaBar0Sizing_ = true;
      return;
    }
    vgaBar0Sizing_ = false;
    vgaBar0_ = (vgaBar0WriteValue_ & 0xFF000000u) | 0x08u;
    if ((vgaBar0_ & 0xFF000000u) == 0) {
      vgaBar0_ = static_cast<uint32_t>(BochsVbeDevice::kFramebufferGpa) | 0x08u;
    }
  }
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
      return 0x71108086u; // Intel PIIX4 ISA bridge.
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
      return ideCommand_; // IO enabled; BMDMA stays off until emulated.
    case 0x08:
      // IDE storage class 0x01, subclass 0x01, prog-if 0x80 = compatibility-mode
      // channels (fixed ISA ports 0x1F0/0x3F6 + legacy IRQ14/15) WITH bus-master
      // DMA capability. A real PIIX4 IDE (8086:7111) is exactly this, and
      // Windows' intelide miniport expects the bus-master register block (BAR4)
      // to be present -- without it pciide/intelide never create the IDE
      // channels, atapi never attaches, and the boot disk is never enumerated
      // (INACCESSIBLE_BOOT_DEVICE 0x7B, kernel issues 0 IDENTIFYs). The legacy
      // command/control ports stay hardwired; only the BMDMA block (BAR4) is
      // PCI-mapped. Revision 0x01.
      return 0x01018001u;
    case 0x0C:
      return 0x00000000u; // Type-0 header.
    case 0x10:
    case 0x14:
    case 0x18:
    case 0x1C:
      // Compatibility-mode IDE: command/control BARs are unimplemented (the
      // ports are hardwired to the legacy ISA addresses 0x1F0/0x3F6/0x170/0x376).
      // Reading 0 tells pci.sys these BARs are absent.
      return 0;
    case 0x20:
      // BAR4: bus-master IDE (BMDMA) register block, a 16-byte IO BAR (8 ports
      // per channel). During sizing the guest writes all-ones; report the size
      // mask (16-byte IO BAR -> low nibble 0x1 = IO, bits[3:1]=0). Otherwise
      // report the current base | IO-indicator. The host re-attaches the 16
      // BMDMA ports wherever the guest assigns this BAR.
      if (ideBarSizing_[4]) {
        return 0xFFFFFFF1u; // ~(16-1) | IO indicator.
      }
      return (static_cast<uint32_t>(ideBmdmaBase_) & 0xFFF0u) | 0x1u;
    case 0x3C:
      // Compatibility-mode IDE uses the dedicated legacy IRQ14/15 lines, NOT a
      // PCI INTx interrupt. A real PIIX-class IDE function in compat mode
      // reports Interrupt Pin = 0 (no PCI interrupt); pciide supplies IRQ14/15
      // itself from the compat-mode prog-if. Previously we claimed INT pin INTA
      // (0x01) while prog-if said compat (0x00) -- an inconsistency that makes
      // Windows arbitrate the IDE interrupt as a PCI INTA line via _PRT instead
      // of (or in addition to) the legacy IRQ, so pciide's StartDevice
      // mishandles its interrupt resource, never creates the channels, and
      // atapi never attaches (kernel issues 0 IDENTIFYs -> 0x7B). INT line 0xFF
      // = "not connected to a PCI interrupt router".
      return 0x000000FFu; // INT line 0xFF (none), INT pin 0 (no PCI INTx).
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
      // BAR0 — linear framebuffer. During PCI BAR sizing, OVMF writes all
      // ones and expects a mask that reports the aperture size. Returning the
      // fixed framebuffer GPA in that window made OVMF believe the VGA BAR was
      // 2 GiB wide, exhausting the root bridge MMIO aperture before GOP could
      // start. A 16 MiB mask matches the mapped Bochs framebuffer.
      return vgaBar0Sizing_ ? 0xFF000008u : vgaBar0_;
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

uint32_t PcIoDevices::ReadPmIo(uint16_t port, uint8_t accessSize) {
  if (port >= kPmIoBase + 0x04 && port < kPmIoBase + 0x06) {
    if (port == kPmIoBase + 0x04 && accessSize >= 2) {
      return pm1Control_;
    }
    const uint8_t shift =
        static_cast<uint8_t>((port - (kPmIoBase + 0x04)) * 8u);
    return (pm1Control_ >> shift) & 0xFFu;
  }
  if (port >= kPmTimerPort && port < kPmTimerPort + 4) {
    const uint32_t value = CurrentPmTimer();
    const uint8_t shift = static_cast<uint8_t>((port - kPmTimerPort) * 8u);
    return value >> shift;
  }
  if (port >= kPmIoBase && port < kPmIoBase + 0x02) {
    // PM1a status. Bit 0 = TMR_STS: set (sticky) when the PM timer's MSB
    // (bit 23 of the 24-bit counter) toggles. Without this the register reads a
    // permanent 0 and any PM1-status poll (a PM-timer-overflow wait, as the
    // OS-called OVMF runtime path does) spins forever. Cleared by write-1.
    const uint32_t timer = CurrentPmTimer();
    const uint32_t msb = (timer >> 23) & 1u;
    if (msb != pm1TmrLastMsb_) {
      pm1TmrLastMsb_ = msb;
      pm1TmrSts_ = true;
    }
    const uint16_t status = pm1TmrSts_ ? 0x0001u : 0x0000u;
    const uint8_t shift = static_cast<uint8_t>((port - kPmIoBase) * 8u);
    const uint32_t mask = accessSize == 1 ? 0xFFu : 0xFFFFu;
    return (static_cast<uint32_t>(status) >> shift) & mask;
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
  const std::tm now = UtcNowStable();
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
