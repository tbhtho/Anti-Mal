#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/Crypto.h"
#include "antimal/EventJournal.h"
#include "antimal/ExternalTools.h"
#include "antimal/FileUtil.h"
#include "antimal/Http.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/IntelLookup.h"
#include "antimal/Json.h"
#include "antimal/PeParser.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/Screenshot.h"
#include "antimal/Strings.h"
#include "antimal/Subprocess.h"
#include "antimal/Tagger.h"
#include "antimal/hv/AcpiTables.h"
#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/BochsVbe.h"
#include "antimal/hv/Firmware.h"
#include "antimal/hv/GuestMemory.h"
#include "antimal/hv/Hpet.h"
#include "antimal/hv/HostSerialChannel.h"
#include "antimal/hv/IoApic.h"
#include "antimal/hv/IoBus.h"
#include "antimal/hv/MmioBus.h"
#include "antimal/hv/PcIoDevices.h"
#include "antimal/hv/SerialConsole.h"
#include "antimal/hv/StorageController.h"
#include "antimal/hv/Vcpu.h"
#include "antimal/hv/VirtualMachine.h"
#include "antimal/hv/VirtualDisk.h"
#include "antimal/hv/WhpHost.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <atomic>
#include <chrono>
#include <stop_token>
#include <thread>
#include <vector>

namespace {

int g_failed = 0;

void Expect(bool condition, const char *message) {
  if (!condition) {
    ++g_failed;
    std::cerr << "FAIL: " << message << "\n";
  }
}

std::filesystem::path TempRoot() {
  auto root = std::filesystem::temp_directory_path() / ("antimal-tests-" + antimal::MakeRunId());
  antimal::EnsureDirectory(root);
  return root;
}

void TestHashEntropyJson() {
  const std::vector<uint8_t> abc{'a', 'b', 'c'};
  Expect(antimal::Sha256Hex(abc) ==
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "sha256 abc");
  Expect(antimal::CalculateEntropy(std::vector<uint8_t>(256, 0)) == 0.0,
         "zero entropy");
  Expect(antimal::JsonEscape("a\"b\\c\n") == "a\\\"b\\\\c\\n", "json escape");
  Expect(antimal::HtmlEscape("<tag>&\"") == "&lt;tag&gt;&amp;&quot;", "html escape");
}

void TestConfig() {
  const auto root = TempRoot();
  antimal::AppConfig config;
  config.baseVhdxPath = L"C:\\Images\\clean.vhdx";
  config.baseDiskPath = root / "AntiMalBase.raw";
  config.baseDiskFormat = "raw";
  config.workspaceRoot = root;
  config.vmNamePrefix = "AM";
  config.defaultTimeoutSec = 99;
  config.networkMode = antimal::NetworkMode::HostOnly;
  config.dynamicExecutionEnabled = true;
  const auto path = root / "antimal.toml";
  antimal::WriteTextFile(path, antimal::SerializeConfig(config));
  const auto loaded = antimal::LoadConfig(path);
  Expect(loaded.baseVhdxPath == config.baseVhdxPath, "config base vhdx");
  Expect(loaded.baseDiskPath == config.baseDiskPath, "config base raw disk");
  Expect(loaded.baseDiskFormat == "raw", "config base disk format");
  Expect(loaded.workspaceRoot == config.workspaceRoot, "config workspace");
  Expect(loaded.networkMode == antimal::NetworkMode::HostOnly, "config network");
  Expect(loaded.dynamicExecutionEnabled, "config dynamic execution gate");
}

void TestLocalBaseVhdxInfo() {
  const std::filesystem::path base = L"C:\\AntiMalRuns\\_base\\AntiMalBase.vhdx";
  if (!std::filesystem::exists(base)) {
    std::cout << "SKIP: local base VHDX not found at "
              << antimal::PathToUtf8(base) << "\n";
    return;
  }

  try {
    auto disk = antimal::hv::VirtualDisk::OpenReadOnly(base);
    const auto info = disk.QueryInfo();
    std::cout << "Local base VHDX info:\n"
              << "  path: " << antimal::PathToUtf8(base) << "\n"
              << "  virtual size: " << info.virtualSize << "\n"
              << "  physical size: " << info.physicalSize << "\n"
              << "  block size: " << info.blockSize << "\n"
              << "  sector size: " << info.sectorSize << "\n"
              << "  vhd physical sector size: "
              << info.vhdPhysicalSectorSize << "\n"
              << "  provider subtype: " << info.providerSubtype << "\n"
              << "  loaded: " << (info.isLoaded ? "yes" : "no") << "\n";

    Expect(info.virtualSize >= 20ull * 1024ull * 1024ull * 1024ull,
           "local VHDX: virtual size is plausible");
    Expect(info.physicalSize > 0, "local VHDX: physical size reported");
    Expect(info.blockSize > 0, "local VHDX: block size reported");
    Expect(info.sectorSize == 512 || info.sectorSize == 4096,
           "local VHDX: sector size is standard");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: local base VHDX info threw WhpError: " << ex.what()
              << "\n";
  }
}

void TestVirtualDiskDifferencingOverlay() {
  const std::filesystem::path base = L"C:\\AntiMalRuns\\_base\\AntiMalBase.vhdx";
  if (!std::filesystem::exists(base)) {
    std::cout << "SKIP: local base VHDX not found for VirtualDisk overlay test at "
              << antimal::PathToUtf8(base) << "\n";
    return;
  }

  try {
    const auto overlay = TempRoot() / "overlay.vhdx";
    antimal::hv::VirtualDisk::CreateDifferencing(base, overlay);
    Expect(std::filesystem::exists(overlay), "VirtualDisk: differencing overlay exists");
    auto disk = antimal::hv::VirtualDisk::OpenReadOnly(overlay);
    const auto info = disk.QueryInfo();
    Expect(info.virtualSize >= 20ull * 1024ull * 1024ull * 1024ull,
           "VirtualDisk: overlay virtual size follows parent");
    Expect(info.physicalSize > 0, "VirtualDisk: overlay physical size reported");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: VirtualDisk overlay threw WhpError: " << ex.what() << "\n";
  }
}

void TestMemoryBlockDeviceReadWrite() {
  antimal::hv::MemoryBlockDevice disk(4);
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> sector{};
  for (size_t i = 0; i < sector.size(); ++i) {
    sector[i] = static_cast<uint8_t>(i & 0xFFu);
  }

  Expect(disk.WriteSectors(2, 1, sector.data()), "memory block: write sector");
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> read{};
  Expect(disk.ReadSectors(2, 1, read.data()), "memory block: read sector");
  Expect(read == sector, "memory block: sector bytes round-trip");
  Expect(!disk.ReadSectors(4, 1, read.data()),
         "memory block: out-of-range read rejected");
}

void TestRawFileBlockDeviceReadWrite() {
  const auto path = TempRoot() / "disk.raw";
  auto disk = antimal::hv::RawFileBlockDevice::Create(path, 3);
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> sector{};
  std::fill(sector.begin(), sector.end(), 0xA5u);

  Expect(disk.SectorCount() == 3, "raw block: sector count");
  Expect(disk.WriteSectors(1, 1, sector.data()), "raw block: write sector");
  Expect(disk.Flush(), "raw block: flush");

  auto reopened = antimal::hv::RawFileBlockDevice::Open(path);
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> read{};
  Expect(reopened.ReadSectors(1, 1, read.data()), "raw block: read sector");
  Expect(read == sector, "raw block: sector bytes round-trip");
}

void TestCowRawBlockDeviceOverlay() {
  const auto root = TempRoot();
  const auto basePath = root / "base.raw";
  const auto overlayPath = root / "overlay.cow";

  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> original{};
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> changed{};
  std::fill(original.begin(), original.end(), 0x11u);
  std::fill(changed.begin(), changed.end(), 0xD4u);

  {
    auto base = antimal::hv::RawFileBlockDevice::Create(basePath, 4);
    Expect(base.WriteSectors(1, 1, original.data()), "cow: write base sector");
    Expect(base.Flush(), "cow: base flush");
  }

  {
    auto cow = antimal::hv::CowRawBlockDevice::Create(basePath, overlayPath);
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> read{};
    Expect(cow.ReadSectors(1, 1, read.data()), "cow: read-through base sector");
    Expect(read == original, "cow: read-through bytes match base");
    Expect(cow.WriteSectors(1, 1, changed.data()), "cow: write overlay sector");
    Expect(cow.Flush(), "cow: overlay flush");
    Expect(cow.OverlaySectorCount() == 1, "cow: one overlay sector tracked");
    Expect(cow.ReadSectors(1, 1, read.data()), "cow: read overlaid sector");
    Expect(read == changed, "cow: overlaid bytes returned");
  }

  {
    auto base = antimal::hv::ReadOnlyRawBlockDevice::Open(basePath);
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> read{};
    Expect(base.ReadSectors(1, 1, read.data()), "cow: base remains readable");
    Expect(read == original, "cow: base remains unchanged");
  }

  {
    auto cow = antimal::hv::CowRawBlockDevice::Open(basePath, overlayPath);
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> read{};
    Expect(cow.ReadSectors(1, 1, read.data()), "cow: replay overlay sector");
    Expect(read == changed, "cow: replayed overlay bytes match");
  }
}

void TestJobMediaBlockDevice() {
  std::vector<antimal::hv::JobMediaEntry> entries;
  entries.push_back({"job.json", {'{', '}', '\n'}});
  entries.push_back({"sample.exe", {'M', 'Z'}});

  auto media = antimal::hv::JobMediaBlockDevice::FromEntries(entries);
  Expect(media.SectorCount() >= 1, "job media: at least one sector");

  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> first{};
  Expect(media.ReadSectors(0, 1, first.data()), "job media: first sector readable");
  Expect(first[0] == 'A' && first[1] == 'M' && first[2] == 'J' &&
             first[3] == 'O',
         "job media: magic present");
  Expect(!media.WriteSectors(0, 1, first.data()), "job media: read-only");
}

void TestHostSerialChannelFrames() {
  auto encoded = antimal::hv::HostSerialChannel::EncodeText(
      antimal::hv::HostChannelMessage::Event, "{\"category\":\"agent\"}");
  Expect(!encoded.empty(), "serial channel: encoded frame");

  antimal::hv::HostSerialChannel channel;
  const uint8_t junk[] = {0xAA, 0xBB, 0xCC};
  channel.PushBytes(junk, sizeof(junk));
  channel.PushBytes(encoded.data(), 5);
  Expect(channel.PendingFrameCount() == 0, "serial channel: partial frame held");
  channel.PushBytes(encoded.data() + 5, encoded.size() - 5);
  Expect(channel.PendingFrameCount() == 1, "serial channel: complete frame decoded");
  const auto frame = channel.PopFrame();
  Expect(frame.has_value(), "serial channel: frame popped");
  Expect(frame->type == antimal::hv::HostChannelMessage::Event,
         "serial channel: frame type preserved");
  const std::string payload(frame->payload.begin(), frame->payload.end());
  Expect(payload.find("agent") != std::string::npos,
         "serial channel: payload preserved");

  auto corrupt = encoded;
  corrupt[12] ^= 0x7Fu;
  channel.PushBytes(corrupt);
  Expect(channel.PendingFrameCount() == 0,
         "serial channel: checksum rejects corrupt frame");
}

void TestCom2UartFrames() {
  antimal::hv::SerialConsole com2(antimal::hv::SerialConsole::kCom2Base);
  com2.OnWrite(antimal::hv::SerialConsole::kCom2Base + 1, 0x01, 1);
  Expect(!com2.InterruptPending(), "COM2 UART: no RX interrupt when empty");

  const auto job = antimal::hv::HostSerialChannel::EncodeText(
      antimal::hv::HostChannelMessage::JobStart, "{\"run\":\"test\"}");
  com2.QueueRxBytes(job);
  Expect(com2.InterruptPending(),
         "COM2 UART: RX interrupt pending after host queues frame");

  std::vector<uint8_t> guestRead;
  while ((com2.OnRead(antimal::hv::SerialConsole::kCom2Base + 5, 1) & 0x01u) != 0) {
    guestRead.push_back(static_cast<uint8_t>(
        com2.OnRead(antimal::hv::SerialConsole::kCom2Base, 1) & 0xFFu));
  }
  antimal::hv::HostSerialChannel guestChannel;
  guestChannel.PushBytes(guestRead);
  auto decodedJob = guestChannel.PopFrame();
  Expect(decodedJob.has_value(), "COM2 UART: guest receives complete frame");
  Expect(decodedJob &&
             decodedJob->type == antimal::hv::HostChannelMessage::JobStart,
         "COM2 UART: received frame type preserved");
  Expect(!com2.InterruptPending(),
         "COM2 UART: RX interrupt clears after guest drains FIFO");

  const auto hello = antimal::hv::HostSerialChannel::EncodeText(
      antimal::hv::HostChannelMessage::Hello, "guest-agent");
  for (uint8_t byte : hello) {
    com2.OnWrite(antimal::hv::SerialConsole::kCom2Base, byte, 1);
  }
  const auto captured = com2.Captured();
  antimal::hv::HostSerialChannel hostChannel;
  hostChannel.PushBytes(reinterpret_cast<const uint8_t *>(captured.data()),
                        captured.size());
  auto decodedHello = hostChannel.PopFrame();
  Expect(decodedHello.has_value(), "COM2 UART: host decodes guest frame");
  Expect(decodedHello &&
             decodedHello->type == antimal::hv::HostChannelMessage::Hello,
         "COM2 UART: guest frame type preserved");
}

void TestPs2QueuedInput() {
  antimal::hv::Ps2Controller ps2;
  ps2.InjectKeyboardScancode(0x1E);
  Expect(ps2.HasDataPending(), "PS/2 input: keyboard scancode queued");
  Expect(ps2.PendingIrqLine() == 1, "PS/2 input: keyboard maps to IRQ1");
  Expect((ps2.OnRead(0x64, 1) & 0x20u) == 0,
         "PS/2 input: keyboard status is not aux data");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0x1Eu,
         "PS/2 input: keyboard scancode drains");
  Expect(!ps2.HasDataPending(), "PS/2 input: keyboard queue empty");

  ps2.InjectMousePacket(0x01, 5, -3);
  Expect(ps2.PendingIrqLine() == 12, "PS/2 input: mouse maps to IRQ12");
  Expect((ps2.OnRead(0x64, 1) & 0x20u) != 0,
         "PS/2 input: mouse status marks aux data");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0x29u,
         "PS/2 input: mouse status byte drains");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0x05u,
         "PS/2 input: mouse dx drains");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0xFDu,
         "PS/2 input: mouse dy drains");
  Expect(!ps2.HasDataPending(), "PS/2 input: mouse queue empty");
}

uint32_t ReadLe32(const std::vector<uint8_t> &data, size_t offset) {
  if (offset + 4 > data.size()) {
    return 0;
  }
  return static_cast<uint32_t>(data[offset]) |
         (static_cast<uint32_t>(data[offset + 1]) << 8) |
         (static_cast<uint32_t>(data[offset + 2]) << 16) |
         (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint64_t ReadLe64(const std::vector<uint8_t> &data, size_t offset) {
  if (offset + 8 > data.size()) {
    return 0;
  }
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
  }
  return value;
}

uint32_t ReadBe32(const std::vector<uint8_t> &data, size_t offset) {
  if (offset + 4 > data.size()) {
    return 0;
  }
  return (static_cast<uint32_t>(data[offset]) << 24) |
         (static_cast<uint32_t>(data[offset + 1]) << 16) |
         (static_cast<uint32_t>(data[offset + 2]) << 8) |
         static_cast<uint32_t>(data[offset + 3]);
}

uint16_t ReadBe16(const std::vector<uint8_t> &data, size_t offset) {
  if (offset + 2 > data.size()) {
    return 0;
  }
  return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8) |
                               static_cast<uint16_t>(data[offset + 1]));
}

void TestAcpiTables() {
  const auto acpi = antimal::hv::BuildPcAcpiTables();
  Expect(!acpi.tables.empty(), "ACPI: table blob produced");
  Expect(!acpi.tableLoader.empty(), "ACPI: table-loader produced");
  Expect(acpi.tableLoader.size() % 128 == 0,
         "ACPI: table-loader entries are 128-byte records");
  Expect(acpi.rsdp.size() == 20, "ACPI: ACPI 1.0 RSDP fw_cfg length");
  Expect(std::memcmp(acpi.rsdp.data(), "RSD PTR ", 8) == 0,
         "ACPI: RSDP signature");
  Expect(antimal::hv::AcpiChecksumValid(acpi.rsdp.data(), acpi.rsdp.size()),
         "ACPI: RSDP checksum valid before relocation");

  auto tableOk = [&](uint32_t offset, const char *sig) {
    const uint32_t length = antimal::hv::AcpiTableLength(acpi.tables, offset);
    Expect(length >= 36, "ACPI: table length is plausible");
    Expect(offset + length <= acpi.tables.size(),
           "ACPI: table stays inside table blob");
    Expect(std::memcmp(acpi.tables.data() + offset, sig, 4) == 0,
           "ACPI: expected table signature");
    Expect(antimal::hv::AcpiChecksumValid(acpi.tables.data() + offset, length),
           "ACPI: table checksum valid before relocation");
  };

  tableOk(acpi.offsets.dsdt, "DSDT");
  tableOk(acpi.offsets.fadt, "FACP");
  tableOk(acpi.offsets.madt, "APIC");
  tableOk(acpi.offsets.waet, "WAET");
  tableOk(acpi.offsets.hpet, "HPET");
  tableOk(acpi.offsets.rsdt, "RSDT");

  Expect(ReadLe32(acpi.tables, acpi.offsets.fadt + 36) == acpi.offsets.facs,
         "ACPI: FADT firmware control points to FACS offset");
  Expect(ReadLe32(acpi.tables, acpi.offsets.fadt + 40) == acpi.offsets.dsdt,
         "ACPI: FADT DSDT points to DSDT offset");
  const uint32_t fadtLen = antimal::hv::AcpiTableLength(acpi.tables, acpi.offsets.fadt);
  Expect(fadtLen >= 244, "ACPI: FADT includes ACPI 2.0 extended blocks");
  Expect(acpi.tables[acpi.offsets.fadt + 8] == 3,
         "ACPI: FADT revision advertises extended fields");
  Expect(acpi.tables[acpi.offsets.fadt + 44] == 1,
         "ACPI: FADT advertises multiple APIC interrupt model");
  Expect(ReadLe32(acpi.tables, acpi.offsets.fadt + 56) == 0xB000u,
         "ACPI: FADT PM1a event block matches PIIX4 PM base");
  Expect(ReadLe32(acpi.tables, acpi.offsets.fadt + 64) == 0xB004u,
         "ACPI: FADT PM1a control block matches shutdown trap");
  Expect(ReadLe32(acpi.tables, acpi.offsets.fadt + 76) == 0xB008u,
         "ACPI: FADT PM timer block matches PM timer emulation");
  Expect(acpi.tables[acpi.offsets.fadt + 88] == 4,
         "ACPI: FADT PM1 event length advertised");
  Expect(acpi.tables[acpi.offsets.fadt + 89] == 2,
         "ACPI: FADT PM1 control length advertised");
  Expect(ReadLe64(acpi.tables, acpi.offsets.fadt + 132) == acpi.offsets.facs,
         "ACPI: X_FirmwareCtrl points to FACS offset");
  Expect(ReadLe64(acpi.tables, acpi.offsets.fadt + 140) == acpi.offsets.dsdt,
         "ACPI: X_DSDT points to DSDT offset");
  Expect(ReadLe64(acpi.tables, acpi.offsets.fadt + 152) == 0xB000u,
         "ACPI: X_PM1a event block GAS matches PM base");
  Expect(ReadLe64(acpi.tables, acpi.offsets.fadt + 176) == 0xB004u,
         "ACPI: X_PM1a control block GAS matches shutdown trap");
  Expect(ReadLe64(acpi.tables, acpi.offsets.fadt + 212) == 0xB008u,
         "ACPI: X_PM timer block GAS matches PM timer");
  Expect(ReadLe32(acpi.tables, acpi.offsets.madt + 36) == 0xFEE00000u,
         "ACPI: MADT local APIC address");
  Expect(ReadLe32(acpi.tables, acpi.offsets.madt + 48) == 1,
         "ACPI: MADT first LAPIC enabled");
  Expect(ReadLe32(acpi.tables, acpi.offsets.madt + 56) == 0xFEC00000u,
         "ACPI: MADT IOAPIC address");
  Expect(ReadLe32(acpi.tables, acpi.offsets.hpet + 36) ==
             antimal::hv::HpetDevice::kEventTimerBlockId,
         "ACPI: HPET event timer block ID");
  Expect(ReadLe64(acpi.tables, acpi.offsets.hpet + 44) ==
             antimal::hv::HpetDevice::kDefaultMmioBase,
         "ACPI: HPET GAS points to MMIO base");
  Expect(ReadLe32(acpi.tables, acpi.offsets.rsdt + 4) == 52,
         "ACPI: RSDT includes four table pointers");

  const auto dsdtLen = antimal::hv::AcpiTableLength(acpi.tables, acpi.offsets.dsdt);
  const auto dsdtBegin = acpi.tables.begin() + acpi.offsets.dsdt;
  const auto dsdtEnd = dsdtBegin + dsdtLen;
  auto contains = [&](const char *needle) {
    return std::search(dsdtBegin, dsdtEnd, needle, needle + std::strlen(needle)) != dsdtEnd;
  };
  Expect(contains("_SB_"), "ACPI: DSDT exposes _SB scope");
  Expect(contains("_S5_"), "ACPI: DSDT exposes S5 shutdown package");
  Expect(contains("PCI0"), "ACPI: DSDT exposes PCI0");
  Expect(contains("RTC0"), "ACPI: DSDT exposes RTC device");
  Expect(contains("HPET"), "ACPI: DSDT exposes HPET device");
  Expect(contains("PMRS"), "ACPI: DSDT exposes PM IO reservation");
  Expect(contains("VGA_"), "ACPI: DSDT exposes VGA PCI function");
  Expect(contains("COM2"), "ACPI: DSDT exposes COM2 for host channel");
  Expect(contains("PS2K"), "ACPI: DSDT exposes PS/2 keyboard");

  const auto acpi2 = antimal::hv::BuildPcAcpiTables(2);
  Expect(ReadLe32(acpi2.tables, acpi2.offsets.madt + 56) == 1,
         "ACPI: second MADT LAPIC entry enabled");
  Expect(acpi2.tables[acpi2.offsets.madt + 55] == 1,
         "ACPI: second MADT LAPIC APIC ID is 1");
  Expect(ReadLe32(acpi2.tables, acpi2.offsets.madt + 64) == 0xFEC00000u,
         "ACPI: two-vCPU MADT still exposes IOAPIC address");

  Expect(ReadLe32(acpi.tableLoader, 0) == 1,
         "ACPI: table-loader starts with allocate command");
  Expect(ReadLe32(acpi.tableLoader, 128) == 1,
         "ACPI: table-loader second entry is allocate command");
  bool sawPointer = false;
  bool sawChecksum = false;
  for (size_t off = 0; off + 128 <= acpi.tableLoader.size(); off += 128) {
    const uint32_t command = ReadLe32(acpi.tableLoader, off);
    sawPointer = sawPointer || command == 2;
    sawChecksum = sawChecksum || command == 3;
  }
  Expect(sawPointer, "ACPI: table-loader contains pointer fixups");
  Expect(sawChecksum, "ACPI: table-loader contains checksum fixups");
}

void TestPcIoPmSleepByteWrites() {
  antimal::hv::PcIoDevices pc;
  pc.OnWrite(0xB004, 0x2001, 2);
  Expect(!pc.ShutdownRequested(),
         "PM1 control: S0 sleep enable does not request host shutdown");
  Expect(pc.LastSleepType() == 0,
         "PM1 control: S0 sleep type is recorded");
  Expect(pc.LastPm1SleepEnable(),
         "PM1 control: S0 sleep enable is recorded");
  Expect(!pc.LastPm1HostStopRequested(),
         "PM1 control: S0 sleep enable is diagnostic only");
  Expect(pc.LastPm1ControlValue() == 0x2001,
         "PM1 control: raw S0 value is recorded");

  antimal::hv::PcIoDevices pcS5;
  pcS5.OnWrite(0xB004, 0x00, 1);
  Expect(!pcS5.ShutdownRequested(),
         "PM1 control: low-byte write alone does not request shutdown");
  pcS5.OnWrite(0xB005, 0x34, 1);
  Expect(pcS5.ShutdownRequested(),
         "PM1 control: high-byte SLP_EN write requests shutdown");
  Expect(pcS5.LastSleepType() == 5,
         "PM1 control: byte writes preserve S5 sleep type");
  Expect(pcS5.LastPm1HostStopRequested(),
         "PM1 control: S5 sleep requests host stop");

  antimal::hv::PcIoDevices pcS4;
  pcS4.OnWrite(0xB004, 0x3000, 2);
  Expect(pcS4.ShutdownRequested(),
         "PM1 control: S4 sleep enable requests host shutdown");
  Expect(pcS4.LastSleepType() == 4,
         "PM1 control: S4 sleep type is recorded");
}

void TestHpetMmioCounter() {
  antimal::hv::HpetDevice hpet;
  uint64_t value = 0;
  Expect(hpet.OnRead(antimal::hv::HpetDevice::kDefaultMmioBase, 4, &value),
         "HPET: capabilities low read succeeds");
  Expect(value == antimal::hv::HpetDevice::kEventTimerBlockId,
         "HPET: capabilities expose event timer block ID");
  Expect(hpet.OnRead(antimal::hv::HpetDevice::kDefaultMmioBase + 4, 4, &value),
         "HPET: capabilities high read succeeds");
  Expect(value == antimal::hv::HpetDevice::kClockPeriodFs,
         "HPET: capabilities expose 10 MHz period");

  Expect(hpet.OnWrite(antimal::hv::HpetDevice::kDefaultMmioBase + 0x10, 4, 1),
         "HPET: general config enable write succeeds");
  std::this_thread::sleep_for(std::chrono::milliseconds{2});
  uint64_t first = 0;
  uint64_t second = 0;
  Expect(hpet.OnRead(antimal::hv::HpetDevice::kDefaultMmioBase + 0xF0, 8,
                     &first),
         "HPET: first counter read succeeds");
  std::this_thread::sleep_for(std::chrono::milliseconds{2});
  Expect(hpet.OnRead(antimal::hv::HpetDevice::kDefaultMmioBase + 0xF0, 8,
                     &second),
         "HPET: second counter read succeeds");
  Expect(second > first, "HPET: enabled counter advances");

  Expect(hpet.OnWrite(antimal::hv::HpetDevice::kDefaultMmioBase + 0x108, 8,
                      0x12345678ull),
         "HPET: comparator write succeeds");
  Expect(hpet.OnRead(antimal::hv::HpetDevice::kDefaultMmioBase + 0x108, 8,
                     &value),
         "HPET: comparator read succeeds");
  Expect(value == 0x12345678ull, "HPET: comparator stores value");
  Expect(hpet.Reads() >= 5 && hpet.Writes() >= 2,
         "HPET: diagnostic counters update");
}

void TestPcIoFwCfgAcpiFiles() {
  antimal::hv::PcIoDevices pc;
  pc.SetProcessorCount(2);
  pc.OnWrite(0x510, 0x0005, 2);
  Expect(static_cast<uint16_t>(pc.OnRead(0x511, 2) & 0xFFFFu) == 2,
         "fw_cfg: NbCpus reflects configured processor count");

  pc.OnWrite(0x510, 0x0019, 2);
  std::vector<uint8_t> dir;
  for (size_t i = 0; i < 4 + 4 * 64; ++i) {
    dir.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(ReadBe32(dir, 0) == 4, "fw_cfg: directory exposes four files");

  bool sawE820 = false;
  bool sawAcpiTables = false;
  bool sawLoader = false;
  bool sawRsdp = false;
  uint16_t acpiSelector = 0;
  uint32_t acpiSize = 0;
  for (size_t entry = 0; entry < 4; ++entry) {
    const size_t off = 4 + entry * 64;
    const uint32_t size = ReadBe32(dir, off);
    const uint16_t selector = ReadBe16(dir, off + 4);
    std::string name;
    for (size_t i = 0; i < 56 && dir[off + 8 + i] != 0; ++i) {
      name.push_back(static_cast<char>(dir[off + 8 + i]));
    }
    sawE820 = sawE820 || name == "etc/e820";
    sawLoader = sawLoader || name == "etc/table-loader";
    sawRsdp = sawRsdp || name == "etc/acpi/rsdp";
    if (name == "etc/acpi/tables") {
      sawAcpiTables = true;
      acpiSelector = selector;
      acpiSize = size;
    }
  }
  Expect(sawE820, "fw_cfg: etc/e820 still present");
  Expect(sawAcpiTables, "fw_cfg: etc/acpi/tables present");
  Expect(sawLoader, "fw_cfg: etc/table-loader present");
  Expect(sawRsdp, "fw_cfg: etc/acpi/rsdp present");
  Expect(acpiSelector != 0 && acpiSize > 64,
         "fw_cfg: ACPI tables selector and size plausible");

  pc.OnWrite(0x510, acpiSelector, 2);
  std::vector<uint8_t> header;
  for (size_t i = 0; i < 4; ++i) {
    header.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(std::memcmp(header.data(), "FACS", 4) == 0,
         "fw_cfg: ACPI table blob starts with FACS");
  Expect(pc.FwCfgFileDirBytesRead() >= dir.size(),
         "fw_cfg: directory byte counter updated");
  Expect(pc.FwCfgAcpiTableBytesRead() >= header.size(),
         "fw_cfg: ACPI table byte counter updated");
}

void TestPcIoFwCfgE820MemoryInventory() {
  antimal::hv::PcIoDevices pc;
  antimal::hv::PcIoMemoryLayout layout{};
  layout.lowRamBytes = 512ull * 1024ull * 1024ull;
  layout.highRamBytes = 256ull * 1024ull * 1024ull;
  pc.SetMemoryLayout(layout);
  pc.SetAcpiTablesEnabled(false);

  pc.OnWrite(0x510, 0x0019, 2);
  std::vector<uint8_t> dir;
  for (size_t i = 0; i < 4 + 64; ++i) {
    dir.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(ReadBe32(dir, 0) == 1,
         "fw_cfg e820: ACPI-disabled directory exposes one file");
  Expect(ReadBe32(dir, 4) == 40,
         "fw_cfg e820: low+high RAM inventory is two entries");
  Expect(ReadBe16(dir, 8) == 0x0020,
         "fw_cfg e820: stable selector starts at 0x0020");
  std::string name;
  for (size_t i = 0; i < 56 && dir[12 + i] != 0; ++i) {
    name.push_back(static_cast<char>(dir[12 + i]));
  }
  Expect(name == "etc/e820", "fw_cfg e820: directory name");

  pc.OnWrite(0x510, 0x0020, 2);
  std::vector<uint8_t> e820;
  for (size_t i = 0; i < 40; ++i) {
    e820.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(ReadLe64(e820, 0) == 0,
         "fw_cfg e820: first entry starts at zero");
  Expect(ReadLe64(e820, 8) == layout.lowRamBytes,
         "fw_cfg e820: first entry length is all low RAM");
  Expect(ReadLe32(e820, 16) == 1,
         "fw_cfg e820: first entry is usable RAM");
  Expect(ReadLe64(e820, 20) == 0x100000000ull,
         "fw_cfg e820: high entry starts at 4 GiB");
  Expect(ReadLe64(e820, 28) == layout.highRamBytes,
         "fw_cfg e820: high entry length matches high RAM");
  Expect(ReadLe32(e820, 36) == 1,
         "fw_cfg e820: high entry is usable RAM");
}

void TestBochsVbeDataPortAliases() {
  antimal::hv::BochsVbeDevice vbe;

  vbe.OnWrite(antimal::hv::BochsVbeDevice::kIndexPort,
              antimal::hv::BochsVbeDevice::DispiIndexXres, 2);
  vbe.OnWrite(antimal::hv::BochsVbeDevice::kDataPort, 800, 2);
  Expect(vbe.Width() == 800, "Bochs VBE: x86 data port writes register");

  vbe.OnWrite(antimal::hv::BochsVbeDevice::kIndexPort,
              antimal::hv::BochsVbeDevice::DispiIndexYres, 2);
  vbe.OnWrite(antimal::hv::BochsVbeDevice::kDataPortAligned, 600, 2);
  Expect(vbe.Height() == 600,
         "Bochs VBE: aligned data port writes register");

  vbe.OnWrite(antimal::hv::BochsVbeDevice::kIndexPort,
              antimal::hv::BochsVbeDevice::DispiIndexId, 2);
  Expect(vbe.OnRead(antimal::hv::BochsVbeDevice::kDataPortAligned, 2) ==
             0xB0C5u,
         "Bochs VBE: aligned data port reads ID");
}

void TestIdeIdentifyDevice() {
  antimal::hv::MemoryBlockDevice disk(2048);
  antimal::hv::IdeController ide(&disk);

  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0xEC, 1);
  Expect((ide.Status() & 0x08u) != 0, "IDE identify: DRQ set");

  std::array<uint16_t, 256> words{};
  for (auto &word : words) {
    word = static_cast<uint16_t>(
        ide.OnRead(antimal::hv::IdeController::kPrimaryBase, 2));
  }
  const uint32_t sectors =
      static_cast<uint32_t>(words[60]) |
      (static_cast<uint32_t>(words[61]) << 16);
  Expect((ide.Status() & 0x08u) == 0, "IDE identify: DRQ cleared after read");
  Expect(words[0] == 0x0040, "IDE identify: fixed disk bit");
  Expect(sectors == 2048, "IDE identify: total sector count");
}

void TestIdeReadWriteSectors() {
  antimal::hv::MemoryBlockDevice disk(8);
  antimal::hv::IdeController ide(&disk);
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> pattern{};
  for (size_t i = 0; i < pattern.size(); ++i) {
    pattern[i] = static_cast<uint8_t>((i * 7) & 0xFFu);
  }

  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 2, 1, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 3, 3, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 4, 0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 5, 0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 6, 0xE0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0x30, 1);
  Expect((ide.Status() & 0x08u) != 0, "IDE write: DRQ set");
  for (size_t i = 0; i < pattern.size(); i += 2) {
    const uint16_t word = static_cast<uint16_t>(
        pattern[i] | (static_cast<uint16_t>(pattern[i + 1]) << 8));
    ide.OnWrite(antimal::hv::IdeController::kPrimaryBase, word, 2);
  }
  Expect((ide.Status() & 0x08u) == 0, "IDE write: DRQ cleared");

  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> fromDisk{};
  Expect(disk.ReadSectors(3, 1, fromDisk.data()),
         "IDE write: backing disk readable");
  Expect(fromDisk == pattern, "IDE write: backing sector matches");

  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 2, 1, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 3, 3, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 4, 0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 5, 0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 6, 0xE0, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0x20, 1);
  std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> readback{};
  for (size_t i = 0; i < readback.size(); i += 2) {
    const uint16_t word = static_cast<uint16_t>(
        ide.OnRead(antimal::hv::IdeController::kPrimaryBase, 2));
    readback[i] = static_cast<uint8_t>(word & 0xFFu);
    readback[i + 1] = static_cast<uint8_t>((word >> 8) & 0xFFu);
  }
  Expect(readback == pattern, "IDE read: sector bytes round-trip");
}

void TestIdeSecondaryNoDeviceStatus() {
  antimal::hv::IdeController secondary(
      nullptr, antimal::hv::IdeController::kSecondaryBase,
      antimal::hv::IdeController::kSecondaryControl);

  Expect(secondary.OnRead(antimal::hv::IdeController::kSecondaryBase + 7, 1) ==
             0,
         "IDE secondary: absent status is not busy");
  secondary.OnWrite(antimal::hv::IdeController::kSecondaryBase + 7, 0xEC, 1);
  Expect((secondary.Status() & 0x80u) == 0,
         "IDE secondary: identify on absent disk does not stay busy");
  Expect((secondary.Status() & 0x01u) != 0,
         "IDE secondary: identify on absent disk reports error");
}

void TestIdeAssertsInterrupt() {
  antimal::hv::MemoryBlockDevice disk(8);
  antimal::hv::IdeController ide(&disk);
  Expect(!ide.InterruptPending(), "IDE IRQ: latch starts clear");
  Expect(ide.IrqLine() == 14, "IDE IRQ: primary maps to IRQ 14");

  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0xEC, 1);
  Expect(ide.InterruptPending(),
         "IDE IRQ: IDENTIFY raises the interrupt line");
  Expect(ide.ConsumeInterrupt(), "IDE IRQ: consume returns true once");
  Expect(!ide.ConsumeInterrupt(),
         "IDE IRQ: consume clears the latch on first read");

  // nIEN bit (bit 1 of device control) should suppress the latch.
  ide.OnWrite(antimal::hv::IdeController::kPrimaryControl, 0x02, 1);
  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0xEC, 1);
  Expect(!ide.InterruptPending(),
         "IDE IRQ: nIEN suppresses interrupt assertion");
}

void TestPcIoPicVectorBaseTracking() {
  antimal::hv::PcIoDevices pic;
  Expect(pic.MasterPicVectorBase() == 0, "PIC: master base starts at 0");
  Expect(pic.SlavePicVectorBase() == 0, "PIC: slave base starts at 0");

  // ICW1, ICW2, ICW3, ICW4 sequence.
  pic.OnWrite(0x20, 0x11, 1);
  pic.OnWrite(0x21, 0x20, 1); // master vector base = 0x20
  pic.OnWrite(0x21, 0x04, 1);
  pic.OnWrite(0x21, 0x01, 1);
  pic.OnWrite(0xA0, 0x11, 1);
  pic.OnWrite(0xA1, 0x28, 1); // slave vector base = 0x28
  pic.OnWrite(0xA1, 0x02, 1);
  pic.OnWrite(0xA1, 0x01, 1);

  Expect(pic.MasterPicVectorBase() == 0x20,
         "PIC: master vector base remembered");
  Expect(pic.SlavePicVectorBase() == 0x28,
         "PIC: slave vector base remembered");

  // Subsequent data-port writes should set the IRQ mask, not the base.
  pic.OnWrite(0x21, 0xFE, 1);
  Expect(pic.MasterPicVectorBase() == 0x20,
         "PIC: post-init data write does not overwrite vector base");
}

void TestIoApicProgramRedirection() {
  struct Capture {
    uint32_t destination = 0;
    uint8_t vector = 0;
    int calls = 0;
  } capture;
  auto deliver = +[](void *context, uint32_t destination,
                     uint8_t vector) -> bool {
    auto *c = static_cast<Capture *>(context);
    c->destination = destination;
    c->vector = vector;
    ++c->calls;
    return true;
  };

  antimal::hv::IoApic ioApic;
  ioApic.SetDeliveryCallback(deliver, &capture);

  // Default state: every entry masked, RaiseIrq does not call back.
  Expect(!ioApic.RaiseIrq(14),
         "IOAPIC: raise on masked entry returns false");
  Expect(capture.calls == 0,
         "IOAPIC: masked raise does not call deliver");

  // Program redirection entry for IRQ 14 to vector 0x76, destination 0,
  // unmasked. The redirection entry index is 0x10 + 2*irq.
  const uint8_t lowIndex = 0x10 + 14 * 2;
  // low dword: vector 0x76, delivery mode 0, dest mode 0, mask 0.
  ioApic.IndirectWrite(lowIndex, 0x00000076u);
  ioApic.IndirectWrite(static_cast<uint8_t>(lowIndex + 1), 0x00000000u);

  Expect(ioApic.RaiseIrq(14), "IOAPIC: unmasked raise delivers");
  Expect(capture.vector == 0x76, "IOAPIC: deliver carries programmed vector");
  Expect(capture.destination == 0, "IOAPIC: destination from entry");
  Expect(capture.calls == 1, "IOAPIC: deliver called once per raise");

  // Indirect read should return the same value we wrote.
  Expect(ioApic.IndirectRead(lowIndex) == 0x76,
         "IOAPIC: indirect read reflects programmed redirection");

  // Mask the entry and confirm raise stops delivering.
  ioApic.IndirectWrite(lowIndex, 0x00010076u); // bit 16 = mask
  Expect(!ioApic.RaiseIrq(14), "IOAPIC: re-masked entry stops delivering");
  Expect(capture.calls == 1, "IOAPIC: deliver not called on masked raise");
}

void TestMmioBusRouting() {
  struct StubDevice : public antimal::hv::IMmioDevice {
    uint64_t lastWriteAddr = 0;
    uint64_t lastWriteValue = 0;
    uint8_t lastWriteSize = 0;
    int readCalls = 0;
    int writeCalls = 0;
    uint64_t MmioBase() const noexcept override { return 0xFEC00000ull; }
    uint64_t MmioLast() const noexcept override { return 0xFEC00FFFull; }
    bool OnRead(uint64_t /*gpa*/, uint8_t /*sz*/, uint64_t *out) override {
      ++readCalls;
      *out = 0xCAFEBABEull;
      return true;
    }
    bool OnWrite(uint64_t gpa, uint8_t sz, uint64_t value) override {
      ++writeCalls;
      lastWriteAddr = gpa;
      lastWriteValue = value;
      lastWriteSize = sz;
      return true;
    }
  } device;

  antimal::hv::MmioBus bus;
  bus.Attach(&device);

  uint64_t value = 0;
  Expect(bus.Read(0xFEC00010ull, 4, &value), "MmioBus: read routes to device");
  Expect(value == 0xCAFEBABEull, "MmioBus: read returns device-provided value");
  Expect(bus.Write(0xFEC00010ull, 4, 0x12345678ull),
         "MmioBus: write routes to device");
  Expect(device.lastWriteValue == 0x12345678ull,
         "MmioBus: write carries programmed value");
  Expect(!bus.Write(0xFED00000ull, 4, 0),
         "MmioBus: writes outside any device return false");
  Expect(!bus.Read(0xFED00000ull, 4, &value),
         "MmioBus: reads outside any device return false");
}

void TestPeParser() {
  wchar_t modulePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
  const auto pe = antimal::ParsePeFile(modulePath);
  Expect(pe.isPe, "current test executable parses as PE");
}

void TestBrowserRisk() {
  std::vector<antimal::BrowserRisk> records;
  antimal::BrowserRisk a;
  a.domain = "accounts.example.com";
  a.savedCredentials = true;
  a.cookiesPresent = true;
  records.push_back(a);

  auto risks =
      antimal::AnalyzeBrowserImpactFromSyntheticData({"https://example.com/c2"}, records);
  Expect(risks.size() == 1, "browser impact domain suffix match");
  Expect(risks[0].recommendation.find("revoke") != std::string::npos,
         "browser recommendation");
  Expect(antimal::ExtractDomain("https://www.Example.com:443/path") == "example.com",
         "domain extraction");
}

// Phase 1 smoke test for the in-house hypervisor: build a partition, give it
// one 4 KiB RAM page containing `mov ax, 0x42 ; hlt`, run a single vCPU in
// 16-bit real mode starting at GPA 0, expect a HLT exit and AX low 16 bits to
// equal 0x42.
//
// Skipped (not failed) when Windows Hypervisor Platform isn't available on
// the host, so the test binary still passes on machines where WHP is off.
// This is the moment that proves WHP plumbing works end-to-end on this
// hardware before later phases pile on firmware/disk/devices.
void TestWhpHelloPartition() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host (enable "
                 "HypervisorPlatform optional feature to run)\n";
    return;
  }

  try {
    antimal::hv::WhpHost host(1);
    antimal::hv::GuestMemoryRegion ram(host, 0, 0x1000,
                                       antimal::hv::GuestMemoryProt::ReadWriteExecute);

    // `mov ax, 0x42 ; hlt` in 16-bit real mode (4 bytes).
    static constexpr uint8_t payload[] = {0xB8, 0x42, 0x00, 0xF4};
    ram.Write(0, payload, sizeof(payload));

    antimal::hv::Vcpu vcpu(host, 0);
    antimal::hv::ResetState16BitRealMode reset{};
    reset.csSelector = 0;
    reset.csBase = 0;
    reset.rip = 0;
    vcpu.SetRealModeStart(reset);

    const auto reason = vcpu.Run();
    Expect(reason == WHvRunVpExitReasonX64Halt, "WHP smoke: vCPU exited on HLT");
    const auto rax = vcpu.ReadRax();
    Expect((rax & 0xFFFFu) == 0x42u, "WHP smoke: AX == 0x42 after run");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP smoke threw WhpError: " << ex.what() << "\n";
  }
}

// Confirms the GuestMemoryProt::ReadOnly trap pattern that VirtualMachine
// uses for the IOAPIC (0xFEC00000) and HPET (0xFED00000) MMIO ranges
// actually causes WHP to generate a WHvRunVpExitReasonMemoryAccess on a
// guest write. The host code assumed this without ever asserting it, so
// when the OVMF boot probe shows mmioReads/mmioWrites == 0 we cannot tell
// whether the trap silently absorbed the access or the guest never touched
// the address. This test pins down the answer.
//
// Approach: a 16-bit real-mode guest writes a known value to a low-memory
// ReadOnly trap page. Real mode avoids needing GDT/page tables but keeps
// us inside the standard segment-limited 64 KiB so the access size is
// well-defined.
void TestWhpMmioReadOnlyTrapsOnWrite() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }

  try {
    antimal::hv::WhpHost host(1);
    // Code page (RWX) at GPA 0 holds the payload; a ReadOnly trap page sits
    // immediately above at GPA 0x1000 (4 KiB). DS:0x1000 with DS=0 in real
    // mode addresses linear 0x1000, which lands in the trap region.
    antimal::hv::GuestMemoryRegion code(
        host, 0, 0x1000, antimal::hv::GuestMemoryProt::ReadWriteExecute);
    antimal::hv::GuestMemoryRegion trap(
        host, 0x1000, 0x1000, antimal::hv::GuestMemoryProt::ReadOnly);

    // 16-bit real-mode payload:
    //   B8 EF BE       mov ax, 0xBEEF
    //   A3 10 00       mov [0x0010], ax    ; segment DS=0, offset 0x10 of trap pg
    //   F4             hlt
    // The `mov` targets word [DS:0x0010] which is linear 0x0010 — INSIDE
    // the code page, not the trap. Re-target to linear 0x1010 by setting
    // DS to 0x0100 (so DS:0x0010 == linear 0x1010).
    //   BB 00 01       mov bx, 0x0100
    //   8E DB          mov ds, bx
    //   B8 EF BE       mov ax, 0xBEEF
    //   A3 10 00       mov [0x0010], ax     ; DS=0x100 -> linear 0x1010
    //   F4             hlt
    static constexpr uint8_t payload[] = {
        0xBB, 0x00, 0x01,
        0x8E, 0xDB,
        0xB8, 0xEF, 0xBE,
        0xA3, 0x10, 0x00,
        0xF4,
    };
    code.Write(0, payload, sizeof(payload));

    antimal::hv::Vcpu vcpu(host, 0);
    antimal::hv::ResetState16BitRealMode reset{};
    vcpu.SetRealModeStart(reset);

    bool sawMemoryAccess = false;
    uint64_t observedGpa = 0;
    uint8_t observedAccessType = 0xFFu;
    bool reachedHalt = false;

    constexpr int kMaxSteps = 16;
    for (int step = 0; step < kMaxSteps; ++step) {
      const auto reason = vcpu.Run();
      if (reason == WHvRunVpExitReasonMemoryAccess) {
        const auto &mem = vcpu.LastExit().MemoryAccess;
        sawMemoryAccess = true;
        observedGpa = mem.Gpa;
        observedAccessType = mem.AccessInfo.AccessType;
        break;
      }
      if (reason == WHvRunVpExitReasonX64Halt) {
        reachedHalt = true;
        break;
      }
      // Anything else (CPUID etc.) is unexpected for this tiny payload.
      // Break so the test fails clearly rather than hanging.
      if (reason != WHvRunVpExitReasonX64IoPortAccess) {
        break;
      }
    }

    Expect(sawMemoryAccess,
           "ReadOnly trap: write to a ReadOnly-mapped page produces a "
           "WHvRunVpExitReasonMemoryAccess (if false, OVMF MMIO trap design "
           "is broken)");
    Expect(!reachedHalt,
           "ReadOnly trap: the trapping write should fire before HLT — if "
           "we reached HLT first, WHP silently let the write succeed");
    Expect((observedGpa & ~0xFFFull) == 0x1000ull,
           "ReadOnly trap: memory-access exit reports the trapped page");
    Expect(observedAccessType == 1,
           "ReadOnly trap: memory-access exit is reported as a write");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: ReadOnly MMIO trap test threw WhpError: " << ex.what()
              << "\n";
  }
}

// Phase 2 smoke test: the guest pushes "Hi\n" out COM1 (0x3F8) one byte at a
// time, then HLTs. The host dispatches IO-port exits to a SerialConsole device
// and advances RIP past each `out dx, al`. Success criteria: SerialConsole
// captured "Hi\n" exactly, vCPU exited via HLT.
void TestWhpSerialConsole() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }

  try {
    antimal::hv::WhpHost host(1);
    antimal::hv::GuestMemoryRegion ram(
        host, 0, 0x1000, antimal::hv::GuestMemoryProt::ReadWriteExecute);

    // 16-bit real-mode payload that writes "Hi\n" to COM1 and halts.
    // Hand-assembled; total 12 bytes.
    static constexpr uint8_t payload[] = {
        0xBA, 0xF8, 0x03,       // mov dx, 0x3F8
        0xB0, 'H',              // mov al, 'H'
        0xEE,                   // out dx, al
        0xB0, 'i',              // mov al, 'i'
        0xEE,                   // out dx, al
        0xB0, 0x0A,             // mov al, 0x0A  ; '\n'
        0xEE,                   // out dx, al
        0xF4,                   // hlt
    };
    ram.Write(0, payload, sizeof(payload));

    antimal::hv::Vcpu vcpu(host, 0);
    antimal::hv::ResetState16BitRealMode reset{};
    vcpu.SetRealModeStart(reset);

    antimal::hv::SerialConsole com1;
    bool halted = false;
    int unexpectedExits = 0;
    constexpr int kMaxSteps = 64;
    for (int step = 0; step < kMaxSteps && !halted; ++step) {
      const auto reason = vcpu.Run();
      const auto &ctx = vcpu.LastExit();
      switch (reason) {
      case WHvRunVpExitReasonX64Halt:
        halted = true;
        break;
      case WHvRunVpExitReasonX64IoPortAccess: {
        const auto &io = ctx.IoPortAccess;
        const uint16_t port = io.PortNumber;
        const uint8_t size = static_cast<uint8_t>(io.AccessInfo.AccessSize);
        if (io.AccessInfo.IsWrite) {
          uint32_t value = static_cast<uint32_t>(io.Rax);
          if (com1.Owns(port)) {
            com1.OnWrite(port, value, size);
          }
        } else {
          uint32_t value = 0;
          if (com1.Owns(port)) {
            value = com1.OnRead(port, size);
          }
          uint64_t rax = io.Rax;
          const uint64_t mask =
              size == 1 ? 0xFFull : size == 2 ? 0xFFFFull : 0xFFFFFFFFull;
          rax = (rax & ~mask) | (value & mask);
          vcpu.WriteRax(rax);
        }
        vcpu.AdvanceRip(ctx.VpContext.InstructionLength);
        break;
      }
      default:
        ++unexpectedExits;
        halted = true;
        break;
      }
    }

    Expect(halted, "WHP serial: vCPU reached HLT (or unexpected exit broke loop)");
    Expect(unexpectedExits == 0, "WHP serial: no unexpected exit reasons");
    Expect(com1.Captured() == "Hi\n", "WHP serial: COM1 captured 'Hi\\n'");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP serial threw WhpError: " << ex.what() << "\n";
  }
}

// Phase 3a: load OVMF.fd from firmware/ at the repo root and verify it maps
// into the partition correctly. We do NOT run a vCPU yet — Phase 3b does that.
// Skip cleanly if the firmware blob has not been dropped in.
std::filesystem::path FindFirmwareBlob() {
  wchar_t modulePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
  // bin\x64\Release\AntiMal.Tests.exe -> walk up three dirs to repo root.
  auto repoRoot = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path();
  return repoRoot / "firmware" / "OVMF.fd";
}

void TestWhpFirmwareMapping() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }
  const auto blobPath = FindFirmwareBlob();
  if (!std::filesystem::exists(blobPath)) {
    std::cout << "SKIP: " << blobPath.string()
              << " not present (see firmware/README.md to drop OVMF.fd)\n";
    return;
  }

  try {
    const auto sizeOnDisk = std::filesystem::file_size(blobPath);

    antimal::hv::WhpHost host(1);
    antimal::hv::Firmware firmware(host, blobPath);

    Expect(firmware.Size() == sizeOnDisk,
           "WHP firmware: mapped size matches on-disk size");
    Expect(firmware.Gpa() == antimal::hv::Firmware::kFourGib - sizeOnDisk,
           "WHP firmware: GPA placed just below 4 GiB");
    Expect(firmware.ContainsGpa(antimal::hv::Firmware::kResetVectorGpa),
           "WHP firmware: reset vector 0xFFFFFFF0 falls inside mapping");

    // Compare a few bytes near the reset vector through the host-side pointer
    // against a fresh disk read. Catches any silent corruption in the copy
    // path between ReadFileAll() and the mapped backing memory.
    std::ifstream stream(blobPath, std::ios::binary);
    Expect(stream.good(), "WHP firmware: blob re-readable for spot check");
    const auto resetOffsetInBlob =
        antimal::hv::Firmware::kResetVectorGpa - firmware.Gpa();
    stream.seekg(static_cast<std::streamoff>(resetOffsetInBlob));
    uint8_t fromDisk[16]{};
    stream.read(reinterpret_cast<char *>(fromDisk), sizeof(fromDisk));
    const auto *mapped = firmware.HostBytes() + resetOffsetInBlob;
    bool resetBytesMatch = true;
    bool anyNonZero = false;
    for (size_t i = 0; i < sizeof(fromDisk); ++i) {
      if (fromDisk[i] != mapped[i]) {
        resetBytesMatch = false;
      }
      if (mapped[i] != 0) {
        anyNonZero = true;
      }
    }
    Expect(resetBytesMatch,
           "WHP firmware: bytes near reset vector match disk read");
    Expect(anyNonZero,
           "WHP firmware: reset-vector region is non-zero (real firmware, not blanks)");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP firmware threw WhpError: " << ex.what() << "\n";
  }
}

// Phase 3b: actually run OVMF in the vCPU. Build a partition with 16 MiB of
// low RAM + the OVMF mapping + a COM1 serial console attached via IoBus, let
// the CPU start from its architectural reset state (CS.Base=0xFFFF0000,
// RIP=0xFFF0, which lands inside our firmware mapping), and dispatch exits
// for up to a step budget.
//
// Unhandled MMIO accesses are advanced past without emulation — broken from
// the guest's perspective, but Phase 3b's success bar is just "OVMF runs for
// a while and something useful comes out the serial port." If anything lands
// in COM1, we know the WHP plumbing and reset-vector mapping are correct.
// The list of MMIO devices we'd need next (LAPIC, PIC, PIT, CMOS, PCI host
// bridge) is documented in INHOUSE_VM.md.
void TestWhpOvmfBoot() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }
  const auto blobPath = FindFirmwareBlob();
  if (!std::filesystem::exists(blobPath)) {
    std::cout << "SKIP: " << blobPath.string() << " not present\n";
    return;
  }

  try {
    antimal::hv::WhpHost host(1, true);
    antimal::hv::GuestMemoryRegion lowRam(
        host, 0, 128ull * 1024ull * 1024ull,
        antimal::hv::GuestMemoryProt::ReadWriteExecute);
    antimal::hv::GuestMemoryRegion highRam(
        host, 0x100000000ull, 32ull * 1024ull * 1024ull,
        antimal::hv::GuestMemoryProt::ReadWriteExecute);
    antimal::hv::Firmware firmware(host, blobPath);
    antimal::hv::Vcpu vcpu(host, 0);

    // WHP's default reset shadow on this host points CS at low memory
    // (0x000FFFF0). OVMF expects the architectural 386+ reset vector at
    // 0xFFFFFFF0 inside the firmware mapping.
    vcpu.SetX86ResetState();

    antimal::hv::SerialConsole com1(antimal::hv::SerialConsole::kCom1Base);
    antimal::hv::PcIoDevices pcIo;
    antimal::hv::IoBus bus;
    bus.Attach(&com1, com1.BasePort(), com1.LastPort());
    bus.Attach(&pcIo, 0x00, 0x0F); // legacy DMA controller
    bus.Attach(&pcIo, 0x20, 0x21); // master PIC
    bus.Attach(&pcIo, 0x40, 0x43); // PIT
    bus.Attach(&pcIo, 0x70, 0x71); // CMOS/RTC
    bus.Attach(&pcIo, 0x80, 0x80); // POST/delay port
    bus.Attach(&pcIo, 0x92, 0x92); // A20/system control port
    bus.Attach(&pcIo, 0xA0, 0xA1); // slave PIC
    bus.Attach(&pcIo, 0xED, 0xED); // firmware delay port
    bus.Attach(&pcIo, 0x510, 0x511); // QEMU fw_cfg selector/data
    bus.Attach(&pcIo, 0xCF8, 0xCFF); // PCI config mechanism #1
    bus.Attach(&pcIo, 0xB000, 0xB0FF); // PIIX4 ACPI PM IO

    auto formatState = [](const antimal::hv::Vcpu::DiagState &s) {
      char buf[384];
      _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                  "    CS=%04X:base=%016llX RIP=%016llX RFLAGS=%016llX\n"
                  "    CR0=%016llX CR3=%016llX CR4=%016llX CR8=%016llX EFER=%016llX\n"
                  "    IDTR=base:%016llX limit:%04X",
                  s.cs_selector, s.cs_base, s.rip, s.rflags, s.cr0, s.cr3,
                  s.cr4, s.cr8, s.efer, s.idtr_base, s.idtr_limit);
      return std::string(buf);
    };

    auto readLowRamByte = [&](uint64_t gpa, uint8_t *out) {
      if (gpa < lowRam.Gpa() || gpa >= lowRam.Gpa() + lowRam.Size()) {
        return false;
      }
      *out = lowRam.HostPtr()[static_cast<size_t>(gpa - lowRam.Gpa())];
      return true;
    };

    auto dumpLowRamBytes = [&](uint64_t gpa) {
      if (gpa >= lowRam.Gpa() && gpa < lowRam.Gpa() + lowRam.Size()) {
        const uint64_t startGpa =
            gpa >= lowRam.Gpa() + 32 ? gpa - 32 : lowRam.Gpa();
        const size_t offset = static_cast<size_t>(startGpa - lowRam.Gpa());
        const size_t available = lowRam.Size() - offset;
        const size_t count = available < 96 ? available : 96;
        char header[96];
        _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "  bytes near RIP (GPA %016llX):",
                    static_cast<unsigned long long>(startGpa));
        std::cout << header;
        for (size_t i = 0; i < count; ++i) {
          char byteBuf[8];
          _snprintf_s(byteBuf, sizeof(byteBuf), _TRUNCATE, " %02X",
                      lowRam.HostPtr()[offset + i]);
          std::cout << byteBuf;
        }
        std::cout << "\n";
      }
    };

    {
      auto pre = vcpu.ReadDiagState();
      std::cout << "WHP OVMF pre-run state:\n" << formatState(pre) << "\n";
    }

    constexpr int kMaxSteps = 25000;
    constexpr int kHltStreakLimit = 8;
    constexpr int kTimerInjectionLimit = 4;
    constexpr int kWatchdogCancelTicks = 50;
    std::map<int, int> exitHist;
    int unhandledMmio = 0;
    uint64_t lastMmioGpa = 0;
    uint64_t lastMmioGva = 0;
    uint32_t lastMmioAccess = 0;
    uint8_t lastMmioInstrLen = 0;
    uint8_t lastMmioInstrBytes[16]{};
    int unhandledIo = 0;
    uint16_t lastUnhandledIoPort = 0;
    uint8_t lastUnhandledIoSize = 0;
    bool lastUnhandledIoWrite = false;
    std::map<uint16_t, int> ioPortHist;
    uint16_t lastIoPort = 0;
    uint8_t lastIoSize = 0;
    bool lastIoWrite = false;
    bool lastIoString = false;
    bool lastIoRep = false;
    uint64_t lastIoRcx = 0;
    uint64_t lastIoRdi = 0;
    uint8_t lastIoInstrLen = 0;
    uint8_t lastIoInstrBytes[16]{};
    int unhandledOther = 0;
    int hltStreak = 0;
    int totalHlts = 0;
    uint64_t lastCancelRip = 0;
    uint8_t lastCancelOpcode = 0;
    bool lastCancelAtHlt = false;
    std::atomic<int> timerInterruptRequests{0};
    std::atomic<int> timerInterruptsInjected{0};
    std::atomic<int> timerInterruptRequestFailures{0};
    std::atomic<unsigned long> lastTimerInterruptHr{S_OK};
    std::atomic<int> lastTimerInterruptVector{-1};
    std::atomic<unsigned long> lastApicLvtTimer{0};
    bool halted = false;
    bool fatal = false;
    bool idleLoop = false;
    WHV_RUN_VP_EXIT_REASON fatalReason = WHvRunVpExitReasonNone;
    antimal::hv::Vcpu::DiagState firstHltState{};
    std::atomic<bool> inRun{false};
    std::atomic<int> watchdogCancels{0};
    auto requestTimerInterrupt = [&](uint8_t vector) {
      int current = timerInterruptRequests.load(std::memory_order_relaxed);
      while (current < kTimerInjectionLimit) {
        if (timerInterruptRequests.compare_exchange_weak(
                current, current + 1, std::memory_order_relaxed)) {
          lastTimerInterruptVector.store(vector, std::memory_order_relaxed);
          const HRESULT hr = vcpu.RequestFixedInterrupt(vector);
          lastTimerInterruptHr.store(static_cast<unsigned long>(hr),
                                     std::memory_order_relaxed);
          if (SUCCEEDED(hr)) {
            timerInterruptsInjected.fetch_add(1, std::memory_order_relaxed);
            return true;
          }
          timerInterruptRequestFailures.fetch_add(1, std::memory_order_relaxed);
          return false;
        }
      }
      return false;
    };
    auto readApicTimer = [&]() {
      uint32_t lvt = 0;
      if (!vcpu.TryReadApicLvtTimer(&lvt)) {
        return 0u;
      }
      lastApicLvtTimer.store(lvt, std::memory_order_relaxed);
      return lvt;
    };
    auto apicTimerVector = [](uint32_t lvt) {
      return static_cast<uint8_t>(lvt & 0xFFu);
    };
    auto apicTimerMasked = [](uint32_t lvt) {
      return (lvt & (1u << 16)) != 0;
    };
    std::jthread watchdog([&](std::stop_token stop) {
      using namespace std::chrono_literals;
      int ticksInRun = 0;
      while (!stop.stop_requested()) {
        std::this_thread::sleep_for(10ms);
        if (!inRun.load(std::memory_order_relaxed)) {
          ticksInRun = 0;
          continue;
        }
        ++ticksInRun;
        if (ticksInRun >= kWatchdogCancelTicks && !stop.stop_requested()) {
          vcpu.CancelRun();
          watchdogCancels.fetch_add(1, std::memory_order_relaxed);
          ticksInRun = 0;
        }
      }
    });

    const auto smokeDeadline = std::chrono::steady_clock::now() +
                               std::chrono::seconds{20};
    for (int step = 0; step < kMaxSteps && !halted && !fatal && !idleLoop &&
                       std::chrono::steady_clock::now() < smokeDeadline;
         ++step) {
      inRun.store(true, std::memory_order_relaxed);
      const auto reason = vcpu.Run();
      inRun.store(false, std::memory_order_relaxed);
      exitHist[static_cast<int>(reason)]++;
      const auto &ctx = vcpu.LastExit();
      const uint64_t instrLen = ctx.VpContext.InstructionLength;

      // Reset the HLT streak on any non-HLT exit; clustered HLTs without
      // intervening exits mean OVMF is idle-looping waiting for an interrupt
      // we don't deliver, so bail.
      if (reason != WHvRunVpExitReasonX64Halt) {
        hltStreak = 0;
      }

      switch (reason) {
      case WHvRunVpExitReasonX64Halt: {
        ++totalHlts;
        ++hltStreak;
        if (totalHlts == 1) {
          firstHltState = vcpu.ReadDiagState();
        }
        if (timerInterruptRequests.load(std::memory_order_relaxed) <
            kTimerInjectionLimit) {
          const uint32_t lvt = readApicTimer();
          const uint8_t vector = apicTimerVector(lvt);
          vcpu.AdvanceRip(instrLen > 0 ? instrLen : 1);
          if (lvt != 0 && !apicTimerMasked(lvt) && vector >= 0x10 &&
              requestTimerInterrupt(vector)) {
            hltStreak = 0;
          }
          break;
        }
        if (hltStreak >= kHltStreakLimit) {
          idleLoop = true;
          break;
        }
        // Advance past HLT (1 byte) so we don't immediately re-trap on the
        // same instruction. With no interrupts wired up the guest will
        // probably execute another HLT shortly — that's the streak limit's
        // job to catch.
        vcpu.AdvanceRip(instrLen > 0 ? instrLen : 1);
        break;
      }
      case WHvRunVpExitReasonX64IoPortAccess: {
        const auto &io = ctx.IoPortAccess;
        const uint16_t port = io.PortNumber;
        const uint8_t size = static_cast<uint8_t>(io.AccessInfo.AccessSize);
        ioPortHist[port]++;
        lastIoPort = port;
        lastIoSize = size;
        lastIoWrite = io.AccessInfo.IsWrite != 0;
        lastIoString = io.AccessInfo.StringOp != 0;
        lastIoRep = io.AccessInfo.RepPrefix != 0;
        lastIoRcx = io.Rcx;
        lastIoRdi = io.Rdi;
        lastIoInstrLen = io.InstructionByteCount;
        for (size_t i = 0; i < sizeof(lastIoInstrBytes); ++i) {
          lastIoInstrBytes[i] = io.InstructionBytes[i];
        }
        bool handled = false;
        if (io.AccessInfo.IsWrite) {
          handled = bus.Write(port, static_cast<uint32_t>(io.Rax), size);
        } else {
          uint32_t value = 0;
          handled = bus.Read(port, size, &value);
          const uint64_t mask = size == 1   ? 0xFFull
                                : size == 2 ? 0xFFFFull
                                            : 0xFFFFFFFFull;
          uint64_t rax = io.Rax;
          rax = (rax & ~mask) | (value & mask);
          vcpu.WriteRax(rax);
        }
        if (!handled) {
          ++unhandledIo;
          lastUnhandledIoPort = port;
          lastUnhandledIoSize = size;
          lastUnhandledIoWrite = io.AccessInfo.IsWrite != 0;
        }
        if (instrLen > 0) vcpu.AdvanceRip(instrLen);
        break;
      }
      case WHvRunVpExitReasonX64Cpuid:
        vcpu.EmulateCpuidExit();
        break;
      case WHvRunVpExitReasonMemoryAccess:
        ++unhandledMmio;
        lastMmioGpa = ctx.MemoryAccess.Gpa;
        lastMmioGva = ctx.MemoryAccess.Gva;
        lastMmioAccess = ctx.MemoryAccess.AccessInfo.AccessType;
        lastMmioInstrLen = ctx.MemoryAccess.InstructionByteCount;
        for (size_t i = 0; i < sizeof(lastMmioInstrBytes); ++i) {
          lastMmioInstrBytes[i] = ctx.MemoryAccess.InstructionBytes[i];
        }
        // Skip past the trapping instruction without emulating. Broken but
        // lets us see how far OVMF gets before its first hard MMIO need.
        if (instrLen > 0) {
          vcpu.AdvanceRip(instrLen);
        } else {
          fatal = true;
          fatalReason = reason;
        }
        break;
      case WHvRunVpExitReasonException:
      case WHvRunVpExitReasonUnrecoverableException:
      case WHvRunVpExitReasonInvalidVpRegisterValue:
      case WHvRunVpExitReasonUnsupportedFeature:
        fatal = true;
        fatalReason = reason;
        break;
      case WHvRunVpExitReasonCanceled:
      {
        const auto canceledState = vcpu.ReadDiagState();
        lastCancelRip = ctx.VpContext.Rip != 0 ? ctx.VpContext.Rip
                                               : canceledState.rip;
        uint8_t opcode = 0;
        uint8_t prevOpcode = 0;
        const bool haveOpcode = readLowRamByte(lastCancelRip, &opcode);
        const bool hltAtRip = haveOpcode && opcode == 0xF4u;
        const bool hltBeforeRip =
            lastCancelRip > 0 && readLowRamByte(lastCancelRip - 1, &prevOpcode) &&
            prevOpcode == 0xF4u;
        const bool canceledAtHlt = hltAtRip || hltBeforeRip;
        lastCancelOpcode = opcode;
        lastCancelAtHlt = canceledAtHlt;
        const uint32_t lvt = readApicTimer();
        const uint8_t vector = apicTimerVector(lvt);
        if (canceledAtHlt &&
            timerInterruptRequests.load(std::memory_order_relaxed) <
                kTimerInjectionLimit &&
            lvt != 0 && !apicTimerMasked(lvt) && vector >= 0x10) {
          if (totalHlts == 0) {
            firstHltState = canceledState;
          }
          ++totalHlts;
          if (hltAtRip) {
            vcpu.AdvanceRip(1);
          }
          (void)requestTimerInterrupt(vector);
          break;
        }
        if (timerInterruptRequests.load(std::memory_order_relaxed) >=
                kTimerInjectionLimit ||
            canceledAtHlt) {
          idleLoop = true;
        } else {
          fatal = true;
          fatalReason = reason;
        }
        break;
      }
      default:
        ++unhandledOther;
        if (instrLen > 0) {
          vcpu.AdvanceRip(instrLen);
        } else {
          // No way to make forward progress. Bail.
          fatal = true;
          fatalReason = reason;
        }
        break;
      }
    }

    const auto captured = com1.Captured();
    std::cout << "WHP OVMF boot diagnostic:\n";
    std::cout << "  result: "
              << (halted    ? "HALTED_VOLUNTARY"
                  : fatal   ? "FATAL"
                  : idleLoop ? "IDLE_LOOP (HLT streak)"
                             : "STEP_LIMIT")
              << "\n";
    if (fatal) {
      std::cout << "  fatal exit reason: " << static_cast<int>(fatalReason) << "\n";
    }
    std::cout << "  total HLTs:              " << totalHlts << "\n";
    std::cout << "  timer interrupts:        last vector ";
    const int lastVector = lastTimerInterruptVector.load(std::memory_order_relaxed);
    if (lastVector >= 0) {
      std::cout << "0x" << std::hex << std::uppercase << lastVector
                << std::dec;
    } else {
      std::cout << "(none)";
    }
    std::cout << ", requested "
              << timerInterruptRequests.load(std::memory_order_relaxed)
              << ", injected "
              << timerInterruptsInjected.load(std::memory_order_relaxed)
              << ", failed "
              << timerInterruptRequestFailures.load(std::memory_order_relaxed)
              << ", last LVT 0x" << std::hex << std::uppercase
              << lastApicLvtTimer.load(std::memory_order_relaxed)
              << std::dec;
    if (timerInterruptRequestFailures.load(std::memory_order_relaxed) > 0) {
      std::cout << ", last HRESULT 0x" << std::hex << std::uppercase
                << lastTimerInterruptHr.load(std::memory_order_relaxed)
                << std::dec;
    }
    std::cout << "\n";
    std::cout << "  watchdog cancellations:  "
              << watchdogCancels.load(std::memory_order_relaxed) << "\n";
    if (watchdogCancels.load(std::memory_order_relaxed) > 0) {
      std::cout << "    last cancel: RIP=0x" << std::hex << std::uppercase
                << lastCancelRip << " opcode=0x"
                << static_cast<int>(lastCancelOpcode) << std::dec
                << " hlt=" << (lastCancelAtHlt ? 1 : 0) << "\n";
    }
    std::cout << "  unhandled MMIO accesses: " << unhandledMmio << "\n";
    if (unhandledMmio > 0) {
      char buf[256];
      _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                  "    last MMIO: access=%u GPA=%016llX GVA=%016llX instrLen=%u",
                  lastMmioAccess,
                  static_cast<unsigned long long>(lastMmioGpa),
                  static_cast<unsigned long long>(lastMmioGva),
                  lastMmioInstrLen);
      std::cout << buf << "\n";
      std::cout << "    last MMIO instruction bytes:";
      const uint8_t byteCount =
          lastMmioInstrLen < sizeof(lastMmioInstrBytes)
              ? lastMmioInstrLen
              : static_cast<uint8_t>(sizeof(lastMmioInstrBytes));
      for (uint8_t i = 0; i < byteCount; ++i) {
        char byteBuf[8];
        _snprintf_s(byteBuf, sizeof(byteBuf), _TRUNCATE, " %02X",
                    lastMmioInstrBytes[i]);
        std::cout << byteBuf;
      }
      std::cout << "\n";
    }
    std::cout << "  unhandled IO accesses:   " << unhandledIo << "\n";
    if (unhandledIo > 0) {
      char buf[128];
      _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                  "    last IO: %s port=%04X size=%u",
                  lastUnhandledIoWrite ? "write" : "read",
                  lastUnhandledIoPort, lastUnhandledIoSize);
      std::cout << buf << "\n";
    }
    if (!ioPortHist.empty()) {
      std::cout << "  IO-port histogram:\n";
      std::vector<std::pair<uint16_t, int>> topPorts(ioPortHist.begin(),
                                                     ioPortHist.end());
      std::sort(topPorts.begin(), topPorts.end(),
                [](const auto &a, const auto &b) {
                  return a.second > b.second;
                });
      const size_t n = topPorts.size() < 8 ? topPorts.size() : 8;
      for (size_t i = 0; i < n; ++i) {
        std::cout << "    port " << std::hex << std::uppercase
                  << topPorts[i].first << std::dec << ": "
                  << topPorts[i].second << "\n";
      }
      char buf[192];
      _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                  "    last IO detail: %s port=%04X size=%u string=%u rep=%u RCX=%016llX RDI=%016llX instrLen=%u",
                  lastIoWrite ? "write" : "read", lastIoPort, lastIoSize,
                  lastIoString ? 1u : 0u, lastIoRep ? 1u : 0u,
                  static_cast<unsigned long long>(lastIoRcx),
                  static_cast<unsigned long long>(lastIoRdi), lastIoInstrLen);
      std::cout << buf << "\n";
      std::cout << "    last IO instruction bytes:";
      const uint8_t byteCount =
          lastIoInstrLen < sizeof(lastIoInstrBytes)
              ? lastIoInstrLen
              : static_cast<uint8_t>(sizeof(lastIoInstrBytes));
      for (uint8_t i = 0; i < byteCount; ++i) {
        char byteBuf[8];
        _snprintf_s(byteBuf, sizeof(byteBuf), _TRUNCATE, " %02X",
                    lastIoInstrBytes[i]);
        std::cout << byteBuf;
      }
      std::cout << "\n";
    }
    std::cout << "  unhandled other exits:   " << unhandledOther << "\n";
    std::cout << "  exit-reason histogram:\n";
    for (const auto &p : exitHist) {
      std::cout << "    reason " << p.first << ": " << p.second << "\n";
    }
    if (totalHlts > 0) {
      std::cout << "  state at first HLT:\n" << formatState(firstHltState) << "\n";
    }
    {
      auto final = vcpu.ReadDiagState();
      std::cout << "  state at loop exit:\n" << formatState(final) << "\n";
      dumpLowRamBytes(final.rip);
    }
    std::cout << "  COM1 captured: " << captured.size() << " bytes\n";
    if (!captured.empty()) {
      // Cap preview and escape non-printable.
      std::string preview;
      const size_t n = captured.size() < 2048 ? captured.size() : 2048;
      for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(captured[i]);
        if (c == '\n' || c == '\r' || (c >= 32 && c < 127)) {
          preview.push_back(static_cast<char>(c));
        } else {
          char buf[6];
          _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\x%02X", c);
          preview += buf;
        }
      }
      std::cout << "  COM1 preview:\n    " << preview << "\n";
    }

    Expect(!exitHist.empty(), "WHP OVMF: at least one vCPU exit occurred");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP OVMF threw WhpError: " << ex.what() << "\n";
  }
}

void TestWhpOvmfBootWithIdeDisk() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }
  const auto blobPath = FindFirmwareBlob();
  if (!std::filesystem::exists(blobPath)) {
    std::cout << "SKIP: " << blobPath.string() << " not present\n";
    return;
  }

  try {
    antimal::hv::MemoryBlockDevice disk(4096);
    // Smaller RAM + no ACPI/framebuffer so the smoke test stays fast. CPUID
    // exits make modern OVMF need more than the old 25k-step budget before it
    // reaches IDE enumeration; the detonate path uses production defaults.
    antimal::hv::VirtualMachineOptions options{};
    options.lowRamBytes = 128ull * 1024ull * 1024ull;
    options.highRamBytes = 0;
    options.enableAcpiTables = false;
    options.enableFramebuffer = false;
    antimal::hv::VirtualMachine vm(blobPath, &disk, options);
    antimal::hv::VmRunRequest request;
    request.maxSteps = 100000;
    request.timeout = std::chrono::seconds{20};
    const auto summary = vm.Run(request);
    std::cout << "WHP OVMF + IDE summary:\n"
              << "  steps: " << summary.steps << "\n"
              << "  fatal: " << (summary.fatal ? "yes" : "no") << "\n"
              << "  idle loop: " << (summary.idleLoop ? "yes" : "no") << "\n"
              << "  HLTs: " << summary.totalHlts << "\n"
              << "  watchdog cancellations: "
              << summary.watchdogCancellations << "\n"
              << "  last cancel RIP: 0x" << std::hex << std::uppercase
              << summary.lastCanceledRip << std::dec
              << " opcode: 0x" << std::hex << std::uppercase
              << static_cast<int>(summary.lastCanceledOpcode) << std::dec
              << " hlt: " << (summary.lastCanceledAtHlt ? "yes" : "no")
              << "\n"
              << "  IDE commands: " << summary.ideCommandsIssued << "\n"
              << "  IDE identify: " << summary.ideIdentifyCommands << "\n"
              << "  IDE reads: " << summary.ideReadCommands << "\n";
    if (!summary.serialOutput.empty()) {
      std::string preview = summary.serialOutput.substr(
          0, std::min<size_t>(summary.serialOutput.size(), 512));
      std::replace(preview.begin(), preview.end(), '\r', '\n');
      std::cout << "  serial preview:\n" << preview << "\n";
    }
    Expect(summary.steps > 0, "WHP OVMF + IDE: at least one exit occurred");
    Expect(!summary.exitHistogram.empty(),
           "WHP OVMF + IDE: exit histogram populated");
    Expect(!summary.fatal, "WHP OVMF + IDE: no fatal exit");
    Expect(summary.ideIdentifyCommands > 0,
           "WHP OVMF + IDE: IDENTIFY DEVICE completed");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP OVMF + IDE threw WhpError: " << ex.what() << "\n";
  }
}

// ------- Enrichment pipeline tests ------------------------------------

void TestStringExtraction() {
  std::vector<uint8_t> data;
  const char *ascii = "GET https://example.com/path HTTP/1.1\nUser-Agent: AntiMal";
  for (size_t i = 0; ascii[i]; ++i) data.push_back(static_cast<uint8_t>(ascii[i]));
  data.push_back(0);
  // Inline UTF-16LE "Hello world"
  const uint16_t wide[] = {'H','e','l','l','o',' ','w','o','r','l','d',0};
  for (uint16_t w : wide) {
    data.push_back(static_cast<uint8_t>(w & 0xFF));
    data.push_back(static_cast<uint8_t>((w >> 8) & 0xFF));
  }

  const auto ascii_strings = antimal::ExtractAsciiStrings(data, 6);
  Expect(!ascii_strings.empty(), "ascii extraction returns at least one string");
  bool foundHttp = false;
  for (const auto &s : ascii_strings) {
    if (s.find("https://example.com") != std::string::npos) foundHttp = true;
  }
  Expect(foundHttp, "ascii extraction captures URL");

  const auto utf16 = antimal::ExtractUtf16Strings(data, 6);
  bool foundHello = false;
  // Substring match: the byte boundary between the ASCII prefix and the
  // UTF-16 section can splice a leading character onto the wide string
  // (e.g. the trailing 'l\\0' of "AntiMal" reads as wide 'l'). The
  // extractor's job is to surface readable strings, not to be perfectly
  // aligned, so substring containment is the right assertion.
  for (const auto &s : utf16) if (s.find("Hello world") != std::string::npos) foundHello = true;
  Expect(foundHello, "utf16 extraction captures wide string");
}

void TestIocMining() {
  std::vector<std::string> strings = {
      "Connect to https://evil.example.com/c2 with token X",
      "Failover server 203.0.113.42 or evil-other.example.net",
      "Path: C:\\Users\\bob\\AppData\\Local\\Temp\\stage.exe",
      "Reg: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
      "Mutex: Global\\Pelican-AAAA-1111",
      "Blob: aGVsbG8gd29ybGQgaXMgbG9uZyBlbm91Z2ggdG8gbG9vayBsaWtlIGJhc2U2NCBub3QgYSBzdHJpbmc=",
      "Calls VirtualAllocEx and CreateRemoteThread"};
  auto iocs = antimal::MineIocs(strings);
  Expect(!iocs.urls.empty(), "ioc mining: urls found");
  Expect(!iocs.ips.empty(), "ioc mining: ips found");
  Expect(!iocs.domains.empty(), "ioc mining: domains found");
  Expect(!iocs.registryPaths.empty(), "ioc mining: registry paths found");
  Expect(!iocs.filePaths.empty(), "ioc mining: file paths found");
  Expect(!iocs.mutexHints.empty(), "ioc mining: mutex hints found");
  Expect(!iocs.suspiciousApis.empty(), "ioc mining: suspicious apis found");
  Expect(!iocs.base64Blobs.empty(), "ioc mining: base64 blob found");
}

void TestTagger() {
  antimal::Tagger tagger;
  tagger.LoadBuiltinRules();

  antimal::ScanResult scan;
  scan.imports = {"WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
                  "URLDownloadToFileA"};
  scan.findings.push_back({"imports.process_injection", "...", 35});
  antimal::ExtractedIocs iocs;
  iocs.domains.push_back("login.live.com");
  iocs.suspiciousApis.push_back("WriteProcessMemory");

  antimal::YaraScanResult yara;
  yara.available = true;
  yara.succeeded = true;
  yara.matches.push_back({"Win_Stealer", "", {"stealer"}, {}});

  antimal::TagInputs inputs;
  inputs.scan = &scan;
  inputs.iocs = &iocs;
  inputs.yara = &yara;

  auto tags = tagger.Evaluate(inputs, /*minConfidence=*/10);
  Expect(!tags.empty(), "tagger emits tags");
  bool hasInjector = false, hasStealer = false;
  for (const auto &t : tags) {
    if (t.tag == "injector") hasInjector = true;
    if (t.tag == "stealer") hasStealer = true;
  }
  Expect(hasInjector, "tagger detects injector capability");
  Expect(hasStealer, "tagger detects stealer family from yara + strings");
}

void TestSubprocessEcho() {
  // cmd.exe is always present on Windows; trivial echo verifies the pipe.
  antimal::SubprocessOptions opts;
  opts.timeout = std::chrono::milliseconds(5000);
  auto result = antimal::RunSubprocess(L"cmd.exe", {"/c", "echo", "antimal-ok"},
                                       opts);
  Expect(result.launched, "subprocess: cmd.exe launched");
  Expect(result.exitCode == 0, "subprocess: exit 0");
  Expect(result.stdoutText.find("antimal-ok") != std::string::npos,
         "subprocess: stdout captured");
}

void TestSubprocessToolMissing() {
  auto missing = antimal::ResolveToolPath("definitely-not-real-antimal-tool.exe");
  Expect(!missing.has_value(), "ResolveToolPath returns nullopt for missing tool");
  auto yaraResult =
      antimal::RunYara(std::filesystem::path(L"C:\\nope.exe"),
                       std::filesystem::path(L"C:\\nope-rules"));
  Expect(!yaraResult.available || !yaraResult.succeeded,
         "RunYara doesn't crash on missing inputs");
}

void TestEventJournalRoundtrip() {
  const auto dir = TempRoot();
  const auto journalPath = dir / "events.jsonl";

  {
    antimal::EventJournalWriter writer(journalPath);
    antimal::EventRecord ev;
    ev.timestampUtc = "2026-05-18T12:00:00Z";
    ev.source = "Test";
    ev.category = "file";
    ev.action = "create";
    ev.processId = 4321;
    ev.parentProcessId = 100;
    ev.imagePath = "C:\\Windows\\evil.exe";
    ev.target = "C:\\Users\\bob\\stage.bin";
    ev.details["size"] = "12345";
    ev.mitre = "T1105";
    writer.Append(ev);

    antimal::EventRecord ev2;
    ev2.timestampUtc = "2026-05-18T12:00:01Z";
    ev2.source = "Test";
    ev2.category = "network";
    ev2.action = "connect";
    ev2.processId = 4321;
    ev2.target = "evil.example.com:443";
    writer.Append(ev2);
  }

  antimal::EventJournalTailer tailer(journalPath);
  auto all = tailer.ReadAll();
  Expect(all.size() == 2, "journal: two events round-trip");
  Expect(all[0].category == "file", "journal: first event category");
  Expect(all[0].processId == 4321, "journal: pid preserved");
  Expect(all[0].details["size"] == "12345", "journal: details map preserved");
  Expect(all[1].target == "evil.example.com:443", "journal: target preserved");

  // Tailer should report 0 new events on the second pull (cursor at EOF).
  antimal::EventJournalTailer tailer2(journalPath);
  auto first = tailer2.PullNew();
  Expect(first.size() == 2, "tailer first pull: full content");
  auto second = tailer2.PullNew();
  Expect(second.empty(), "tailer second pull: empty when nothing new");

  // Append a new event and verify only that one is returned next.
  {
    antimal::EventJournalWriter writer2(journalPath);
    antimal::EventRecord ev;
    ev.source = "Test";
    ev.category = "process";
    ev.action = "exit";
    ev.processId = 4321;
    writer2.Append(ev);
  }
  auto third = tailer2.PullNew();
  Expect(third.size() == 1, "tailer third pull: only new event");
  Expect(third[0].action == "exit", "tailer third pull: correct event");
}

void TestReportRoundtripAndFramePaths() {
  antimal::AnalysisReport report;
  report.schemaVersion = 1;
  report.runId = "roundtrip";
  report.samplePath = L"C:\\Samples\\benign.exe";
  report.sandboxVerdict = antimal::Verdict::Suspicious;
  report.scannerVerdict.path = report.samplePath;
  report.scannerVerdict.sha256 = "abc123";
  report.scannerVerdict.score = 77;
  report.scannerVerdict.verdict = antimal::Verdict::Suspicious;
  report.scannerVerdict.iocs.domains.push_back("example.com");
  report.scannerVerdict.tags.push_back({"loader", "capability", 60, {"test"}});
  report.dynamicSummary.started = true;
  report.dynamicSummary.status = "boot attempted";
  report.dynamicSummary.bootMilestones.push_back("bootmgfw loaded");
  report.dynamicSummary.bootMilestones.push_back("BCD opened");
  report.artifacts.push_back(std::filesystem::path("artifacts") / "agent-health.json");
  antimal::EventRecord ev;
  ev.timestampUtc = "2026-05-18T12:00:00Z";
  ev.source = "Test";
  ev.category = "process";
  ev.action = "create";
  ev.processId = 1234;
  ev.target = "benign.exe";
  ev.details["note"] = "roundtrip";
  report.events.push_back(ev);
  report.networkDomains.push_back("c2.example.com");
  report.errors.push_back("synthetic error");

  const auto dir = TempRoot();
  const auto reportPath = dir / "report.json";
  antimal::WriteReportJson(reportPath, report);
  auto loaded = antimal::LoadReportBestEffort(reportPath);
  Expect(loaded.scannerVerdict.score == 77, "report load: scanner score preserved");
  Expect(!loaded.scannerVerdict.tags.empty(), "report load: tags preserved");
  Expect(loaded.events.size() == 1, "report load: events preserved");
  Expect(loaded.events[0].details["note"] == "roundtrip",
         "report load: event details preserved");
  Expect(loaded.dynamicSummary.bootMilestones.size() == 2,
         "report load: boot milestones preserved");
  Expect(loaded.artifacts.size() == 1, "report load: artifacts preserved");
  Expect(loaded.networkDomains.size() == 1, "report load: network preserved");
  Expect(loaded.errors.size() == 1, "report load: errors preserved");

  const auto html = antimal::BuildHtmlReportWithFrames(
      loaded, {std::filesystem::path("screenshots") / "frame-000001.png"});
  Expect(html.find("screenshots/frame-000001.png") != std::string::npos,
         "report html: frame path includes screenshots directory");
}

void TestIntelLookupOffline() {
  // With enabled=false the lookup returns immediately, no transport.
  antimal::IntelLookupConfig cfg;
  cfg.enabled = false;
  auto offline = antimal::LookupHash("a" + std::string(63, '0'), cfg);
  Expect(!offline.enabled, "intel: skipped when not enabled");
  Expect(offline.hits.empty(), "intel: no hits when disabled");

  // Parser checks against canned responses (no network).
  const std::string mbOk =
      R"({"query_status": "ok", "data": [{"sha256_hash": "abc", "signature": "AgentTesla", "tags": ["AgentTesla", "stealer"]}]})";
  auto mb = antimal::ParseMalwareBazaarResponse(mbOk);
  Expect(mb.known, "malwarebazaar: known response");
  Expect(mb.family == "AgentTesla", "malwarebazaar: family parsed");
  Expect(!mb.tags.empty(), "malwarebazaar: tags parsed");

  const std::string vtClean =
      R"({"data":{"attributes":{"last_analysis_stats":{"malicious":0,"harmless":62,"suspicious":0,"undetected":11}}}})";
  auto vt = antimal::ParseVirusTotalResponse(vtClean);
  Expect(!vt.known, "virustotal: clean known=false");
  Expect(vt.totalScanners == 73, "virustotal: scanner total");

  const std::string vtBad =
      R"({"data":{"attributes":{"last_analysis_stats":{"malicious":35,"harmless":2,"suspicious":3,"undetected":30},"popular_threat_classification":{"suggested_threat_label":"trojan.formbook"}}}})";
  auto vt2 = antimal::ParseVirusTotalResponse(vtBad);
  Expect(vt2.known, "virustotal: malicious known=true");
  Expect(vt2.detectionRatio == 35, "virustotal: detections");
  Expect(vt2.family == "trojan.formbook", "virustotal: label parsed");
}

void TestHttpUrlEncode() {
  Expect(antimal::UrlEncode("a b/c") == "a%20b%2Fc", "url encode space + slash");
  Expect(antimal::UrlEncode("simple") == "simple", "url encode passthrough");
}

void TestScreenshotCaptureBestEffort() {
  // GDI+ requires a window station + desktop; some CI environments don't have
  // one. Treat capture failure as a skip, not a test failure.
  const auto path = TempRoot() / "screenshot.png";
  const bool ok = antimal::CaptureScreenToPng(path);
  if (!ok) {
    std::cout << "SKIP: screen capture unavailable in this environment\n";
    return;
  }
  std::error_code ec;
  Expect(std::filesystem::exists(path, ec), "screenshot: file written");
  Expect(std::filesystem::file_size(path, ec) > 100,
         "screenshot: non-trivial size");
}

void TestOrchestratorPreflight() {
  const auto root = TempRoot();
  antimal::AppConfig config;
  config.workspaceRoot = root;
  config.baseVhdxPath = root / "missing.vhdx";
  config.baseDiskPath = root / "missing.raw";
  antimal::HyperVOrchestrator orchestrator(config);
  const auto preflight = orchestrator.Preflight();
  Expect(!preflight.baseVhdxPresent, "missing base vhdx detected");
  Expect(!preflight.baseDiskPresent, "missing raw base disk detected");
  Expect(!preflight.dynamicExecutionEnabled, "dynamic execution defaults off");
  Expect(!preflight.safeToExecute, "preflight safety gate remains closed");

  const auto sample = root / "sample.bin";
  antimal::WriteTextFile(sample, "hello");
  const auto result =
      orchestrator.PrepareAndRun(sample, 1, antimal::NetworkMode::Disabled, false);
  Expect(std::filesystem::exists(result.jobPath), "job.json written");
  Expect(std::filesystem::exists(result.journalPath), "events.jsonl written");
  Expect(std::filesystem::exists(result.screenshotsDir), "screenshots dir created");
  Expect(std::filesystem::exists(result.reportPath), "failure report written");
  const auto report = antimal::LoadReportBestEffort(result.reportPath);
  Expect(!report.events.empty(), "orchestrator report: staged events preserved");
  Expect(!report.errors.empty(), "orchestrator report: readiness errors preserved");
  Expect(result.status == "blocked" || result.status == "staged",
         "orchestrator result: explicit status");
}

void TestOrchestratorPreflightRequiresRawBase() {
  const auto root = TempRoot();
  const auto fakeVhdx = root / "AntiMalBase.vhdx";
  antimal::WriteTextFile(fakeVhdx, "not a real vhdx; preflight only checks presence");

  antimal::AppConfig config;
  config.workspaceRoot = root;
  config.baseVhdxPath = fakeVhdx;
  config.baseDiskPath = root / "missing.raw";
  config.baseDiskFormat = "raw";
  antimal::HyperVOrchestrator orchestrator(config);
  const auto preflight = orchestrator.Preflight();
  Expect(preflight.baseVhdxPresent, "preflight: vhdx presence detected");
  Expect(!preflight.baseVhdxReadable, "preflight: invalid vhdx rejected");
  Expect(!preflight.rawBaseReady, "preflight: raw base required");
  Expect(preflight.vhdxConversionRequired,
         "preflight: conversion/import still required for invalid vhdx");
  Expect(!preflight.storageBootReady,
         "preflight: storage boot not ready without readable base");
  Expect(!preflight.bootCapabilityReady,
         "preflight: boot capability blocked without readable base");
}

void TestVhdxBlockDeviceReadLocalBase() {
  const std::filesystem::path base = L"C:\\AntiMalRuns\\_base\\AntiMalBase.vhdx";
  if (!std::filesystem::exists(base)) {
    std::cout << "SKIP: local base VHDX not found for direct VHDX read test at "
              << antimal::PathToUtf8(base) << "\n";
    return;
  }

  try {
    auto disk = antimal::hv::VhdxBlockDevice::Open(base);
    Expect(disk.SectorCount() > 0, "vhdx block: sector count populated");
    std::array<uint8_t, antimal::hv::IBlockDevice::kSectorSize> sector{};
    Expect(disk.ReadSectors(0, 1, sector.data()),
           "vhdx block: first sector read");
  } catch (const std::exception &ex) {
    ++g_failed;
    std::cerr << "FAIL: VHDX block reader threw: " << ex.what() << "\n";
  }
}

void TestVhdxToRawConversionSkipWhenRawExists() {
  const std::filesystem::path base = L"C:\\AntiMalRuns\\_base\\AntiMalBase.vhdx";
  if (!std::filesystem::exists(base)) {
    std::cout << "SKIP: local base VHDX not found for conversion test at "
              << antimal::PathToUtf8(base) << "\n";
    return;
  }
  const auto root = TempRoot();
  const auto raw = root / "AntiMalBase.raw";
  antimal::WriteTextFile(raw, "existing raw placeholder");

  const auto result = antimal::ConvertVhdxToRaw(base, raw, false);
  Expect(result.skipped, "vhdx conversion: skip existing raw without force");
  Expect(result.errors.empty(), "vhdx conversion: skip has no errors");
}

void TestOrchestratorBootAttemptDoesNotExecuteSample() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }
  const auto blobPath = FindFirmwareBlob();
  if (!std::filesystem::exists(blobPath)) {
    std::cout << "SKIP: " << blobPath.string() << " not present\n";
    return;
  }

  const auto root = TempRoot();
  const auto baseRaw = root / "AntiMalBase.raw";
  {
    auto base = antimal::hv::RawFileBlockDevice::Create(baseRaw, 4096);
    Expect(base.Flush(), "boot attempt: base raw flush");
  }

  antimal::AppConfig config;
  config.workspaceRoot = root;
  config.baseDiskPath = baseRaw;
  config.baseDiskFormat = "raw";
  config.baseVhdxPath.clear();
  config.networkMode = antimal::NetworkMode::Disabled;
  config.dynamicExecutionEnabled = false;
  antimal::HyperVOrchestrator orchestrator(config);

  const auto sample = root / "benign.txt";
  antimal::WriteTextFile(sample, "benign boot-attempt check");
  const auto result =
      orchestrator.PrepareAndRun(sample, 1, antimal::NetworkMode::Disabled, true);

  Expect(std::filesystem::exists(result.overlayDiskPath),
         "boot attempt: raw overlay exists");
  Expect(std::filesystem::exists(result.runDir / "vm-summary.json"),
         "boot attempt: vm summary written");
  Expect(std::filesystem::exists(result.runDir / "serial.log"),
         "boot attempt: serial log written");
  const auto report = antimal::LoadReportBestEffort(result.reportPath);
  Expect(report.dynamicSummary.started, "boot attempt: dynamic summary started");
  Expect(!report.dynamicSummary.sampleExecuted,
         "boot attempt: sample execution remains gated");
  Expect(report.dynamicSummary.ideCommandsIssued > 0,
         "boot attempt: IDE was exercised by firmware");
  bool sawBootEvent = false;
  for (const auto &event : report.events) {
    if (event.action == "vm.boot.completed" ||
        event.action == "vm.boot.incomplete" ||
        event.action == "vm.boot.failed") {
      sawBootEvent = true;
    }
  }
  Expect(sawBootEvent, "boot attempt: boot event journaled");
}

void TestOrchestratorCreatesDifferencingOverlay() {
  const std::filesystem::path base = L"C:\\AntiMalRuns\\_base\\AntiMalBase.vhdx";
  if (!std::filesystem::exists(base)) {
    std::cout << "SKIP: base VHDX not found for overlay test at "
              << antimal::PathToUtf8(base) << "\n";
    return;
  }

  const auto root = TempRoot();
  antimal::AppConfig config;
  config.workspaceRoot = root;
  config.baseVhdxPath = base;
  antimal::HyperVOrchestrator orchestrator(config);

  const auto sample = root / "benign.txt";
  antimal::WriteTextFile(sample, "benign overlay staging check");
  const auto result =
      orchestrator.PrepareAndRun(sample, 5, antimal::NetworkMode::Disabled, false);

  Expect(std::filesystem::exists(result.overlayDiskPath),
         "orchestrator: per-run differencing overlay created");
  Expect(std::filesystem::file_size(result.overlayDiskPath) > 0,
         "orchestrator: overlay has nonzero size");
  auto report = antimal::LoadReportBestEffort(result.reportPath);
  bool sawOverlayEvent = false;
  for (const auto &event : report.events) {
    if (event.action == "overlay.created") {
      sawOverlayEvent = true;
    }
  }
  Expect(sawOverlayEvent, "orchestrator: overlay creation journaled");
}

void TestOrchestratorCreatesRawCowOverlay() {
  const auto root = TempRoot();
  const auto baseRaw = root / "AntiMalBase.raw";
  {
    auto base = antimal::hv::RawFileBlockDevice::Create(baseRaw, 4);
    Expect(base.Flush(), "orchestrator raw overlay: base flush");
  }

  antimal::AppConfig config;
  config.workspaceRoot = root;
  config.baseDiskPath = baseRaw;
  config.baseDiskFormat = "raw";
  config.baseVhdxPath.clear();
  antimal::HyperVOrchestrator orchestrator(config);

  const auto sample = root / "benign.txt";
  antimal::WriteTextFile(sample, "benign raw overlay staging check");
  const auto result =
      orchestrator.PrepareAndRun(sample, 5, antimal::NetworkMode::Disabled, false);

  Expect(result.overlayDiskPath.extension() == L".raw",
         "orchestrator raw overlay: raw extension");
  Expect(std::filesystem::exists(result.overlayDiskPath),
         "orchestrator raw overlay: overlay exists");
  auto cow = antimal::hv::CowRawBlockDevice::Open(baseRaw, result.overlayDiskPath);
  Expect(cow.SectorCount() == 4, "orchestrator raw overlay: opens as COW disk");
}

} // namespace

int main() {
  try {
    TestHashEntropyJson();
    TestConfig();
    TestLocalBaseVhdxInfo();
    TestVirtualDiskDifferencingOverlay();
    TestMemoryBlockDeviceReadWrite();
    TestRawFileBlockDeviceReadWrite();
    TestCowRawBlockDeviceOverlay();
    TestJobMediaBlockDevice();
    TestHostSerialChannelFrames();
    TestCom2UartFrames();
    TestPs2QueuedInput();
    TestAcpiTables();
    TestPcIoPmSleepByteWrites();
    TestPcIoFwCfgAcpiFiles();
    TestPcIoFwCfgE820MemoryInventory();
    TestBochsVbeDataPortAliases();
    TestHpetMmioCounter();
    TestIdeIdentifyDevice();
    TestIdeReadWriteSectors();
    TestIdeSecondaryNoDeviceStatus();
    TestIdeAssertsInterrupt();
    TestPcIoPicVectorBaseTracking();
    TestIoApicProgramRedirection();
    TestMmioBusRouting();
    TestPeParser();
    TestBrowserRisk();
    TestStringExtraction();
    TestIocMining();
    TestTagger();
    TestSubprocessEcho();
    TestSubprocessToolMissing();
    TestEventJournalRoundtrip();
    TestReportRoundtripAndFramePaths();
    TestIntelLookupOffline();
    TestHttpUrlEncode();
    TestScreenshotCaptureBestEffort();
    TestWhpHelloPartition();
    TestWhpMmioReadOnlyTrapsOnWrite();
    TestWhpSerialConsole();
    TestWhpFirmwareMapping();
    TestWhpOvmfBoot();
    TestWhpOvmfBootWithIdeDisk();
    TestOrchestratorPreflight();
    TestOrchestratorPreflightRequiresRawBase();
    TestVhdxBlockDeviceReadLocalBase();
    TestVhdxToRawConversionSkipWhenRawExists();
    TestOrchestratorBootAttemptDoesNotExecuteSample();
    TestOrchestratorCreatesDifferencingOverlay();
    TestOrchestratorCreatesRawCowOverlay();

    if (g_failed) {
      std::cerr << g_failed << " test(s) failed.\n";
      return 1;
    }
    std::cout << "All AntiMal tests passed.\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "Unhandled test error: " << ex.what() << "\n";
    return 1;
  }
}
