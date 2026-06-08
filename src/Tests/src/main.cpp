#include <stdexcept>
#include "antimal/BridgeRouter.h"
#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/Crypto.h"
#include "antimal/DetonationProtocol.h"
#include "antimal/EventJournal.h"
#include "antimal/ExternalTools.h"
#include "antimal/FileSystemTelemetry.h"
#include "antimal/FileUtil.h"
#include "antimal/Http.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/IntelLookup.h"
#include "antimal/Json.h"
#include "antimal/JsonValue.h"
#include "antimal/NetworkTelemetry.h"
#include "antimal/PacketInspector.h"
#include "antimal/PeParser.h"
#include "antimal/RegistryTelemetry.h"
#include "antimal/ProcessTelemetry.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/Screenshot.h"
#include "antimal/Strings.h"
#include "antimal/Subprocess.h"
#include "antimal/Tagger.h"
#include "antimal/hv/AcpiTables.h"
#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/BochsVbe.h"
#include "antimal/hv/E1000Device.h"
#include "antimal/hv/Firmware.h"
#include "antimal/hv/GuestMemory.h"
#include "antimal/hv/Hpet.h"
#include "antimal/hv/HostSerialChannel.h"
#include "antimal/hv/IoApic.h"
#include "antimal/hv/IoBus.h"
#include "antimal/hv/KdPipeBridge.h"
#include "antimal/hv/KdSerialDebugger.h"
#include "antimal/hv/LiveFrameShm.h"
#include "antimal/hv/LiveInputProtocol.h"
#include "antimal/hv/MmioBus.h"
#include "antimal/hv/MmioEmulator.h"
#include "antimal/hv/PcIoDevices.h"
#include "antimal/hv/SerialConsole.h"
#include "antimal/hv/AhciController.h"
#include "antimal/hv/StorageController.h"
#include "antimal/hv/Tpm2CrbDevice.h"
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

  // A config written with a UTF-8 BOM (PowerShell 5.1 `Set-Content -Encoding UTF8`,
  // and the project's own Write-AntiMalConfig, prepend one) must still parse: the
  // loader strips a leading BOM, else the first key (base_vhdx_path) silently fails
  // to match and the base path comes back empty -> "no readable base VHDX".
  const auto bomPath = root / "antimal-bom.toml";
  antimal::WriteTextFile(bomPath, "\xEF\xBB\xBF" + antimal::SerializeConfig(config));
  const auto loadedBom = antimal::LoadConfig(bomPath);
  Expect(loadedBom.baseVhdxPath == config.baseVhdxPath,
         "config base vhdx parses despite a leading UTF-8 BOM");
  Expect(loadedBom.workspaceRoot == config.workspaceRoot,
         "config workspace parses despite a leading UTF-8 BOM");
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

void TestProcessTelemetryDiff() {
  using antimal::ProcessInfo;
  using antimal::ProcessSnapshot;

  ProcessSnapshot t0;
  t0[4] = ProcessInfo{0, "System"};
  t0[100] = ProcessInfo{4, "smss.exe"};
  t0[200] = ProcessInfo{100, "explorer.exe"};

  // First snapshot: emit a baseline of everything currently running.
  auto baseline = antimal::DiffProcessSnapshots({}, t0, true, 64, 64);
  Expect(baseline.size() == 3, "proc telemetry: baseline emits all running");
  Expect(baseline[0].category == "process" && baseline[0].source == "GuestAgent",
         "proc telemetry: baseline event shape");
  Expect(baseline[0].action == "process.running",
         "proc telemetry: baseline action");

  // Baseline cap is honored.
  auto capped = antimal::DiffProcessSnapshots({}, t0, true, 2, 64);
  Expect(capped.size() == 2, "proc telemetry: baseline cap honored");

  // Delta: one new process appears, one exits.
  ProcessSnapshot t1 = t0;
  t1.erase(100);                          // smss.exe exited
  t1[300] = ProcessInfo{200, "malware.exe"}; // new child of explorer
  auto delta = antimal::DiffProcessSnapshots(t0, t1, false, 64, 64);
  Expect(delta.size() == 2, "proc telemetry: delta emits start+stop only");
  bool sawStart = false, sawStop = false;
  for (const auto &ev : delta) {
    if (ev.action == "process.start" && ev.processId == 300) {
      sawStart = true;
      Expect(ev.parentProcessId == 200, "proc telemetry: start ppid carried");
      Expect(ev.imagePath == "malware.exe", "proc telemetry: start image carried");
    }
    if (ev.action == "process.stop" && ev.processId == 100) {
      sawStop = true;
    }
  }
  Expect(sawStart, "proc telemetry: new process -> process.start");
  Expect(sawStop, "proc telemetry: exited process -> process.stop");

  // No change between snapshots -> no events.
  auto stable = antimal::DiffProcessSnapshots(t0, t0, false, 64, 64);
  Expect(stable.empty(), "proc telemetry: unchanged table -> no events");

  // Start cap limits process.start volume even with many new processes.
  ProcessSnapshot many = t0;
  for (uint32_t pid = 1000; pid < 1010; ++pid) {
    many[pid] = ProcessInfo{200, "x.exe"};
  }
  auto deltaCapped = antimal::DiffProcessSnapshots(t0, many, false, 64, 3);
  size_t starts = 0;
  for (const auto &ev : deltaCapped) {
    if (ev.action == "process.start") {
      ++starts;
    }
  }
  Expect(starts == 3, "proc telemetry: delta start cap honored");
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

// The THR-empty (transmit) interrupt must be EDGE-triggered: asserted on
// ETBEI-enable / THR-write, cleared on IIR read. A level model (always pending
// while ETBEI set, since THR is perpetually empty) wedged a real boot in
// serial.sys with 111M IRQ deliveries. This test pins the edge semantics so the
// storm cannot regress while still delivering the interrupt serial.sys needs to
// transmit at all.
void TestSerialThreInterruptIsEdgeTriggered() {
  using SC = antimal::hv::SerialConsole;
  const uint16_t base = SC::kCom1Base;
  SC com(base);
  Expect(!com.InterruptPending(), "THRE: idle at reset");

  // Enabling ETBEI (IER bit 1) asserts a THRE edge (THR is empty).
  com.OnWrite(base + 1, 0x02, 1);
  Expect(com.InterruptPending(), "THRE: pending after ETBEI enable");
  // IIR reports transmitter-empty (0x02) AND reading it clears the edge.
  Expect((com.OnRead(base + 2, 1) & 0x0Fu) == 0x02u, "THRE: IIR reports 0x02");
  Expect(!com.InterruptPending(),
         "THRE: cleared after IIR read (no storm)");
  Expect((com.OnRead(base + 2, 1) & 0x0Fu) == 0x01u,
         "THRE: IIR reports no-interrupt once drained");

  // A THR write re-arms the edge so serial.sys is driven byte-by-byte.
  com.OnWrite(base + 0, 'X', 1);
  Expect(com.InterruptPending(), "THRE: re-armed after THR write");
  Expect((com.OnRead(base + 2, 1) & 0x0Fu) == 0x02u, "THRE: 0x02 after THR write");
  Expect(!com.InterruptPending(), "THRE: cleared again");

  // Disabling ETBEI deasserts entirely.
  com.OnWrite(base + 0, 'Y', 1); // re-arm
  com.OnWrite(base + 1, 0x00, 1); // disable ETBEI
  Expect(!com.InterruptPending(), "THRE: gone after ETBEI disabled");

  // RX remains level: it stays pending after an IIR read until the FIFO drains,
  // and outranks THRE in the IIR.
  com.OnWrite(base + 1, 0x03, 1); // RX-available + ETBEI both enabled
  com.QueueRxByte(0x5A);
  Expect((com.OnRead(base + 2, 1) & 0x0Fu) == 0x04u, "THRE: RX (0x04) outranks THRE");
  Expect(com.InterruptPending(), "THRE: RX still pending after IIR read (level)");
}

// Regression for the detonation "intermittent delivery" failure: the host queues
// a host->guest payload (a JobStart + the sample as SampleChunk frames) into the
// COM2 RX deque before the guest opens COM2. serial.sys writes FCR with the
// RX-FIFO-reset bit (bit 1) during driver init -- that must NOT flush the queued
// delivery backlog (it models the 16-byte hardware FIFO on real hardware, not our
// multi-KB delivery deque), or an in-flight authorized sample is silently dropped.
void TestSerialRxFifoResetPreservesBacklog() {
  using SC = antimal::hv::SerialConsole;
  const uint16_t base = SC::kCom2Base;
  SC com(base);
  const std::vector<uint8_t> payload = {0x41, 0x4D, 0x43, 0x48, 0x01, 0x02, 0x03};
  com.QueueRxBytes(payload);
  Expect(com.RxQueuedBytes() == payload.size(), "RX reset: backlog queued");

  com.OnWrite(base + 2, 0x02, 1); // FCR write with RX-FIFO-reset (bit 1)
  Expect(com.RxQueuedBytes() == payload.size(),
         "RX reset: FCR FIFO-reset preserves the host->guest backlog");
  Expect(com.Stats().rxFifoResetRequests == 1,
         "RX reset: the reset request is still recorded");
  Expect(com.Stats().rxBytesCleared == 0, "RX reset: nothing was cleared");

  for (size_t i = 0; i < payload.size(); ++i) {
    Expect((com.OnRead(base + 5, 1) & 0x01u) != 0, "RX reset: data-ready stays set");
    Expect(static_cast<uint8_t>(com.OnRead(base, 1) & 0xFFu) == payload[i],
           "RX reset: every byte survives, in order");
  }
}

void TestKdSerialDebuggerPackets() {
  using Kd = antimal::hv::KdSerialDebugger;
  Kd kd;
  const auto first = Kd::EncodeDebugPrintPacket(
      "KD hello\n", Kd::kInitialPacketId | Kd::kSyncPacketId);
  kd.PushBytes(reinterpret_cast<const uint8_t *>("noise"), 5);
  kd.PushBytes(first.data(), 8);
  Expect(kd.Summary().packetsReceived == 0,
         "KD serial: split packet waits for full frame");
  kd.PushBytes(first.data() + 8, first.size() - 8);
  Expect(kd.Summary().noiseBytes == 5, "KD serial: noise skipped");
  Expect(kd.Summary().packetsReceived == 1,
         "KD serial: complete packet decoded");
  Expect(kd.Summary().debugPrintPackets == 1,
         "KD serial: debug print decoded");
  Expect(kd.Transcript().find("KD hello") != std::string::npos,
         "KD serial: transcript captures debug text");
  auto replies = kd.PullReplies();
  Expect(replies.size() >= 16, "KD serial: ACK queued");
  Expect(replies[0] == 0x69 && replies[4] == Kd::kPacketTypeAcknowledge,
         "KD serial: ACK control packet shape");

  const auto second =
      Kd::EncodeDebugPrintPacket("again", Kd::kInitialPacketId ^ 1u);
  kd.PushBytes(second.data(), second.size());
  Expect(kd.Summary().duplicatePacketIds == 0,
         "KD serial: expected packet ID toggles");
  (void)kd.PullReplies();

  auto bad = Kd::EncodeDebugPrintPacket("bad", Kd::kInitialPacketId);
  bad[16] ^= 0x5Au;
  kd.PushBytes(bad.data(), bad.size());
  replies = kd.PullReplies();
  Expect(kd.Summary().checksumFailures == 1,
         "KD serial: bad checksum rejected");
  Expect(!replies.empty() && replies[4] == Kd::kPacketTypeResend,
         "KD serial: bad checksum asks for resend");

  auto missingTrailing =
      Kd::EncodeDebugPrintPacket("trail", Kd::kInitialPacketId);
  missingTrailing.pop_back();
  kd.PushBytes(missingTrailing.data(), missingTrailing.size());
  Expect(kd.Summary().trailingByteFailures == 0,
         "KD serial: missing trailing byte waits");
  const uint8_t wrongTrailing = 0;
  kd.PushBytes(&wrongTrailing, 1);
  Expect(kd.Summary().trailingByteFailures == 1,
         "KD serial: wrong trailing byte rejected");

  const auto reset = Kd::EncodeControlPacket(Kd::kPacketTypeReset, 0);
  kd.PushBytes(reset.data(), reset.size());
  Expect(kd.Summary().resetPacketsReceived == 1,
         "KD serial: reset control decoded");
  Expect(kd.Summary().resetPacketsSent == 1,
         "KD serial: reset control echoed");
  (void)kd.PullReplies();
  kd.QueueHostReset("unit-test host reset probe");
  replies = kd.PullReplies();
  Expect(kd.Summary().resetPacketsSent == 2 && replies.size() == 16,
         "KD serial: host reset probe queued");
  Expect(kd.PacketsJsonl().find("host-reset") != std::string::npos,
         "KD serial: host reset probe logged");
}

void TestKdSerialDebuggerStatePackets() {
  using Kd = antimal::hv::KdSerialDebugger;
  Kd kd;
  const auto exception = Kd::EncodeStateChange64Packet(
      Kd::kDbgKdExceptionStateChange, 0x80000003u, "",
      Kd::kInitialPacketId | Kd::kSyncPacketId);
  kd.PushBytes(exception.data(), exception.size());
  Expect(kd.Summary().stateChangePackets == 1,
         "KD serial: state change decoded");
  Expect(kd.Summary().statusPackets == 1,
         "KD serial: exception status captured");
  Expect(kd.Summary().lastStatus == 0x80000003u,
         "KD serial: breakpoint status preserved");
  Expect(kd.Summary().autoContinuesSent == 1,
         "KD serial: exception auto-continue queued");
  Expect(kd.PacketsJsonl().find("auto-continue") != std::string::npos,
         "KD serial: auto-continue logged");

  auto replies = kd.PullReplies();
  Expect(replies.size() > 16, "KD serial: ACK plus continue queued");
  const auto ack = Kd::EncodeControlPacket(Kd::kPacketTypeAcknowledge,
                                           Kd::kInitialPacketId);
  kd.PushBytes(ack.data(), ack.size());
  Expect(kd.Summary().targetAcksReceived == 1,
         "KD serial: target ACK decoded");

  const auto load = Kd::EncodeStateChange64Packet(
      Kd::kDbgKdLoadSymbolsStateChange, 0x12000u,
      "\\Windows\\System32\\ntoskrnl.exe", Kd::kInitialPacketId ^ 1u);
  kd.PushBytes(load.data(), load.size());
  Expect(kd.Summary().loadSymbolPackets == 1,
         "KD serial: load-symbol state decoded");
  Expect(kd.PacketsJsonl().find("ntoskrnl.exe") != std::string::npos,
         "KD serial: load-symbol path logged");
}

void TestKdSerialDebuggerCom1Integration() {
  using Kd = antimal::hv::KdSerialDebugger;
  antimal::hv::SerialConsole com1;
  Kd kd;
  com1.OnWrite(antimal::hv::SerialConsole::kCom1Base + 1, 0x01, 1);
  const auto packet = Kd::EncodeDebugPrintPacket(
      "COM1 KD", Kd::kInitialPacketId | Kd::kSyncPacketId);
  for (uint8_t byte : packet) {
    com1.OnWrite(antimal::hv::SerialConsole::kCom1Base, byte, 1);
  }
  const auto guestTx = com1.PullNew();
  kd.PushBytes(guestTx);
  const auto replies = kd.PullReplies();
  com1.QueueRxBytes(replies);
  Expect(com1.InterruptPending(),
         "KD serial COM1: ACK bytes raise RX interrupt when enabled");
  Expect((com1.OnRead(antimal::hv::SerialConsole::kCom1Base + 5, 1) &
          0x01u) != 0,
         "KD serial COM1: ACK byte visible in UART LSR");
  Expect((com1.OnRead(antimal::hv::SerialConsole::kCom1Base, 1) & 0xFFu) ==
             0x69u,
         "KD serial COM1: ACK leader queued into RX FIFO");
  Expect(com1.Captured() == guestTx,
         "KD serial COM1: normal TX capture remains intact");
  const auto stats = com1.Stats();
  Expect(stats.ierWrites == 1, "KD serial COM1: IER write counted");
  Expect(stats.dataWrites == packet.size(),
         "KD serial COM1: guest TX byte writes counted");
  Expect(stats.lsrReads == 1, "KD serial COM1: LSR read counted");
  Expect(stats.dataReads == 1, "KD serial COM1: host RX read counted");
  Expect(stats.rxBytesQueued == replies.size(),
         "KD serial COM1: queued RX bytes counted");
  Expect(stats.rxBytesRead == 1, "KD serial COM1: RX drain counted");
}

// Exercises the production "real VM display" IPC contract end to end WITHOUT a
// VM: the host publisher (antimal::hv::LiveFrameShmPublisher) writes a frame into
// a named shared section; an independent READ-ONLY reader -- the same role the UI
// process plays -- maps it and walks the seqlock the way WebViewHost does. Locks
// the wire layout (magic/version/dims/format/byteLength), the BGRX pixel
// round-trip, the read-only mapping (UI must not be able to write the VM's
// framebuffer), and the seqlock tear-detection invariant.
void TestLiveFrameShmContract() {
  // The reader's view of the header must match the publisher's byte-for-byte.
  // This mirrors the struct in App/src/WebViewHost.cpp; if either drifts, the
  // field-offset asserts below fail.
  struct ReaderHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t format;
    uint32_t byteLength;
    uint32_t reserved;
    volatile uint64_t frameSeq;
  };
  using Pub = antimal::hv::LiveFrameShmPublisher;
  Expect(sizeof(ReaderHeader) == sizeof(Pub::Header),
         "live-frame reader/writer header sizes agree");

  // An empty name is the "no live display requested" path -> not Valid, no crash.
  {
    Pub none(L"");
    Expect(!none.Valid(), "empty shm name yields an inert publisher");
  }

  const std::wstring name =
      L"Local\\AntiMalTestFrame-" +
      std::wstring(antimal::Utf8ToWide(antimal::MakeRunId()));
  Pub pub(name);
  Expect(pub.Valid(), "named live-frame publisher maps its section");
  if (!pub.Valid()) {
    return;
  }

  // A 4x2 BGRX frame with distinct, asymmetric pixels so a width/height swap or a
  // channel-order mistake is caught. Memory order per pixel is B,G,R,X.
  const uint32_t w = 4, h = 2;
  std::vector<uint8_t> src(static_cast<size_t>(w) * h * 4);
  for (uint32_t i = 0; i < w * h; ++i) {
    src[i * 4 + 0] = static_cast<uint8_t>(0x10 + i); // B
    src[i * 4 + 1] = static_cast<uint8_t>(0x40 + i); // G
    src[i * 4 + 2] = static_cast<uint8_t>(0x80 + i); // R
    src[i * 4 + 3] = 0xFF;                           // X
  }
  pub.Publish(src.data(), w, h, 32);

  // Reader side: open the SAME section read-only (FILE_MAP_READ), exactly as the
  // sandboxed UI process does -- it must never be able to write guest pixels.
  HANDLE rh = OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str());
  Expect(rh != nullptr, "reader opens the live-frame section read-only");
  if (!rh) {
    return;
  }
  const size_t mapBytes = Pub::kHeaderBytes + Pub::kMaxPixelBytes;
  auto *base = static_cast<const uint8_t *>(
      MapViewOfFile(rh, FILE_MAP_READ, 0, 0, mapBytes));
  Expect(base != nullptr, "reader maps a view of the live-frame section");
  if (base) {
    const auto *hdr = reinterpret_cast<const ReaderHeader *>(base);
    Expect(hdr->magic == Pub::kMagic, "frame magic is 'AMLF'");
    Expect(hdr->version == 1, "frame version is 1");
    Expect(hdr->width == w && hdr->height == h, "frame dims survive the round-trip");
    Expect(hdr->bpp == 32, "frame is 32bpp");
    Expect(hdr->format == 0, "frame format is BGRX (0)");
    Expect(hdr->byteLength == w * h * 4, "frame byteLength matches w*h*4");
    Expect(hdr->frameSeq == 1, "first publish bumps frameSeq to 1");

    // Seqlock read: latch seq, copy pixels, re-check. A stable seq == untorn.
    const uint64_t seqBefore = hdr->frameSeq;
    const uint8_t *px = base + Pub::kHeaderBytes;
    bool pixelsMatch = true;
    for (size_t i = 0; i < src.size(); ++i) {
      if (px[i] != src[i]) {
        pixelsMatch = false;
        break;
      }
    }
    Expect(pixelsMatch, "BGRX pixels survive the shared-memory round-trip");
    Expect(hdr->frameSeq == seqBefore, "seqlock stable across an untorn read");

    // A second publish must advance the seqlock (so a poller can tell frames
    // apart and the UI only repaints on genuinely new content).
    src[0] = 0x99;
    pub.Publish(src.data(), w, h, 32);
    Expect(hdr->frameSeq == 2, "second publish advances frameSeq to 2");
    Expect((base + Pub::kHeaderBytes)[0] == 0x99, "new pixel content is visible");

    UnmapViewOfFile(base);
  }
  CloseHandle(rh);
}

// Locks the host->guest live-input wire format (the framed 'K'/'M' keyboard +
// mouse protocol the UI appends to _live-input.bin and the VM run loop tails).
// The subtle, easy-to-break parts are split records across polls and resync on
// garbage -- exactly what makes the live VM feel interactive, and exactly what
// can't be exercised without a boot unless the parser is pulled out. Mirrors the
// run loop: a persistent remainder buffer fed in chunks.
void TestLiveInputProtocol() {
  using antimal::hv::LiveInputEvent;
  using antimal::hv::ParseLiveInput;

  // A clean keyboard record then a clean mouse record, all bytes present.
  {
    std::vector<uint8_t> buf = {'K', 3, 0x1E, 0x9E, 0x1C,         // 3 scancodes
                                'M', 0x01, static_cast<uint8_t>(-4),
                                static_cast<uint8_t>(7)};         // btn,dx,dy
    std::vector<LiveInputEvent> ev;
    ParseLiveInput(buf, ev);
    Expect(ev.size() == 2, "two complete records decode to two events");
    Expect(ev[0].type == LiveInputEvent::Type::Keyboard &&
               ev[0].scancodes.size() == 3 && ev[0].scancodes[1] == 0x9E,
           "keyboard record carries its scancodes verbatim");
    Expect(ev[1].type == LiveInputEvent::Type::Mouse && ev[1].buttons == 0x01 &&
               ev[1].dx == -4 && ev[1].dy == 7,
           "mouse record carries signed dx/dy + buttons");
    Expect(buf.empty(), "fully-consumed buffer is drained");
  }

  // A record split across two polls must stay buffered until it completes -- no
  // event, no bytes lost.
  {
    std::vector<uint8_t> buf = {'K', 3, 0x1E}; // header says 3, only 1 present
    std::vector<LiveInputEvent> ev;
    ParseLiveInput(buf, ev);
    Expect(ev.empty(), "incomplete record yields no event");
    Expect(buf.size() == 3, "incomplete record stays fully buffered");
    // Remaining scancodes arrive on the next poll.
    buf.push_back(0x9E);
    buf.push_back(0x1C);
    ParseLiveInput(buf, ev);
    Expect(ev.size() == 1 && ev[0].scancodes.size() == 3,
           "record completes once its tail arrives");
    Expect(buf.empty(), "completed record is drained");
  }

  // A split tag/count boundary ('K' alone) must also wait.
  {
    std::vector<uint8_t> buf = {'K'};
    std::vector<LiveInputEvent> ev;
    ParseLiveInput(buf, ev);
    Expect(ev.empty() && buf.size() == 1, "lone 'K' tag waits for its count");
  }

  // Garbage bytes are skipped one at a time to resync onto the next real record.
  {
    std::vector<uint8_t> buf = {0xAB, 0xCD, 'M', 0x00, 0x05, 0x06};
    std::vector<LiveInputEvent> ev;
    ParseLiveInput(buf, ev);
    Expect(ev.size() == 1 && ev[0].type == LiveInputEvent::Type::Mouse &&
               ev[0].dx == 5 && ev[0].dy == 6,
           "parser resyncs past garbage onto the next valid record");
    Expect(buf.empty(), "garbage + record fully consumed");
  }

  // An empty 'K' record (count 0) consumes its 2 header bytes but emits nothing.
  {
    std::vector<uint8_t> buf = {'K', 0, 'M', 0x02, 0x00, 0x00};
    std::vector<LiveInputEvent> ev;
    ParseLiveInput(buf, ev);
    Expect(ev.size() == 1 && ev[0].type == LiveInputEvent::Type::Mouse &&
               ev[0].buttons == 0x02,
           "empty 'K' is consumed without an event; following record decodes");
    Expect(buf.empty(), "empty-K + mouse fully consumed");
  }
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

  ps2.OnWrite(0x60, 0xF0, 1);
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0xFAu,
         "PS/2 input: scan-code command ACKs");
  ps2.OnWrite(0x60, 0x00, 1);
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0xFAu,
         "PS/2 input: scan-code query subcommand ACKs");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0x01u,
         "PS/2 input: scan-code set reported");

  ps2.OnWrite(0x60, 0xF5, 1);
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0xFAu,
         "PS/2 input: disable scanning ACKs");
  Expect(!ps2.KeyboardScanningEnabled(),
         "PS/2 input: scanning disable tracked");
  ps2.InjectKeyboardScancode(0x1C);
  Expect(ps2.PendingIrqLine() == 0,
         "PS/2 input: disabled scanning blocks IRQ1");
  ps2.OnWrite(0x60, 0xF4, 1);
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0x1Cu,
         "PS/2 input: queued scancode can be polled while disabled");
  Expect((ps2.OnRead(0x60, 1) & 0xFFu) == 0xFAu,
         "PS/2 input: enable scanning ACK drains");
  Expect(ps2.KeyboardScanningEnabled(),
         "PS/2 input: scanning enable tracked");
  Expect(ps2.StatusReads() >= 2 && ps2.DataReads() >= 10,
         "PS/2 input: read diagnostics count port traffic");
}

uint16_t ReadLe16(const std::vector<uint8_t> &data, size_t offset) {
  if (offset + 2 > data.size()) {
    return 0;
  }
  return static_cast<uint16_t>(data[offset]) |
         static_cast<uint16_t>(data[offset + 1] << 8);
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

void PushBe16(std::vector<uint8_t> &data, uint16_t value) {
  data.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  data.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void PushBe32(std::vector<uint8_t> &data, uint32_t value) {
  data.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
  data.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
  data.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  data.push_back(static_cast<uint8_t>(value & 0xFFu));
}

std::vector<uint8_t> MakeTpmCommand(uint32_t commandCode,
                                    const std::vector<uint8_t> &body = {},
                                    uint16_t tag = 0x8001) {
  std::vector<uint8_t> command;
  PushBe16(command, tag);
  PushBe32(command, static_cast<uint32_t>(10 + body.size()));
  PushBe32(command, commandCode);
  command.insert(command.end(), body.begin(), body.end());
  return command;
}

std::vector<uint8_t> SubmitTpmCommand(antimal::hv::Tpm2CrbDevice &tpm,
                                      uint64_t base,
                                      const std::vector<uint8_t> &command) {
  tpm.OnWrite(base + 0x40, 4, 1);
  for (size_t i = 0; i < command.size(); ++i) {
    tpm.OnWrite(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset + i, 1,
                command[i]);
  }
  tpm.OnWrite(base + 0x4C, 4, 1);

  std::vector<uint8_t> response(10);
  uint64_t value = 0;
  for (size_t i = 0; i < response.size(); ++i) {
    tpm.OnRead(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset + i, 1,
               &value);
    response[i] = static_cast<uint8_t>(value & 0xFFu);
  }
  const uint32_t responseSize = ReadBe32(response, 2);
  response.resize(std::max<uint32_t>(responseSize, 10));
  for (size_t i = 10; i < response.size(); ++i) {
    tpm.OnRead(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset + i, 1,
               &value);
    response[i] = static_cast<uint8_t>(value & 0xFFu);
  }
  return response;
}

void TestTpm2CrbDevice() {
  antimal::hv::Tpm2CrbDevice tpm;
  const uint64_t base = antimal::hv::Tpm2CrbDevice::kDefaultMmioBase;
  uint64_t value = 0;

  Expect(tpm.OnRead(base + 0x30, 4, &value), "TPM2 CRB: interface ID read");
  Expect((value & 0xFu) == 1, "TPM2 CRB: interface type is CRB");
  Expect(((value >> 4) & 0xFu) == 1, "TPM2 CRB: interface version is CRB v1");
  Expect(((value >> 11) & 0x3u) == 3,
         "TPM2 CRB: data transfer size advertises 64-byte support");
  Expect(((value >> 14) & 0x1u) == 1, "TPM2 CRB: CRB capability bit set");
  Expect(((value >> 17) & 0x3u) == 1,
         "TPM2 CRB: selected interface is CRB");

  Expect(tpm.OnRead(base + 0x34, 4, &value), "TPM2 CRB: VID/DID dword read");
  Expect((value & 0xFFFFu) == 0x1AF4u, "TPM2 CRB: vendor ID");
  Expect(((value >> 16) & 0xFFFFu) == 0x0001u, "TPM2 CRB: device ID");

  tpm.OnWrite(base + 0x08, 4, 1);
  Expect(tpm.OnRead(base + 0x0C, 4, &value), "TPM2 CRB: locality status read");
  Expect((value & 1u) == 1, "TPM2 CRB: locality request is granted");

  tpm.OnWrite(base + 0x40, 4, 1);
  Expect(tpm.OnRead(base + 0x40, 4, &value), "TPM2 CRB: control request read");
  Expect((value & 1u) == 0, "TPM2 CRB: cmdReady is acknowledged");
  Expect(tpm.OnRead(base + 0x44, 4, &value), "TPM2 CRB: control status read");
  Expect((value & 2u) == 0, "TPM2 CRB: ready state clears idle bit");

  const uint8_t startup[] = {
      0x80, 0x01, 0x00, 0x00, 0x00, 0x0C,
      0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
  };
  for (size_t i = 0; i < sizeof(startup); ++i) {
    tpm.OnWrite(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset + i, 1,
                startup[i]);
  }
  tpm.OnWrite(base + 0x4C, 4, 1);
  Expect(tpm.CommandsProcessed() == 1, "TPM2 CRB: start executes command");
  Expect(tpm.LastCommandCode() == 0x00000144u,
         "TPM2 CRB: last command is TPM2_Startup");
  const auto &histogram = tpm.CommandHistogram();
  Expect(histogram.find(0x00000144u) != histogram.end() &&
             histogram.at(0x00000144u) == 1,
         "TPM2 CRB: command histogram records TPM2_Startup");
  Expect(!tpm.RecentCommands().empty() &&
             tpm.RecentCommands().back() == 0x00000144u,
         "TPM2 CRB: recent command trace records TPM2_Startup");
  Expect(tpm.OnRead(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset, 4,
                    &value),
         "TPM2 CRB: response header read");
  Expect((value & 0xFFFFu) == 0x0180u,
         "TPM2 CRB: response tag is big-endian TPM_ST_NO_SESSIONS");
  Expect(tpm.OnRead(base + antimal::hv::Tpm2CrbDevice::kDataBufferOffset + 6, 4,
                    &value),
         "TPM2 CRB: response code read");
  Expect(value == 0, "TPM2 CRB: response code is TPM_RC_SUCCESS");

  std::vector<uint8_t> capBody;
  PushBe32(capBody, 0x00000006); // TPM_CAP_TPM_PROPERTIES
  PushBe32(capBody, 0x0000011E); // TPM_PT_MAX_COMMAND_SIZE
  PushBe32(capBody, 1);
  const auto capResp =
      SubmitTpmCommand(tpm, base, MakeTpmCommand(0x0000017A, capBody));
  Expect(ReadBe16(capResp, 0) == 0x8001,
         "TPM2 CRB: GetCapability response tag");
  Expect(ReadBe32(capResp, 2) >= 27,
         "TPM2 CRB: GetCapability response has property body");
  Expect(capResp[10] == 0, "TPM2 CRB: GetCapability moreData false");
  Expect(ReadBe32(capResp, 11) == 0x00000006,
         "TPM2 CRB: GetCapability returns requested capability");
  Expect(ReadBe32(capResp, 15) == 1,
         "TPM2 CRB: GetCapability returns one TPM property");
  Expect(ReadBe32(capResp, 19) == 0x0000011E &&
             ReadBe32(capResp, 23) >= 0x80,
         "TPM2 CRB: GetCapability returns max command size");

  const auto randomResp = SubmitTpmCommand(
      tpm, base, MakeTpmCommand(0x0000017B, std::vector<uint8_t>{0x00, 0x10}));
  Expect(ReadBe16(randomResp, 10) == 16,
         "TPM2 CRB: GetRandom returns requested byte count");
  Expect(ReadBe32(randomResp, 2) == 28,
         "TPM2 CRB: GetRandom response size includes digest bytes");

  std::vector<uint8_t> extendBody;
  PushBe32(extendBody, 0); // PCR 0
  PushBe32(extendBody, 0); // empty auth session area for the stub
  PushBe32(extendBody, 1);
  PushBe16(extendBody, 0x000B); // TPM_ALG_SHA256
  extendBody.insert(extendBody.end(), 32, 0x11);
  const auto extendResp =
      SubmitTpmCommand(tpm, base,
                       MakeTpmCommand(0x00000182, extendBody, 0x8002));
  Expect(ReadBe16(extendResp, 0) == 0x8002,
         "TPM2 CRB: session command response tag is preserved");
  Expect(ReadBe32(extendResp, 10) == 0,
         "TPM2 CRB: empty session response has zero parameter size");

  std::vector<uint8_t> pcrBody;
  PushBe32(pcrBody, 1);
  PushBe16(pcrBody, 0x000B); // TPM_ALG_SHA256
  pcrBody.push_back(3);
  pcrBody.insert(pcrBody.end(), {0x01, 0x00, 0x00});
  const auto pcrResp =
      SubmitTpmCommand(tpm, base, MakeTpmCommand(0x0000017E, pcrBody));
  Expect(ReadBe32(pcrResp, 10) == 1,
         "TPM2 CRB: PCR_Read update counter follows PCR_Extend");
  Expect(ReadBe32(pcrResp, 14) == 1,
         "TPM2 CRB: PCR_Read returns one selection");
  Expect(ReadBe16(pcrResp, 18) == 0x000B && pcrResp[20] == 3 &&
             (pcrResp[21] & 0x01) != 0,
         "TPM2 CRB: PCR_Read preserves requested SHA256 PCR");
  Expect(ReadBe32(pcrResp, 24) == 1 && ReadBe16(pcrResp, 28) == 32,
         "TPM2 CRB: PCR_Read returns one SHA256 digest");
  const bool pcrDigestNonZero =
      pcrResp.size() >= 62 &&
      std::any_of(pcrResp.begin() + 30, pcrResp.begin() + 62,
                  [](uint8_t b) { return b != 0; });
  Expect(pcrDigestNonZero,
         "TPM2 CRB: PCR_Read reflects prior PCR_Extend");

  const auto clockResp =
      SubmitTpmCommand(tpm, base, MakeTpmCommand(0x00000181));
  Expect(ReadBe32(clockResp, 2) == 35 && clockResp.size() >= 35,
         "TPM2 CRB: ReadClock response has TPMS_TIME_INFO body");
  Expect(clockResp[34] == 1, "TPM2 CRB: ReadClock marks clock safe");
}

void TestAcpiTables() {
  const auto acpi = antimal::hv::BuildPcAcpiTables();
  Expect(!acpi.tables.empty(), "ACPI: table blob produced");
  if (std::getenv("ANTIMAL_DUMP_ACPI") != nullptr) {
    // Dump our built DSDT so it can be validated offline with iasl -- a malformed
    // DSDT would make the guest's acpi.sys fail to enumerate the PCI root, which
    // would leave pci.sys unable to attach pciide (INACCESSIBLE_BOOT_DEVICE 0x7B).
    const auto dOff = acpi.offsets.dsdt;
    const auto dLen = antimal::hv::AcpiTableLength(acpi.tables, dOff);
    std::ofstream of("C:\\Temp\\our-dsdt.aml",
                     std::ios::binary | std::ios::trunc);
    of.write(reinterpret_cast<const char *>(acpi.tables.data() + dOff),
             static_cast<std::streamsize>(dLen));
  }
  Expect(!acpi.tableLoader.empty(), "ACPI: table-loader produced");
  Expect(acpi.tableLoader.size() % 128 == 0,
         "ACPI: table-loader entries are 128-byte records");
  Expect(acpi.rsdp.size() == 36, "ACPI: ACPI 2.0 RSDP fw_cfg length");
  Expect(std::memcmp(acpi.rsdp.data(), "RSD PTR ", 8) == 0,
         "ACPI: RSDP signature");
  Expect(acpi.rsdp[15] == 2, "ACPI: RSDP advertises ACPI 2.0 revision");
  Expect(ReadLe32(acpi.rsdp, 20) == 36, "ACPI: RSDP length field is 36");
  Expect(ReadLe64(acpi.rsdp, 24) == acpi.offsets.xsdt,
         "ACPI: RSDP XsdtAddress points to XSDT offset");
  // Checksum bytes are left 0 at build time; the fw_cfg table-loader fills them
  // at load. (OVMF's ADD_CHECKSUM sums the byte in-place without pre-zeroing, so
  // a pre-computed non-zero checksum would make every SDT fail validation.)
  Expect(acpi.rsdp[8] == 0,
         "ACPI: RSDP legacy checksum byte left 0 for table-loader");
  Expect(acpi.rsdp[32] == 0,
         "ACPI: RSDP extended checksum byte left 0 for table-loader");

  auto tableOk = [&](uint32_t offset, const char *sig) {
    const uint32_t length = antimal::hv::AcpiTableLength(acpi.tables, offset);
    Expect(length >= 36, "ACPI: table length is plausible");
    Expect(offset + length <= acpi.tables.size(),
           "ACPI: table stays inside table blob");
    Expect(std::memcmp(acpi.tables.data() + offset, sig, 4) == 0,
           "ACPI: expected table signature");
    Expect(acpi.tables[offset + 9] == 0,
           "ACPI: table checksum byte left 0 for table-loader");
  };

  tableOk(acpi.offsets.dsdt, "DSDT");
  tableOk(acpi.offsets.fadt, "FACP");
  tableOk(acpi.offsets.madt, "APIC");
  tableOk(acpi.offsets.waet, "WAET");
  tableOk(acpi.offsets.hpet, "HPET");
  tableOk(acpi.offsets.spcr, "SPCR");
  tableOk(acpi.offsets.dbg2, "DBG2");
  tableOk(acpi.offsets.tpm2, "TPM2");
  tableOk(acpi.offsets.rsdt, "RSDT");
  tableOk(acpi.offsets.xsdt, "XSDT");
  Expect(acpi.offsets.dbgp == 0, "ACPI: DBGP is opt-in by default");

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
  Expect(acpi.tables[acpi.offsets.madt + 64] == 2,
         "ACPI: MADT first ISO entry is Interrupt Source Override type");
  Expect(acpi.tables[acpi.offsets.madt + 67] == 0,
         "ACPI: MADT ISO #1 sources ISA IRQ 0");
  Expect(ReadLe32(acpi.tables, acpi.offsets.madt + 68) == 2,
         "ACPI: MADT ISO #1 remaps PIT to GSI 2");
  Expect(acpi.tables[acpi.offsets.madt + 74] == 2,
         "ACPI: MADT second ISO entry is Interrupt Source Override type");
  Expect(acpi.tables[acpi.offsets.madt + 77] == 9,
         "ACPI: MADT ISO #2 sources ISA IRQ 9");
  Expect(ReadLe32(acpi.tables, acpi.offsets.madt + 78) == 9,
         "ACPI: MADT ISO #2 keeps SCI on GSI 9");
  Expect(acpi.tables[acpi.offsets.madt + 82] == 0x0D &&
             acpi.tables[acpi.offsets.madt + 83] == 0x00,
         "ACPI: MADT ISO #2 marks SCI active-low / level-triggered");
  Expect(ReadLe32(acpi.tables, acpi.offsets.hpet + 36) ==
             antimal::hv::HpetDevice::kEventTimerBlockId,
         "ACPI: HPET event timer block ID");
  Expect(ReadLe64(acpi.tables, acpi.offsets.hpet + 44) ==
             antimal::hv::HpetDevice::kDefaultMmioBase,
         "ACPI: HPET GAS points to MMIO base");
  Expect(acpi.tables[acpi.offsets.spcr + 36] == 0,
         "ACPI: SPCR advertises full 16550-compatible COM1");
  Expect(ReadLe64(acpi.tables, acpi.offsets.spcr + 44) == 0x03F8u,
         "ACPI: SPCR GAS points to COM1");
  Expect(acpi.tables[acpi.offsets.spcr + 52] == 0x03,
         "ACPI: SPCR advertises PIC and IOAPIC interrupt delivery");
  Expect(acpi.tables[acpi.offsets.spcr + 53] == 4,
         "ACPI: SPCR legacy IRQ is COM1 IRQ4");
  Expect(ReadLe32(acpi.tables, acpi.offsets.spcr + 54) == 4,
         "ACPI: SPCR GSI is 4");
  Expect(acpi.tables[acpi.offsets.spcr + 58] == 7,
         "ACPI: SPCR baud rate is 115200");
  Expect(ReadLe16(acpi.tables, acpi.offsets.spcr + 84) == 11 &&
             ReadLe16(acpi.tables, acpi.offsets.spcr + 86) == 88,
         "ACPI: SPCR namespace string points to COM1");
  Expect(ReadLe32(acpi.tables, acpi.offsets.dbg2 + 36) == 44 &&
             ReadLe32(acpi.tables, acpi.offsets.dbg2 + 40) == 1,
         "ACPI: DBG2 exposes one debug device");
  Expect(ReadLe16(acpi.tables, acpi.offsets.dbg2 + 56) == 0x8000 &&
             ReadLe16(acpi.tables, acpi.offsets.dbg2 + 58) == 0x0001,
         "ACPI: DBG2 debug port is serial DBGP-compatible");
  Expect(ReadLe64(acpi.tables, acpi.offsets.dbg2 + 70) == 0x03F8u,
         "ACPI: DBG2 GAS points to COM1");
  Expect(ReadLe32(acpi.tables, acpi.offsets.dbg2 + 78) == 8,
         "ACPI: DBG2 COM1 address size is eight registers");
  Expect(ReadLe64(acpi.tables, acpi.offsets.tpm2 + 40) ==
             antimal::hv::Tpm2CrbDevice::kDefaultMmioBase +
                 antimal::hv::Tpm2CrbDevice::kControlAreaOffset,
         "ACPI: TPM2 points at CRB control area");
  Expect(ReadLe32(acpi.tables, acpi.offsets.tpm2 + 48) == 7,
         "ACPI: TPM2 advertises CRB ACPI start method");
  Expect(ReadLe32(acpi.tables, acpi.offsets.rsdt + 4) == 64,
         "ACPI: RSDT includes seven default table pointers");
  Expect(ReadLe32(acpi.tables, acpi.offsets.rsdt + 52) == acpi.offsets.spcr &&
             ReadLe32(acpi.tables, acpi.offsets.rsdt + 56) == acpi.offsets.dbg2 &&
             ReadLe32(acpi.tables, acpi.offsets.rsdt + 60) == acpi.offsets.tpm2,
         "ACPI: RSDT references SPCR, DBG2, and TPM2");
  // XSDT (ACPI 2.0): seven 64-bit entries (36-byte header + 7*8).
  Expect(ReadLe32(acpi.tables, acpi.offsets.xsdt + 4) == 92,
         "ACPI: XSDT includes seven 64-bit table pointers");
  Expect(ReadLe64(acpi.tables, acpi.offsets.xsdt + 36) == acpi.offsets.fadt,
         "ACPI: XSDT first entry points to FADT");
  Expect(ReadLe64(acpi.tables, acpi.offsets.xsdt + 44) == acpi.offsets.madt,
         "ACPI: XSDT second entry points to MADT (APIC)");

  const auto acpiDbgp = antimal::hv::BuildPcAcpiTables(1, true);
  const uint32_t dbgpLen =
      antimal::hv::AcpiTableLength(acpiDbgp.tables, acpiDbgp.offsets.dbgp);
  Expect(acpiDbgp.offsets.dbgp != 0, "ACPI: DBGP probe table can be enabled");
  Expect(dbgpLen >= 36 &&
             std::memcmp(acpiDbgp.tables.data() + acpiDbgp.offsets.dbgp,
                         "DBGP", 4) == 0,
         "ACPI: DBGP probe signature");
  Expect(acpiDbgp.tables[acpiDbgp.offsets.dbgp + 9] == 0,
         "ACPI: DBGP probe checksum byte left 0 for table-loader");
  Expect(acpiDbgp.tables[acpiDbgp.offsets.dbgp + 36] == 0,
         "ACPI: DBGP probe advertises full 16550-compatible COM1");
  Expect(ReadLe64(acpiDbgp.tables, acpiDbgp.offsets.dbgp + 44) == 0x03F8u,
         "ACPI: DBGP probe GAS points to COM1");
  Expect(ReadLe32(acpiDbgp.tables, acpiDbgp.offsets.rsdt + 4) == 68,
         "ACPI: DBGP probe RSDT includes eight table pointers");
  Expect(ReadLe32(acpiDbgp.tables, acpiDbgp.offsets.rsdt + 52) ==
             acpiDbgp.offsets.dbgp &&
             ReadLe32(acpiDbgp.tables, acpiDbgp.offsets.rsdt + 56) ==
                 acpiDbgp.offsets.spcr &&
             ReadLe32(acpiDbgp.tables, acpiDbgp.offsets.rsdt + 60) ==
                 acpiDbgp.offsets.dbg2 &&
             ReadLe32(acpiDbgp.tables, acpiDbgp.offsets.rsdt + 64) ==
                 acpiDbgp.offsets.tpm2,
         "ACPI: DBGP probe RSDT references DBGP, SPCR, DBG2, and TPM2");

  const auto dsdtLen = antimal::hv::AcpiTableLength(acpi.tables, acpi.offsets.dsdt);
  const auto dsdtBegin = acpi.tables.begin() + acpi.offsets.dsdt;
  const auto dsdtEnd = dsdtBegin + dsdtLen;
  auto contains = [&](const char *needle) {
    return std::search(dsdtBegin, dsdtEnd, needle, needle + std::strlen(needle)) != dsdtEnd;
  };
  Expect(contains("_SB_"), "ACPI: DSDT exposes _SB scope");
  Expect(contains("_S5_"), "ACPI: DSDT exposes S5 shutdown package");
  Expect(contains("PCI0"), "ACPI: DSDT exposes PCI0");
  Expect(contains("_CRS"), "ACPI: DSDT exposes PCI root resources");
  Expect(contains("_PRT"), "ACPI: DSDT exposes PCI interrupt routing");
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
  Expect(!pc.LastPm1SleepEnable(),
         "PM1 control: SLP_EN auto-clears for S0 per PIIX4 contract");
  Expect(!pc.LastPm1HostStopRequested(),
         "PM1 control: S0 sleep enable is diagnostic only");
  Expect(pc.LastPm1ControlValue() == 0x0001,
         "PM1 control: S0 write keeps SCI_EN set after SLP_EN auto-clears");

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
  for (size_t i = 0; i < 4 + 6 * 64; ++i) {
    dir.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(ReadBe32(dir, 0) == 6, "fw_cfg: directory exposes six files");
  Expect(pc.FwCfgFileCount() == 6, "fw_cfg: file count includes SMBIOS files");

  bool sawE820 = false;
  bool sawAcpiTables = false;
  bool sawLoader = false;
  bool sawRsdp = false;
  bool sawSmbiosTables = false;
  bool sawSmbiosAnchor = false;
  uint16_t acpiSelector = 0;
  uint32_t acpiSize = 0;
  uint16_t smbiosTablesSelector = 0;
  uint32_t smbiosTablesSize = 0;
  uint16_t smbiosAnchorSelector = 0;
  uint32_t smbiosAnchorSize = 0;
  for (size_t entry = 0; entry < 6; ++entry) {
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
    if (name == "etc/smbios/smbios-tables") {
      sawSmbiosTables = true;
      smbiosTablesSelector = selector;
      smbiosTablesSize = size;
    }
    if (name == "etc/smbios/smbios-anchor") {
      sawSmbiosAnchor = true;
      smbiosAnchorSelector = selector;
      smbiosAnchorSize = size;
    }
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
  Expect(sawSmbiosTables, "fw_cfg: etc/smbios/smbios-tables present");
  Expect(sawSmbiosAnchor, "fw_cfg: etc/smbios/smbios-anchor present");
  Expect(acpiSelector != 0 && acpiSize > 64,
         "fw_cfg: ACPI tables selector and size plausible");
  Expect(smbiosTablesSelector != 0 && smbiosTablesSize > 64,
         "fw_cfg: SMBIOS tables selector and size plausible");
  Expect(smbiosAnchorSelector != 0 && smbiosAnchorSize == 0x1F,
         "fw_cfg: SMBIOS anchor selector and size plausible");

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

  pc.OnWrite(0x510, smbiosTablesSelector, 2);
  std::vector<uint8_t> smbiosHeader;
  for (size_t i = 0; i < 8; ++i) {
    smbiosHeader.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(smbiosHeader[0] == 0 && smbiosHeader[1] == 0x18,
         "fw_cfg: SMBIOS tables start with Type 0 BIOS record");

  pc.OnWrite(0x510, smbiosAnchorSelector, 2);
  std::vector<uint8_t> smbiosAnchor;
  for (size_t i = 0; i < smbiosAnchorSize; ++i) {
    smbiosAnchor.push_back(static_cast<uint8_t>(pc.OnRead(0x511, 1) & 0xFFu));
  }
  Expect(std::memcmp(smbiosAnchor.data(), "_SM_", 4) == 0,
         "fw_cfg: SMBIOS 2.x anchor signature");
  Expect(std::memcmp(smbiosAnchor.data() + 0x10, "_DMI_", 5) == 0,
         "fw_cfg: SMBIOS DMI anchor signature");
  Expect(smbiosAnchor[0x06] == 2 && smbiosAnchor[0x07] == 8,
         "fw_cfg: SMBIOS version is 2.8");
  Expect(ReadLe16(smbiosAnchor, 0x16) == smbiosTablesSize,
         "fw_cfg: SMBIOS anchor table length matches tables file");
  Expect(pc.FwCfgSmbiosTableBytesRead() >= smbiosHeader.size(),
         "fw_cfg: SMBIOS table byte counter updated");
  Expect(pc.FwCfgSmbiosAnchorBytesRead() >= smbiosAnchor.size(),
         "fw_cfg: SMBIOS anchor byte counter updated");
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

void TestPcIoVgaBarSizing() {
  antimal::hv::PcIoDevices pc;
  pc.SetVgaControllerPresent(true);

  // PCI config mechanism #1 address for bus 0, device 2, function 0, BAR0.
  pc.OnWrite(0xCF8, 0x80001010u, 4);
  Expect(pc.OnRead(0xCFC, 4) == 0x80000008u,
         "PCI VGA BAR: starts at AntiMal framebuffer GPA");

  pc.OnWrite(0xCFC, 0xFFFFFFFFu, 4);
  Expect(pc.VgaBar0Sizing(), "PCI VGA BAR: all-ones write enters sizing mode");
  Expect(pc.OnRead(0xCFC, 4) == 0xFF000008u,
         "PCI VGA BAR: reports 16 MiB memory aperture mask");

  pc.OnWrite(0xCFC, 0x80000000u, 4);
  Expect(!pc.VgaBar0Sizing(), "PCI VGA BAR: base write leaves sizing mode");
  Expect(pc.OnRead(0xCFC, 4) == 0x80000008u,
         "PCI VGA BAR: assigned base preserves prefetchable memory bits");
}

void TestPcIoIdePciResources() {
  antimal::hv::PcIoDevices pc;
  pc.SetIdeControllerPresent(true);

  auto select = [&](uint8_t reg) {
    pc.OnWrite(0xCF8, 0x80000900u | reg, 4); // bus 0, device 1, function 1.
  };

  select(0x00);
  Expect(pc.OnRead(0xCFC, 4) == 0x71118086u,
         "PCI IDE: exposes Intel PIIX4 IDE identifier");

  select(0x08);
  // Pure legacy compatibility-mode IDE: class 01/01, prog-if 0x00 (fixed ISA
  // ports + IRQ14/15, PIO, no bus-master BAR). Minimal conflict-free controller.
  Expect(pc.OnRead(0xCFC, 4) == 0x01010001u,
         "PCI IDE: reports compat-mode IDE storage class (prog-if 0x00)");

  // No PCI-mapped BARs at all (legacy fixed ports; no bus-master block).
  select(0x10);
  Expect(pc.OnRead(0xCFC, 4) == 0u,
         "PCI IDE: command BAR is unimplemented (compat fixed ports)");

  select(0x14);
  Expect(pc.OnRead(0xCFC, 4) == 0u,
         "PCI IDE: control BAR is unimplemented (compat fixed ports)");

  select(0x20);
  Expect(pc.OnRead(0xCFC, 4) == 0u,
         "PCI IDE: no bus-master BAR (PIO compat)");

  select(0x3C);
  Expect(pc.OnRead(0xCFC, 4) == 0x000000FFu,
         "PCI IDE: compat-mode reports no PCI INTx (pin 0, line 0xFF)");

  // PIIX4 IDE Timing register (0x40): bit 15 = primary "IDE Decode Enable".
  // intelide reads this to decide the primary channel exists and create its
  // channel PDO; without it the boot disk is never enumerated (0x7B). Default
  // 0x00008000 = primary enabled, secondary disabled (empty channel).
  select(0x40);
  Expect((pc.OnRead(0xCFC, 4) & 0x00008000u) != 0,
         "PCI IDE: IDETIM primary decode-enable set (channel enumerates)");
  Expect((pc.OnRead(0xCFC, 4) & 0x80000000u) == 0,
         "PCI IDE: IDETIM secondary decode-disable (empty channel)");

  // IDETIM is read/write so intelide's read-modify-write of the per-drive PIO
  // timing fields sticks and its decode-enable readback stays set.
  pc.OnWrite(0xCFC, 0x0000A30Fu, 4); // set some primary timing bits, keep bit15.
  Expect(pc.OnRead(0xCFC, 4) == 0x0000A30Fu,
         "PCI IDE: IDETIM register is read/write (timing fields persist)");
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

void TestPcIoAhciPciResources() {
  antimal::hv::PcIoDevices pc;
  pc.SetAhciControllerPresent(true);
  auto select = [&](uint8_t reg) {
    pc.OnWrite(0xCF8, 0x80001800u | reg, 4); // bus 0, device 3, function 0.
  };
  select(0x00);
  Expect(pc.OnRead(0xCFC, 4) == 0x29228086u,
         "PCI AHCI: exposes ICH9 AHCI identifier (8086:2922)");
  select(0x08);
  Expect(pc.OnRead(0xCFC, 4) == 0x01060102u,
         "PCI AHCI: mass storage / SATA / AHCI prog-if (01/06/01)");
  select(0x24); // BAR5 / ABAR.
  Expect((pc.OnRead(0xCFC, 4) & 0xFFFFF000u) != 0,
         "PCI AHCI: BAR5 reports an MMIO base");
  pc.OnWrite(0xCFC, 0xFFFFFFFFu, 4); // sizing probe.
  Expect(pc.OnRead(0xCFC, 4) == 0xFFFFF000u,
         "PCI AHCI: BAR5 reports a 4 KiB size mask under sizing");
  pc.OnWrite(0xCFC, 0x90000000u, 4); // assign a base.
  Expect(pc.AhciAbarBase() == 0x90000000u,
         "PCI AHCI: BAR5 assignment latches the ABAR base");
  Expect(pc.ConsumeAhciAbarDirty(),
         "PCI AHCI: BAR5 assignment flags the host to relocate ABAR");
  select(0x3C);
  Expect((pc.OnRead(0xCFC, 4) & 0x0000FF00u) == 0x00000100u,
         "PCI AHCI: reports Interrupt Pin INTA (PCI-native interrupt)");
}

void TestAhciIdentifyCommand() {
  using namespace antimal::hv;
  MemoryBlockDevice disk(4096); // 4096 sectors.
  AhciController ahci(&disk);
  // Fake guest RAM window [ramBase, ramBase+size) backing the DMA accessor.
  const uint64_t ramBase = 0x00100000;
  std::vector<uint8_t> ram(0x00020000, 0);
  ahci.SetDmaMemory([&](uint64_t gpa, std::size_t len) -> uint8_t * {
    if (gpa < ramBase || gpa + len > ramBase + ram.size()) {
      return nullptr;
    }
    return ram.data() + static_cast<size_t>(gpa - ramBase);
  });
  const uint64_t abar = 0xFEBB0000;
  ahci.SetAbarBase(abar);
  auto wr = [&](uint32_t off, uint32_t v) { ahci.OnWrite(abar + off, 4, v); };
  auto rd = [&](uint32_t off) -> uint32_t {
    uint64_t v = 0;
    ahci.OnRead(abar + off, 4, &v);
    return static_cast<uint32_t>(v);
  };
  auto put32 = [&](uint64_t gpa, uint32_t v) {
    uint8_t *p = ram.data() + static_cast<size_t>(gpa - ramBase);
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
  };
  // The device must report present (signature + ready task file).
  Expect(rd(0x100 + 0x24) == 0x00000101u, "AHCI: port reports SATA disk signature");
  Expect((rd(0x100 + 0x28) & 0xF) == 0x3u, "AHCI: port detects device present (DET=3)");

  const uint64_t clb = ramBase + 0x0000;   // command list.
  const uint64_t fb = ramBase + 0x1000;    // FIS receive.
  const uint64_t ctba = ramBase + 0x2000;  // command table.
  const uint64_t dataBuf = ramBase + 0x3000;
  // Command header slot 0: PRDTL=1, CFL=5 DWORDs; CTBA -> command table.
  put32(clb + 0, (1u << 16) | 5u);
  put32(clb + 8, static_cast<uint32_t>(ctba));
  put32(clb + 12, 0);
  // Command FIS: Host-to-Device Register FIS, command 0xEC (IDENTIFY DEVICE).
  ram[static_cast<size_t>(ctba - ramBase) + 0] = 0x27;
  ram[static_cast<size_t>(ctba - ramBase) + 1] = 0x80;
  ram[static_cast<size_t>(ctba - ramBase) + 2] = 0xEC;
  // PRDT entry 0 (at command table + 0x80): 512-byte buffer at dataBuf.
  put32(ctba + 0x80 + 0, static_cast<uint32_t>(dataBuf));
  put32(ctba + 0x80 + 4, 0);
  put32(ctba + 0x80 + 12, 512u - 1u); // DBC = bytes-1.
  // Program the port and issue.
  wr(0x100 + 0x00, static_cast<uint32_t>(clb)); // PxCLB.
  wr(0x100 + 0x08, static_cast<uint32_t>(fb));   // PxFB.
  wr(0x100 + 0x14, 0xFFFFFFFFu);                 // PxIE.
  wr(0x04, 0x80000002u);                         // GHC: AE | IE.
  wr(0x100 + 0x18, 0x11u);                       // PxCMD: ST | FRE.
  wr(0x100 + 0x38, 0x1u);                        // PxCI: issue slot 0.

  const uint16_t word0 = static_cast<uint16_t>(
      ram[static_cast<size_t>(dataBuf - ramBase)] |
      (ram[static_cast<size_t>(dataBuf - ramBase) + 1] << 8));
  Expect(word0 == 0x0040, "AHCI IDENTIFY: fixed-disk word 0 in PRDT buffer");
  Expect(ahci.IdentifyCommands() == 1, "AHCI IDENTIFY: command counted");
  Expect((rd(0x100 + 0x38) & 0x1u) == 0,
         "AHCI IDENTIFY: PxCI slot cleared on completion");
  Expect((rd(0x100 + 0x10) & 0x1u) != 0,
         "AHCI IDENTIFY: PxIS DHRS set (D2H register FIS posted)");
  Expect(ahci.InterruptPending(),
         "AHCI IDENTIFY: interrupt asserted to the host");
  // The D2H Register FIS landed in the FIS-receive area at PxFB + 0x40.
  Expect(ram[static_cast<size_t>(fb - ramBase) + 0x40] == 0x34,
         "AHCI IDENTIFY: D2H Register FIS type in FIS-receive area");
}

void TestAhciReadSectors() {
  using namespace antimal::hv;
  MemoryBlockDevice disk(64);
  // Seed sector 7 with a recognizable pattern.
  std::array<uint8_t, IBlockDevice::kSectorSize> sector{};
  for (size_t i = 0; i < sector.size(); ++i) {
    sector[i] = static_cast<uint8_t>(0xA0 + (i & 0x1F));
  }
  disk.WriteSectors(7, 1, sector.data());
  AhciController ahci(&disk);
  const uint64_t ramBase = 0x00100000;
  std::vector<uint8_t> ram(0x00020000, 0);
  ahci.SetDmaMemory([&](uint64_t gpa, std::size_t len) -> uint8_t * {
    if (gpa < ramBase || gpa + len > ramBase + ram.size()) {
      return nullptr;
    }
    return ram.data() + static_cast<size_t>(gpa - ramBase);
  });
  const uint64_t abar = 0xFEBB0000;
  ahci.SetAbarBase(abar);
  auto wr = [&](uint32_t off, uint32_t v) { ahci.OnWrite(abar + off, 4, v); };
  auto put32 = [&](uint64_t gpa, uint32_t v) {
    uint8_t *p = ram.data() + static_cast<size_t>(gpa - ramBase);
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
  };
  const uint64_t clb = ramBase, ctba = ramBase + 0x2000, dataBuf = ramBase + 0x3000;
  put32(clb + 0, (1u << 16) | 5u);
  put32(clb + 8, static_cast<uint32_t>(ctba));
  // READ DMA EXT (0x25), LBA 7, count 1.
  ram[static_cast<size_t>(ctba - ramBase) + 0] = 0x27;
  ram[static_cast<size_t>(ctba - ramBase) + 1] = 0x80;
  ram[static_cast<size_t>(ctba - ramBase) + 2] = 0x25;
  ram[static_cast<size_t>(ctba - ramBase) + 4] = 7; // LBA 7:0.
  ram[static_cast<size_t>(ctba - ramBase) + 12] = 1; // count low.
  put32(ctba + 0x80 + 0, static_cast<uint32_t>(dataBuf));
  put32(ctba + 0x80 + 12, 512u - 1u);
  wr(0x100 + 0x00, static_cast<uint32_t>(clb));
  wr(0x04, 0x80000002u);
  wr(0x100 + 0x18, 0x11u);
  wr(0x100 + 0x38, 0x1u);
  Expect(ahci.ReadCommands() == 1, "AHCI READ: command counted");
  Expect(ahci.SectorsRead() == 1, "AHCI READ: one sector moved");
  Expect(ram[static_cast<size_t>(dataBuf - ramBase)] == 0xA0,
         "AHCI READ: sector data DMA'd into the PRDT buffer");
  Expect(ram[static_cast<size_t>(dataBuf - ramBase) + 31] == 0xBF,
         "AHCI READ: full sector pattern landed");
}

// Regression for the 28-bit READ DMA (0xC8) LBA decode: LBA bits 27:24 live in
// the Device register (CFIS byte 7) low nibble, not in the 48-bit "exp" bytes.
// Decoding 0xC8 as 48-bit drops those bits, so any read at LBA >= 16M sectors
// (>= 8 GiB, e.g. the SYSTEM hive) returns the wrong sectors (boot 0xc000000f).
void TestAhciReadDma28HighLba() {
  using namespace antimal::hv;
  // Formula-backed virtual disk: each sector's first 8 bytes are its own LBA, so
  // we can probe a high LBA without allocating gigabytes.
  struct LbaPatternDisk final : IBlockDevice {
    uint64_t SectorCount() const noexcept override { return 0x10000000ull; }
    bool ReadSectors(uint64_t lba, uint16_t count, uint8_t *out) override {
      for (uint16_t i = 0; i < count; ++i) {
        const uint64_t l = lba + i;
        uint8_t *p = out + static_cast<size_t>(i) * kSectorSize;
        std::memset(p, 0, kSectorSize);
        std::memcpy(p, &l, sizeof(l));
      }
      return true;
    }
    bool WriteSectors(uint64_t, uint16_t, const uint8_t *) override { return true; }
    bool Flush() override { return true; }
  } disk;
  AhciController ahci(&disk);
  const uint64_t ramBase = 0x00100000;
  std::vector<uint8_t> ram(0x00010000, 0);
  ahci.SetDmaMemory([&](uint64_t gpa, std::size_t len) -> uint8_t * {
    if (gpa < ramBase || gpa + len > ramBase + ram.size()) {
      return nullptr;
    }
    return ram.data() + static_cast<size_t>(gpa - ramBase);
  });
  const uint64_t abar = 0xFEBB0000;
  ahci.SetAbarBase(abar);
  auto wr = [&](uint32_t off, uint32_t v) { ahci.OnWrite(abar + off, 4, v); };
  auto put32 = [&](uint64_t gpa, uint32_t v) {
    uint8_t *p = ram.data() + static_cast<size_t>(gpa - ramBase);
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
  };
  const uint64_t clb = ramBase, ctba = ramBase + 0x2000, dataBuf = ramBase + 0x3000;
  put32(clb + 0, (1u << 16) | 5u);
  put32(clb + 8, static_cast<uint32_t>(ctba));
  // READ DMA (0xC8, 28-bit), LBA 0x01234567 (bits 27:24 = 0x1 in the Device reg).
  const uint64_t targetLba = 0x01234567ull;
  ram[static_cast<size_t>(ctba - ramBase) + 0] = 0x27;
  ram[static_cast<size_t>(ctba - ramBase) + 1] = 0x80;
  ram[static_cast<size_t>(ctba - ramBase) + 2] = 0xC8;
  ram[static_cast<size_t>(ctba - ramBase) + 4] = targetLba & 0xFF;        // LBA 7:0.
  ram[static_cast<size_t>(ctba - ramBase) + 5] = (targetLba >> 8) & 0xFF; // LBA 15:8.
  ram[static_cast<size_t>(ctba - ramBase) + 6] = (targetLba >> 16) & 0xFF;// LBA 23:16.
  ram[static_cast<size_t>(ctba - ramBase) + 7] =
      static_cast<uint8_t>(0x40u | ((targetLba >> 24) & 0x0F)); // LBA mode + 27:24.
  ram[static_cast<size_t>(ctba - ramBase) + 12] = 1;            // count = 1.
  put32(ctba + 0x80 + 0, static_cast<uint32_t>(dataBuf));
  put32(ctba + 0x80 + 12, 512u - 1u);
  wr(0x100 + 0x00, static_cast<uint32_t>(clb));
  wr(0x04, 0x80000002u);
  wr(0x100 + 0x18, 0x11u);
  wr(0x100 + 0x38, 0x1u);
  uint64_t gotLba = 0;
  std::memcpy(&gotLba, ram.data() + static_cast<size_t>(dataBuf - ramBase),
              sizeof(gotLba));
  Expect(gotLba == targetLba,
         "AHCI READ DMA 28-bit: LBA bits 27:24 decoded from Device register");
}

// Security hardening (live-sandbox-console P6): the AHCI controller is the #1
// VM-escape surface -- it moves bytes between the disk and *guest-supplied* DMA
// addresses driven by a guest-built command list + PRDT. A malicious guest must
// never be able to make the host read/write outside backed guest RAM. This
// adversarial harness canaries the whole RAM and drives hostile commands
// (out-of-range command-list base, out-of-range PRDT data base, max byte count
// straddling the RAM end) then asserts no out-of-bounds host write occurred and
// the DMA accessor rejected the bad ranges. Mirrors TestAhciReadSectors' setup.
void TestAhciAdversarialDma() {
  using namespace antimal::hv;
  MemoryBlockDevice disk(64);
  std::array<uint8_t, IBlockDevice::kSectorSize> sec{};
  for (size_t i = 0; i < sec.size(); ++i) {
    sec[i] = static_cast<uint8_t>(0xC0 + (i & 0x1F));
  }
  disk.WriteSectors(7, 1, sec.data());

  AhciController ahci(&disk);
  const uint64_t ramBase = 0x00100000;
  std::vector<uint8_t> ram(0x00020000, 0x5A); // 0x5A canary over all guest RAM.
  size_t dmaNull = 0;
  ahci.SetDmaMemory([&](uint64_t gpa, std::size_t len) -> uint8_t * {
    // Exactly the real bound: reject any range not fully inside guest RAM.
    if (gpa < ramBase || len > ram.size() || gpa + len > ramBase + ram.size()) {
      ++dmaNull;
      return nullptr;
    }
    return ram.data() + static_cast<size_t>(gpa - ramBase);
  });
  const uint64_t abar = 0xFEBB0000;
  ahci.SetAbarBase(abar);
  auto wr = [&](uint32_t off, uint32_t v) { ahci.OnWrite(abar + off, 4, v); };
  auto put32 = [&](uint64_t gpa, uint32_t v) {
    uint8_t *p = ram.data() + static_cast<size_t>(gpa - ramBase);
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
  };
  const uint64_t clb = ramBase, ctba = ramBase + 0x2000;

  // Case 1: command-list base points far outside guest RAM -> clean bail.
  wr(0x04, 0x80000002u);       // GHC: AE | IE.
  wr(0x100 + 0x18, 0x11u);     // PxCMD: ST | FRE.
  wr(0x100 + 0x00, 0xFFFF0000u); // PxCLB out of range.
  wr(0x100 + 0x38, 0x1u);      // PxCI slot 0.
  Expect(ahci.CiWrites() >= 1, "AHCI adv: out-of-range CLB processed (counted)");

  // Build a valid READ DMA EXT (LBA 7, count 1) command for cases 2-3.
  put32(clb + 0, (1u << 16) | 5u);                 // prdtl=1, cfl=5 dwords.
  put32(clb + 8, static_cast<uint32_t>(ctba));     // CTBA low.
  const size_t c = static_cast<size_t>(ctba - ramBase);
  ram[c + 0] = 0x27; ram[c + 1] = 0x80; ram[c + 2] = 0x25; // H2D, C=1, READ DMA EXT.
  ram[c + 4] = 7; ram[c + 12] = 1;                  // LBA 7, count 1.
  wr(0x100 + 0x00, static_cast<uint32_t>(clb));     // restore a valid PxCLB.

  // Case 2: PRDT data base far out of range + max byte count (0x3FFFFF).
  put32(ctba + 0x80 + 0, 0xEEEE0000u);
  put32(ctba + 0x80 + 12, 0x3FFFFFu);
  wr(0x100 + 0x38, 0x1u);
  Expect(ram[static_cast<size_t>(0x110000 - 0x100000)] == 0x5A,
         "AHCI adv: out-of-range PRDT data base did not corrupt host RAM");

  // Case 3: PRDT data base 256B before RAM end + max byte count -> the 512B
  // sector transfer straddles the end, so the accessor must refuse it whole
  // (no partial over-write past the validated range).
  const uint64_t nearEnd = ramBase + ram.size() - 256;
  put32(ctba + 0x80 + 0, static_cast<uint32_t>(nearEnd));
  put32(ctba + 0x80 + 12, 0x3FFFFFu);
  wr(0x100 + 0x38, 0x1u);
  Expect(ram[ram.size() - 1] == 0x5A,
         "AHCI adv: max DBC straddling RAM end did not over-write");
  Expect(ram[ram.size() - 256] == 0x5A,
         "AHCI adv: partial transfer past validated range suppressed");

  Expect(dmaNull >= 2,
         "AHCI adv: DMA accessor rejected out-of-range guest addresses");
}

// Security hardening (escape surface): the legacy-IO + display + firmware-config
// devices all take guest-controlled port writes; a missing bound (e.g. a
// guest-controlled register index or an fw_cfg read offset past an item's end)
// is a host OOB = a VM escape. This sweeps those devices with adversarial IO and
// asserts none crash/over-read. Complements TestAhciAdversarialDma (DMA surface).
void TestDeviceIoFuzz() {
  using namespace antimal::hv;
  unsigned long lcg = 0x2468ace0u;
  auto next = [&lcg]() {
    lcg = lcg * 1103515245u + 12345u;
    return static_cast<unsigned>((lcg >> 16) & 0x7fff);
  };
  auto val32 = [&]() {
    return static_cast<uint32_t>(next()) | (static_cast<uint32_t>(next()) << 15) |
           (static_cast<uint32_t>(next() & 0x3u) << 30);
  };
  auto sz = [&]() {
    static const uint8_t s[] = {1, 2, 4};
    return s[next() % 3];
  };

  // 1) BochsVbe display: a guest-controlled register index feeds a fixed 16-entry
  //    array -- it must never index out of bounds whatever index is written.
  {
    BochsVbeDevice vbe;
    std::vector<uint8_t> fb(64u * 1024u, 0);
    vbe.SetFramebufferHostBytes(fb.data(), fb.size());
    const uint16_t ports[] = {BochsVbeDevice::kIndexPort, BochsVbeDevice::kDataPort,
                              BochsVbeDevice::kDataPortAligned};
    for (int i = 0; i < 60000; ++i) {
      const uint16_t p = ports[next() % 3];
      if (next() & 1) {
        vbe.OnWrite(p, val32(), sz());
      } else {
        (void)vbe.OnRead(p, sz());
      }
    }
    Expect(true, "device fuzz: BochsVbe survived 60k adversarial register IO ops");
  }

  // 2) Legacy PC IO incl. fw_cfg. Random IO across the real ports, then a focused
  //    fw_cfg sweep: select an arbitrary item, then read 0x511 far past any
  //    item's length -- a missing per-item offset bound would OOB-read host
  //    memory (the classic QEMU-style firmware escape).
  {
    PcIoDevices pc;
    const uint16_t ports[] = {0x0020, 0x0021, 0x00A0, 0x00A1, 0x0040, 0x0041,
                              0x0042, 0x0043, 0x0070, 0x0071, 0x0092, 0x0402,
                              0x0CF9, 0x0CF8, 0x0CFC, 0x0510, 0x0511, 0xB000,
                              0xB002, 0xB004, 0xB008, 0xB00A, 0xAF00, 0xAF10,
                              0xAF1F};
    const int n = static_cast<int>(sizeof(ports) / sizeof(ports[0]));
    for (int i = 0; i < 120000; ++i) {
      const uint16_t p = ports[next() % n];
      if (next() & 1) {
        pc.OnWrite(p, val32(), sz());
      } else {
        (void)pc.OnRead(p, sz());
      }
    }
    Expect(true,
           "device fuzz: PcIoDevices survived 120k adversarial legacy-IO ops");
    for (int s = 0; s < 4000; ++s) {
      pc.OnWrite(0x510, val32() & 0xFFFFu, 2); // arbitrary fw_cfg selector
      for (int r = 0; r < 600; ++r) {
        (void)pc.OnRead(0x511, 1); // read far past any item end
      }
    }
    Expect(true,
           "device fuzz: fw_cfg arbitrary-selector over-read stayed bounded");
  }
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
  Expect(pic.MasterPicMask() == 0xFE, "PIC: master mask remembered");
  pic.OnWrite(0xA1, 0xFD, 1);
  Expect(pic.SlavePicMask() == 0xFD, "PIC: slave mask remembered");
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

void TestIdeInterruptRetriedUntilDelivered() {
  struct Capture {
    int calls = 0;
  } capture;
  auto deliver = +[](void *context, uint32_t, uint8_t) -> bool {
    auto *c = static_cast<Capture *>(context);
    ++c->calls;
    return true;
  };

  antimal::hv::MemoryBlockDevice disk(8);
  antimal::hv::IdeController ide(&disk);
  antimal::hv::IoApic ioApic;
  ioApic.SetDeliveryCallback(deliver, &capture);

  ide.OnWrite(antimal::hv::IdeController::kPrimaryBase + 7, 0xEC, 1);
  Expect(ide.InterruptPending(),
         "IDE IRQ retry: IDENTIFY leaves interrupt pending");
  Expect(!ioApic.RaiseIrq(ide.IrqLine()),
         "IDE IRQ retry: masked IOAPIC delivery fails");
  Expect(ide.InterruptPending(),
         "IDE IRQ retry: failed delivery keeps interrupt pending");

  const uint8_t lowIndex = 0x10 + ide.IrqLine() * 2;
  ioApic.IndirectWrite(lowIndex, 0x00000076u);
  ioApic.IndirectWrite(static_cast<uint8_t>(lowIndex + 1), 0x00000000u);
  if (ioApic.RaiseIrq(ide.IrqLine())) {
    (void)ide.ConsumeInterrupt();
  }
  Expect(capture.calls == 1, "IDE IRQ retry: unmasked delivery called once");
  Expect(!ide.InterruptPending(),
         "IDE IRQ retry: successful delivery consumes interrupt");
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

void TestWhpUnmappedMmioTrapsOnRead() {
  if (!antimal::hv::WhpHost::IsAvailable()) {
    std::cout << "SKIP: WHP not available on this host\n";
    return;
  }

  try {
    antimal::hv::WhpHost host(1);
    antimal::hv::GuestMemoryRegion code(
        host, 0, 0x1000, antimal::hv::GuestMemoryProt::ReadWriteExecute);

    // DS=0x100 makes [0x0010] resolve to GPA 0x1010, which is intentionally
    // unmapped. This pins the MMIO-hole pattern used for IOAPIC/HPET reads.
    static constexpr uint8_t payload[] = {
        0xBB, 0x00, 0x01, // mov bx, 0x0100
        0x8E, 0xDB,       // mov ds, bx
        0xA1, 0x10, 0x00, // mov ax, [0x0010]
        0xF4,             // hlt
    };
    code.Write(0, payload, sizeof(payload));

    antimal::hv::Vcpu vcpu(host, 0);
    antimal::hv::ResetState16BitRealMode reset{};
    vcpu.SetRealModeStart(reset);

    const auto reason = vcpu.Run();
    Expect(reason == WHvRunVpExitReasonMemoryAccess,
           "Unmapped MMIO: read produces WHvRunVpExitReasonMemoryAccess");
    if (reason == WHvRunVpExitReasonMemoryAccess) {
      const auto &mem = vcpu.LastExit().MemoryAccess;
      Expect((mem.Gpa & ~0xFFFull) == 0x1000ull,
             "Unmapped MMIO: read reports the trapped page");
      Expect(mem.AccessInfo.AccessType == 0,
             "Unmapped MMIO: memory-access exit is reported as a read");
    }
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: unmapped MMIO trap test threw WhpError: " << ex.what()
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
  std::string firmwareName = "OVMF.fd";
  {
    char buf[260]{};
    size_t needed = 0;
    if (getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_FIRMWARE_NAME") == 0 &&
        needed > 1 && buf[0] != '\0') {
      firmwareName.assign(buf);
    }
  }
  return repoRoot / "firmware" / firmwareName;
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
    antimal::hv::Tpm2CrbDevice tpm;
    antimal::hv::MmioBus mmioBus;
    antimal::hv::MmioEmulator mmioEmulator;
    mmioBus.Attach(&tpm);
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
    int handledMmio = 0;
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
        if (mmioBus.Find(ctx.MemoryAccess.Gpa)) {
          bool deviceOwned = false;
          if (mmioEmulator.TryEmulate(vcpu, ctx, mmioBus, &deviceOwned)) {
            ++handledMmio;
            break;
          }
        }
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
    std::cout << "  handled MMIO accesses:   " << handledMmio << "\n";
    std::cout << "  TPM2 CRB: reads " << tpm.Reads() << ", writes "
              << tpm.Writes() << ", commands " << tpm.CommandsProcessed()
              << ", last command 0x" << std::hex << std::uppercase
              << tpm.LastCommandCode() << ", last response 0x"
              << tpm.LastResponseCode() << std::dec << "\n";
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
              << "  AHCI abar: 0x" << std::hex << std::uppercase
              << summary.ahciAbarBase << std::dec << "\n"
              << "  AHCI commands: " << summary.ahciCommandsIssued << "\n"
              << "  AHCI identify: " << summary.ahciIdentifyCommands << "\n"
              << "  AHCI reads: " << summary.ahciReadCommands
              << " sectors: " << summary.ahciSectorsRead << "\n"
              << "  AHCI ci writes: " << summary.ahciCiWrites
              << " portcmd writes: " << summary.ahciPortCmdWrites << "\n"
              << "  AHCI unknown cmds: " << summary.ahciUnknownCommands
              << " last cmd: 0x" << std::hex << std::uppercase
              << summary.ahciLastCommand << std::dec << "\n";
    const std::string &previewSource = summary.firmwareDebugOutput.empty()
                                           ? summary.serialOutput
                                           : summary.firmwareDebugOutput;
    if (!previewSource.empty()) {
      std::string preview = previewSource.substr(
          0, std::min<size_t>(previewSource.size(), 512));
      std::replace(preview.begin(), preview.end(), '\r', '\n');
      std::cout << "  serial preview:\n" << preview << "\n";
    }
    Expect(summary.steps > 0, "WHP OVMF + AHCI: at least one exit occurred");
    Expect(!summary.exitHistogram.empty(),
           "WHP OVMF + AHCI: exit histogram populated");
    Expect(!summary.fatal, "WHP OVMF + AHCI: no fatal exit");
    // The boot disk is on the AHCI HBA now (PCI-native). OVMF's AhciBusDxe
    // enumerates the port and issues IDENTIFY DEVICE through our emulated HBA;
    // a non-zero count proves the command-list/FIS/PRDT engine works end to end
    // with real firmware before we spend a full Windows boot cycle on it.
    Expect(summary.ahciIdentifyCommands > 0,
           "WHP OVMF + AHCI: IDENTIFY DEVICE completed via AHCI");
  } catch (const antimal::hv::WhpError &ex) {
    ++g_failed;
    std::cerr << "FAIL: WHP OVMF + AHCI threw WhpError: " << ex.what() << "\n";
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
    ev.details["quoted"] = "C:\\Temp\\\"payload\"\\stage.bin";
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
  Expect(all[0].details["quoted"] == "C:\\Temp\\\"payload\"\\stage.bin",
         "journal: escaped detail preserved");
  Expect(all[1].target == "evil.example.com:443", "journal: target preserved");

  const std::string richLine = R"JSON({"timestampUtc":"2026-05-23T20:00:00Z","source":"Host","category":"vm","action":"boot.status","processId":0,"parentProcessId":0,"imagePath":"","target":"C:\\AntiMalRuns\\run\\vm-diagnostics.txt","details":{"message":"DriverSiPolicy.p7b, active CI policy data, bootres.dll","nested":"{\"status\":\"0xc0000225\",\"items\":[\"a\",\"b\"]}","note":"line\nquote\"slash\\"},"mitre":""})JSON";
  const auto rich = antimal::ParseEventJsonLine(richLine);
  Expect(rich.category == "vm", "journal parse: rich event category");
  Expect(rich.target == "C:\\AntiMalRuns\\run\\vm-diagnostics.txt",
         "journal parse: escaped target path");
  const auto nested = rich.details.find("nested");
  const auto note = rich.details.find("note");
  Expect(nested != rich.details.end() &&
             nested->second.find("0xc0000225") != std::string::npos,
         "journal parse: nested escaped detail");
  Expect(note != rich.details.end() &&
             note->second.find("quote\"slash\\") != std::string::npos,
         "journal parse: escaped quote and slash detail");

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
  report.dynamicSummary.ideInterruptsRequested = 7;
  report.dynamicSummary.ideInterruptsInjected = 3;
  report.dynamicSummary.ideInterruptsFailed = 4;
  report.dynamicSummary.ideInterruptsPending = 1;
  report.dynamicSummary.irqPicFallbackDeliveries = 3;
  report.dynamicSummary.masterPicVectorBase = 0x20;
  report.dynamicSummary.slavePicVectorBase = 0x28;
  report.dynamicSummary.masterPicMask = 0xFE;
  report.dynamicSummary.slavePicMask = 0xFD;
  report.dynamicSummary.kdPacketsReceived = 2;
  report.dynamicSummary.kdAckPacketsSent = 2;
  report.dynamicSummary.kdResetPacketsSent = 1;
  report.dynamicSummary.kdCom1RxQueuedBytes = 4;
  report.dynamicSummary.kdDebugPrintPackets = 1;
  report.dynamicSummary.kdLoadSymbolPackets = 1;
  report.dynamicSummary.kdLastStatus = 0x80000003;
  report.dynamicSummary.kdLastStatusText = "0x80000003";
  report.dynamicSummary.kdCom1Status = "active";
  report.dynamicSummary.com1RegisterReads = 3;
  report.dynamicSummary.com1RegisterWrites = 12;
  report.dynamicSummary.com1DataReads = 1;
  report.dynamicSummary.com1DataWrites = 9;
  report.dynamicSummary.com1RxBytesQueued = 16;
  report.dynamicSummary.com1RxBytesRead = 1;
  report.dynamicSummary.com1IerWrites = 1;
  report.dynamicSummary.com1LcrWrites = 2;
  report.dynamicSummary.com1Ier = 1;
  report.dynamicSummary.com1RxInterruptEnabled = true;
  report.dynamicSummary.com1TouchStatus = "guest-tx-observed";
  report.dynamicSummary.tpmCrbReads = 11;
  report.dynamicSummary.tpmCrbWrites = 22;
  report.dynamicSummary.tpmCrbCommands = 2;
  report.dynamicSummary.tpmCrbLastCommand = 0x0000017A;
  report.dynamicSummary.tpmCrbLastResponse = 0;
  report.dynamicSummary.tpmCrbLastReadOffset = 0x80;
  report.dynamicSummary.tpmCrbLastWriteOffset = 0x4C;
  report.dynamicSummary.tpmCrbCommandSummary =
      "reads=11 writes=22 commands=2 lastCommand=0x17A(TPM2_GetCapability)";
  report.dynamicSummary.tpmPcrExtendTraceSummary =
      "#1 pcr=7 0xB(SHA256) digest=AA resultingPcr=BB";
  report.dynamicSummary.tpmPcrFinalBanksSummary =
      "SHA1[PCR7=AA; zeroPcrs=23] SHA256[PCR7=BB; zeroPcrs=23]";
  report.dynamicSummary.acpiTpm2EventLogSummary =
      "TPM2 table CRB controlArea=0xFED40040 LAML=0 LASA=0; no ACPI TPM event log advertised";
  report.dynamicSummary.fwCfgSmbiosAnchorBytesRead = 31;
  report.dynamicSummary.fwCfgSmbiosTableBytesRead = 304;
  report.dynamicSummary.keyboardScancodesInjected = 2;
  report.dynamicSummary.ps2StatusReads = 0;
  report.dynamicSummary.ps2DataReads = 0;
  report.dynamicSummary.ps2KeyboardBytesQueued = 2;
  report.dynamicSummary.ps2KeyboardBytesRead = 0;
  report.dynamicSummary.ps2KeyboardPortEnabled = true;
  report.dynamicSummary.ps2KeyboardScanningEnabled = true;
  report.dynamicSummary.ps2InputStatus = "queued-not-polled";
  report.dynamicSummary.windowsKernelReadGateReached = false;
  report.dynamicSummary.windowsKernelReadGateStatus = "not-reached";
  report.dynamicSummary.windowsKernelReadGateEvidence =
      "no reads of kernel-gate targets";
  report.dynamicSummary.windowsKernelReadGateFirstTarget =
      "Windows\\System32\\ntoskrnl.exe";
  report.dynamicSummary.windowsUserModeGateReached = true;
  report.dynamicSummary.windowsUserModeGateStatus = "reached";
  report.dynamicSummary.windowsUserModeGateEvidence =
      "Windows\\System32\\winlogon.exe readCommands=1 sectorsRead=32";
  report.dynamicSummary.windowsUserModeGateFirstTarget =
      "Windows\\System32\\winlogon.exe";
  report.dynamicSummary.bootFailureStatus = "0xC0000225";
  report.dynamicSummary.bootFailureStatusName = "STATUS_NOT_FOUND";
  report.dynamicSummary.bootFailureStatusSource =
      "bootstat decoded record {bootmgr}";
  report.dynamicSummary.bootBlocker = "winload reached pre-kernel work";
  report.dynamicSummary.bootContractSuspect =
      "winload returned to bootmgr during CI/VBS handoff";
  report.dynamicSummary.bootContractSuspectDetails =
      "stage=winload-pre-kernel; bootstat=0xC0000225(STATUS_NOT_FOUND); "
      "hypervisorlaunchtype=Off overlay applied";
  report.dynamicSummary.ciPolicyInventory =
      "Windows:{784C4414-79F4-4C32-A6A5-F0FB42A51D0D} present documented "
      "size=4096 lba=100-107 readCommands=1 sectorsRead=8; "
      "ESP:{8F9CB695-5D48-48D6-A329-7202B44607E3} missing documented";
  report.dynamicSummary.bootstatScalarSummary =
      "FailedPicrootExceptionsPolicy@0x100 dwords=[+4:0x00000001]";
  report.dynamicSummary.cpuidDiagnostics.push_back(
      "vcpu0 leaf=0x00000001 sub=0x00000000 ecx=0x00000000 hypervisorBit=clear");
  report.dynamicSummary.bootStage = "winload-pre-kernel";
  report.dynamicSummary.bootMilestones.push_back("bootmgfw loaded");
  report.dynamicSummary.bootMilestones.push_back("BCD opened");
  report.dynamicSummary.interruptDiagnostics.push_back(
      "irq14: ioapicMasked=true picBase=0x28");
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
  Expect(loaded.dynamicSummary.bootStage == "winload-pre-kernel",
         "report load: boot stage preserved");
  Expect(loaded.dynamicSummary.ideInterruptsRequested == 7,
         "report load: IDE IRQ counters preserved");
  Expect(loaded.dynamicSummary.interruptDiagnostics.size() == 1,
         "report load: interrupt diagnostics preserved");
  Expect(loaded.dynamicSummary.kdPacketsReceived == 2 &&
             loaded.dynamicSummary.kdResetPacketsSent == 1 &&
             loaded.dynamicSummary.kdCom1RxQueuedBytes == 4 &&
             loaded.dynamicSummary.kdLastStatusText == "0x80000003" &&
             loaded.dynamicSummary.kdCom1Status == "active",
         "report load: KD counters preserved");
  Expect(loaded.dynamicSummary.com1RegisterWrites == 12 &&
             loaded.dynamicSummary.com1DataWrites == 9 &&
             loaded.dynamicSummary.com1RxBytesQueued == 16 &&
             loaded.dynamicSummary.com1RxInterruptEnabled &&
             loaded.dynamicSummary.com1TouchStatus == "guest-tx-observed",
         "report load: COM1 UART diagnostics preserved");
  Expect(loaded.dynamicSummary.tpmCrbReads == 11 &&
             loaded.dynamicSummary.tpmCrbWrites == 22 &&
             loaded.dynamicSummary.tpmCrbCommands == 2 &&
             loaded.dynamicSummary.tpmCrbLastCommand == 0x0000017A &&
             loaded.dynamicSummary.tpmCrbLastReadOffset == 0x80 &&
             loaded.dynamicSummary.tpmCrbCommandSummary.find(
                 "TPM2_GetCapability") != std::string::npos,
         "report load: TPM2 CRB diagnostics preserved");
  Expect(loaded.dynamicSummary.tpmPcrExtendTraceSummary.find("pcr=7") !=
             std::string::npos &&
             loaded.dynamicSummary.tpmPcrFinalBanksSummary.find("PCR7=BB") !=
                 std::string::npos &&
             loaded.dynamicSummary.acpiTpm2EventLogSummary.find("LAML=0") !=
                 std::string::npos,
         "report load: TPM PCR diagnostics preserved");
  Expect(loaded.dynamicSummary.fwCfgSmbiosAnchorBytesRead == 31 &&
             loaded.dynamicSummary.fwCfgSmbiosTableBytesRead == 304,
         "report load: SMBIOS fw_cfg counters preserved");
  Expect(loaded.dynamicSummary.keyboardScancodesInjected == 2 &&
             loaded.dynamicSummary.ps2KeyboardBytesQueued == 2 &&
             loaded.dynamicSummary.ps2InputStatus == "queued-not-polled",
         "report load: PS/2 diagnostics preserved");
  Expect(!loaded.dynamicSummary.windowsKernelReadGateReached &&
             loaded.dynamicSummary.windowsKernelReadGateStatus == "not-reached" &&
             loaded.dynamicSummary.windowsKernelReadGateFirstTarget ==
                 "Windows\\System32\\ntoskrnl.exe" &&
             loaded.dynamicSummary.windowsUserModeGateReached &&
             loaded.dynamicSummary.windowsUserModeGateStatus == "reached" &&
             loaded.dynamicSummary.windowsUserModeGateFirstTarget ==
                 "Windows\\System32\\winlogon.exe" &&
             loaded.dynamicSummary.bootFailureStatus == "0xC0000225" &&
             loaded.dynamicSummary.bootFailureStatusName == "STATUS_NOT_FOUND" &&
             loaded.dynamicSummary.bootFailureStatusSource ==
                 "bootstat decoded record {bootmgr}" &&
             loaded.dynamicSummary.bootBlocker == "winload reached pre-kernel work" &&
             loaded.dynamicSummary.bootContractSuspect ==
                 "winload returned to bootmgr during CI/VBS handoff" &&
             loaded.dynamicSummary.bootContractSuspectDetails.find(
                 "hypervisorlaunchtype=Off overlay applied") !=
                 std::string::npos &&
             loaded.dynamicSummary.ciPolicyInventory.find(
                 "{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}") !=
                 std::string::npos &&
             loaded.dynamicSummary.bootstatScalarSummary.find(
                 "FailedPicrootExceptionsPolicy") != std::string::npos,
         "report load: boot gate summaries preserved");
  Expect(loaded.dynamicSummary.cpuidDiagnostics.size() == 1,
         "report load: CPUID diagnostics preserved");
  Expect(loaded.artifacts.size() == 1, "report load: artifacts preserved");
  Expect(loaded.networkDomains.size() == 1, "report load: network preserved");
  Expect(loaded.errors.size() == 1, "report load: errors preserved");

  const auto html = antimal::BuildHtmlReportWithFrames(
      loaded, {std::filesystem::path("screenshots") / "frame-000001.png"});
  Expect(html.find("screenshots/frame-000001.png") != std::string::npos,
         "report html: frame path includes screenshots directory");
  const auto explicitMixedHtml = antimal::BuildHtmlReportWithFrames(
      loaded, {std::filesystem::path("screenshots") / "livevm-000001.png",
               std::filesystem::path("screenshots") / "guest-000001.png"});
  Expect(explicitMixedHtml.find("screenshots/guest-000001.png") !=
             std::string::npos,
         "report html: explicit guest frame rendered");
  Expect(explicitMixedHtml.find("screenshots/livevm-000001.png") ==
             std::string::npos,
         "report html: explicit diagnostic frames skipped when guest frames exist");
  Expect(html.find("winload-pre-kernel") != std::string::npos,
         "report html: boot stage rendered");
  Expect(html.find("kernel gate") != std::string::npos &&
             html.find("not-reached") != std::string::npos,
         "report html: kernel gate rendered");
  Expect(html.find("user-mode gate") != std::string::npos &&
             html.find("winlogon.exe") != std::string::npos,
         "report html: user-mode gate rendered");
  Expect(html.find("boot contract suspect") != std::string::npos &&
             html.find("CI/VBS handoff") != std::string::npos,
         "report html: boot contract suspect rendered");
  Expect(html.find("hypervisorlaunchtype=Off overlay applied") !=
             std::string::npos,
         "report html: boot contract details rendered");
  Expect(html.find("CI policy inventory") != std::string::npos &&
             html.find("{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}") !=
                 std::string::npos,
         "report html: CI policy inventory rendered");
  Expect(html.find("bootstat scalars") != std::string::npos &&
             html.find("FailedPicrootExceptionsPolicy") != std::string::npos,
         "report html: bootstat scalar summary rendered");
  Expect(html.find("PS/2 input") != std::string::npos &&
             html.find("queued-not-polled") != std::string::npos,
         "report html: PS/2 diagnostics rendered");
  Expect(html.find("COM1 UART") != std::string::npos &&
             html.find("guest-tx-observed") != std::string::npos,
         "report html: COM1 UART diagnostics rendered");
  Expect(html.find("TPM2 CRB") != std::string::npos &&
             html.find("TPM2_GetCapability") != std::string::npos,
         "report html: TPM2 CRB diagnostics rendered");
  Expect(html.find("TPM PCR extend trace") != std::string::npos &&
             html.find("resultingPcr=BB") != std::string::npos &&
             html.find("ACPI TPM2 event log") != std::string::npos,
         "report html: TPM PCR diagnostics rendered");
  Expect(html.find("CPUID") != std::string::npos &&
             html.find("hypervisorBit=clear") != std::string::npos,
         "report html: CPUID diagnostics rendered");

  const auto mixedDir = TempRoot();
  antimal::EnsureDirectory(mixedDir / "screenshots");
  antimal::WriteTextFile(mixedDir / "screenshots" / "livevm-000001.png", "diag");
  antimal::WriteTextFile(mixedDir / "screenshots" / "guest-000001.png", "guest1");
  antimal::WriteTextFile(mixedDir / "screenshots" / "guest-000002.png", "guest2");
  antimal::WriteReportHtml(mixedDir / "report.html", loaded);
  const auto mixedHtml = antimal::ReadTextFile(mixedDir / "report.html");
  Expect(mixedHtml.find("screenshots/guest-000001.png") != std::string::npos &&
             mixedHtml.find("screenshots/guest-000002.png") != std::string::npos,
         "report html: discovered guest frames rendered");
  Expect(mixedHtml.find("screenshots/livevm-000001.png") == std::string::npos,
         "report html: diagnostic frames skipped when guest frames exist");

  const auto diagDir = TempRoot();
  antimal::EnsureDirectory(diagDir / "screenshots");
  antimal::WriteTextFile(diagDir / "screenshots" / "livevm-000001.png", "diag");
  antimal::WriteReportHtml(diagDir / "report.html", loaded);
  const auto diagHtml = antimal::ReadTextFile(diagDir / "report.html");
  Expect(diagHtml.find("screenshots/livevm-000001.png") != std::string::npos,
         "report html: diagnostic frames render without guest frames");
}

void TestPolicyProbeScriptGuards() {
  wchar_t modulePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
  const auto moduleDir = std::filesystem::path(modulePath).parent_path();
  const std::vector<std::filesystem::path> candidates{
      moduleDir / "tools" / "New-AntiMalPolicyProbeBase.ps1",
      std::filesystem::current_path() / "tools" /
          "New-AntiMalPolicyProbeBase.ps1",
      std::filesystem::current_path().parent_path().parent_path() / "tools" /
          "New-AntiMalPolicyProbeBase.ps1"};
  std::filesystem::path scriptPath;
  for (const auto &candidate : candidates) {
    if (std::filesystem::exists(candidate)) {
      scriptPath = candidate;
      break;
    }
  }
  Expect(!scriptPath.empty(), "policy probe script: copied or present");
  if (scriptPath.empty()) {
    return;
  }
  const auto script = antimal::ReadTextFile(scriptPath);
  Expect(script.find("Scratch VHDX path must not equal the clean base path") !=
             std::string::npos,
         "policy probe script: clean-base equality guard present");
  Expect(script.find("ScratchRoot must not contain the clean base VHDX") !=
             std::string::npos,
         "policy probe script: scratch-root containment guard present");
  Expect(script.find("{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}.cip") !=
             std::string::npos &&
             script.find("{8F9CB695-5D48-48D6-A329-7202B44607E3}.cip") !=
                 std::string::npos,
         "policy probe script: documented policies listed");
  Expect(script.find("{0283AC0F-FFF1-49AE-ADA1-8A933130CAD6}.cip") !=
             std::string::npos &&
             script.find("{1939ED82-BFD5-4D32-B58E-D31D3C49715A}.cip") !=
                 std::string::npos,
         "policy probe script: bootstat-mentioned policies listed");
  Expect(script.find("ANTIMAL_PROBE_POLICY_OFF_BASE") != std::string::npos,
         "policy probe script: runner toggle documented");
}

void TestDetonationProtocol() {
  // Execute-job JSON build -> parse round-trip (all fields).
  antimal::ExecuteJobRequest req;
  req.allowSampleExecution = true;
  req.sampleName = "evil sample.exe";
  req.sampleBytes = 4242;
  req.timeoutMs = 90000;
  req.networkMode = "disabled";
  req.runId = "run-123";
  const auto json = antimal::BuildExecuteJobJson(req);
  const auto parsed = antimal::ParseExecuteJobJson(json);
  Expect(parsed.isExecute, "detonation: kind=execute parsed");
  Expect(parsed.allowSampleExecution, "detonation: allowSampleExecution parsed");
  Expect(parsed.sampleName == "evil sample.exe",
         "detonation: sampleName round-trips");
  Expect(parsed.sampleBytes == 4242, "detonation: sampleBytes round-trips");
  Expect(parsed.timeoutMs == 90000, "detonation: timeoutMs round-trips");
  Expect(parsed.runId == "run-123", "detonation: runId round-trips");

  // A healthcheck payload must NOT read as an execute job (the protocol gate).
  const auto health = antimal::ParseExecuteJobJson(
      R"({"kind":"healthcheck","runId":"r","allowSampleExecution":false})");
  Expect(!health.isExecute, "detonation: healthcheck is not execute");
  Expect(!health.allowSampleExecution, "detonation: healthcheck not authorized");

  // SampleChunk encodes + decodes through the AMCH channel and the payload
  // parses back to (offset, bytes).
  const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20};
  auto frameBytes =
      antimal::EncodeSampleChunkFrame(7, payload.data(), payload.size());
  antimal::HostSerialChannel dec;
  dec.PushBytes(frameBytes);
  auto frame = dec.PopFrame();
  Expect(frame.has_value() &&
             frame->type == antimal::HostChannelMessage::SampleChunk,
         "detonation: SampleChunk frame decodes through AMCH");
  auto chunk = frame ? antimal::ParseSampleChunkPayload(frame->payload)
                     : std::nullopt;
  Expect(chunk.has_value() && chunk->offset == 7 && chunk->bytes == payload,
         "detonation: SampleChunk payload round-trips offset+bytes");

  // Reassembler: in-order chunks complete and reconstruct the buffer exactly.
  std::vector<uint8_t> sample;
  for (int i = 0; i < 100; ++i) sample.push_back(static_cast<uint8_t>(i * 7));
  antimal::SampleReassembler r(sample.size());
  antimal::SampleChunk c1{
      0, std::vector<uint8_t>(sample.begin(), sample.begin() + 40)};
  antimal::SampleChunk c2{
      40, std::vector<uint8_t>(sample.begin() + 40, sample.end())};
  Expect(r.Add(c1), "detonation: reassembler accepts first chunk");
  Expect(!r.Complete(), "detonation: not complete after partial transfer");
  Expect(r.Add(c2), "detonation: reassembler accepts second chunk");
  Expect(r.Complete() && r.Bytes() == sample,
         "detonation: reassembled bytes match the source");

  // Out-of-order, overflow, and oversized transfers are rejected (no silent
  // corruption) — these are the guards that protect the guest from a malformed
  // or hostile delivery.
  antimal::SampleReassembler r2(sample.size());
  antimal::SampleChunk outOfOrder{40, {1, 2, 3}};
  Expect(!r2.Add(outOfOrder), "detonation: out-of-order chunk rejected");
  antimal::SampleReassembler r3(4);
  antimal::SampleChunk tooBig{0, {1, 2, 3, 4, 5}};
  Expect(!r3.Add(tooBig), "detonation: overflowing chunk rejected");
  antimal::SampleReassembler r4(8ull * 1024 * 1024 + 1, 8ull * 1024 * 1024);
  antimal::SampleChunk anyChunk{0, {1}};
  Expect(!r4.Add(anyChunk), "detonation: oversized job rejected by cap");

  // A SampleChunk payload shorter than the 4-byte offset header is rejected.
  Expect(!antimal::ParseSampleChunkPayload({0x01, 0x02}).has_value(),
         "detonation: truncated SampleChunk payload rejected");
}

void TestNetworkTelemetry() {
  antimal::TcpConnection conn;
  conn.pid = 1000;
  conn.localAddress = "10.0.2.15";
  conn.localPort = 49200;
  conn.remoteAddress = "93.184.216.34";
  conn.remotePort = 443;
  conn.state = "ESTABLISHED";
  antimal::TcpSnapshot withConn;
  withConn[antimal::TcpConnectionKey(conn)] = conn;

  // Baseline: existing connections become network.connection events.
  auto baseline = antimal::DiffTcpConnections({}, withConn, true, 64, 64);
  Expect(baseline.size() == 1 && baseline[0].action == "network.connection" &&
             baseline[0].category == "network" &&
             baseline[0].target == "93.184.216.34:443" &&
             baseline[0].processId == 1000,
         "network: baseline emits network.connection with remote target");

  // A new connection appears -> network.connect (what the sample reaches out to).
  antimal::TcpConnection dns;
  dns.pid = 1000;
  dns.localAddress = "10.0.2.15";
  dns.localPort = 50000;
  dns.remoteAddress = "1.1.1.1";
  dns.remotePort = 53;
  dns.state = "SYN_SENT";
  antimal::TcpSnapshot both = withConn;
  both[antimal::TcpConnectionKey(dns)] = dns;
  auto connectEvents = antimal::DiffTcpConnections(withConn, both, false, 64, 64);
  Expect(connectEvents.size() == 1 &&
             connectEvents[0].action == "network.connect" &&
             connectEvents[0].target == "1.1.1.1:53",
         "network: new connection emits network.connect");

  // A connection disappears -> network.close (uncapped).
  auto closeEvents = antimal::DiffTcpConnections(both, withConn, false, 64, 64);
  Expect(closeEvents.size() == 1 && closeEvents[0].action == "network.close" &&
             closeEvents[0].target == "1.1.1.1:53",
         "network: dropped connection emits network.close");

  // The identity key ignores state, so a SYN_SENT->ESTABLISHED transition is not
  // mistaken for a close + reopen.
  antimal::TcpConnection synced = conn;
  synced.state = "SYN_SENT";
  Expect(antimal::TcpConnectionKey(conn) == antimal::TcpConnectionKey(synced),
         "network: connection identity key is state-independent");
}

void TestRegistryTelemetry() {
  antimal::RegistrySnapshot prev, cur;
  prev["HKLM\\...\\Run\\legit"] = "C:\\Windows\\legit.exe";
  cur["HKLM\\...\\Run\\legit"] = "C:\\Windows\\legit.exe";
  cur["HKCU\\...\\Run\\evil"] = "C:\\Users\\x\\AppData\\evil.exe";

  // Baseline: existing autostart values become registry.value events.
  auto base = antimal::DiffRegistrySnapshots({}, cur, true, 64, 64);
  Expect(base.size() == 2 && base[0].action == "registry.value" &&
             base[0].category == "registry",
         "registry: baseline emits registry.value");

  // A new persistence value -> registry.set with its data.
  auto delta = antimal::DiffRegistrySnapshots(prev, cur, false, 64, 64);
  Expect(delta.size() == 1 && delta[0].action == "registry.set" &&
             delta[0].target == "HKCU\\...\\Run\\evil" &&
             delta[0].details["data"] == "C:\\Users\\x\\AppData\\evil.exe",
         "registry: new persistence value -> registry.set");

  // A changed value (hijack) -> registry.set with the new data.
  antimal::RegistrySnapshot changed = prev;
  changed["HKLM\\...\\Run\\legit"] = "C:\\hijacked.exe";
  auto chg = antimal::DiffRegistrySnapshots(prev, changed, false, 64, 64);
  Expect(chg.size() == 1 && chg[0].action == "registry.set" &&
             chg[0].details["data"] == "C:\\hijacked.exe",
         "registry: changed value -> registry.set");

  // A removed value -> registry.delete.
  auto del = antimal::DiffRegistrySnapshots(cur, prev, false, 64, 64);
  Expect(del.size() == 1 && del[0].action == "registry.delete" &&
             del[0].target == "HKCU\\...\\Run\\evil",
         "registry: removed value -> registry.delete");
}

void TestFileSystemTelemetry() {
  antimal::FileSnapshot prev, cur;
  prev["C:\\Temp\\a.txt"] = antimal::FileMeta{10, 100};
  cur["C:\\Temp\\a.txt"] = antimal::FileMeta{10, 100};
  cur["C:\\Temp\\dropped.exe"] = antimal::FileMeta{2048, 200};

  // A new file -> file.create with its size.
  auto delta = antimal::DiffFileSnapshots(prev, cur, false, 64, 64);
  Expect(delta.size() == 1 && delta[0].action == "file.create" &&
             delta[0].category == "file" &&
             delta[0].target == "C:\\Temp\\dropped.exe" &&
             delta[0].details["size"] == "2048",
         "file: new file -> file.create");

  // A size change -> file.modify.
  antimal::FileSnapshot resized = prev;
  resized["C:\\Temp\\a.txt"] = antimal::FileMeta{99, 100};
  auto mod = antimal::DiffFileSnapshots(prev, resized, false, 64, 64);
  Expect(mod.size() == 1 && mod[0].action == "file.modify",
         "file: size change -> file.modify");

  // An mtime change -> file.modify.
  antimal::FileSnapshot touched = prev;
  touched["C:\\Temp\\a.txt"] = antimal::FileMeta{10, 999};
  auto tch = antimal::DiffFileSnapshots(prev, touched, false, 64, 64);
  Expect(tch.size() == 1 && tch[0].action == "file.modify",
         "file: mtime change -> file.modify");

  // A removed file -> file.delete.
  auto del = antimal::DiffFileSnapshots(cur, prev, false, 64, 64);
  Expect(del.size() == 1 && del[0].action == "file.delete" &&
             del[0].target == "C:\\Temp\\dropped.exe",
         "file: removed file -> file.delete");

  // Baseline is capped (a huge %TEMP% can't flood the channel).
  auto baseline = antimal::DiffFileSnapshots({}, cur, true, 1, 64);
  Expect(baseline.size() == 1 && baseline[0].action == "file.observed",
         "file: baseline is capped");
}

void TestPacketInspector() {
  // Frame builders. IPv4 total-length is left 0 (the parser clamps to the
  // captured length), so we only need structurally valid headers + payload.
  auto eth = [](std::vector<uint8_t> &f, uint16_t ethertype) {
    for (int i = 0; i < 12; ++i) f.push_back(0);  // dst+src MAC
    f.push_back(static_cast<uint8_t>(ethertype >> 8));
    f.push_back(static_cast<uint8_t>(ethertype & 0xFF));
  };
  auto ipv4 = [](std::vector<uint8_t> &f, uint8_t proto,
                 std::array<uint8_t, 4> dst) {
    const uint8_t hdr[] = {0x45, 0,  0,  0,  0, 0, 0, 0, 64, proto, 0, 0,
                           10,   0,  2,  15};  // ver/ihl..proto..src 10.0.2.15
    for (uint8_t b : hdr) f.push_back(b);
    for (uint8_t b : dst) f.push_back(b);
  };

  // DNS query for example.com (UDP -> :53).
  std::vector<uint8_t> dns;
  eth(dns, 0x0800);
  ipv4(dns, 17, {8, 8, 8, 8});
  const uint8_t udp[] = {0xC0, 0x00, 0x00, 0x35, 0, 0, 0, 0};  // dst port 53
  for (uint8_t b : udp) dns.push_back(b);
  for (int i = 0; i < 12; ++i) dns.push_back(0);  // DNS header
  for (const char *lbl : {"example", "com"}) {
    dns.push_back(static_cast<uint8_t>(std::strlen(lbl)));
    for (const char *p = lbl; *p; ++p) dns.push_back(static_cast<uint8_t>(*p));
  }
  dns.push_back(0);  // root label
  const uint8_t qtc[] = {0x00, 0x01, 0x00, 0x01};  // qtype/qclass
  for (uint8_t b : qtc) dns.push_back(b);
  auto dnsEvents = antimal::InspectEthernetFrame(dns.data(), dns.size());
  Expect(dnsEvents.size() == 1 && dnsEvents[0].action == "network.dns" &&
             dnsEvents[0].target == "example.com" &&
             dnsEvents[0].category == "network",
         "packet: DNS query -> network.dns example.com");

  // HTTP GET to :80 with a Host header.
  std::vector<uint8_t> http;
  eth(http, 0x0800);
  ipv4(http, 6, {1, 2, 3, 4});
  const uint8_t tcp80[] = {0xC0, 0x00, 0x00, 0x50, 0, 0, 0, 0, 0, 0,
                           0,    0,    0x50, 0x18, 0, 0, 0, 0, 0, 0};
  for (uint8_t b : tcp80) http.push_back(b);  // dst 80, PSH+ACK, 20-byte hdr
  const std::string req =
      "GET /malware.exe HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";
  for (char c : req) http.push_back(static_cast<uint8_t>(c));
  auto httpEvents = antimal::InspectEthernetFrame(http.data(), http.size());
  Expect(httpEvents.size() == 1 && httpEvents[0].action == "network.http" &&
             httpEvents[0].target == "evil.example.com/malware.exe" &&
             httpEvents[0].details["method"] == "GET" &&
             httpEvents[0].details["host"] == "evil.example.com",
         "packet: HTTP GET -> network.http with method/host/path");

  // Bare TCP SYN to :443 -> a connection attempt.
  std::vector<uint8_t> syn;
  eth(syn, 0x0800);
  ipv4(syn, 6, {93, 184, 216, 34});
  const uint8_t tcpSyn[] = {0xC0, 0x00, 0x01, 0xBB, 0, 0, 0, 0, 0, 0,
                            0,    0,    0x50, 0x02, 0, 0, 0, 0, 0, 0};
  for (uint8_t b : tcpSyn) syn.push_back(b);  // dst 443, SYN
  auto synEvents = antimal::InspectEthernetFrame(syn.data(), syn.size());
  Expect(synEvents.size() == 1 && synEvents[0].action == "network.connect" &&
             synEvents[0].target == "93.184.216.34:443",
         "packet: TCP SYN -> network.connect");

  // Malformed / non-IPv4 frames yield nothing (hardened against guest bytes).
  Expect(antimal::InspectEthernetFrame(nullptr, 0).empty(),
         "packet: null frame -> no events");
  std::vector<uint8_t> tiny = {1, 2, 3};
  Expect(antimal::InspectEthernetFrame(tiny.data(), tiny.size()).empty(),
         "packet: short frame -> no events");
  std::vector<uint8_t> arp;
  eth(arp, 0x0806);
  arp.resize(60, 0);
  Expect(antimal::InspectEthernetFrame(arp.data(), arp.size()).empty(),
         "packet: non-IPv4 (ARP) ignored");
}

void TestE1000Device() {
  antimal::hv::E1000Device nic;
  const uint64_t kMmio = 0xF0000000ull;
  nic.SetMmioBase(kMmio);

  // A 4 KiB "guest RAM" window the device DMAs against.
  const uint64_t baseGpa = 0x10000ull;
  std::vector<uint8_t> mem(4096, 0);
  nic.SetDmaMemory([&](uint64_t gpa, std::size_t len) -> uint8_t * {
    if (gpa < baseGpa || gpa + len > baseGpa + mem.size()) return nullptr;
    return mem.data() + static_cast<size_t>(gpa - baseGpa);
  });
  std::vector<uint8_t> captured;
  nic.SetTxHandler([&](const uint8_t *f, std::size_t len) {
    captured.assign(f, f + len);
  });

  // The frame to transmit, at baseGpa+0x200.
  std::vector<uint8_t> frame;
  for (int i = 0; i < 64; ++i) frame.push_back(static_cast<uint8_t>(i + 1));
  const uint64_t bufGpa = baseGpa + 0x200;
  for (size_t i = 0; i < frame.size(); ++i) mem[0x200 + i] = frame[i];

  // Legacy TX descriptor 0 at baseGpa+0: buffer addr(8) | length(2) | _ | CMD.
  for (int i = 0; i < 8; ++i)
    mem[i] = static_cast<uint8_t>((bufGpa >> (i * 8)) & 0xFF);
  mem[8] = static_cast<uint8_t>(frame.size() & 0xFF);
  mem[9] = static_cast<uint8_t>((frame.size() >> 8) & 0xFF);
  mem[11] = 0x09;  // CMD = EOP | RS

  auto w = [&](uint32_t reg, uint32_t val) {
    nic.OnWrite(kMmio + reg, 4, val);
  };
  w(0x3800, static_cast<uint32_t>(baseGpa & 0xFFFFFFFF));  // TDBAL
  w(0x3804, static_cast<uint32_t>(baseGpa >> 32));         // TDBAH
  w(0x3808, 16 * 8);  // TDLEN = 8 descriptors
  w(0x3810, 0);       // TDH
  w(0x00D0, 0x01);    // IMS: enable TXDW
  w(0x3818, 1);       // TDT = 1 -> transmit descriptor 0

  Expect(captured == frame, "e1000: TX descriptor frame DMA'd to the handler");
  Expect(nic.FramesTransmitted() == 1 &&
             nic.BytesTransmitted() == frame.size(),
         "e1000: transmit counters advance");
  Expect(nic.InterruptPending(),
         "e1000: TXDW interrupt latched (IMS enabled)");
  Expect((mem[12] & 0x01) != 0, "e1000: descriptor DD status written back");

  // EEPROM MAC read (EERD): START + addr 0 -> DONE + data word.
  w(0x0014, 0x00000001);
  uint64_t eerd = 0;
  nic.OnRead(kMmio + 0x0014, 4, &eerd);
  Expect((eerd & 0x10) != 0, "e1000: EERD returns DONE");
  Expect((eerd >> 16) != 0, "e1000: EERD returns a nonzero MAC word");

  // STATUS reports link up so the driver proceeds past init.
  uint64_t status = 0;
  nic.OnRead(kMmio + 0x0008, 4, &status);
  Expect((status & 0x2) != 0, "e1000: STATUS link-up bit set");

  // RX ring registers round-trip (the driver sets up the RX ring during init;
  // storing them lets RX init complete so the driver starts and reaches TX).
  w(0x2800, 0xCAFE0000);  // RDBAL
  w(0x2808, 0x80);        // RDLEN
  uint64_t rdbal = 0;
  nic.OnRead(kMmio + 0x2800, 4, &rdbal);
  Expect(rdbal == 0xCAFE0000, "e1000: RX ring base (RDBAL) round-trips");

  // Enabling Link-Status-Change in IMS announces link-up via one interrupt, so
  // the driver brings the interface up.
  antimal::hv::E1000Device nic2;
  nic2.SetMmioBase(kMmio);
  nic2.OnWrite(kMmio + 0x00D0, 4, 0x04);  // IMS: enable LSC
  Expect(nic2.InterruptPending(),
         "e1000: enabling LSC announces link-up (interrupt asserted)");
  uint64_t icr = 0;
  nic2.OnRead(kMmio + 0x00C0, 4, &icr);
  Expect((icr & 0x04) != 0, "e1000: ICR reports Link-Status-Change cause");

  // EEPROM checksum: all 64 words must sum to 0xBABA or the Windows driver
  // rejects the EEPROM and never binds.
  {
    antimal::hv::E1000Device nic3;
    nic3.SetMmioBase(kMmio);
    uint16_t sum = 0;
    for (uint32_t addr = 0; addr < 64; ++addr) {
      nic3.OnWrite(kMmio + 0x0014, 4, (addr << 8) | 0x1);  // EERD START + addr
      uint64_t v = 0;
      nic3.OnRead(kMmio + 0x0014, 4, &v);
      sum = static_cast<uint16_t>(sum + ((v >> 16) & 0xFFFF));
    }
    Expect(sum == 0xBABA,
           "e1000: EEPROM words sum to 0xBABA (driver accepts the checksum)");
  }

  // MDIC PHY access: a read of PHY status register (1) completes (Ready) and
  // reports link up, so the driver's PHY probe succeeds.
  {
    antimal::hv::E1000Device nic4;
    nic4.SetMmioBase(kMmio);
    nic4.OnWrite(kMmio + 0x0020, 4, (2u << 26) | (1u << 21) | (1u << 16));
    uint64_t mdic = 0;
    nic4.OnRead(kMmio + 0x0020, 4, &mdic);
    Expect((mdic & (1u << 28)) != 0, "e1000: MDIC read completes (Ready set)");
    Expect((mdic & 0x04) != 0, "e1000: PHY status register reports link up");
  }
}

void TestNicPciConfig() {
  antimal::hv::PcIoDevices pc;
  pc.SetNicPresent(true);
  auto cfg = [&](uint8_t dev, uint8_t func, uint8_t reg) -> uint32_t {
    const uint32_t addr = 0x80000000u | (static_cast<uint32_t>(dev) << 11) |
                          (static_cast<uint32_t>(func) << 8) | (reg & 0xFC);
    pc.OnWrite(0xCF8, addr, 4);
    return pc.OnRead(0xCFC, 4);
  };
  Expect(cfg(4, 0, 0x00) == 0x100E8086u,
         "nic pci: device 4 is Intel 8086:100E");
  Expect((cfg(4, 0, 0x08) >> 8) == 0x020000u,
         "nic pci: class 0x02 subclass 0x00 (ethernet)");

  // BAR0 sizing: write all-ones -> read back the 128 KiB size mask.
  const uint32_t bar = 0x80000000u | (4u << 11) | 0x10u;
  pc.OnWrite(0xCF8, bar, 4);
  pc.OnWrite(0xCFC, 0xFFFFFFFFu, 4);
  pc.OnWrite(0xCF8, bar, 4);
  Expect(pc.OnRead(0xCFC, 4) == 0xFFFE0000u,
         "nic pci: BAR0 sizes to 128 KiB (mask 0xFFFE0000)");

  // Assign a base -> latched + flagged dirty for the device to follow.
  pc.OnWrite(0xCF8, bar, 4);
  pc.OnWrite(0xCFC, 0xF0000000u, 4);
  Expect(pc.NicBar0Base() == 0xF0000000ull, "nic pci: BAR0 base latched");
  Expect(pc.ConsumeNicBar0Dirty(), "nic pci: BAR0 assignment flagged dirty");

  // Default (no SetNicPresent) -> device 4 reads all-ones, i.e. absent, so the
  // default boot enumerates exactly as before.
  antimal::hv::PcIoDevices absent;
  absent.OnWrite(0xCF8, 0x80000000u | (4u << 11), 4);
  Expect(absent.OnRead(0xCFC, 4) == 0xFFFFFFFFu,
         "nic pci: absent by default (no NIC enumerated)");
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

  // Cache round-trip. Regression: cache reads used to dispatch on a
  // "sourceName" field the raw API bodies never contain, so every cached hit
  // decoded to an empty IntelHit. The cache now stores parsed hits per line.
  std::vector<antimal::IntelHit> hits;
  {
    antimal::IntelHit a;
    a.source = antimal::IntelSource::MalwareBazaar;
    a.sourceName = "malwarebazaar";
    a.known = true;
    a.family = "AgentTesla";
    a.tags = {"AgentTesla", "stealer"};
    hits.push_back(a);
    antimal::IntelHit b;
    b.source = antimal::IntelSource::VirusTotal;
    b.sourceName = "virustotal";
    b.known = true;
    b.family = "trojan.formbook";
    b.detectionRatio = 35;
    b.totalScanners = 70;
    hits.push_back(b);
  }
  const auto blob = antimal::SerializeIntelCache(hits);
  const auto round = antimal::ParseIntelCache(blob);
  Expect(round.size() == 2, "intel cache: round-trip preserves hit count");
  Expect(round.size() == 2 && round[0].sourceName == "malwarebazaar" &&
             round[0].source == antimal::IntelSource::MalwareBazaar &&
             round[0].known && round[0].family == "AgentTesla" &&
             round[0].tags.size() == 2,
         "intel cache: malwarebazaar hit round-trips with source + fields");
  Expect(round.size() == 2 && round[1].sourceName == "virustotal" &&
             round[1].source == antimal::IntelSource::VirusTotal &&
             round[1].detectionRatio == 35 && round[1].totalScanners == 70 &&
             round[1].family == "trojan.formbook",
         "intel cache: virustotal hit round-trips with source + fields");

  // End-to-end: LookupHash serves a fresh on-disk cache instead of the network.
  {
    const auto cacheDir =
        std::filesystem::temp_directory_path() / "antimal_intel_cache_test";
    std::error_code ec;
    std::filesystem::remove_all(cacheDir, ec);
    std::filesystem::create_directories(cacheDir, ec);
    const std::string sha(64, 'a');
    antimal::WriteTextFile(cacheDir / (sha + ".json"), blob);
    antimal::IntelLookupConfig cc;
    cc.enabled = true;
    cc.cacheDir = cacheDir;
    auto cachedResult = antimal::LookupHash(sha, cc);
    Expect(cachedResult.fromCache, "intel cache: LookupHash served from cache");
    Expect(cachedResult.hits.size() == 2 &&
               cachedResult.hits[0].family == "AgentTesla",
           "intel cache: cached hits carry parsed fields (not empty)");
    std::filesystem::remove_all(cacheDir, ec);
  }
}

void TestHttpUrlEncode() {
  Expect(antimal::UrlEncode("a b/c") == "a%20b%2Fc", "url encode space + slash");
  Expect(antimal::UrlEncode("simple") == "simple", "url encode passthrough");
}

void TestFramebufferVisiblePixels() {
  std::array<uint8_t, 4 * 4 * 4> pixels{};
  Expect(!antimal::FramebufferHasVisiblePixels(pixels.data(), 4, 4, 4),
         "framebuffer visibility: blank surface rejected");
  pixels[2] = 0x7F;
  Expect(antimal::FramebufferHasVisiblePixels(pixels.data(), 4, 4, 4),
         "framebuffer visibility: non-zero color accepted");

  const auto path = TempRoot() / "framebuffer.png";
  Expect(antimal::EncodeFramebufferPng(path, pixels.data(), 4, 4, 4),
         "framebuffer png: nonblank surface encoded");
  std::error_code ec;
  Expect(std::filesystem::exists(path, ec) &&
             std::filesystem::file_size(path, ec) > 0,
         "framebuffer png: file written");
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
  Expect(report.dynamicSummary.ideCommandsIssued > 0 ||
             report.dynamicSummary.bootStage == "firmware",
         "boot attempt: blank synthetic disk either exercises IDE or remains a firmware probe");
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

void TestJsonValueParser() {
  auto v = antimal::ParseJson(
      R"({"cmd":"scan.file","reqId":7,"ok":true,"args":{"path":"C:\\a.exe"}})");
  Expect(v.has_value(), "ParseJson: valid object parses");
  Expect(v->IsObject(), "ParseJson: root is object");
  Expect(v->At("cmd").AsString() == "scan.file", "ParseJson: string field");
  Expect(v->At("reqId").AsInt64() == 7, "ParseJson: number field");
  Expect(v->At("ok").AsBool(), "ParseJson: bool field");
  Expect(v->At("args").At("path").AsString() == "C:\\a.exe",
         "ParseJson: nested object + unescaped backslash");
  Expect(!antimal::ParseJson("{bad json").has_value(),
         "ParseJson: malformed rejected");
  Expect(!antimal::ParseJson("").has_value(), "ParseJson: empty rejected");
  Expect(v->At("missing").IsNull(), "ParseJson: missing field is Null");
}

void TestBridgeRouter() {
  antimal::BridgeRouter router;
  router.Register("ping", [](const antimal::JsonValue &) {
    return std::string(R"({"pong":true})");
  });
  const auto reply = router.Handle(R"({"cmd":"ping","reqId":42,"args":{}})");
  Expect(reply.find("\"reqId\":42") != std::string::npos, "router: echoes reqId");
  Expect(reply.find("\"ok\":true") != std::string::npos, "router: ok=true");
  Expect(reply.find("\"pong\":true") != std::string::npos,
         "router: result embedded");
  const auto unknown = router.Handle(R"({"cmd":"nope","reqId":1,"args":{}})");
  Expect(unknown.find("\"ok\":false") != std::string::npos,
         "router: unknown cmd -> ok=false");
  const auto malformed = router.Handle("not json");
  Expect(malformed.find("\"ok\":false") != std::string::npos,
         "router: malformed envelope -> ok=false");
  router.Register("boom", [](const antimal::JsonValue &) -> std::string {
    throw std::runtime_error("kaboom");
  });
  const auto boom = router.Handle(R"({"cmd":"boom","reqId":9,"args":{}})");
  Expect(boom.find("\"ok\":false") != std::string::npos,
         "router: handler exception contained");
}

// Security hardening (live-sandbox-console P6): the bridge JSON parser + router
// parse UI-controlled input, so they must never crash, stack-overflow, or
// return a malformed reply on adversarial bytes. This is a deterministic
// robustness/fuzz harness (no RNG -> reproducible).
void TestBridgeFuzz() {
  using antimal::BridgeRouter;
  using antimal::JsonValue;
  using antimal::ParseJson;

  BridgeRouter router;
  router.Register("echo", [](const JsonValue &args) {
    // Touches args the way real handlers do; At() is null-safe.
    return std::string("{\"len\":") +
           std::to_string(args.At("path").AsString().size()) + "}";
  });

  // 1) Depth cap: pathological nesting is rejected, never a stack overflow.
  {
    std::string deepArr(5000, '[');
    Expect(!ParseJson(deepArr).has_value(),
           "fuzz: 5000-deep array rejected (depth cap, no overflow)");
    std::string deepObj;
    for (int i = 0; i < 5000; ++i) {
      deepObj += "{\"a\":";
    }
    Expect(!ParseJson(deepObj).has_value(),
           "fuzz: 5000-deep object rejected (depth cap)");
  }

  // 2) Size cap: oversized input is rejected before parsing.
  {
    std::string huge = "\"" + std::string(9 * 1024 * 1024, 'a') + "\"";
    Expect(!ParseJson(huge).has_value(), "fuzz: 9MiB input rejected (size cap)");
  }

  // 3) Adversarial seeds: parse-or-reject without crashing; router ALWAYS
  //    returns a well-formed reply object carrying a bool ok + reqId.
  const char *seeds[] = {
      "", " ", "\t\n", "null", "true", "0", "-", "1e999", "NaN", "[", "]",
      "{", "}", "[,]", "{,}", "{:}", "{\"a\"}", "{\"a\":}", "\"unterminated",
      "\"\\u00\"", "\"\\uZZZZ\"", "\"\\x41\"", "\"\\\"", "[1,2,3,]", "{\"a\":1,}",
      "{\"cmd\":\"echo\",\"reqId\":1,\"args\":{\"path\":\"\\u0000\"}}",
      "{\"cmd\":1,\"reqId\":\"x\"}", "{\"reqId\":[]}", "{\"cmd\":null}",
      "{\"cmd\":\"echo\",\"reqId\":99,\"args\":{\"path\":12345}}",
      "\xff\xfe\x01\x02", "{\"a\":\"\xc3\x28\"}"};
  for (const char *s : seeds) {
    (void)ParseJson(std::string(s)); // must not throw/crash
    const std::string reply = router.Handle(std::string(s));
    const auto pr = ParseJson(reply);
    Expect(pr.has_value() && pr->IsObject(),
           "fuzz: router reply is a valid JSON object");
    Expect(pr->Has("ok") && pr->At("ok").IsBool(), "fuzz: reply has bool ok");
    Expect(pr->Has("reqId"), "fuzz: reply has reqId");
  }

  // 4) Deterministic byte-mutation fuzz over a valid envelope (LCG, seeded).
  const std::string base =
      R"({"cmd":"echo","reqId":3,"args":{"path":"C:\\Users\\x\\a.exe"}})";
  unsigned long lcg = 0x12345678u;
  auto next = [&lcg]() {
    lcg = lcg * 1103515245u + 12345u;
    return static_cast<unsigned>((lcg >> 16) & 0x7fff);
  };
  int bad = 0;
  for (int iter = 0; iter < 20000; ++iter) {
    std::string m = base;
    const int muts = 1 + static_cast<int>(next() % 6);
    for (int k = 0; k < muts && !m.empty(); ++k) {
      const int op = static_cast<int>(next() % 4);
      const size_t pos = next() % m.size();
      if (op == 0) {
        m[pos] = static_cast<char>(next() & 0xff);
      } else if (op == 1) {
        m.erase(pos, 1 + (next() % 3));
      } else if (op == 2) {
        m.insert(pos, 1, static_cast<char>(next() & 0xff));
      } else {
        m[pos] = m[next() % m.size()];
      }
    }
    (void)ParseJson(m); // must not crash
    const auto pr = ParseJson(router.Handle(m));
    if (!(pr.has_value() && pr->IsObject() && pr->Has("ok"))) {
      ++bad;
    }
  }
  Expect(bad == 0, "fuzz: 20000 mutated envelopes all yield valid replies");
}

// Security hardening (live-sandbox-console P6): the AMCH frame decoder parses
// the host<->guest control channel (COM2 today), i.e. *guest*-controlled bytes.
// A malicious guest must never crash the host decoder, smuggle a malformed
// frame past validation, or force unbounded buffering. Deterministic harness.
void TestHostChannelFuzz() {
  using antimal::hv::HostChannelFrame;
  using antimal::hv::HostChannelMessage;
  using antimal::hv::HostSerialChannel;
  auto makeFrame = [](const std::string &s) {
    return HostSerialChannel::EncodeText(HostChannelMessage::Event, s);
  };
  auto wellFormed = [](const HostChannelFrame &f) {
    const uint16_t t = static_cast<uint16_t>(f.type);
    return t >= 1 && t <= 10 &&
           f.payload.size() <= HostSerialChannel::kMaxPayloadBytes;
  };

  // 1) Byte-at-a-time delivery still decodes exactly one intact frame.
  {
    HostSerialChannel ch;
    const auto enc = makeFrame("hello-guest");
    for (uint8_t b : enc) {
      ch.PushBytes(&b, 1);
    }
    Expect(ch.PendingFrameCount() == 1, "channel fuzz: dribbled frame decodes");
    const auto f = ch.PopFrame();
    Expect(f && f->type == HostChannelMessage::Event &&
               std::string(f->payload.begin(), f->payload.end()) == "hello-guest",
           "channel fuzz: type + payload preserved across byte-at-a-time");
  }

  // 2) Garbage prefix then a valid frame -> magic resync recovers it.
  {
    HostSerialChannel ch;
    const std::vector<uint8_t> junk = {0, 1, 2, 'A', 'M', 0xFF, 'A', 'M', 'C', 0};
    ch.PushBytes(junk);
    ch.PushBytes(makeFrame("after-junk"));
    const auto f = ch.PopFrame();
    Expect(f && std::string(f->payload.begin(), f->payload.end()) == "after-junk",
           "channel fuzz: resync past leading garbage");
  }

  // 3) Corrupted payload (checksum mismatch) -> discarded, not delivered.
  {
    HostSerialChannel ch;
    auto enc = makeFrame("tamper");
    enc[enc.size() - 1] ^= 0xFF;
    ch.PushBytes(enc);
    Expect(ch.PendingFrameCount() == 0, "channel fuzz: bad checksum discarded");
  }

  // 4) Header claims max payload but stream is truncated -> waits, no crash,
  //    no huge allocation (the bytes never arrive).
  {
    HostSerialChannel ch;
    std::vector<uint8_t> hdr = {'A', 'M', 'C', 'H', 1, 0, 3, 0,
                                0x00, 0x00, 0x00, 0x01, // length = 16 MiB (== cap)
                                0,    0,    0,    0,    // checksum
                                'x'};                   // 1 of 16 MiB payload bytes
    ch.PushBytes(hdr);
    Expect(ch.PendingFrameCount() == 0,
           "channel fuzz: truncated max-length frame waits without crash");
  }

  // 5) Mutation fuzz over a valid frame fed in random chunk sizes: never crash;
  //    nothing malformed is ever delivered.
  {
    const auto base = makeFrame("C:\\Windows\\System32\\evil.dll");
    unsigned long lcg = 0xABCDEF01u;
    auto next = [&lcg]() {
      lcg = lcg * 1103515245u + 12345u;
      return static_cast<unsigned>((lcg >> 16) & 0x7fff);
    };
    int malformed = 0;
    for (int iter = 0; iter < 20000; ++iter) {
      std::vector<uint8_t> m = base;
      const int muts = 1 + static_cast<int>(next() % 5);
      for (int k = 0; k < muts && !m.empty(); ++k) {
        const int op = static_cast<int>(next() % 3);
        const size_t pos = next() % m.size();
        if (op == 0) {
          m[pos] = static_cast<uint8_t>(next() & 0xff);
        } else if (op == 1 && m.size() > 1) {
          m.erase(m.begin() + static_cast<long>(pos));
        } else {
          m.insert(m.begin() + static_cast<long>(pos),
                   static_cast<uint8_t>(next() & 0xff));
        }
      }
      HostSerialChannel ch;
      size_t off = 0;
      while (off < m.size()) {
        const size_t chunk = std::min<size_t>(1 + (next() % 7), m.size() - off);
        ch.PushBytes(m.data() + off, chunk);
        off += chunk;
      }
      while (const auto f = ch.PopFrame()) {
        if (!wellFormed(*f)) {
          ++malformed;
        }
      }
    }
    Expect(malformed == 0,
           "channel fuzz: 20000 mutated frames -> no malformed frame delivered");
  }

  // 6) A long pure-random byte stream never crashes nor smuggles a frame.
  {
    HostSerialChannel ch;
    unsigned long lcg = 0x13579BDFu;
    auto next = [&lcg]() {
      lcg = lcg * 1103515245u + 12345u;
      return static_cast<uint8_t>((lcg >> 16) & 0xff);
    };
    int malformed = 0;
    for (int i = 0; i < 120000; ++i) {
      const uint8_t b = next();
      ch.PushBytes(&b, 1);
      while (const auto f = ch.PopFrame()) {
        if (!wellFormed(*f)) {
          ++malformed;
        }
      }
    }
    Expect(malformed == 0,
           "channel fuzz: random byte stream delivers no malformed frame");
  }
}

// End-to-end test of the live-sandbox-console telemetry channel data path (the
// project's main goal), VM-free: GuestAgent-side encode (SerializeEventJsonLine
// + AMCH frame) -> COM2 wire bytes -> host-side decode (HostSerialChannel) ->
// events.jsonl (EventJournalWriter) -> the UI tail (EventJournalTailer, what
// run.watch uses). Asserts frame routing, journaling, field fidelity across the
// whole round-trip, and incremental-tail semantics. Only the GuestAgent running
// *inside* the guest remains to close the loop (the VM-dependent frontier).
void TestChannelTelemetryRoundTrip() {
  using antimal::hv::HostChannelMessage;
  using antimal::hv::HostSerialChannel;

  // 1) GuestAgent side: a realistic COM2 byte stream (Hello + N Events +
  //    ReportComplete), exactly as AntiMal.GuestAgent.exe emits.
  std::vector<uint8_t> wire;
  auto append = [&](const std::vector<uint8_t> &f) {
    wire.insert(wire.end(), f.begin(), f.end());
  };
  append(HostSerialChannel::EncodeText(HostChannelMessage::Hello,
                                       "AntiMal.GuestAgent hello; pid=4242"));
  const int kEvents = 5;
  for (int i = 0; i < kEvents; ++i) {
    antimal::EventRecord ev;
    ev.timestampUtc = "2026-05-31T06:00:0" + std::to_string(i) + "Z";
    ev.source = "GuestAgent";
    ev.category = "process";
    ev.action = "proc.create";
    ev.processId = static_cast<uint32_t>(1000 + i);
    ev.imagePath = "C:\\Windows\\System32\\evil" + std::to_string(i) + ".exe";
    ev.target = "child" + std::to_string(i);
    ev.mitre = "T1059";
    append(HostSerialChannel::EncodeText(HostChannelMessage::Event,
                                         antimal::SerializeEventJsonLine(ev)));
  }
  append(HostSerialChannel::EncodeText(HostChannelMessage::ReportComplete,
                                       "status=ok\n"));

  // 2) Host side: decode the stream and journal Event frames (mirrors the
  //    orchestrator's host-channel processing).
  std::error_code ec;
  const auto tmp = std::filesystem::temp_directory_path() / "antimal-chan-rt";
  std::filesystem::create_directories(tmp, ec);
  const auto journalPath = tmp / "events.jsonl";
  std::filesystem::remove(journalPath, ec);
  int helloSeen = 0, reportComplete = 0, journaled = 0;
  {
    HostSerialChannel channel;
    channel.PushBytes(wire);
    antimal::EventJournalWriter writer(journalPath);
    while (const auto frame = channel.PopFrame()) {
      const std::string payload(frame->payload.begin(), frame->payload.end());
      if (frame->type == HostChannelMessage::Hello) {
        ++helloSeen;
      } else if (frame->type == HostChannelMessage::ReportComplete) {
        ++reportComplete;
      } else if (frame->type == HostChannelMessage::Event) {
        writer.Append(antimal::ParseEventJsonLine(payload));
        ++journaled;
      }
    }
  } // writer flushes + closes here.
  Expect(helloSeen == 1, "channel pipeline: Hello frame decoded");
  Expect(reportComplete == 1, "channel pipeline: ReportComplete decoded");
  Expect(journaled == kEvents, "channel pipeline: all Event frames journaled");

  // 3) UI side (what run.watch tails): confirm fidelity + incremental semantics.
  antimal::EventJournalTailer tailer(journalPath);
  const auto pulled = tailer.PullNew();
  Expect(static_cast<int>(pulled.size()) == kEvents,
         "channel pipeline: tailer reads every journaled event");
  const bool fieldsOk =
      !pulled.empty() && pulled.front().action == "proc.create" &&
      pulled.front().source == "GuestAgent" && pulled.back().mitre == "T1059" &&
      pulled.back().processId == static_cast<uint32_t>(1000 + kEvents - 1);
  Expect(fieldsOk,
         "channel pipeline: fields survive encode->decode->journal->tail");
  Expect(tailer.PullNew().empty(),
         "channel pipeline: incremental tail returns nothing when idle");
  std::filesystem::remove(journalPath, ec);
}

// Regression guard for the in-loop KD pipe relay (KdPipeBridge::Pump). The live
// timing bug it fixed only reproduces under a real kernel KD handshake, but this
// verifies the bridge relays bytes BOTH directions inline from the caller (no
// CV-woken worker threads) and registers/clears the client via the accept thread.
void TestKdPipeBridgeRelay() {
  const std::wstring pipeName = L"\\\\.\\pipe\\antimal-kd-test-relay";
  antimal::hv::KdPipeBridge bridge(pipeName);
  Expect(bridge.Valid(), "KdPipeBridge: pipe created");
  if (!bridge.Valid()) {
    return;
  }
  // Connect a client; the accept thread accepts on open.
  HANDLE client = INVALID_HANDLE_VALUE;
  for (int i = 0; i < 200 && client == INVALID_HANDLE_VALUE; ++i) {
    client = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                         nullptr, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE) {
      Sleep(5);
    }
  }
  Expect(client != INVALID_HANDLE_VALUE, "KdPipeBridge: test client opened pipe");
  if (client == INVALID_HANDLE_VALUE) {
    return;
  }
  for (int i = 0; i < 400 && !bridge.ClientConnected(); ++i) {
    Sleep(5);
  }
  Expect(bridge.ClientConnected(),
         "KdPipeBridge: accept thread registered client");

  // debugger -> guest: client writes; Pump pulls; ReceiveFromDebugger returns.
  const uint8_t inbytes[] = {0x69, 0x69, 0x69, 0x69, 'A', 'C', 'K'};
  DWORD wrote = 0;
  WriteFile(client, inbytes, sizeof(inbytes), &wrote, nullptr);
  std::vector<uint8_t> got;
  for (int i = 0; i < 400 && got.empty(); ++i) {
    bridge.Pump();
    got = bridge.ReceiveFromDebugger();
    if (got.empty()) {
      Sleep(2);
    }
  }
  Expect(got.size() == sizeof(inbytes) && !got.empty() && got.front() == 0x69 &&
             got.back() == 'K',
         "KdPipeBridge: relayed debugger->guest bytes inline");

  // guest -> debugger: SendToDebugger + Pump; client reads back.
  const uint8_t outbytes[] = {0x30, 0x30, 0x30, 0x30, 1, 2, 3, 4};
  bridge.SendToDebugger(outbytes, sizeof(outbytes));
  bridge.Pump();
  DWORD cavail = 0;
  for (int i = 0; i < 400 && cavail < sizeof(outbytes); ++i) {
    if (!PeekNamedPipe(client, nullptr, 0, nullptr, &cavail, nullptr)) {
      break;
    }
    if (cavail < sizeof(outbytes)) {
      Sleep(2);
    }
  }
  uint8_t rbuf[64] = {0};
  DWORD rd = 0;
  if (cavail > 0) {
    ReadFile(client, rbuf, sizeof(rbuf), &rd, nullptr);
  }
  Expect(rd == sizeof(outbytes) && rbuf[0] == 0x30 && rbuf[7] == 4,
         "KdPipeBridge: relayed guest->debugger bytes inline");

  CloseHandle(client);
}

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
    TestProcessTelemetryDiff();
    TestCom2UartFrames();
    TestSerialThreInterruptIsEdgeTriggered();
    TestSerialRxFifoResetPreservesBacklog();
    TestPs2QueuedInput();
    TestLiveInputProtocol();
    TestLiveFrameShmContract();
    TestTpm2CrbDevice();
    TestAcpiTables();
    TestPcIoPmSleepByteWrites();
    TestPcIoFwCfgAcpiFiles();
    TestPcIoFwCfgE820MemoryInventory();
    TestBochsVbeDataPortAliases();
    TestPcIoVgaBarSizing();
    TestPcIoIdePciResources();
    TestPcIoAhciPciResources();
    TestHpetMmioCounter();
    TestIdeIdentifyDevice();
    TestAhciIdentifyCommand();
    TestAhciReadSectors();
    TestAhciReadDma28HighLba();
    TestAhciAdversarialDma();
    TestDeviceIoFuzz();
    TestJsonValueParser();
    TestBridgeRouter();
    TestBridgeFuzz();
    TestHostChannelFuzz();
    TestChannelTelemetryRoundTrip();
    TestKdPipeBridgeRelay();
    TestIdeReadWriteSectors();
    TestIdeSecondaryNoDeviceStatus();
    TestIdeAssertsInterrupt();
    TestPcIoPicVectorBaseTracking();
    TestIoApicProgramRedirection();
    TestIdeInterruptRetriedUntilDelivered();
    TestMmioBusRouting();
    TestPeParser();
    TestBrowserRisk();
    TestStringExtraction();
    TestIocMining();
    TestTagger();
    TestSubprocessEcho();
    TestSubprocessToolMissing();
    TestEventJournalRoundtrip();
    TestKdSerialDebuggerPackets();
    TestKdSerialDebuggerStatePackets();
    TestKdSerialDebuggerCom1Integration();
    TestReportRoundtripAndFramePaths();
    TestPolicyProbeScriptGuards();
    TestIntelLookupOffline();
    TestDetonationProtocol();
    TestNetworkTelemetry();
    TestRegistryTelemetry();
    TestFileSystemTelemetry();
    TestPacketInspector();
    TestE1000Device();
    TestNicPciConfig();
    TestHttpUrlEncode();
    TestFramebufferVisiblePixels();
    TestScreenshotCaptureBestEffort();
    TestWhpHelloPartition();
    TestWhpMmioReadOnlyTrapsOnWrite();
    TestWhpUnmappedMmioTrapsOnRead();
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
