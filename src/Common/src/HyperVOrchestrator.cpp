#include "antimal/HyperVOrchestrator.h"

#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"
#include "antimal/Screenshot.h"
#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/HostSerialChannel.h"
#include "antimal/hv/VirtualMachine.h"
#include "antimal/hv/WhpHost.h"

#include <Windows.h>
#include <objbase.h>
#include <virtdisk.h>
#include <winioctl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <type_traits>
#include <vector>

namespace antimal {
namespace {

std::string RequestedProvider(const AppConfig &config) {
  auto provider = ToLowerAscii(config.vmProvider);
  if (provider.empty()) {
    provider = "inhouse";
  }
  return provider;
}

std::string SelectProvider(const AppConfig &config) {
  const auto requested = RequestedProvider(config);
  if (requested == "auto" || requested == "local") {
    return "inhouse";
  }
  return requested;
}

struct BootSignalSummary {
  std::vector<std::string> milestones;
  bool guestAgentConnected = false;
  uint32_t guestAgentHeartbeats = 0;
  bool reportComplete = false;
};

bool ContainsText(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

void AddMilestone(BootSignalSummary *summary, std::string milestone) {
  if (!summary) {
    return;
  }
  if (std::find(summary->milestones.begin(), summary->milestones.end(),
                milestone) == summary->milestones.end()) {
    summary->milestones.push_back(std::move(milestone));
  }
}

std::string JoinStrings(const std::vector<std::string> &items,
                        const char *separator) {
  std::ostringstream out;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i) {
      out << separator;
    }
    out << items[i];
  }
  return out.str();
}

BootSignalSummary AnalyzeBootSignals(const std::string &serialOutput,
                                     const std::string &hostChannelOutput) {
  BootSignalSummary signals;
  if (ContainsText(serialOutput, "BOOTX64.EFI")) {
    AddMilestone(&signals, "fallback bootloader opened");
  }
  if (ContainsText(serialOutput, "bootmgfw.efi")) {
    AddMilestone(&signals, "bootmgfw loaded");
  }
  if (ContainsText(serialOutput, "Open 'BCD' Success") ||
      ContainsText(serialOutput, "Open 'BCD'")) {
    AddMilestone(&signals, "BCD opened");
  }
  if (ContainsText(serialOutput, "CiPolicies")) {
    AddMilestone(&signals, "code-integrity policies opened");
  }
  if (ContainsText(serialOutput, "winload.efi") ||
      ContainsText(serialOutput, "winload.exe")) {
    AddMilestone(&signals, "winload opened");
  }
  if (ContainsText(serialOutput, "ResetSystem2") ||
      ContainsText(serialOutput, "ResetType Shutdown")) {
    AddMilestone(&signals, "firmware reset/shutdown requested");
  }

  hv::HostSerialChannel channel;
  channel.PushBytes(reinterpret_cast<const uint8_t *>(hostChannelOutput.data()),
                    hostChannelOutput.size());
  while (const auto frame = channel.PopFrame()) {
    switch (frame->type) {
    case hv::HostChannelMessage::Hello:
      signals.guestAgentConnected = true;
      AddMilestone(&signals, "GuestAgent hello");
      break;
    case hv::HostChannelMessage::Heartbeat:
      signals.guestAgentConnected = true;
      ++signals.guestAgentHeartbeats;
      AddMilestone(&signals, "GuestAgent heartbeat");
      break;
    case hv::HostChannelMessage::ReportComplete:
      signals.guestAgentConnected = true;
      signals.reportComplete = true;
      AddMilestone(&signals, "GuestAgent report complete");
      break;
    default:
      break;
    }
  }
  return signals;
}

std::filesystem::path CurrentExecutableDir() {
  std::wstring buffer(MAX_PATH, L'\0');
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  while (size == buffer.size()) {
    buffer.resize(buffer.size() * 2);
    size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  }
  buffer.resize(size);
  return std::filesystem::path(buffer).parent_path();
}

void WritePlan(const std::filesystem::path &path, const std::vector<std::string> &commands) {
  WriteTextFile(path, [&] {
    std::ostringstream script;
    for (const auto &line : commands) {
      script << line << "\n";
    }
    return script.str();
  }());
}

bool WhpDllPresent() {
  HMODULE module = LoadLibraryW(L"WinHvPlatform.dll");
  if (!module) {
    return false;
  }
  FreeLibrary(module);
  return true;
}

constexpr GUID kMicrosoftVirtualStorageVendor = {
    0xEC984AEC,
    0xA0F9,
    0x47E9,
    {0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B},
};

std::string FormatWin32Error(DWORD error) {
  char buffer[32]{};
  _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x%08lX", error);
  return buffer;
}

VIRTUAL_STORAGE_TYPE StorageTypeForVirtualDisk(
    const std::filesystem::path &path) {
  VIRTUAL_STORAGE_TYPE storage{};
  const auto ext = ToLowerAscii(path.extension().string());
  storage.DeviceId = ext == ".vhd" ? VIRTUAL_STORAGE_TYPE_DEVICE_VHD
                                   : VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;
  return storage;
}

bool IsAllZero(const uint8_t *data, size_t bytes) {
  return std::all_of(data, data + bytes, [](uint8_t b) { return b == 0; });
}

bool SetFilePointerTo(HANDLE handle, uint64_t offset) {
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(offset);
  return SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN) != FALSE;
}

uint64_t QueryVirtualDiskSize(HANDLE handle) {
  GET_VIRTUAL_DISK_INFO info{};
  info.Version = GET_VIRTUAL_DISK_INFO_SIZE;
  ULONG size = sizeof(info);
  ULONG used = 0;
  const DWORD error = GetVirtualDiskInformation(handle, &size, &info, &used);
  if (error != ERROR_SUCCESS) {
    throw std::runtime_error("GetVirtualDiskInformation(size) failed with " +
                             FormatWin32Error(error));
  }
  return info.Size.VirtualSize;
}

bool CreateDifferencingVhdx(const std::filesystem::path &parent,
                            const std::filesystem::path &overlay,
                            std::string *error) {
  EnsureDirectory(overlay.parent_path());
  std::error_code ec;
  std::filesystem::remove(overlay, ec);

  VIRTUAL_STORAGE_TYPE storage{};
  storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
  storage.VendorId = kMicrosoftVirtualStorageVendor;

  CREATE_VIRTUAL_DISK_PARAMETERS params{};
  params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
  CoCreateGuid(&params.Version1.UniqueId);
  params.Version1.MaximumSize = 0;
  params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
  params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
  const auto parentAbsolute = std::filesystem::absolute(parent);
  params.Version1.ParentPath = parentAbsolute.c_str();

  HANDLE handle = INVALID_HANDLE_VALUE;
  const DWORD createError =
      CreateVirtualDisk(&storage, overlay.c_str(), VIRTUAL_DISK_ACCESS_CREATE,
                        nullptr, CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &params,
                        nullptr, &handle);
  if (handle != INVALID_HANDLE_VALUE) {
    CloseHandle(handle);
  }
  if (createError != ERROR_SUCCESS) {
    if (error) {
      *error = "CreateVirtualDisk differencing overlay failed with " +
               FormatWin32Error(createError);
    }
    return false;
  }
  return true;
}

bool CreateRawCowOverlay(const std::filesystem::path &overlay,
                         std::string *error) {
  EnsureDirectory(overlay.parent_path());
  std::error_code ec;
  std::filesystem::remove(overlay, ec);
  try {
    static constexpr char kHeader[] = {'A', 'M', 'C', 'O', 'W', '1', '\r', '\n'};
    std::ofstream out(overlay, std::ios::binary | std::ios::trunc);
    if (!out) {
      if (error) *error = "Unable to create raw COW overlay.";
      return false;
    }
    out.write(kHeader, sizeof(kHeader));
    return out.good();
  } catch (const std::exception &ex) {
    if (error) *error = ex.what();
    return false;
  }
}

std::filesystem::path FindFirmwareBlob() {
  // ANTIMAL_FIRMWARE_NAME lets us point the orchestrator at OVMF-debug.fd (or
  // any other blob in firmware/) without rebuilding. Honors the same search
  // locations as the default path. Empty or unset env var keeps the
  // production default of OVMF.fd.
  std::string firmwareName = "OVMF.fd";
  {
    char buf[260]{};
    size_t needed = 0;
    if (getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_FIRMWARE_NAME") == 0 &&
        needed > 1 && buf[0] != '\0') {
      firmwareName.assign(buf);
    }
  }
  const auto exeDir = CurrentExecutableDir();
  const std::vector<std::filesystem::path> candidates = {
      exeDir / "firmware" / firmwareName,
      exeDir.parent_path().parent_path().parent_path() / "firmware" /
          firmwareName,
      std::filesystem::current_path() / "firmware" / firmwareName,
  };
  for (const auto &candidate : candidates) {
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec)) {
      return candidate;
    }
  }
  return {};
}

std::filesystem::path GuestAgentPath() {
  return CurrentExecutableDir() / "AntiMal.GuestAgent.exe";
}

EventRecord MakeSandboxEvent(const std::string &action,
                             const std::filesystem::path &target,
                             std::map<std::string, std::string> details = {}) {
  EventRecord event;
  event.timestampUtc = UtcNowIso8601();
  event.source = "host-orchestrator";
  event.category = "sandbox";
  event.action = action;
  event.target = PathToUtf8(target);
  event.details = std::move(details);
  return event;
}

void AppendJournalEvent(const std::filesystem::path &journalPath,
                        const EventRecord &event,
                        std::vector<EventRecord> *events) {
  if (events) {
    events->push_back(event);
  }
  try {
    EventJournalWriter writer(journalPath);
    writer.Append(event);
  } catch (...) {
    // The final report still carries the event vector; journal failures should
    // not make staging run host-side code.
  }
}

void WriteErrorReport(const std::filesystem::path &reportPath,
                      const std::string &runId,
                      const std::filesystem::path &samplePath,
                      const std::vector<std::string> &errors,
                      const std::vector<EventRecord> &events = {},
                      const DynamicRunSummary &dynamicSummary = {}) {
  AnalysisReport report;
  report.runId = runId;
  report.samplePath = samplePath;
  report.scannerVerdict = ScanFile(samplePath);
  report.sandboxVerdict = Verdict::Error;
  report.dynamicSummary = dynamicSummary;
  report.events = events;
  report.errors = errors;
  WriteTextFile(reportPath, ToJson(report));
  WriteReportHtml(reportPath.parent_path() / "report.html", report);
}

void WriteStagedReport(const std::filesystem::path &reportPath,
                       const std::string &runId,
                       const std::filesystem::path &samplePath,
                       const std::vector<EventRecord> &events,
                       const DynamicRunSummary &dynamicSummary = {}) {
  AnalysisReport report;
  report.runId = runId;
  report.samplePath = samplePath;
  report.scannerVerdict = ScanFile(samplePath);
  report.sandboxVerdict = Verdict::Error;
  report.dynamicSummary = dynamicSummary;
  report.events = events;
  report.errors.push_back(
      "Dynamic execution not started; this run is staged for the in-house VM path.");
  WriteTextFile(reportPath, ToJson(report));
  WriteReportHtml(reportPath.parent_path() / "report.html", report);
}

hv::VmNetworkMode ToHvNetworkMode(NetworkMode mode) {
  switch (mode) {
  case NetworkMode::Disabled:
    return hv::VmNetworkMode::Disabled;
  case NetworkMode::HostOnly:
    return hv::VmNetworkMode::HostOnly;
  case NetworkMode::Nat:
    return hv::VmNetworkMode::Nat;
  }
  return hv::VmNetworkMode::Disabled;
}

DynamicRunSummary ToDynamicSummary(const hv::VmRunSummary &vm,
                                   NetworkMode networkMode,
                                   const std::filesystem::path &serialLogPath,
                                   const std::filesystem::path &summaryPath) {
  DynamicRunSummary summary;
  summary.started = vm.started;
  summary.completed = vm.completed;
  summary.timedOut = vm.timedOut;
  summary.crashed = vm.crashed || vm.fatal;
  summary.sampleExecuted = false;
  summary.firmwareIdle = vm.idleLoop && !summary.timedOut && !summary.crashed;
  summary.guestAgentConnected = false;
  summary.networkMode = networkMode;
  summary.framesCaptured = vm.framesCaptured;
  summary.eventsCaptured = vm.eventsCaptured;
  summary.artifactsCaptured = vm.artifactsCaptured;
  summary.vcpuExits = static_cast<uint32_t>(std::max(0, vm.steps));
  summary.hltCount = static_cast<uint32_t>(std::max(0, vm.totalHlts));
  summary.ideCommandsIssued = vm.ideCommandsIssued;
  summary.ideIdentifyCommands = vm.ideIdentifyCommands;
  summary.ideReadCommands = vm.ideReadCommands;
  summary.ideWriteCommands = vm.ideWriteCommands;
  summary.ideAbortedCommands = vm.ideAbortedCommands;
  summary.ideSectorsRead = vm.ideSectorsRead;
  summary.ideSectorsWritten = vm.ideSectorsWritten;
  summary.unhandledIo = static_cast<uint32_t>(std::max(0, vm.unhandledIo));
  summary.unhandledMmio = static_cast<uint32_t>(std::max(0, vm.unhandledMmio));
  summary.watchdogCancellations =
      static_cast<uint32_t>(std::max(0, vm.watchdogCancellations));
  summary.serialLogPath = serialLogPath;
  summary.vmSummaryPath = summaryPath;
  if (summary.timedOut) {
    summary.status = "timed out";
  } else if (summary.crashed) {
    summary.status = "boot failed";
  } else if (summary.firmwareIdle) {
    summary.status = "firmware idle before guest";
  } else {
    summary.status = "boot attempted";
  }
  return summary;
}

std::string FormatVmDiagnostics(const hv::VmRunSummary &vm) {
  auto topEntries = [](const auto &items, size_t limit) {
    using ContainerT = std::decay_t<decltype(items)>;
    using K = typename ContainerT::key_type;
    using V = typename ContainerT::mapped_type;
    std::vector<std::pair<K, V>> entries(items.begin(), items.end());
    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });
    if (entries.size() > limit) {
      entries.resize(limit);
    }
    return entries;
  };
  auto writeBytes = [](std::ostringstream &out, const char *name,
                       const uint8_t *bytes, size_t count) {
    out << name << ":";
    for (size_t i = 0; i < count; ++i) {
      char hex[8]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, " %02X", bytes[i]);
      out << hex;
    }
    out << "\n";
  };
  auto writeImage = [](std::ostringstream &out, const char *prefix,
                       const hv::VmGuestImageInfo &image) {
    if (!image.valid) {
      return;
    }
    out << prefix << "ImageBase: 0x" << std::hex << std::uppercase
        << image.base << std::dec << "\n";
    out << prefix << "ImageSize: 0x" << std::hex << std::uppercase
        << image.sizeOfImage << std::dec << "\n";
    out << prefix << "ImageEntryRva: 0x" << std::hex << std::uppercase
        << image.entryPointRva << std::dec << "\n";
    out << prefix << "ImageMachine: 0x" << std::hex << std::uppercase
        << image.machine << std::dec << "\n";
    out << prefix << "ImageSubsystem: 0x" << std::hex << std::uppercase
        << image.subsystem << std::dec << "\n";
    out << prefix << "ImageTimestamp: 0x" << std::hex << std::uppercase
        << image.timeDateStamp << std::dec << "\n";
    if (!image.pdbPath.empty()) {
      out << prefix << "ImagePdb: " << image.pdbPath << "\n";
    }
  };

  std::ostringstream out;
  out << "AntiMal in-house VM diagnostics\n";
  out << "started: " << (vm.started ? "true" : "false") << "\n";
  out << "completed: " << (vm.completed ? "true" : "false") << "\n";
  out << "timedOut: " << (vm.timedOut ? "true" : "false") << "\n";
  out << "fatal: " << (vm.fatal ? "true" : "false") << "\n";
  out << "guestShutdown: " << (vm.guestShutdown ? "true" : "false") << "\n";
  if (vm.guestShutdown) {
    out << "guestShutdownSleepType: S"
        << static_cast<int>(vm.guestShutdownSleepType) << "\n";
  }
  const bool hasStopState =
      vm.fatal || vm.timedOut || vm.idleLoop || vm.halted || vm.fatalRip != 0;
  if (hasStopState) {
    if (vm.fatal) {
      out << "fatalReason: " << static_cast<int>(vm.fatalReason) << "\n";
    }
    out << "fatalRip: 0x" << std::hex << std::uppercase << vm.fatalRip
        << std::dec << "\n";
    out << "fatalCsSelector: 0x" << std::hex << std::uppercase
        << vm.fatalCsSelector << std::dec << "\n";
    if (vm.fatalRipBytesValid) {
      writeBytes(out, "fatalRipBytes", vm.fatalRipBytes,
                 sizeof(vm.fatalRipBytes));
    }
    if (vm.fatalRipWindowValid) {
      out << "fatalRipWindowBase: 0x" << std::hex << std::uppercase
          << vm.fatalRipWindowBase << std::dec << "\n";
      writeBytes(out, "fatalRipWindow", vm.fatalRipWindow,
                 sizeof(vm.fatalRipWindow));
    }
    writeImage(out, "fatalRip", vm.fatalRipImage);
    out << "fatalRax: 0x" << std::hex << std::uppercase << vm.fatalRax
        << std::dec << "\n";
    out << "fatalRbx: 0x" << std::hex << std::uppercase << vm.fatalRbx
        << std::dec << "\n";
    out << "fatalRcx: 0x" << std::hex << std::uppercase << vm.fatalRcx
        << std::dec << "\n";
    out << "fatalRdx: 0x" << std::hex << std::uppercase << vm.fatalRdx
        << std::dec << "\n";
    out << "fatalRsi: 0x" << std::hex << std::uppercase << vm.fatalRsi
        << std::dec << "\n";
    out << "fatalRdi: 0x" << std::hex << std::uppercase << vm.fatalRdi
        << std::dec << "\n";
    out << "fatalRbp: 0x" << std::hex << std::uppercase << vm.fatalRbp
        << std::dec << "\n";
    out << "fatalRsp: 0x" << std::hex << std::uppercase << vm.fatalRsp
        << std::dec << "\n";
    out << "fatalR8: 0x" << std::hex << std::uppercase << vm.fatalR8
        << std::dec << "\n";
    out << "fatalR9: 0x" << std::hex << std::uppercase << vm.fatalR9
        << std::dec << "\n";
    out << "fatalR10: 0x" << std::hex << std::uppercase << vm.fatalR10
        << std::dec << "\n";
    out << "fatalR11: 0x" << std::hex << std::uppercase << vm.fatalR11
        << std::dec << "\n";
    out << "fatalR12: 0x" << std::hex << std::uppercase << vm.fatalR12
        << std::dec << "\n";
    out << "fatalR13: 0x" << std::hex << std::uppercase << vm.fatalR13
        << std::dec << "\n";
    out << "fatalR14: 0x" << std::hex << std::uppercase << vm.fatalR14
        << std::dec << "\n";
    out << "fatalR15: 0x" << std::hex << std::uppercase << vm.fatalR15
        << std::dec << "\n";
    if (vm.fatalRdxBytesValid) {
      writeBytes(out, "fatalRdxBytes", vm.fatalRdxBytes,
                 sizeof(vm.fatalRdxBytes));
    }
    if (vm.fatalRsiBytesValid) {
      writeBytes(out, "fatalRsiBytes", vm.fatalRsiBytes,
                 sizeof(vm.fatalRsiBytes));
    }
    if (vm.fatalRdiBytesValid) {
      writeBytes(out, "fatalRdiBytes", vm.fatalRdiBytes,
                 sizeof(vm.fatalRdiBytes));
    }
    if (vm.fatalRspBytesValid) {
      writeBytes(out, "fatalRspBytes", vm.fatalRspBytes,
                 sizeof(vm.fatalRspBytes));
    }
    for (size_t i = 0; i < 4; ++i) {
      if (vm.fatalStackReturn[i] == 0) {
        continue;
      }
      out << "fatalStackReturn" << i << ": 0x" << std::hex
          << std::uppercase << vm.fatalStackReturn[i] << std::dec << "\n";
      if (vm.fatalStackReturnBytesValid[i]) {
        out << "fatalStackReturn" << i << "WindowBase: 0x" << std::hex
            << std::uppercase << vm.fatalStackReturnWindowBase[i] << std::dec
            << "\n";
        std::string name = "fatalStackReturn" + std::to_string(i) + "Bytes";
        writeBytes(out, name.c_str(), vm.fatalStackReturnBytes[i],
                   sizeof(vm.fatalStackReturnBytes[i]));
      }
      std::string prefix = "fatalStackReturn" + std::to_string(i);
      writeImage(out, prefix.c_str(), vm.fatalStackReturnImage[i]);
    }
  }
  out << "idleLoop: " << (vm.idleLoop ? "true" : "false") << "\n";
  out << "steps: " << vm.steps << "\n";
  out << "processorCount: " << vm.processorCount << "\n";
  out << "hltCount: " << vm.totalHlts << "\n";
  out << "apVcpuExits: " << vm.apVcpuExits << "\n";
  out << "apHltExits: " << vm.apHltExits << "\n";
  out << "apCpuidExits: " << vm.apCpuidExits << "\n";
  out << "apUnhandledExits: " << vm.apUnhandledExits << "\n";
  for (const auto &ap : vm.apStates) {
    out << "ap" << ap.index << "Rip: 0x" << std::hex << std::uppercase
        << ap.rip << std::dec << "\n";
    out << "ap" << ap.index << "CsSelector: 0x" << std::hex
        << std::uppercase << ap.csSelector << std::dec << "\n";
    if (ap.ripBytesValid) {
      std::string name = "ap" + std::to_string(ap.index) + "RipBytes";
      writeBytes(out, name.c_str(), ap.ripBytes, sizeof(ap.ripBytes));
    }
  }
  out << "watchdogCancellations: " << vm.watchdogCancellations << "\n";
  out << "timerInterruptsRequested: " << vm.timerInterruptsRequested << "\n";
  out << "timerInterruptsInjected: " << vm.timerInterruptsInjected << "\n";
  out << "ideInterruptsRequested: " << vm.ideInterruptsRequested << "\n";
  out << "ideInterruptsInjected: " << vm.ideInterruptsInjected << "\n";
  out << "ideCommandsIssued: " << vm.ideCommandsIssued << "\n";
  out << "ideIdentifyCommands: " << vm.ideIdentifyCommands << "\n";
  out << "ideReadCommands: " << vm.ideReadCommands << "\n";
  out << "ideWriteCommands: " << vm.ideWriteCommands << "\n";
  out << "ideAbortedCommands: " << vm.ideAbortedCommands << "\n";
  out << "ideSectorsRead: " << vm.ideSectorsRead << "\n";
  out << "ideSectorsWritten: " << vm.ideSectorsWritten << "\n";
  out << "unhandledIo: " << vm.unhandledIo << "\n";
  out << "unhandledMmio: " << vm.unhandledMmio << "\n";
  out << "unhandledOther: " << vm.unhandledOther << "\n";
  if (vm.lastExceptionType != 0 || vm.lastExceptionErrorCode != 0 ||
      vm.lastExceptionParameter != 0) {
    out << "lastExceptionType: " << static_cast<int>(vm.lastExceptionType)
        << "\n";
    out << "lastExceptionErrorCode: 0x" << std::hex << std::uppercase
        << vm.lastExceptionErrorCode << std::dec << "\n";
    out << "lastExceptionParameter: 0x" << std::hex << std::uppercase
        << vm.lastExceptionParameter << std::dec << "\n";
  }
  if (vm.lastUnhandledMmioGpa != 0 || vm.lastUnhandledMmioGva != 0) {
    out << "lastUnhandledMmioGpa: 0x" << std::hex << std::uppercase
        << vm.lastUnhandledMmioGpa << std::dec << "\n";
    out << "lastUnhandledMmioGva: 0x" << std::hex << std::uppercase
        << vm.lastUnhandledMmioGva << std::dec << "\n";
    out << "lastUnhandledMmioAccess: " << vm.lastUnhandledMmioAccess << "\n";
    out << "lastUnhandledMmioInstructionLength: "
        << static_cast<int>(vm.lastUnhandledMmioInstructionLength) << "\n";
  }
  out << "mmioReads: " << vm.mmioReads << "\n";
  out << "mmioWrites: " << vm.mmioWrites << "\n";
  out << "ioApicRaises: " << vm.ioApicRaises << "\n";
  out << "ioApicDeliveries: " << vm.ioApicDeliveries << "\n";
  out << "ioApicMaskedDrops: " << vm.ioApicMaskedDrops << "\n";
  out << "hpetReads: " << vm.hpetReads << "\n";
  out << "hpetWrites: " << vm.hpetWrites << "\n";
  out << "pitIrqsDelivered: " << vm.pitIrqsDelivered << "\n";
  out << "rtcIrqsDelivered: " << vm.rtcIrqsDelivered << "\n";
  out << "fwCfgFileDirBytesRead: " << vm.fwCfgFileDirBytesRead << "\n";
  out << "fwCfgE820BytesRead: " << vm.fwCfgE820BytesRead << "\n";
  out << "fwCfgAcpiTableBytesRead: " << vm.fwCfgAcpiTableBytesRead << "\n";
  out << "fwCfgTableLoaderBytesRead: " << vm.fwCfgTableLoaderBytesRead << "\n";
  out << "fwCfgRsdpBytesRead: " << vm.fwCfgRsdpBytesRead << "\n";
  out << "pageFaultAssists: " << vm.pageFaultAssists << "\n";
  out << "hostChannelBytes: " << vm.hostChannelOutput.size() << "\n";
  if (vm.pageFaultAssists != 0) {
    out << "lastPageFaultAssistGva: 0x" << std::hex << std::uppercase
        << vm.lastPageFaultAssistGva << std::dec << "\n";
    out << "lastPageFaultAssistGpa: 0x" << std::hex << std::uppercase
        << vm.lastPageFaultAssistGpa << std::dec << "\n";
  }
  out << "\nTop IO ports:\n";
  for (const auto &[port, count] : topEntries(vm.ioPortHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%04X", port);
    out << "  " << hex << ": " << count << "\n";
  }
  out << "\nIDE commands:\n";
  for (const auto &[command, count] : topEntries(vm.ideCommandHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%02X", command);
    out << "  " << hex << ": " << count << "\n";
  }
  out << "\nCMOS reads:\n";
  for (const auto &[index, count] : topEntries(vm.cmosReadHistogram, 32)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%02X", index);
    out << "  " << hex << ": " << count << "\n";
  }
  out << "\nExit reasons:\n";
  for (const auto &[reason, count] : topEntries(vm.exitHistogram, 32)) {
    out << "  " << reason << ": " << count << "\n";
  }
  out << "\nCPUID leaves:\n";
  for (const auto &[leaf, count] : topEntries(vm.cpuidLeafHistogram, 64)) {
    char hex[16]{};
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%08X", leaf);
    out << "  " << hex << ": " << count << "\n";
  }
  if (!vm.ripHotspots.empty()) {
    out << "\nTop BSP RIP hotspots (16-byte bucket, hits across whole run):\n";
    for (const auto &[ripBucket, count] : topEntries(vm.ripHotspots, 32)) {
      char hex[24]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%016llX",
                  static_cast<unsigned long long>(ripBucket));
      out << "  " << hex << ": " << count << "\n";
    }
  }
  if (!vm.recentRips.empty()) {
    out << "\nBSP recent RIPs (oldest first, last "
        << vm.recentRips.size() << " exits):\n";
    for (const auto rip : vm.recentRips) {
      char hex[24]{};
      _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%016llX",
                  static_cast<unsigned long long>(rip));
      out << "  " << hex << "\n";
    }
  }
  if (!vm.recentCmosAccesses.empty()) {
    out << "\nRecent CMOS / RTC accesses (oldest first, last "
        << vm.recentCmosAccesses.size() << "):\n";
    for (const auto &acc : vm.recentCmosAccesses) {
      char line[96]{};
      _snprintf_s(line, sizeof(line), _TRUNCATE,
                  "  %s port=0x%04X idx=0x%02X val=0x%02X",
                  acc.isWrite ? "WR" : "RD",
                  static_cast<unsigned int>(acc.port),
                  static_cast<unsigned int>(acc.index),
                  static_cast<unsigned int>(acc.value));
      out << line << "\n";
    }
  }
  return out.str();
}

} // namespace

VhdxRawConversionResult ConvertVhdxToRaw(const std::filesystem::path &vhdxPath,
                                         const std::filesystem::path &rawPath,
                                         bool force) {
  VhdxRawConversionResult result;
  result.vhdxPath = vhdxPath;
  result.rawPath = rawPath;

  std::error_code ec;
  if (!std::filesystem::exists(vhdxPath, ec)) {
    result.errors.push_back("Base VHDX does not exist: " + PathToUtf8(vhdxPath));
    return result;
  }
  if (std::filesystem::exists(rawPath, ec) && !force) {
    result.skipped = true;
    result.messages.push_back("Raw base already exists; pass --force to replace it.");
    return result;
  }

  HANDLE diskHandle = INVALID_HANDLE_VALUE;
  HANDLE physicalHandle = INVALID_HANDLE_VALUE;
  HANDLE rawHandle = INVALID_HANDLE_VALUE;
  bool attached = false;
  bool removePartialRaw = false;

  try {
    EnsureDirectory(rawPath.parent_path());
    std::filesystem::remove(rawPath, ec);

    auto storage = StorageTypeForVirtualDisk(vhdxPath);
    OPEN_VIRTUAL_DISK_PARAMETERS openParams{};
    openParams.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    const DWORD openError = OpenVirtualDisk(
        &storage, vhdxPath.c_str(),
        VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_GET_INFO,
        OPEN_VIRTUAL_DISK_FLAG_NONE, &openParams, &diskHandle);
    if (openError != ERROR_SUCCESS) {
      throw std::runtime_error("OpenVirtualDisk failed with " +
                               FormatWin32Error(openError));
    }

    result.virtualSize = QueryVirtualDiskSize(diskHandle);

    ATTACH_VIRTUAL_DISK_PARAMETERS attachParams{};
    attachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    const DWORD attachError = AttachVirtualDisk(
        diskHandle, nullptr,
        ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY |
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
        0, &attachParams, nullptr);
    if (attachError != ERROR_SUCCESS) {
      throw std::runtime_error("AttachVirtualDisk(read-only/no-drive-letter) failed with " +
                               FormatWin32Error(attachError));
    }
    attached = true;

    ULONG pathChars = 0;
    DWORD pathError = GetVirtualDiskPhysicalPath(diskHandle, &pathChars, nullptr);
    if (pathError != ERROR_INSUFFICIENT_BUFFER || pathChars == 0) {
      throw std::runtime_error("GetVirtualDiskPhysicalPath(size) failed with " +
                               FormatWin32Error(pathError));
    }
    std::vector<wchar_t> physicalPath(pathChars + 1);
    pathError = GetVirtualDiskPhysicalPath(diskHandle, &pathChars,
                                           physicalPath.data());
    if (pathError != ERROR_SUCCESS) {
      throw std::runtime_error("GetVirtualDiskPhysicalPath failed with " +
                               FormatWin32Error(pathError));
    }

    physicalHandle =
        CreateFileW(physicalPath.data(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (physicalHandle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("CreateFile(virtual disk physical path) failed with " +
                               FormatWin32Error(GetLastError()));
    }

    rawHandle = CreateFileW(rawPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (rawHandle == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("CreateFile(raw output) failed with " +
                               FormatWin32Error(GetLastError()));
    }

    DWORD ignored = 0;
    (void)DeviceIoControl(rawHandle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0,
                          &ignored, nullptr);
    if (!SetFilePointerTo(rawHandle, result.virtualSize) ||
        SetEndOfFile(rawHandle) == FALSE) {
      throw std::runtime_error("Unable to size raw output with " +
                               FormatWin32Error(GetLastError()));
    }

    constexpr DWORD kChunkBytes = 4u * 1024u * 1024u;
    std::vector<uint8_t> buffer(kChunkBytes);
    uint64_t offset = 0;
    while (offset < result.virtualSize) {
      const DWORD want = static_cast<DWORD>(
          std::min<uint64_t>(buffer.size(), result.virtualSize - offset));
      DWORD got = 0;
      if (ReadFile(physicalHandle, buffer.data(), want, &got, nullptr) == FALSE) {
        throw std::runtime_error("ReadFile(virtual disk) failed with " +
                                 FormatWin32Error(GetLastError()));
      }
      if (got == 0) {
        break;
      }
      result.bytesRead += got;
      if (!IsAllZero(buffer.data(), got)) {
        if (!SetFilePointerTo(rawHandle, offset)) {
          throw std::runtime_error("SetFilePointer(raw output) failed with " +
                                   FormatWin32Error(GetLastError()));
        }
        DWORD written = 0;
        if (WriteFile(rawHandle, buffer.data(), got, &written, nullptr) ==
                FALSE ||
            written != got) {
          throw std::runtime_error("WriteFile(raw output) failed with " +
                                   FormatWin32Error(GetLastError()));
        }
        result.bytesWritten += written;
      }
      offset += got;
    }

    FlushFileBuffers(rawHandle);
    result.converted = true;
    result.messages.push_back("Converted VHDX to sparse raw disk.");
  } catch (const std::exception &ex) {
    result.errors.push_back(ex.what());
    removePartialRaw = true;
  }

  if (rawHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(rawHandle);
  }
  if (physicalHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(physicalHandle);
  }
  if (attached) {
    DetachVirtualDisk(diskHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
  }
  if (diskHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(diskHandle);
  }
  if (removePartialRaw) {
    std::filesystem::remove(rawPath, ec);
  }
  return result;
}

InHouseOrchestrator::InHouseOrchestrator(AppConfig config) : config_(std::move(config)) {}

HyperVPreflight InHouseOrchestrator::Preflight() const {
  HyperVPreflight result;
  result.baseVhdxPresent = !config_.baseVhdxPath.empty() &&
                           std::filesystem::exists(config_.baseVhdxPath);
  if (result.baseVhdxPresent) {
    try {
      auto vhdx = hv::VhdxBlockDevice::Open(config_.baseVhdxPath);
      result.baseVhdxReadable = vhdx.SectorCount() > 0;
    } catch (const std::exception &ex) {
      result.messages.push_back("Base VHDX is present but unreadable: " +
                                std::string(ex.what()));
    }
  }
  result.baseDiskFormat = ToLowerAscii(config_.baseDiskFormat.empty() ? "raw" : config_.baseDiskFormat);
  result.baseDiskPresent = !config_.baseDiskPath.empty() &&
                           std::filesystem::exists(config_.baseDiskPath);
  result.rawBaseReady = result.baseDiskFormat == "raw" && result.baseDiskPresent;
  result.vhdxConversionRequired =
      result.baseVhdxPresent && !result.baseVhdxReadable && !result.rawBaseReady;
  result.baseVhdxPath = config_.baseVhdxPath;
  result.baseDiskPath = config_.baseDiskPath;
  result.provider = SelectProvider(config_);
  result.inHouseSelected = result.provider == "inhouse";
  result.firmwarePath = FindFirmwareBlob();
  result.firmwarePresent = !result.firmwarePath.empty();
  result.guestAgentPath = GuestAgentPath();
  result.guestAgentPresent = std::filesystem::exists(result.guestAgentPath);
  result.whpDllPresent = WhpDllPresent();
  result.whpAvailable = result.whpDllPresent && hv::WhpHost::IsAvailable();
  result.storageBootReady =
      result.whpAvailable && result.firmwarePresent &&
      (result.rawBaseReady || result.baseVhdxReadable);
  result.displayReady = false;
  result.hostChannelReady = false;
  result.networkReady = config_.networkMode == NetworkMode::Disabled;
  result.dynamicExecutionEnabled = config_.dynamicExecutionEnabled;
  result.safeToExecute = false;
  result.bootCapabilityReady =
      result.inHouseSelected && result.storageBootReady && result.networkReady;

  if (result.provider == "inhouse") {
    if (!result.rawBaseReady && !result.baseVhdxReadable && !result.baseVhdxPresent) {
      result.blockers.push_back(
          "base_disk_path raw runtime disk is missing, and no readable base VHDX is available.");
    } else if (!result.rawBaseReady && !result.baseVhdxReadable) {
      result.blockers.push_back(
          "base_disk_path raw runtime disk is missing, and the configured base VHDX could not be read.");
    }
    if (result.vhdxConversionRequired) {
      result.messages.push_back(
          "Base VHDX is present, but raw conversion is required for the in-house IDE boot path.");
    } else if (!result.rawBaseReady && result.baseVhdxReadable) {
      result.messages.push_back(
          "Base VHDX will be used directly with a disposable COW overlay.");
    }
    if (!result.firmwarePresent) {
      result.blockers.push_back(
          "firmware/OVMF.fd was not found for the in-house WHP backend.");
    }
    if (!result.guestAgentPresent) {
      result.messages.push_back("AntiMal.GuestAgent.exe was not found beside the host executable.");
    }
    if (!result.whpDllPresent) {
      result.blockers.push_back(
          "WinHvPlatform.dll was not found on this Windows installation.");
    } else if (!result.whpAvailable) {
      result.blockers.push_back(
          "Windows Hypervisor Platform is not available/enabled on this host.");
    }
    if (!result.dynamicExecutionEnabled) {
      result.messages.push_back(
          "dynamic_execution_enabled is false; samples will be staged but not executed.");
    }
    if (!result.networkReady) {
      result.blockers.push_back(
          "Only network_mode = \"disabled\" is ready; hostonly/nat NIC backends are not implemented.");
    }
    if (!result.displayReady) {
      result.messages.push_back("Display/framebuffer channel is not implemented; live UI uses journal/screenshot files only.");
    }
    if (!result.hostChannelReady) {
      result.messages.push_back(
          "Host/guest channel is not implemented; staged samples are not launched inside the guest.");
    }
  } else if (result.provider == "hyperv") {
    result.blockers.push_back(
        "Hyper-V VM provider support has been removed. Use vm_provider = \"inhouse\".");
  } else if (result.provider == "virtualbox") {
    result.blockers.push_back(
        "VirtualBox support has been removed. AntiMal will not launch third-party VM apps.");
  } else if (result.provider == "vmware") {
    result.blockers.push_back(
        "VMware support has been removed. AntiMal will not launch third-party VM apps.");
  } else {
    result.blockers.push_back("Unknown vm_provider: " + config_.vmProvider);
  }
  result.messages.insert(result.messages.begin(), result.blockers.begin(),
                         result.blockers.end());
  return result;
}

DetonationResult InHouseOrchestrator::PrepareAndRun(
    const std::filesystem::path &samplePath, uint32_t timeoutSec,
    NetworkMode networkMode, bool executeVmCommands,
    DetonationProgressCallback progressCallback) {
  DetonationResult result;
  result.runId = MakeRunId();
  result.runDir = config_.workspaceRoot / result.runId;
  result.jobPath = result.runDir / "job.json";
  result.journalPath = result.runDir / "events.jsonl";
  result.screenshotsDir = result.runDir / "screenshots";
  result.overlayDiskPath = result.runDir / "disk" / "overlay.vhdx";
  result.reportPath = result.runDir / "report.json";
  result.dynamicSummary.networkMode = networkMode;
  result.status = "staging";

  auto fireProgress = [&](const std::string &phase, const std::string &msg) {
    if (!progressCallback) {
      return;
    }
    DetonationProgress progress{};
    progress.runId = result.runId;
    progress.runDir = result.runDir;
    progress.phase = phase;
    progress.message = msg;
    try {
      progressCallback(progress);
    } catch (...) {
      // Progress is best-effort.
    }
  };
  fireProgress("staging", "Staging sample and creating workspace");

  EnsureDirectory(result.runDir / "in");
  EnsureDirectory(result.runDir / "out");
  EnsureDirectory(result.runDir / "disk");
  EnsureDirectory(result.screenshotsDir);

  std::vector<EventRecord> events;
  AppendJournalEvent(result.journalPath,
                     MakeSandboxEvent("run.staged", samplePath,
                                      {{"runId", result.runId},
                                       {"networkMode", ToString(networkMode)}}),
                     &events);

  const auto stagedSample = result.runDir / "in" / samplePath.filename();
  std::error_code ec;
  std::filesystem::copy_file(samplePath, stagedSample,
                             std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    result.errors.push_back("Unable to stage sample: " + ec.message());
  } else {
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("sample.staged", stagedSample),
                       &events);
  }

  const auto agentPath = GuestAgentPath();
  if (std::filesystem::exists(agentPath)) {
    std::filesystem::copy_file(agentPath, result.runDir / "in" / "AntiMal.GuestAgent.exe",
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      result.errors.push_back("Unable to stage GuestAgent: " + ec.message());
      ec.clear();
    } else {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("guest-agent.staged",
                                          result.runDir / "in" / "AntiMal.GuestAgent.exe"),
                         &events);
    }
  } else {
    result.errors.push_back("AntiMal.GuestAgent.exe was not found beside the host CLI.");
  }

  const auto baseDiskFormat = ToLowerAscii(config_.baseDiskFormat.empty() ? "raw" : config_.baseDiskFormat);
  if (baseDiskFormat == "raw" && !config_.baseDiskPath.empty() &&
      std::filesystem::exists(config_.baseDiskPath)) {
    result.overlayDiskPath = result.runDir / "disk" / "overlay.raw";
    std::string overlayError;
    if (CreateRawCowOverlay(result.overlayDiskPath, &overlayError)) {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.created", result.overlayDiskPath,
                                          {{"parent", PathToUtf8(config_.baseDiskPath)},
                                           {"format", "raw-cow"}}),
                         &events);
    } else {
      result.errors.push_back(overlayError);
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.create-failed", result.overlayDiskPath,
                                          {{"error", overlayError},
                                           {"format", "raw-cow"}}),
                         &events);
    }
  } else if (!config_.baseVhdxPath.empty() && std::filesystem::exists(config_.baseVhdxPath)) {
    result.overlayDiskPath = result.runDir / "disk" / "overlay.cow";
    std::string overlayError;
    if (CreateRawCowOverlay(result.overlayDiskPath, &overlayError)) {
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.created", result.overlayDiskPath,
                                          {{"parent", PathToUtf8(config_.baseVhdxPath)},
                                           {"format", "vhdx-cow"}}),
                         &events);
    } else {
      result.errors.push_back(overlayError);
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("overlay.create-failed", result.overlayDiskPath,
                                          {{"error", overlayError},
                                           {"format", "vhdx-cow"}}),
                         &events);
    }
  }

  JobConfig job;
  job.runId = result.runId;
  job.samplePath = stagedSample;
  job.timeoutMs = timeoutSec * 1000;
  job.networkMode = networkMode;
  job.collectScreenshots = true;
  job.outputDir = result.runDir / "out";
  WriteTextFile(result.jobPath, ToJson(job));

  auto effectiveConfig = config_;
  effectiveConfig.networkMode = networkMode;
  const auto preflight = InHouseOrchestrator(effectiveConfig).Preflight();
  const std::string vmName = config_.vmNamePrefix + "-" + result.runId.substr(0, 8);
  result.commands.push_back("$ErrorActionPreference='Stop'");

  const std::filesystem::path planPath = result.runDir / "inhouse-plan.ps1";
  result.commands.push_back("# AntiMal in-house VM boot plan for " + vmName + ".");
  result.commands.push_back("# This file is documentation only. AntiMal does not execute the submitted sample on the host.");
  result.commands.push_back("# Staged sample: " + PathToUtf8(stagedSample));
  result.commands.push_back("# Journal: " + PathToUtf8(result.journalPath));
  result.commands.push_back("# Screenshots: " + PathToUtf8(result.screenshotsDir));
  result.commands.push_back("# Base disk: " + PathToUtf8(config_.baseDiskPath));
  result.commands.push_back("# Firmware: " + PathToUtf8(preflight.firmwarePath));
  result.commands.push_back("# Sample execution remains blocked until guest boot, host channel, and artifact return are proven.");

  WritePlan(planPath, result.commands);

  AppendJournalEvent(result.journalPath,
                     MakeSandboxEvent("preflight.checked", config_.baseVhdxPath,
                                     {{"baseVhdxPresent", preflight.baseVhdxPresent ? "true" : "false"},
                                      {"baseVhdxReadable", preflight.baseVhdxReadable ? "true" : "false"},
                                      {"baseDiskPresent", preflight.baseDiskPresent ? "true" : "false"},
                                      {"rawBaseReady", preflight.rawBaseReady ? "true" : "false"},
                                      {"vhdxConversionRequired", preflight.vhdxConversionRequired ? "true" : "false"},
                                      {"baseDiskFormat", preflight.baseDiskFormat},
                                      {"firmwarePresent", preflight.firmwarePresent ? "true" : "false"},
                                      {"guestAgentPresent", preflight.guestAgentPresent ? "true" : "false"},
                                      {"whpDllPresent", preflight.whpDllPresent ? "true" : "false"},
                                      {"whpAvailable", preflight.whpAvailable ? "true" : "false"},
                                      {"storageBootReady", preflight.storageBootReady ? "true" : "false"},
                                      {"bootCapabilityReady", preflight.bootCapabilityReady ? "true" : "false"},
                                      {"hostChannelReady", preflight.hostChannelReady ? "true" : "false"},
                                      {"dynamicExecutionEnabled", preflight.dynamicExecutionEnabled ? "true" : "false"},
                                      {"safeToExecute", preflight.safeToExecute ? "true" : "false"}}),
                      &events);

  result.dynamicSummary.status = "staged";
  result.dynamicSummary.sampleExecuted = false;
  result.dynamicSummary.networkMode = networkMode;

  if (!preflight.blockers.empty()) {
    for (const auto &message : preflight.blockers) {
      result.errors.push_back(message);
    }
    result.status = "blocked";
    result.dynamicSummary.status = "blocked";
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("run.blocked", result.runDir,
                                        {{"reason", "preflight"}}),
                       &events);
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    WriteErrorReport(result.reportPath, result.runId, samplePath, result.errors,
                     events, result.dynamicSummary);
    return result;
  }

  if (executeVmCommands) {
    AppendJournalEvent(result.journalPath,
                       MakeSandboxEvent("vm.boot.started", result.overlayDiskPath,
                                        {{"baseDisk", preflight.rawBaseReady
                                                          ? PathToUtf8(config_.baseDiskPath)
                                                          : PathToUtf8(config_.baseVhdxPath)},
                                         {"firmware", PathToUtf8(preflight.firmwarePath)}}),
                       &events);
    result.started = true;
    result.status = "booting";
    result.dynamicSummary.started = true;
    result.dynamicSummary.status = "booting";

    const auto serialLogPath = result.runDir / "serial.log";
    const auto vmSummaryPath = result.runDir / "vm-summary.json";
    const auto vmDiagnosticsPath = result.runDir / "vm-diagnostics.txt";
    try {
      hv::VmRunRequest request;
      request.networkMode = ToHvNetworkMode(networkMode);
      request.timeout = std::chrono::milliseconds(
          static_cast<int64_t>(std::max<uint32_t>(1, timeoutSec)) * 1000);
      // A Windows boot with CMOS/PM-timer polling spends millions of steps
      // per second of guest time, so the multiplier must be large enough
      // that the timeout — not the step cap — is the binding constraint.
      request.maxSteps = std::numeric_limits<int>::max();
      request.progressInterval = std::chrono::milliseconds{1500};
      const std::string runIdCopy = result.runId;
      const std::filesystem::path runDirCopy = result.runDir;
      const std::filesystem::path screenshotsDirCopy = result.screenshotsDir;
      auto frameCounter = std::make_shared<std::atomic<uint32_t>>(0);
      if (progressCallback) {
        request.progressCallback = [progressCallback, runIdCopy, runDirCopy,
                                    screenshotsDirCopy, frameCounter](
                                       const hv::VmProgressSnapshot &snap) {
          DetonationProgress progress{};
          progress.runId = runIdCopy;
          progress.runDir = runDirCopy;
          progress.phase = "running";
          progress.steps = snap.steps;
          progress.totalHlts = snap.totalHlts;
          progress.ideSectorsRead = snap.ideSectorsRead;
          progress.ideSectorsWritten = snap.ideSectorsWritten;
          progress.ideCommands = snap.ideCommandsIssued;
          progress.mmioReads = snap.mmioReads;
          progress.mmioWrites = snap.mmioWrites;
          progress.ioApicDeliveries = snap.ioApicDeliveries;
          progress.elapsedMs =
              static_cast<uint64_t>(snap.elapsed.count());
          progress.newSerialBytes = snap.newSerialBytes;
          for (size_t i = 0; i < 3; ++i) {
            progress.topPorts[i].port = snap.topPorts[i].port;
            progress.topPorts[i].count = snap.topPorts[i].count;
          }
          progress.currentRip = snap.currentRip;
          progress.currentCsSelector = snap.currentCsSelector;
          progress.framebufferEnabled = snap.framebufferEnabled;
          progress.framebufferWidth = snap.framebufferWidth;
          progress.framebufferHeight = snap.framebufferHeight;
          progress.framebufferBpp = snap.framebufferBpp;
          if (snap.textFramebufferActive) {
            std::string screen;
            screen.reserve(81 * 25);
            for (size_t row = 0; row < 25; ++row) {
              for (size_t col = 0; col < 80; ++col) {
                const uint16_t cell = snap.textFramebuffer[row * 80 + col];
                const auto ch = static_cast<uint8_t>(cell & 0xFFu);
                if (ch >= 32 && ch < 127) {
                  screen.push_back(static_cast<char>(ch));
                } else if (ch == 0) {
                  screen.push_back(' ');
                } else {
                  screen.push_back('?');
                }
              }
              screen.push_back('\n');
            }
            progress.vgaTextScreen = std::move(screen);
          }
          char ripHex[128] = "(unmapped)";
          if (snap.ripBytesValid) {
            std::string acc;
            for (size_t i = 0; i < sizeof(snap.ripBytes); ++i) {
              char b[4];
              _snprintf_s(b, sizeof(b), _TRUNCATE, "%02X", snap.ripBytes[i]);
              acc += b;
              if (i + 1 < sizeof(snap.ripBytes)) {
                acc += ' ';
              }
            }
            _snprintf_s(ripHex, sizeof(ripHex), _TRUNCATE, "%s", acc.c_str());
          }
          char fbDesc[48] = "fb=off";
          if (progress.framebufferEnabled) {
            _snprintf_s(fbDesc, sizeof(fbDesc), _TRUNCATE,
                        "fb=%ux%ux%u", progress.framebufferWidth,
                        progress.framebufferHeight, progress.framebufferBpp);
          }
          char buffer[896]{};
          _snprintf_s(
              buffer, sizeof(buffer), _TRUNCATE,
              "VM running %llus: %d steps, %llu sectors read, "
              "%llu written, %d HLTs, %llu IOAPIC IRQs | %s | top IO: "
              "0x%04X=%llu  0x%04X=%llu  0x%04X=%llu | RIP=%04X:%016llX "
              "| code: %s",
              static_cast<unsigned long long>(progress.elapsedMs / 1000ull),
              progress.steps,
              static_cast<unsigned long long>(progress.ideSectorsRead),
              static_cast<unsigned long long>(progress.ideSectorsWritten),
              progress.totalHlts,
              static_cast<unsigned long long>(progress.ioApicDeliveries),
              fbDesc,
              progress.topPorts[0].port,
              static_cast<unsigned long long>(progress.topPorts[0].count),
              progress.topPorts[1].port,
              static_cast<unsigned long long>(progress.topPorts[1].count),
              progress.topPorts[2].port,
              static_cast<unsigned long long>(progress.topPorts[2].count),
              progress.currentCsSelector,
              static_cast<unsigned long long>(progress.currentRip),
              ripHex);
          progress.message = buffer;

          // Compose a multi-line text panel and render it as a PNG into
          // runDir/screenshots/ so the GUI's filmstrip + latest-frame
          // captions animate live, even before the guest has a real
          // framebuffer to display.
          {
            std::ostringstream frameText;
            frameText << "AntiMal Live VM   run "
                      << runIdCopy.substr(0, 8) << "\n";
            frameText << "phase=" << progress.phase
                      << "   elapsed=" << (progress.elapsedMs / 1000ull)
                      << "s\n\n";
            frameText << "  steps  : " << progress.steps << "\n";
            frameText << "  HLTs   : " << progress.totalHlts << "\n";
            frameText << "  IDE r  : " << progress.ideSectorsRead
                      << "   IDE w: " << progress.ideSectorsWritten << "\n";
            frameText << "  IDE cmd: " << progress.ideCommands << "\n";
            frameText << "  MMIO   : " << progress.mmioReads << " r / "
                      << progress.mmioWrites << " w\n";
            frameText << "  IOAPIC : " << progress.ioApicDeliveries
                      << " delivered\n\n";
            char portLine[256];
            _snprintf_s(portLine, sizeof(portLine), _TRUNCATE,
                        "  top IO : 0x%04X=%llu  0x%04X=%llu  0x%04X=%llu",
                        progress.topPorts[0].port,
                        static_cast<unsigned long long>(progress.topPorts[0].count),
                        progress.topPorts[1].port,
                        static_cast<unsigned long long>(progress.topPorts[1].count),
                        progress.topPorts[2].port,
                        static_cast<unsigned long long>(progress.topPorts[2].count));
            frameText << portLine << "\n";
            char ripLine[256];
            _snprintf_s(ripLine, sizeof(ripLine), _TRUNCATE,
                        "  RIP    : %04X:%016llX",
                        progress.currentCsSelector,
                        static_cast<unsigned long long>(progress.currentRip));
            frameText << ripLine << "\n";
            frameText << "  code   : " << ripHex << "\n";

            const uint32_t frameIdx = frameCounter->fetch_add(1);
            char nameBuf[64];
            _snprintf_s(nameBuf, sizeof(nameBuf), _TRUNCATE,
                        "livevm-%06u.png", frameIdx);
            const auto pngPath = screenshotsDirCopy / nameBuf;
            try {
              (void)RenderTextToPng(pngPath, frameText.str(), 760, 460);
            } catch (...) {
              // Rendering must not break the VM run loop.
            }

            // If the guest has programmed the VBE framebuffer, also capture
            // the actual guest pixels as a PNG so the user can SEE the boot
            // logo / firmware menu / Windows splash. Independent file name
            // so both rolls of frames coexist in screenshots/.
            if (snap.framebufferEnabled && snap.framebufferHost &&
                snap.framebufferWidth > 0 && snap.framebufferHeight > 0 &&
                snap.framebufferBpp == 32) {
              const size_t needed =
                  static_cast<size_t>(snap.framebufferWidth) *
                  static_cast<size_t>(snap.framebufferHeight) * 4ull;
              if (needed <= snap.framebufferBytes) {
                char gpuName[64];
                _snprintf_s(gpuName, sizeof(gpuName), _TRUNCATE,
                            "guest-%06u.png", frameIdx);
                const auto gpuPath = screenshotsDirCopy / gpuName;
                try {
                  (void)EncodeFramebufferPng(gpuPath, snap.framebufferHost,
                                             snap.framebufferWidth,
                                             snap.framebufferHeight,
                                             snap.framebufferBpp / 8);
                } catch (...) {
                  // Encoding must not break the VM run loop.
                }
              }
            }
          }

          try {
            progressCallback(progress);
          } catch (...) {
            // Best-effort progress reporting.
          }
        };
      }
      fireProgress("booting", "Booting VM (firmware -> guest)");
      hv::VmRunSummary vmSummary;
      hv::VirtualMachineOptions vmOptions;
      vmOptions.processorCount = 2;
      // ANTIMAL_VCPU_COUNT lets us test single-CPU vs multi-CPU boot paths
      // without rebuilding. Useful when chasing AP-bringup synchronization
      // hangs in firmware MP init — drop to 1 to side-step the AP sync
      // entirely.
      {
        char buf[16]{};
        size_t needed = 0;
        if (getenv_s(&needed, buf, sizeof(buf), "ANTIMAL_VCPU_COUNT") == 0 &&
            needed > 1 && buf[0] != '\0') {
          const int requested = std::atoi(buf);
          if (requested >= 1 && requested <= 64) {
            vmOptions.processorCount = static_cast<uint32_t>(requested);
          }
        }
      }
      if (preflight.rawBaseReady) {
        auto cow = hv::CowRawBlockDevice::Open(config_.baseDiskPath,
                                               result.overlayDiskPath);
        hv::VirtualMachine vm(preflight.firmwarePath, &cow, vmOptions);
        vmSummary = vm.Run(request);
      } else if (preflight.baseVhdxReadable) {
        auto base = hv::VhdxBlockDevice::Open(config_.baseVhdxPath);
        auto cow = hv::CowOverlayBlockDevice::Open(&base, result.overlayDiskPath);
        hv::VirtualMachine vm(preflight.firmwarePath, &cow, vmOptions);
        vmSummary = vm.Run(request);
      } else {
        throw std::runtime_error("no bootable base disk was available");
      }
      fireProgress("finishing", "VM run loop returned; writing diagnostics");
      WriteTextFile(serialLogPath, vmSummary.serialOutput);
      WriteTextFile(vmDiagnosticsPath, FormatVmDiagnostics(vmSummary));
      result.dynamicSummary =
          ToDynamicSummary(vmSummary, networkMode, serialLogPath, vmSummaryPath);
      const auto bootSignals =
          AnalyzeBootSignals(vmSummary.serialOutput, vmSummary.hostChannelOutput);
      result.dynamicSummary.bootMilestones = bootSignals.milestones;
      result.dynamicSummary.guestAgentConnected =
          bootSignals.guestAgentConnected;
      if (result.dynamicSummary.guestAgentConnected &&
          !result.dynamicSummary.crashed) {
        result.dynamicSummary.status = "guest agent connected";
      }
      result.status = result.dynamicSummary.status;
      result.completed = vmSummary.completed;
      result.dynamicSummary.eventsCaptured =
          static_cast<uint32_t>(events.size());

      if (bootSignals.guestAgentConnected) {
        AppendJournalEvent(result.journalPath,
                           MakeSandboxEvent("guest-agent.connected",
                                            result.overlayDiskPath,
                                            {{"channel", "COM2"}}),
                           &events);
      }
      if (bootSignals.guestAgentHeartbeats != 0) {
        AppendJournalEvent(
            result.journalPath,
            MakeSandboxEvent("guest-agent.heartbeat", result.overlayDiskPath,
                             {{"count", std::to_string(
                                           bootSignals.guestAgentHeartbeats)}}),
            &events);
      }
      if (bootSignals.reportComplete) {
        AppendJournalEvent(result.journalPath,
                           MakeSandboxEvent("guest-agent.report-complete",
                                            result.overlayDiskPath),
                           &events);
      }

      std::map<std::string, std::string> details{
          {"status", result.dynamicSummary.status},
          {"vcpuExits", std::to_string(result.dynamicSummary.vcpuExits)},
          {"ideCommandsIssued",
           std::to_string(result.dynamicSummary.ideCommandsIssued)},
          {"ideIdentifyCommands",
           std::to_string(result.dynamicSummary.ideIdentifyCommands)},
          {"ideReadCommands",
           std::to_string(result.dynamicSummary.ideReadCommands)},
          {"ideSectorsRead",
           std::to_string(result.dynamicSummary.ideSectorsRead)},
          {"ideAbortedCommands",
           std::to_string(result.dynamicSummary.ideAbortedCommands)},
          {"bootMilestones",
           JoinStrings(result.dynamicSummary.bootMilestones, ", ")},
          {"firmwareIdle", result.dynamicSummary.firmwareIdle ? "true" : "false"},
          {"guestAgentConnected",
           result.dynamicSummary.guestAgentConnected ? "true" : "false"},
          {"sampleExecuted", "false"}};
      if (vmSummary.timedOut) {
        details["reason"] = "timeout";
      } else if (vmSummary.fatal) {
        details["reason"] = "fatal-vcpu-exit";
      } else if (result.dynamicSummary.firmwareIdle) {
        details["reason"] = "firmware-idle-before-guest";
      }
      const bool bootReachedGuest =
          result.dynamicSummary.status == "boot attempted";
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent(bootReachedGuest
                                              ? "vm.boot.completed"
                                              : "vm.boot.incomplete",
                                          result.overlayDiskPath, details),
                         &events);
    } catch (const std::exception &ex) {
      result.status = "boot failed";
      result.dynamicSummary.status = "boot failed";
      result.dynamicSummary.started = true;
      result.dynamicSummary.completed = false;
      result.dynamicSummary.crashed = true;
      result.dynamicSummary.networkMode = networkMode;
      result.dynamicSummary.serialLogPath = serialLogPath;
      result.dynamicSummary.vmSummaryPath = vmSummaryPath;
      WriteTextFile(vmDiagnosticsPath,
                    std::string("VM boot failed before diagnostics: ") +
                        ex.what() + "\n");
      result.errors.push_back(std::string("In-house VM boot failed: ") + ex.what());
      AppendJournalEvent(result.journalPath,
                         MakeSandboxEvent("vm.boot.failed", result.overlayDiskPath,
                                          {{"error", ex.what()}}),
                         &events);
    }

    result.errors.push_back(
        "Sample was staged but not executed; host/guest channel and safe sample execution remain disabled.");
    result.dynamicSummary.sampleExecuted = false;
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    WriteTextFile(vmSummaryPath, ToJson(result.dynamicSummary));
    WriteErrorReport(result.reportPath, result.runId, samplePath, result.errors,
                     events, result.dynamicSummary);
  } else {
    result.status = "staged";
    result.dynamicSummary.status = "staged";
    result.dynamicSummary.eventsCaptured = static_cast<uint32_t>(events.size());
    WriteStagedReport(result.reportPath, result.runId, samplePath, events,
                      result.dynamicSummary);
  }

  return result;
}

HyperVOrchestrator::HyperVOrchestrator(AppConfig config) : config_(std::move(config)) {}

HyperVPreflight HyperVOrchestrator::Preflight() const {
  return InHouseOrchestrator(config_).Preflight();
}

DetonationResult HyperVOrchestrator::PrepareAndRun(
    const std::filesystem::path &samplePath, uint32_t timeoutSec,
    NetworkMode networkMode, bool executeVmCommands,
    DetonationProgressCallback progressCallback) {
  return InHouseOrchestrator(config_).PrepareAndRun(
      samplePath, timeoutSec, networkMode, executeVmCommands,
      std::move(progressCallback));
}

} // namespace antimal
