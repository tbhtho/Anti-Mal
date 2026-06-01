#include "antimal/Config.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/GuestMonitor.h"
#include "antimal/HostChannel.h"
#include "antimal/Json.h"
#include "antimal/ProcessTelemetry.h"
#include "antimal/Report.h"
#include "antimal/Screenshot.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::atomic_bool g_stopRequested{false};
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};

// Emits a placeholder journal line so the host UI has something to render
// even when no in-guest collector is wired up yet. Real collectors (Sysmon
// tail, ETW subscribers, file/registry watchers) replace these emit calls
// without changing the on-disk format. See the private development documentation
void EmitStartupEvent(antimal::EventJournalWriter &journal,
                      const antimal::JobConfig &job) {
  antimal::EventRecord ev;
  ev.timestampUtc = antimal::UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "process";
  ev.action = "agent.start";
  ev.processId = static_cast<uint32_t>(GetCurrentProcessId());
  ev.imagePath = antimal::PathToUtf8(job.samplePath);
  ev.target = job.runId;
  ev.details["timeoutMs"] = std::to_string(job.timeoutMs);
  ev.details["networkMode"] = antimal::ToString(job.networkMode);
  ev.mitre = "";
  journal.Append(ev);
}

bool WriteAll(HANDLE handle, const std::vector<uint8_t> &bytes) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    DWORD written = 0;
    const DWORD chunk = static_cast<DWORD>(
        std::min<size_t>(bytes.size() - offset, 4096));
    if (!WriteFile(handle, bytes.data() + offset, chunk, &written, nullptr) ||
        written == 0) {
      return false;
    }
    offset += written;
  }
  return true;
}

bool SendFrame(HANDLE handle, antimal::HostChannelMessage type,
               std::string_view payload) {
  return WriteAll(handle, antimal::HostSerialChannel::EncodeText(type, payload));
}

HANDLE OpenCom2WithRetry() {
  for (int attempt = 0; attempt < 60 && !g_stopRequested.load(); ++attempt) {
    HANDLE handle = CreateFileW(L"\\\\.\\COM2", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      DCB dcb{};
      dcb.DCBlength = sizeof(dcb);
      if (GetCommState(handle, &dcb)) {
        dcb.BaudRate = CBR_115200;
        dcb.ByteSize = 8;
        dcb.Parity = NOPARITY;
        dcb.StopBits = ONESTOPBIT;
        (void)SetCommState(handle, &dcb);
      }
      COMMTIMEOUTS timeouts{};
      timeouts.ReadIntervalTimeout = 50;
      timeouts.ReadTotalTimeoutConstant = 50;
      timeouts.WriteTotalTimeoutConstant = 1000;
      (void)SetCommTimeouts(handle, &timeouts);
      return handle;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return INVALID_HANDLE_VALUE;
}

std::string PayloadString(const antimal::HostChannelFrame &frame) {
  return std::string(frame.payload.begin(), frame.payload.end());
}

bool ContainsText(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

antimal::EventRecord MakeAgentEvent(std::string action, std::string target = {}) {
  antimal::EventRecord ev;
  ev.timestampUtc = antimal::UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "agent";
  ev.action = std::move(action);
  ev.processId = static_cast<uint32_t>(GetCurrentProcessId());
  ev.target = std::move(target);
  return ev;
}

bool SendAgentEvent(HANDLE com2, const antimal::EventRecord &event) {
  return SendFrame(com2, antimal::HostChannelMessage::Event,
                   antimal::SerializeEventJsonLine(event));
}

bool SendHealthcheck(HANDLE com2, const std::string &jobPayload) {
  auto start = MakeAgentEvent("agent.job.start", "healthcheck");
  start.details["kind"] = "healthcheck";
  start.details["allowSampleExecution"] = "false";
  if (!SendAgentEvent(com2, start)) {
    return false;
  }

  auto health = MakeAgentEvent("agent.healthcheck", "COM2");
  health.details["channel"] = "COM2";
  health.details["sampleExecutionAllowed"] = "false";
  health.details["payloadBytes"] = std::to_string(jobPayload.size());
  if (!SendAgentEvent(com2, health)) {
    return false;
  }

  antimal::JsonObjectBuilder artifact;
  artifact.AddString("kind", "healthcheck");
  artifact.AddString("status", "ok");
  artifact.AddString("timestampUtc", antimal::UtcNowIso8601());
  artifact.AddNumber("processId", static_cast<int64_t>(GetCurrentProcessId()));
  artifact.AddBool("sampleExecutionAllowed", false);
  artifact.AddString("channel", "COM2");
  const std::string artifactPayload =
      std::string("agent-health.json\n") + artifact.Finish();
  if (!SendFrame(com2, antimal::HostChannelMessage::ArtifactChunk,
                 artifactPayload)) {
    return false;
  }

  auto complete = MakeAgentEvent("agent.job.complete", "healthcheck");
  complete.details["status"] = "ok";
  complete.details["events"] = "3";
  complete.details["artifacts"] = "1";
  if (!SendAgentEvent(com2, complete)) {
    return false;
  }

  return SendFrame(com2, antimal::HostChannelMessage::ReportComplete,
                   "status=ok\nevents=3\nartifacts=1\nsampleExecuted=false\n");
}

bool ReadCom2Frames(HANDLE com2, antimal::HostSerialChannel *channel) {
  if (!channel) {
    return false;
  }
  for (;;) {
    uint8_t buffer[512]{};
    DWORD read = 0;
    if (!ReadFile(com2, buffer, sizeof(buffer), &read, nullptr)) {
      const DWORD err = GetLastError();
      return err == ERROR_TIMEOUT || err == ERROR_OPERATION_ABORTED;
    }
    if (read == 0) {
      return true;
    }
    channel->PushBytes(buffer, read);
    if (read < sizeof(buffer)) {
      return true;
    }
  }
}

int RunHostChannelLoop(std::string reason, bool serviceMode) {
  HANDLE com2 = OpenCom2WithRetry();
  if (com2 == INVALID_HANDLE_VALUE) {
    std::cerr << "GuestAgent: COM2 unavailable for heartbeat: "
              << GetLastError() << "\n";
    return 1;
  }

  const auto helloPayload = "AntiMal.GuestAgent hello; reason=" + reason +
                            "; pid=" + std::to_string(GetCurrentProcessId());
  if (!SendFrame(com2, antimal::HostChannelMessage::Hello, helloPayload)) {
    CloseHandle(com2);
    return 1;
  }

  antimal::HostSerialChannel incoming;
  bool healthcheckComplete = false;
  // Live process telemetry: snapshot the guest process table every few ticks
  // and stream the deltas (process.start/stop) to the host over COM2. The very
  // first snapshot emits a capped "process.running" baseline so the host's live
  // process panel shows what is already running.
  antimal::ProcessSnapshot knownProcs;
  bool processBaselineSent = false;
  constexpr uint32_t kProcessPollEveryTicks = 2; // ~2s between snapshots
  constexpr size_t kProcessBaselineCap = 64;
  constexpr size_t kProcessDeltaCap = 64;
  uint32_t tick = 0;
  const uint32_t maxTicks = serviceMode ? 24u * 60u * 60u : 120u;
  while (!g_stopRequested.load() && tick < maxTicks) {
    if (!ReadCom2Frames(com2, &incoming)) {
      CloseHandle(com2);
      return 1;
    }
    while (const auto frame = incoming.PopFrame()) {
      if (frame->type != antimal::HostChannelMessage::JobStart) {
        continue;
      }
      const auto payload = PayloadString(*frame);
      const bool isHealthcheck = ContainsText(payload, "\"kind\":\"healthcheck\"") ||
                                 ContainsText(payload, "\"kind\": \"healthcheck\"");
      const bool allowsSample = ContainsText(payload, "\"allowSampleExecution\":true") ||
                                ContainsText(payload, "\"allowSampleExecution\": true");
      if (isHealthcheck && !allowsSample && !healthcheckComplete) {
        healthcheckComplete = SendHealthcheck(com2, payload);
      } else {
        auto rejected = MakeAgentEvent("agent.job.rejected", "host-channel");
        rejected.details["reason"] =
            allowsSample ? "sample-execution-not-authorized"
                         : "unsupported-job";
        (void)SendAgentEvent(com2, rejected);
      }
    }

    const std::string heartbeat =
        "heartbeat=" + std::to_string(tick) +
        "; healthcheckComplete=" + (healthcheckComplete ? "true" : "false");
    if (!SendFrame(com2, antimal::HostChannelMessage::Heartbeat, heartbeat)) {
      CloseHandle(com2);
      return 1;
    }

    if (tick % kProcessPollEveryTicks == 0) {
      auto current = antimal::CaptureProcessSnapshot();
      if (!current.empty() || processBaselineSent) {
        auto procEvents = antimal::DiffProcessSnapshots(
            knownProcs, current, !processBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        processBaselineSent = true;
        knownProcs = std::move(current);
        for (const auto &ev : procEvents) {
          if (!SendAgentEvent(com2, ev)) {
            CloseHandle(com2);
            return 1;
          }
        }
      }
    }

    ++tick;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  CloseHandle(com2);
  return 0;
}

bool GuestExecutionAuthorized() {
  wchar_t value[8]{};
  const DWORD len = GetEnvironmentVariableW(
      L"ANTIMAL_GUEST_ALLOW_EXECUTION", value,
      static_cast<DWORD>(std::size(value)));
  return len == 1 && value[0] == L'1';
}

int RunAuthorizedFileJob(const std::filesystem::path &jobPath) {
  auto job = antimal::LoadJobBestEffort(jobPath);
  if (job.samplePath.empty() || !std::filesystem::exists(job.samplePath)) {
    return RunHostChannelLoop("no-executable-job", false);
  }

  auto config = antimal::LoadConfig(antimal::DefaultConfigPath());
  const auto runDir = job.outputDir.empty()
                          ? std::filesystem::current_path()
                          : job.outputDir.parent_path();
  antimal::EnsureDirectory(runDir);

  auto journalPath = runDir / "events.jsonl";
  std::optional<antimal::EventJournalWriter> journal;
  try {
    journal.emplace(journalPath);
    EmitStartupEvent(*journal, job);
  } catch (const std::exception &ex) {
    std::cerr << "GuestAgent: journal disabled: " << ex.what() << "\n";
  }

  std::optional<antimal::ScreenshotLoop> shots;
  if (config.collectScreenshots && job.collectScreenshots) {
    shots.emplace(runDir / "screenshots",
                  std::chrono::milliseconds(config.screenshotIntervalMs));
    shots->Start();
  }

  auto report = antimal::RunGuestJob(job);

  if (shots) shots->Stop();

  if (journal) {
    antimal::EventRecord ev;
    ev.timestampUtc = antimal::UtcNowIso8601();
    ev.source = "GuestAgent";
    ev.category = "process";
    ev.action = "agent.stop";
    ev.processId = static_cast<uint32_t>(GetCurrentProcessId());
    ev.target = job.runId;
    ev.details["events"] = std::to_string(report.events.size());
    if (shots) {
      ev.details["screenshots"] = std::to_string(shots->FrameCount());
    }
    journal->Append(ev);
  }

  if (journal) {
    antimal::EventJournalTailer tail(journalPath);
    auto journaledEvents = tail.ReadAll();
    report.events.insert(report.events.end(),
                         std::make_move_iterator(journaledEvents.begin()),
                         std::make_move_iterator(journaledEvents.end()));
  }

  const auto reportPath = runDir / "report.json";
  antimal::WriteReportJson(reportPath, report);
  antimal::WriteReportHtml(runDir / "report.html", report);
  std::wcout << L"AntiMal GuestAgent wrote " << reportPath.wstring() << L"\n";
  return report.sandboxVerdict == antimal::Verdict::Error ? 2 : 0;
}

void ReportServiceStatus(DWORD state, DWORD win32ExitCode = NO_ERROR,
                         DWORD waitHint = 0) {
  if (!g_serviceStatusHandle) {
    return;
  }
  g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_serviceStatus.dwCurrentState = state;
  g_serviceStatus.dwWin32ExitCode = win32ExitCode;
  g_serviceStatus.dwWaitHint = waitHint;
  g_serviceStatus.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                               : 0;
  static DWORD checkpoint = 1;
  g_serviceStatus.dwCheckPoint =
      (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
  (void)SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
  if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
    g_stopRequested.store(true);
    ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 1000);
    return NO_ERROR;
  }
  return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR *) {
  g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(
      L"AntiMalGuestAgent", ServiceControlHandler, nullptr);
  if (!g_serviceStatusHandle) {
    return;
  }
  g_stopRequested.store(false);
  ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 1000);
  ReportServiceStatus(SERVICE_RUNNING);
  const int rc = RunHostChannelLoop("service", true);
  ReportServiceStatus(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int RunAsService() {
  SERVICE_TABLE_ENTRYW table[] = {
      {const_cast<LPWSTR>(L"AntiMalGuestAgent"), ServiceMain},
      {nullptr, nullptr},
  };
  if (StartServiceCtrlDispatcherW(table)) {
    return 0;
  }
  if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
    return RunHostChannelLoop("service-console", false);
  }
  return 1;
}

bool HasArg(int argc, wchar_t **argv, std::wstring_view needle) {
  for (int i = 1; i < argc; ++i) {
    if (argv[i] && needle == std::wstring_view(argv[i])) {
      return true;
    }
  }
  return false;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    if (HasArg(argc, argv, L"--service")) {
      return RunAsService();
    }

    std::filesystem::path jobPath =
        argc > 1 ? std::filesystem::path(argv[1])
                 : std::filesystem::current_path() / "job.json";
    if (!std::filesystem::exists(jobPath) || !GuestExecutionAuthorized()) {
      return RunHostChannelLoop(std::filesystem::exists(jobPath)
                                    ? "execution-gate-closed"
                                    : "no-job",
                                false);
    }

    return RunAuthorizedFileJob(jobPath);
  } catch (const std::exception &ex) {
    std::cerr << "GuestAgent error: " << ex.what() << "\n";
    return 1;
  }
}
