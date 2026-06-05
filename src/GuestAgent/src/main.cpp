#include "antimal/Config.h"
#include "antimal/DetonationProtocol.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/FileSystemTelemetry.h"
#include "antimal/GuestMonitor.h"
#include "antimal/HostChannel.h"
#include "antimal/NetworkTelemetry.h"
#include "antimal/RegistryTelemetry.h"
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

// Diagnostic breadcrumb: append a timestamped line to a fixed on-disk log so a
// post-boot overlay inspection can see how far the service actually got (the
// agent runs with full Win32, unlike the offline host-side writer that can only
// see COM2 byte counts). Best-effort, never throws; tries two locations in case
// one is unwritable for the LocalSystem service account.
void BootLog(const std::string &line) {
  for (const wchar_t *path : {L"C:\\AntiMal\\agent-boot.log",
                              L"C:\\Windows\\Temp\\antimal-agent-boot.log"}) {
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      continue;
    }
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[64];
    const int n =
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%02u:%02u:%02u.%03u ",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    DWORD w = 0;
    if (n > 0) {
      WriteFile(h, buf, static_cast<DWORD>(n), &w, nullptr);
    }
    WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
  }
}

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

bool WriteFileBytes(const std::filesystem::path &path,
                    const std::vector<uint8_t> &bytes) {
  HANDLE h = CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return false;
  }
  const bool ok = WriteAll(h, bytes);
  CloseHandle(h);
  return ok;
}

// Launches the delivered sample. CreateProcessW runs it in the agent's session
// (session 0 for the installed service); the process telemetry collector below
// captures its subtree regardless of session. Visible-desktop launch
// (CreateProcessAsUser into the active session) is a later refinement (SP5).
bool LaunchSampleProcess(const std::filesystem::path &path, DWORD *pid,
                         HANDLE *proc) {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::wstring cmd = L"\"" + path.wstring() + L"\"";
  cmd.push_back(L'\0');  // CreateProcessW may write into the buffer.
  const std::wstring workdir = path.parent_path().wstring();
  if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                      workdir.empty() ? nullptr : workdir.c_str(), &si, &pi)) {
    return false;
  }
  CloseHandle(pi.hThread);
  *pid = pi.dwProcessId;
  *proc = pi.hProcess;
  return true;
}

// Writes the reassembled sample to a per-run guest directory and launches it.
// Emits agent.sample.received + process.create over COM2. Returns true and fills
// proc/pid/deadline on success; false (with a failure event) otherwise.
bool LaunchExecuteJob(HANDLE com2, const antimal::ExecuteJobRequest &req,
                      const std::vector<uint8_t> &bytes, HANDLE *proc,
                      DWORD *pid, std::chrono::steady_clock::time_point *deadline) {
  auto received = MakeAgentEvent("agent.sample.received", req.sampleName);
  received.details["bytes"] = std::to_string(bytes.size());
  (void)SendAgentEvent(com2, received);

  const std::filesystem::path runDir =
      std::filesystem::path(L"C:\\AntiMal\\run") /
      std::filesystem::path(req.runId.empty() ? "exec" : req.runId);
  const std::filesystem::path sampleDir = runDir / "sample";
  antimal::EnsureDirectory(sampleDir);
  std::wstring safeName =
      std::filesystem::path(req.sampleName).filename().wstring();
  if (safeName.empty()) {
    safeName = L"sample.bin";
  }
  const std::filesystem::path samplePath = sampleDir / safeName;
  if (!WriteFileBytes(samplePath, bytes)) {
    auto fail = MakeAgentEvent("agent.sample.write-failed", req.sampleName);
    fail.details["error"] = std::to_string(GetLastError());
    (void)SendAgentEvent(com2, fail);
    return false;
  }

  DWORD launchedPid = 0;
  HANDLE launchedProc = nullptr;
  if (!LaunchSampleProcess(samplePath, &launchedPid, &launchedProc)) {
    auto fail = MakeAgentEvent("process.create-failed",
                               antimal::PathToUtf8(samplePath));
    fail.category = "process";
    fail.details["error"] = std::to_string(GetLastError());
    (void)SendAgentEvent(com2, fail);
    return false;
  }
  *proc = launchedProc;
  *pid = launchedPid;
  *deadline = std::chrono::steady_clock::now() +
              std::chrono::milliseconds(req.timeoutMs);
  auto created =
      MakeAgentEvent("process.create", antimal::PathToUtf8(samplePath));
  created.category = "process";
  created.processId = launchedPid;
  created.details["sampleExecuted"] = "true";
  (void)SendAgentEvent(com2, created);
  return true;
}

// Terminal failure of an execute job: an agent.job.rejected Event AND a
// ReportComplete(status=error) frame. The ReportComplete is the load-bearing
// part -- without it the host has no completion signal and waits out the entire
// detonation timeout, turning a fast clean failure into a multi-minute hang.
void SendExecuteFailure(HANDLE com2, const std::string &reason) {
  auto rejected = MakeAgentEvent("agent.job.rejected", "execute");
  rejected.details["reason"] = reason;
  (void)SendAgentEvent(com2, rejected);
  (void)SendFrame(com2, antimal::HostChannelMessage::ReportComplete,
                  std::string("status=error\nsampleExecuted=false\nreason=") +
                      reason + "\n");
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

// Defined below (wmain path also uses it); the service loop's execute branch
// needs it here, so forward-declare. True only when the guest's own gate
// (ANTIMAL_GUEST_ALLOW_EXECUTION=1) is set.
bool GuestExecutionAuthorized();

int RunHostChannelLoop(std::string reason, bool serviceMode) {
  BootLog("RunHostChannelLoop enter reason=" + reason +
          " serviceMode=" + (serviceMode ? "1" : "0") +
          " pid=" + std::to_string(GetCurrentProcessId()));
  HANDLE com2 = OpenCom2WithRetry();
  if (com2 == INVALID_HANDLE_VALUE) {
    BootLog("COM2 open FAILED err=" + std::to_string(GetLastError()));
    std::cerr << "GuestAgent: COM2 unavailable for heartbeat: "
              << GetLastError() << "\n";
    return 1;
  }
  BootLog("COM2 opened ok");

  const auto helloPayload = "AntiMal.GuestAgent hello; reason=" + reason +
                            "; pid=" + std::to_string(GetCurrentProcessId());
  if (!SendFrame(com2, antimal::HostChannelMessage::Hello, helloPayload)) {
    BootLog("Hello send FAILED err=" + std::to_string(GetLastError()));
    CloseHandle(com2);
    return 1;
  }
  BootLog("Hello sent ok");

  antimal::HostSerialChannel incoming;
  bool healthcheckComplete = false;
  // Live process telemetry: snapshot the guest process table every few ticks
  // and stream the deltas (process.start/stop) to the host over COM2. The very
  // first snapshot emits a capped "process.running" baseline so the host's live
  // process panel shows what is already running.
  antimal::ProcessSnapshot knownProcs;
  bool processBaselineSent = false;
  antimal::TcpSnapshot knownConns;
  bool netBaselineSent = false;
  antimal::RegistrySnapshot knownReg;
  bool regBaselineSent = false;
  antimal::FileSnapshot knownFiles;
  bool fileBaselineSent = false;
  const std::vector<std::filesystem::path> watchedDirs =
      antimal::DefaultWatchedDirs();
  // Authorized-detonation state: an execute JobStart opens a transfer, the
  // SampleChunk frames fill the reassembler, then the sample launches and we
  // track it to exit/timeout. All gated on GuestExecutionAuthorized().
  std::optional<antimal::ExecuteJobRequest> executeReq;
  std::optional<antimal::SampleReassembler> reassembler;
  HANDLE sampleProcess = nullptr;
  DWORD samplePid = 0;
  std::chrono::steady_clock::time_point sampleDeadline{};
  // Bounds the sample TRANSFER (JobStart -> all SampleChunks). Without it, a lost
  // chunk would leave the agent waiting on Complete() forever (24h in service
  // mode). 90s is generous: the COM2 link is ~11 KB/s, so even an 8 MB sample
  // (the cap) drains in well under that.
  std::chrono::steady_clock::time_point transferDeadline{};
  constexpr int kTransferTimeoutSec = 90;
  bool sampleLaunched = false;
  bool sampleReported = false;
  constexpr uint32_t kProcessPollEveryTicks = 2; // ~2s between snapshots
  constexpr uint32_t kFilePollEveryTicks = 5;    // file walk is heavier
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
      if (frame->type == antimal::HostChannelMessage::SampleChunk) {
        // Sample bytes for an authorized execute job, arriving after the
        // JobStart. Collect until complete, then write + launch.
        if (!executeReq || !reassembler || sampleLaunched) {
          continue;  // no pending transfer
        }
        const auto chunk = antimal::ParseSampleChunkPayload(frame->payload);
        if (!chunk || !reassembler->Add(*chunk)) {
          SendExecuteFailure(com2, "sample-transfer-error");
          executeReq.reset();
          reassembler.reset();
          continue;
        }
        if (reassembler->Complete()) {
          sampleLaunched =
              LaunchExecuteJob(com2, *executeReq, reassembler->Bytes(),
                               &sampleProcess, &samplePid, &sampleDeadline);
          if (!sampleLaunched) {
            // LaunchExecuteJob already emitted the specific failure Event
            // (write-failed / create-failed); add the completion signal.
            (void)SendFrame(com2, antimal::HostChannelMessage::ReportComplete,
                            "status=error\nsampleExecuted=false\n"
                            "reason=sample-launch-failed\n");
            executeReq.reset();
            reassembler.reset();
          }
        }
        continue;
      }
      if (frame->type != antimal::HostChannelMessage::JobStart) {
        continue;
      }
      const auto payload = PayloadString(*frame);
      const auto req = antimal::ParseExecuteJobJson(payload);
      if (req.isExecute && req.allowSampleExecution) {
        // Authorized execute job. The guest re-checks its own gate before
        // accepting the transfer; a host that armed execution without the guest
        // being authorized is rejected here.
        if (!GuestExecutionAuthorized()) {
          // Terminal: the host armed execution but the guest's own key is not
          // set. Report it so the operator sees the gate was closed in-guest.
          SendExecuteFailure(com2, "sample-execution-not-authorized");
        } else if (req.sampleBytes == 0) {
          SendExecuteFailure(com2, "empty-sample");
        } else if (executeReq || sampleLaunched) {
          // A job is already in flight -- not terminal for that job, so this is
          // a plain rejection with no ReportComplete.
          auto rejected = MakeAgentEvent("agent.job.rejected", "execute");
          rejected.details["reason"] = "execute-already-active";
          (void)SendAgentEvent(com2, rejected);
        } else {
          executeReq = req;
          reassembler.emplace(req.sampleBytes);
          transferDeadline = std::chrono::steady_clock::now() +
                             std::chrono::seconds(kTransferTimeoutSec);
          auto started = MakeAgentEvent("agent.job.start", "execute");
          started.details["kind"] = "execute";
          started.details["sampleName"] = req.sampleName;
          started.details["sampleBytes"] = std::to_string(req.sampleBytes);
          (void)SendAgentEvent(com2, started);
        }
        continue;
      }
      const bool isHealthcheck = ContainsText(payload, "\"kind\":\"healthcheck\"") ||
                                 ContainsText(payload, "\"kind\": \"healthcheck\"");
      if (isHealthcheck && !req.allowSampleExecution && !healthcheckComplete) {
        healthcheckComplete = SendHealthcheck(com2, payload);
      } else {
        auto rejected = MakeAgentEvent("agent.job.rejected", "host-channel");
        rejected.details["reason"] = "unsupported-job";
        (void)SendAgentEvent(com2, rejected);
      }
    }

    // Transfer watchdog: an execute job was armed but the sample never fully
    // arrived within the budget (a dropped/never-delivered chunk). Fail it with a
    // ReportComplete so the host finalizes instead of heartbeating to maxTicks.
    if (executeReq && !sampleLaunched &&
        std::chrono::steady_clock::now() >= transferDeadline) {
      auto note = MakeAgentEvent("agent.sample.transfer-timeout",
                                 executeReq->sampleName);
      note.details["received"] =
          std::to_string(reassembler ? reassembler->Received() : 0);
      note.details["expected"] =
          std::to_string(reassembler ? reassembler->Expected() : 0);
      (void)SendAgentEvent(com2, note);
      SendExecuteFailure(com2, "sample-transfer-timeout");
      executeReq.reset();
      reassembler.reset();
    }

    // Track a launched sample to exit/timeout, then send ReportComplete. The
    // process-telemetry poll below keeps streaming its subtree meanwhile.
    if (sampleLaunched && !sampleReported) {
      const bool exited =
          WaitForSingleObject(sampleProcess, 0) == WAIT_OBJECT_0;
      const bool timedOut = std::chrono::steady_clock::now() >= sampleDeadline;
      if (exited || timedOut) {
        DWORD exitCode = 0;
        if (exited) {
          GetExitCodeProcess(sampleProcess, &exitCode);
        } else {
          TerminateProcess(sampleProcess, 0xDEADu);
        }
        auto done = MakeAgentEvent(exited ? "process.exit" : "process.timeout",
                                   executeReq ? executeReq->sampleName : "");
        done.category = "process";
        done.processId = samplePid;
        done.details["exitCode"] = std::to_string(exitCode);
        (void)SendAgentEvent(com2, done);
        (void)SendFrame(com2, antimal::HostChannelMessage::ReportComplete,
                        std::string("status=ok\nsampleExecuted=true\nexitCode=") +
                            std::to_string(exitCode) + "\n");
        CloseHandle(sampleProcess);
        sampleProcess = nullptr;
        sampleReported = true;
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

    // Network-connection telemetry: snapshot the guest TCP table and stream
    // network.connect / network.close deltas (what the sample is reaching out
    // to). Fully meaningful once the VM has a NIC (SP3); until then it captures
    // local/loopback connections.
    if (tick % kProcessPollEveryTicks == 0) {
      auto conns = antimal::CaptureTcpConnections();
      if (!conns.empty() || netBaselineSent) {
        auto netEvents = antimal::DiffTcpConnections(
            knownConns, conns, !netBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        netBaselineSent = true;
        knownConns = std::move(conns);
        for (const auto &ev : netEvents) {
          if (!SendAgentEvent(com2, ev)) {
            CloseHandle(com2);
            return 1;
          }
        }
      }
    }

    // Registry-persistence telemetry: snapshot the autostart keys and stream
    // registry.set / registry.delete deltas (did the sample install persistence?).
    if (tick % kProcessPollEveryTicks == 0) {
      auto reg = antimal::CaptureRegistrySnapshot();
      if (!reg.empty() || regBaselineSent) {
        auto regEvents = antimal::DiffRegistrySnapshots(
            knownReg, reg, !regBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        regBaselineSent = true;
        knownReg = std::move(reg);
        for (const auto &ev : regEvents) {
          if (!SendAgentEvent(com2, ev)) {
            CloseHandle(com2);
            return 1;
          }
        }
      }
    }

    // Filesystem telemetry: snapshot the drop directories and stream
    // file.create / file.modify / file.delete deltas. Polled less often than the
    // others because the directory walk is heavier.
    if (tick % kFilePollEveryTicks == 0) {
      auto files = antimal::CaptureFileSnapshot(watchedDirs);
      if (!files.empty() || fileBaselineSent) {
        auto fileEvents = antimal::DiffFileSnapshots(
            knownFiles, files, !fileBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        fileBaselineSent = true;
        knownFiles = std::move(files);
        for (const auto &ev : fileEvents) {
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
  BootLog("ServiceMain entered");
  g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(
      L"AntiMalGuestAgent", ServiceControlHandler, nullptr);
  if (!g_serviceStatusHandle) {
    BootLog("RegisterServiceCtrlHandlerEx FAILED err=" +
            std::to_string(GetLastError()));
    return;
  }
  g_stopRequested.store(false);
  ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 1000);
  ReportServiceStatus(SERVICE_RUNNING);
  const int rc = RunHostChannelLoop("service", true);
  ReportServiceStatus(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int RunAsService() {
  BootLog("RunAsService: calling StartServiceCtrlDispatcher");
  SERVICE_TABLE_ENTRYW table[] = {
      {const_cast<LPWSTR>(L"AntiMalGuestAgent"), ServiceMain},
      {nullptr, nullptr},
  };
  if (StartServiceCtrlDispatcherW(table)) {
    BootLog("StartServiceCtrlDispatcher returned 0 (clean)");
    return 0;
  }
  const DWORD err = GetLastError();
  BootLog("StartServiceCtrlDispatcher FAILED err=" + std::to_string(err));
  if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
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
  BootLog("wmain start argc=" + std::to_string(argc) +
          " service=" + (HasArg(argc, argv, L"--service") ? "1" : "0"));
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
