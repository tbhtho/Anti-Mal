#include "antimal/Config.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/GuestMonitor.h"
#include "antimal/Report.h"
#include "antimal/Screenshot.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

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

void PutU16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutU32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

uint32_t FrameChecksum(const uint8_t *data, size_t size) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash;
}

std::vector<uint8_t> EncodeHostFrame(uint16_t type, std::string_view payload) {
  constexpr uint8_t kMagic[] = {'A', 'M', 'C', 'H'};
  std::vector<uint8_t> out;
  out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
  PutU16(out, 1);
  PutU16(out, type);
  PutU32(out, static_cast<uint32_t>(payload.size()));
  PutU32(out, FrameChecksum(reinterpret_cast<const uint8_t *>(payload.data()),
                            payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
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

HANDLE OpenCom2WithRetry() {
  for (int attempt = 0; attempt < 60; ++attempt) {
    HANDLE handle = CreateFileW(L"\\\\.\\COM2", GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
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
      timeouts.WriteTotalTimeoutConstant = 1000;
      (void)SetCommTimeouts(handle, &timeouts);
      return handle;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return INVALID_HANDLE_VALUE;
}

int RunHeartbeatOnly(std::string reason) {
  HANDLE com2 = OpenCom2WithRetry();
  if (com2 == INVALID_HANDLE_VALUE) {
    std::cerr << "GuestAgent: COM2 unavailable for heartbeat: "
              << GetLastError() << "\n";
    return 1;
  }

  const auto hello = EncodeHostFrame(
      1, "AntiMal.GuestAgent hello; reason=" + reason +
             "; pid=" + std::to_string(GetCurrentProcessId()));
  if (!WriteAll(com2, hello)) {
    CloseHandle(com2);
    return 1;
  }

  for (uint32_t tick = 0; tick < 120; ++tick) {
    const auto heartbeat =
        EncodeHostFrame(9, "heartbeat=" + std::to_string(tick));
    if (!WriteAll(com2, heartbeat)) {
      CloseHandle(com2);
      return 1;
    }
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

} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    std::filesystem::path jobPath = argc > 1 ? std::filesystem::path(argv[1])
                                             : std::filesystem::current_path() / "job.json";
    if (!std::filesystem::exists(jobPath) || !GuestExecutionAuthorized()) {
      return RunHeartbeatOnly(std::filesystem::exists(jobPath)
                                  ? "execution-gate-closed"
                                  : "no-job");
    }

    auto job = antimal::LoadJobBestEffort(jobPath);
    if (job.samplePath.empty() || !std::filesystem::exists(job.samplePath)) {
      return RunHeartbeatOnly("no-executable-job");
    }

    // Load app config so the agent honors the same screenshot/journal knobs
    // as the host. The config file lives wherever the orchestrator dropped
    // it; fall back to the default location if not provided.
    auto config = antimal::LoadConfig(antimal::DefaultConfigPath());

    const auto runDir = job.outputDir.empty()
                            ? std::filesystem::current_path()
                            : job.outputDir.parent_path();
    antimal::EnsureDirectory(runDir);

    // Journal lives at runDir/events.jsonl so the host tailer can find it.
    auto journalPath = runDir / "events.jsonl";
    std::optional<antimal::EventJournalWriter> journal;
    try {
      journal.emplace(journalPath);
      EmitStartupEvent(*journal, job);
    } catch (const std::exception &ex) {
      std::cerr << "GuestAgent: journal disabled: " << ex.what() << "\n";
    }

    // Screenshot loop (only when configured + the job opts in).
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

    // Fold any journaled events into the final report so the host sees
    // them even if it doesn't tail the journal directly.
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
  } catch (const std::exception &ex) {
    std::cerr << "GuestAgent error: " << ex.what() << "\n";
    return 1;
  }
}
