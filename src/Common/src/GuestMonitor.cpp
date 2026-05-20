#include "antimal/GuestMonitor.h"

#include "antimal/FileUtil.h"
#include "antimal/Json.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"

#include <Windows.h>

#include <regex>
#include <sstream>

namespace antimal {
namespace {

std::string RegexValue(const std::string &text, const std::string &key) {
  std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch match;
  if (std::regex_search(text, match, re)) {
    return match[1].str();
  }
  return {};
}

uint32_t RegexNumber(const std::string &text, const std::string &key, uint32_t fallback) {
  std::regex re("\"" + key + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(text, match, re)) {
    return static_cast<uint32_t>(std::stoul(match[1].str()));
  }
  return fallback;
}

EventRecord MakeEvent(std::string category, std::string action, std::string target) {
  EventRecord event;
  event.timestampUtc = UtcNowIso8601();
  event.source = "guest-agent";
  event.category = std::move(category);
  event.action = std::move(action);
  event.target = std::move(target);
  return event;
}

} // namespace

JobConfig LoadJobBestEffort(const std::filesystem::path &path) {
  const std::string text = ReadTextFile(path);
  JobConfig job;
  job.runId = RegexValue(text, "runId");
  job.samplePath = Utf8ToWide(RegexValue(text, "samplePath"));
  job.timeoutMs = RegexNumber(text, "timeoutMs", 180000);
  const auto mode = ParseNetworkMode(RegexValue(text, "networkMode"));
  if (mode) {
    job.networkMode = *mode;
  }
  job.outputDir = Utf8ToWide(RegexValue(text, "outputDir"));
  if (job.outputDir.empty()) {
    job.outputDir = path.parent_path() / "out";
  }
  return job;
}

AnalysisReport RunGuestJob(const JobConfig &job) {
  AnalysisReport report;
  report.runId = job.runId.empty() ? MakeRunId() : job.runId;
  report.samplePath = job.samplePath;
  report.scannerVerdict = ScanFile(job.samplePath);
  report.sandboxVerdict = Verdict::Suspicious;
  report.events.push_back(MakeEvent("agent", "job-start", PathToUtf8(job.samplePath)));

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};

  std::wstring command = L"\"" + job.samplePath.wstring() + L"\"";
  std::wstring mutableCommand = command;
  const BOOL created = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                                      CREATE_NO_WINDOW, nullptr,
                                      job.samplePath.parent_path().wstring().c_str(), &startup,
                                      &process);
  if (!created) {
    report.sandboxVerdict = Verdict::Error;
    report.errors.push_back("CreateProcessW failed with error " +
                            std::to_string(GetLastError()));
    report.events.push_back(MakeEvent("process", "create-failed", PathToUtf8(job.samplePath)));
    return report;
  }

  EventRecord start = MakeEvent("process", "create", PathToUtf8(job.samplePath));
  start.processId = process.dwProcessId;
  report.events.push_back(start);

  const DWORD wait = WaitForSingleObject(process.hProcess, job.timeoutMs);
  if (wait == WAIT_TIMEOUT) {
    TerminateProcess(process.hProcess, 0xDEAD);
    report.sandboxVerdict = Verdict::Malicious;
    report.events.push_back(MakeEvent("process", "timeout-terminated",
                                      PathToUtf8(job.samplePath)));
  } else {
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    EventRecord exit = MakeEvent("process", "exit", PathToUtf8(job.samplePath));
    exit.processId = process.dwProcessId;
    exit.details["exitCode"] = std::to_string(exitCode);
    report.events.push_back(exit);
  }

  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);

  EnsureDirectory(job.outputDir);
  report.events.push_back(MakeEvent("agent", "job-complete", PathToUtf8(job.outputDir)));
  return report;
}

} // namespace antimal
