#include "antimal/ProcessTelemetry.h"

#include "antimal/FileUtil.h" // UtcNowIso8601

#include <cstdio> // _snprintf_s (hex exit-code formatting)

#ifdef _WIN32
#include <Windows.h>
#include <tlhelp32.h>
#endif

namespace antimal {

namespace {

EventRecord MakeProcessEvent(const std::string &action, uint32_t pid,
                             const ProcessInfo &info) {
  EventRecord ev;
  ev.timestampUtc = UtcNowIso8601();
  ev.source = "GuestAgent";
  ev.category = "process";
  ev.action = action;
  ev.processId = pid;
  ev.parentProcessId = info.parentPid;
  ev.imagePath = info.image;
  // Target shows the full path when we have it (more useful in the UI), else
  // the base name.
  ev.target = info.fullImagePath.empty() ? info.image : info.fullImagePath;
  ev.fullImagePath = info.fullImagePath;
  ev.commandLine = info.commandLine;
  ev.integrityLevel = info.integrityLevel;
  ev.userName = info.userName;
  ev.details["pid"] = std::to_string(pid);
  ev.details["ppid"] = std::to_string(info.parentPid);
  // Lower-frequency attributes ride in the details map (round-trips through
  // both serializers without per-field plumbing). Only set keys we captured.
  if (!info.userSid.empty()) {
    ev.details["sid"] = info.userSid;
  }
  if (info.hasSessionId) {
    ev.details["sessionId"] = std::to_string(info.sessionId);
  }
  if (!info.startTimeUtc.empty()) {
    ev.details["startTime"] = info.startTimeUtc;
  }
  // Exit code is the high-value signal — render in hex so crash codes like
  // 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN) are immediately recognizable.
  if (info.hasExitCode) {
    char hex[16];
    _snprintf_s(hex, sizeof(hex), _TRUNCATE, "0x%08X", info.exitCode);
    ev.details["exitCode"] = hex;
  }
  return ev;
}

} // namespace

ProcessSnapshot CaptureProcessSnapshot() {
  ProcessSnapshot out;
#ifdef _WIN32
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return out;
  }
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      ProcessInfo info;
      info.parentPid = pe.th32ParentProcessID;
      char narrow[MAX_PATH * 2]{};
      const int n =
          WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow,
                              static_cast<int>(sizeof(narrow)), nullptr, nullptr);
      info.image = n > 0 ? std::string(narrow) : std::string();
      out[pe.th32ProcessID] = std::move(info);
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
#endif
  return out;
}

std::vector<EventRecord> DiffProcessSnapshots(const ProcessSnapshot &prev,
                                              const ProcessSnapshot &cur,
                                              bool emitBaseline,
                                              size_t baselineCap,
                                              size_t deltaCap) {
  std::vector<EventRecord> events;
  if (emitBaseline) {
    size_t count = 0;
    for (const auto &entry : cur) {
      if (count++ >= baselineCap) {
        break;
      }
      events.push_back(MakeProcessEvent("process.running", entry.first, entry.second));
    }
    return events;
  }

  size_t started = 0;
  for (const auto &entry : cur) {
    if (prev.find(entry.first) == prev.end()) {
      if (started++ >= deltaCap) {
        break;
      }
      events.push_back(MakeProcessEvent("process.start", entry.first, entry.second));
    }
  }
  for (const auto &entry : prev) {
    if (cur.find(entry.first) == cur.end()) {
      events.push_back(MakeProcessEvent("process.stop", entry.first, entry.second));
    }
  }
  return events;
}

} // namespace antimal
