#include "antimal/Config.h"
#include "antimal/DetonationProtocol.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/FileSystemTelemetry.h"
#include "antimal/GuestMonitor.h"
#include "antimal/HostChannel.h"
#include "antimal/ImageLoadTelemetry.h"
#include "antimal/NetworkTelemetry.h"
#include "antimal/RegistryTelemetry.h"
#include "antimal/Json.h"
#include "antimal/ProcessTelemetry.h"
#include "antimal/Report.h"
#include "antimal/Screenshot.h"
#include "antimal/SensorCoverage.h"
#include "antimal/WerReport.h"

#include <Windows.h>
#include <winioctl.h>  // IOCTL_DISK_GET_LENGTH_INFO (raw sample-disk delivery)
#include <tlhelp32.h>  // CreateToolhelp32Snapshot (per-process module enumeration)
#include <UserEnv.h>   // CreateEnvironmentBlock (visible-session launch)
#include <WtsApi32.h>  // WTSQueryUserToken (active console session token)
#include <sddl.h>      // ConvertSidToStringSidW (process-token SID string)
#include <winternl.h>  // NTSTATUS / UNICODE_STRING for the ntdll command-line query

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <set>
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

// ---------------------------------------------------------------------------
// Deep process telemetry (backlog T11).
//
// Enriches each tracked guest process with the detail an Any.Run-class report
// expects: full image path, command line, integrity level, token user/SID,
// session id, start time, and -- the high-value one -- the exit code, captured
// at the moment a tracked process exits (so a crash code like 0xC0000409,
// STATUS_STACK_BUFFER_OVERRUN, surfaces as telemetry instead of a guess).
//
// The agent runs as LocalSystem, so enabling SeDebugPrivilege lets it open
// cross-session processes with PROCESS_QUERY_LIMITED_INFORMATION. The pure diff
// (DiffProcessSnapshots) consumes whatever we fill in here -- it never calls an
// OS API itself, so it stays host-unit-testable.
// ---------------------------------------------------------------------------

void EnableDebugPrivilege() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    return;
  }
  LUID luid{};
  if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    (void)AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
  }
  CloseHandle(token);
}

std::string NarrowUtf8(const wchar_t *wide, int wideLen = -1) {
  if (!wide || !*wide) {
    return {};
  }
  const int n =
      WideCharToMultiByte(CP_UTF8, 0, wide, wideLen, nullptr, 0, nullptr, nullptr);
  if (n <= 0) {
    return {};
  }
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide, wideLen, out.data(), n, nullptr, nullptr);
  // For a NUL-terminated source the count includes the terminator; trim it.
  if (wideLen == -1 && !out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}

// FILETIME (100ns ticks since 1601) -> "YYYY-MM-DDTHH:MM:SSZ".
std::string FileTimeToIso8601Utc(const FILETIME &ft) {
  if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
    return {};
  }
  SYSTEMTIME st{};
  if (!FileTimeToSystemTime(&ft, &st)) {
    return {};
  }
  char buf[32];
  _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  return std::string(buf);
}

std::string IntegrityLevelString(HANDLE token) {
  DWORD size = 0;
  GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
  if (size == 0) {
    return {};
  }
  std::vector<unsigned char> buf(size);
  if (!GetTokenInformation(token, TokenIntegrityLevel, buf.data(), size,
                           &size)) {
    return {};
  }
  auto *til = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(buf.data());
  const DWORD subCount = *GetSidSubAuthorityCount(til->Label.Sid);
  if (subCount == 0) {
    return {};
  }
  const DWORD rid = *GetSidSubAuthority(til->Label.Sid, subCount - 1);
  if (rid < SECURITY_MANDATORY_LOW_RID) {
    return "Untrusted";
  }
  if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
    return "Low";
  }
  if (rid < SECURITY_MANDATORY_HIGH_RID) {
    return "Medium";
  }
  if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
    return "High";
  }
  return "System";
}

void FillTokenIdentity(HANDLE process, antimal::ProcessInfo &info) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
    return;
  }
  info.integrityLevel = IntegrityLevelString(token);

  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  if (size > 0) {
    std::vector<unsigned char> buf(size);
    if (GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
      auto *tu = reinterpret_cast<TOKEN_USER *>(buf.data());
      LPWSTR sidStr = nullptr;
      if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
        info.userSid = NarrowUtf8(sidStr);
        LocalFree(sidStr);
      }
      wchar_t name[256];
      wchar_t domain[256];
      DWORD nameLen = 256;
      DWORD domainLen = 256;
      SID_NAME_USE use{};
      if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen, domain,
                            &domainLen, &use)) {
        std::string domainUtf8 = NarrowUtf8(domain);
        std::string nameUtf8 = NarrowUtf8(name);
        info.userName =
            domainUtf8.empty() ? nameUtf8 : (domainUtf8 + "\\" + nameUtf8);
      }
    }
  }
  CloseHandle(token);
}

// ProcessCommandLineInformation == 60 (Win8.1+; supported on Win11). The query
// returns a UNICODE_STRING followed inline by the command-line buffer.
constexpr int kProcessCommandLineInformation = 60;
constexpr size_t kCommandLineCap = 4096;

std::string QueryCommandLine(HANDLE process) {
  using NtQip_t = LONG(NTAPI *)(HANDLE, int, PVOID, ULONG, PULONG);
  static NtQip_t ntqip = []() -> NtQip_t {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    return nt ? reinterpret_cast<NtQip_t>(
                    GetProcAddress(nt, "NtQueryInformationProcess"))
              : nullptr;
  }();
  if (!ntqip) {
    return {};
  }
  ULONG needed = 0;
  // First call sizes the buffer (STATUS_INFO_LENGTH_MISMATCH expected).
  ntqip(process, kProcessCommandLineInformation, nullptr, 0, &needed);
  if (needed == 0 || needed > (1u << 20)) {
    return {};
  }
  std::vector<unsigned char> buf(needed);
  const LONG status = ntqip(process, kProcessCommandLineInformation, buf.data(),
                            needed, &needed);
  if (status < 0) {
    return {};
  }
  auto *us = reinterpret_cast<UNICODE_STRING *>(buf.data());
  if (!us->Buffer || us->Length == 0) {
    return {};
  }
  std::string cmd =
      NarrowUtf8(us->Buffer, static_cast<int>(us->Length / sizeof(wchar_t)));
  if (cmd.size() > kCommandLineCap) {
    cmd.resize(kCommandLineCap);
    cmd += "...(truncated)";
  }
  return cmd;
}

// Opens `pid` and enriches `info` (full path, command line, integrity, user,
// SID, session, start time). On success the returned handle is kept by the
// caller (in the per-PID handle map) so the exit code can be read later; the
// caller owns closing it. Returns nullptr if the process can't be opened.
HANDLE EnrichProcessInfo(uint32_t pid, antimal::ProcessInfo &info) {
  if (pid == 0) {
    return nullptr;
  }
  HANDLE process =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!process) {
    return nullptr;
  }
  wchar_t path[MAX_PATH * 2];
  DWORD pathLen = static_cast<DWORD>(std::size(path));
  if (QueryFullProcessImageNameW(process, 0, path, &pathLen)) {
    info.fullImagePath = NarrowUtf8(path, static_cast<int>(pathLen));
  }
  info.commandLine = QueryCommandLine(process);
  FillTokenIdentity(process, info);

  DWORD session = 0;
  if (ProcessIdToSessionId(pid, &session)) {
    info.sessionId = session;
    info.hasSessionId = true;
  }
  FILETIME creation{}, exitT{}, kernelT{}, userT{};
  if (GetProcessTimes(process, &creation, &exitT, &kernelT, &userT)) {
    info.startTimeUtc = FileTimeToIso8601Utc(creation);
  }
  return process;
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
      // Enlarge the driver's receive buffer so paced host->guest bursts (the
      // ~100 KB detonation payload) can't overrun it when a telemetry tick
      // briefly delays the agent's next read -- an overrun drops bytes, fails a
      // frame checksum, and aborts the strict in-order reassembler
      // (sample-transfer-error). 1 MiB comfortably holds the whole payload.
      (void)SetupComm(handle, 1u << 20, 4096);
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

// Launches the delivered sample. SP5: when an interactive console session is
// logged in, launch the sample INTO that session (CreateProcessAsUserW on
// winsta0\\default) so it runs VISIBLY on the desktop the analyst is watching --
// the Any.Run experience. Falls back to a headless session-0 CreateProcessW when
// no console session is available (e.g. still at the lock screen). The process
// telemetry collector captures its subtree either way. `*interactive` reports
// which path was taken so the host can show it.
bool LaunchSampleProcess(const std::filesystem::path &path, DWORD *pid,
                         HANDLE *proc, bool *interactive) {
  if (interactive) *interactive = false;
  std::wstring cmd = L"\"" + path.wstring() + L"\"";
  cmd.push_back(L'\0');  // CreateProcess* may write into the buffer.
  const std::wstring workdir = path.parent_path().wstring();
  const wchar_t *cwd = workdir.empty() ? nullptr : workdir.c_str();

  const DWORD sessionId = WTSGetActiveConsoleSessionId();
  if (sessionId != 0xFFFFFFFFu) {
    HANDLE userToken = nullptr;
    if (WTSQueryUserToken(sessionId, &userToken)) {
      STARTUPINFOW si{};
      si.cb = sizeof(si);
      wchar_t desktop[] = L"winsta0\\default";
      si.lpDesktop = desktop;
      PROCESS_INFORMATION pi{};
      LPVOID env = nullptr;
      const bool haveEnv =
          CreateEnvironmentBlock(&env, userToken, FALSE) != FALSE;
      const BOOL ok = CreateProcessAsUserW(
          userToken, nullptr, cmd.data(), nullptr, nullptr, FALSE,
          (haveEnv ? CREATE_UNICODE_ENVIRONMENT : 0u) | CREATE_NEW_CONSOLE,
          haveEnv ? env : nullptr, cwd, &si, &pi);
      if (haveEnv) DestroyEnvironmentBlock(env);
      CloseHandle(userToken);
      if (ok) {
        CloseHandle(pi.hThread);
        *pid = pi.dwProcessId;
        *proc = pi.hProcess;
        if (interactive) *interactive = true;
        return true;
      }
      // No usable interactive session -> fall through to the session-0 launch.
    }
  }

  // Fallback 2: duplicate our own (SYSTEM) token into the ACTIVE console
  // session and launch there. This keeps the sample VISIBLE on the logged-in
  // desktop even when the per-user token path above refuses -- e.g. the user
  // token is UAC-filtered while the executable's manifest requires elevation
  // (common for installers), or WTSQueryUserToken succeeded but the secondary
  // token cannot create the process. The session id must be set on the token
  // before CreateProcessAsUser, which is what makes the window land on the
  // interactive desktop instead of the invisible session 0.
  if (sessionId != 0xFFFFFFFFu) {
    HANDLE selfToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &selfToken)) {
      HANDLE sessionToken = nullptr;
      if (DuplicateTokenEx(selfToken, MAXIMUM_ALLOWED, nullptr,
                           SecurityImpersonation, TokenPrimary,
                           &sessionToken)) {
        DWORD sessionForToken = sessionId;
        if (SetTokenInformation(sessionToken, TokenSessionId,
                                &sessionForToken,
                                sizeof(sessionForToken))) {
          STARTUPINFOW si2{};
          si2.cb = sizeof(si2);
          wchar_t desktop2[] = L"winsta0\\default";
          si2.lpDesktop = desktop2;
          PROCESS_INFORMATION pi2{};
          LPVOID env2 = nullptr;
          const bool haveEnv2 =
              CreateEnvironmentBlock(&env2, sessionToken, FALSE) != FALSE;
          const BOOL ok2 = CreateProcessAsUserW(
              sessionToken, nullptr, cmd.data(), nullptr, nullptr, FALSE,
              (haveEnv2 ? CREATE_UNICODE_ENVIRONMENT : 0u) | CREATE_NEW_CONSOLE,
              haveEnv2 ? env2 : nullptr, cwd, &si2, &pi2);
          if (haveEnv2) {
            DestroyEnvironmentBlock(env2);
          }
          if (ok2) {
            CloseHandle(pi2.hThread);
            CloseHandle(sessionToken);
            CloseHandle(selfToken);
            *pid = pi2.dwProcessId;
            *proc = pi2.hProcess;
            if (interactive) *interactive = true;
            return true;
          }
        }
        CloseHandle(sessionToken);
      }
      CloseHandle(selfToken);
    }
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                      cwd, &si, &pi)) {
    return false;
  }
  CloseHandle(pi.hThread);
  *pid = pi.dwProcessId;
  *proc = pi.hProcess;
  return true;
}

// True when an interactive user is logged in to the active console session (the
// desktop is up). Used to defer the sample launch until SP5 can place it on the
// visible desktop instead of headless session 0.
bool HasInteractiveSession() {
  const DWORD sid = WTSGetActiveConsoleSessionId();
  if (sid == 0xFFFFFFFFu) {
    return false;
  }
  HANDLE token = nullptr;
  if (!WTSQueryUserToken(sid, &token)) {
    return false;
  }
  CloseHandle(token);
  return true;
}

// Resolves WHAT to launch (the sample itself, or -- for a delivered .iso -- the
// installer inside the mounted image) and launches it INTO the active desktop
// session. Emits process.create. Returns true and fills proc/pid/deadline on
// success; false (with a failure event) otherwise.
bool LaunchPreparedSample(HANDLE com2, const antimal::ExecuteJobRequest &req,
                          const std::filesystem::path &samplePath, HANDLE *proc,
                          DWORD *pid,
                          std::chrono::steady_clock::time_point *deadline);

// Writes the reassembled sample to a per-run guest directory and launches it.
// Emits agent.sample.received + process.create over COM2. Returns true and fills
// proc/pid/deadline on success; false (with a failure event) otherwise.
bool LaunchExecuteJob(HANDLE com2, const antimal::ExecuteJobRequest &req,
                      const std::vector<uint8_t> &bytes, HANDLE *proc,
                      DWORD *pid, std::chrono::steady_clock::time_point *deadline) {
  auto received = MakeAgentEvent("agent.sample.received", req.sampleName);
  received.details["bytes"] = std::to_string(bytes.size());
  received.details["delivery"] = "serial";
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
  return LaunchPreparedSample(com2, req, samplePath, proc, pid, deadline);
}

// Mounts a delivered .iso in-guest (Windows' native ISO mount) and picks the
// installer to run from its root: the well-known Adobe/modern installer names
// first, else the first top-level .exe/.msi. Fills launchPath (+ mountRoot).
bool MountIsoAndFindInstaller(HANDLE com2, const std::filesystem::path &isoPath,
                              std::filesystem::path *launchPath,
                              std::wstring *mountRoot) {
  const std::filesystem::path letterFile =
      isoPath.parent_path() / L"iso-letter.txt";
  std::error_code ec;
  std::filesystem::remove(letterFile, ec);
  std::wstring cmd =
      L"powershell.exe -NoProfile -NonInteractive -Command \""
      L"$v = Mount-DiskImage -ImagePath '" + isoPath.wstring() +
      L"' -PassThru | Get-Volume; "
      L"if ($v) { Set-Content -LiteralPath '" + letterFile.wstring() +
      L"' -Value $v.DriveLetter }\"";
  cmd.push_back(L'\0');
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    return false;
  }
  WaitForSingleObject(pi.hProcess, 120000);
  DWORD psExit = 1;
  GetExitCodeProcess(pi.hProcess, &psExit);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  std::ifstream letterIn(letterFile);
  std::string letter;
  std::getline(letterIn, letter);
  if (letter.empty()) {
    auto fail = MakeAgentEvent("agent.sample.mount-failed", antimal::PathToUtf8(isoPath.filename()));
    fail.details["powershellExit"] = std::to_string(psExit);
    fail.details["error"] = std::to_string(GetLastError());
    (void)SendAgentEvent(com2, fail);
    return false;
  }
  const std::wstring root =
      std::wstring(letter.begin(), letter.end()) + L":\\";
  auto lowerExt = [](std::wstring ext) {
    for (wchar_t &c : ext) {
      if (c >= L'A' && c <= L'Z') {
        c = static_cast<wchar_t>(c - L'A' + L'a');
      }
    }
    return ext;
  };
  static const wchar_t *kPreferred[] = {L"Set-up.exe", L"setup.exe",
                                        L"Setup.exe", L"Autoplay.exe",
                                        L"install.exe"};
  for (const wchar_t *name : kPreferred) {
    const std::filesystem::path candidate = std::filesystem::path(root) / name;
    if (std::filesystem::exists(candidate)) {
      *launchPath = candidate;
      *mountRoot = root;
      auto mounted = MakeAgentEvent("agent.sample.mounted", antimal::PathToUtf8(isoPath.filename()));
      mounted.details["mountRoot"] = antimal::PathToUtf8(root);
      mounted.details["installer"] = antimal::PathToUtf8(candidate);
      (void)SendAgentEvent(com2, mounted);
      return true;
    }
  }
  // Bounded recursive scan (an Adobe-style ISO can nest its installer one or
  // two levels down). Prefer setup/install-sounding names, then any exe/msi.
  std::filesystem::path firstCandidate;
  size_t seen = 0;
  constexpr size_t kMaxEntries = 4000;
  for (auto it = std::filesystem::recursive_directory_iterator(
           root, std::filesystem::directory_options::skip_permission_denied, ec);
       it != std::filesystem::recursive_directory_iterator() &&
       seen < kMaxEntries;
       it.increment(ec)) {
    if (ec) {
      break;
    }
    ++seen;
    if (!it->is_regular_file(ec)) {
      continue;
    }
    const std::wstring ext = lowerExt(it->path().extension().wstring());
    if (ext != L".exe" && ext != L".msi") {
      continue;
    }
    const std::wstring stem = lowerExt(it->path().stem().wstring());
    if (stem.find(L"setup") != std::wstring::npos ||
        stem.find(L"set-up") != std::wstring::npos ||
        stem.find(L"install") != std::wstring::npos ||
        stem.find(L"autoplay") != std::wstring::npos) {
      *launchPath = it->path();
      *mountRoot = root;
      auto mounted = MakeAgentEvent("agent.sample.mounted", antimal::PathToUtf8(isoPath.filename()));
      mounted.details["mountRoot"] = antimal::PathToUtf8(root);
      mounted.details["installer"] = antimal::PathToUtf8(it->path());
      (void)SendAgentEvent(com2, mounted);
      return true;
    }
    if (firstCandidate.empty()) {
      firstCandidate = it->path();
    }
  }
  if (!firstCandidate.empty()) {
    *launchPath = firstCandidate;
    *mountRoot = root;
    auto mounted = MakeAgentEvent("agent.sample.mounted", antimal::PathToUtf8(isoPath.filename()));
    mounted.details["mountRoot"] = antimal::PathToUtf8(root);
    mounted.details["installer"] = antimal::PathToUtf8(firstCandidate);
    (void)SendAgentEvent(com2, mounted);
    return true;
  }
  auto fail = MakeAgentEvent("agent.sample.mount-failed", antimal::PathToUtf8(isoPath.filename()));
  fail.details["reason"] = "no installer found at the image root";
  (void)SendAgentEvent(com2, fail);
  return false;
}

bool LaunchPreparedSample(HANDLE com2, const antimal::ExecuteJobRequest &req,
                          const std::filesystem::path &samplePath, HANDLE *proc,
                          DWORD *pid,
                          std::chrono::steady_clock::time_point *deadline) {
  std::filesystem::path launchPath = samplePath;
  if (req.sampleKind == "iso") {
    std::wstring mountRoot;
    if (!MountIsoAndFindInstaller(com2, samplePath, &launchPath, &mountRoot)) {
      return false;
    }
  }

  DWORD launchedPid = 0;
  HANDLE launchedProc = nullptr;
  bool interactive = false;
  if (!LaunchSampleProcess(launchPath, &launchedPid, &launchedProc,
                           &interactive)) {
    auto fail = MakeAgentEvent("process.create-failed",
                               antimal::PathToUtf8(launchPath));
    fail.category = "process";
    fail.details["error"] = std::to_string(GetLastError());
    (void)SendAgentEvent(com2, fail);
    return false;
  }
  *proc = launchedProc;
  *pid = launchedPid;
  // timeoutMs == 0 is the "until stopped" policy: no guest-side analysis
  // deadline at all (the host keeps observing until it is told to stop), so a
  // time_point::max() is used rather than collapsing to "deadline now".
  *deadline = req.timeoutMs == 0
                  ? std::chrono::steady_clock::time_point::max()
                  : std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(req.timeoutMs);
  auto created =
      MakeAgentEvent("process.create", antimal::PathToUtf8(launchPath));
  created.category = "process";
  created.processId = launchedPid;
  created.details["sampleExecuted"] = "true";
  // SP5: "desktop" = launched into the active interactive session (visible on
  // the live desktop); "service" = headless session-0 fallback (no logon yet).
  created.details["session"] = interactive ? "desktop" : "service";
  if (launchPath != samplePath) {
    created.details["launchedFrom"] = antimal::PathToUtf8(samplePath);
  }
  (void)SendAgentEvent(com2, created);
  return true;
}

// Disk-backed delivery: the sample rides a second read-only AHCI disk presented
// by the host. Find the raw device whose length matches the job's declared disk
// size, then copy exactly sampleBytes off it into the per-run sample dir.
std::optional<std::filesystem::path> ReceiveDiskSample(
    HANDLE com2, const antimal::ExecuteJobRequest &req) {
  if (req.diskBytes == 0) {
    return std::nullopt;
  }
  HANDLE disk = INVALID_HANDLE_VALUE;
  DWORD selectedDrive = 0;
  for (DWORD i = 0; i < 16; ++i) {
    const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      continue;
    }
    GET_LENGTH_INFORMATION li{};
    DWORD bytes = 0;
    const bool ok = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                                    &li, sizeof(li), &bytes, nullptr) != FALSE;
    if (ok && static_cast<uint64_t>(li.Length.QuadPart) == req.diskBytes) {
      disk = h;
      selectedDrive = i;
      break;
    }
    CloseHandle(h);
  }
  if (disk == INVALID_HANDLE_VALUE) {
    auto fail = MakeAgentEvent("agent.sample.disk-not-found", req.sampleName);
    fail.details["diskBytes"] = std::to_string(req.diskBytes);
    (void)SendAgentEvent(com2, fail);
    return std::nullopt;
  }
  auto found = MakeAgentEvent("agent.sample.disk-found", req.sampleName);
  found.details["physicalDrive"] = std::to_string(selectedDrive);
  found.details["diskBytes"] = std::to_string(req.diskBytes);
  (void)SendAgentEvent(com2, found);

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

  HANDLE out = CreateFileW(samplePath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (out == INVALID_HANDLE_VALUE) {
    CloseHandle(disk);
    auto fail = MakeAgentEvent("agent.sample.write-failed", req.sampleName);
    fail.details["error"] = std::to_string(GetLastError());
    (void)SendAgentEvent(com2, fail);
    return std::nullopt;
  }

  LARGE_INTEGER zero{};
  zero.QuadPart = 0;
  SetFilePointerEx(disk, zero, nullptr, FILE_BEGIN);
  constexpr DWORD kChunk = 1u << 20;             // 1 MiB (sector-aligned).
  constexpr DWORD kSector = 512;
  // Byte-level progress: a multi-GB installer copy runs for minutes with no
  // other host-visible signal, so emit the copied/total bytes at a bounded
  // cadence (every ~32 MiB) -- the host tails these events and renders real
  // progress instead of an apparently idle desktop. Rate is bounded so a long
  // copy can't flood COM2; the final event always lands.
  constexpr uint64_t kProgressEveryBytes = 32ull * 1024ull * 1024ull;
  std::vector<uint8_t> buf(kChunk);
  uint64_t remaining = req.sampleBytes;
  uint64_t lastProgressAt = 0;
  bool ok = true;
  while (remaining > 0) {
    // Raw-disk reads MUST be sector-aligned in both offset and length; the
    // final chunk of an unaligned file is rounded UP to a whole sector and the
    // extra bytes are trimmed when writing the file out.
    const DWORD want = static_cast<DWORD>(std::min<uint64_t>(remaining, kChunk));
    DWORD readSize = (want + kSector - 1) / kSector * kSector;
    if (readSize > kChunk) {
      readSize = kChunk;
    }
    DWORD got = 0;
    if (!ReadFile(disk, buf.data(), readSize, &got, nullptr) || got == 0) {
      ok = false;
      break;
    }
    const DWORD toWrite = static_cast<DWORD>(
        std::min<uint64_t>(got, remaining));
    DWORD wrote = 0;
    if (!WriteFile(out, buf.data(), toWrite, &wrote, nullptr) || wrote != toWrite) {
      ok = false;
      break;
    }
    remaining -= toWrite;
    const uint64_t copied = req.sampleBytes - remaining;
    if (copied - lastProgressAt >= kProgressEveryBytes) {
      lastProgressAt = copied;
      auto prog = MakeAgentEvent("agent.sample.progress", req.sampleName);
      prog.details["copiedBytes"] = std::to_string(copied);
      prog.details["totalBytes"] = std::to_string(req.sampleBytes);
      prog.details["percent"] = std::to_string(
          req.sampleBytes == 0
              ? 100
              : static_cast<int>(copied * 100ull / req.sampleBytes));
      prog.details["delivery"] = "disk";
      (void)SendAgentEvent(com2, prog);
    }
  }
  if (ok) {
    // The sample disk is sector-padded; truncate to the exact byte size.
    LARGE_INTEGER end{};
    end.QuadPart = static_cast<LONGLONG>(req.sampleBytes);
    SetFilePointerEx(out, end, nullptr, FILE_BEGIN);
    SetEndOfFile(out);
  }
  CloseHandle(out);
  CloseHandle(disk);
  if (!ok) {
    std::error_code ec;
    std::filesystem::remove(samplePath, ec);
    auto fail = MakeAgentEvent("agent.sample.disk-read-failed", req.sampleName);
    fail.details["remainingBytes"] = std::to_string(remaining);
    (void)SendAgentEvent(com2, fail);
    return std::nullopt;
  }
  auto received = MakeAgentEvent("agent.sample.received", req.sampleName);
  received.details["bytes"] = std::to_string(req.sampleBytes);
  received.details["delivery"] = "disk";
  received.details["physicalDrive"] = std::to_string(selectedDrive);
  (void)SendAgentEvent(com2, received);
  return samplePath;
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

// Force a High-Performance power profile so the single vCPU isn't parked or
// downclocked by the default Balanced plan (a major cause of guest micro-stutter
// and the sluggishness on the in-house VM). Activates High Performance and pins
// the minimum processor state to 100%. Best-effort; runs once per process.
void SetHighPerformancePowerPlan() {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  wchar_t cmd[] =
      L"cmd.exe /c powercfg /setactive scheme_min & "
      L"powercfg /setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN "
      L"100 & powercfg /setactive scheme_current";
  if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

// ---------------------------------------------------------------------------
// In-guest WER (Windows Error Reporting) crash decoder.
//
// When a process crashes, WER writes a Report.wer (UTF-16LE, INI-like
// key=value) under the WER ReportQueue/ReportArchive trees. The agent runs as
// LocalSystem, so it can read both the machine-wide ProgramData location and
// every per-user profile. We enumerate those Report.wer files, parse out the
// faulting module + exception code + offset, and stream a "crash" event over
// COM2 -- so a diagnostic detonation surfaces the EXACT fault behind a process
// crash (e.g. ShellHost.exe STATUS_STACK_BUFFER_OVERRUN 0xC0000409) instead of
// just an exit code. ParseWerReport is pure; the OS-specific work here is only
// directory enumeration + the UTF-16LE -> UTF-8 file read.
//
// Bounded: at most kWerMaxDirsPerTick report dirs are inspected per tick and at
// most kWerMaxReportBytes are read per file, so the scan stays cheap. Each
// Report.wer is emitted once via a caller-owned seen-set keyed on full path.
// ---------------------------------------------------------------------------

constexpr size_t kWerMaxDirsPerTick = 64;
constexpr DWORD kWerMaxReportBytes = 64u * 1024u;

// Reads up to kWerMaxReportBytes of a UTF-16LE Report.wer and returns it as
// UTF-8. WER files start with a UTF-16LE BOM (0xFF 0xFE); we skip it if present.
std::string ReadWerFileUtf8(const std::wstring &path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return {};
  }
  std::vector<unsigned char> raw;
  raw.resize(kWerMaxReportBytes);
  DWORD read = 0;
  const BOOL ok = ReadFile(h, raw.data(), kWerMaxReportBytes, &read, nullptr);
  CloseHandle(h);
  if (!ok || read < 2) {
    return {};
  }
  raw.resize(read);
  size_t offset = 0;
  // Skip a UTF-16LE byte-order mark if present.
  if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
    offset = 2;
  }
  // Drop a trailing odd byte so the wchar_t reinterpret stays in bounds.
  const size_t wideBytes = (raw.size() - offset) & ~static_cast<size_t>(1);
  if (wideBytes == 0) {
    return {};
  }
  const auto *wide = reinterpret_cast<const wchar_t *>(raw.data() + offset);
  return NarrowUtf8(wide, static_cast<int>(wideBytes / sizeof(wchar_t)));
}

// Enumerates Report.wer files under one WER root (which contains ReportQueue\
// and ReportArchive\, each holding per-crash subdirectories). For every
// not-yet-seen Report.wer found (bounded by `budget`), parses it and -- when
// valid -- emits a process.crash event over COM2. `budget` is decremented per
// report directory inspected so the per-tick cap spans all roots.
void ScanWerRoot(HANDLE com2, const std::wstring &werRoot,
                 std::set<std::wstring> &seen, size_t &budget) {
  for (const wchar_t *bucket : {L"ReportQueue", L"ReportArchive"}) {
    if (budget == 0) {
      return;
    }
    const std::wstring bucketDir = werRoot + L"\\" + bucket;
    const std::wstring pattern = bucketDir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) {
      continue;
    }
    do {
      if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        continue;
      }
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
        continue;
      }
      if (budget == 0) {
        break;
      }
      --budget;
      const std::wstring reportPath =
          bucketDir + L"\\" + fd.cFileName + L"\\Report.wer";
      if (seen.count(reportPath)) {
        continue;
      }
      const std::string text = ReadWerFileUtf8(reportPath);
      if (text.empty()) {
        continue; // not written yet / unreadable; retry on a later tick
      }
      // Mark seen only once we have content to parse, so a report dir created
      // before its Report.wer is flushed gets revisited. Bound the set on a
      // very long service run (WER queues rarely hold more than a handful):
      // past an absurd count, reset it -- at worst a few already-seen crashes
      // re-emit once, vs unbounded growth.
      constexpr size_t kMaxSeenWerReports = 4096;
      if (seen.size() >= kMaxSeenWerReports) {
        seen.clear();
      }
      seen.insert(reportPath);
      const antimal::WerCrashInfo crash = antimal::ParseWerReport(text);
      if (!crash.valid) {
        continue;
      }
      antimal::EventRecord ev = MakeAgentEvent("process.crash", crash.appName);
      ev.category = "crash";
      ev.imagePath = crash.appName;
      ev.details["module"] = crash.faultModule;
      ev.details["moduleVersion"] = crash.faultModuleVersion;
      ev.details["exceptionCode"] = crash.exceptionCode;
      ev.details["exceptionOffset"] = crash.exceptionOffset;
      ev.details["eventType"] = crash.eventType;
      // The __fastfail subcode (when the WER report carried an exception-info
      // field). SummarizeCrashes decodes it to a FAST_FAIL_* name -> the precise
      // reason the shell crash-loop fast-fails.
      if (crash.fastFailSubcode >= 0) {
        ev.details["fastFailSubcode"] = std::to_string(crash.fastFailSubcode);
      }
      (void)SendAgentEvent(com2, ev);
    } while (FindNextFileW(find, &fd));
    FindClose(find);
  }
}

// One WER scan pass: the machine-wide ProgramData root plus every per-user
// profile's WER root. Bounded by kWerMaxDirsPerTick across all roots.
void ScanForWerCrashes(HANDLE com2, std::set<std::wstring> &seen) {
  size_t budget = kWerMaxDirsPerTick;
  ScanWerRoot(com2,
              L"C:\\ProgramData\\Microsoft\\Windows\\WER", seen, budget);

  // Per-user: C:\Users\*\AppData\Local\Microsoft\Windows\WER.
  WIN32_FIND_DATAW fd{};
  HANDLE find = FindFirstFileW(L"C:\\Users\\*", &fd);
  if (find == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    if (budget == 0) {
      break;
    }
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      continue;
    }
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
      continue;
    }
    const std::wstring userWer = std::wstring(L"C:\\Users\\") + fd.cFileName +
                                 L"\\AppData\\Local\\Microsoft\\Windows\\WER";
    ScanWerRoot(com2, userWer, seen, budget);
  } while (FindNextFileW(find, &fd));
  FindClose(find);
}

// ---------------------------------------------------------------------------
// Image / DLL-load telemetry capture.
//
// Builds a per-process module snapshot by enumerating each live process's loaded
// modules via a per-PID Toolhelp32 module snapshot. This is HEAVIER than the
// process-table poll (one snapshot handle per process), so the caller runs it on
// its own slower cadence, and we BOUND it hard so a single vCPU can't stall:
//   * at most kModuleMaxPidsPerPass processes are scanned per pass;
//   * at most kModuleMaxModulesPerProc modules are recorded per process.
// Truncation is marked on the snapshot side via the diff's per-batch caps; here
// we simply stop at the per-process module cap (the common process has well
// under 256 modules, so this almost never trips). pid 0 (System Idle) and pid 4
// (System) are skipped -- they have no user-mode module list. A snapshot failure
// on a protected/exited process (access denied) is tolerated per-pid: that pid
// contributes no modules and the pass continues.
// ---------------------------------------------------------------------------

constexpr size_t kModuleMaxPidsPerPass = 128;
constexpr size_t kModuleMaxModulesPerProc = 256;

antimal::ProcessModuleSnapshot BuildModuleSnapshot(
    const std::vector<uint32_t> &pids) {
  antimal::ProcessModuleSnapshot snap;
  size_t scanned = 0;
  for (uint32_t pid : pids) {
    if (scanned >= kModuleMaxPidsPerPass) {
      break;
    }
    if (pid == 0 || pid == 4) {
      continue;  // System Idle / System -- no user-mode module list
    }
    HANDLE modSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (modSnap == INVALID_HANDLE_VALUE) {
      continue;  // access denied on a protected/exited process -- tolerate it
    }
    ++scanned;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    std::vector<antimal::LoadedModule> mods;
    if (Module32FirstW(modSnap, &me)) {
      do {
        if (mods.size() >= kModuleMaxModulesPerProc) {
          break;  // per-process cap (honestly bounded; rarely hit)
        }
        antimal::LoadedModule m;
        m.path = NarrowUtf8(me.szExePath);
        m.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        if (!m.path.empty()) {
          mods.push_back(std::move(m));
        }
      } while (Module32NextW(modSnap, &me));
    }
    CloseHandle(modSnap);
    if (!mods.empty()) {
      snap[pid] = std::move(mods);
    }
  }
  return snap;
}

int RunHostChannelLoop(std::string reason, bool serviceMode) {
  static std::atomic_bool powerPlanSet{false};
  if (!powerPlanSet.exchange(true)) {
    SetHighPerformancePowerPlan();
  }
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
  // Per-PID query handle (PROCESS_QUERY_LIMITED_INFORMATION) held for every
  // tracked process so its exit code can be read at the moment it exits (T11).
  // SeDebugPrivilege (enabled below) lets the LocalSystem agent open
  // cross-session processes.
  std::map<uint32_t, HANDLE> procHandles;
  EnableDebugPrivilege();
  antimal::TcpSnapshot knownConns;
  bool netBaselineSent = false;
  antimal::RegistrySnapshot knownReg;
  bool regBaselineSent = false;
  antimal::FileSnapshot knownFiles;
  bool fileBaselineSent = false;
  // Image/DLL-load telemetry: a per-process module map, diffed into
  // image.load/unload (suspicious side-loads/hijacks tagged with MITRE). Heavier
  // than the others (one Toolhelp snapshot per process), so polled on its own
  // slower cadence (kModulePollEveryTicks) and bounded in BuildModuleSnapshot.
  antimal::ProcessModuleSnapshot knownModules;
  bool moduleBaselineSent = false;
  // Each Report.wer is decoded + emitted once; keyed on its full path so a
  // crash surfaces as a single process.crash event across ticks.
  std::set<std::wstring> seenWerReports;
  const std::vector<std::filesystem::path> watchedDirs =
      antimal::DefaultWatchedDirs();
  // G4 per-sensor coverage: register the collectors this agent runs and record
  // whether each succeeds and whether it hits a cap. Emitted as `agent.coverage`
  // records so the host/scorer can gate a Clean verdict on achieved coverage
  // instead of assuming healthy defaults.
  antimal::SensorCoverageTracker coverage;
  {
    // The file collector resolves from the agent's environment; record which
    // profile that actually is so the report can expose a service-vs-user gap.
    std::string profile;
    wchar_t profileBuf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"USERPROFILE", profileBuf, MAX_PATH) > 0) {
      profile = antimal::WideToUtf8(profileBuf);
    }
    wchar_t userBuf[256]{};
    DWORD userLen = sizeof(userBuf);
    if (GetUserNameW(userBuf, &userLen)) {
      profile = antimal::WideToUtf8(userBuf);
    }
    coverage.Register("process");
    coverage.Register("network");
    coverage.Register("registry");
    coverage.Register("filesystem", profile);
    coverage.Register("image");
    coverage.Register("wer_crash");
  }
  uint32_t coverageEmitCounter = 0;
  constexpr uint32_t kCoverageEmitEveryTicks = 5; // ~5s

  // Authorized-detonation state: an execute JobStart opens a transfer, the
  // SampleChunk frames fill the reassembler, then the sample launches and we
  // track it to exit/timeout. All gated on GuestExecutionAuthorized().
  std::optional<antimal::ExecuteJobRequest> executeReq;
  std::optional<antimal::SampleReassembler> reassembler;
  // Disk-backed delivery: the sample was already written from the raw sample
  // disk; this is the path the deferred launch will run.
  std::optional<std::filesystem::path> diskSamplePath;
  HANDLE sampleProcess = nullptr;
  DWORD samplePid = 0;
  std::chrono::steady_clock::time_point sampleDeadline{};
  // Bounds the sample TRANSFER (JobStart -> all SampleChunks). Without it, a lost
  // chunk would leave the agent waiting on Complete() forever (24h in service
  // mode). Paced host->guest delivery (SetPacedCom2Payload) now sustains ~8 KB/s
  // (2 KB bursts, 250 ms interval, RX-queue-gated), so a near-cap 8 MB sample
  // takes ~17 min; 1800s bounds that with headroom while still failing a truly
  // dropped chunk instead of heartbeating to maxTicks.
  std::chrono::steady_clock::time_point transferDeadline{};
  constexpr int kTransferTimeoutSec = 1800;
  bool sampleLaunched = false;
  bool sampleReported = false;
  // SP5 deferred launch: after the transfer completes the agent waits (up to
  // kLaunchWaitSec) for a logged-in desktop session before launching, so the
  // sample runs VISIBLY on the live desktop rather than headless in session 0
  // during the login transition. A no-login boot still detonates after the wait.
  bool sampleStaged = false;
  std::chrono::steady_clock::time_point launchDeadline{};
  // Generous so a human has time to log in manually before the sample launches
  // (it launches the moment the desktop session appears; this is just the upper
  // bound after which it runs headless anyway).
  constexpr int kLaunchWaitSec = 600;
  constexpr uint32_t kProcessPollEveryTicks = 2; // ~2s between snapshots
  constexpr uint32_t kFilePollEveryTicks = 5;    // file walk is heavier
  constexpr uint32_t kModulePollEveryTicks = 6;  // per-process module walk is heaviest
  constexpr size_t kProcessBaselineCap = 64;
  constexpr size_t kProcessDeltaCap = 64;
  // Cap on dropped files hashed per file-poll tick. A burst of drops beyond this
  // is still reported (with details["hashSkipped"]="rate"); the hashing just
  // defers, so a flood can't stall the collector on a single vCPU.
  constexpr size_t kFileEnrichPerTick = 64;
  uint32_t tick = 0;
  // Last byte mark for which an `agent.sample.progress` event was emitted on the
  // serial (COM2) delivery path (the disk path keeps its own local counter).
  uint64_t lastTransferProgressAt = 0;
  // Base budget: a service run lingers all day; a bare console run exits after
  // ~2 min. But once a sample is STAGED, a console run must outlast the deferred
  // manual-login wait (kLaunchWaitSec) plus a short observation tail -- otherwise
  // the 120s cap fires before the sample ever launches and nothing is reported.
  const uint32_t baseMaxTicks = serviceMode ? 24u * 60u * 60u : 120u;
  const uint32_t stagedMaxTicks =
      serviceMode ? baseMaxTicks
                  : static_cast<uint32_t>(kLaunchWaitSec) + 120u;
  while (!g_stopRequested.load() &&
         tick < (sampleStaged ? stagedMaxTicks : baseMaxTicks)) {
    if (!ReadCom2Frames(com2, &incoming)) {
      CloseHandle(com2);
      return 1;
    }
    while (const auto frame = incoming.PopFrame()) {
      if (frame->type == antimal::HostChannelMessage::SampleChunk) {
        // Sample bytes for an authorized execute job, arriving after the
        // JobStart. Collect until complete, then write + launch. Once staged
        // (transfer complete, awaiting the desktop) or launched, ignore any
        // trailing chunk so it can't spuriously trip the reassembler.
        if (!executeReq || !reassembler || sampleLaunched || sampleStaged) {
          continue;  // no pending transfer
        }
        const auto chunk = antimal::ParseSampleChunkPayload(frame->payload);
        if (!chunk || !reassembler->Add(*chunk)) {
          SendExecuteFailure(com2, "sample-transfer-error");
          executeReq.reset();
          reassembler.reset();
          continue;
        }
        // Byte-level transfer progress (~every 32 MiB, plus the final chunk):
        // the host uses this to render real delivery progress for a multi-GB
        // package instead of a silent multi-minute stall.
        {
          static constexpr uint64_t kReportEvery = 32ull * 1024ull * 1024ull;
          const uint64_t receivedNow = reassembler->Received();
          const uint64_t expectedNow = reassembler->Expected();
          const bool complete = reassembler->Complete();
          if (complete || receivedNow - lastTransferProgressAt >= kReportEvery) {
            lastTransferProgressAt = receivedNow;
            auto prog =
                MakeAgentEvent("agent.sample.progress", executeReq->sampleName);
            prog.details["copiedBytes"] = std::to_string(receivedNow);
            prog.details["totalBytes"] = std::to_string(expectedNow);
            prog.details["percent"] = std::to_string(
                expectedNow == 0
                    ? 100
                    : static_cast<int>(receivedNow * 100ull / expectedNow));
            prog.details["delivery"] = "serial";
            (void)SendAgentEvent(com2, prog);
          }
        }
        if (reassembler->Complete() && !sampleStaged) {
          // Transfer done. Defer the launch until a desktop session is logged in
          // (checked each tick below), so the sample lands ON the live desktop
          // (SP5) instead of headless session 0 during the login transition.
          sampleStaged = true;
          launchDeadline = std::chrono::steady_clock::now() +
                           std::chrono::seconds(kLaunchWaitSec);
          auto staged =
              MakeAgentEvent("agent.sample.staged", executeReq->sampleName);
          staged.details["waitingForDesktop"] = "true";
          (void)SendAgentEvent(com2, staged);
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
        } else if (req.delivery == "disk") {
          // Disk-backed delivery: the sample rides a second read-only disk the
          // host attached; copy it off the raw device (inline -- it is
          // disk-speed, and the sample window the host computed already budgeted
          // for it).
          executeReq = req;
          auto started = MakeAgentEvent("agent.job.start", "execute");
          started.details["kind"] = "execute";
          started.details["delivery"] = "disk";
          started.details["sampleName"] = req.sampleName;
          started.details["sampleBytes"] = std::to_string(req.sampleBytes);
          (void)SendAgentEvent(com2, started);
          const auto diskPath = ReceiveDiskSample(com2, req);
          if (diskPath) {
            diskSamplePath = *diskPath;
            sampleStaged = true;
            launchDeadline = std::chrono::steady_clock::now() +
                             std::chrono::seconds(kLaunchWaitSec);
            auto stagedEvent =
                MakeAgentEvent("agent.sample.staged", req.sampleName);
            stagedEvent.details["waitingForDesktop"] = "true";
            stagedEvent.details["delivery"] = "disk";
            (void)SendAgentEvent(com2, stagedEvent);
          } else {
            SendExecuteFailure(com2, "sample-disk-read-failed");
            executeReq.reset();
          }
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
    // Suppressed once the transfer is staged (waiting on the desktop, not the
    // transfer).
    if (executeReq && !sampleLaunched && !sampleStaged &&
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

    // Deferred launch (SP5): the delivery is staged; launch the sample as soon as
    // a desktop session is logged in (so it runs VISIBLY on the live desktop), or
    // after the wait budget so a no-login boot still detonates (headless).
    if (sampleStaged && !sampleLaunched && executeReq &&
        (diskSamplePath || reassembler)) {
      if (HasInteractiveSession() ||
          std::chrono::steady_clock::now() >= launchDeadline) {
        sampleLaunched =
            diskSamplePath
                ? LaunchPreparedSample(com2, *executeReq, *diskSamplePath,
                                       &sampleProcess, &samplePid, &sampleDeadline)
                : LaunchExecuteJob(com2, *executeReq, reassembler->Bytes(),
                                   &sampleProcess, &samplePid, &sampleDeadline);
        sampleStaged = false;
        if (!sampleLaunched) {
          (void)SendFrame(com2, antimal::HostChannelMessage::ReportComplete,
                          "status=error\nsampleExecuted=false\n"
                          "reason=sample-launch-failed\n");
          executeReq.reset();
          reassembler.reset();
          diskSamplePath.reset();
        }
      }
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

    // Fast-drain while a sample transfer is in flight: the paced host->guest
    // delivery is the critical path, so pause the ~1s telemetry cadence
    // (heartbeat + collectors + tick) and poll COM2 at ~20 Hz instead. The
    // collectors resume the moment the transfer completes (staged/launched) or
    // is failed by the watchdog above. Frame processing is unaffected -- the
    // inner PopFrame loop above still drains every arrival.
    const bool transferInFlight = executeReq && !sampleLaunched && !sampleStaged;
    const bool telemetryTick = !transferInFlight;

    if (telemetryTick) {
      const std::string heartbeat =
          "heartbeat=" + std::to_string(tick) +
          "; healthcheckComplete=" + (healthcheckComplete ? "true" : "false");
      if (!SendFrame(com2, antimal::HostChannelMessage::Heartbeat, heartbeat)) {
        CloseHandle(com2);
        return 1;
      }
    }

    if (telemetryTick && tick % kProcessPollEveryTicks == 0) {
      auto current = antimal::CaptureProcessSnapshot();
      // G4: a collector that returns an empty snapshot before its baseline has
      // run is unhealthy; after the baseline it is a legitimate "no change".
      coverage.Observe("process", !current.empty() || processBaselineSent,
                       current.size(), 0, /*lossKnown=*/false,
                       current.empty() && !processBaselineSent
                           ? "process snapshot returned empty"
                           : "");
      if (!current.empty() || processBaselineSent) {
        // Enrich every process in the fresh snapshot with deep detail (full
        // path, command line, integrity, user/SID, session, start time) and
        // keep an open query handle so its exit code can be read later. New
        // PIDs get opened+enriched; PIDs we already track inherit their cached
        // enrichment (it doesn't change over a process's lifetime).
        for (auto &entry : current) {
          const uint32_t pid = entry.first;
          auto known = knownProcs.find(pid);
          if (known != knownProcs.end()) {
            const antimal::ProcessInfo &prevInfo = known->second;
            // PID-reuse guard: if the (cheap, snapshot-provided) base image name
            // or parent PID differ, this PID now hosts a DIFFERENT process. Don't
            // inherit the old process's path/cmdline/user, and drop its stale
            // query handle (whose exit code belongs to the OLD process) -- fall
            // through and re-enrich as fresh. Without this, a reused PID reported
            // the prior process's metadata and exit code.
            if (prevInfo.image == entry.second.image &&
                prevInfo.parentPid == entry.second.parentPid) {
              entry.second.fullImagePath = prevInfo.fullImagePath;
              entry.second.commandLine = prevInfo.commandLine;
              entry.second.integrityLevel = prevInfo.integrityLevel;
              entry.second.userName = prevInfo.userName;
              entry.second.userSid = prevInfo.userSid;
              entry.second.startTimeUtc = prevInfo.startTimeUtc;
              entry.second.sessionId = prevInfo.sessionId;
              entry.second.hasSessionId = prevInfo.hasSessionId;
              continue;
            }
            auto stale = procHandles.find(pid);
            if (stale != procHandles.end()) {
              CloseHandle(stale->second);
              procHandles.erase(stale);
            }
          }
          HANDLE h = EnrichProcessInfo(pid, entry.second);
          if (h) {
            procHandles[pid] = h;
          }
        }
        // For PIDs that vanished, read their exit code (the high-value T11
        // signal -- captures crash codes like 0xC0000409) into the cached
        // `knownProcs` entry that DiffProcessSnapshots reports as process.stop,
        // then release the held handle.
        for (auto &entry : knownProcs) {
          if (current.find(entry.first) != current.end()) {
            continue; // still alive
          }
          auto hit = procHandles.find(entry.first);
          if (hit != procHandles.end()) {
            DWORD code = 0;
            if (GetExitCodeProcess(hit->second, &code) &&
                code != STILL_ACTIVE) {
              entry.second.exitCode = code;
              entry.second.hasExitCode = true;
            }
            CloseHandle(hit->second);
            procHandles.erase(hit);
          }
        }
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
    if (telemetryTick && tick % kProcessPollEveryTicks == 0) {
      auto conns = antimal::CaptureTcpConnections();
      coverage.Observe("network", true, conns.size(), 0, /*lossKnown=*/false);
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
    if (telemetryTick && tick % kProcessPollEveryTicks == 0) {
      auto reg = antimal::CaptureRegistrySnapshot();
      coverage.Observe("registry", true, reg.size(), 0, /*lossKnown=*/false);
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
    //
    // For a newly-seen file (file.create / file.modify) the agent reads the file
    // in-guest and enriches the event with its sha256 + magic-byte file type --
    // the high-signal "WHAT did it drop" detail (e.g. "dropped a PE"). Bounded so
    // a burst of drops can't stall the ~2s collector on a single vCPU: at most
    // kFileEnrichPerTick files are hashed per tick (the rest carry
    // details["hashSkipped"]="rate"), each capped at kMaxHashBytes; a locked file
    // is reported WITHOUT a hash. The pure diff above stays untouched -- all of
    // the disk I/O / hashing happens here.
    if (telemetryTick && tick % kFilePollEveryTicks == 0) {
      auto files = antimal::CaptureFileSnapshot(watchedDirs);
      // A snapshot that hit the entry cap (4096) is lossy; the walk does not
      // report the exact overflow, so lossKnown stays false.
      coverage.Observe("filesystem", true, files.size(), 0, /*lossKnown=*/false,
                       files.size() >= 4096 ? "file snapshot hit the 4096-entry cap"
                                            : "");
      if (!files.empty() || fileBaselineSent) {
        auto fileEvents = antimal::DiffFileSnapshots(
            knownFiles, files, !fileBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        fileBaselineSent = true;
        knownFiles = std::move(files);
        size_t enriched = 0;
        for (auto &ev : fileEvents) {
          if (ev.action == "file.create" || ev.action == "file.modify") {
            if (enriched < kFileEnrichPerTick) {
              antimal::EnrichDroppedFileEvent(ev);
              ++enriched;
            } else {
              ev.details["hashSkipped"] = "rate";  // per-tick cap hit
            }
          }
          if (!SendAgentEvent(com2, ev)) {
            CloseHandle(com2);
            return 1;
          }
        }
      }
    }

    // Image/DLL-load telemetry: snapshot each live process's loaded modules and
    // stream image.load / image.unload deltas -- the high-signal "what DLLs got
    // pulled in, and were any side-loaded / search-order-hijacked from a
    // writable, non-system path?" (DiffModuleSnapshots tags those with MITRE +
    // details["suspicion"]). Polled on the slowest cadence because the per-process
    // module walk is the heaviest collector; PIDs come from the freshest process
    // snapshot (knownProcs), and BuildModuleSnapshot bounds PIDs + modules so a
    // module flood can't stall the single vCPU.
    if (telemetryTick && tick % kModulePollEveryTicks == 0) {
      std::vector<uint32_t> livePids;
      livePids.reserve(knownProcs.size());
      for (const auto &entry : knownProcs) {
        livePids.push_back(entry.first);
      }
      auto modules = BuildModuleSnapshot(livePids);
      coverage.Observe("image", !livePids.empty(), modules.size(), 0,
                       /*lossKnown=*/false,
                       livePids.size() > 128
                           ? "module PID pass capped at 128 (high PIDs unscanned)"
                           : "");
      if (!modules.empty() || moduleBaselineSent) {
        auto modEvents = antimal::DiffModuleSnapshots(
            knownModules, modules, !moduleBaselineSent, kProcessBaselineCap,
            kProcessDeltaCap);
        moduleBaselineSent = true;
        knownModules = std::move(modules);
        for (const auto &ev : modEvents) {
          if (!SendAgentEvent(com2, ev)) {
            CloseHandle(com2);
            return 1;
          }
        }
      }
    }

    // WER crash decoder: enumerate Report.wer files (machine-wide + per-user)
    // and stream a process.crash event for each new fault, decoding the exact
    // faulting module + exception code + offset behind a process crash. Polled
    // on the process cadence (~2s); bounded per tick + de-duped by full path.
    if (telemetryTick && tick % kProcessPollEveryTicks == 0) {
      ScanForWerCrashes(com2, seenWerReports);
      coverage.Observe("wer_crash", true, 0, 0, /*lossKnown=*/false);
    }

    // G4: periodically stream the accumulated per-sensor coverage so the host
    // can gate negatives on achieved coverage. Emitted every few ticks, and
    // always once before the sample is reported, so a short run still carries a
    // coverage record.
    if (telemetryTick && (tick % kCoverageEmitEveryTicks == 0 ||
                          (sampleReported && coverageEmitCounter == 0))) {
      ++coverageEmitCounter;
      for (const auto &ev : coverage.ToEvents(0)) {
        if (!SendAgentEvent(com2, ev)) {
          CloseHandle(com2);
          return 1;
        }
      }
    }

    if (telemetryTick) {
      ++tick;
    }
    std::this_thread::sleep_for(transferInFlight
                                    ? std::chrono::milliseconds(50)
                                    : std::chrono::seconds(1));
  }

  for (auto &h : procHandles) {
    CloseHandle(h.second);
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
      // Explicit filmstrip retention: identical consecutive frames are not
      // re-encoded; this states how many were skipped so a still period is
      // visible as a measured gap, not silently misrepresented.
      ev.details["screenshotsSkippedIdentical"] =
          std::to_string(shots->DuplicateCount());
      ev.details["screenshotsSkippedSpanSec"] =
          std::to_string(shots->DuplicateSpanSeconds());
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

// Defined in FileBrowser.cpp (a self-contained Win32 file browser).
int RunFileBrowserGui(const std::wstring &startDir);
// Defined in MiniShell.cpp (a minimal analyst desktop / launcher).
int RunMiniShellGui();

int wmain(int argc, wchar_t **argv) {
  BootLog("wmain start argc=" + std::to_string(argc) +
          " service=" + (HasArg(argc, argv, L"--service") ? "1" : "0"));
  try {
    // Minimal in-guest GUI file browser: usable File-Explorer functionality even
    // when the Win11 modern shell crash-loops. Launch it from the cmd-shell
    // sidestep: `AntiMal.GuestAgent.exe --file-browser [start-dir]`.
    if (HasArg(argc, argv, L"--file-browser")) {
      std::wstring start = L"C:\\";
      for (int i = 1; i < argc; ++i) {
        if (argv[i] && std::wstring_view(argv[i]) != L"--file-browser") {
          start = argv[i];
          break;
        }
      }
      return RunFileBrowserGui(start);
    }
    // Minimal analyst desktop / launcher -- a usable replacement for the
    // crash-looping modern shell. Set as the Winlogon shell (ANTIMAL_PROBE_SHELL)
    // or launch from cmd: `AntiMal.GuestAgent.exe --shell`.
    if (HasArg(argc, argv, L"--shell")) {
      return RunMiniShellGui();
    }
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
