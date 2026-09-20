// AntiMal benign GUI application fixture.
//
// The first "usable investigation" needs an APPLICATION to investigate: a
// windowed program whose behavior is known exactly, so the report can be
// checked against expectations instead of merely being non-empty. It performs
// ONLY self-labelled, reversible, benign actions:
//
//   click "Run behaviors" (or wait for --auto) then:
//     * writes  %TEMP%\antimal-gui-probe.log            -> file.create
//     * drops   %PUBLIC%\antimal-gui-probe-marker.txt   -> file.create
//     * sets    HKCU\...\CurrentVersion\Run\AntiMalGuiProbe -> registry.set
//     * spawns  cmd.exe /c echo ... > %TEMP%\antimal-gui-probe-child.txt
//                                                       -> process.start subtree
//     * opens a loopback TCP connection and holds it briefly -> network.connect
//     * shows "Done" and exits 0 after a short linger
//
// Expected report (the acceptance baseline):
//   process tree root = antimal_gui_probe.exe with the cmd.exe child under it,
//   the two dropped files with sha256 + fileType data, one registry autostart
//   write, one loopback (NON-external) connection, clean exit, no persistence
//   verdict escalation (unattributed + no attributable malice => at most
//   Suspicious), and an accurate "limited coverage" note if anything was missed.
//
// Build: tools\Build-SampleProbe.ps1 builds this alongside antimal_probe.cpp.
// NEVER run this on the host: it writes registry values and opens sockets by
// design. It is only ever executed inside the disposable analysis VM.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h> // GET_X_LPARAM / GET_Y_LPARAM

#include <cstdio>
#include <cstring>
#include <string>
#include "containment_checks.h"
#include "telemetry_checks.h"

namespace {

constexpr wchar_t kWindowClass[] = L"AntiMalGuiProbeWindow";
constexpr UINT_PTR kAutoTimerId = 0xA1;
constexpr UINT_PTR kExitTimerId = 0xA2;

void DropFile(const std::wstring &path, const char *content);
std::wstring TempPath(const wchar_t *name);
std::wstring PublicPath(const wchar_t *name);

// --- Diagnostic channel -----------------------------------------------------
// The 2026-09-18 live run launched this fixture, the window never appeared, and
// the diagnostic was lost because it was written into the INTERACTIVE user's
// %TEMP% while the LocalSystem agent's file collector watched SYSTEM's profile.
// v2 writes the same diagnostic to BOTH the user's %TEMP% and %PUBLIC% (watched
// machine-wide regardless of user scoping) and records the exact registration /
// CreateWindowEx results, GetLastError values, and the session/desktop/window-
// station identity, so a launch failure is evidence rather than an invisible
// no-op.
std::wstring TempDiagPath() {
  return TempPath(L"antimal-gui-probe-diag.txt");
}

std::wstring PublicDiagPath() {
  return PublicPath(L"antimal-gui-probe-diag.txt");
}

std::string Narrow(const std::wstring &w) {
  std::string out;
  for (wchar_t c : w) {
    out.push_back(c < 128 ? static_cast<char>(c) : '?');
  }
  return out;
}

std::wstring ObjectName(HANDLE h) {
  if (h == nullptr) {
    return L"<none>";
  }
  DWORD needed = 0;
  GetUserObjectInformationW(h, UOI_NAME, nullptr, 0, &needed);
  if (needed == 0) {
    return L"<err " + std::to_wstring(GetLastError()) + L">";
  }
  std::wstring buf(needed / sizeof(wchar_t), L'\0');
  if (!GetUserObjectInformationW(h, UOI_NAME, buf.data(), needed, &needed)) {
    return L"<err " + std::to_wstring(GetLastError()) + L">";
  }
  while (!buf.empty() && buf.back() == L'\0') {
    buf.pop_back();
  }
  return buf;
}

std::wstring ErrorText(DWORD gle) {
  LPWSTR msg = nullptr;
  const DWORD n = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, gle, 0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
  std::wstring out;
  if (n != 0 && msg != nullptr) {
    out.assign(msg, n);
    while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n' ||
                            out.back() == L' ')) {
      out.pop_back();
    }
  }
  LocalFree(msg);
  return out;
}

std::wstring BuildDiagnostic(const std::wstring &classResult, DWORD classGle,
                             int attempts, HWND hwnd, DWORD createGle) {
  DWORD sessionId = 0xFFFFFFFFu;
  ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
  wchar_t user[256]{};
  DWORD userLen = 256;
  GetUserNameW(user, &userLen);
  const std::wstring winsta =
      ObjectName(reinterpret_cast<HANDLE>(GetProcessWindowStation()));
  const std::wstring desktop =
      ObjectName(reinterpret_cast<HANDLE>(GetThreadDesktop(GetCurrentThreadId())));

  std::wstring d;
  d += L"antimal-gui-probe diagnostic v2\n";
  d += L"pid=" + std::to_wstring(GetCurrentProcessId()) + L"\n";
  d += L"sessionId=" + std::to_wstring(sessionId) + L"\n";
  d += L"windowStation=" + winsta + L"\n";
  d += L"desktop=" + desktop + L"\n";
  d += L"user=" + std::wstring(user) + L"\n";
  d += L"classResult=" + classResult + L" gle=" + std::to_wstring(classGle) +
       L" (" + ErrorText(classGle) + L")\n";
  d += L"attempts=" + std::to_wstring(attempts) + L"\n";
  d += L"window=" + std::wstring(hwnd != nullptr ? L"created" : L"not-created") +
       L" gle=" + std::to_wstring(createGle) + L" (" + ErrorText(createGle) +
       L")\n";
  d += L"diagPath=" + TempDiagPath() + L"\n";
  d += L"diagPathPublic=" + PublicDiagPath() + L"\n";
  // Record reset evidence BEFORE RunBehaviors creates this fixture's state.
  // Absence is asserted only for these known fixture markers, never for malware.
  for (const auto &path : {TempPath(L"antimal-gui-probe.log"),
                          PublicPath(L"antimal-gui-probe-marker.txt")}) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    const DWORD error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
    d += L"preexistingMarker=" + path + L" status=" +
         (attributes != INVALID_FILE_ATTRIBUTES ? L"present" :
          (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ?
              L"absent" : L"unknown") + L" error=" + std::to_wstring(error) + L"\n";
  }
  DWORD type = 0, size = 0;
  const LSTATUS registry = RegGetValueW(HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"AntiMalGuiProbe",
      RRF_RT_ANY, &type, nullptr, &size);
  d += L"preexistingAutostart=" + std::wstring(registry == ERROR_SUCCESS ? L"present" :
      registry == ERROR_FILE_NOT_FOUND ? L"absent" : L"unknown") +
      L" error=" + std::to_wstring(registry) + L"\n";
  return d;
}

void WriteDiagnostic(const std::wstring &content) {
  const std::string utf8 = Narrow(content);
  DropFile(TempDiagPath(), utf8.c_str());
  DropFile(PublicDiagPath(), utf8.c_str());
}

void DropFile(const std::wstring &path, const char *content) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(h, content, static_cast<DWORD>(std::strlen(content)), &written,
            nullptr);
  CloseHandle(h);
}

std::wstring TempPath(const wchar_t *name) {
  wchar_t dir[MAX_PATH]{};
  const DWORD n = GetTempPathW(MAX_PATH, dir);
  if (n == 0 || n >= MAX_PATH) {
    return name;
  }
  return std::wstring(dir) + name;
}

std::wstring PublicPath(const wchar_t *name) {
  wchar_t dir[MAX_PATH]{};
  const DWORD n = GetEnvironmentVariableW(L"PUBLIC", dir, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return TempPath(name);
  }
  return std::wstring(dir) + L"\\" + name;
}

void SetAutostartValue() {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                      nullptr, 0, KEY_SET_VALUE, nullptr, &key,
                      nullptr) != ERROR_SUCCESS) {
    return;
  }
  const wchar_t *value = L"C:\\Users\\Public\\antimal-gui-probe-marker.txt";
  RegSetValueExW(key, L"AntiMalGuiProbe", 0, REG_SZ,
                 reinterpret_cast<const BYTE *>(value),
                 static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
}

void SpawnChild() {
  const std::wstring childOut = TempPath(L"antimal-gui-probe-child.txt");
  std::wstring cmd = L"cmd.exe /c echo antimal-gui-probe-child > \"" + childOut +
                     L"\"";
  std::wstring mutableCmd = cmd;
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  if (CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
}

void LoopbackConnect() {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return;
  }
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s != INVALID_SOCKET) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    Sleep(400); // hold it long enough for the TCP-table collector to see it
    closesocket(s);
  }
  WSACleanup();
}

// Application-level receipt log: the fixture records the input events and focus
// changes the GUI actually received, so a host-side "queued/read" byte count can
// be checked against what the APPLICATION observed. Written to the user %TEMP%
// and %PUBLIC% (both telemetry-visible).
std::string g_eventLog;

void LogEvent(const std::string &line) {
  g_eventLog += line;
  g_eventLog += "\n";
  DropFile(TempPath(L"antimal-gui-probe-events.txt"), g_eventLog.c_str());
  DropFile(PublicPath(L"antimal-gui-probe-events.txt"), g_eventLog.c_str());
}

// All expected behaviors, in a fixed order, each self-labelled.
void RunBehaviors(HWND hwnd) {
  RunContainmentChecks();
  RunTelemetryChecks();
  LogEvent("behavior=run");
  DropFile(TempPath(L"antimal-gui-probe.log"),
           "antimal-gui-probe: benign fixture behavior log\n");
  DropFile(PublicPath(L"antimal-gui-probe-marker.txt"),
           "antimal-gui-probe: benign dropped marker\n");
  SetAutostartValue();
  LogEvent("behavior=autostart-written");
  SpawnChild();
  LogEvent("behavior=child-spawned");
  LoopbackConnect();
  LogEvent("behavior=loopback-connected");
  LogEvent("behavior=exiting");
  SetWindowTextW(hwnd, L"AntiMal GUI Probe - done (exiting)");
  SetTimer(hwnd, kExitTimerId, 3000, nullptr);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
  case WM_CREATE: {
    // Deterministic geometry so the operator/agent can compute click targets
    // from a screenshot instead of guessing: window at (100,100), client
    // 384x220. Button row, then a HARMLESS text field (edit control) with a
    // Show button whose label echoes EXACTLY what arrived -- the bounded
    // typing diagnostic for the known keyboard defect (never a command shell).
    CreateWindowExW(0, L"BUTTON", L"Run behaviors", WS_CHILD | WS_VISIBLE |
                                      BS_PUSHBUTTON,
                    20, 20, 160, 40, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)),
                    GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"STATIC", L"Waiting for input...",
                    WS_CHILD | WS_VISIBLE, 20, 70, 340, 20, hwnd, nullptr,
                    GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER |
                                       ES_AUTOHSCROLL,
                    20, 100, 240, 24, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)),
                    GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Show typed text", WS_CHILD | WS_VISIBLE |
                                        BS_PUSHBUTTON,
                    270, 100, 110, 24, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(3)),
                    GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"STATIC", L"typed: (nothing yet)",
                    WS_CHILD | WS_VISIBLE, 20, 134, 360, 60, hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(4)),
                    GetModuleHandleW(nullptr), nullptr);
    if (GetEnvironmentVariableW(L"ANTIMAL_GUI_PROBE_AUTO", nullptr, 0) > 0) {
      SetTimer(hwnd, kAutoTimerId, 3000, nullptr); // unattended fallback
    }
    return 0;
  }
  case WM_ACTIVATE:
    LogEvent(std::string("window_active=") +
             (LOWORD(wParam) != WA_INACTIVE ? "1" : "0"));
    break;
  case WM_SETFOCUS:
    LogEvent("window_focus=1");
    break;
  case WM_KILLFOCUS:
    LogEvent("window_focus=0");
    break;
  case WM_KEYDOWN:
  case WM_SYSKEYDOWN:
    LogEvent("keydown_vk=" + std::to_string(static_cast<unsigned>(wParam)));
    break;
  case WM_KEYUP:
  case WM_SYSKEYUP:
    LogEvent("keyup_vk=" + std::to_string(static_cast<unsigned>(wParam)));
    break;
  case WM_CHAR:
    LogEvent("char_code=" + std::to_string(static_cast<unsigned>(wParam)));
    break;
  case WM_LBUTTONDOWN:
    LogEvent("lbutton_down_x=" + std::to_string(GET_X_LPARAM(lParam)) +
             " y=" + std::to_string(GET_Y_LPARAM(lParam)));
    break;
  case WM_LBUTTONUP:
    LogEvent("lbutton_up_x=" + std::to_string(GET_X_LPARAM(lParam)) +
             " y=" + std::to_string(GET_Y_LPARAM(lParam)));
    break;
  case WM_COMMAND:
    if (LOWORD(wParam) == 2 && HIWORD(wParam) == EN_CHANGE) {
      wchar_t text[256]{};
      GetDlgItemTextW(hwnd, 2, text, 256);
      std::string ascii;
      for (wchar_t c : std::wstring(text)) {
        ascii.push_back(c < 128 ? static_cast<char>(c) : '?');
      }
      LogEvent("edit_text=" + ascii);
      return 0;
    }
    if (LOWORD(wParam) == 1) {
      RunBehaviors(hwnd);
      return 0;
    }
    if (LOWORD(wParam) == 3) {
      LogEvent("button=show");
      // Echo the edit control's content verbatim into the label. Reading the
      // screenshot then shows exactly which characters the guest received.
      wchar_t text[256]{};
      GetDlgItemTextW(hwnd, 2, text, 256);
      std::wstring label = L"typed: ";
      label += text;
      SetDlgItemTextW(hwnd, 4, label.c_str());
      // Also persist it (the file collector picks this up as file.create).
      const std::string utf8 = [&] {
        std::string out;
        for (wchar_t c : std::wstring(text)) {
          out.push_back(c < 128 ? static_cast<char>(c) : '?');
        }
        return out;
      }();
      DropFile(TempPath(L"antimal-gui-probe-typed.txt"), utf8.c_str());
      return 0;
    }
    break;
  case WM_TIMER:
    if (wParam == kAutoTimerId) {
      KillTimer(hwnd, kAutoTimerId);
      RunBehaviors(hwnd);
      return 0;
    }
    if (wParam == kExitTimerId) {
      DestroyWindow(hwnd);
      return 0;
    }
    break;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
  // Immediate startup changes exercise the pre-launch baseline barrier. The
  // previous-state records also let a second fresh-overlay run prove reset.
  const auto startupMarker = PublicPath(L"antimal-baseline-probe-20260919.txt");
  const DWORD priorAttrs = GetFileAttributesW(startupMarker.c_str());
  const DWORD priorError = priorAttrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
  LogEvent("baseline_prior_file_error=" + std::to_string(priorError));
  DWORD priorSize = 0;
  const auto priorReg = RegGetValueW(HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"AntiMalBaselineProbe", RRF_RT_REG_SZ, nullptr, nullptr, &priorSize);
  LogEvent("baseline_prior_registry_status=" + std::to_string(priorReg));
  DropFile(startupMarker, "Immediate startup marker for baseline verification\n");
  HKEY baselineKey = nullptr;
  const auto opened = RegCreateKeyExW(HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, 0,
      KEY_SET_VALUE, nullptr, &baselineKey, nullptr);
  LONG written = opened;
  if (opened == ERROR_SUCCESS) {
    const wchar_t value[] = L"cmd.exe /c exit 0";
    written = RegSetValueExW(baselineKey, L"AntiMalBaselineProbe", 0, REG_SZ,
        reinterpret_cast<const BYTE *>(value), sizeof(value));
    RegCloseKey(baselineKey);
  }
  LogEvent("baseline_startup_registry_write=" + std::to_string(written));
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = instance;
  wc.lpszClassName = kWindowClass;
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
  const BOOL classOk = RegisterClassExW(&wc);
  const DWORD classGle = classOk ? 0 : GetLastError();
  const std::wstring classResult =
      classOk ? L"registered"
              : (classGle == ERROR_CLASS_ALREADY_EXISTS
                     ? L"already-exists"
                     : L"register-failed");
  WriteDiagnostic(
      BuildDiagnostic(classResult, classGle, 0, nullptr, 0));

  // The agent launches this immediately after the desktop session appears, and
  // the FIRST run showed the window never came up: CreateWindowEx can fail while
  // the session/window station is still initializing, and the old code then
  // exited silently. Retry for up to a minute and write a telemetry-visible
  // diagnostic (user %TEMP% + %PUBLIC%) with the exact Win32 results, so a
  // launch problem is evidence rather than an invisible no-op.
  HWND hwnd = nullptr;
  DWORD lastError = 0;
  int attempts = 0;
  for (int attempt = 0; attempt < 30; ++attempt) {
    attempts = attempt + 1;
    hwnd = CreateWindowExW(0, kWindowClass, L"AntiMal GUI Probe",
                           WS_OVERLAPPEDWINDOW, 100, 100, 424, 280, nullptr,
                           nullptr, instance, nullptr);
    if (hwnd != nullptr) {
      break;
    }
    lastError = GetLastError();
    if (attempt % 5 == 0) {
      WriteDiagnostic(BuildDiagnostic(classResult, classGle, attempts, nullptr,
                                      lastError));
    }
    Sleep(2000);
  }
  // Final state: created (gle 0) or the last CreateWindowEx failure, written to
  // both diagnostic paths BEFORE any exit, so the collector sees it even if the
  // process then terminates.
  WriteDiagnostic(BuildDiagnostic(classResult, classGle, attempts, hwnd,
                                  hwnd != nullptr ? 0 : lastError));
  if (hwnd == nullptr) {
    return 1;
  }
  ShowWindow(hwnd, show);
  UpdateWindow(hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return 0;
}
