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

#include <cstdio>
#include <cstring>
#include <string>

namespace {

constexpr wchar_t kWindowClass[] = L"AntiMalGuiProbeWindow";
constexpr UINT_PTR kAutoTimerId = 0xA1;
constexpr UINT_PTR kExitTimerId = 0xA2;

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

// All expected behaviors, in a fixed order, each self-labelled.
void RunBehaviors(HWND hwnd) {
  DropFile(TempPath(L"antimal-gui-probe.log"),
           "antimal-gui-probe: benign fixture behavior log\n");
  DropFile(PublicPath(L"antimal-gui-probe-marker.txt"),
           "antimal-gui-probe: benign dropped marker\n");
  SetAutostartValue();
  SpawnChild();
  LoopbackConnect();
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
  case WM_COMMAND:
    if (LOWORD(wParam) == 1) {
      RunBehaviors(hwnd);
      return 0;
    }
    if (LOWORD(wParam) == 3) {
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
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = instance;
  wc.lpszClassName = kWindowClass;
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
  RegisterClassExW(&wc);

  // The agent launches this immediately after the desktop session appears, and
  // the FIRST run showed the window never came up: CreateWindowEx can fail while
  // the session/window station is still initializing, and the old code then
  // exited silently. Retry for up to a minute and leave a telemetry-visible
  // diagnostic when it still fails, so a launch problem is evidence rather than
  // an invisible no-op.
  HWND hwnd = nullptr;
  DWORD lastError = 0;
  for (int attempt = 0; attempt < 30; ++attempt) {
    hwnd = CreateWindowExW(0, kWindowClass, L"AntiMal GUI Probe",
                           WS_OVERLAPPEDWINDOW, 100, 100, 424, 280, nullptr,
                           nullptr, instance, nullptr);
    if (hwnd != nullptr) {
      break;
    }
    lastError = GetLastError();
    Sleep(2000);
  }
  if (hwnd == nullptr) {
    char message[128]{};
    sprintf_s(message, "antimal-gui-probe: window creation failed GLE=%lu\n",
              static_cast<unsigned long>(lastError));
    DropFile(TempPath(L"antimal-gui-probe-error.txt"), message);
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
