// AntiMal benign detonation probe.
//
// A deliberately harmless stand-in for "a suspected sample", built to exercise
// every in-guest telemetry collector the GuestAgent runs during a detonation so
// that a live run produces visible, attributable behavior WITHOUT doing anything
// malicious. It:
//
//   * drops files into the watched drop directories (%PUBLIC%, %TEMP%) -> file.*
//   * writes a fake autostart value under HKLM\...\Run               -> registry.set
//   * spawns a short-lived cmd.exe child (which also drops a file)   -> process.start
//   * opens a loopback TCP connection and holds it briefly           -> network.connect
//
// Then it exits 0. Everything it touches is self-labelled "antimal-probe" and is
// trivially reversible. This is the binary the runbook means by "validate the
// flow with a benign test binary" before any real sample.
//
// Built /MT (static CRT) by tools\Build-SampleProbe.ps1 so it runs on a clean
// Windows guest with no VC++ redistributable installed.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace {

void DropFile(const wchar_t *path, const char *content) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD written = 0;
  WriteFile(h, content, static_cast<DWORD>(std::strlen(content)), &written,
            nullptr);
  CloseHandle(h);
}

// Writes a fake persistence value under the machine Run key — the exact key the
// GuestAgent's RegistrySnapshot watches. The value path is fictional; nothing is
// ever launched from it.
void WriteFakePersistence() {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                      nullptr, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key,
                      nullptr) != ERROR_SUCCESS) {
    return;
  }
  const wchar_t *data = L"C:\\Users\\Public\\antimal-probe.exe";
  RegSetValueExW(key, L"AntiMalProbe", 0, REG_SZ,
                 reinterpret_cast<const BYTE *>(data),
                 static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
}

// Spawns a benign child that echoes into a watched directory. The child process
// itself is the process-telemetry signal; its file drop is a bonus file signal.
void SpawnChild() {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  wchar_t cmd[] =
      L"cmd.exe /c echo antimal-probe child ran > "
      L"C:\\Users\\Public\\antimal-probe-child.txt";
  if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &si, &pi)) {
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

// Opens a loopback TCP connection to itself and holds it open long enough for the
// agent's ~2s TCP-table poll to observe an ESTABLISHED connection owned by this
// PID. No external network is touched (and the guest has no NIC anyway).
void LoopbackConnect() {
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return;
  }
  SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  SOCKET client = INVALID_SOCKET;
  SOCKET accepted = INVALID_SOCKET;
  if (listener != INVALID_SOCKET) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // let the OS pick a free port
    if (bind(listener, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
        listen(listener, 1) == 0) {
      int len = sizeof(addr);
      getsockname(listener, reinterpret_cast<sockaddr *>(&addr), &len);
      client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (client != INVALID_SOCKET) {
        connect(client, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        accepted = accept(listener, nullptr, nullptr);
        // Hold the ESTABLISHED pair so a snapshot catches it.
        std::this_thread::sleep_for(std::chrono::seconds(6));
      }
    }
  }
  if (accepted != INVALID_SOCKET) closesocket(accepted);
  if (client != INVALID_SOCKET) closesocket(client);
  if (listener != INVALID_SOCKET) closesocket(listener);
  WSACleanup();
}

}  // namespace

// Opens Notepad on the probe's own dropped file. When the agent launches the
// sample into the interactive desktop session (SP5), this window is VISIBLE on
// the live desktop — the analyst sees the sample do something. In a headless
// session-0 launch it simply runs without a visible window. Benign.
void ShowVisibleWindow() {
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_SHOWNORMAL;
  PROCESS_INFORMATION pi{};
  wchar_t cmd[] =
      L"notepad.exe C:\\Users\\Public\\antimal-probe-drop.txt";
  if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                     &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

int main() {
  DropFile(L"C:\\Users\\Public\\antimal-probe-drop.txt",
           "AntiMal benign detonation probe ran here.\r\n"
           "If you can see this in Notepad, the sample launched on the live "
           "desktop (SP5 visible-session launch).\r\n");
  DropFile(L"C:\\Windows\\Temp\\antimal-probe-temp.txt",
           "AntiMal benign detonation probe temp drop.\n");
  WriteFakePersistence();
  ShowVisibleWindow();
  SpawnChild();
  LoopbackConnect();
  return 0;
}
