// A minimal analyst desktop shell for the analysis guest.
//
// Why this exists: the Win11 modern shell (explorer.exe) crash-loops in this VM
// (the 0xC0000409 wall -- two distinct __fastfail sites, see memory
// `shell-wall-two-signatures`), so there is no usable desktop/taskbar. The
// cmd-shell sidestep proved you CAN swap the Winlogon shell to a non-explorer
// program. This is that program done properly: a tiny always-present launcher
// window giving the analyst the core desktop actions -- open the File Browser,
// a Command Prompt, the Web Browser -- plus a live process list, with NO
// dependency on explorer / AppX (user32 + comctl32 + shell32 + toolhelp only).
//
// Set it as the Winlogon shell (ANTIMAL_PROBE_SHELL) or launch it from cmd:
// `AntiMal.GuestAgent.exe --shell`. Also a normal Win32 app, so it builds + runs
// + is verifiable on the host, not only in the guest.

#include <windows.h>

#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <string>

namespace {

enum : int {
  kIdFiles = 201,
  kIdConsole = 202,
  kIdBrowser = 203,
  kIdRefresh = 204,
  kIdKill = 205,
};

HWND g_list = nullptr;
HWND g_status = nullptr;
HWND g_btnFiles = nullptr, g_btnConsole = nullptr, g_btnBrowser = nullptr,
     g_btnRefresh = nullptr, g_btnKill = nullptr;

std::wstring SelfPath() {
  wchar_t buf[MAX_PATH]{};
  GetModuleFileNameW(nullptr, buf, MAX_PATH);
  return buf;
}

void SetStatus(const std::wstring &text) {
  if (g_status) SetWindowTextW(g_status, text.c_str());
}

// Launch our own --file-browser in a separate process (so a crash there can't
// take the shell down).
void LaunchFileBrowser() {
  const std::wstring self = SelfPath();
  std::wstring cmd = L"\"" + self + L"\" --file-browser C:\\";
  STARTUPINFOW si{sizeof(si)};
  PROCESS_INFORMATION pi{};
  std::wstring mutableCmd = cmd;
  if (CreateProcessW(self.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE, 0,
                     nullptr, nullptr, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    SetStatus(L"Opened File Browser");
  } else {
    SetStatus(L"Failed to open File Browser");
  }
}

// ShellExecute goes through registry associations + CreateProcess, NOT the
// modern shell, so it works even with explorer dead.
void LaunchConsole() {
  ShellExecuteW(nullptr, L"open", L"cmd.exe", nullptr, L"C:\\", SW_SHOWNORMAL);
  SetStatus(L"Opened Command Prompt");
}

void LaunchBrowser() {
  // Edge is reachable in-guest (separate process from the shell). Fall back to
  // the http handler if msedge isn't on PATH.
  HINSTANCE r = ShellExecuteW(nullptr, L"open", L"msedge.exe", nullptr, nullptr,
                              SW_SHOWNORMAL);
  if (reinterpret_cast<INT_PTR>(r) <= 32) {
    ShellExecuteW(nullptr, L"open", L"https://www.example.com", nullptr, nullptr,
                  SW_SHOWNORMAL);
  }
  SetStatus(L"Opened Web Browser");
}

void RefreshProcesses() {
  ListView_DeleteAllItems(g_list);
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    SetStatus(L"process snapshot failed");
    return;
  }
  PROCESSENTRY32W pe{sizeof(pe)};
  int index = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      LVITEMW it{};
      it.mask = LVIF_TEXT | LVIF_PARAM;
      it.iItem = index;
      it.pszText = pe.szExeFile;
      it.lParam = static_cast<LPARAM>(pe.th32ProcessID);
      ListView_InsertItem(g_list, &it);
      wchar_t pid[16];
      swprintf(pid, 16, L"%lu", pe.th32ProcessID);
      ListView_SetItemText(g_list, index, 1, pid);
      ++index;
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  SetStatus(std::to_wstring(index) + L" process(es) running");
}

void KillSelected() {
  const int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
  if (sel < 0) return;
  LVITEMW it{};
  it.mask = LVIF_PARAM;
  it.iItem = sel;
  ListView_GetItem(g_list, &it);
  const DWORD pid = static_cast<DWORD>(it.lParam);
  if (pid == GetCurrentProcessId()) {
    SetStatus(L"refusing to terminate the shell itself");
    return;
  }
  HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (h) {
    const bool ok = TerminateProcess(h, 1) != 0;
    CloseHandle(h);
    SetStatus(ok ? L"terminated pid " + std::to_wstring(pid)
                 : L"could not terminate pid " + std::to_wstring(pid));
    RefreshProcesses();
  } else {
    SetStatus(L"access denied opening pid " + std::to_wstring(pid));
  }
}

HWND MakeButton(HWND parent, const wchar_t *text, int id) {
  return CreateWindowExW(0, L"BUTTON", text,
                         WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0,
                         parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                         nullptr, nullptr);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_btnFiles = MakeButton(hwnd, L"Files", kIdFiles);
      g_btnConsole = MakeButton(hwnd, L"Command Prompt", kIdConsole);
      g_btnBrowser = MakeButton(hwnd, L"Web Browser", kIdBrowser);
      g_btnRefresh = MakeButton(hwnd, L"Refresh", kIdRefresh);
      g_btnKill = MakeButton(hwnd, L"End Task", kIdKill);
      g_list = CreateWindowExW(
          WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 0, 0, 0, 0, hwnd,
          nullptr, nullptr, nullptr);
      ListView_SetExtendedListViewStyle(
          g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
      const wchar_t *cols[] = {L"Process", L"PID"};
      const int widths[] = {320, 100};
      for (int i = 0; i < 2; ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = const_cast<wchar_t *>(cols[i]);
        c.cx = widths[i];
        c.iSubItem = i;
        ListView_InsertColumn(g_list, i, &c);
      }
      g_status = CreateWindowExW(0, L"STATIC",
                                 L"AntiMal shell - explorer is unavailable in "
                                 L"this VM; use these actions.",
                                 WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, nullptr,
                                 nullptr, nullptr);
      return 0;
    }
    case WM_SIZE: {
      const int w = LOWORD(lp), h = HIWORD(lp);
      const int bh = 26, y = 6;
      int x = 6;
      const int bw[] = {70, 130, 110, 80, 80};
      HWND btns[] = {g_btnFiles, g_btnConsole, g_btnBrowser, g_btnRefresh,
                     g_btnKill};
      for (int i = 0; i < 5; ++i) {
        MoveWindow(btns[i], x, y, bw[i], bh, TRUE);
        x += bw[i] + 6;
      }
      MoveWindow(g_list, 6, y + bh + 6, w - 12, h - (y + bh + 6) - 24, TRUE);
      MoveWindow(g_status, 6, h - 20, w - 12, 18, TRUE);
      return 0;
    }
    case WM_COMMAND: {
      switch (LOWORD(wp)) {
        case kIdFiles: LaunchFileBrowser(); return 0;
        case kIdConsole: LaunchConsole(); return 0;
        case kIdBrowser: LaunchBrowser(); return 0;
        case kIdRefresh: RefreshProcesses(); return 0;
        case kIdKill: KillSelected(); return 0;
        default: return 0;
      }
    }
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd, msg, wp, lp);
  }
}

} // namespace

// Entry point for the GuestAgent's --shell mode (and host testing).
int RunMiniShellGui() {
  INITCOMMONCONTROLSEX icc{sizeof(icc),
                           ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
  InitCommonControlsEx(&icc);

  WNDCLASSW wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = L"AntiMalMiniShell";
  RegisterClassW(&wc);

  HWND hwnd = CreateWindowExW(
      0, wc.lpszClassName, L"AntiMal Shell (analyst desktop)",
      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 760, 520, nullptr,
      nullptr, wc.hInstance, nullptr);
  if (!hwnd) return 1;

  RefreshProcesses();
  ShowWindow(hwnd, SW_SHOW);
  UpdateWindow(hwnd);

  MSG m{};
  while (GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  return 0;
}
