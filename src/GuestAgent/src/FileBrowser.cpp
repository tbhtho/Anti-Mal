// A minimal, self-contained Win32 file browser for the analysis guest.
//
// Why this exists: the Win11 modern shell (explorer.exe / ShellHost) crash-loops
// in this VM (the documented ucrtbase 0xC0000409 wall), so the built-in File
// Explorer is unusable. The cmd-shell sidestep gives a working console; this gives
// the analyst a working GUI FILE BROWSER launched from that console
// (`AntiMal.GuestAgent.exe --file-browser`), with NO dependency on the modern
// shell / AppX -- just user32 + comctl32 (a plain ListView). It is also a normal
// Win32 app, so it runs + is verifiable on the host, not only in the guest.
//
// Scope: navigate directories (double-click a folder or ".."), see name/size/
// type/modified, and copy the current path. Deliberately tiny and dependency-light
// so it can never hit the modern shell's failure surface.

#include <windows.h>

#include <commctrl.h>

#include <string>
#include <vector>

namespace {

HWND g_list = nullptr;
HWND g_path = nullptr;
std::wstring g_dir;

std::wstring FormatSize(unsigned long long bytes) {
  wchar_t buf[32];
  if (bytes >= (1ull << 30)) {
    swprintf(buf, 32, L"%.1f GB", static_cast<double>(bytes) / (1ull << 30));
  } else if (bytes >= (1ull << 20)) {
    swprintf(buf, 32, L"%.1f MB", static_cast<double>(bytes) / (1ull << 20));
  } else if (bytes >= (1ull << 10)) {
    swprintf(buf, 32, L"%.1f KB", static_cast<double>(bytes) / (1ull << 10));
  } else {
    swprintf(buf, 32, L"%llu B", bytes);
  }
  return buf;
}

std::wstring FormatTime(const FILETIME &ft) {
  SYSTEMTIME st{};
  FILETIME local{};
  FileTimeToLocalFileTime(&ft, &local);
  if (!FileTimeToSystemTime(&local, &st)) return L"";
  wchar_t buf[40];
  swprintf(buf, 40, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay,
           st.wHour, st.wMinute);
  return buf;
}

void AddRow(int index, const std::wstring &name, const std::wstring &size,
            const std::wstring &type, const std::wstring &modified, bool isDir) {
  LVITEMW it{};
  it.mask = LVIF_TEXT | LVIF_PARAM;
  it.iItem = index;
  it.iSubItem = 0;
  it.pszText = const_cast<wchar_t *>(name.c_str());
  it.lParam = isDir ? 1 : 0;
  ListView_InsertItem(g_list, &it);
  ListView_SetItemText(g_list, index, 1, const_cast<wchar_t *>(size.c_str()));
  ListView_SetItemText(g_list, index, 2, const_cast<wchar_t *>(type.c_str()));
  ListView_SetItemText(g_list, index, 3, const_cast<wchar_t *>(modified.c_str()));
}

void Populate(std::wstring dir) {
  if (dir.empty()) dir = L"C:\\";
  if (dir.back() != L'\\') dir.push_back(L'\\');
  g_dir = dir;
  SetWindowTextW(g_path, dir.c_str());
  ListView_DeleteAllItems(g_list);

  int index = 0;
  // Parent entry (unless at a drive root like "C:\").
  if (dir.size() > 3) {
    AddRow(index++, L"..", L"", L"<up>", L"", true);
  }

  WIN32_FIND_DATAW fd{};
  const std::wstring pattern = dir + L"*";
  HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  std::vector<WIN32_FIND_DATAW> dirs, files;
  do {
    const std::wstring n = fd.cFileName;
    if (n == L"." || n == L"..") continue;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      dirs.push_back(fd);
    } else {
      files.push_back(fd);
    }
  } while (FindNextFileW(h, &fd));
  FindClose(h);

  for (const auto &e : dirs) {
    AddRow(index++, e.cFileName, L"", L"<DIR>", FormatTime(e.ftLastWriteTime),
           true);
  }
  for (const auto &e : files) {
    const unsigned long long sz =
        (static_cast<unsigned long long>(e.nFileSizeHigh) << 32) | e.nFileSizeLow;
    const std::wstring n = e.cFileName;
    const size_t dot = n.find_last_of(L'.');
    const std::wstring ext = dot == std::wstring::npos ? L"" : n.substr(dot);
    AddRow(index++, n, FormatSize(sz), ext, FormatTime(e.ftLastWriteTime), false);
  }
}

void OnActivate() {
  const int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
  if (sel < 0) return;
  LVITEMW it{};
  it.mask = LVIF_PARAM;
  it.iItem = sel;
  ListView_GetItem(g_list, &it);
  if (!it.lParam) return; // a file -- nothing to navigate into

  wchar_t name[MAX_PATH]{};
  ListView_GetItemText(g_list, sel, 0, name, MAX_PATH);
  if (wcscmp(name, L"..") == 0) {
    std::wstring d = g_dir;
    if (!d.empty() && d.back() == L'\\') d.pop_back();
    const size_t slash = d.find_last_of(L'\\');
    if (slash != std::wstring::npos) {
      d = d.substr(0, slash + 1);
      Populate(d);
    }
  } else {
    Populate(g_dir + name);
  }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_path = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                               0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
      g_list = CreateWindowExW(
          WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 0, 0, 0, 0, hwnd,
          nullptr, nullptr, nullptr);
      ListView_SetExtendedListViewStyle(
          g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
      const wchar_t *cols[] = {L"Name", L"Size", L"Type", L"Modified"};
      const int widths[] = {340, 100, 90, 150};
      for (int i = 0; i < 4; ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = const_cast<wchar_t *>(cols[i]);
        c.cx = widths[i];
        c.iSubItem = i;
        ListView_InsertColumn(g_list, i, &c);
      }
      return 0;
    }
    case WM_SIZE: {
      const int w = LOWORD(lp), h = HIWORD(lp);
      MoveWindow(g_path, 4, 4, w - 8, 22, TRUE);
      MoveWindow(g_list, 4, 30, w - 8, h - 34, TRUE);
      return 0;
    }
    case WM_NOTIFY: {
      auto *nh = reinterpret_cast<LPNMHDR>(lp);
      if (nh->hwndFrom == g_list && nh->code == NM_DBLCLK) {
        OnActivate();
      }
      return 0;
    }
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd, msg, wp, lp);
  }
}

} // namespace

// Entry point used by the GuestAgent's --file-browser mode (and host testing).
int RunFileBrowserGui(const std::wstring &startDir) {
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES};
  InitCommonControlsEx(&icc);

  WNDCLASSW wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = L"AntiMalFileBrowser";
  RegisterClassW(&wc);

  HWND hwnd = CreateWindowExW(
      0, wc.lpszClassName, L"AntiMal Files (in-guest file browser)",
      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 760, 520, nullptr,
      nullptr, wc.hInstance, nullptr);
  if (!hwnd) return 1;

  Populate(startDir.empty() ? L"C:\\" : startDir);
  ShowWindow(hwnd, SW_SHOW);
  UpdateWindow(hwnd);

  MSG m{};
  while (GetMessageW(&m, nullptr, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  return 0;
}
