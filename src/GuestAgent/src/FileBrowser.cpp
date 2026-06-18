// A self-contained Win32 file browser for the analysis guest.
//
// Why this exists: the Win11 modern shell (explorer.exe / ShellHost) crash-loops
// in this VM (the documented ucrtbase 0xC0000409 wall -- two distinct __fastfail
// sites, see memory `shell-wall-two-signatures`), so the built-in File Explorer
// is unusable. The cmd-shell sidestep gives a working console; this gives the
// analyst a working GUI FILE BROWSER launched from that console
// (`AntiMal.GuestAgent.exe --file-browser`), with NO dependency on the modern
// shell / AppX -- just user32 + comctl32 + shell32. It is also a normal Win32
// app, so it builds + runs + is verifiable on the host, not only in the guest.
//
// Scope (a usable File-Explorer replacement): an editable address bar (Enter to
// navigate), Up / Refresh / Open / This-PC toolbar buttons, a drive listing,
// name/size/type/modified columns, keyboard nav (F5 refresh, Backspace up, Enter
// open), SHA-256 triage on a file, and "Open" (ShellExecute) to launch/inspect a
// file. Deliberately dependency-light so it can never hit the modern shell's
// failure surface.

#include <windows.h>

#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>

#include <string>
#include <vector>

namespace {

enum : int {
  kIdUp = 101,
  kIdRefresh = 102,
  kIdOpen = 103,
  kIdThisPc = 104,
  kIdPath = 105,
};

HWND g_list = nullptr;
HWND g_path = nullptr;
HWND g_status = nullptr;
std::wstring g_dir; // current directory; empty == the "This PC" drive listing

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

void SetStatus(const std::wstring &text) {
  if (g_status) SetWindowTextW(g_status, text.c_str());
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

// The "This PC" view: list every logical drive as a navigable row.
void PopulateDrives() {
  g_dir.clear();
  SetWindowTextW(g_path, L"This PC");
  ListView_DeleteAllItems(g_list);
  wchar_t buf[512]{};
  const DWORD n = GetLogicalDriveStringsW(512, buf);
  int index = 0;
  if (n > 0 && n < 512) {
    for (wchar_t *p = buf; *p; p += wcslen(p) + 1) {
      const UINT type = GetDriveTypeW(p);
      const wchar_t *label = type == DRIVE_REMOVABLE ? L"<removable>"
                             : type == DRIVE_CDROM    ? L"<cd-rom>"
                             : type == DRIVE_REMOTE   ? L"<network>"
                                                      : L"<drive>";
      AddRow(index++, p, L"", label, L"", true);
    }
  }
  SetStatus(std::to_wstring(index) + L" drive(s)");
}

void Populate(std::wstring dir) {
  if (dir.empty()) {
    PopulateDrives();
    return;
  }
  if (dir.back() != L'\\') dir.push_back(L'\\');
  // Validate -- a bad address-bar entry shouldn't blank the view.
  const DWORD attrs = GetFileAttributesW(dir.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES ||
      !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    SetStatus(L"path not found: " + dir);
    return;
  }
  g_dir = dir;
  SetWindowTextW(g_path, dir.c_str());
  ListView_DeleteAllItems(g_list);

  int index = 0;
  AddRow(index++, L"..", L"", L"<up>", L"", true); // always offer "up"

  WIN32_FIND_DATAW fd{};
  const std::wstring pattern = dir + L"*";
  HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
  std::vector<WIN32_FIND_DATAW> dirs, files;
  if (h != INVALID_HANDLE_VALUE) {
    do {
      const std::wstring nm = fd.cFileName;
      if (nm == L"." || nm == L"..") continue;
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) dirs.push_back(fd);
      else files.push_back(fd);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }

  for (const auto &e : dirs) {
    AddRow(index++, e.cFileName, L"", L"<DIR>", FormatTime(e.ftLastWriteTime),
           true);
  }
  for (const auto &e : files) {
    const unsigned long long sz =
        (static_cast<unsigned long long>(e.nFileSizeHigh) << 32) | e.nFileSizeLow;
    const std::wstring nm = e.cFileName;
    const size_t dot = nm.find_last_of(L'.');
    const std::wstring ext = dot == std::wstring::npos ? L"" : nm.substr(dot);
    AddRow(index++, nm, FormatSize(sz), ext, FormatTime(e.ftLastWriteTime), false);
  }
  SetStatus(std::to_wstring(dirs.size()) + L" folder(s), " +
            std::to_wstring(files.size()) + L" file(s)");
}

// SHA-256 of a file via BCrypt (the agent already links bcrypt.lib). Returns ""
// on any error. Capped so a huge file never hangs the UI.
std::wstring Sha256OfFile(const std::wstring &path, unsigned long long size) {
  if (size > (256ull << 20)) return L"(file > 256 MB, skipped)";
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (f == INVALID_HANDLE_VALUE) return L"";
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::wstring result;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ==
      0) {
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
      std::vector<unsigned char> buf(1 << 16);
      DWORD got = 0;
      bool ok = true;
      while (ReadFile(f, buf.data(), static_cast<DWORD>(buf.size()), &got,
                      nullptr) &&
             got > 0) {
        if (BCryptHashData(hash, buf.data(), got, 0) != 0) {
          ok = false;
          break;
        }
      }
      if (ok) {
        unsigned char digest[32]{};
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
          static const wchar_t *kHex = L"0123456789abcdef";
          for (unsigned char b : digest) {
            result.push_back(kHex[b >> 4]);
            result.push_back(kHex[b & 0xF]);
          }
        }
      }
      BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  CloseHandle(f);
  return result;
}

// Name of the selected row (or "" if none). Sets *isDir.
std::wstring SelectedName(bool *isDir) {
  const int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
  if (sel < 0) return L"";
  LVITEMW it{};
  it.mask = LVIF_PARAM;
  it.iItem = sel;
  ListView_GetItem(g_list, &it);
  if (isDir) *isDir = it.lParam != 0;
  wchar_t name[MAX_PATH]{};
  ListView_GetItemText(g_list, sel, 0, name, MAX_PATH);
  return name;
}

void GoUp() {
  if (g_dir.empty()) return; // already at This PC
  std::wstring d = g_dir;
  if (!d.empty() && d.back() == L'\\') d.pop_back();
  const size_t slash = d.find_last_of(L'\\');
  if (slash == std::wstring::npos) {
    Populate(L""); // a drive root -> This PC
  } else {
    Populate(d.substr(0, slash + 1));
  }
}

// Open/run the selected file via ShellExecute (works without explorer -- it goes
// through the registry associations + CreateProcess, not the modern shell). The
// point of a sandbox is to be able to launch a file; this makes that explicit.
void OpenSelected() {
  bool isDir = false;
  const std::wstring name = SelectedName(&isDir);
  if (name.empty() || isDir || g_dir.empty()) return;
  const std::wstring full = g_dir + name;
  ShellExecuteW(nullptr, L"open", full.c_str(), nullptr, g_dir.c_str(),
                SW_SHOWNORMAL);
}

void OnActivate() {
  bool isDir = false;
  const std::wstring name = SelectedName(&isDir);
  if (name.empty()) return;
  if (!isDir) {
    // A file: show a quick triage card (full path, size, SHA-256).
    const std::wstring full = g_dir + name;
    WIN32_FILE_ATTRIBUTE_DATA fa{};
    unsigned long long size = 0;
    if (GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &fa)) {
      size = (static_cast<unsigned long long>(fa.nFileSizeHigh) << 32) |
             fa.nFileSizeLow;
    }
    const std::wstring sha = Sha256OfFile(full, size);
    std::wstring msg = full + L"\n\nSize: " + FormatSize(size) +
                       L"\nSHA-256: " + (sha.empty() ? L"(unavailable)" : sha) +
                       L"\n\n(Use the Open button to launch this file.)";
    MessageBoxW(nullptr, msg.c_str(), L"AntiMal Files - file info",
                MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (name == L"..") {
    GoUp();
  } else {
    // In the drives view g_dir is empty, so g_dir+name == the drive root.
    Populate(g_dir + name);
  }
}

// Subclass the address bar so Enter navigates to the typed path.
LRESULT CALLBACK EditProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR,
                          DWORD_PTR) {
  if (m == WM_KEYDOWN && w == VK_RETURN) {
    wchar_t buf[1024]{};
    GetWindowTextW(h, buf, 1024);
    std::wstring p = buf;
    if (p == L"This PC" || p.empty()) Populate(L"");
    else Populate(p);
    return 0;
  }
  if (m == WM_CHAR && w == VK_RETURN) return 0; // swallow the message-beep
  return DefSubclassProc(h, m, w, l);
}

HWND MakeButton(HWND parent, const wchar_t *text, int id) {
  return CreateWindowExW(0, L"BUTTON", text,
                         WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0,
                         parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                         nullptr, nullptr);
}

HWND g_btnUp = nullptr, g_btnRefresh = nullptr, g_btnOpen = nullptr,
     g_btnThisPc = nullptr;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_btnUp = MakeButton(hwnd, L"Up", kIdUp);
      g_btnRefresh = MakeButton(hwnd, L"Refresh", kIdRefresh);
      g_btnOpen = MakeButton(hwnd, L"Open", kIdOpen);
      g_btnThisPc = MakeButton(hwnd, L"This PC", kIdThisPc);
      g_path = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0,
                               hwnd, reinterpret_cast<HMENU>(kIdPath), nullptr,
                               nullptr);
      SetWindowSubclass(g_path, EditProc, 1, 0);
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
      g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0,
                                 0, 0, hwnd, nullptr, nullptr, nullptr);
      return 0;
    }
    case WM_SIZE: {
      const int w = LOWORD(lp), h = HIWORD(lp);
      const int bw = 64, bh = 24, y = 4;
      MoveWindow(g_btnUp, 4, y, bw, bh, TRUE);
      MoveWindow(g_btnRefresh, 4 + bw + 4, y, bw, bh, TRUE);
      MoveWindow(g_btnOpen, 4 + (bw + 4) * 2, y, bw, bh, TRUE);
      MoveWindow(g_btnThisPc, 4 + (bw + 4) * 3, y, bw, bh, TRUE);
      const int barX = 4 + (bw + 4) * 4;
      MoveWindow(g_path, barX, y, w - barX - 4, bh - 2, TRUE);
      MoveWindow(g_list, 4, y + bh + 4, w - 8, h - (y + bh + 4) - 22, TRUE);
      MoveWindow(g_status, 4, h - 18, w - 8, 16, TRUE);
      return 0;
    }
    case WM_COMMAND: {
      switch (LOWORD(wp)) {
        case kIdUp: GoUp(); return 0;
        case kIdRefresh: Populate(g_dir.empty() ? std::wstring() : g_dir); return 0;
        case kIdOpen: OpenSelected(); return 0;
        case kIdThisPc: Populate(L""); return 0;
        default: return 0;
      }
    }
    case WM_NOTIFY: {
      auto *nh = reinterpret_cast<LPNMHDR>(lp);
      if (nh->hwndFrom == g_list) {
        if (nh->code == NM_DBLCLK) {
          OnActivate();
        } else if (nh->code == LVN_KEYDOWN) {
          auto *kd = reinterpret_cast<LPNMLVKEYDOWN>(lp);
          if (kd->wVKey == VK_RETURN) OnActivate();
          else if (kd->wVKey == VK_BACK) GoUp();
          else if (kd->wVKey == VK_F5)
            Populate(g_dir.empty() ? std::wstring() : g_dir);
        }
      }
      return 0;
    }
    case WM_DESTROY:
      RemoveWindowSubclass(g_path, EditProc, 1);
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd, msg, wp, lp);
  }
}

} // namespace

// Entry point used by the GuestAgent's --file-browser mode (and host testing).
int RunFileBrowserGui(const std::wstring &startDir) {
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
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
      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 820, 560, nullptr,
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
