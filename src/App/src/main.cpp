#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/HyperVOrchestrator.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"

#include <Windows.h>
#include <CommCtrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <richedit.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwchar>
#include <filesystem>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr int IDC_SCAN_FILE = 1001;
constexpr int IDC_SCAN_FOLDER = 1002;
constexpr int IDC_SCAN_COMPUTER = 1003;
constexpr int IDC_DETONATE = 1004;
constexpr int IDC_OPEN_REPORTS = 1005;
constexpr int IDC_OPEN_CONFIG = 1006;
constexpr int IDC_BROWSER_IMPACT = 1007;
constexpr int IDC_AUTO_DETONATE = 1008;
constexpr int IDC_THRESHOLD = 1009;
constexpr int IDC_TIMEOUT = 1010;
constexpr int IDC_NETWORK_DISABLED = 1011;
constexpr int IDC_BASE_SETUP = 1012;
constexpr int IDC_NETWORK_ISOLATED = 1013;
constexpr int IDC_NETWORK_LIVE = 1014;
constexpr int IDC_BASE_SETUP_BUILD = 1301;
constexpr int IDC_BASE_SETUP_IMPORT = 1302;
constexpr int IDC_RESULTS = 1100;
constexpr int IDC_LOG = 1101;
constexpr int IDC_STATUS = 1102;
constexpr int IDC_RUN_EVENTS = 1103;
constexpr int IDC_LATEST_FRAME = 1104;

constexpr UINT WM_APP_SCAN_RESULT = WM_APP + 1;
constexpr UINT WM_APP_LOG = WM_APP + 2;
constexpr UINT WM_APP_SCAN_DONE = WM_APP + 3;
constexpr UINT WM_APP_DETONATION_DONE = WM_APP + 4;
constexpr UINT WM_APP_RUN_EVENT = WM_APP + 5;
constexpr UINT WM_APP_RUN_FRAME = WM_APP + 6;
constexpr UINT WM_APP_RUN_RESET = WM_APP + 7;
constexpr UINT WM_APP_VM_SCREEN = WM_APP + 8;
constexpr UINT WM_APP_VM_STATUS = WM_APP + 9;

HMENU MenuId(int id) {
  return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

constexpr COLORREF kBg = RGB(12, 14, 18);
constexpr COLORREF kPanel = RGB(20, 22, 27);
constexpr COLORREF kPanel2 = RGB(25, 28, 34);
constexpr COLORREF kBorder = RGB(47, 53, 62);
constexpr COLORREF kText = RGB(232, 238, 247);
constexpr COLORREF kMuted = RGB(148, 159, 176);
constexpr COLORREF kBlue = RGB(47, 136, 255);
constexpr COLORREF kGreen = RGB(23, 201, 123);
constexpr COLORREF kWarn = RGB(255, 176, 49);
constexpr COLORREF kRed = RGB(255, 62, 81);
constexpr int kGridHeaderH = 24;
constexpr int kContentTop = 144;

HBRUSH g_bgBrush = nullptr;
HBRUSH g_panelBrush = nullptr;
HBRUSH g_editBrush = nullptr;
HFONT g_font = nullptr;
HFONT g_fontBold = nullptr;
HFONT g_fontMono = nullptr;

struct AppState {
  HWND hwnd = nullptr;
  HWND brand = nullptr;
  HWND vmTitle = nullptr;
  HWND vmScreen = nullptr;
  HWND results = nullptr;
  HWND runEvents = nullptr;
  HWND log = nullptr;
  HWND status = nullptr;
  HWND tooltip = nullptr;
  HWND latestFrame = nullptr;
  HWND threshold = nullptr;
  HWND timeout = nullptr;
  HWND networkDisabled = nullptr;
  HWND networkIsolated = nullptr;
  HWND networkLive = nullptr;
  HWND autoDetonate = nullptr;
  antimal::AppConfig config;
  std::vector<antimal::ScanResult> scanResults;
  std::unique_ptr<Gdiplus::Image> vmFrame;
  std::filesystem::path vmFramePath;
  std::mutex mutex;
  std::atomic_bool scanning = false;
  std::atomic_uint64_t runWatchGeneration = 0;
  int flagged = 0;
  std::string vmMetaText = "VM: preflight pending";
};

AppState g_app;

std::wstring Wide(std::string_view text) {
  try {
    return antimal::Utf8ToWide(text);
  } catch (...) {
    return L"";
  }
}

std::string Narrow(std::wstring_view text) {
  try {
    return antimal::WideToUtf8(text);
  } catch (...) {
    return {};
  }
}

void InitThemeObjects() {
  if (!g_bgBrush) g_bgBrush = CreateSolidBrush(kBg);
  if (!g_panelBrush) g_panelBrush = CreateSolidBrush(kPanel);
  if (!g_editBrush) g_editBrush = CreateSolidBrush(kPanel2);
  if (!g_font) {
    g_font = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                         CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
  }
  if (!g_fontBold) {
    g_fontBold = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
  }
  if (!g_fontMono) {
    g_fontMono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                             L"Cascadia Mono");
  }
}

void ApplyFont(HWND hwnd, HFONT font = nullptr) {
  if (hwnd) {
    SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font ? font : g_font), TRUE);
  }
}

void ApplyDarkWindowTheme(HWND hwnd) {
  if (!hwnd) return;
  using SetWindowThemeFn = HRESULT(WINAPI *)(HWND, LPCWSTR, LPCWSTR);
  static SetWindowThemeFn setWindowTheme = []() -> SetWindowThemeFn {
    HMODULE theme = LoadLibraryW(L"uxtheme.dll");
    if (!theme) return nullptr;
    return reinterpret_cast<SetWindowThemeFn>(
        GetProcAddress(theme, "SetWindowTheme"));
  }();
  if (setWindowTheme) {
    setWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
  }
}

void ApplyDarkTitleBar(HWND hwnd) {
  if (!hwnd) return;
  BOOL useDark = TRUE;
  (void)DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                              &useDark, sizeof(useDark));
  COLORREF caption = kBg;
  COLORREF text = kText;
  COLORREF border = kBorder;
  (void)DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR,
                              &caption, sizeof(caption));
  (void)DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));
  (void)DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border,
                              sizeof(border));
}

void ApplyListTheme(HWND list) {
  ApplyDarkWindowTheme(list);
  ListView_SetBkColor(list, kPanel);
  ListView_SetTextBkColor(list, kPanel);
  ListView_SetTextColor(list, kText);
  ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  ApplyFont(list, g_fontMono);
}

void PostLog(std::string text) {
  PostMessageW(g_app.hwnd, WM_APP_LOG, 0,
               reinterpret_cast<LPARAM>(new std::string(std::move(text))));
}

void AppendLog(std::string_view text) {
  const std::wstring wide = Wide(text);
  const int len = GetWindowTextLengthW(g_app.log);
  SendMessageW(g_app.log, EM_SETSEL, len, len);
  SendMessageW(g_app.log, EM_REPLACESEL, FALSE,
               reinterpret_cast<LPARAM>(wide.c_str()));
  SendMessageW(g_app.log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
}

void SetStatus(std::string_view text) {
  SetWindowTextW(g_app.status, Wide(text).c_str());
}

void AddTooltip(HWND control, const wchar_t *text) {
  if (!g_app.tooltip || !control || !text) {
    return;
  }
  TOOLINFOW tool{};
  tool.cbSize = sizeof(tool);
  tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
  tool.hwnd = g_app.hwnd;
  tool.uId = reinterpret_cast<UINT_PTR>(control);
  tool.lpszText = const_cast<LPWSTR>(text);
  SendMessageW(g_app.tooltip, TTM_ADDTOOLW, 0,
               reinterpret_cast<LPARAM>(&tool));
}

std::wstring GetControlText(HWND control) {
  const int len = GetWindowTextLengthW(control);
  std::wstring value(static_cast<size_t>(len) + 1, L'\0');
  GetWindowTextW(control, value.data(), static_cast<int>(value.size()));
  value.resize(static_cast<size_t>(len));
  return value;
}

int GetThreshold() {
  const std::string value = Narrow(GetControlText(g_app.threshold));
  try {
    return std::clamp(std::stoi(value), 0, 100);
  } catch (...) {
    return 70;
  }
}

uint32_t GetTimeoutSec() {
  const std::string value = Narrow(GetControlText(g_app.timeout));
  try {
    return std::clamp(static_cast<uint32_t>(std::stoul(value)), 5u, 3600u);
  } catch (...) {
    return g_app.config.defaultTimeoutSec ? g_app.config.defaultTimeoutSec : 180;
  }
}

antimal::NetworkMode GetNetworkMode() {
  if (SendMessageW(g_app.networkIsolated, BM_GETCHECK, 0, 0) == BST_CHECKED) {
    return antimal::NetworkMode::HostOnly;
  }
  if (SendMessageW(g_app.networkLive, BM_GETCHECK, 0, 0) == BST_CHECKED) {
    return antimal::NetworkMode::Nat;
  }
  return antimal::NetworkMode::Disabled;
}

bool AutoDetonateEnabled() {
  return SendMessageW(g_app.autoDetonate, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

std::string VerdictText(const antimal::ScanResult &result) {
  return antimal::ToString(result.verdict);
}

void InsertResult(const antimal::ScanResult &result, int row) {
  LVITEMW item{};
  item.mask = LVIF_TEXT | LVIF_PARAM;
  item.iItem = row;
  std::wstring score = std::to_wstring(result.score);
  item.pszText = score.data();
  item.lParam = row;
  ListView_InsertItem(g_app.results, &item);

  const std::wstring verdict = Wide(VerdictText(result));
  const std::wstring path = result.path.wstring();
  const std::wstring sha = Wide(result.sha256);

  std::string tagSummary;
  for (size_t i = 0; i < result.tags.size() && i < 6; ++i) {
    if (!tagSummary.empty()) tagSummary += ", ";
    tagSummary += result.tags[i].tag;
  }
  if (result.tags.size() > 6) tagSummary += ", ...";
  const std::wstring tagWide = Wide(tagSummary);

  ListView_SetItemText(g_app.results, row, 1, const_cast<LPWSTR>(verdict.c_str()));
  ListView_SetItemText(g_app.results, row, 2, const_cast<LPWSTR>(tagWide.c_str()));
  ListView_SetItemText(g_app.results, row, 3, const_cast<LPWSTR>(path.c_str()));
  ListView_SetItemText(g_app.results, row, 4, const_cast<LPWSTR>(sha.c_str()));
}

void InsertRunEvent(const antimal::EventRecord &event) {
  const int row = ListView_GetItemCount(g_app.runEvents);
  LVITEMW item{};
  item.mask = LVIF_TEXT;
  item.iItem = row;
  std::wstring time = Wide(event.timestampUtc);
  item.pszText = time.data();
  ListView_InsertItem(g_app.runEvents, &item);

  const std::wstring pid = std::to_wstring(event.processId);
  const std::wstring category = Wide(event.category);
  const std::wstring action = Wide(event.action);
  const std::wstring target = Wide(event.target);
  ListView_SetItemText(g_app.runEvents, row, 1, const_cast<LPWSTR>(pid.c_str()));
  ListView_SetItemText(g_app.runEvents, row, 2, const_cast<LPWSTR>(category.c_str()));
  ListView_SetItemText(g_app.runEvents, row, 3, const_cast<LPWSTR>(action.c_str()));
  ListView_SetItemText(g_app.runEvents, row, 4, const_cast<LPWSTR>(target.c_str()));
  ListView_EnsureVisible(g_app.runEvents, row, FALSE);
}

std::optional<antimal::ScanResult> SelectedResult() {
  const int selected = ListView_GetNextItem(g_app.results, -1, LVNI_SELECTED);
  if (selected < 0) {
    return std::nullopt;
  }
  std::lock_guard lock(g_app.mutex);
  if (static_cast<size_t>(selected) >= g_app.scanResults.size()) {
    return std::nullopt;
  }
  return g_app.scanResults[static_cast<size_t>(selected)];
}

std::filesystem::path ChooseFile() {
  wchar_t fileName[MAX_PATH]{};
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_app.hwnd;
  ofn.lpstrFile = fileName;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = L"Executable and binaries\0*.exe;*.dll;*.sys;*.scr;*.bin\0All files\0*.*\0";
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  if (!GetOpenFileNameW(&ofn)) {
    return {};
  }
  return fileName;
}

std::filesystem::path ChooseVhdx() {
  wchar_t fileName[MAX_PATH]{};
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_app.hwnd;
  ofn.lpstrFile = fileName;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = L"Windows virtual disks\0*.vhdx;*.vhd\0All files\0*.*\0";
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  ofn.lpstrTitle = L"Select the clean Windows analysis VHDX";
  if (!GetOpenFileNameW(&ofn)) {
    return {};
  }
  return fileName;
}

std::filesystem::path ChooseIso() {
  wchar_t fileName[MAX_PATH]{};
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_app.hwnd;
  ofn.lpstrFile = fileName;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = L"Windows ISO images\0*.iso\0All files\0*.*\0";
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  ofn.lpstrTitle = L"Select a Windows ISO";
  if (!GetOpenFileNameW(&ofn)) {
    return {};
  }
  return fileName;
}

std::filesystem::path ChooseFolder() {
  BROWSEINFOW browse{};
  browse.hwndOwner = g_app.hwnd;
  browse.lpszTitle = L"Select a folder to scan";
  browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
  PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&browse);
  if (!pidl) {
    return {};
  }
  wchar_t path[MAX_PATH]{};
  SHGetPathFromIDListW(pidl, path);
  CoTaskMemFree(pidl);
  return path;
}

std::vector<std::filesystem::path> FixedDriveRoots() {
  std::vector<std::filesystem::path> roots;
  wchar_t buffer[512]{};
  const DWORD chars = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(buffer)), buffer);
  for (wchar_t *drive = buffer; drive < buffer + chars && *drive; drive += wcslen(drive) + 1) {
    if (GetDriveTypeW(drive) == DRIVE_FIXED) {
      roots.emplace_back(drive);
    }
  }
  return roots;
}

std::filesystem::path ExecutableDir() {
  std::wstring buffer(MAX_PATH, L'\0');
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  while (size == buffer.size()) {
    buffer.resize(buffer.size() * 2);
    size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  }
  buffer.resize(size);
  return std::filesystem::path(buffer).parent_path();
}

std::filesystem::path RepoRoot() {
  if (const auto root = antimal::FindRepoRoot(ExecutableDir())) {
    return *root;
  }
  if (const auto root = antimal::FindRepoRoot(std::filesystem::current_path())) {
    return *root;
  }
  return ExecutableDir();
}

std::filesystem::path ToolScriptPath(const wchar_t *scriptName) {
  const auto repoPath = RepoRoot() / "tools" / scriptName;
  if (std::filesystem::exists(repoPath)) {
    return repoPath;
  }
  return ExecutableDir() / "tools" / scriptName;
}

std::filesystem::path BaseImageScriptPath() {
  return ToolScriptPath(L"New-AntiMalVmBase.ps1");
}

std::filesystem::path DefaultBaseVhdxPath() {
  return g_app.config.workspaceRoot / "_base" / "AntiMalBase.vhdx";
}

std::wstring QuoteArg(const std::filesystem::path &path) {
  std::wstring value = path.wstring();
  std::wstring out = L"\"";
  for (wchar_t ch : value) {
    if (ch == L'"') {
      out += L"\\\"";
    } else {
      out += ch;
    }
  }
  out += L"\"";
  return out;
}

std::wstring QuoteText(std::wstring value) {
  std::wstring out = L"\"";
  for (wchar_t ch : value) {
    if (ch == L'"') {
      out += L"\\\"";
    } else {
      out += ch;
    }
  }
  out += L"\"";
  return out;
}

std::filesystem::path ExecutableDir();
std::filesystem::path DefaultBaseVhdxPath();

void SaveCurrentConfig() {
  const auto configPath = antimal::DefaultConfigPath();
  antimal::EnsureDirectory(configPath.parent_path());
  antimal::WriteTextFile(configPath, antimal::SerializeConfig(g_app.config));
}

std::string BoolWord(bool value) {
  return value ? "ok" : "missing";
}

std::string ConversionCommand(const antimal::HyperVPreflight &preflight) {
  const auto exe = ExecutableDir() / "AntiMal.HostCli.exe";
  const auto vhdx = preflight.baseVhdxPath.empty()
                        ? DefaultBaseVhdxPath()
                        : preflight.baseVhdxPath;
  const auto raw = preflight.baseDiskPath.empty()
                       ? g_app.config.workspaceRoot / "_base" / "AntiMalBase.raw"
                       : preflight.baseDiskPath;
  return antimal::PathToUtf8(exe) + " base convert --vhdx " +
         antimal::PathToUtf8(vhdx) + " --raw " + antimal::PathToUtf8(raw);
}

void RefreshVmReadiness(bool updateStatus = false) {
  antimal::HyperVOrchestrator orchestrator(g_app.config);
  const auto preflight = orchestrator.Preflight();

  std::ostringstream title;
  title << "In-house VM readiness: "
        << (preflight.bootCapabilityReady ? "boot attempt ready"
                                           : "boot blocked");
  if (g_app.vmTitle) {
    SetWindowTextW(g_app.vmTitle, Wide(title.str()).c_str());
  }

  std::ostringstream screen;
  screen << "WHP: " << (preflight.whpAvailable ? "available" : "not available")
         << " | OVMF: " << BoolWord(preflight.firmwarePresent)
         << " | GuestAgent: " << BoolWord(preflight.guestAgentPresent) << "\n";
  screen << "Base: "
         << (preflight.rawBaseReady
                 ? "raw ready"
                 : preflight.baseVhdxReadable ? "VHDX readable" : "missing")
         << " | Raw: " << (preflight.rawBaseReady ? "ready" : "optional/missing")
         << " | Network: "
         << (preflight.networkReady ? "disabled/ready" : "unsupported mode")
         << "\n";
  screen << "VHDX: "
         << (preflight.baseVhdxReadable
                 ? "readable"
                 : preflight.baseVhdxPresent ? "present/unreadable" : "missing")
         << " | Boot: "
         << (preflight.bootCapabilityReady ? "real boot attempt ready"
                                            : "blocked")
         << "\n";
  if (preflight.vhdxConversionRequired) {
    screen << "Action: direct VHDX read failed; convert to raw before boot.\n"
           << ConversionCommand(preflight);
  } else if (preflight.bootCapabilityReady) {
    screen << "Samples stay gated until Windows boot and GuestAgent connection are proven.";
  } else if (!preflight.blockers.empty()) {
    screen << "Blocker: " << preflight.blockers.front();
  } else {
    screen << "Sample execution remains disabled until host/guest channel wiring lands.";
  }

  if (g_app.vmScreen) {
    SetWindowTextW(g_app.vmScreen, Wide(screen.str()).c_str());
  }

  std::ostringstream meta;
  meta << "VM: inhouse"
       << "    WHP: " << (preflight.whpAvailable ? "yes" : "no")
       << "    Base: "
       << (preflight.rawBaseReady ? "raw" : preflight.baseVhdxReadable ? "vhdx" : "no")
       << "    Boot: " << (preflight.bootCapabilityReady ? "ready" : "blocked");
  g_app.vmMetaText = meta.str();

  if (updateStatus) {
    SetStatus(preflight.bootCapabilityReady
                  ? "VM boot attempt ready."
                  : "VM boot blocked; see workspace readiness.");
  }
  InvalidateRect(g_app.hwnd, nullptr, FALSE);
}

void StartRunWatch(std::filesystem::path runDir) {
  const uint64_t generation = ++g_app.runWatchGeneration;
  PostMessageW(g_app.hwnd, WM_APP_RUN_RESET, 0,
               reinterpret_cast<LPARAM>(new std::filesystem::path(runDir)));

  std::thread([runDir = std::move(runDir), generation] {
    using namespace std::chrono_literals;
    const auto journalPath = runDir / "events.jsonl";
    const auto screenshotsDir = runDir / "screenshots";
    antimal::EventJournalTailer tailer(journalPath);
    std::set<std::filesystem::path> seenFrames;
    int quietPollsAfterReport = 0;

    while (g_app.runWatchGeneration.load() == generation) {
      for (auto &event : tailer.PullNew()) {
        PostMessageW(g_app.hwnd, WM_APP_RUN_EVENT, 0,
                     reinterpret_cast<LPARAM>(new antimal::EventRecord(std::move(event))));
      }

      std::error_code ec;
      if (std::filesystem::exists(screenshotsDir, ec)) {
        std::vector<std::filesystem::path> frames;
        for (std::filesystem::directory_iterator it(screenshotsDir, ec), end;
             !ec && it != end; it.increment(ec)) {
          if (it->is_regular_file(ec) &&
              antimal::ToLowerAscii(it->path().extension().string()) == ".png") {
            frames.push_back(it->path());
          }
        }
        std::sort(frames.begin(), frames.end());
        for (const auto &frame : frames) {
          if (seenFrames.insert(frame).second) {
            PostMessageW(g_app.hwnd, WM_APP_RUN_FRAME, 0,
                         reinterpret_cast<LPARAM>(new std::filesystem::path(frame)));
          }
        }
      }

      if (std::filesystem::exists(runDir / "report.json", ec)) {
        ++quietPollsAfterReport;
        if (quietPollsAfterReport >= 6) {
          break;
        }
      }
      std::this_thread::sleep_for(500ms);
    }
    PostLog("Live watch stopped for " + antimal::PathToUtf8(runDir));
  }).detach();
}

void StartDetonationWithOptions(std::filesystem::path samplePath,
                                uint32_t timeoutSec,
                                antimal::NetworkMode networkMode) {
  std::thread([samplePath = std::move(samplePath), timeoutSec, networkMode] {
    try {
      PostLog("Detonation requested for " + antimal::PathToUtf8(samplePath));
      PostLog("This typically takes 30s-3min; live boot progress will appear "
              "below.");
      antimal::HyperVOrchestrator orchestrator(g_app.config);

      // Watch-start latch: the run watcher (filmstrip + journal tail) is
      // kicked off the first time the progress callback hands us a runDir,
      // so the UI sees screenshots and events as they appear instead of
      // waiting until PrepareAndRun returns.
      std::atomic<bool> watchStarted{false};
      auto progress = [&watchStarted](
                          const antimal::DetonationProgress &snap) {
        if (!watchStarted.exchange(true) && !snap.runDir.empty()) {
          StartRunWatch(snap.runDir);
        }
        if (!snap.message.empty()) {
          PostLog(snap.message);
        }
        if (!snap.vgaTextScreen.empty()) {
          PostMessageW(g_app.hwnd, WM_APP_VM_SCREEN, 0,
                       reinterpret_cast<LPARAM>(
                           new std::string(snap.vgaTextScreen)));
        } else {
          // No VGA text yet (OVMF runs in UEFI GOP mode for most of boot).
          // Synthesize a fixed-width status pseudo-screen so the VM panel
          // still has something to look at — counters, dominant ports,
          // phase, plus a one-line diagnosis when a port spin is detected.
          auto formatLine = [](char *out, size_t cap, const char *fmt,
                                auto... args) {
            _snprintf_s(out, cap, _TRUNCATE, fmt, args...);
          };
          char header[120];
          formatLine(header, sizeof(header),
                     "AntiMal Live VM   phase=%-10s elapsed=%llus",
                     snap.phase.c_str(),
                     static_cast<unsigned long long>(snap.elapsedMs / 1000ull));
          char line1[120];
          formatLine(line1, sizeof(line1),
                     "  steps=%-10d  HLTs=%-6d  vcpuExits=%d",
                     snap.steps, snap.totalHlts, snap.steps);
          char line2[120];
          formatLine(line2, sizeof(line2),
                     "  IDE: %llu sectors read, %llu written, %llu commands",
                     static_cast<unsigned long long>(snap.ideSectorsRead),
                     static_cast<unsigned long long>(snap.ideSectorsWritten),
                     static_cast<unsigned long long>(snap.ideCommands));
          char line3[120];
          formatLine(line3, sizeof(line3),
                     "  MMIO: %u reads, %u writes  IOAPIC: %llu delivered",
                     snap.mmioReads, snap.mmioWrites,
                     static_cast<unsigned long long>(snap.ioApicDeliveries));
          char line4[120];
          formatLine(line4, sizeof(line4),
                     "  Top I/O: 0x%04X=%llu, 0x%04X=%llu, 0x%04X=%llu",
                     snap.topPorts[0].port,
                     static_cast<unsigned long long>(snap.topPorts[0].count),
                     snap.topPorts[1].port,
                     static_cast<unsigned long long>(snap.topPorts[1].count),
                     snap.topPorts[2].port,
                     static_cast<unsigned long long>(snap.topPorts[2].count));
          char line5[120];
          formatLine(line5, sizeof(line5),
                     "  Guest %04X:%016llX",
                     snap.currentCsSelector,
                     static_cast<unsigned long long>(snap.currentRip));

          const char *diagnosis = "Guest is making progress.";
          const uint16_t top = snap.topPorts[0].port;
          if (top == 0x70 || top == 0x71) {
            diagnosis = "Guest is spinning on CMOS — likely TSC calibration.";
          } else if (top == 0xB008) {
            diagnosis = "Guest is polling ACPI PM timer.";
          } else if (top == 0x40 || top == 0x41 || top == 0x42) {
            diagnosis = "Guest is polling PIT current-count register.";
          } else if (top == 0xCF8 || top == 0xCFC) {
            diagnosis = "Guest is probing PCI configuration space.";
          } else if (top == 0x1F0 || top == 0x1F7) {
            diagnosis = "Guest is doing IDE PIO I/O.";
          } else if (top == 0 && snap.steps == 0) {
            diagnosis = "Waiting for first vCPU exit.";
          }

          std::string screen;
          screen.reserve(80 * 25);
          screen.append(header).append("\n");
          screen.append("\n");
          screen.append(line1).append("\n");
          screen.append(line2).append("\n");
          screen.append(line3).append("\n");
          screen.append(line4).append("\n");
          screen.append(line5).append("\n");
          screen.append("\n");
          screen.append("  Diagnosis: ").append(diagnosis).append("\n");
          screen.append("\n");
          screen.append("  (Legacy VGA text framebuffer at 0xB8000 is empty —\n"
                        "   OVMF + Windows boot in UEFI GOP graphics mode.\n"
                        "   GOP framebuffer rendering is on the roadmap.)\n");
          PostMessageW(g_app.hwnd, WM_APP_VM_SCREEN, 0,
                       reinterpret_cast<LPARAM>(new std::string(screen)));
        }
        {
          char buf[256]{};
          _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                      "Live VM [%s] %llus  steps=%d  HLTs=%d  "
                      "ide_r=%llu  ide_w=%llu  mmio=%u/%u  "
                      "ioapic=%llu",
                      snap.phase.c_str(),
                      static_cast<unsigned long long>(snap.elapsedMs / 1000ull),
                      snap.steps, snap.totalHlts,
                      static_cast<unsigned long long>(snap.ideSectorsRead),
                      static_cast<unsigned long long>(snap.ideSectorsWritten),
                      snap.mmioReads, snap.mmioWrites,
                      static_cast<unsigned long long>(snap.ioApicDeliveries));
          PostMessageW(g_app.hwnd, WM_APP_VM_STATUS, 0,
                       reinterpret_cast<LPARAM>(new std::string(buf)));
        }
        if (!snap.newSerialBytes.empty()) {
          // The guest's COM1 output. Most of OVMF speaks ASCII; Windows
          // bootloader uses tabs and newlines plus a few VT100-style escapes.
          // Strip control bytes other than CR/LF/TAB so they don't make the
          // log unreadable.
          std::string line = "[guest serial] ";
          for (char c : snap.newSerialBytes) {
            const auto byte = static_cast<unsigned char>(c);
            if (byte == '\n') {
              PostLog(line);
              line = "[guest serial] ";
            } else if (byte == '\r' || byte == '\t' ||
                       (byte >= 32 && byte < 127)) {
              line.push_back(static_cast<char>(byte));
            } else {
              char esc[8];
              _snprintf_s(esc, sizeof(esc), _TRUNCATE, "\\x%02X", byte);
              line.append(esc);
            }
          }
          if (line.size() > 16) {  // 16 = strlen("[guest serial] ")+1
            PostLog(line);
          }
        }
      };

      auto result = orchestrator.PrepareAndRun(samplePath, timeoutSec,
                                               networkMode, true, progress);

      std::ostringstream out;
      out << "VM run " << result.runId << " workspace "
          << antimal::PathToUtf8(result.runDir);
      PostLog(out.str());
      if (!result.overlayDiskPath.empty()) {
        PostLog("Per-run overlay disk: " + antimal::PathToUtf8(result.overlayDiskPath));
      }
      PostLog("Run status: " + result.status);
      PostLog(result.dynamicSummary.sampleExecuted
                  ? "Sample executed inside guest."
                  : "Sample not executed; in-house boot/channel safety gate remains closed.");
      for (const auto &error : result.errors) {
        PostLog("VM error: " + error);
      }
      if (!watchStarted.exchange(true)) {
        // Defensive: if PrepareAndRun returned without ever firing the
        // progress callback (e.g. blocked-by-preflight), still start the
        // watcher so the user can see the final report/screenshots.
        StartRunWatch(result.runDir);
      }
      PostMessageW(g_app.hwnd, WM_APP_DETONATION_DONE, 0,
                   reinterpret_cast<LPARAM>(new std::filesystem::path(result.runDir)));
    } catch (const std::exception &ex) {
      PostLog(std::string("Detonation failed: ") + ex.what());
    }
  }).detach();
}

void StartDetonation(std::filesystem::path samplePath) {
  StartDetonationWithOptions(std::move(samplePath), GetTimeoutSec(), GetNetworkMode());
}

void StartScan(std::vector<std::filesystem::path> roots, std::string label) {
  if (g_app.scanning.exchange(true)) {
    MessageBoxW(g_app.hwnd, L"A scan is already running.", L"AntiMal", MB_OK | MB_ICONINFORMATION);
    return;
  }

  {
    std::lock_guard lock(g_app.mutex);
    g_app.scanResults.clear();
    g_app.flagged = 0;
  }
  ListView_DeleteAllItems(g_app.results);
  SetStatus("Scanning...");
  PostLog("Starting scan: " + label);

  const int threshold = GetThreshold();
  const bool autoDetonate = AutoDetonateEnabled();
  const uint32_t timeoutSec = GetTimeoutSec();
  const antimal::NetworkMode networkMode = GetNetworkMode();

  // Pull the enrichment knobs off the loaded AppConfig so the GUI scan
  // path uses the same yara/capa/die/intel posture as the CLI.
  antimal::ScannerOptions scanOpts;
  {
    std::lock_guard<std::mutex> lock(g_app.mutex);
    scanOpts.runYara = g_app.config.enrichYara;
    scanOpts.runCapa = g_app.config.enrichCapa;
    scanOpts.runDie = g_app.config.enrichDie;
    scanOpts.applyTagger = g_app.config.enrichTagger;
    scanOpts.yaraRulesDir = g_app.config.yaraRulesDir;
    scanOpts.tagsRulesPath = g_app.config.tagsRulesPath;
    scanOpts.intelLookupEnabled = g_app.config.intelEnabled;
    scanOpts.malwareBazaarEnabled = g_app.config.intelMalwareBazaar;
    scanOpts.virusTotalApiKey = g_app.config.virusTotalApiKey;
    if (!g_app.config.workspaceRoot.empty()) {
      scanOpts.intelCacheDir = g_app.config.workspaceRoot / "_intel_cache";
    }
  }

  std::thread([roots = std::move(roots), threshold, autoDetonate, timeoutSec,
               networkMode, scanOpts = std::move(scanOpts)] {
    size_t count = 0;
    try {
      for (const auto &root : roots) {
        PostLog("Scanning " + antimal::PathToUtf8(root));
        auto results = antimal::ScanPath(root, scanOpts);
        for (auto &result : results) {
          ++count;
          const bool flagged = result.score >= threshold;
          auto heapResult = new antimal::ScanResult(std::move(result));
          const std::filesystem::path sample = heapResult->path;
          PostMessageW(g_app.hwnd, WM_APP_SCAN_RESULT, flagged ? 1 : 0,
                       reinterpret_cast<LPARAM>(heapResult));
          if (flagged && autoDetonate) {
            StartDetonationWithOptions(sample, timeoutSec, networkMode);
          }
        }
      }
    } catch (const std::exception &ex) {
      PostLog(std::string("Scan error: ") + ex.what());
    }
    PostMessageW(g_app.hwnd, WM_APP_SCAN_DONE, count, 0);
  }).detach();
}

void AddColumns(HWND list) {
  LVCOLUMNW col{};
  col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  col.pszText = const_cast<LPWSTR>(L"Score");
  col.cx = 72;
  ListView_InsertColumn(list, 0, &col);
  col.pszText = const_cast<LPWSTR>(L"Verdict");
  col.cx = 100;
  ListView_InsertColumn(list, 1, &col);
  col.pszText = const_cast<LPWSTR>(L"Tags");
  col.cx = 260;
  ListView_InsertColumn(list, 2, &col);
  col.pszText = const_cast<LPWSTR>(L"Path");
  col.cx = 500;
  ListView_InsertColumn(list, 3, &col);
  col.pszText = const_cast<LPWSTR>(L"SHA-256");
  col.cx = 460;
  ListView_InsertColumn(list, 4, &col);
}

void AddRunEventColumns(HWND list) {
  LVCOLUMNW col{};
  col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  col.pszText = const_cast<LPWSTR>(L"Time");
  col.cx = 180;
  ListView_InsertColumn(list, 0, &col);
  col.pszText = const_cast<LPWSTR>(L"PID");
  col.cx = 64;
  ListView_InsertColumn(list, 1, &col);
  col.pszText = const_cast<LPWSTR>(L"Category");
  col.cx = 110;
  ListView_InsertColumn(list, 2, &col);
  col.pszText = const_cast<LPWSTR>(L"Action");
  col.cx = 160;
  ListView_InsertColumn(list, 3, &col);
  col.pszText = const_cast<LPWSTR>(L"Target");
  col.cx = 620;
  ListView_InsertColumn(list, 4, &col);
}

void FitResultsColumns(HWND list) {
  RECT rc{};
  if (!GetClientRect(list, &rc)) return;
  const int width = std::max(480, static_cast<int>(rc.right - rc.left - 4));
  const int scoreW = 72;
  const int verdictW = 100;
  const int tagsW = 180;
  const int shaW = std::clamp(width / 4, 220, 340);
  const int pathW = std::max(220, width - scoreW - verdictW - tagsW - shaW);
  ListView_SetColumnWidth(list, 0, scoreW);
  ListView_SetColumnWidth(list, 1, verdictW);
  ListView_SetColumnWidth(list, 2, tagsW);
  ListView_SetColumnWidth(list, 3, pathW);
  ListView_SetColumnWidth(list, 4, shaW);
}

void FitRunEventColumns(HWND list) {
  RECT rc{};
  if (!GetClientRect(list, &rc)) return;
  const int width = std::max(480, static_cast<int>(rc.right - rc.left - 4));
  const int timeW = 172;
  const int pidW = 64;
  const int categoryW = 110;
  const int actionW = 150;
  const int targetW = std::max(220, width - timeW - pidW - categoryW - actionW);
  ListView_SetColumnWidth(list, 0, timeW);
  ListView_SetColumnWidth(list, 1, pidW);
  ListView_SetColumnWidth(list, 2, categoryW);
  ListView_SetColumnWidth(list, 3, actionW);
  ListView_SetColumnWidth(list, 4, targetW);
}

RECT VmScreenContentRect(HWND hwnd) {
  RECT rc{};
  GetClientRect(hwnd, &rc);
  const int width = rc.right - rc.left;
  const int margin = 12;
  const int rightW = std::clamp(width / 3, 330, 390);
  const int gap = 16;
  const int leftW = std::max(520, width - rightW - gap - margin * 2);
  const int vmH = 360;
  return RECT{margin + 22, kContentTop + 48, margin + leftW - 22,
              kContentTop + vmH - 32};
}

void ClearVmFrame() {
  g_app.vmFrame.reset();
  g_app.vmFramePath.clear();
  if (g_app.vmScreen) {
    ShowWindow(g_app.vmScreen, SW_SHOW);
  }
  if (g_app.hwnd) {
    InvalidateRect(g_app.hwnd, nullptr, FALSE);
  }
}

bool ShowVmFrame(const std::filesystem::path &framePath) {
  auto image = std::make_unique<Gdiplus::Image>(framePath.wstring().c_str());
  if (image->GetLastStatus() != Gdiplus::Ok || image->GetWidth() == 0 ||
      image->GetHeight() == 0) {
    return false;
  }
  g_app.vmFramePath = framePath;
  g_app.vmFrame = std::move(image);
  if (g_app.vmScreen) {
    ShowWindow(g_app.vmScreen, SW_HIDE);
  }
  if (g_app.hwnd) {
    InvalidateRect(g_app.hwnd, nullptr, FALSE);
  }
  return true;
}

bool IsGuestFrame(const std::filesystem::path &framePath) {
  const std::string name =
      antimal::ToLowerAscii(framePath.filename().string());
  return name.rfind("guest-", 0) == 0;
}

bool ShouldDisplayVmFrame(const std::filesystem::path &framePath) {
  if (!g_app.vmFrame) {
    return true;
  }
  if (IsGuestFrame(framePath)) {
    return true;
  }
  return !IsGuestFrame(g_app.vmFramePath);
}

void DrawVmFrame(HDC dc, const RECT &rc) {
  if (!g_app.vmFrame) {
    return;
  }

  const int boxW = std::max(1, static_cast<int>(rc.right - rc.left));
  const int boxH = std::max(1, static_cast<int>(rc.bottom - rc.top));
  const UINT imageW = g_app.vmFrame->GetWidth();
  const UINT imageH = g_app.vmFrame->GetHeight();
  if (imageW == 0 || imageH == 0) {
    return;
  }

  Gdiplus::Graphics graphics(dc);
  graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
  graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);

  Gdiplus::SolidBrush fill(Gdiplus::Color(255, 8, 10, 14));
  graphics.FillRectangle(&fill, rc.left, rc.top, boxW, boxH);

  const double scale =
      std::min(static_cast<double>(boxW) / static_cast<double>(imageW),
               static_cast<double>(boxH) / static_cast<double>(imageH));
  const int drawW = std::max(1, static_cast<int>(imageW * scale + 0.5));
  const int drawH = std::max(1, static_cast<int>(imageH * scale + 0.5));
  const int x = rc.left + (boxW - drawW) / 2;
  const int y = rc.top + (boxH - drawH) / 2;

  graphics.DrawImage(g_app.vmFrame.get(), x, y, drawW, drawH);
  Gdiplus::Pen border(Gdiplus::Color(255, 47, 53, 62), 1.0f);
  graphics.DrawRectangle(&border, rc.left, rc.top, boxW - 1, boxH - 1);
}

std::optional<std::filesystem::path> FindLatestRunDir() {
  std::error_code ec;
  const auto &root = g_app.config.workspaceRoot;
  if (root.empty() || !std::filesystem::exists(root, ec)) {
    return std::nullopt;
  }

  std::optional<std::filesystem::path> latest;
  std::filesystem::file_time_type latestTime{};
  for (std::filesystem::directory_iterator it(root, ec), end; !ec && it != end;
       it.increment(ec)) {
    if (!it->is_directory(ec)) {
      continue;
    }
    const auto runDir = it->path();
    const bool looksLikeRun =
        std::filesystem::exists(runDir / "report.json", ec) ||
        std::filesystem::exists(runDir / "events.jsonl", ec) ||
        std::filesystem::exists(runDir / "screenshots", ec);
    if (!looksLikeRun) {
      continue;
    }

    const auto marker = std::filesystem::exists(runDir / "report.json", ec)
                            ? runDir / "report.json"
                            : runDir;
    const auto stamp = std::filesystem::last_write_time(marker, ec);
    if (ec) {
      continue;
    }
    if (!latest || stamp > latestTime) {
      latest = runDir;
      latestTime = stamp;
    }
  }
  return latest;
}

std::vector<std::filesystem::path> ListRunFrames(
    const std::filesystem::path &runDir) {
  std::vector<std::filesystem::path> frames;
  const auto screenshotsDir = runDir / "screenshots";
  std::error_code ec;
  if (!std::filesystem::exists(screenshotsDir, ec)) {
    return frames;
  }

  for (std::filesystem::directory_iterator it(screenshotsDir, ec), end;
       !ec && it != end; it.increment(ec)) {
    if (it->is_regular_file(ec) &&
        antimal::ToLowerAscii(it->path().extension().string()) == ".png") {
      frames.push_back(it->path());
    }
  }
  std::sort(frames.begin(), frames.end());
  return frames;
}

std::optional<std::filesystem::path> LatestPreferredFrame(
    const std::vector<std::filesystem::path> &frames) {
  for (auto it = frames.rbegin(); it != frames.rend(); ++it) {
    if (IsGuestFrame(*it)) {
      return *it;
    }
  }
  if (!frames.empty()) {
    return frames.back();
  }
  return std::nullopt;
}

void LoadRunPreview(const std::filesystem::path &runDir,
                    std::string_view label) {
  ClearVmFrame();
  ListView_DeleteAllItems(g_app.runEvents);

  std::string status = "completed run";
  const auto reportPath = runDir / "report.json";
  std::error_code ec;
  if (std::filesystem::exists(reportPath, ec)) {
    try {
      const auto report = antimal::LoadReportBestEffort(reportPath);
      if (!report.dynamicSummary.status.empty()) {
        status = report.dynamicSummary.status;
      }
      if (!report.dynamicSummary.bootStage.empty()) {
        status += " / " + report.dynamicSummary.bootStage;
      }
    } catch (...) {
      status = "report present";
    }
  }

  const auto frames = ListRunFrames(runDir);
  const auto preferredFrame = LatestPreferredFrame(frames);
  if (preferredFrame) {
    ShowVmFrame(*preferredFrame);
    SetWindowTextW(g_app.latestFrame,
                   (L"Preview frame: " + preferredFrame->wstring()).c_str());
  } else {
    SetWindowTextW(g_app.vmScreen,
                   (L"Run workspace\n" + runDir.wstring() +
                    L"\nNo screenshots were captured for this run.").c_str());
    SetWindowTextW(g_app.latestFrame, L"Preview: no screenshots captured");
  }

  antimal::EventJournalTailer tailer(runDir / "events.jsonl");
  auto events = tailer.ReadAll();
  constexpr size_t kMaxPreviewEvents = 2500;
  if (events.size() > kMaxPreviewEvents) {
    events.erase(events.begin(), events.end() - kMaxPreviewEvents);
  }
  for (const auto &event : events) {
    InsertRunEvent(event);
  }

  SetWindowTextW(g_app.vmTitle,
                 Wide("Latest run preview: " + status).c_str());
  SetStatus(std::string(label) + ": " + antimal::PathToUtf8(runDir));
  AppendLog(std::string(label) + ": " + antimal::PathToUtf8(runDir));
}

void Layout(HWND hwnd) {
  RECT rc{};
  GetClientRect(hwnd, &rc);
  const int width = rc.right - rc.left;
  const int height = rc.bottom - rc.top;

  const int margin = 12;
  const int buttonH = 30;
  int x = margin + 150;

  auto move = [&](int id, int w) {
    HWND child = GetDlgItem(hwnd, id);
    MoveWindow(child, x, 10, w, buttonH, TRUE);
    x += w + 8;
  };

  MoveWindow(g_app.brand, margin, 12, 128, 26, TRUE);
  move(IDC_SCAN_FILE, 94);
  move(IDC_SCAN_FOLDER, 104);
  move(IDC_SCAN_COMPUTER, 122);
  x += 10;
  move(IDC_BASE_SETUP, 102);
  move(IDC_DETONATE, 136);
  move(IDC_BROWSER_IMPACT, 112);
  move(IDC_OPEN_REPORTS, 96);
  move(IDC_OPEN_CONFIG, 86);

  MoveWindow(g_app.autoDetonate, std::max(x, width - 170), 10, 158, buttonH, TRUE);

  HWND thresholdLabel = GetDlgItem(hwnd, 1201);
  HWND timeoutLabel = GetDlgItem(hwnd, 1202);
  HWND networkLabel = GetDlgItem(hwnd, 1203);
  const int controlsY = 64;
  MoveWindow(thresholdLabel, margin, controlsY, 76, 22, TRUE);
  MoveWindow(g_app.threshold, margin + 78, controlsY - 4, 58, 26, TRUE);
  MoveWindow(timeoutLabel, margin + 170, controlsY, 70, 22, TRUE);
  MoveWindow(g_app.timeout, margin + 242, controlsY - 4, 70, 26, TRUE);
  MoveWindow(networkLabel, margin + 350, controlsY, 70, 22, TRUE);
  MoveWindow(g_app.networkDisabled, margin + 422, controlsY - 5, 86, 26, TRUE);
  MoveWindow(g_app.networkIsolated, margin + 512, controlsY - 5, 84, 26, TRUE);
  MoveWindow(g_app.networkLive, margin + 600, controlsY - 5, 60, 26, TRUE);
  MoveWindow(g_app.status, margin, 98, width - margin * 2, 34, TRUE);

  const int rightW = std::clamp(width / 3, 330, 390);
  const int gap = 16;
  const int leftW = std::max(520, width - rightW - gap - margin * 2);
  const int rightX = margin + leftW + gap;
  const int vmH = 360;
  const int logH = std::max(240, height - kContentTop - margin);
  const int resultsY = kContentTop + vmH + gap;
  const int liveH = std::max(150, (height - resultsY - margin - gap) / 2);
  const int resultsH = std::max(170, height - resultsY - liveH - gap - margin);
  const int liveY = resultsY + resultsH + gap;
  const RECT vmScreenRc = VmScreenContentRect(hwnd);

  MoveWindow(g_app.vmTitle, margin + 16, kContentTop + 10, leftW - 32, 24, TRUE);
  MoveWindow(g_app.vmScreen, vmScreenRc.left, vmScreenRc.top,
             vmScreenRc.right - vmScreenRc.left,
             vmScreenRc.bottom - vmScreenRc.top, TRUE);
  MoveWindow(g_app.latestFrame, margin + 22, kContentTop + vmH - 28,
             leftW - 44, 22, TRUE);
  MoveWindow(g_app.results, margin, resultsY + 34 + kGridHeaderH, leftW,
             resultsH - 34 - kGridHeaderH, TRUE);
  MoveWindow(g_app.runEvents, margin, liveY + 34 + kGridHeaderH, leftW,
             liveH - 34 - kGridHeaderH, TRUE);
  FitResultsColumns(g_app.results);
  FitRunEventColumns(g_app.runEvents);

  MoveWindow(g_app.log, rightX, kContentTop + 34, rightW, logH - 34, TRUE);
}

void CreateControls(HWND hwnd) {
  InitThemeObjects();
  g_app.brand = CreateWindowW(L"STATIC", L"ANTIMAL .VX",
                              WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                              0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
  ApplyFont(g_app.brand, g_fontBold);

  const DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_OWNERDRAW;
  CreateWindowW(L"BUTTON", L"Scan File", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_SCAN_FILE), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Scan Folder", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_SCAN_FOLDER), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Scan Computer", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_SCAN_COMPUTER), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Base Setup", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_BASE_SETUP), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Detonate Selected", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_DETONATE), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Browser Risk", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_BROWSER_IMPACT), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Reports", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_OPEN_REPORTS), nullptr, nullptr);
  CreateWindowW(L"BUTTON", L"Config", buttonStyle, 0, 0, 0, 0, hwnd,
                MenuId(IDC_OPEN_CONFIG), nullptr, nullptr);

  g_app.autoDetonate = CreateWindowW(L"BUTTON", L"Auto-detonate flagged",
                                     WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0,
                                     hwnd, MenuId(IDC_AUTO_DETONATE),
                                     nullptr, nullptr);
  g_app.tooltip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                  WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                  CW_USEDEFAULT, CW_USEDEFAULT,
                                  CW_USEDEFAULT, CW_USEDEFAULT,
                                  hwnd, nullptr, nullptr, nullptr);
  if (g_app.tooltip) {
    SendMessageW(g_app.tooltip, TTM_SETMAXTIPWIDTH, 0, 360);
  }

  CreateWindowW(L"STATIC", L"Flag >=", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                MenuId(1201), nullptr, nullptr);
  g_app.threshold = CreateWindowW(L"EDIT", L"70", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
                                  0, 0, 0, 0, hwnd,
                                  MenuId(IDC_THRESHOLD), nullptr, nullptr);

  CreateWindowW(L"STATIC", L"VM sec", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                MenuId(1202), nullptr, nullptr);
  std::wstring timeout = std::to_wstring(g_app.config.defaultTimeoutSec);
  g_app.timeout = CreateWindowW(L"EDIT", timeout.c_str(),
                                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER, 0, 0, 0, 0,
                                hwnd, MenuId(IDC_TIMEOUT), nullptr, nullptr);

  CreateWindowW(L"STATIC", L"Network", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                MenuId(1203), nullptr, nullptr);
  g_app.networkDisabled =
      CreateWindowW(L"BUTTON", L"DISABLED",
                    WS_CHILD | WS_VISIBLE | WS_GROUP | BS_AUTORADIOBUTTON |
                        BS_PUSHLIKE | BS_OWNERDRAW,
                    0, 0, 0, 0, hwnd, MenuId(IDC_NETWORK_DISABLED),
                    nullptr, nullptr);
  g_app.networkIsolated =
      CreateWindowW(L"BUTTON", L"ISOLATED",
                    WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | BS_PUSHLIKE |
                        BS_OWNERDRAW,
                    0, 0, 0, 0, hwnd, MenuId(IDC_NETWORK_ISOLATED),
                    nullptr, nullptr);
  g_app.networkLive =
      CreateWindowW(L"BUTTON", L"LIVE",
                    WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | BS_PUSHLIKE |
                        BS_OWNERDRAW,
                    0, 0, 0, 0, hwnd, MenuId(IDC_NETWORK_LIVE),
                    nullptr, nullptr);
  HWND selectedNetwork = g_app.networkDisabled;
  if (g_app.config.networkMode == antimal::NetworkMode::HostOnly) {
    selectedNetwork = g_app.networkIsolated;
  } else if (g_app.config.networkMode == antimal::NetworkMode::Nat) {
    selectedNetwork = g_app.networkLive;
  }
  SendMessageW(selectedNetwork, BM_SETCHECK, BST_CHECKED, 0);

  g_app.status =
      CreateWindowW(L"STATIC", L"Ready",
                    WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                    0, 0, 0, 0, hwnd, MenuId(IDC_STATUS), nullptr, nullptr);
  g_app.vmTitle =
      CreateWindowW(L"STATIC", L"In-house VM readiness: preflight pending",
                    WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0,
                    hwnd, nullptr, nullptr, nullptr);
  g_app.vmScreen =
      CreateWindowW(L"STATIC",
                    L"VM screen will appear here while a sample is detonating.\n"
                    L"Live boot status, serial output, and the legacy VGA text\n"
                    L"framebuffer (when populated) are mirrored above the log.",
                    WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 0, 0,
                    hwnd, nullptr, nullptr, nullptr);
  g_app.latestFrame =
      CreateWindowW(L"STATIC", L"Live run: no active run", WS_CHILD | WS_VISIBLE,
                    0, 0, 0, 0, hwnd, MenuId(IDC_LATEST_FRAME), nullptr, nullptr);

  g_app.results = CreateWindowW(WC_LISTVIEWW, nullptr,
                                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT |
                                    LVS_SINGLESEL | LVS_SHOWSELALWAYS |
                                    LVS_NOCOLUMNHEADER,
                                0, 0, 0, 0, hwnd, MenuId(IDC_RESULTS),
                                nullptr, nullptr);
  ApplyListTheme(g_app.results);
  AddColumns(g_app.results);

  g_app.runEvents = CreateWindowW(WC_LISTVIEWW, nullptr,
                                  WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT |
                                      LVS_SINGLESEL | LVS_SHOWSELALWAYS |
                                      LVS_NOCOLUMNHEADER,
                                  0, 0, 0, 0, hwnd, MenuId(IDC_RUN_EVENTS),
                                  nullptr, nullptr);
  ApplyListTheme(g_app.runEvents);
  AddRunEventColumns(g_app.runEvents);

  g_app.log = CreateWindowW(L"EDIT", nullptr,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE |
                                ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                            0, 0, 0, 0, hwnd, MenuId(IDC_LOG),
                            nullptr, nullptr);
  SendMessageW(g_app.log, EM_SETLIMITTEXT, 1024 * 1024, 0);
  SendMessageW(g_app.log, EM_SETBKGNDCOLOR, 0, kPanel);
  ApplyDarkWindowTheme(g_app.log);

  for (int id : {IDC_SCAN_FILE, IDC_SCAN_FOLDER, IDC_SCAN_COMPUTER, IDC_BASE_SETUP,
                 IDC_DETONATE, IDC_BROWSER_IMPACT, IDC_OPEN_REPORTS,
                 IDC_OPEN_CONFIG, IDC_THRESHOLD, IDC_TIMEOUT, IDC_NETWORK_DISABLED,
                 IDC_NETWORK_ISOLATED, IDC_NETWORK_LIVE}) {
    ApplyFont(GetDlgItem(hwnd, id));
  }
  ApplyFont(g_app.autoDetonate);
  ApplyFont(g_app.status);
  ApplyFont(g_app.vmTitle, g_fontBold);
  ApplyFont(g_app.vmScreen, g_fontMono);
  ApplyFont(g_app.latestFrame, g_fontMono);
  ApplyFont(g_app.log, g_fontMono);

  AddTooltip(GetDlgItem(hwnd, 1201),
             L"Minimum scan score that counts as flagged. Auto-detonate only uses flagged results.");
  AddTooltip(g_app.threshold,
             L"Threshold is 0-100. Your sample scored 60, so threshold 70 means flagged 0.");
  AddTooltip(GetDlgItem(hwnd, 1202),
             L"Maximum seconds for the VM boot/detonation attempt after you press Detonate Selected.");
  AddTooltip(g_app.timeout,
             L"Timeout applies to Detonate Selected, not to the static scan.");
  AddTooltip(g_app.autoDetonate,
             L"When checked, only results with score >= threshold are automatically staged for the VM path.");
  AddTooltip(GetDlgItem(hwnd, IDC_DETONATE),
             L"Runs the in-house VM boot attempt for the selected result. The sample is still safety-gated.");
}

void OpenPath(const std::filesystem::path &path) {
  ShellExecuteW(g_app.hwnd, L"open", path.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void OpenLatestReportOrWorkspace() {
  antimal::EnsureDirectory(g_app.config.workspaceRoot);
  if (const auto latestRun = FindLatestRunDir()) {
    const auto html = *latestRun / "report.html";
    const auto json = *latestRun / "report.json";
    std::error_code ec;
    if (std::filesystem::exists(html, ec)) {
      OpenPath(html);
      SetStatus("Opened latest HTML report: " + antimal::PathToUtf8(html));
      return;
    }
    if (std::filesystem::exists(json, ec)) {
      OpenPath(json);
      SetStatus("Opened latest JSON report: " + antimal::PathToUtf8(json));
      return;
    }
    OpenPath(*latestRun);
    SetStatus("Opened latest run workspace: " + antimal::PathToUtf8(*latestRun));
    return;
  }
  OpenPath(g_app.config.workspaceRoot);
  SetStatus("Opened report workspace: " +
            antimal::PathToUtf8(g_app.config.workspaceRoot));
}

void RunImportBase() {
  auto baseVhdx = g_app.config.baseVhdxPath;
  if (baseVhdx.empty() || !std::filesystem::exists(baseVhdx)) {
    MessageBoxW(g_app.hwnd,
                L"Choose a clean Windows VHDX. AntiMal will save it as the local in-house base disk.",
                L"AntiMal Base Import", MB_OK | MB_ICONINFORMATION);
    baseVhdx = ChooseVhdx();
    if (baseVhdx.empty()) {
      return;
    }
  }

  try {
    g_app.config.baseVhdxPath = std::filesystem::absolute(baseVhdx);
    g_app.config.vmProvider = "inhouse";
    SaveCurrentConfig();
  } catch (const std::exception &ex) {
    MessageBoxW(g_app.hwnd, Wide(std::string("Unable to save config: ") + ex.what()).c_str(),
                L"AntiMal Base Import", MB_OK | MB_ICONERROR);
    return;
  }

  PostLog("Imported local in-house base VHDX: " +
          antimal::PathToUtf8(g_app.config.baseVhdxPath));
  {
    antimal::HyperVOrchestrator orchestrator(g_app.config);
    const auto preflight = orchestrator.Preflight();
    if (preflight.baseVhdxReadable) {
      PostLog("VHDX is readable; in-house boot attempt will use it directly with a disposable overlay.");
      if (!std::filesystem::exists(g_app.config.baseDiskPath)) {
        PostLog("Raw base disk is not present; raw conversion is optional unless direct VHDX read fails.");
      }
    } else if (preflight.vhdxConversionRequired) {
      PostLog("VHDX imported, but direct read failed; raw conversion is required before in-house boot.");
      PostLog("Convert with: " +
              antimal::PathToUtf8(ExecutableDir() / "AntiMal.HostCli.exe") +
              " base convert --vhdx " +
              antimal::PathToUtf8(g_app.config.baseVhdxPath) + " --raw " +
              antimal::PathToUtf8(g_app.config.baseDiskPath));
    }
  }
  RefreshVmReadiness(true);
}

void RunBaseImageBuilder() {
  MessageBoxW(g_app.hwnd,
              L"Select a Windows ISO. Base Setup creates the base disk locally with built-in Windows image tools only. It will not launch VirtualBox, VMware, Hyper-V Manager, or Hyper-V VM cmdlets.",
              L"AntiMal Base Setup", MB_OK | MB_ICONINFORMATION);

  const auto isoPath = ChooseIso();
  if (isoPath.empty()) {
    return;
  }

  const auto scriptPath = BaseImageScriptPath();
  if (!std::filesystem::exists(scriptPath)) {
    MessageBoxW(g_app.hwnd, L"New-AntiMalVmBase.ps1 was not found in the tools folder.",
                L"AntiMal Base Setup", MB_OK | MB_ICONERROR);
    return;
  }

  const auto outputVhdx = DefaultBaseVhdxPath();
  try {
    g_app.config.baseVhdxPath = outputVhdx;
    SaveCurrentConfig();
  } catch (const std::exception &ex) {
    MessageBoxW(g_app.hwnd, Wide(std::string("Unable to save config: ") + ex.what()).c_str(),
                L"AntiMal Base Setup", MB_OK | MB_ICONERROR);
    return;
  }

  const auto configPath = antimal::DefaultConfigPath();
  std::wstring parameters =
      L"-NoExit -ExecutionPolicy Bypass -File " + QuoteArg(scriptPath) +
      L" -WindowsIsoPath " + QuoteArg(isoPath) +
      L" -WorkspaceRoot " + QuoteArg(g_app.config.workspaceRoot) +
      L" -VmNamePrefix " + QuoteText(Wide(g_app.config.vmNamePrefix)) +
      L" -ConfigPath " + QuoteArg(configPath) +
      L" -Provider local -WriteConfig";

  HINSTANCE launched = ShellExecuteW(g_app.hwnd, L"runas", L"powershell.exe",
                                     parameters.c_str(), nullptr, SW_SHOWNORMAL);
  if (reinterpret_cast<INT_PTR>(launched) <= 32) {
    MessageBoxW(g_app.hwnd, L"Unable to launch elevated base image builder.",
                L"AntiMal Base Setup", MB_OK | MB_ICONERROR);
    return;
  }

  PostLog("Base Setup builder launched elevated from ISO: " + antimal::PathToUtf8(isoPath));
  PostLog("Base Setup build is local-only: diskpart + DISM + bcdboot.");
  PostLog("Builder creates a VHDX. AntiMal will try direct VHDX boot; raw export is optional if direct read fails.");
  RefreshVmReadiness(true);
}

void BrowserImpactSelected() {
  const auto selected = SelectedResult();
  if (!selected) {
    MessageBoxW(g_app.hwnd, L"Select a scan result first.", L"AntiMal", MB_OK | MB_ICONINFORMATION);
    return;
  }
  std::thread([path = selected->path] {
    try {
      PostLog("Browser-risk analysis started.");
      antimal::AnalysisReport report;
      report.runId = antimal::MakeRunId();
      report.samplePath = path;
      report.scannerVerdict = antimal::ScanFile(path);
      report.networkDomains = {};
      report.browserImpact = antimal::AnalyzeBrowserImpact(report.networkDomains, true);
      const auto outDir = g_app.config.workspaceRoot / report.runId;
      antimal::EnsureDirectory(outDir);
      antimal::WriteReportHtml(outDir / "browser-impact.html", report);
      antimal::WriteReportJson(outDir / "browser-impact.json", report);
      PostLog("Browser-risk report written to " + antimal::PathToUtf8(outDir));
      PostMessageW(g_app.hwnd, WM_APP_DETONATION_DONE, 0,
                   reinterpret_cast<LPARAM>(new std::filesystem::path(outDir)));
    } catch (const std::exception &ex) {
      PostLog(std::string("Browser-risk analysis failed: ") + ex.what());
    }
  }).detach();
}

void DrawPanel(HDC dc, RECT rc, const wchar_t *title) {
  FillRect(dc, &rc, g_panelBrush);
  HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
  HGDIOBJ oldPen = SelectObject(dc, pen);
  HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
  Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
  SelectObject(dc, oldBrush);
  SelectObject(dc, oldPen);
  DeleteObject(pen);

  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, kMuted);
  SelectObject(dc, g_fontBold);
  RECT titleRc{rc.left + 16, rc.top + 9, rc.right - 16, rc.top + 32};
  DrawTextW(dc, title, -1, &titleRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
}

void DrawGridHeader(HDC dc, HWND list, RECT rc,
                    std::initializer_list<const wchar_t *> labels) {
  HBRUSH darkFill = CreateSolidBrush(RGB(31, 34, 41));
  FillRect(dc, &rc, darkFill);
  DeleteObject(darkFill);

  HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
  HGDIOBJ oldPen = SelectObject(dc, pen);
  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, kText);
  SelectObject(dc, g_fontBold);

  int x = rc.left;
  int index = 0;
  for (const wchar_t *label : labels) {
    const int colW = ListView_GetColumnWidth(list, index);
    RECT cell{x, rc.top, x + colW, rc.bottom};
    MoveToEx(dc, cell.right - 1, cell.top + 3, nullptr);
    LineTo(dc, cell.right - 1, cell.bottom - 3);
    RECT textRc{cell.left + 8, cell.top, cell.right - 8, cell.bottom};
    DrawTextW(dc, label, -1, &textRc,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    x += colW;
    ++index;
  }
  MoveToEx(dc, rc.left, rc.bottom - 1, nullptr);
  LineTo(dc, rc.right, rc.bottom - 1);
  SelectObject(dc, oldPen);
  DeleteObject(pen);
}

void PaintWorkspace(HWND hwnd, HDC dc) {
  RECT rc{};
  GetClientRect(hwnd, &rc);
  FillRect(dc, &rc, g_bgBrush);

  RECT top{0, 0, rc.right, 50};
  FillRect(dc, &top, g_bgBrush);
  RECT controls{0, 50, rc.right, kContentTop - 8};
  FillRect(dc, &controls, g_panelBrush);

  const int width = rc.right - rc.left;
  const int height = rc.bottom - rc.top;
  const int margin = 12;
  const int rightW = std::clamp(width / 3, 330, 390);
  const int gap = 16;
  const int leftW = std::max(520, width - rightW - gap - margin * 2);
  const int rightX = margin + leftW + gap;
  const int vmH = 360;
  const int logH = std::max(240, height - kContentTop - margin);
  const int resultsY = kContentTop + vmH + gap;
  const int liveH = std::max(150, (height - resultsY - margin - gap) / 2);
  const int resultsH = std::max(170, height - resultsY - liveH - gap - margin);
  const int liveY = resultsY + resultsH + gap;

  DrawPanel(dc, RECT{margin, kContentTop, margin + leftW, kContentTop + vmH},
            L"VM WORKSPACE");
  DrawVmFrame(dc, VmScreenContentRect(hwnd));
  DrawPanel(dc, RECT{margin, resultsY, margin + leftW, resultsY + resultsH},
            L"ANALYSIS RESULTS");
  DrawPanel(dc, RECT{margin, liveY, margin + leftW, liveY + liveH},
            L"LIVE RUN TELEMETRY");
  DrawPanel(dc, RECT{rightX, kContentTop, rightX + rightW, kContentTop + logH},
            L"STATUS LOG");

  DrawGridHeader(dc, g_app.results,
                 RECT{margin, resultsY + 34, margin + leftW,
                      resultsY + 34 + kGridHeaderH},
                 {L"Score", L"Verdict", L"Tags", L"Path", L"SHA-256"});
  DrawGridHeader(dc, g_app.runEvents,
                 RECT{margin, liveY + 34, margin + leftW,
                      liveY + 34 + kGridHeaderH},
                 {L"Time", L"PID", L"Category", L"Action", L"Target"});

}

void DrawOwnerButton(const DRAWITEMSTRUCT *dis) {
  if (!dis || dis->CtlType != ODT_BUTTON) return;
  wchar_t text[128]{};
  GetWindowTextW(dis->hwndItem, text, static_cast<int>(std::size(text)));

  const bool selected = (dis->itemState & ODS_SELECTED) != 0;
  const bool checked = SendMessageW(dis->hwndItem, BM_GETCHECK, 0, 0) == BST_CHECKED;
  const bool disabled = (dis->itemState & ODS_DISABLED) != 0;
  COLORREF border = kBorder;
  COLORREF fill = checked ? RGB(45, 33, 20) : (selected ? RGB(31, 38, 49) : kPanel);
  COLORREF textColor = disabled ? RGB(96, 102, 112) : kText;
  const int id = static_cast<int>(dis->CtlID);
  if (id == IDC_SCAN_FILE) {
    border = kBlue;
    textColor = kBlue;
  } else if (id == IDC_DETONATE) {
    border = kRed;
    textColor = kRed;
  } else if (id == IDC_BASE_SETUP || id == IDC_BASE_SETUP_BUILD ||
             id == IDC_BASE_SETUP_IMPORT) {
    border = kWarn;
    textColor = kWarn;
  } else if (id == IDC_NETWORK_DISABLED || id == IDC_NETWORK_ISOLATED ||
             id == IDC_NETWORK_LIVE) {
    border = checked ? kWarn : kBorder;
    textColor = checked ? kWarn : kMuted;
  }

  HBRUSH fillBrush = CreateSolidBrush(fill);
  FillRect(dis->hDC, &dis->rcItem, fillBrush);
  DeleteObject(fillBrush);
  HPEN pen = CreatePen(PS_SOLID, 1, border);
  HGDIOBJ oldPen = SelectObject(dis->hDC, pen);
  HGDIOBJ oldBrush = SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
  Rectangle(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right,
            dis->rcItem.bottom);
  SelectObject(dis->hDC, oldBrush);
  SelectObject(dis->hDC, oldPen);
  DeleteObject(pen);

  SetBkMode(dis->hDC, TRANSPARENT);
  SetTextColor(dis->hDC, textColor);
  SelectObject(dis->hDC, g_font);
  RECT textRc = dis->rcItem;
  DrawTextW(dis->hDC, text, -1, &textRc,
            DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}

enum class BaseSetupAction {
  None,
  BuildFromIso,
  ImportVhdx,
};

struct BaseSetupDialogState {
  BaseSetupAction action = BaseSetupAction::None;
  std::wstring baseStatus;
};

std::wstring CurrentBaseStatusText() {
  if (g_app.config.baseVhdxPath.empty()) {
    return L"Current base: not configured";
  }
  std::wstring status = L"Current base: " + g_app.config.baseVhdxPath.wstring();
  status += std::filesystem::exists(g_app.config.baseVhdxPath) ? L" (found)" : L" (missing)";
  return status;
}

LRESULT CALLBACK BaseSetupDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  auto *state = reinterpret_cast<BaseSetupDialogState *>(
      GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  switch (msg) {
  case WM_NCCREATE: {
    auto *create = reinterpret_cast<CREATESTRUCTW *>(lParam);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                      reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    return TRUE;
  }
  case WM_CREATE: {
    InitThemeObjects();
    state = reinterpret_cast<BaseSetupDialogState *>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    CreateWindowW(L"STATIC", L"Base Setup", WS_CHILD | WS_VISIBLE,
                  22, 18, 460, 24, hwnd, nullptr, nullptr, nullptr);
    CreateWindowW(L"STATIC",
                  L"Prepare the clean in-house Windows guest base for safe dynamic analysis.",
                  WS_CHILD | WS_VISIBLE, 22, 50, 460, 22, hwnd, nullptr,
                  nullptr, nullptr);
    CreateWindowW(L"STATIC", state ? state->baseStatus.c_str() : L"",
                  WS_CHILD | WS_VISIBLE, 22, 82, 460, 44, hwnd, nullptr,
                  nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Build from Windows ISO",
                  WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 22, 142, 190, 32,
                  hwnd, MenuId(IDC_BASE_SETUP_BUILD), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Import clean VHDX",
                  WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 224, 142, 160, 32,
                  hwnd, MenuId(IDC_BASE_SETUP_IMPORT), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Cancel",
                  WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 396, 142, 88, 32,
                  hwnd, MenuId(IDCANCEL), nullptr, nullptr);

    for (HWND child = GetWindow(hwnd, GW_CHILD); child;
         child = GetWindow(child, GW_HWNDNEXT)) {
      ApplyFont(child);
    }
    return 0;
  }
  case WM_PAINT: {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);
    FillRect(dc, &rc, g_bgBrush);
    RECT panel{10, 10, rc.right - 10, rc.bottom - 10};
    FillRect(dc, &panel, g_panelBrush);
    HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, panel.left, panel.top, panel.right, panel.bottom);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
    EndPaint(hwnd, &ps);
    return 0;
  }
  case WM_DRAWITEM:
    DrawOwnerButton(reinterpret_cast<DRAWITEMSTRUCT *>(lParam));
    return TRUE;
  case WM_CTLCOLORSTATIC: {
    HDC dc = reinterpret_cast<HDC>(wParam);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kText);
    return reinterpret_cast<LRESULT>(g_panelBrush);
  }
  case WM_COMMAND:
    if (!state) return 0;
    if (LOWORD(wParam) == IDC_BASE_SETUP_BUILD) {
      state->action = BaseSetupAction::BuildFromIso;
      DestroyWindow(hwnd);
      return 0;
    }
    if (LOWORD(wParam) == IDC_BASE_SETUP_IMPORT) {
      state->action = BaseSetupAction::ImportVhdx;
      DestroyWindow(hwnd);
      return 0;
    }
    if (LOWORD(wParam) == IDCANCEL) {
      state->action = BaseSetupAction::None;
      DestroyWindow(hwnd);
      return 0;
    }
    break;
  case WM_KEYDOWN:
    if (wParam == VK_ESCAPE) {
      if (state) state->action = BaseSetupAction::None;
      DestroyWindow(hwnd);
      return 0;
    }
    break;
  case WM_CLOSE:
    if (state) state->action = BaseSetupAction::None;
    DestroyWindow(hwnd);
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

BaseSetupAction ChooseBaseSetupAction() {
  static bool registered = false;
  const wchar_t *className = L"AntiMalBaseSetupDialog";
  if (!registered) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = BaseSetupDialogProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = className;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush;
    RegisterClassW(&wc);
    registered = true;
  }

  BaseSetupDialogState state{};
  state.baseStatus = CurrentBaseStatusText();

  RECT ownerRc{};
  GetWindowRect(g_app.hwnd, &ownerRc);
  const int w = 520;
  const int h = 230;
  const int x = ownerRc.left + ((ownerRc.right - ownerRc.left) - w) / 2;
  const int y = ownerRc.top + ((ownerRc.bottom - ownerRc.top) - h) / 2;
  HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, className,
                                L"AntiMal Base Setup",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                x, y, w, h, g_app.hwnd, nullptr,
                                GetModuleHandleW(nullptr), &state);
  if (!dialog) {
    return BaseSetupAction::None;
  }

  EnableWindow(g_app.hwnd, FALSE);
  ShowWindow(dialog, SW_SHOW);
  MSG msg{};
  while (IsWindow(dialog) && GetMessageW(&msg, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(dialog, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  EnableWindow(g_app.hwnd, TRUE);
  SetForegroundWindow(g_app.hwnd);
  return state.action;
}

void RunBaseSetupFlow() {
  const BaseSetupAction action = ChooseBaseSetupAction();
  if (action == BaseSetupAction::BuildFromIso) {
    RunBaseImageBuilder();
  } else if (action == BaseSetupAction::ImportVhdx) {
    RunImportBase();
  }
}

LRESULT HandleListCustomDraw(LPARAM lParam) {
  auto *draw = reinterpret_cast<NMLVCUSTOMDRAW *>(lParam);
  if (!draw || (draw->nmcd.hdr.hwndFrom != g_app.results &&
                draw->nmcd.hdr.hwndFrom != g_app.runEvents)) {
    return CDRF_DODEFAULT;
  }
  if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) {
    return CDRF_NOTIFYITEMDRAW;
  }
  if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
    const bool odd = (draw->nmcd.dwItemSpec % 2) != 0;
    const bool selected = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
    draw->clrText = selected ? RGB(255, 255, 255) : kText;
    draw->clrTextBk =
        selected ? RGB(32, 72, 120) : (odd ? RGB(18, 20, 25) : kPanel);
    return CDRF_NEWFONT;
  }
  return CDRF_DODEFAULT;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
  case WM_CREATE:
    g_app.hwnd = hwnd;
    ApplyDarkTitleBar(hwnd);
    g_app.config = antimal::LoadConfig(antimal::DefaultConfigPath());
    antimal::EnsureDirectory(g_app.config.workspaceRoot);
    CreateControls(hwnd);
    AppendLog("AntiMal UI ready.");
    AppendLog("Use Base Setup to build/import a clean VHDX. Direct VHDX boot attempts are supported; external VM apps are not used.");
    RefreshVmReadiness(true);
    if (const auto latestRun = FindLatestRunDir()) {
      LoadRunPreview(*latestRun, "Loaded latest run preview");
    }
    return 0;

  case WM_SIZE:
    Layout(hwnd);
    InvalidateRect(hwnd, nullptr, TRUE);
    return 0;

  case WM_ERASEBKGND:
    return 1;

  case WM_PAINT: {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    PaintWorkspace(hwnd, dc);
    EndPaint(hwnd, &ps);
    return 0;
  }

  case WM_DRAWITEM:
    DrawOwnerButton(reinterpret_cast<DRAWITEMSTRUCT *>(lParam));
    return TRUE;

  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLOREDIT:
  case WM_CTLCOLORBTN:
  case WM_CTLCOLORLISTBOX: {
    HDC dc = reinterpret_cast<HDC>(wParam);
    HWND child = reinterpret_cast<HWND>(lParam);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, child == g_app.brand ? RGB(255, 255, 255) : kText);
    if (child == g_app.brand) {
      SetBkColor(dc, kBg);
      return reinterpret_cast<LRESULT>(g_bgBrush);
    }
    if (child == g_app.vmScreen || child == g_app.log ||
        msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORLISTBOX) {
      SetBkColor(dc, kPanel2);
      return reinterpret_cast<LRESULT>(g_editBrush);
    }
    SetBkColor(dc, kPanel);
    return reinterpret_cast<LRESULT>(g_panelBrush);
  }

  case WM_NOTIFY: {
    auto *hdr = reinterpret_cast<NMHDR *>(lParam);
    if (hdr && hdr->code == NM_CUSTOMDRAW) {
      return HandleListCustomDraw(lParam);
    }
    return 0;
  }

  case WM_COMMAND:
  {
    const int id = LOWORD(wParam);
    const int code = HIWORD(wParam);
    if (id == IDC_THRESHOLD) {
      if (code == EN_SETFOCUS) {
        SetStatus("Flag >= score: scan results at or above this score count as flagged. Auto-detonate uses only flagged rows.");
      } else if (code == EN_KILLFOCUS) {
        const int value = GetThreshold();
        SetWindowTextW(g_app.threshold, std::to_wstring(value).c_str());
        SetStatus("Flag threshold set to " + std::to_string(value) + ". It affects the next scan and auto-detonate.");
      }
      return 0;
    }
    if (id == IDC_TIMEOUT) {
      if (code == EN_SETFOCUS) {
        SetStatus("VM sec: max seconds for Detonate Selected. It does not affect Scan File.");
      } else if (code == EN_KILLFOCUS) {
        const uint32_t value = GetTimeoutSec();
        SetWindowTextW(g_app.timeout, std::to_wstring(value).c_str());
        g_app.config.defaultTimeoutSec = value;
        SaveCurrentConfig();
        SetStatus("VM timeout set to " + std::to_string(value) + " seconds for future detonation attempts.");
      }
      return 0;
    }
    if ((id == IDC_NETWORK_DISABLED || id == IDC_NETWORK_ISOLATED ||
         id == IDC_NETWORK_LIVE) &&
        code == BN_CLICKED) {
      g_app.config.networkMode = GetNetworkMode();
      SaveCurrentConfig();
      RefreshVmReadiness(true);
      return 0;
    }
    if (id == IDC_AUTO_DETONATE && code == BN_CLICKED) {
      SetStatus(AutoDetonateEnabled()
                    ? "Auto-detonate is on: only rows with score >= flag threshold will be sent to the VM path."
                    : "Auto-detonate is off. Select a result row and press Detonate Selected manually.");
      return 0;
    }
    switch (id) {
    case IDC_SCAN_FILE: {
      auto file = ChooseFile();
      if (!file.empty()) {
        StartScan({file}, "file " + antimal::PathToUtf8(file));
      }
      return 0;
    }
    case IDC_SCAN_FOLDER: {
      auto folder = ChooseFolder();
      if (!folder.empty()) {
        StartScan({folder}, "folder " + antimal::PathToUtf8(folder));
      }
      return 0;
    }
    case IDC_SCAN_COMPUTER: {
      const auto roots = FixedDriveRoots();
      if (roots.empty()) {
        MessageBoxW(hwnd, L"No fixed drives were found.", L"AntiMal", MB_OK | MB_ICONINFORMATION);
      } else {
        StartScan(roots, "computer fixed drives");
      }
      return 0;
    }
    case IDC_BASE_SETUP:
      RunBaseSetupFlow();
      return 0;
    case IDC_DETONATE: {
      auto selected = SelectedResult();
      if (!selected) {
        MessageBoxW(hwnd, L"Select a scan result first.", L"AntiMal", MB_OK | MB_ICONINFORMATION);
      } else {
        StartDetonation(selected->path);
      }
      return 0;
    }
    case IDC_OPEN_REPORTS:
      OpenLatestReportOrWorkspace();
      return 0;
    case IDC_OPEN_CONFIG:
      OpenPath(antimal::DefaultConfigPath());
      return 0;
    case IDC_BROWSER_IMPACT:
      BrowserImpactSelected();
      return 0;
    default:
      break;
    }
  }
    break;

  case WM_APP_SCAN_RESULT: {
    std::unique_ptr<antimal::ScanResult> result(
        reinterpret_cast<antimal::ScanResult *>(lParam));
    const bool flagged = wParam != 0;
    int row = 0;
    {
      std::lock_guard lock(g_app.mutex);
      row = static_cast<int>(g_app.scanResults.size());
      if (flagged) {
        ++g_app.flagged;
      }
      g_app.scanResults.push_back(*result);
    }
    InsertResult(*result, row);
    if (flagged) {
      PostLog("Flagged score " + std::to_string(result->score) + ": " +
              antimal::PathToUtf8(result->path));
    }
    return 0;
  }

  case WM_APP_LOG: {
    std::unique_ptr<std::string> text(reinterpret_cast<std::string *>(lParam));
    AppendLog(*text);
    return 0;
  }

  case WM_APP_SCAN_DONE: {
    g_app.scanning = false;
    std::ostringstream status;
    status << "Scan complete: " << static_cast<size_t>(wParam)
           << " scanned, " << g_app.flagged << " flagged. Flag threshold "
           << GetThreshold() << "; select a row and press Detonate Selected to VM-test it.";
    SetStatus(status.str());
    PostLog(status.str());
    return 0;
  }

  case WM_APP_DETONATION_DONE: {
    std::unique_ptr<std::filesystem::path> path(
        reinterpret_cast<std::filesystem::path *>(lParam));
    if (path && std::filesystem::exists(*path)) {
      std::string state = "workspace active";
      const auto reportPath = *path / "report.json";
      if (std::filesystem::exists(reportPath)) {
        try {
          const auto report = antimal::LoadReportBestEffort(reportPath);
          if (!report.dynamicSummary.status.empty()) {
            state = report.dynamicSummary.status;
          } else if (!report.errors.empty()) {
            state = "blocked";
          }
        } catch (...) {
        }
      }
      SetStatus("Run " + state + ": " + antimal::PathToUtf8(*path));
      PostLog("Run " + state + ". Use Reports to open the written artifacts.");
    }
    return 0;
  }

  case WM_APP_RUN_RESET: {
    std::unique_ptr<std::filesystem::path> path(
        reinterpret_cast<std::filesystem::path *>(lParam));
    ClearVmFrame();
    ListView_DeleteAllItems(g_app.runEvents);
    if (path) {
      SetWindowTextW(g_app.latestFrame,
                     (L"Live run: " + path->wstring()).c_str());
      SetWindowTextW(g_app.vmScreen,
                     (L"Run workspace\n" + path->wstring() +
                      L"\nReading real journal and VM summary files").c_str());
      SetStatus("Watching run " + antimal::PathToUtf8(path->filename()));
    }
    return 0;
  }

  case WM_APP_RUN_EVENT: {
    std::unique_ptr<antimal::EventRecord> event(
        reinterpret_cast<antimal::EventRecord *>(lParam));
    if (event) {
      InsertRunEvent(*event);
    }
    return 0;
  }

  case WM_APP_RUN_FRAME: {
    std::unique_ptr<std::filesystem::path> frame(
        reinterpret_cast<std::filesystem::path *>(lParam));
    if (frame) {
      SetWindowTextW(g_app.latestFrame,
                     (L"Latest screenshot: " + frame->wstring()).c_str());
      if (!ShouldDisplayVmFrame(*frame)) {
        return 0;
      }
      if (!ShowVmFrame(*frame)) {
        PostLog("Latest screenshot was found but could not be rendered yet: " +
                antimal::PathToUtf8(*frame));
      }
    }
    return 0;
  }

  case WM_APP_VM_SCREEN: {
    std::unique_ptr<std::string> screen(
        reinterpret_cast<std::string *>(lParam));
    if (screen) {
      SetWindowTextW(g_app.vmScreen, Wide(*screen).c_str());
    }
    return 0;
  }

  case WM_APP_VM_STATUS: {
    std::unique_ptr<std::string> status(
        reinterpret_cast<std::string *>(lParam));
    if (status) {
      SetWindowTextW(g_app.vmTitle, Wide(*status).c_str());
    }
    return 0;
  }

  case WM_DESTROY:
    ++g_app.runWatchGeneration;
    g_app.vmFrame.reset();
    if (g_font) DeleteObject(g_font);
    if (g_fontBold) DeleteObject(g_fontBold);
    if (g_fontMono) DeleteObject(g_fontMono);
    if (g_bgBrush) DeleteObject(g_bgBrush);
    if (g_panelBrush) DeleteObject(g_panelBrush);
    if (g_editBrush) DeleteObject(g_editBrush);
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int show) {
  INITCOMMONCONTROLSEX icc{};
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
  InitCommonControlsEx(&icc);
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  Gdiplus::GdiplusStartupInput gdiInput{};
  ULONG_PTR gdiToken = 0;
  if (Gdiplus::GdiplusStartup(&gdiToken, &gdiInput, nullptr) != Gdiplus::Ok) {
    CoUninitialize();
    return 1;
  }

  const wchar_t *className = L"AntiMalAppWindow";
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = instance;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  wc.lpszClassName = className;
  wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
  wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
  RegisterClassExW(&wc);

  HWND hwnd = CreateWindowExW(0, className, L"AntiMal - Scanner and VM Analysis",
                              WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT,
                              CW_USEDEFAULT, 1280, 760, nullptr, nullptr, instance, nullptr);
  if (!hwnd) {
    if (gdiToken) {
      Gdiplus::GdiplusShutdown(gdiToken);
    }
    CoUninitialize();
    return 1;
  }
  ApplyDarkTitleBar(hwnd);
  ShowWindow(hwnd, show);
  UpdateWindow(hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  g_app.vmFrame.reset();
  if (gdiToken) {
    Gdiplus::GdiplusShutdown(gdiToken);
  }
  CoUninitialize();
  return static_cast<int>(msg.wParam);
}
