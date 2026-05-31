#include "WebViewHost.h"

#include <dwmapi.h>
#include <shellapi.h> // ShellExecuteW (open run folder in Explorer)
#include <shobjidl.h> // IFileOpenDialog / IShellItem (native file/folder picker)

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "antimal/BrowserImpact.h"
#include "antimal/Config.h"
#include "antimal/EventJournal.h"
#include "antimal/FileUtil.h"
#include "antimal/Json.h"
#include "antimal/JsonValue.h"
#include "antimal/Report.h"
#include "antimal/Scanner.h"

// CLSID_FileOpenDialog lives in uuid.lib; CoCreateInstance/CoInitializeEx in
// ole32.lib. Both are MSVC default libs, but pin them so the native picker
// links regardless of how a consumer overrides AdditionalDependencies.
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

namespace antimal {

namespace {

std::wstring Widen(const std::string &s) {
  if (s.empty()) {
    return std::wstring();
  }
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                    static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(),
                      n);
  return w;
}

std::string Narrow(const wchar_t *w) {
  if (!w) {
    return std::string();
  }
  const int n =
      WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (n <= 1) {
    return std::string();
  }
  std::string s(static_cast<size_t>(n - 1), '\0'); // n counts the null
  WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring ExeDir() {
  wchar_t buf[MAX_PATH];
  const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
  std::wstring p(buf, n);
  const auto slash = p.find_last_of(L"\\/");
  return slash == std::wstring::npos ? std::wstring(L".") : p.substr(0, slash);
}

std::wstring UserDataDir() {
  wchar_t *base = nullptr;
  size_t len = 0;
  std::wstring dir = ExeDir(); // fallback
  if (_wdupenv_s(&base, &len, L"LOCALAPPDATA") == 0 && base) {
    dir = std::wstring(base) + L"\\AntiMal\\WebView2";
    free(base);
  }
  return dir;
}

// Native file/folder picker (Common Item Dialog). Returns the chosen filesystem
// path, or empty on cancel/error. Must run on the UI (STA) thread.
std::wstring PickPath(HWND owner, bool pickFolder) {
  // Automation/headless hook: ANTIMAL_SCAN_PATH bypasses the interactive picker
  // (scripted scans, tests, CI). When unset, the normal dialog shows.
  {
    wchar_t *over = nullptr;
    size_t len = 0;
    if (_wdupenv_s(&over, &len, L"ANTIMAL_SCAN_PATH") == 0 && over) {
      std::wstring p(over);
      free(over);
      if (!p.empty()) {
        return p;
      }
    }
  }
  ComPtr<IFileOpenDialog> dlg;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                              CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) {
    return std::wstring();
  }
  if (pickFolder) {
    FILEOPENDIALOGOPTIONS opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS);
  }
  if (FAILED(dlg->Show(owner))) {
    return std::wstring(); // user cancelled
  }
  ComPtr<IShellItem> item;
  if (FAILED(dlg->GetResult(&item))) {
    return std::wstring();
  }
  PWSTR raw = nullptr;
  if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &raw)) || !raw) {
    return std::wstring();
  }
  std::wstring result(raw);
  CoTaskMemFree(raw);
  return result;
}

// Newest run dir (by report.json mtime) under workspaceRoot that holds a
// report.json. Returns empty paths when none exist. Skips _-prefixed dirs
// (_base, _intel_cache). Shared by dashboard.get + browser.get.
struct NewestRun {
  std::filesystem::path dir;
  std::filesystem::path json;
};
NewestRun FindNewestRun(const std::filesystem::path &workspaceRoot) {
  namespace fs = std::filesystem;
  NewestRun best;
  unsigned long long bestMtime = 0;
  std::error_code ec;
  if (fs::is_directory(workspaceRoot, ec)) {
    for (const auto &e : fs::directory_iterator(workspaceRoot, ec)) {
      if (!e.is_directory(ec)) {
        continue;
      }
      const fs::path dir = e.path();
      const std::wstring name = dir.filename().wstring();
      if (name.empty() || name[0] == L'_') {
        continue;
      }
      const fs::path json = dir / L"report.json";
      WIN32_FILE_ATTRIBUTE_DATA fad{};
      if (!GetFileAttributesExW(json.c_str(), GetFileExInfoStandard, &fad)) {
        continue;
      }
      ULARGE_INTEGER t{};
      t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
      t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
      if (t.QuadPart >= bestMtime) {
        bestMtime = t.QuadPart;
        best.dir = dir;
        best.json = json;
      }
    }
  }
  return best;
}

// Local-time "YYYY-MM-DD HH:MM" of a file's last-write time; empty on error.
std::string FormatFileTime(const std::filesystem::path &p) {
  WIN32_FILE_ATTRIBUTE_DATA fad{};
  if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) {
    return std::string();
  }
  SYSTEMTIME utc{}, local{};
  if (!FileTimeToSystemTime(&fad.ftLastWriteTime, &utc) ||
      !SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local)) {
    return std::string();
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d", local.wYear,
                local.wMonth, local.wDay, local.wHour, local.wMinute);
  return std::string(buf);
}

} // namespace

LRESULT CALLBACK WebViewHost::WndProc(HWND hwnd, UINT msg, WPARAM wParam,
                                      LPARAM lParam) {
  if (msg == WM_NCCREATE) {
    auto *cs = reinterpret_cast<CREATESTRUCTW *>(lParam);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                      reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
  }
  auto *self =
      reinterpret_cast<WebViewHost *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  switch (msg) {
  case WM_SIZE:
    if (self) {
      self->OnSize();
    }
    return 0;
  case kEmitMessage: {
    // A worker thread handed us a heap JSON envelope; forward it to the page.
    auto *payload = reinterpret_cast<std::string *>(lParam);
    if (self && self->webview_ && payload) {
      self->webview_->PostWebMessageAsJson(Widen(*payload).c_str());
    }
    delete payload;
    return 0;
  }
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  default:
    return DefWindowProcW(hwnd, msg, wParam, lParam);
  }
}

void WebViewHost::OnSize() {
  if (controller_) {
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    controller_->put_Bounds(rc);
  }
}

void WebViewHost::HandleWebMessage(ICoreWebView2 *sender,
                                   const std::string &json) {
  const std::string reply = router_.Handle(json);
  if (sender) {
    sender->PostWebMessageAsJson(Widen(reply).c_str());
  }
}

void WebViewHost::Emit(HWND hwnd, const std::string &evt,
                       const std::string &dataJson) {
  if (!hwnd) {
    return;
  }
  std::string envelope =
      "{\"evt\":" + JsonQuote(evt) + ",\"data\":" + dataJson + "}";
  PostMessageW(hwnd, kEmitMessage, 0,
               reinterpret_cast<LPARAM>(new std::string(std::move(envelope))));
}

HRESULT WebViewHost::OnControllerCreated(HRESULT result,
                                         ICoreWebView2Controller *controller) {
  if (FAILED(result) || !controller) {
    return result;
  }
  controller_ = controller;
  controller_->get_CoreWebView2(&webview_);
  OnSize();
  controller_->put_IsVisible(TRUE);

  ComPtr<ICoreWebView2Settings> settings;
  if (SUCCEEDED(webview_->get_Settings(&settings))) {
    settings->put_IsWebMessageEnabled(TRUE);
#ifdef NDEBUG
    settings->put_AreDevToolsEnabled(FALSE);
#endif
    settings->put_AreDefaultContextMenusEnabled(FALSE);
    settings->put_IsStatusBarEnabled(FALSE);
    settings->put_AreHostObjectsAllowed(FALSE);
    settings->put_IsZoomControlEnabled(FALSE);
  }

  // Serve webui/ from a virtual https origin so CSP/origin are clean and there
  // is no remote/file:// content.
  ComPtr<ICoreWebView2_3> wv3;
  if (SUCCEEDED(webview_.As(&wv3))) {
    const std::wstring webui = ExeDir() + L"\\webui";
    wv3->SetVirtualHostNameToFolderMapping(
        L"antimal.local", webui.c_str(),
        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS);
    // Read-only map of the workspace so the UI can render run screenshots at
    // https://runs.antimal.local/<run>/screenshots/<frame>.png. DENY_CORS +
    // sub-resource only; NavigationStarting still locks top-level nav to
    // antimal.local, and the page CSP whitelists this origin for img-src only.
    const std::wstring runs =
        LoadConfig(DefaultConfigPath()).workspaceRoot.wstring();
    if (!runs.empty()) {
      wv3->SetVirtualHostNameToFolderMapping(
          L"runs.antimal.local", runs.c_str(),
          COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS);
    }
  }

  RegisterHandlers();
  webview_->Navigate(L"https://antimal.local/index.html");
  return S_OK;
}

void WebViewHost::RegisterHandlers() {
  EventRegistrationToken token{};

  // JS -> C++ commands.
  webview_->add_WebMessageReceived(
      Callback<ICoreWebView2WebMessageReceivedEventHandler>(
          [this](ICoreWebView2 *sender,
                 ICoreWebView2WebMessageReceivedEventArgs *args) -> HRESULT {
            LPWSTR json = nullptr;
            if (SUCCEEDED(args->get_WebMessageAsJson(&json)) && json) {
              const std::string msg = Narrow(json);
              CoTaskMemFree(json);
              HandleWebMessage(sender, msg);
            }
            return S_OK;
          })
          .Get(),
      &token);

  // Lock navigation to our virtual host.
  webview_->add_NavigationStarting(
      Callback<ICoreWebView2NavigationStartingEventHandler>(
          [](ICoreWebView2 *,
             ICoreWebView2NavigationStartingEventArgs *args) -> HRESULT {
            LPWSTR uri = nullptr;
            if (SUCCEEDED(args->get_Uri(&uri)) && uri) {
              const std::wstring u(uri);
              CoTaskMemFree(uri);
              if (u.rfind(L"https://antimal.local/", 0) != 0) {
                args->put_Cancel(TRUE);
              }
            }
            return S_OK;
          })
          .Get(),
      &token);

  // Deny popups / new windows.
  webview_->add_NewWindowRequested(
      Callback<ICoreWebView2NewWindowRequestedEventHandler>(
          [](ICoreWebView2 *,
             ICoreWebView2NewWindowRequestedEventArgs *args) -> HRESULT {
            args->put_Handled(TRUE);
            return S_OK;
          })
          .Get(),
      &token);

  // After the page loads (and its listener is registered), prove the C++->JS
  // event path with a log line.
  webview_->add_NavigationCompleted(
      Callback<ICoreWebView2NavigationCompletedEventHandler>(
          [](ICoreWebView2 *sender,
             ICoreWebView2NavigationCompletedEventArgs *) -> HRESULT {
            sender->PostWebMessageAsJson(
                LR"({"evt":"log","data":{"level":"INFO","msg":"AntiMal host bridge online"}})");
            return S_OK;
          })
          .Get(),
      &token);

  // P1 bridge command.
  router_.Register("ping", [](const JsonValue &) {
    return std::string(R"({"version":"P1","ok":true})");
  });

  // P3: real config (read-only). The VirtualTotal API key is never exposed --
  // only whether one is set.
  router_.Register("config.get", [](const JsonValue &) -> std::string {
    const AppConfig c = LoadConfig(DefaultConfigPath());
    auto b = [](bool v) { return std::string(v ? "true" : "false"); };
    std::string j = "{";
    j += "\"baseVhdxPath\":" + JsonQuote(Narrow(c.baseVhdxPath.wstring().c_str())) + ",";
    j += "\"workspaceRoot\":" + JsonQuote(Narrow(c.workspaceRoot.wstring().c_str())) + ",";
    j += "\"vmProvider\":" + JsonQuote(c.vmProvider) + ",";
    j += "\"networkMode\":" + JsonQuote(ToString(c.networkMode)) + ",";
    j += "\"baseDiskFormat\":" + JsonQuote(c.baseDiskFormat) + ",";
    j += "\"defaultTimeoutSec\":" + std::to_string(c.defaultTimeoutSec) + ",";
    j += "\"screenshotIntervalMs\":" + std::to_string(c.screenshotIntervalMs) + ",";
    j += "\"enrichYara\":" + b(c.enrichYara) + ",";
    j += "\"enrichCapa\":" + b(c.enrichCapa) + ",";
    j += "\"enrichDie\":" + b(c.enrichDie) + ",";
    j += "\"enrichTagger\":" + b(c.enrichTagger) + ",";
    j += "\"intelEnabled\":" + b(c.intelEnabled) + ",";
    j += "\"intelMalwareBazaar\":" + b(c.intelMalwareBazaar) + ",";
    j += "\"virusTotalKeySet\":" + b(!c.virusTotalApiKey.empty()) + ",";
    std::error_code ec;
    const bool baseExists =
        std::filesystem::exists(c.baseVhdxPath, ec) &&
        std::filesystem::is_regular_file(c.baseVhdxPath, ec);
    unsigned long long baseSize = 0;
    if (baseExists) {
      baseSize = static_cast<unsigned long long>(
          std::filesystem::file_size(c.baseVhdxPath, ec));
    }
    j += "\"baseExists\":" + b(baseExists) + ",";
    j += "\"baseSizeBytes\":" + std::to_string(baseSize) + ",";
    j += "\"dynamicExecutionEnabled\":" + b(c.dynamicExecutionEnabled);
    j += "}";
    return j;
  });

  // P3: static scan. The native picker runs on this (UI/STA) thread; the scan
  // itself runs on a detached worker that streams scan.result + scan.progress
  // events back via Emit() (a stale HWND posts nowhere, so worker outliving the
  // window is safe). Enrichment uses offline defaults -- YARA/capa/DIE are
  // auto-skipped when their binaries are absent, so this never blocks on tools.
  auto runScan = [this](bool pickFolder) -> std::string {
    const std::wstring path = PickPath(hwnd_, pickFolder);
    if (path.empty()) {
      return std::string(R"({"cancelled":true})");
    }
    const HWND h = hwnd_;
    const bool isFolder = pickFolder;
    std::thread([h, path, isFolder]() {
      CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      WebViewHost::Emit(h, "scan.progress", R"({"stage":"start","pct":5})");
      ScannerOptions opts;
      if (isFolder) {
        const std::vector<ScanResult> results = ScanPath(path, opts);
        for (const auto &r : results) {
          WebViewHost::Emit(h, "scan.result", ToJson(r));
        }
        WebViewHost::Emit(
            h, "scan.progress",
            std::string("{\"stage\":\"done\",\"pct\":100,\"count\":") +
                std::to_string(results.size()) + "}");
      } else {
        const ScanResult r = ScanFile(path, opts);
        WebViewHost::Emit(h, "scan.result", ToJson(r));
        WebViewHost::Emit(h, "scan.progress",
                          R"({"stage":"done","pct":100,"count":1})");
      }
      CoUninitialize();
    }).detach();
    return std::string(R"({"started":true})");
  };

  router_.Register("scan.file",
                   [runScan](const JsonValue &) { return runScan(false); });
  router_.Register("scan.folder",
                   [runScan](const JsonValue &) { return runScan(true); });
  // "Scan Computer" sweeps a chosen root recursively (same engine as folder).
  router_.Register("scan.computer",
                   [runScan](const JsonValue &) { return runScan(true); });

  // P3: reports list. Enumerates run dirs under workspace_root that hold a
  // report.json, sorts by mtime, and surfaces the most recent kMax (a workspace
  // can hold hundreds of runs, and each parse is non-trivial). Runs on a worker
  // and returns the rows via a reports.data event so the UI never blocks.
  router_.Register("reports.list", [this](const JsonValue &) -> std::string {
    const HWND h = hwnd_;
    std::thread([h]() {
      CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      namespace fs = std::filesystem;
      const AppConfig c = LoadConfig(DefaultConfigPath());
      struct Entry {
        fs::path dir;
        fs::path json;
        unsigned long long mtime;
      };
      std::vector<Entry> entries;
      std::error_code ec;
      if (fs::is_directory(c.workspaceRoot, ec)) {
        for (const auto &e : fs::directory_iterator(c.workspaceRoot, ec)) {
          if (!e.is_directory(ec)) {
            continue;
          }
          const fs::path dir = e.path();
          const std::wstring name = dir.filename().wstring();
          if (name.empty() || name[0] == L'_') {
            continue; // skip _base, _intel_cache, etc.
          }
          const fs::path json = dir / L"report.json";
          WIN32_FILE_ATTRIBUTE_DATA fad{};
          if (!GetFileAttributesExW(json.c_str(), GetFileExInfoStandard,
                                    &fad)) {
            continue;
          }
          ULARGE_INTEGER t{};
          t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
          t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
          entries.push_back({dir, json, t.QuadPart});
        }
      }
      std::sort(entries.begin(), entries.end(),
                [](const Entry &a, const Entry &b) { return a.mtime > b.mtime; });
      const size_t totalFound = entries.size();
      const size_t kMax = 100;
      if (entries.size() > kMax) {
        entries.resize(kMax);
      }
      std::string arr = "[";
      for (size_t i = 0; i < entries.size(); ++i) {
        const AnalysisReport r = LoadReportBestEffort(entries[i].json);
        const bool hasHtml = fs::exists(entries[i].dir / L"report.html", ec);
        JsonObjectBuilder o;
        o.AddString("id", r.runId.empty()
                              ? Narrow(entries[i].dir.filename().wstring().c_str())
                              : r.runId);
        o.AddString("file", Narrow(r.samplePath.filename().wstring().c_str()));
        o.AddNumber("score", r.scannerVerdict.score);
        o.AddString("verdict", ToString(r.scannerVerdict.verdict));
        o.AddString("created", FormatFileTime(entries[i].json));
        o.AddString("type", hasHtml ? "HTML+JSON" : "JSON");
        o.AddString("runDir", Narrow(entries[i].dir.wstring().c_str()));
        if (i) {
          arr += ",";
        }
        arr += o.Finish();
      }
      arr += "]";
      WebViewHost::Emit(h, "reports.data",
                        std::string("{\"reports\":") + arr +
                            ",\"total\":" + std::to_string(totalFound) +
                            ",\"shown\":" + std::to_string(entries.size()) +
                            "}");
      CoUninitialize();
    }).detach();
    return std::string(R"({"loading":true})");
  });

  // P3: open a run folder in Explorer. The path MUST resolve under
  // workspace_root (defense against the page opening arbitrary locations --
  // see the live-sandbox-console security model). Throws on rejection so the
  // router reports ok:false to the caller.
  router_.Register("run.open", [](const JsonValue &args) -> std::string {
    namespace fs = std::filesystem;
    const std::string wanted = args.At("runDir").AsString();
    if (wanted.empty()) {
      throw std::runtime_error("missing runDir");
    }
    const AppConfig c = LoadConfig(DefaultConfigPath());
    std::error_code ec;
    const fs::path root = fs::weakly_canonical(c.workspaceRoot, ec);
    const fs::path target = fs::weakly_canonical(fs::path(Widen(wanted)), ec);
    const fs::path rel = fs::relative(target, root, ec);
    const bool inside =
        !ec && !rel.empty() && rel.native().rfind(L"..", 0) != 0;
    if (!inside || !fs::is_directory(target, ec)) {
      throw std::runtime_error("path not under workspace");
    }
    ShellExecuteW(nullptr, L"open", target.c_str(), nullptr, nullptr,
                  SW_SHOWNORMAL);
    return std::string(R"({"opened":true})");
  });

  // P4: dashboard summary. Finds the newest run dir with a report.json, reads
  // it, lists its screenshot frames, and emits dashboard.data with the
  // latest-run preview, telemetry metrics, the event feed, and frame URLs
  // (served read-only via runs.antimal.local). Worker thread -> never blocks.
  router_.Register("dashboard.get", [this](const JsonValue &) -> std::string {
    const HWND h = hwnd_;
    std::thread([h]() {
      CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      namespace fs = std::filesystem;
      const AppConfig c = LoadConfig(DefaultConfigPath());
      std::error_code ec;
      const NewestRun nr = FindNewestRun(c.workspaceRoot);
      if (nr.json.empty()) {
        WebViewHost::Emit(h, "dashboard.data", R"({"hasRun":false})");
        CoUninitialize();
        return;
      }
      const fs::path bestDir = nr.dir;
      const fs::path bestJson = nr.json;
      const AnalysisReport r = LoadReportBestEffort(bestJson);
      const std::string dirName = Narrow(bestDir.filename().wstring().c_str());

      // Frames: prefer guest-*.png (real VM framebuffer) over diagnostics.
      std::vector<std::wstring> guest, other;
      const fs::path shots = bestDir / L"screenshots";
      if (fs::is_directory(shots, ec)) {
        for (const auto &f : fs::directory_iterator(shots, ec)) {
          if (!f.is_regular_file(ec)) {
            continue;
          }
          const std::wstring ext = f.path().extension().wstring();
          if (ext != L".png" && ext != L".PNG") {
            continue;
          }
          const std::wstring fn = f.path().filename().wstring();
          if (fn.rfind(L"guest-", 0) == 0) {
            guest.push_back(fn);
          } else {
            other.push_back(fn);
          }
        }
      }
      std::sort(guest.begin(), guest.end());
      std::sort(other.begin(), other.end());
      const std::vector<std::wstring> &frames = !guest.empty() ? guest : other;
      auto frameUrl = [&](const std::wstring &fn) {
        return std::string("https://runs.antimal.local/") + dirName +
               "/screenshots/" + Narrow(fn.c_str());
      };
      std::string framesArr = "[";
      const size_t fstart = frames.size() > 16 ? frames.size() - 16 : 0;
      for (size_t i = fstart; i < frames.size(); ++i) {
        if (i > fstart) {
          framesArr += ",";
        }
        framesArr += JsonQuote(frameUrl(frames[i]));
      }
      framesArr += "]";
      const std::string latestFrame =
          frames.empty() ? std::string() : frameUrl(frames.back());

      // Event feed: most recent 60 events.
      std::string evArr = "[";
      const size_t estart = r.events.size() > 60 ? r.events.size() - 60 : 0;
      for (size_t i = estart; i < r.events.size(); ++i) {
        const EventRecord &ev = r.events[i];
        if (i > estart) {
          evArr += ",";
        }
        JsonObjectBuilder eo;
        eo.AddString("time", ev.timestampUtc);
        eo.AddString("source", ev.source);
        eo.AddString("category", ev.category);
        eo.AddString("action", ev.action);
        eo.AddNumber("pid", ev.processId);
        eo.AddString("image", ev.imagePath);
        eo.AddString("target", ev.target);
        eo.AddString("mitre", ev.mitre);
        evArr += eo.Finish();
      }
      evArr += "]";

      JsonObjectBuilder lr;
      lr.AddString("runId", r.runId.empty() ? dirName : r.runId);
      lr.AddString("file", Narrow(r.samplePath.filename().wstring().c_str()));
      lr.AddString("verdict", ToString(r.sandboxVerdict));
      lr.AddNumber("score", r.scannerVerdict.score);
      lr.AddString("scannerVerdict", ToString(r.scannerVerdict.verdict));
      lr.AddString("when", FormatFileTime(bestJson));
      lr.AddString("runDir", Narrow(bestDir.wstring().c_str()));
      lr.AddString("frame", latestFrame);

      JsonObjectBuilder met;
      met.AddNumber("events", static_cast<int64_t>(r.events.size()));
      met.AddNumber("frames", static_cast<int64_t>(frames.size()));
      met.AddNumber("domains", static_cast<int64_t>(r.networkDomains.size()));
      met.AddNumber("artifacts", static_cast<int64_t>(r.artifacts.size()));
      met.AddNumber("mitre", static_cast<int64_t>(r.mitreTechniques.size()));
      met.AddNumber("errors", static_cast<int64_t>(r.errors.size()));

      const std::string payload =
          "{\"hasRun\":true,\"latestRun\":" + lr.Finish() +
          ",\"metrics\":" + met.Finish() + ",\"frames\":" + framesArr +
          ",\"events\":" + evArr + "}";
      WebViewHost::Emit(h, "dashboard.data", payload);
      CoUninitialize();
    }).detach();
    return std::string(R"({"loading":true})");
  });

  // P7: browser-impact triage over the latest run's contacted domains.
  // Decryption is OFF -- decrypting saved browser secrets is a deliberate,
  // separately-gated action, never auto-run from the UI. Worker -> browser.data.
  router_.Register("browser.get", [this](const JsonValue &) -> std::string {
    const HWND h = hwnd_;
    std::thread([h]() {
      CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      const AppConfig c = LoadConfig(DefaultConfigPath());
      const NewestRun nr = FindNewestRun(c.workspaceRoot);
      std::vector<std::string> domains;
      std::string runId;
      if (!nr.json.empty()) {
        const AnalysisReport r = LoadReportBestEffort(nr.json);
        domains = r.networkDomains;
        runId = r.runId.empty() ? Narrow(nr.dir.filename().wstring().c_str())
                                : r.runId;
      }
      const std::vector<BrowserRisk> risks =
          AnalyzeBrowserImpact(domains, /*decryptBrowserSecrets=*/false);
      std::string arr = "[";
      for (size_t i = 0; i < risks.size(); ++i) {
        if (i) {
          arr += ",";
        }
        JsonObjectBuilder o;
        o.AddString("site", risks[i].site);
        o.AddString("domain", risks[i].domain);
        o.AddBool("contactedBySample", risks[i].contactedBySample);
        o.AddBool("savedCredentials", risks[i].savedCredentials);
        o.AddBool("cookiesPresent", risks[i].cookiesPresent);
        o.AddString("recommendation", risks[i].recommendation);
        arr += o.Finish();
      }
      arr += "]";
      WebViewHost::Emit(h, "browser.data",
                        std::string("{\"risks\":") + arr +
                            ",\"domains\":" + std::to_string(domains.size()) +
                            ",\"runId\":" + JsonQuote(runId) + "}");
      CoUninitialize();
    }).detach();
    return std::string(R"({"loading":true})");
  });

  // P5 (host->UI half of the live telemetry channel): tail a run's events.jsonl
  // with EventJournalTailer and stream each new EventRecord to the page as a
  // paced `telemetry` event, with run.status bookends. This is the exact path a
  // live detonation will drive once the GuestAgent streams from inside the VM;
  // here it also replays a completed run's journal. Worker thread; stops after
  // a stretch of no growth (completed run) or a safety cap.
  router_.Register("run.watch", [this](const JsonValue &args) -> std::string {
    const HWND h = hwnd_;
    const std::string argDir = args.At("runDir").AsString();
    std::thread([h, argDir]() {
      CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      namespace fs = std::filesystem;
      const AppConfig c = LoadConfig(DefaultConfigPath());
      fs::path runDir = argDir.empty() ? FindNewestRun(c.workspaceRoot).dir
                                       : fs::path(Widen(argDir));
      // Same workspace-confinement guard as run.open: never tail a journal
      // outside workspace_root, even if the page asks for an arbitrary path.
      std::error_code ec;
      const fs::path root = fs::weakly_canonical(c.workspaceRoot, ec);
      const fs::path target =
          runDir.empty() ? fs::path() : fs::weakly_canonical(runDir, ec);
      const fs::path rel =
          target.empty() ? fs::path() : fs::relative(target, root, ec);
      const bool inside = !target.empty() && !ec && !rel.empty() &&
                          rel.native().rfind(L"..", 0) != 0;
      if (!inside) {
        WebViewHost::Emit(h, "run.status", R"({"state":"no-run"})");
        CoUninitialize();
        return;
      }
      runDir = target;
      const fs::path journal = runDir / L"events.jsonl";
      EventJournalTailer tailer(journal);
      WebViewHost::Emit(
          h, "run.status",
          std::string("{\"state\":\"watching\",\"journal\":") +
              JsonQuote(Narrow(journal.wstring().c_str())) + "}");
      int empties = 0, streamed = 0;
      const int kMaxEmpties = 8;   // ~2s of no growth on a completed run -> stop
      const int kMaxEvents = 5000; // safety cap
      while (empties < kMaxEmpties && streamed < kMaxEvents) {
        const std::vector<EventRecord> evs = tailer.PullNew();
        if (evs.empty()) {
          ++empties;
          std::this_thread::sleep_for(std::chrono::milliseconds(250));
          continue;
        }
        empties = 0;
        for (const EventRecord &ev : evs) {
          JsonObjectBuilder eo;
          eo.AddString("time", ev.timestampUtc);
          eo.AddString("source", ev.source);
          eo.AddString("category", ev.category);
          eo.AddString("action", ev.action);
          eo.AddNumber("pid", ev.processId);
          eo.AddString("image", ev.imagePath);
          eo.AddString("target", ev.target);
          eo.AddString("mitre", ev.mitre);
          WebViewHost::Emit(h, "telemetry", eo.Finish());
          if (++streamed >= kMaxEvents) {
            break;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(140));
        }
      }
      WebViewHost::Emit(h, "run.status",
                        std::string("{\"state\":\"done\",\"streamed\":") +
                            std::to_string(streamed) + "}");
      CoUninitialize();
    }).detach();
    return std::string(R"({"watching":true})");
  });
}

int WebViewHost::Run(HINSTANCE hInstance, int nCmdShow) {
  const HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = L"AntiMalWebViewHost";
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
  RegisterClassExW(&wc);

  hwnd_ = CreateWindowExW(0, wc.lpszClassName,
                          L"AntiMal - Scanner and VM Analysis",
                          WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280,
                          820, nullptr, nullptr, hInstance, this);
  if (!hwnd_) {
    return 1;
  }
  BOOL dark = TRUE;
  DwmSetWindowAttribute(hwnd_, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark,
                        sizeof(dark));
  ShowWindow(hwnd_, nCmdShow);
  UpdateWindow(hwnd_);

  const std::wstring userData = UserDataDir();
  const HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
      nullptr, userData.c_str(), nullptr,
      Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
          [this](HRESULT envResult,
                 ICoreWebView2Environment *env) -> HRESULT {
            if (FAILED(envResult) || !env) {
              return envResult;
            }
            return env->CreateCoreWebView2Controller(
                hwnd_,
                Callback<
                    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                    [this](HRESULT ctrlResult,
                           ICoreWebView2Controller *ctrl) -> HRESULT {
                      return OnControllerCreated(ctrlResult, ctrl);
                    })
                    .Get());
          })
          .Get());
  if (FAILED(hr)) {
    MessageBoxW(hwnd_,
                L"WebView2 runtime not available. Install the Microsoft Edge "
                L"WebView2 Runtime and relaunch.",
                L"AntiMal", MB_ICONERROR | MB_OK);
    return 2;
  }

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  if (SUCCEEDED(hrCo)) {
    CoUninitialize();
  }
  return static_cast<int>(msg.wParam);
}

} // namespace antimal
