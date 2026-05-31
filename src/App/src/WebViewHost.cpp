#include "WebViewHost.h"

#include <dwmapi.h>

#include <cstdlib>
#include <string>

#include "antimal/JsonValue.h"

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
