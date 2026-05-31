#pragma once

// Thin Win32 shell hosting a single, hardened WebView2 control that renders the
// local web UI (webui/, served from https://antimal.local/). The only C++<->JS
// seam is a BridgeRouter. See
// historical design notes (not distributed) (P1).

#include <windows.h>
#include <wrl.h>

#include "WebView2.h"

#include "antimal/BridgeRouter.h"

namespace antimal {

class WebViewHost {
public:
  int Run(HINSTANCE hInstance, int nCmdShow);

private:
  static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
  void OnSize();
  HRESULT OnControllerCreated(HRESULT result,
                              ICoreWebView2Controller *controller);
  void RegisterHandlers();
  void HandleWebMessage(ICoreWebView2 *sender, const std::string &json);

  HWND hwnd_ = nullptr;
  Microsoft::WRL::ComPtr<ICoreWebView2Controller> controller_;
  Microsoft::WRL::ComPtr<ICoreWebView2> webview_;
  BridgeRouter router_;
};

} // namespace antimal
