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

  // Posted to the UI thread (via PostMessage) carrying a heap std::string* whose
  // contents are forwarded to the page with PostWebMessageAsJson. This is the
  // ONLY safe way to push a C++->JS event from a worker thread.
  static constexpr UINT kEmitMessage = WM_APP + 1;

  // Build a {"evt":...,"data":...} envelope and marshal it to the UI thread for
  // delivery to the page. Safe to call from any thread: `hwnd` is a value (a
  // stale handle posts nowhere rather than dereferencing freed state). `evt` is
  // quoted; `dataJson` must already be a valid JSON value (object/array/string).
  static void Emit(HWND hwnd, const std::string &evt,
                   const std::string &dataJson);

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
