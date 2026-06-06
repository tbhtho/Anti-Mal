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

  // Live-VM process liveness. We RETAIN the process handle (not just the PID) so
  // termination and the "is a VM running?" check can never act on a recycled PID
  // -- and so vm.frame only reports a live framebuffer while the VM is actually
  // running (otherwise a leftover run dir's last screenshot looks "live").
  bool VmAlive() const;     // true iff the spawned VM process is still running
  void StopVmProcess();     // terminate (if running) + close handle + clear PID
  // Drive the host window borderless-fullscreen when the page requests it (the
  // VM "Fullscreen" button -> JS requestFullscreen -> WebView2 fullscreen event).
  // Without this, requestFullscreen only fills the WebView control, not the
  // monitor.
  void SetHostFullscreen(bool on);

  // Live framebuffer pump: maps the VM's shared-memory framebuffer section
  // read-only and, on a UI-thread timer, swizzles each new frame (BGRX->RGBA)
  // into a WebView2 SharedBuffer and signals the page to blit it to a <canvas>.
  // This is the production "real VM display" path (no PNG encode / disk).
  static constexpr UINT_PTR kFrameTimerId = 0xA11F;
  void StartFramePump();    // begin the ~60Hz UI timer (called on VM boot)
  void StopFramePump();     // stop the timer + release the shm mapping
  void PumpLiveFrame();     // one timer tick: publish the newest frame, if any

  HWND hwnd_ = nullptr;
  bool isFullscreen_ = false;
  WINDOWPLACEMENT savedPlacement_{sizeof(WINDOWPLACEMENT)};
  LONG_PTR savedStyle_ = 0;
  Microsoft::WRL::ComPtr<ICoreWebView2Controller> controller_;
  Microsoft::WRL::ComPtr<ICoreWebView2> webview_;
  Microsoft::WRL::ComPtr<ICoreWebView2Environment> env_; // for CreateSharedBuffer
  Microsoft::WRL::ComPtr<ICoreWebView2SharedBuffer> frameBuffer_; // page-shared
  BridgeRouter router_;
  unsigned long vmPid_ = 0;   // PID of the spawned live-VM HostCli process (P1).
  void *vmProcess_ = nullptr; // HANDLE to that process while it runs (owned).
  void *frameShmHandle_ = nullptr;        // OpenFileMapping handle (live frame)
  const unsigned char *frameShmView_ = nullptr; // read-only mapped view
  unsigned long long lastFrameSeq_ = 0;   // last frame sequence pushed to page
  bool frameBufferPosted_ = false;        // SharedBuffer handed to the page yet
  bool frameTimerActive_ = false;
};

} // namespace antimal
