// AntiMal.exe entry point. The UI is the WebView2-hosted web app (webui/),
// driven through the C++<->JS bridge. See WebViewHost + the live-sandbox-console
// historical console design. The previous hand-rolled Win32 GUI lives in
// git history (its scan/detonate command wiring is ported onto the bridge in P3).

#include <windows.h>

#include "WebViewHost.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
                    PWSTR /*pCmdLine*/, int nCmdShow) {
  antimal::WebViewHost host;
  return host.Run(hInstance, nCmdShow);
}
