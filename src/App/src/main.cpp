// AntiMal.exe entry point. The UI is the WebView2-hosted web app (webui/),
// driven through the C++<->JS bridge. See WebViewHost + the live-sandbox-console
// historical console design. The previous hand-rolled Win32 GUI lives in
// git history (its scan/detonate command wiring is ported onto the bridge in P3).

#include <windows.h>

#include <dbghelp.h>
#include <stdio.h>

#include "WebViewHost.h"

#pragma comment(lib, "dbghelp.lib")

namespace {

// Last-resort crash diagnostics: on an otherwise-silent unhandled exception,
// write a minidump to %LOCALAPPDATA%\AntiMal so a crash leaves a trail instead of
// the window just vanishing. Crash-handler-safe: stack buffers only, no heap
// allocation (the heap may be corrupt when this runs).
LONG WINAPI WriteCrashDump(EXCEPTION_POINTERS *ep) {
  wchar_t base[MAX_PATH] = {};
  const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return EXCEPTION_CONTINUE_SEARCH; // let WER take it
  }
  wchar_t dir[MAX_PATH] = {};
  _snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%s\\AntiMal", base);
  CreateDirectoryW(dir, nullptr); // best effort
  wchar_t path[MAX_PATH] = {};
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\crash-%lu.dmp", dir,
               GetCurrentProcessId());
  HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (f != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f,
                      MiniDumpNormal, &mei, nullptr, nullptr);
    CloseHandle(f);
    MessageBoxW(nullptr,
                L"AntiMal hit an unexpected error and must close.\n"
                L"A diagnostic dump was saved under %LOCALAPPDATA%\\AntiMal.",
                L"AntiMal", MB_ICONERROR | MB_OK);
  }
  return EXCEPTION_EXECUTE_HANDLER; // terminate after dumping
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
                    PWSTR /*pCmdLine*/, int nCmdShow) {
  SetUnhandledExceptionFilter(WriteCrashDump);
  antimal::WebViewHost host;
  return host.Run(hInstance, nCmdShow);
}
