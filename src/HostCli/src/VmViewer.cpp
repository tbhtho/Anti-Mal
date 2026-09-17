// VmViewer.cpp - a plain Win32 window that mirrors the VMM's live guest
// framebuffer, so an operator (or a screen recording) can WATCH the VM while a
// detonation runs. It attaches read-only to the same named shared-memory section
// the VM publishes to (see antimal/hv/LiveFrameShm.h for the wire contract:
// 64-byte header + BGRX pixels, seqlock-torn-free).
//
// The VM publishes when ANTIMAL_LIVE_FRAME_SHM=<name> is set for the run; start
// this viewer with the same --name before/while the run executes. The window
// shows "waiting for VM frames" until the mapping appears, then blits at ~30 Hz.
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct ShmHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t width;
  uint32_t height;
  uint32_t bpp;
  uint32_t format; // 0 = BGRX
  uint32_t byteLength;
  uint32_t reserved;
  volatile uint64_t frameSeq;
};

constexpr size_t kHeaderBytes = 64;
constexpr uint32_t kMagic = 0x414D4C46u; // 'AMLF'

HWND g_wnd = nullptr;
HANDLE g_map = nullptr;
uint8_t *g_view = nullptr;
std::wstring g_shmName;
std::vector<uint8_t> g_pixels;
uint32_t g_w = 0;
uint32_t g_h = 0;
uint64_t g_lastSeq = 0;
std::string g_status = "waiting for VM frames...";

bool EnsureMapped() {
  if (g_view) {
    return true;
  }
  if (!g_map) {
    g_map = OpenFileMappingW(FILE_MAP_READ, FALSE, g_shmName.c_str());
    if (!g_map) {
      return false;
    }
  }
  g_view = static_cast<uint8_t *>(MapViewOfFile(g_map, FILE_MAP_READ, 0, 0, 0));
  return g_view != nullptr;
}

void PumpFrame() {
  if (!EnsureMapped()) {
    return;
  }
  const auto *h = reinterpret_cast<const ShmHeader *>(g_view);
  if (h->magic != kMagic || h->frameSeq == 0 || h->width == 0 ||
      h->height == 0 || h->bpp != 32) {
    return;
  }
  const uint64_t seq = h->frameSeq;
  if (seq == g_lastSeq) {
    return;
  }
  const uint32_t w = h->width;
  const uint32_t ht = h->height;
  if (w > 8192 || ht > 8192) {
    return;
  }
  const size_t bytes = static_cast<size_t>(w) * ht * 4ull;
  g_pixels.resize(bytes);
  std::memcpy(g_pixels.data(), g_view + kHeaderBytes, bytes);
  if (h->frameSeq != seq) {
    return; // torn frame; retry next tick
  }
  g_lastSeq = seq;
  g_w = w;
  g_h = ht;
  InvalidateRect(g_wnd, nullptr, FALSE);
}

// Double-buffered paint: compose the whole frame in an off-screen DC and blit
// it in one pass. Painting straight to the window DC at ~30 Hz flickers badly
// (the background fill and the frame land in separate frames).
void OnPaint(HDC dc) {
  RECT rc{};
  GetClientRect(g_wnd, &rc);
  const int cw = rc.right - rc.left;
  const int ch = rc.bottom - rc.top;
  if (cw <= 0 || ch <= 0) {
    return;
  }

  static HDC memDc = nullptr;
  static HBITMAP memBmp = nullptr;
  static int memW = 0;
  static int memH = 0;
  if (!memDc) {
    memDc = CreateCompatibleDC(dc);
  }
  if (!memBmp || memW != cw || memH != ch) {
    if (memBmp) {
      DeleteObject(memBmp);
    }
    memBmp = CreateCompatibleBitmap(dc, cw, ch);
    memW = cw;
    memH = ch;
    SelectObject(memDc, memBmp);
  }

  HBRUSH bg = CreateSolidBrush(RGB(12, 12, 14));
  FillRect(memDc, &rc, bg);
  DeleteObject(bg);

  if (g_w != 0 && g_h != 0 && !g_pixels.empty()) {
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = static_cast<LONG>(g_w);
    bi.bmiHeader.biHeight = -static_cast<LONG>(g_h); // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(memDc, COLORONCOLOR);
    StretchDIBits(memDc, 0, 0, cw, ch, 0, 0, static_cast<int>(g_w),
                  static_cast<int>(g_h), g_pixels.data(), &bi, DIB_RGB_COLORS,
                  SRCCOPY);
  } else {
    SetBkMode(memDc, TRANSPARENT);
    SetTextColor(memDc, RGB(190, 190, 195));
    DrawTextA(memDc, g_status.c_str(), -1, &rc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  }

  BitBlt(dc, 0, 0, cw, ch, memDc, 0, 0, SRCCOPY);
}

LRESULT CALLBACK WndProc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
  case WM_PAINT: {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(w, &ps);
    OnPaint(dc);
    EndPaint(w, &ps);
    return 0;
  }
  case WM_ERASEBKGND:
    return 1;
  case WM_TIMER:
    PumpFrame();
    return 0;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  default:
    break;
  }
  return DefWindowProcW(w, m, wp, lp);
}

int ArgInt(int argc, wchar_t **argv, const wchar_t *name, int fallback) {
  for (int i = 2; i + 1 < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return _wtoi(argv[i + 1]);
    }
  }
  return fallback;
}

std::wstring ArgStr(int argc, wchar_t **argv, const wchar_t *name,
                    const wchar_t *fallback) {
  for (int i = 2; i + 1 < argc; ++i) {
    if (std::wcscmp(argv[i], name) == 0) {
      return argv[i + 1];
    }
  }
  return fallback;
}

} // namespace

// antimal vmview --name <shmName> [--x N] [--y N] [--w N] [--h N] [--title T]
int CommandVmView(int argc, wchar_t **argv) {
  g_shmName = ArgStr(argc, argv, L"--name", L"Local\\AntiMalLiveFrameV1");
  const std::wstring title =
      ArgStr(argc, argv, L"--title", L"AntiMal VM - live guest screen");
  const int x = ArgInt(argc, argv, L"--x", 40);
  const int y = ArgInt(argc, argv, L"--y", 40);
  const int w = ArgInt(argc, argv, L"--w", 1100);
  const int h = ArgInt(argc, argv, L"--h", 700);

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = nullptr;
  wc.lpszClassName = L"AntiMalVmViewer";
  if (!RegisterClassExW(&wc)) {
    return 2;
  }
  g_wnd = CreateWindowExW(0, wc.lpszClassName, title.c_str(),
                          WS_OVERLAPPEDWINDOW, x, y, w, h, nullptr, nullptr,
                          wc.hInstance, nullptr);
  if (!g_wnd) {
    return 2;
  }
  ShowWindow(g_wnd, SW_SHOW);
  SetForegroundWindow(g_wnd); // come to the front so recordings show the VM
  BringWindowToTop(g_wnd);
  UpdateWindow(g_wnd);
  SetTimer(g_wnd, 1, 33, nullptr); // ~30 Hz frame pump.

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return 0;
}
