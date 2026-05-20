#include "antimal/Screenshot.h"

#include "antimal/FileUtil.h"

#include <Windows.h>
// GDI+ headers reference IStream from <objidl.h> which is not pulled in
// by Windows.h when WIN32_LEAN_AND_MEAN is defined (we set that in
// Directory.Build.props). Include the COM marshaling header first.
#include <objidl.h>
#include <gdiplus.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>

#pragma comment(lib, "gdiplus.lib")

namespace antimal {
namespace {

struct GdiPlusGuard {
  GdiPlusGuard() {
    Gdiplus::GdiplusStartupInput input;
    Gdiplus::GdiplusStartup(&token_, &input, nullptr);
  }
  ~GdiPlusGuard() {
    if (token_) Gdiplus::GdiplusShutdown(token_);
  }
  ULONG_PTR token_ = 0;
};

GdiPlusGuard &GdiPlusInstance() {
  static GdiPlusGuard instance;
  return instance;
}

// Returns the CLSID of the requested encoder (e.g. L"image/png").
bool GetEncoderClsid(const wchar_t *mimeType, CLSID &clsid) {
  UINT num = 0;
  UINT size = 0;
  if (Gdiplus::GetImageEncodersSize(&num, &size) != Gdiplus::Ok || size == 0) {
    return false;
  }
  std::vector<uint8_t> buffer(size);
  auto *codecs = reinterpret_cast<Gdiplus::ImageCodecInfo *>(buffer.data());
  if (Gdiplus::GetImageEncoders(num, size, codecs) != Gdiplus::Ok) {
    return false;
  }
  for (UINT i = 0; i < num; ++i) {
    if (wcscmp(codecs[i].MimeType, mimeType) == 0) {
      clsid = codecs[i].Clsid;
      return true;
    }
  }
  return false;
}

} // namespace

namespace {

std::wstring Utf8ToWide(const std::string &text) {
  if (text.empty()) {
    return L"";
  }
  const int needed = MultiByteToWideChar(
      CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return L"";
  }
  std::wstring wide(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                      wide.data(), needed);
  return wide;
}

} // namespace

bool RenderTextToPng(const std::filesystem::path &outputPath,
                     const std::string &text, int width, int height) {
  (void)GdiPlusInstance();
  if (width <= 0 || height <= 0) {
    return false;
  }

  // Build an off-screen GDI bitmap, paint a dark panel + the text, hand to
  // GDI+ for PNG encoding. Mirrors the AntiMal UI's dark VM panel so the
  // generated frames feel like part of the same product.
  HDC screenDc = GetDC(nullptr);
  if (!screenDc) {
    return false;
  }
  HDC memDc = CreateCompatibleDC(screenDc);
  if (!memDc) {
    ReleaseDC(nullptr, screenDc);
    return false;
  }
  HBITMAP bitmap = CreateCompatibleBitmap(screenDc, width, height);
  if (!bitmap) {
    DeleteDC(memDc);
    ReleaseDC(nullptr, screenDc);
    return false;
  }
  HGDIOBJ oldBitmap = SelectObject(memDc, bitmap);

  RECT rc{0, 0, width, height};
  HBRUSH bg = CreateSolidBrush(RGB(20, 22, 27));
  FillRect(memDc, &rc, bg);
  DeleteObject(bg);

  // Thin accent stripe along the top so frames look intentional.
  RECT accent{0, 0, width, 4};
  HBRUSH accentBrush = CreateSolidBrush(RGB(120, 150, 255));
  FillRect(memDc, &accent, accentBrush);
  DeleteObject(accentBrush);

  // Use Consolas at 14pt for the monospaced VM-console look.
  LOGFONTW lf{};
  lf.lfHeight = -16;
  lf.lfWeight = FW_NORMAL;
  lf.lfCharSet = DEFAULT_CHARSET;
  lf.lfQuality = CLEARTYPE_QUALITY;
  wcscpy_s(lf.lfFaceName, L"Consolas");
  HFONT font = CreateFontIndirectW(&lf);
  HGDIOBJ oldFont = font ? SelectObject(memDc, font) : nullptr;

  SetTextColor(memDc, RGB(220, 230, 240));
  SetBkMode(memDc, TRANSPARENT);

  RECT textRect{18, 18, width - 18, height - 18};
  const auto wide = Utf8ToWide(text);
  DrawTextW(memDc, wide.c_str(), -1, &textRect,
            DT_LEFT | DT_TOP | DT_NOPREFIX | DT_EXPANDTABS);

  if (oldFont) {
    SelectObject(memDc, oldFont);
  }
  if (font) {
    DeleteObject(font);
  }

  bool wrote = false;
  CLSID pngClsid{};
  if (GetEncoderClsid(L"image/png", pngClsid)) {
    Gdiplus::Bitmap gdiBitmap(bitmap, nullptr);
    EnsureDirectory(outputPath.parent_path());
    const auto saved = gdiBitmap.Save(outputPath.wstring().c_str(), &pngClsid,
                                      nullptr);
    wrote = saved == Gdiplus::Ok;
  }

  SelectObject(memDc, oldBitmap);
  DeleteObject(bitmap);
  DeleteDC(memDc);
  ReleaseDC(nullptr, screenDc);
  return wrote;
}

bool EncodeFramebufferPng(const std::filesystem::path &outputPath,
                          const uint8_t *pixels, int width, int height,
                          int bytesPerPixel) {
  (void)GdiPlusInstance();
  if (!pixels || width <= 0 || height <= 0 || bytesPerPixel != 4) {
    return false;
  }
  // GDI+ Bitmap from a memory pointer. PixelFormat32bppRGB matches BGRX —
  // OVMF's GOP and Windows GDI both default to that on QEMU std VGA.
  const INT stride = width * 4;
  Gdiplus::Bitmap source(width, height, stride, PixelFormat32bppRGB,
                         const_cast<BYTE *>(pixels));
  CLSID pngClsid{};
  if (!GetEncoderClsid(L"image/png", pngClsid)) {
    return false;
  }
  EnsureDirectory(outputPath.parent_path());
  return source.Save(outputPath.wstring().c_str(), &pngClsid, nullptr) ==
         Gdiplus::Ok;
}

bool CaptureScreenToPng(const std::filesystem::path &outputPath) {
  (void)GdiPlusInstance(); // ensure GDI+ is initialized

  const int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
  const int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
  const int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
  const int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  if (width <= 0 || height <= 0) return false;

  HDC screenDc = GetDC(nullptr);
  if (!screenDc) return false;
  HDC memDc = CreateCompatibleDC(screenDc);
  if (!memDc) {
    ReleaseDC(nullptr, screenDc);
    return false;
  }
  HBITMAP bitmap = CreateCompatibleBitmap(screenDc, width, height);
  if (!bitmap) {
    DeleteDC(memDc);
    ReleaseDC(nullptr, screenDc);
    return false;
  }
  HGDIOBJ oldObject = SelectObject(memDc, bitmap);
  const BOOL ok = BitBlt(memDc, 0, 0, width, height, screenDc, x, y, SRCCOPY);
  SelectObject(memDc, oldObject);

  bool wrote = false;
  if (ok) {
    CLSID pngClsid{};
    if (GetEncoderClsid(L"image/png", pngClsid)) {
      Gdiplus::Bitmap gdiBitmap(bitmap, nullptr);
      EnsureDirectory(outputPath.parent_path());
      const auto saved = gdiBitmap.Save(outputPath.wstring().c_str(), &pngClsid,
                                        nullptr);
      wrote = saved == Gdiplus::Ok;
    }
  }

  DeleteObject(bitmap);
  DeleteDC(memDc);
  ReleaseDC(nullptr, screenDc);
  return wrote;
}

ScreenshotLoop::ScreenshotLoop(std::filesystem::path outputDir,
                               std::chrono::milliseconds interval)
    : outputDir_(std::move(outputDir)), interval_(interval) {}

ScreenshotLoop::~ScreenshotLoop() {
  Stop();
}

void ScreenshotLoop::Start() {
  if (running_.exchange(true)) return;
  stop_.store(false);
  EnsureDirectory(outputDir_);
  thread_ = std::thread([this] {
    while (!stop_.load()) {
      const uint32_t frame = frameCount_.fetch_add(1);
      char nameBuf[32];
      _snprintf_s(nameBuf, _TRUNCATE, "frame-%06u.png", frame);
      const auto path = outputDir_ / nameBuf;
      if (CaptureScreenToPng(path)) {
        // OK
      } else {
        // Roll back the increment if we failed so the numbering stays
        // contiguous on the next try.
        frameCount_.fetch_sub(1);
      }
      // Sleep in short slices so Stop() doesn't have to wait a full interval.
      const auto end = std::chrono::steady_clock::now() + interval_;
      while (!stop_.load() && std::chrono::steady_clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    running_.store(false);
  });
}

void ScreenshotLoop::Stop() {
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  running_.store(false);
}

} // namespace antimal
