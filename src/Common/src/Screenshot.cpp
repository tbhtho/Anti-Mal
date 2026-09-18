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

bool FramebufferHasVisiblePixels(const uint8_t *pixels, int width, int height,
                                 int bytesPerPixel) {
  if (!pixels || width <= 0 || height <= 0 || bytesPerPixel < 3) {
    return false;
  }
  const size_t total =
      static_cast<size_t>(width) * static_cast<size_t>(height) *
      static_cast<size_t>(bytesPerPixel);
  for (size_t i = 0; i + 2 < total; i += static_cast<size_t>(bytesPerPixel)) {
    if (pixels[i] != 0 || pixels[i + 1] != 0 || pixels[i + 2] != 0) {
      return true;
    }
  }
  return false;
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

bool CaptureScreenToBgra(std::vector<uint8_t> *pixels, int *width, int *height) {
  (void)GdiPlusInstance();
  if (!pixels || !width || !height) {
    return false;
  }
  const int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
  const int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
  const int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
  const int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  if (w <= 0 || h <= 0) {
    return false;
  }
  HDC screenDc = GetDC(nullptr);
  if (!screenDc) {
    return false;
  }
  HDC memDc = CreateCompatibleDC(screenDc);
  HBITMAP bitmap =
      memDc ? CreateCompatibleBitmap(screenDc, w, h) : nullptr;
  if (!bitmap) {
    if (memDc) DeleteDC(memDc);
    ReleaseDC(nullptr, screenDc);
    return false;
  }
  HGDIOBJ oldObject = SelectObject(memDc, bitmap);
  const BOOL ok = BitBlt(memDc, 0, 0, w, h, screenDc, x, y, SRCCOPY);
  SelectObject(memDc, oldObject);

  bool copied = false;
  if (ok) {
    Gdiplus::Bitmap gdiBitmap(bitmap, nullptr);
    Gdiplus::Rect rect(0, 0, w, h);
    Gdiplus::BitmapData data{};
    if (gdiBitmap.LockBits(&rect, Gdiplus::ImageLockModeRead,
                           PixelFormat32bppRGB, &data) == Gdiplus::Ok) {
      pixels->assign(static_cast<size_t>(w) * h * 4, 0);
      const int rowBytes = w * 4;
      for (int row = 0; row < h; ++row) {
        const auto *src = static_cast<const uint8_t *>(data.Scan0) +
                          static_cast<size_t>(row) * data.Stride;
        std::memcpy(pixels->data() + static_cast<size_t>(row) * rowBytes, src,
                    static_cast<size_t>(rowBytes));
      }
      gdiBitmap.UnlockBits(&data);
      *width = w;
      *height = h;
      copied = true;
    }
  }
  DeleteObject(bitmap);
  DeleteDC(memDc);
  ReleaseDC(nullptr, screenDc);
  return copied;
}

uint64_t FrameSignature(const uint8_t *pixels, int width, int height,
                        int bytesPerPixel, int sampleEveryNthPixel) {
  if (!pixels || width <= 0 || height <= 0 || bytesPerPixel != 4) {
    return 0;
  }
  if (sampleEveryNthPixel < 1) {
    sampleEveryNthPixel = 1;
  }
  // FNV-1a over a strided sample. The per-row start offset advances by a prime
  // so a static image cannot alias, and sampling keeps the cost proportional to
  // pixels/sample rather than the whole 4 MB frame.
  constexpr uint64_t kOffset = 1469598103934665603ull;
  constexpr uint64_t kPrime = 1099511628211ull;
  uint64_t hash = kOffset;
  const size_t rowPixels = static_cast<size_t>(width);
  for (int row = 0; row < height; ++row) {
    const uint8_t *rowPtr = pixels + static_cast<size_t>(row) * rowPixels * 4;
    const size_t start = static_cast<size_t>((row * 7) % sampleEveryNthPixel);
    for (size_t px = start; px < rowPixels;
         px += static_cast<size_t>(sampleEveryNthPixel)) {
      const uint8_t *p = rowPtr + px * 4;
      hash ^= p[0];
      hash *= kPrime;
      hash ^= p[1];
      hash *= kPrime;
      hash ^= p[2];
      hash *= kPrime;
    }
  }
  return hash == 0 ? 1 : hash; // 0 is reserved for "no signature"
}

bool DecideFrameKeep(uint64_t signature,
                     std::chrono::steady_clock::time_point now,
                     const FrameRetentionPolicy &policy,
                     FrameRetentionState *state, bool forced) {
  if (state == nullptr || signature == 0) {
    return true; // never suppress a frame we could not signature
  }
  if (forced) {
    // Action-verification capture: always keep, even when unchanged.
    state->haveLast = true;
    state->lastSignature = signature;
    state->lastKept = now;
    state->consecutiveDuplicates = 0;
    return true;
  }
  const bool changed = !state->haveLast || signature != state->lastSignature;
  const bool keyframeDue =
      !state->haveLast ||
      (policy.keyframeInterval.count() > 0 &&
       now - state->lastKept >= policy.keyframeInterval);
  const bool duplicateCapHit =
      policy.maxConsecutiveDuplicates > 0 &&
      state->consecutiveDuplicates >=
          static_cast<uint64_t>(policy.maxConsecutiveDuplicates);
  if (changed) {
    state->haveLast = true;
    state->lastSignature = signature;
    state->lastKept = now;
    state->consecutiveDuplicates = 0;
    return true;
  }
  if (keyframeDue || duplicateCapHit) {
    state->lastKept = now;
    state->consecutiveDuplicates = 0;
    return true;
  }
  if (state->consecutiveDuplicates == 0) {
    state->firstDuplicate = now;
  }
  state->lastDuplicate = now;
  ++state->consecutiveDuplicates;
  ++state->duplicatesSkipped;
  return false;
}

ScreenshotLoop::ScreenshotLoop(std::filesystem::path outputDir,
                               std::chrono::milliseconds interval,
                               FrameRetentionPolicy retention)
    : outputDir_(std::move(outputDir)),
      interval_(interval),
      retention_(retention) {}

ScreenshotLoop::~ScreenshotLoop() {
  Stop();
}

void ScreenshotLoop::Start() {
  if (running_.exchange(true)) return;
  stop_.store(false);
  EnsureDirectory(outputDir_);
  thread_ = std::thread([this] {
    FrameRetentionState retention;
    std::vector<uint8_t> pixels;
    int width = 0;
    int height = 0;
    while (!stop_.load()) {
      // Capture to memory first: an unchanged frame must not pay the PNG
      // encode or create a file (the historical 1,138 files / 341 MB per
      // 30 min came from unconditional captures of a static desktop).
      if (CaptureScreenToBgra(&pixels, &width, &height)) {
        const uint64_t signature =
            FrameSignature(pixels.data(), width, height, 4);
        const bool forced = forceNextCapture_.exchange(false);
        if (DecideFrameKeep(signature, std::chrono::steady_clock::now(),
                            retention_, &retention, forced)) {
          const uint32_t frame = frameCount_.fetch_add(1);
          char nameBuf[32];
          _snprintf_s(nameBuf, _TRUNCATE, "frame-%06u.png", frame);
          const auto path = outputDir_ / nameBuf;
          if (!EncodeFramebufferPng(path, pixels.data(), width, height, 4)) {
            frameCount_.fetch_sub(1); // keep numbering contiguous on failure
          }
        } else {
          duplicates_.fetch_add(1);
          const int64_t nowMs =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now().time_since_epoch())
                  .count();
          if (firstDuplicateMs_.load() == 0) {
            firstDuplicateMs_.store(nowMs);
          }
          lastDuplicateMs_.store(nowMs);
        }
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
