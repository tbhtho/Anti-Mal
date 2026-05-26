#pragma once

// GDI+ screen capture, used by GuestAgent to produce the filmstrip the
// host UI shows in the report. Frames land as PNG files in a directory
// the host can later enumerate.

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

namespace antimal {

// Captures the entire virtual screen (all monitors) and writes a PNG to
// `outputPath`. Returns true on success. Initializes GDI+ on demand and
// keeps it initialized for the process lifetime so repeat calls are cheap.
bool CaptureScreenToPng(const std::filesystem::path &outputPath);

// Renders `text` to a PNG using a monospaced font on a dark background and
// writes it to `outputPath`. Used by the orchestrator to produce live "VM
// screen" frames during a detonation so the GUI filmstrip + latest-frame
// caption animate as the boot progresses, even without a guest framebuffer.
// `width` and `height` are the image dimensions in pixels.
bool RenderTextToPng(const std::filesystem::path &outputPath,
                     const std::string &text, int width = 720,
                     int height = 405);

// Encodes a raw BGRA / BGRX framebuffer to a PNG at `outputPath`. `pixels`
// points to `width * height * bytesPerPixel` bytes of guest pixel data; only
// 4-byte pixel formats (BGRA8888, BGRX8888 — what OVMF + Windows use under
// QEMU std VGA) are supported in this v1.
bool EncodeFramebufferPng(const std::filesystem::path &outputPath,
                          const uint8_t *pixels, int width, int height,
                          int bytesPerPixel);

// Returns true when a framebuffer contains at least one non-zero color byte.
// This lets the host avoid emitting blank guest frames before OVMF/Windows
// has actually painted the GOP surface.
bool FramebufferHasVisiblePixels(const uint8_t *pixels, int width, int height,
                                 int bytesPerPixel);

// Long-running worker that writes numbered PNG frames to `outputDir`
// at the requested interval until Stop() is called.
//
// Use case: GuestAgent constructs one, lets it run for the detonation
// timeout, then Stop()s it before writing the final report. Frames are
// named `frame-NNNNNN.png` so the host can scrub through them.
class ScreenshotLoop {
public:
  ScreenshotLoop(std::filesystem::path outputDir,
                 std::chrono::milliseconds interval);
  ~ScreenshotLoop();

  ScreenshotLoop(const ScreenshotLoop &) = delete;
  ScreenshotLoop &operator=(const ScreenshotLoop &) = delete;

  void Start();
  void Stop();

  uint32_t FrameCount() const noexcept { return frameCount_.load(); }
  bool IsRunning() const noexcept { return running_.load(); }

private:
  std::filesystem::path outputDir_;
  std::chrono::milliseconds interval_;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_{false};
  std::atomic<uint32_t> frameCount_{0};
};

} // namespace antimal
