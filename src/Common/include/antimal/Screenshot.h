#pragma once

// GDI+ screen capture, used by GuestAgent to produce the filmstrip the
// host UI shows in the report. Frames land as PNG files in a directory
// the host can later enumerate.

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

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

// Captures the entire virtual screen into a caller-owned BGRA/BGRX buffer
// (tightly packed rows, 4 bytes per pixel). This is the capture half of the
// filmstrip path without the PNG encode, so callers can decide whether a frame
// is worth keeping BEFORE paying the encoder + disk cost.
bool CaptureScreenToBgra(std::vector<uint8_t> *pixels, int *width, int *height);

// Cheap content signature of a frame (FNV-1a over a strided sample of pixels,
// with a per-row offset so a static image cannot alias). Sampling keeps the cost
// far below a full compare -- measured in the dedupe benchmark -- and identical
// frames produce identical signatures, which is what the retention policy keys
// on. Two DIFFERENT frames colliding is possible in principle; a collision only
// costs one skipped frame, and the next keyframe re-anchors the filmstrip.
uint64_t FrameSignature(const uint8_t *pixels, int width, int height,
                        int bytesPerPixel, int sampleEveryNthPixel = 64);

// Filmstrip retention: identical consecutive frames are not re-encoded; a
// keyframe is still kept at `keyframeInterval` so a static desktop is
// represented by timestamped anchors rather than hundreds of identical PNGs.
struct FrameRetentionPolicy {
  std::chrono::milliseconds keyframeInterval{60000};
  // Hard cap on consecutive duplicates; 0 = unlimited (keyframes bound it).
  int maxConsecutiveDuplicates = 0;
};

struct FrameRetentionState {
  bool haveLast = false;
  uint64_t lastSignature = 0;
  std::chrono::steady_clock::time_point lastKept{};
  uint64_t duplicatesSkipped = 0;
  uint64_t consecutiveDuplicates = 0;
  std::chrono::steady_clock::time_point firstDuplicate{};
  std::chrono::steady_clock::time_point lastDuplicate{};
};

// Pure decision: keep this frame (encode + write) or skip it as a duplicate.
// Mutates `state`; deterministic given the clock value passed in. `forced`
// means an ACTION-verification capture (e.g. before/after an injected input):
// it always keeps, even for an identical frame, so the evidence trail contains
// the state the operator/AI actually acted on.
bool DecideFrameKeep(uint64_t signature, std::chrono::steady_clock::time_point now,
                     const FrameRetentionPolicy &policy,
                     FrameRetentionState *state, bool forced = false);

// Long-running worker that writes numbered PNG frames to `outputDir`
// at the requested interval until Stop() is called.
//
// Use case: GuestAgent constructs one, lets it run for the detonation
// timeout, then Stop()s it before writing the final report. Frames are
// named `frame-NNNNNN.png` so the host can scrub through them.
//
// Identical consecutive frames are skipped (no PNG encode, no file) and
// represented by periodic keyframes; the skip counters are exposed so the run
// report can state that a still period was observed rather than misrepresenting
// it as continuous capture.
class ScreenshotLoop {
public:
  ScreenshotLoop(std::filesystem::path outputDir,
                 std::chrono::milliseconds interval,
                 FrameRetentionPolicy retention = {});
  ~ScreenshotLoop();

  ScreenshotLoop(const ScreenshotLoop &) = delete;
  ScreenshotLoop &operator=(const ScreenshotLoop &) = delete;

  void Start();
  void Stop();

  // Force the next captured frame to be kept regardless of duplication (used
  // after a guest action so the evidence trail has the acted-on state).
  void RequestCapture() noexcept { forceNextCapture_.store(true); }

  // Frames actually written (keyframes + changes).
  uint32_t FrameCount() const noexcept { return frameCount_.load(); }
  uint32_t DuplicateCount() const noexcept { return duplicates_.load(); }
  // Wall-span of the skipped-identical interval, in seconds (0 when none).
  uint64_t DuplicateSpanSeconds() const noexcept {
    const int64_t first = firstDuplicateMs_.load();
    const int64_t last = lastDuplicateMs_.load();
    if (first <= 0 || last <= first) {
      return 0;
    }
    return static_cast<uint64_t>((last - first) / 1000);
  }
  bool IsRunning() const noexcept { return running_.load(); }

private:
  std::filesystem::path outputDir_;
  std::chrono::milliseconds interval_;
  FrameRetentionPolicy retention_;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_{false};
  std::atomic<bool> forceNextCapture_{false};
  std::atomic<uint32_t> frameCount_{0};
  std::atomic<uint32_t> duplicates_{0};
  std::atomic<int64_t> firstDuplicateMs_{0};
  std::atomic<int64_t> lastDuplicateMs_{0};
};

} // namespace antimal
