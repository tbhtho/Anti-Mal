// LiveFrameShm.h - the host-side publisher for the "real VM display" channel.
//
// Mirrors the guest Bochs-VBE framebuffer into a named shared-memory section so
// the UI process can map it READ-ONLY and blit it straight to a <canvas> -- no
// PNG encode and no disk anywhere in the path. This is the production live-VM
// display channel (it replaced the PNG-screenshot slideshow).
//
// Wire layout (must stay in lockstep with the reader in App/src/WebViewHost.cpp):
//   - a fixed 64-byte Header, then
//   - raw 32bpp BGRX pixels (width*height*4 bytes).
//
// Tearing protection is a seqlock: Publish() copies the pixels, issues a release
// barrier, THEN bumps frameSeq. A reader that latches frameSeq, copies, and sees
// the same frameSeq afterwards is guaranteed a complete, untorn frame.
//
// Extracted from VirtualMachine.cpp so the IPC contract can be exercised by a
// deterministic unit test without booting a VM (the publisher is the half of the
// "usable VM, not a screenshot" pipe that is otherwise only reachable via a live
// boot). The reader half lives in the App and mirrors this same Header.
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace antimal::hv {

class LiveFrameShmPublisher {
public:
  static constexpr uint32_t kMagic = 0x414D4C46u; // 'AMLF'
  static constexpr size_t kHeaderBytes = 64;
  static constexpr size_t kMaxPixelBytes = 16ull * 1024 * 1024; // <= VBE fb size

  struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t format; // 0 = BGRX (little-endian 0x00RRGGBB in memory)
    uint32_t byteLength;
    uint32_t reserved;
    volatile uint64_t frameSeq;
  };
  static_assert(sizeof(Header) <= kHeaderBytes,
                "LiveFrame header must fit in the 64-byte reserved prefix");

  explicit LiveFrameShmPublisher(const std::wstring &name) {
    if (name.empty()) {
      return;
    }
    const uint64_t total = kHeaderBytes + kMaxPixelBytes;
    handle_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                 static_cast<DWORD>(total >> 32),
                                 static_cast<DWORD>(total & 0xFFFFFFFFull),
                                 name.c_str());
    if (!handle_) {
      return;
    }
    view_ = static_cast<uint8_t *>(MapViewOfFile(
        handle_, FILE_MAP_WRITE, 0, 0, static_cast<SIZE_T>(total)));
    if (view_) {
      auto *h = reinterpret_cast<Header *>(view_);
      h->magic = kMagic;
      h->version = 1;
      h->frameSeq = 0;
    }
  }
  ~LiveFrameShmPublisher() {
    if (view_) {
      UnmapViewOfFile(view_);
    }
    if (handle_) {
      CloseHandle(handle_);
    }
  }
  LiveFrameShmPublisher(const LiveFrameShmPublisher &) = delete;
  LiveFrameShmPublisher &operator=(const LiveFrameShmPublisher &) = delete;

  bool Valid() const noexcept { return view_ != nullptr; }

  // srcStride = bytes between source rows (0 = tightly packed width*4). A wider
  // stride lets the caller copy just the visible width out of a larger virtual
  // surface (panning / double-buffering) without the off-screen padding.
  void Publish(const uint8_t *pixels, uint32_t width, uint32_t height,
               uint32_t bpp, uint32_t srcStride = 0) {
    if (!view_ || !pixels || bpp != 32 || width == 0 || height == 0) {
      return;
    }
    const uint64_t bytes = static_cast<uint64_t>(width) * height * 4ull;
    if (bytes > kMaxPixelBytes) {
      return;
    }
    const uint32_t rowBytes = width * 4u;
    const uint32_t stride = srcStride ? srcStride : rowBytes;
    auto *h = reinterpret_cast<Header *>(view_);
    if (stride == rowBytes) {
      std::memcpy(view_ + kHeaderBytes, pixels, static_cast<size_t>(bytes));
    } else {
      for (uint32_t y = 0; y < height; ++y) {
        std::memcpy(view_ + kHeaderBytes + static_cast<size_t>(y) * rowBytes,
                    pixels + static_cast<size_t>(y) * stride, rowBytes);
      }
    }
    h->width = width;
    h->height = height;
    h->bpp = bpp;
    h->format = 0;
    h->byteLength = static_cast<uint32_t>(bytes);
    MemoryBarrier();
    h->frameSeq = h->frameSeq + 1;
  }

private:
  HANDLE handle_ = nullptr;
  uint8_t *view_ = nullptr;
};

// True if a BGRX frame region is near-uniform (e.g. the guest cleared the
// framebuffer mid-repaint and hasn't redrawn yet). Windows' basic display path
// clears to a flat dark color then repaints the desktop, so a ~30 Hz capture
// catches the cleared state half the time -- the desktop<->blank flash. Callers
// skip publishing/saving these so only complete frames are shown. Samples a
// sparse grid (cheap); a real desktop has wide luma spread, a cleared frame ~0.
inline bool LiveFrameIsBlank(const uint8_t *px, uint32_t width, uint32_t height,
                             uint32_t stride) {
  if (!px || width < 8 || height < 8) {
    return false;
  }
  const uint32_t steps = 12; // 12x12 = 144 samples across the frame
  uint8_t lo = 255, hi = 0;
  for (uint32_t gy = 0; gy < steps; ++gy) {
    const uint32_t y = (height - 1) * gy / (steps - 1);
    const uint8_t *row = px + static_cast<size_t>(y) * stride;
    for (uint32_t gx = 0; gx < steps; ++gx) {
      const uint32_t x = (width - 1) * gx / (steps - 1);
      const uint8_t *p = row + static_cast<size_t>(x) * 4;
      const uint8_t v = static_cast<uint8_t>(
          (static_cast<int>(p[0]) + p[1] + p[2]) / 3); // BGRX -> avg luma
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
  }
  return (hi - lo) < 14; // tight spread => uniform/cleared frame
}

} // namespace antimal::hv
