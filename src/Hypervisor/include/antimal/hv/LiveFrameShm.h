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

  void Publish(const uint8_t *pixels, uint32_t width, uint32_t height,
               uint32_t bpp) {
    if (!view_ || !pixels || bpp != 32 || width == 0 || height == 0) {
      return;
    }
    const uint64_t bytes = static_cast<uint64_t>(width) * height * 4ull;
    if (bytes > kMaxPixelBytes) {
      return;
    }
    auto *h = reinterpret_cast<Header *>(view_);
    std::memcpy(view_ + kHeaderBytes, pixels, static_cast<size_t>(bytes));
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

} // namespace antimal::hv
