#pragma once

// VmPointer - the host-side pointer model for coordinate-based live-VM input.
//
// Windows draws the guest pointer into the framebuffer itself (Bochs VBE has no
// hardware cursor), so the host can SEE it and close the loop: capture, locate,
// nudge, re-capture. That feedback is what turns "relative PS/2 deltas run
// through an unknown pointer-acceleration curve" into a dependable
// "click at (x, y)" primitive an agent can call.
//
// Everything here is pure arithmetic over BGRX frames -- no Windows APIs, no
// VM. The sprite learn/track/aim pipeline is unit-tested with synthetic frames
// and a fake accelerated guest, so the live code path is only wiring.

#include <cstdint>
#include <string>
#include <vector>

namespace antimal {

// 32-bit BGRX frame (the LiveFrameShm wire format: little-endian B,G,R,X).
struct BgrxFrame {
  uint32_t width = 0;
  uint32_t height = 0;
  std::vector<uint8_t> pixels; // width * height * 4

  bool Valid() const {
    return width > 0 && height > 0 &&
           pixels.size() >= static_cast<size_t>(width) * height * 4;
  }
  bool Contains(int x, int y) const {
    return x >= 0 && y >= 0 && x < static_cast<int>(width) &&
           y < static_cast<int>(height);
  }
  const uint8_t *At(int x, int y) const {
    return pixels.data() + (static_cast<size_t>(y) * width + x) * 4;
  }
  uint8_t *At(int x, int y) {
    return pixels.data() + (static_cast<size_t>(y) * width + x) * 4;
  }
};

// The learned pointer image: its pixels plus a foreground mask. `mask` is
// width*height; nonzero bytes mark sprite pixels. Compared masked (not the raw
// patch) so the desktop underneath the pointer does not fool tracking.
struct CursorSprite {
  int width = 0;
  int height = 0;
  std::vector<uint8_t> pixels; // width * height * 4
  std::vector<uint8_t> mask;   // width * height, 0/1

  int MaskPixels() const {
    int n = 0;
    for (uint8_t m : mask) {
      n += m ? 1 : 0;
    }
    return n;
  }
  bool Valid() const {
    return width > 0 && height > 0 &&
           pixels.size() >= static_cast<size_t>(width) * height * 4 &&
           mask.size() >= static_cast<size_t>(width) * height &&
           MaskPixels() >= 6;
  }
};

struct CursorMatch {
  bool valid = false;
  int x = 0; // top-left of the sprite in frame coordinates
  int y = 0;
  double score = 0.0; // matched mask fraction, 1.0 = every mask pixel agrees
};

struct ShiftLearnResult {
  bool valid = false;
  CursorSprite sprite;
  int x = 0; // sprite top-left in the `after` frame
  int y = 0;
  // Movement actually observed between the frames. Equals the injected delta
  // when the pointer gain is 1:1; differs when Windows pointer acceleration
  // scaled the move -- this is how the aim loop measures the gain.
  int actualDx = 0;
  int actualDy = 0;
  double confidence = 0.0;
  std::string failure;
};

// Learns the pointer sprite from a frame pair where the pointer moved by the
// known injected PS/2 delta (dx, dy). The pointer is the small region in
// `after` that `before` explains by shifting exactly (dx, dy): content that
// moved by that delta matches, everything else does not. `dx`/`dy` are in
// SCREEN space (x right, y down) -- the same space the caller injects.
ShiftLearnResult LearnCursorByKnownShift(const BgrxFrame &before,
                                         const BgrxFrame &after, int dx, int dy);

// Tracks the learned sprite in `frame` near (hintX, hintY) -- the expected
// top-left. Returns the best match when the score clears kTrackMinScore.
CursorMatch TrackCursor(const BgrxFrame &frame, const CursorSprite &sprite,
                        int hintX, int hintY, int searchRadius = 96);

// ---- Aiming (pure feedback loop, no I/O) ------------------------------------

// Converts a target position into relative PS/2 steps, learning each axis's
// gain from (injected, measured) pairs. Screen space: x right, y down; the
// caller negates dy when framing the PS/2 packet (positive PS/2 Y is up).
//
// The controller is deliberately stateless about the guest: it never assumes
// the pointer accelerated 1:1. It probes, measures what actually happened,
// updates the gain, and converges -- and gives up honestly (failed = true)
// when the pointer stops responding or the iteration budget runs out.
struct PointerAimState {
  int targetX = 0;
  int targetY = 0;
  int cursorX = 0; // current pointer hotspot in screen space
  int cursorY = 0;
  double gainX = 1.0; // measured screen-pixels per injected PS/2 count
  double gainY = 1.0;
  int tolerance = 4;      // reached when |error| <= tolerance on both axes
  int maxStep = 64;       // per-step clamp (also stays well inside int8)
  int maxIterations = 16; // injected moves before giving up
  int iterations = 0;
  int stalls = 0; // consecutive in-place moves (pointer not listening)

  struct Decision {
    bool done = false;   // stop: reached, or failed -- check failed
    bool failed = false; // stopped short of the target
    int dx = 0;          // next relative PS/2 step (screen space)
    int dy = 0;
  };

  bool WithinTolerance() const {
    const int ex = targetX - cursorX;
    const int ey = targetY - cursorY;
    return ex <= tolerance && ex >= -tolerance && ey <= tolerance &&
           ey >= -tolerance;
  }

  // Plans the next relative move toward the target.
  Decision Next();

  // Feedback for one injected step: what the pointer actually did, in screen
  // pixels (measured = new position - previous position).
  void Observe(int injectedDx, int injectedDy, int measuredDx, int measuredDy);
};

} // namespace antimal
