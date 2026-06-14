#pragma once

// Coarse screen-state classifier for a guest framebuffer (BGRX). Distinguishes
// "nothing rendered yet" from "booting / a simple screen" from "a populated,
// detailed desktop", deterministically and cheaply (samples a grid, O(grid) not
// O(pixels)). The orchestrator uses the RICHEST state a run reaches as a
// boot-outcome signal -- it formalizes the frame-size heuristic that previously
// distinguished a ~13 KB boot/spinner frame from a ~1.2 MB desktop frame, so a
// run can report "reached a desktop" without a human eyeballing screenshots.
//
// It is a coarse three-way bucket, NOT OCR / UI-element detection: a solid-blue
// OOBE screen with a small console reads as Sparse (correctly "not a desktop"),
// a fully painted desktop with a wallpaper gradient + icons + taskbar reads as
// Rich. Thresholds are heuristic + tunable; the invariant is the ordering
// Blank < Sparse < Rich in luma-spread / colour-variety / local detail.

#include <cstdint>

namespace antimal::hv {

enum class ScreenState : uint8_t {
  Unknown = 0, // frame too small / no pixels to judge
  Blank = 1,   // near-uniform (cleared, black, or a single flat colour)
  Sparse = 2,  // some content but low overall detail (firmware/boot/spinner/dialog)
  Rich = 3,    // high colour-variety + local detail (a populated desktop / UI)
};

struct ScreenStateResult {
  ScreenState state = ScreenState::Unknown;
  uint32_t lumaSpread = 0;   // max-min sampled luma (0..255)
  uint32_t colorBuckets = 0; // distinct coarse colours seen (variety proxy)
  uint32_t detailPerMille = 0; // adjacent-sample luma jumps, per 1000 (detail proxy)
};

// Tuning knobs (header-visible so the unit test asserts against the same values).
inline constexpr uint32_t kScreenBlankLumaSpread = 14; // matches LiveFrameIsBlank
inline constexpr uint32_t kScreenRichColorBuckets = 10;
inline constexpr uint32_t kScreenRichDetailPerMille = 120; // 12% of adjacent pairs
inline constexpr uint32_t kScreenDetailLumaDelta = 24;     // a "jump" between samples

inline ScreenStateResult ClassifyScreenState(const uint8_t *px, uint32_t width,
                                             uint32_t height, uint32_t stride) {
  ScreenStateResult r{};
  if (!px || width < 8 || height < 8 || stride < width * 4) {
    return r; // Unknown
  }
  constexpr uint32_t kCols = 64;
  constexpr uint32_t kRows = 36;
  bool seen[64] = {}; // one per 6-bit (2 bits/channel) coarse colour bucket
  uint32_t bucketCount = 0;
  uint8_t lo = 255, hi = 0;
  uint32_t jumpPairs = 0, totalPairs = 0;
  for (uint32_t gy = 0; gy < kRows; ++gy) {
    const uint32_t y = (height - 1) * gy / (kRows - 1);
    const uint8_t *row = px + static_cast<size_t>(y) * stride;
    uint8_t prevLuma = 0;
    bool havePrev = false;
    for (uint32_t gx = 0; gx < kCols; ++gx) {
      const uint32_t x = (width - 1) * gx / (kCols - 1);
      const uint8_t *p = row + static_cast<size_t>(x) * 4;
      const uint8_t b = p[0], g = p[1], rr = p[2]; // BGRX
      const uint8_t luma =
          static_cast<uint8_t>((static_cast<int>(b) + g + rr) / 3);
      if (luma < lo) lo = luma;
      if (luma > hi) hi = luma;
      // 2 bits per channel -> 6-bit (64-entry) coarse colour bucket. Coarse so
      // gradient noise/dither doesn't inflate "variety".
      const uint8_t bucket = static_cast<uint8_t>(((rr >> 6) << 4) |
                                                  ((g >> 6) << 2) | (b >> 6));
      if (!seen[bucket]) {
        seen[bucket] = true;
        ++bucketCount;
      }
      if (havePrev) {
        ++totalPairs;
        const int d = static_cast<int>(luma) - static_cast<int>(prevLuma);
        if (static_cast<uint32_t>(d < 0 ? -d : d) > kScreenDetailLumaDelta) {
          ++jumpPairs;
        }
      }
      prevLuma = luma;
      havePrev = true;
    }
  }
  r.lumaSpread = static_cast<uint32_t>(hi - lo);
  r.colorBuckets = bucketCount;
  r.detailPerMille = totalPairs ? (jumpPairs * 1000u) / totalPairs : 0;

  if (r.lumaSpread < kScreenBlankLumaSpread) {
    r.state = ScreenState::Blank;
  } else if (r.colorBuckets >= kScreenRichColorBuckets ||
             r.detailPerMille >= kScreenRichDetailPerMille) {
    r.state = ScreenState::Rich;
  } else {
    r.state = ScreenState::Sparse;
  }
  return r;
}

inline const char *ScreenStateName(ScreenState s) {
  switch (s) {
  case ScreenState::Blank:
    return "blank";
  case ScreenState::Sparse:
    return "sparse";
  case ScreenState::Rich:
    return "rich";
  case ScreenState::Unknown:
  default:
    return "unknown";
  }
}

} // namespace antimal::hv
