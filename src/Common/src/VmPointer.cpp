#include "antimal/VmPointer.h"

#include <algorithm>
#include <cmath>

namespace antimal {
namespace {

// A channel that changed by more than this between frames is "moved" content.
constexpr int kMotionThreshold = 28;
// ...and it counts as "explained by the injected shift" only when, at the
// shifted position, it agrees within this tolerance. Two thresholds, not one:
// it keeps anti-aliased edges (which shift by a few levels) from disqualifying
// an otherwise exact match.
constexpr int kShiftTolerance = 20;
// Masked tracking tolerance: how far a sprite pixel may drift before it stops
// counting as a match. Generous because the guest may re-render the cursor
// over different backgrounds.
constexpr int kTrackTolerance = 32;
// A track is only believed when this fraction of mask pixels agree.
constexpr double kTrackMinScore = 0.9;
// The pointer sprite is small; anything larger that moved by exactly the probe
// delta is something else (a scrolling pane, a video).
constexpr int kMaxSpriteDim = 80;
constexpr int kMinMaskPixels = 8;

int MaxChannelDiff(const uint8_t *a, const uint8_t *b) {
  const int db = std::abs(static_cast<int>(a[0]) - static_cast<int>(b[0]));
  const int dg = std::abs(static_cast<int>(a[1]) - static_cast<int>(b[1]));
  const int dr = std::abs(static_cast<int>(a[2]) - static_cast<int>(b[2]));
  return std::max(db, std::max(dg, dr));
}

struct Component {
  int minX = 0, minY = 0, maxX = 0, maxY = 0, count = 0;
  int Width() const { return maxX - minX + 1; }
  int Height() const { return maxY - minY + 1; }
  int Area() const { return Width() * Height(); }
};

// 8-connected components over a byte mask (BFS with an explicit stack; frames
// are ~1 MP so this stays well inside a tool call's latency budget).
std::vector<Component> FindComponents(const std::vector<uint8_t> &mask, int w,
                                      int h) {
  std::vector<uint8_t> seen(mask.size(), 0);
  std::vector<Component> out;
  std::vector<int> stack;
  for (int y = 0; y < h; ++y) {
    for (int x = 0; x < w; ++x) {
      const int start = y * w + x;
      if (!mask[start] || seen[start]) {
        continue;
      }
      Component c;
      c.minX = c.maxX = x;
      c.minY = c.maxY = y;
      stack.clear();
      stack.push_back(start);
      seen[start] = 1;
      while (!stack.empty()) {
        const int idx = stack.back();
        stack.pop_back();
        const int cx = idx % w;
        const int cy = idx / w;
        ++c.count;
        c.minX = std::min(c.minX, cx);
        c.maxX = std::max(c.maxX, cx);
        c.minY = std::min(c.minY, cy);
        c.maxY = std::max(c.maxY, cy);
        for (int ny = cy - 1; ny <= cy + 1; ++ny) {
          if (ny < 0 || ny >= h) {
            continue;
          }
          for (int nx = cx - 1; nx <= cx + 1; ++nx) {
            if (nx < 0 || nx >= w) {
              continue;
            }
            const int ni = ny * w + nx;
            if (mask[ni] && !seen[ni]) {
              seen[ni] = 1;
              stack.push_back(ni);
            }
          }
        }
      }
      out.push_back(c);
    }
  }
  return out;
}

} // namespace

static ShiftLearnResult LearnCursorAtShift(const BgrxFrame &before,
                                         const BgrxFrame &after, int dx,
                                         int dy) {
  ShiftLearnResult r;
  if (!before.Valid() || !after.Valid() ||
      before.width != after.width || before.height != after.height) {
    r.failure = "frames differ in size";
    return r;
  }
  if (dx == 0 && dy == 0) {
    r.failure = "probe delta must be non-zero";
    return r;
  }
  const int w = static_cast<int>(after.width);
  const int h = static_cast<int>(after.height);

  // Candidate pixels: changed between the frames AND matching the frame
  // content shifted by exactly (dx, dy). The pointer's new pixels satisfy
  // both (the desktop it uncovers did not move; the pointer did).
  std::vector<uint8_t> cand(static_cast<size_t>(w) * h, 0);
  for (int y = 0; y < h; ++y) {
    const int sy = y - dy;
    if (sy < 0 || sy >= h) {
      continue;
    }
    for (int x = 0; x < w; ++x) {
      const int sx = x - dx;
      if (sx < 0 || sx >= w) {
        continue;
      }
      const uint8_t *a = after.At(x, y);
      if (MaxChannelDiff(a, before.At(x, y)) <= kMotionThreshold) {
        continue; // this pixel did not change
      }
      if (MaxChannelDiff(a, before.At(sx, sy)) > kShiftTolerance) {
        continue; // changed, but not by exactly the injected delta
      }
      // The source must have changed too. Otherwise the desktop uncovered by
      // the OLD pointer can masquerade as a moving sprite on a smooth wall.
      if (MaxChannelDiff(before.At(sx, sy), after.At(sx, sy)) <=
          kMotionThreshold) {
        continue;
      }
      cand[static_cast<size_t>(y) * w + x] = 1;
    }
  }

  const std::vector<Component> comps = FindComponents(cand, w, h);
  const Component *best = nullptr;
  double bestRank = -1.0;
  for (const Component &c : comps) {
    if (c.count < kMinMaskPixels || c.Width() > kMaxSpriteDim ||
        c.Height() > kMaxSpriteDim) {
      continue;
    }
    // Prefer dense compact blobs (the cursor arrow) over sparse wider ones.
    const double density =
        static_cast<double>(c.count) / std::max(1, c.Area());
    const double rank = density * 1000.0 + c.count;
    if (rank > bestRank ||
        (rank == bestRank && best && (c.minY < best->minY ||
                                      (c.minY == best->minY &&
                                       c.minX < best->minX)))) {
      bestRank = rank;
      best = &c;
    }
  }
  if (!best) {
    r.failure = "no pointer-sized region moved by the probe delta";
    return r;
  }

  // The sprite box is the component's own bounding box (no padding): its
  // top-left is the pointer's hotspot-ish corner, which is the position the
  // aim loop targets and the frame coordinates callers reason about.
  const int bx0 = best->minX;
  const int by0 = best->minY;
  const int bx1 = best->maxX;
  const int by1 = best->maxY;
  CursorSprite sprite;
  sprite.width = bx1 - bx0 + 1;
  sprite.height = by1 - by0 + 1;
  sprite.pixels.resize(static_cast<size_t>(sprite.width) * sprite.height * 4);
  sprite.mask.assign(static_cast<size_t>(sprite.width) * sprite.height, 0);
  for (int y = 0; y < sprite.height; ++y) {
    const uint8_t *src = after.At(bx0, by0 + y);
    std::copy(src, src + static_cast<size_t>(sprite.width) * 4,
              sprite.pixels.begin() + static_cast<size_t>(y) * sprite.width * 4);
  }
  // Add a one-pixel outline only when it agrees at BOTH endpoints of the
  // confirmed move. This distinguishes a black I-beam from static dark text
  // without importing an arbitrary patch of uncovered wallpaper.
  for (int y = by0; y <= by1; ++y) {
    for (int x = bx0; x <= bx1; ++x) {
      if (!cand[static_cast<size_t>(y) * w + x]) continue;
      for (int oy = -1; oy <= 1; ++oy) {
        for (int ox = -1; ox <= 1; ++ox) {
          const int nx = x + ox, ny = y + oy;
          if (nx < bx0 || nx > bx1 || ny < by0 || ny > by1 ||
              !before.Contains(nx - dx, ny - dy)) continue;
          if (MaxChannelDiff(after.At(nx, ny), before.At(nx - dx, ny - dy)) <=
              kShiftTolerance) {
            sprite.mask[static_cast<size_t>(ny - by0) * sprite.width + nx - bx0] = 1;
          }
        }
      }
    }
  }
  if (!sprite.Valid()) {
    r.failure = "pointer mask too small";
    return r;
  }

  int minColor = 255, maxColor = 0;
  for (size_t i = 0; i < sprite.mask.size(); ++i) {
    if (!sprite.mask[i]) continue;
    for (int c = 0; c < 3; ++c) {
      minColor = std::min(minColor, static_cast<int>(sprite.pixels[i * 4 + c]));
      maxColor = std::max(maxColor, static_cast<int>(sprite.pixels[i * 4 + c]));
    }
  }
  if (sprite.MaskPixels() < 20 || maxColor - minColor < 96) {
    r.failure = "moving fragment lacks a distinctive pointer outline";
    return r;
  }

  // Refine the ACTUAL delta by locating the sprite in the pre-move frame:
  // measured gain (acceleration) comes straight from this pair.
  const CursorMatch pre =
      TrackCursor(before, sprite, bx0 - dx, by0 - dy, 0);
  const double density = static_cast<double>(best->count) /
                         std::max(1, best->Area());
  if (pre.valid &&
      (dx == 0 ? std::abs(bx0 - pre.x) <= 2 : (bx0 - pre.x) * dx > 0) &&
      (dy == 0 ? std::abs(by0 - pre.y) <= 2 : (by0 - pre.y) * dy > 0)) {
    r.actualDx = bx0 - pre.x;
    r.actualDy = by0 - pre.y;
    r.confidence = pre.score * density;
  } else {
    r.failure = "sprite motion could not be confirmed in the pre-move frame";
    return r;
  }
  r.valid = true;
  r.sprite = std::move(sprite);
  r.x = bx0;
  r.y = by0;
  return r;
}

ShiftLearnResult LearnCursorByKnownShift(const BgrxFrame &before,
                                         const BgrxFrame &after, int dx, int dy) {
  // PS/2 counts are not screen pixels. Search bounded gains for small axis
  // probes, retaining the most complete confirmed sprite rather than a tiny
  // fragment that happens to match the requested count.
  ShiftLearnResult best = LearnCursorAtShift(before, after, dx, dy);
  if ((dx == 0) != (dy == 0) && std::max(std::abs(dx), std::abs(dy)) <= 16) {
    for (int distance = 1; distance <= 32; ++distance) {
      const int sx = dx == 0 ? 0 : (dx > 0 ? distance : -distance);
      const int sy = dy == 0 ? 0 : (dy > 0 ? distance : -distance);
      if (sx == dx && sy == dy) continue;
      auto candidate = LearnCursorAtShift(before, after, sx, sy);
      if (candidate.valid && (!best.valid ||
          candidate.sprite.MaskPixels() > best.sprite.MaskPixels())) {
        best = std::move(candidate);
      }
    }
  }
  return best;
}

CursorMatch TrackCursor(const BgrxFrame &frame, const CursorSprite &sprite,
                        int hintX, int hintY, int searchRadius) {
  CursorMatch best;
  if (!frame.Valid() || !sprite.Valid()) {
    return best;
  }
  const int total = sprite.MaskPixels();
  if (total <= 0) {
    return best;
  }
  // Flatten the mask once: the inner loop is then a linear walk over sprite
  // pixels, with an early exit the moment a candidate cannot beat the best.
  std::vector<std::pair<int, int>> offsets;
  offsets.reserve(static_cast<size_t>(total));
  for (int y = 0; y < sprite.height; ++y) {
    for (int x = 0; x < sprite.width; ++x) {
      if (sprite.mask[static_cast<size_t>(y) * sprite.width + x]) {
        offsets.emplace_back(x, y);
      }
    }
  }
  const int w = static_cast<int>(frame.width);
  const int h = static_cast<int>(frame.height);
  const int x0 = std::max(0, hintX - searchRadius);
  const int y0 = std::max(0, hintY - searchRadius);
  const int x1 = std::min(w - sprite.width, hintX + searchRadius);
  const int y1 = std::min(h - sprite.height, hintY + searchRadius);
  int bestMatched = -1;
  for (int oy = y0; oy <= y1; ++oy) {
    if (oy < 0 || oy + sprite.height > h) {
      continue;
    }
    for (int ox = x0; ox <= x1; ++ox) {
      if (ox < 0 || ox + sprite.width > w) {
        continue;
      }
      int matched = 0;
      int remaining = total;
      for (const auto &[mx, my] : offsets) {
        const uint8_t *fp = frame.At(ox + mx, oy + my);
        const uint8_t *sp =
            sprite.pixels.data() +
            (static_cast<size_t>(my) * sprite.width + mx) * 4;
        if (MaxChannelDiff(fp, sp) <= kTrackTolerance) {
          ++matched;
        }
        --remaining;
        if (matched + remaining < bestMatched) {
          break; // cannot beat the best even if every remaining pixel hits
        }
      }
      if (matched > bestMatched) {
        bestMatched = matched;
        best.x = ox;
        best.y = oy;
        best.score = static_cast<double>(matched) / total;
      }
    }
  }
  best.valid = bestMatched >= 0 && best.score >= kTrackMinScore;
  return best;
}

PointerAimState::Decision PointerAimState::Next() {
  Decision d;
  if (WithinTolerance()) {
    d.done = true;
    return d;
  }
  if (iterations >= maxIterations || stalls >= 4) {
    d.done = true;
    d.failed = true;
    return d;
  }
  auto axis = [](double error, double gain, int stepCap) -> int {
    if (gain < 0.2) {
      gain = 0.2; // never divide by (near) zero
    }
    double v = error / gain;
    if (v > stepCap) {
      v = stepCap;
    }
    if (v < -stepCap) {
      v = -stepCap;
    }
    int s = static_cast<int>(std::lround(v));
    if (s == 0 && error != 0.0) {
      s = error > 0 ? 1 : -1; // always make progress on a non-zero error
    }
    return s;
  };
  d.dx = std::clamp(axis(targetX - cursorX, gainX, maxStep), -127, 127);
  d.dy = std::clamp(axis(targetY - cursorY, gainY, maxStep), -127, 127);
  return d;
}

void PointerAimState::Observe(int injectedDx, int injectedDy, int measuredDx,
                              int measuredDy) {
  cursorX += measuredDx;
  cursorY += measuredDy;
  ++iterations;
  if (measuredDx == 0 && measuredDy == 0) {
    ++stalls;
  } else {
    stalls = 0;
  }
  auto update = [](double gain, int injected, int measured) -> double {
    if (injected == 0) {
      return gain;
    }
    if (std::abs(measured) <= 2 && std::abs(injected) >= 6) {
      return gain; // pointer barely responded (edge clamp?) -- keep prior gain
    }
    const double observed = static_cast<double>(measured) /
                            static_cast<double>(injected);
    if (observed <= 0.05) {
      return gain * 0.5; // wrong direction = overshoot; damp the gain
    }
    double blended = 0.5 * gain + 0.5 * observed;
    blended = std::clamp(blended, 0.2, 8.0);
    return blended;
  };
  gainX = update(gainX, injectedDx, measuredDx);
  gainY = update(gainY, injectedDy, measuredDy);
}

} // namespace antimal
