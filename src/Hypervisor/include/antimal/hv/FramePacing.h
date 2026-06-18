// FramePacing.h - measured frame-cadence statistics for the live VM display.
//
// Feed RecordPublish() the monotonic microsecond timestamp at each *published*
// frame and this reports the achieved cadence (FPS), the inter-frame interval
// distribution (mean / p50 / p95 / min / max), and how often the stream kept pace
// with its target rate. RecordBlankSkip() separately counts frames the publish
// gate suppressed, so an operator can distinguish "no new content" from "we're
// slow toward the 25-30 FPS goal".
//
// This is the measured-diagnostics half of the FPS work: you can't tune what you
// don't measure. Deliberately pure (no Windows / no I/O) so it is unit-tested
// with synthetic timestamps without booting a VM. The Windows QPC clock that
// feeds it in production lives in LiveFrameShm.h (LiveFrameNowMicros()).
#pragma once

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace antimal::hv {

class FramePacingStats {
public:
  explicit FramePacingStats(uint32_t targetFps = 30, size_t window = 300)
      : targetFps_(targetFps ? targetFps : 30u),
        window_(window ? window : size_t{1}) {}

  // Call once per published frame with a monotonic timestamp in microseconds.
  void RecordPublish(uint64_t nowMicros) {
    ++framesPublished_;
    if (haveLast_ && nowMicros >= lastMicros_) {
      intervalsMicros_.push_back(nowMicros - lastMicros_);
      if (intervalsMicros_.size() > window_) {
        intervalsMicros_.erase(intervalsMicros_.begin());
      }
    }
    haveLast_ = true;
    lastMicros_ = nowMicros;
  }

  // Call when the publish gate suppressed a near-uniform frame.
  void RecordBlankSkip() { ++blankSkips_; }

  uint64_t FramesPublished() const noexcept { return framesPublished_; }
  uint64_t BlankSkips() const noexcept { return blankSkips_; }
  size_t SampleCount() const noexcept { return intervalsMicros_.size(); }
  uint32_t TargetFps() const noexcept { return targetFps_; }

  double MeanIntervalMs() const {
    if (intervalsMicros_.empty()) return 0.0;
    uint64_t sum = 0;
    for (uint64_t v : intervalsMicros_) sum += v;
    return (static_cast<double>(sum) / intervalsMicros_.size()) / 1000.0;
  }
  double MeasuredFps() const {
    const double mean = MeanIntervalMs();
    return mean > 0.0 ? 1000.0 / mean : 0.0;
  }
  double MinIntervalMs() const {
    if (intervalsMicros_.empty()) return 0.0;
    return static_cast<double>(
               *std::min_element(intervalsMicros_.begin(), intervalsMicros_.end())) /
           1000.0;
  }
  double MaxIntervalMs() const {
    if (intervalsMicros_.empty()) return 0.0;
    return static_cast<double>(
               *std::max_element(intervalsMicros_.begin(), intervalsMicros_.end())) /
           1000.0;
  }
  // pct in [0,1]; nearest-rank over the retained window.
  double PercentileIntervalMs(double pct) const {
    if (intervalsMicros_.empty()) return 0.0;
    if (pct < 0.0) pct = 0.0;
    if (pct > 1.0) pct = 1.0;
    std::vector<uint64_t> sorted(intervalsMicros_);
    std::sort(sorted.begin(), sorted.end());
    size_t idx = static_cast<size_t>(pct * (sorted.size() - 1) + 0.5);
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return static_cast<double>(sorted[idx]) / 1000.0;
  }
  // A "stall" is an inter-frame interval far beyond the target frame time -- a
  // visible hitch/freeze the average FPS hides. Threshold = 3x the target frame
  // interval (e.g. 100ms at 30fps).
  double StallThresholdMs() const noexcept {
    return 1000.0 / static_cast<double>(targetFps_) * 3.0;
  }
  uint64_t StallCount() const {
    const double stallMicros = 1.0e6 / static_cast<double>(targetFps_) * 3.0;
    uint64_t n = 0;
    for (uint64_t v : intervalsMicros_) {
      if (static_cast<double>(v) > stallMicros) ++n;
    }
    return n;
  }

  // Fraction (0..1) of inter-frame intervals at/under the target frame time (with
  // 20% slack) -- frames that kept pace with the target rate.
  double OnTargetRatio() const {
    if (intervalsMicros_.empty()) return 0.0;
    const double targetMicros = 1.0e6 / static_cast<double>(targetFps_) * 1.2;
    size_t ok = 0;
    for (uint64_t v : intervalsMicros_) {
      if (static_cast<double>(v) <= targetMicros) ++ok;
    }
    return static_cast<double>(ok) / intervalsMicros_.size();
  }

  std::string Summary() const {
    std::ostringstream o;
    o << std::fixed << std::setprecision(1) << MeasuredFps() << "fps (target "
      << targetFps_ << ") p50 " << PercentileIntervalMs(0.50) << "ms p95 "
      << PercentileIntervalMs(0.95) << "ms min " << MinIntervalMs() << "ms max "
      << MaxIntervalMs() << "ms" << std::setprecision(0) << " on-target "
      << (OnTargetRatio() * 100.0) << "% stalls " << StallCount() << " frames "
      << framesPublished_ << " blank-skips " << blankSkips_;
    return o.str();
  }

private:
  uint32_t targetFps_;
  size_t window_;
  std::vector<uint64_t> intervalsMicros_;
  uint64_t framesPublished_ = 0;
  uint64_t blankSkips_ = 0;
  uint64_t lastMicros_ = 0;
  bool haveLast_ = false;
};

} // namespace antimal::hv
