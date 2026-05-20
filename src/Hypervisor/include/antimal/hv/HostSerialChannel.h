#pragma once

// Binary framing for the first host<->guest channel carried over COM1. The
// serial device wiring lands later; this codec is intentionally independent so
// tests can harden framing before any malware path is enabled.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace antimal::hv {

enum class HostChannelMessage : uint16_t {
  Hello = 1,
  JobStart = 2,
  Event = 3,
  ScreenshotChunk = 4,
  ArtifactChunk = 5,
  ReportComplete = 6,
  InputMouse = 7,
  InputKey = 8,
  Heartbeat = 9,
  Shutdown = 10,
};

struct HostChannelFrame {
  HostChannelMessage type = HostChannelMessage::Hello;
  std::vector<uint8_t> payload;
};

class HostSerialChannel {
public:
  static constexpr uint32_t kMaxPayloadBytes = 16u * 1024u * 1024u;

  static std::vector<uint8_t> Encode(const HostChannelFrame &frame);
  static std::vector<uint8_t> EncodeText(HostChannelMessage type,
                                         std::string_view text);

  void PushBytes(const uint8_t *data, size_t size);
  void PushBytes(const std::vector<uint8_t> &bytes);

  std::optional<HostChannelFrame> PopFrame();
  size_t PendingFrameCount() const noexcept { return frames_.size(); }
  void Reset();

private:
  void TryDecode();

  std::vector<uint8_t> buffer_;
  std::vector<HostChannelFrame> frames_;
};

} // namespace antimal::hv
