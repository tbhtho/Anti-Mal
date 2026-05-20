#include "antimal/hv/HostSerialChannel.h"

#include <algorithm>
#include <cstring>
#include <iterator>

namespace antimal::hv {
namespace {

constexpr uint8_t kMagic[] = {'A', 'M', 'C', 'H'};
constexpr uint16_t kVersion = 1;
constexpr size_t kHeaderBytes = 16; // magic u32 + version u16 + type u16 + len u32 + checksum u32.

void PutU16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutU32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

uint16_t ReadU16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) |
         (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadU32(const uint8_t *p) {
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(p[i]) << (i * 8);
  }
  return value;
}

uint32_t Checksum(const uint8_t *data, size_t size) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash;
}

bool ValidType(uint16_t type) {
  return type >= static_cast<uint16_t>(HostChannelMessage::Hello) &&
         type <= static_cast<uint16_t>(HostChannelMessage::Shutdown);
}

} // namespace

std::vector<uint8_t> HostSerialChannel::Encode(const HostChannelFrame &frame) {
  if (frame.payload.size() > kMaxPayloadBytes) {
    return {};
  }
  std::vector<uint8_t> out;
  out.reserve(kHeaderBytes + frame.payload.size());
  out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
  PutU16(out, kVersion);
  PutU16(out, static_cast<uint16_t>(frame.type));
  PutU32(out, static_cast<uint32_t>(frame.payload.size()));
  PutU32(out, Checksum(frame.payload.data(), frame.payload.size()));
  out.insert(out.end(), frame.payload.begin(), frame.payload.end());
  return out;
}

std::vector<uint8_t> HostSerialChannel::EncodeText(HostChannelMessage type,
                                                   std::string_view text) {
  HostChannelFrame frame;
  frame.type = type;
  frame.payload.assign(text.begin(), text.end());
  return Encode(frame);
}

void HostSerialChannel::PushBytes(const uint8_t *data, size_t size) {
  if (!data || size == 0) {
    return;
  }
  buffer_.insert(buffer_.end(), data, data + size);
  TryDecode();
}

void HostSerialChannel::PushBytes(const std::vector<uint8_t> &bytes) {
  PushBytes(bytes.data(), bytes.size());
}

std::optional<HostChannelFrame> HostSerialChannel::PopFrame() {
  if (frames_.empty()) {
    return std::nullopt;
  }
  HostChannelFrame frame = std::move(frames_.front());
  frames_.erase(frames_.begin());
  return frame;
}

void HostSerialChannel::Reset() {
  buffer_.clear();
  frames_.clear();
}

void HostSerialChannel::TryDecode() {
  for (;;) {
    auto magic = std::search(buffer_.begin(), buffer_.end(),
                             std::begin(kMagic), std::end(kMagic));
    if (magic == buffer_.end()) {
      if (buffer_.size() > sizeof(kMagic)) {
        buffer_.erase(buffer_.begin(), buffer_.end() - (sizeof(kMagic) - 1));
      }
      return;
    }
    if (magic != buffer_.begin()) {
      buffer_.erase(buffer_.begin(), magic);
    }
    if (buffer_.size() < kHeaderBytes) {
      return;
    }

    const uint16_t version = ReadU16(buffer_.data() + 4);
    const uint16_t type = ReadU16(buffer_.data() + 6);
    const uint32_t length = ReadU32(buffer_.data() + 8);
    const uint32_t checksum = ReadU32(buffer_.data() + 12);
    if (version != kVersion || !ValidType(type) ||
        length > kMaxPayloadBytes) {
      buffer_.erase(buffer_.begin());
      continue;
    }
    const size_t total = kHeaderBytes + static_cast<size_t>(length);
    if (buffer_.size() < total) {
      return;
    }
    const uint8_t *payload = buffer_.data() + kHeaderBytes;
    if (Checksum(payload, length) != checksum) {
      buffer_.erase(buffer_.begin());
      continue;
    }

    HostChannelFrame frame;
    frame.type = static_cast<HostChannelMessage>(type);
    frame.payload.assign(payload, payload + length);
    frames_.push_back(std::move(frame));
    buffer_.erase(buffer_.begin(), buffer_.begin() + total);
  }
}

} // namespace antimal::hv
