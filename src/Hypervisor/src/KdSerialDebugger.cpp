#include "antimal/hv/KdSerialDebugger.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace antimal::hv {

namespace {

constexpr size_t kPacketHeaderBytes = 16;
constexpr uint16_t kPacketMaxSize = 4000;
constexpr uint32_t kStatusSuccess = 0;

uint16_t ReadU16(const std::vector<uint8_t> &bytes, size_t offset) noexcept {
  if (offset + 2 > bytes.size()) {
    return 0;
  }
  return static_cast<uint16_t>(bytes[offset]) |
         (static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

uint32_t ReadU32(const std::vector<uint8_t> &bytes, size_t offset) noexcept {
  if (offset + 4 > bytes.size()) {
    return 0;
  }
  return static_cast<uint32_t>(bytes[offset]) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

uint64_t ReadU64(const std::vector<uint8_t> &bytes, size_t offset) noexcept {
  if (offset + 8 > bytes.size()) {
    return 0;
  }
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
  }
  return value;
}

void PutU16(std::vector<uint8_t> &bytes, uint16_t value) {
  bytes.push_back(static_cast<uint8_t>(value & 0xFFu));
  bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void PutU32(std::vector<uint8_t> &bytes, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void PutU64(std::vector<uint8_t> &bytes, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void PutU32At(std::vector<uint8_t> &bytes, size_t offset, uint32_t value) {
  if (offset + 4 > bytes.size()) {
    return;
  }
  for (int i = 0; i < 4; ++i) {
    bytes[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

std::string Hex32(uint32_t value) {
  char buf[16]{};
  _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08X", value);
  return buf;
}

std::string Hex64(uint64_t value) {
  char buf[24]{};
  _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%016llX",
              static_cast<unsigned long long>(value));
  return buf;
}

std::string JsonEscapeLocal(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8);
  for (unsigned char c : text) {
    switch (c) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        char buf[8]{};
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\u%04X", c);
        out += buf;
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  return out;
}

std::string CleanText(std::string text) {
  for (char &ch : text) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c != '\r' && c != '\n' && c != '\t' && c < 0x20) {
      ch = '.';
    }
  }
  return text;
}

const char *PacketTypeName(uint16_t packetType) noexcept {
  switch (packetType) {
  case KdSerialDebugger::kPacketTypeStateChange32:
    return "KD_STATE_CHANGE32";
  case KdSerialDebugger::kPacketTypeStateManipulate:
    return "KD_STATE_MANIPULATE";
  case KdSerialDebugger::kPacketTypeDebugIo:
    return "KD_DEBUG_IO";
  case KdSerialDebugger::kPacketTypeAcknowledge:
    return "KD_ACKNOWLEDGE";
  case KdSerialDebugger::kPacketTypeResend:
    return "KD_RESEND";
  case KdSerialDebugger::kPacketTypeReset:
    return "KD_RESET";
  case KdSerialDebugger::kPacketTypeStateChange64:
    return "KD_STATE_CHANGE64";
  case KdSerialDebugger::kPacketTypePollBreakin:
    return "KD_POLL_BREAKIN";
  case KdSerialDebugger::kPacketTypeTraceIo:
    return "KD_TRACE_IO";
  case KdSerialDebugger::kPacketTypeControlRequest:
    return "KD_CONTROL_REQUEST";
  case KdSerialDebugger::kPacketTypeFileIo:
    return "KD_FILE_IO";
  default:
    return "KD_UNKNOWN";
  }
}

const char *ApiName(uint32_t api) noexcept {
  switch (api) {
  case KdSerialDebugger::kDbgKdPrintStringApi:
    return "DbgKdPrintStringApi";
  case KdSerialDebugger::kDbgKdContinueApi:
    return "DbgKdContinueApi";
  default:
    return "ApiUnknown";
  }
}

const char *StateName(uint32_t state) noexcept {
  switch (state) {
  case KdSerialDebugger::kDbgKdExceptionStateChange:
    return "DbgKdExceptionStateChange";
  case KdSerialDebugger::kDbgKdLoadSymbolsStateChange:
    return "DbgKdLoadSymbolsStateChange";
  default:
    return "DbgKdUnknownStateChange";
  }
}

bool IsLeaderByte(uint8_t value) noexcept {
  return value == 0x30u || value == 0x69u || value == 0x62u;
}

uint32_t NormalizePacketId(uint32_t packetId) noexcept {
  return packetId & ~KdSerialDebugger::kSyncPacketId;
}

} // namespace

void KdSerialDebugger::PushBytes(const uint8_t *data, size_t size) {
  if (!data || size == 0) {
    return;
  }
  summary_.bytesObserved += size;
  buffer_.insert(buffer_.end(), data, data + size);
  TryDecode();
}

void KdSerialDebugger::PushBytes(const std::string &bytes) {
  PushBytes(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size());
}

std::vector<uint8_t> KdSerialDebugger::PullReplies() {
  std::vector<uint8_t> out;
  out.swap(replies_);
  return out;
}

void KdSerialDebugger::QueueHostReset(std::string_view reason) {
  QueueControl(kPacketTypeReset, 0);
  KdSerialEvent event;
  event.kind = "host-reset";
  event.packetType = kPacketTypeReset;
  event.detail = reason.empty() ? "host KD reset/resync probe"
                                : std::string(reason);
  RecordEvent(std::move(event));
}

uint32_t KdSerialDebugger::Checksum(const uint8_t *data, size_t size) noexcept {
  uint32_t checksum = 0;
  if (!data) {
    return 0;
  }
  for (size_t i = 0; i < size; ++i) {
    checksum += data[i];
  }
  return checksum;
}

std::vector<uint8_t> KdSerialDebugger::EncodeControlPacket(uint16_t packetType,
                                                           uint32_t packetId) {
  std::vector<uint8_t> out;
  out.reserve(kPacketHeaderBytes);
  PutU32(out, kControlPacketLeader);
  PutU16(out, packetType);
  PutU16(out, 0);
  PutU32(out, packetId);
  PutU32(out, 0);
  return out;
}

std::vector<uint8_t>
KdSerialDebugger::EncodeDataPacket(uint16_t packetType, uint32_t packetId,
                                   const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> out;
  if (payload.size() > kPacketMaxSize) {
    return out;
  }
  out.reserve(kPacketHeaderBytes + payload.size() + 1);
  PutU32(out, kPacketLeader);
  PutU16(out, packetType);
  PutU16(out, static_cast<uint16_t>(payload.size()));
  PutU32(out, packetId);
  PutU32(out, Checksum(payload.data(), payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  out.push_back(kPacketTrailingByte);
  return out;
}

std::vector<uint8_t>
KdSerialDebugger::EncodeDebugPrintPacket(std::string_view text,
                                         uint32_t packetId) {
  std::vector<uint8_t> payload;
  payload.reserve(16 + text.size());
  PutU32(payload, kDbgKdPrintStringApi);
  PutU16(payload, 0x8664);
  PutU16(payload, 0);
  PutU32(payload, static_cast<uint32_t>(text.size()));
  PutU32(payload, 0);
  payload.insert(payload.end(), text.begin(), text.end());
  return EncodeDataPacket(kPacketTypeDebugIo, packetId, payload);
}

std::vector<uint8_t>
KdSerialDebugger::EncodeStateChange64Packet(uint32_t newState, uint32_t status,
                                            std::string_view text,
                                            uint32_t packetId) {
  std::vector<uint8_t> payload(192, 0);
  PutU32At(payload, 0, newState);
  PutU32At(payload, 8, 1);
  if (newState == kDbgKdExceptionStateChange) {
    PutU32At(payload, 32, status);
  } else if (newState == kDbgKdLoadSymbolsStateChange) {
    PutU32At(payload, 32, static_cast<uint32_t>(text.size()));
    PutU32At(payload, 60, status);
    payload.insert(payload.end(), text.begin(), text.end());
  }
  return EncodeDataPacket(kPacketTypeStateChange64, packetId, payload);
}

void KdSerialDebugger::TryDecode() {
  for (;;) {
    auto leader = std::search_n(buffer_.begin(), buffer_.end(), 4,
                                static_cast<uint8_t>(0x30));
    auto control = std::search_n(buffer_.begin(), buffer_.end(), 4,
                                 static_cast<uint8_t>(0x69));
    auto breakin = std::search_n(buffer_.begin(), buffer_.end(), 4,
                                 static_cast<uint8_t>(0x62));
    auto first = buffer_.end();
    for (auto it : {leader, control, breakin}) {
      if (it != buffer_.end() && (first == buffer_.end() || it < first)) {
        first = it;
      }
    }
    if (first == buffer_.end()) {
      if (buffer_.size() > 3) {
        summary_.noiseBytes += buffer_.size() - 3;
        buffer_.erase(buffer_.begin(), buffer_.end() - 3);
      }
      return;
    }
    if (first != buffer_.begin()) {
      summary_.noiseBytes += static_cast<uint64_t>(first - buffer_.begin());
      buffer_.erase(buffer_.begin(), first);
    }
    if (buffer_.size() < 4) {
      return;
    }

    const uint32_t packetLeader = ReadU32(buffer_, 0);
    if (packetLeader == kBreakinPacket) {
      summary_.breakinsReceived++;
      buffer_.erase(buffer_.begin(), buffer_.begin() + 4);
      KdSerialEvent event;
      event.kind = "breakin";
      event.detail = "KD break-in leader observed";
      RecordEvent(std::move(event));
      continue;
    }

    if (buffer_.size() < kPacketHeaderBytes) {
      return;
    }

    ParsedPacket packet;
    packet.leader = packetLeader;
    packet.packetType = ReadU16(buffer_, 4);
    packet.byteCount = ReadU16(buffer_, 6);
    packet.packetId = ReadU32(buffer_, 8);
    packet.checksum = ReadU32(buffer_, 12);
    if (packet.byteCount > kPacketMaxSize) {
      ++summary_.invalidPackets;
      QueueControl(kPacketTypeResend, 0);
      buffer_.erase(buffer_.begin());
      continue;
    }

    if (packet.leader == kControlPacketLeader) {
      buffer_.erase(buffer_.begin(), buffer_.begin() + kPacketHeaderBytes);
      ProcessControlPacket(packet);
      continue;
    }

    if (packet.leader != kPacketLeader) {
      ++summary_.invalidPackets;
      buffer_.erase(buffer_.begin());
      continue;
    }

    const size_t total = kPacketHeaderBytes + packet.byteCount + 1;
    if (buffer_.size() < total) {
      return;
    }

    packet.payload.assign(buffer_.begin() + kPacketHeaderBytes,
                          buffer_.begin() + kPacketHeaderBytes +
                              packet.byteCount);
    const uint8_t trailing = buffer_[kPacketHeaderBytes + packet.byteCount];
    buffer_.erase(buffer_.begin(), buffer_.begin() + total);

    if (trailing != kPacketTrailingByte) {
      ++summary_.trailingByteFailures;
      ++summary_.invalidPackets;
      QueueControl(kPacketTypeResend, 0);
      continue;
    }
    const uint32_t checksum = Checksum(packet.payload.data(),
                                       packet.payload.size());
    if (checksum != packet.checksum) {
      ++summary_.checksumFailures;
      ++summary_.invalidPackets;
      QueueControl(kPacketTypeResend, 0);
      continue;
    }
    ProcessDataPacket(packet);
  }
}

void KdSerialDebugger::ProcessControlPacket(const ParsedPacket &packet) {
  ++summary_.packetsReceived;
  ++summary_.controlPacketsReceived;
  summary_.lastPacketType = packet.packetType;
  summary_.lastPacketId = packet.packetId;

  KdSerialEvent event;
  event.kind = "control";
  event.packetType = packet.packetType;
  event.packetId = packet.packetId;
  event.detail = PacketTypeName(packet.packetType);

  switch (packet.packetType) {
  case kPacketTypeAcknowledge:
    ++summary_.targetAcksReceived;
    if (packet.packetId == NormalizePacketId(currentPacketId_)) {
      currentPacketId_ = NormalizePacketId(currentPacketId_) ^ 1u;
    }
    break;
  case kPacketTypeResend:
    ++summary_.targetResendsReceived;
    if (!lastSentPacket_.empty()) {
      replies_.insert(replies_.end(), lastSentPacket_.begin(),
                      lastSentPacket_.end());
    }
    break;
  case kPacketTypeReset:
    ++summary_.resetPacketsReceived;
    currentPacketId_ = kInitialPacketId | kSyncPacketId;
    expectedRemotePacketId_ = kInitialPacketId;
    QueueControl(kPacketTypeReset, 0);
    break;
  default:
    break;
  }
  RecordEvent(std::move(event));
}

void KdSerialDebugger::ProcessDataPacket(const ParsedPacket &packet) {
  ++summary_.packetsReceived;
  ++summary_.dataPacketsReceived;
  summary_.lastPacketType = packet.packetType;
  summary_.lastPacketId = packet.packetId;
  QueueControl(kPacketTypeAcknowledge, packet.packetId);

  if (NormalizePacketId(packet.packetId) == expectedRemotePacketId_) {
    expectedRemotePacketId_ ^= 1u;
  } else {
    ++summary_.duplicatePacketIds;
  }

  KdSerialEvent packetEvent;
  packetEvent.kind = "packet";
  packetEvent.packetType = packet.packetType;
  packetEvent.packetId = packet.packetId;
  packetEvent.byteCount = packet.byteCount;
  packetEvent.detail = PacketTypeName(packet.packetType);
  RecordEvent(std::move(packetEvent));

  switch (packet.packetType) {
  case kPacketTypeDebugIo:
    DecodeDebugIo(packet);
    break;
  case kPacketTypeStateChange64:
    DecodeStateChange(packet, true);
    break;
  case kPacketTypeStateChange32:
    DecodeStateChange(packet, false);
    break;
  case kPacketTypeStateManipulate:
    DecodeStateManipulate(packet);
    break;
  default:
    ++summary_.unknownDataPackets;
    break;
  }
}

void KdSerialDebugger::DecodeDebugIo(const ParsedPacket &packet) {
  if (packet.payload.size() < 12) {
    return;
  }
  const uint32_t api = ReadU32(packet.payload, 0);
  summary_.lastApiNumber = api;
  if (api != kDbgKdPrintStringApi) {
    return;
  }
  const uint32_t length = ReadU32(packet.payload, 8);
  size_t textOffset = 16;
  if (packet.payload.size() < textOffset + length && packet.payload.size() >= 12) {
    textOffset = 12;
  }
  if (textOffset > packet.payload.size()) {
    return;
  }
  const size_t available = packet.payload.size() - textOffset;
  const size_t count = std::min<size_t>(length, available);
  std::string text(reinterpret_cast<const char *>(packet.payload.data() +
                                                 textOffset),
                   count);
  text = CleanText(std::move(text));
  ++summary_.debugPrintPackets;
  summary_.debugPrintBytes += count;

  KdSerialEvent event;
  event.kind = "debug-print";
  event.packetType = packet.packetType;
  event.packetId = packet.packetId;
  event.byteCount = packet.byteCount;
  event.apiNumber = api;
  event.text = text;
  event.detail = ApiName(api);
  RecordEvent(std::move(event));
}

void KdSerialDebugger::DecodeStateChange(const ParsedPacket &packet,
                                         bool is64) {
  if (packet.payload.size() < 4) {
    return;
  }
  ++summary_.stateChangePackets;
  const uint32_t state = ReadU32(packet.payload, 0);
  summary_.lastApiNumber = state;

  KdSerialEvent event;
  event.kind = is64 ? "state-change64" : "state-change32";
  event.packetType = packet.packetType;
  event.packetId = packet.packetId;
  event.byteCount = packet.byteCount;
  event.apiNumber = state;
  event.detail = StateName(state);

  if (state == kDbgKdExceptionStateChange) {
    const uint32_t status = ReadU32(packet.payload, is64 ? 32 : 24);
    ++summary_.statusPackets;
    summary_.lastStatus = status;
    summary_.lastStatusText = Hex32(status);
    event.status = status;
    event.detail += " status=" + Hex32(status);
    RecordEvent(std::move(event));
    QueueAutoContinue();
    return;
  }

  if (state == kDbgKdLoadSymbolsStateChange) {
    ++summary_.loadSymbolPackets;
    const size_t loadOffset = is64 ? 32 : 24;
    const uint32_t pathLength = ReadU32(packet.payload, loadOffset);
    event.address = is64 ? ReadU64(packet.payload, loadOffset + 8)
                         : ReadU32(packet.payload, loadOffset + 4);
    event.size = ReadU32(packet.payload, loadOffset + (is64 ? 28 : 16));
    if (pathLength != 0 && pathLength <= packet.payload.size()) {
      const size_t pathOffset = packet.payload.size() - pathLength;
      event.text.assign(reinterpret_cast<const char *>(packet.payload.data() +
                                                       pathOffset),
                        pathLength);
      event.text = CleanText(std::move(event.text));
    }
    event.detail += " base=" + Hex64(event.address) +
                    " size=" + Hex32(event.size);
    RecordEvent(std::move(event));
    return;
  }

  RecordEvent(std::move(event));
}

void KdSerialDebugger::DecodeStateManipulate(const ParsedPacket &packet) {
  if (packet.payload.size() < 4) {
    return;
  }
  const uint32_t api = ReadU32(packet.payload, 0);
  summary_.lastApiNumber = api;
  KdSerialEvent event;
  event.kind = "state-manipulate";
  event.packetType = packet.packetType;
  event.packetId = packet.packetId;
  event.byteCount = packet.byteCount;
  event.apiNumber = api;
  event.detail = ApiName(api);
  RecordEvent(std::move(event));
}

void KdSerialDebugger::QueueControl(uint16_t packetType, uint32_t packetId) {
  auto bytes = EncodeControlPacket(packetType, packetId);
  replies_.insert(replies_.end(), bytes.begin(), bytes.end());
  if (packetType == kPacketTypeAcknowledge) {
    ++summary_.ackPacketsSent;
  } else if (packetType == kPacketTypeResend) {
    ++summary_.resendPacketsSent;
  } else if (packetType == kPacketTypeReset) {
    ++summary_.resetPacketsSent;
  }
}

void KdSerialDebugger::QueueAutoContinue() {
  std::vector<uint8_t> payload(48, 0);
  PutU32At(payload, 0, kDbgKdContinueApi);
  PutU32At(payload, 8, kStatusSuccess);
  PutU32At(payload, 16, kDbgContinue);
  lastSentPacket_ =
      EncodeDataPacket(kPacketTypeStateManipulate, currentPacketId_, payload);
  replies_.insert(replies_.end(), lastSentPacket_.begin(),
                  lastSentPacket_.end());
  ++summary_.autoContinuesSent;

  KdSerialEvent event;
  event.kind = "auto-continue";
  event.packetType = kPacketTypeStateManipulate;
  event.packetId = currentPacketId_;
  event.byteCount = static_cast<uint16_t>(payload.size());
  event.apiNumber = kDbgKdContinueApi;
  event.status = kDbgContinue;
  event.detail = "DbgKdContinueApi status=" + Hex32(kDbgContinue);
  RecordEvent(std::move(event));
}

void KdSerialDebugger::RecordEvent(KdSerialEvent event) {
  events_.push_back(event);
  std::ostringstream json;
  json << "{\"kind\":\"" << JsonEscapeLocal(event.kind) << "\""
       << ",\"packetType\":" << event.packetType
       << ",\"packetTypeName\":\"" << PacketTypeName(event.packetType) << "\""
       << ",\"packetId\":" << event.packetId
       << ",\"byteCount\":" << event.byteCount
       << ",\"apiNumber\":" << event.apiNumber
       << ",\"status\":" << event.status
       << ",\"address\":" << event.address
       << ",\"size\":" << event.size
       << ",\"detail\":\"" << JsonEscapeLocal(event.detail) << "\""
       << ",\"text\":\"" << JsonEscapeLocal(event.text) << "\"}\n";
  packetsJsonl_ += json.str();

  if (event.kind == "debug-print" && !event.text.empty()) {
    AppendTranscript(event.text);
  } else if (!event.detail.empty()) {
    AppendTranscript("[kd] " + event.kind + ": " + event.detail);
  }
}

void KdSerialDebugger::AppendTranscript(std::string_view line) {
  transcript_.append(line);
  if (transcript_.empty() || transcript_.back() != '\n') {
    transcript_.push_back('\n');
  }
}

} // namespace antimal::hv
