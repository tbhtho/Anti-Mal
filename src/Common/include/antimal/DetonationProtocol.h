#pragma once

// Detonation message schema layered on top of the AMCH framing (HostChannel.h).
//
// An *authorized* detonation is a host->guest JobStart frame whose JSON payload
// has kind=="execute" + allowSampleExecution==true, followed by one or more
// SampleChunk frames that deliver the sample bytes for [0, sampleBytes). The
// guest reassembles, writes the file, launches it, and streams telemetry.
//
// Header-only + dependency-light on purpose: both the host (Common) and the
// in-guest agent (links Common, built /MT) use these helpers, and they must
// parse only messages AntiMal itself produced, so the JSON handling is a small
// hand-rolled key lookup rather than a full parser.

#include "antimal/HostChannel.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace antimal {

inline std::string SampleKindForName(std::string_view name) {
  if (name.size() < 4) return "exe";
  std::string suffix(name.substr(name.size() - 4));
  for (char &c : suffix) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return suffix == ".iso" ? "iso" : "exe";
}

inline bool PreferSampleDisk(std::string_view name, uint64_t bytes) {
  return SampleKindForName(name) == "iso" || bytes > 2ull * 1024 * 1024;
}

struct ExecuteJobRequest {
  bool isExecute = false;             // kind == "execute"
  bool allowSampleExecution = false;  // host authorized execution
  std::string sampleName;             // base file name to write in the guest
  uint64_t sampleBytes = 0;           // total sample size that will follow
  uint32_t timeoutMs = 180000;        // bound the detonation
  std::string networkMode = "disabled";
  std::string runId;
  // Delivery channel: "serial" = SampleChunk frames over COM2 (small samples);
  // "disk" = the sample file is exposed as a second read-only AHCI disk and the
  // guest copies it off the raw device (no size cap, disk-speed transfer).
  std::string delivery = "serial";
  // "exe" = launch the delivered file directly; "iso" = mount the delivered
  // image and launch the installer inside it.
  std::string sampleKind = "exe";
  // Byte size of the guest-visible sample disk (sector-padded). The guest finds
  // the raw device by matching this length, then reads sampleBytes from it.
  uint64_t diskBytes = 0;
};

// The guest-side sample-observation window derived from the host's run budget.
// `hostTimeoutMs == 0` means "until stopped" (the operator ends the run with
// vm_finalize): the guest must then run UNBOUNDED, not fall back to a small
// default -- a 0-to-60s collapse silently reaps a still-working sample (e.g. a
// GUI fixture the operator is about to interact with) while the host keeps
// running, which is exactly the 2026-09-18 "window never appeared" defect.
// A finite budget reserves the boot/transfer/launch/report margin first, but
// never hands the guest less than 60s.
inline uint32_t GuestSampleWindowMs(uint32_t hostTimeoutMs,
                                    uint64_t transferMs) {
  if (hostTimeoutMs == 0) {
    return 0; // propagate "until stopped"
  }
  const uint64_t marginMs = 300000ull + transferMs;
  return hostTimeoutMs > marginMs + 60000ull
             ? static_cast<uint32_t>(hostTimeoutMs - marginMs)
             : 60000u;
}

namespace detail {

// Returns the raw value token for "key" in a flat JSON object: the unescaped
// string contents for a string value, or the literal token (number/bool) for a
// non-string value. nullopt when the key is absent.
inline std::optional<std::string> JsonValueToken(std::string_view json,
                                                 std::string_view key) {
  std::string needle;
  needle.reserve(key.size() + 2);
  needle.push_back('"');
  needle.append(key);
  needle.push_back('"');
  const auto k = json.find(needle);
  if (k == std::string_view::npos) return std::nullopt;
  auto i = json.find(':', k + needle.size());
  if (i == std::string_view::npos) return std::nullopt;
  ++i;
  auto isWs = [](char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
  };
  while (i < json.size() && isWs(json[i])) ++i;
  if (i >= json.size()) return std::nullopt;
  if (json[i] == '"') {
    ++i;
    std::string out;
    while (i < json.size() && json[i] != '"') {
      if (json[i] == '\\' && i + 1 < json.size()) {
        const char n = json[i + 1];
        switch (n) {
          case 'n': out.push_back('\n'); break;
          case 't': out.push_back('\t'); break;
          case 'r': out.push_back('\r'); break;
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          default: out.push_back(n); break;
        }
        i += 2;
        continue;
      }
      out.push_back(json[i]);
      ++i;
    }
    return out;
  }
  const auto start = i;
  while (i < json.size() && json[i] != ',' && json[i] != '}' && json[i] != ']' &&
         !isWs(json[i])) {
    ++i;
  }
  return std::string(json.substr(start, i - start));
}

inline std::string JsonEscape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

}  // namespace detail

// Builds the JobStart JSON payload for an authorized execute job.
inline std::string BuildExecuteJobJson(const ExecuteJobRequest &req) {
  std::string out = "{";
  out += "\"kind\":\"execute\",";
  out += "\"allowSampleExecution\":";
  out += req.allowSampleExecution ? "true" : "false";
  out += ",\"sampleName\":\"" + detail::JsonEscape(req.sampleName) + "\"";
  out += ",\"sampleBytes\":" + std::to_string(req.sampleBytes);
  out += ",\"timeoutMs\":" + std::to_string(req.timeoutMs);
  out += ",\"networkMode\":\"" + detail::JsonEscape(req.networkMode) + "\"";
  if (!req.runId.empty()) {
    out += ",\"runId\":\"" + detail::JsonEscape(req.runId) + "\"";
  }
  out += ",\"delivery\":\"" + detail::JsonEscape(req.delivery) + "\"";
  out += ",\"sampleKind\":\"" + detail::JsonEscape(req.sampleKind) + "\"";
  if (req.diskBytes != 0) {
    out += ",\"diskBytes\":" + std::to_string(req.diskBytes);
  }
  out += "}";
  return out;
}

// Parses a JobStart payload. isExecute is true only when kind=="execute".
inline ExecuteJobRequest ParseExecuteJobJson(std::string_view payload) {
  ExecuteJobRequest req;
  if (const auto kind = detail::JsonValueToken(payload, "kind")) {
    req.isExecute = (*kind == "execute");
  }
  if (const auto allow = detail::JsonValueToken(payload, "allowSampleExecution")) {
    req.allowSampleExecution = (*allow == "true");
  }
  if (const auto name = detail::JsonValueToken(payload, "sampleName")) {
    req.sampleName = *name;
  }
  if (const auto bytes = detail::JsonValueToken(payload, "sampleBytes")) {
    try {
      req.sampleBytes = std::stoull(*bytes);
    } catch (...) {
      req.sampleBytes = 0;
    }
  }
  if (const auto to = detail::JsonValueToken(payload, "timeoutMs")) {
    try {
      req.timeoutMs = static_cast<uint32_t>(std::stoul(*to));
    } catch (...) {
    }
  }
  if (const auto net = detail::JsonValueToken(payload, "networkMode")) {
    req.networkMode = *net;
  }
  if (const auto run = detail::JsonValueToken(payload, "runId")) {
    req.runId = *run;
  }
  if (const auto delivery = detail::JsonValueToken(payload, "delivery")) {
    req.delivery = *delivery;
  }
  if (const auto kind = detail::JsonValueToken(payload, "sampleKind")) {
    req.sampleKind = *kind;
  }
  if (const auto disk = detail::JsonValueToken(payload, "diskBytes")) {
    try {
      req.diskBytes = std::stoull(*disk);
    } catch (...) {
      req.diskBytes = 0;
    }
  }
  return req;
}

// A single host->guest sample fragment: <u32 offset LE><bytes>.
struct SampleChunk {
  uint32_t offset = 0;
  std::vector<uint8_t> bytes;
};

// Encodes a SampleChunk as a full AMCH frame ready to write to the channel.
inline std::vector<uint8_t> EncodeSampleChunkFrame(uint32_t offset,
                                                   const uint8_t *data,
                                                   size_t len) {
  HostChannelFrame frame;
  frame.type = HostChannelMessage::SampleChunk;
  frame.payload.reserve(4 + len);
  for (int i = 0; i < 4; ++i) {
    frame.payload.push_back(static_cast<uint8_t>((offset >> (i * 8)) & 0xFFu));
  }
  if (data && len) frame.payload.insert(frame.payload.end(), data, data + len);
  return HostSerialChannel::Encode(frame);
}

// Parses a SampleChunk frame payload. nullopt if shorter than the 4-byte offset.
inline std::optional<SampleChunk> ParseSampleChunkPayload(
    const std::vector<uint8_t> &payload) {
  if (payload.size() < 4) return std::nullopt;
  SampleChunk chunk;
  chunk.offset = static_cast<uint32_t>(payload[0]) |
                 (static_cast<uint32_t>(payload[1]) << 8) |
                 (static_cast<uint32_t>(payload[2]) << 16) |
                 (static_cast<uint32_t>(payload[3]) << 24);
  chunk.bytes.assign(payload.begin() + 4, payload.end());
  return chunk;
}

// The single source of truth for the maximum sample size deliverable over the
// paced COM2 channel. The host refuses to SEND a larger sample and the guest
// reassembler refuses to ACCEPT one, so both sides agree on one bound.
constexpr uint64_t kMaxCom2SampleBytes = 8ull * 1024 * 1024;

// Reassembles in-order, non-overlapping SampleChunks into a contiguous buffer,
// bounded by expectedBytes and a hard cap. The host sends chunks sequentially,
// so out-of-order or overflowing fragments are rejected rather than tolerated.
class SampleReassembler {
 public:
  explicit SampleReassembler(uint64_t expectedBytes,
                             uint64_t capBytes = kMaxCom2SampleBytes)
      : expected_(expectedBytes), cap_(capBytes) {
    if (expected_ <= cap_) buf_.reserve(static_cast<size_t>(expected_));
  }

  // Returns false (and ignores the chunk) on overflow, out-of-order delivery,
  // or an oversized job. A false return means the transfer is unrecoverable.
  bool Add(const SampleChunk &chunk) {
    if (expected_ == 0 || expected_ > cap_) return false;
    if (chunk.offset != received_) return false;
    if (received_ + chunk.bytes.size() > expected_) return false;
    buf_.insert(buf_.end(), chunk.bytes.begin(), chunk.bytes.end());
    received_ += chunk.bytes.size();
    return true;
  }

  bool Complete() const { return expected_ > 0 && received_ == expected_; }
  uint64_t Received() const { return received_; }
  uint64_t Expected() const { return expected_; }
  const std::vector<uint8_t> &Bytes() const { return buf_; }

 private:
  uint64_t expected_;
  uint64_t cap_;
  uint64_t received_ = 0;
  std::vector<uint8_t> buf_;
};

}  // namespace antimal
