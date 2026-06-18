#pragma once

// Minimal classic-libpcap (.pcap) writer for LINKTYPE_ETHERNET frames — the
// capture artifact for the contained-network path. The e1000e NIC DMA-captures
// the guest's transmitted frames and the fake-internet sink synthesizes replies;
// both directions are appended here so a detonation produces a `network.pcap`
// that opens in Wireshark/tshark alongside the in-guest TCP-table telemetry.
//
// Pure + header-only: no clock, no I/O in Build() — the caller supplies a
// timestamp per frame (a monotonic counter is fine; pcap only needs the ordering
// + relative deltas to render a sane capture). `WriteFile` is the one I/O helper.
//
// Format (all fields little-endian; readers detect endianness from the magic):
//   Global header (24B): magic 0xA1B2C3D4, ver 2.4, thiszone 0, sigfigs 0,
//                        snaplen, network=1 (LINKTYPE_ETHERNET).
//   Per record (16B + data): ts_sec, ts_usec, incl_len (=min(len,snaplen)),
//                        orig_len (=len), then incl_len bytes.

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace antimal {

struct PcapFrame {
  std::vector<uint8_t> data;
  uint32_t tsSec = 0;   // capture timestamp (seconds); caller-supplied
  uint32_t tsUsec = 0;  // microseconds within the second
};

class PcapWriter {
 public:
  static constexpr uint32_t kLinkTypeEthernet = 1;
  static constexpr uint32_t kDefaultSnaplen = 65535;

  explicit PcapWriter(uint32_t snaplen = kDefaultSnaplen) : snaplen_(snaplen) {
    AppendGlobalHeader();
  }

  // Append one frame record. Frames longer than snaplen are truncated in the
  // capture (incl_len < orig_len), matching standard pcap snaplen behavior.
  void Append(const uint8_t *frame, size_t len, uint32_t tsSec, uint32_t tsUsec) {
    if (!frame && len) return;
    const uint32_t inclLen =
        len > snaplen_ ? snaplen_ : static_cast<uint32_t>(len);
    PutU32(tsSec);
    PutU32(tsUsec);
    PutU32(inclLen);
    PutU32(static_cast<uint32_t>(len));  // original (untruncated) length
    bytes_.insert(bytes_.end(), frame, frame + inclLen);
    ++frameCount_;
  }

  void Append(const PcapFrame &f) {
    Append(f.data.data(), f.data.size(), f.tsSec, f.tsUsec);
  }

  const std::vector<uint8_t> &Bytes() const noexcept { return bytes_; }
  size_t FrameCount() const noexcept { return frameCount_; }

  // Build a complete capture from a frame list in one call (convenience).
  static std::vector<uint8_t> Build(const std::vector<PcapFrame> &frames,
                                    uint32_t snaplen = kDefaultSnaplen) {
    PcapWriter w(snaplen);
    for (const auto &f : frames) w.Append(f);
    return w.Bytes();
  }

  // Write the accumulated capture to disk. Returns false on open/write failure.
  bool WriteFile(const std::string &path) const {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char *>(bytes_.data()),
              static_cast<std::streamsize>(bytes_.size()));
    return static_cast<bool>(out);
  }

 private:
  void PutU16(uint16_t v) {
    bytes_.push_back(static_cast<uint8_t>(v & 0xFF));
    bytes_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  }
  void PutU32(uint32_t v) {
    for (int i = 0; i < 4; ++i)
      bytes_.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
  }
  void AppendGlobalHeader() {
    PutU32(0xA1B2C3D4u);  // magic
    PutU16(2);            // version major
    PutU16(4);            // version minor
    PutU32(0);            // thiszone (GMT offset)
    PutU32(0);            // sigfigs
    PutU32(snaplen_);     // snaplen
    PutU32(kLinkTypeEthernet);
  }

  uint32_t snaplen_;
  std::vector<uint8_t> bytes_;
  size_t frameCount_ = 0;
};

}  // namespace antimal
