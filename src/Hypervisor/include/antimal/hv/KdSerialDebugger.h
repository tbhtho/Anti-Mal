#pragma once

// Minimal host-side KD serial speaker for the COM1 boot-debug transport.
// It is intentionally observational first: parse Windows KD packets, ACK
// valid target packets so retail boot components know a debugger is present,
// decode high-value debug-print / state-change payloads, and only send a
// conservative continue response for exception state changes.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace antimal::hv {

struct KdSerialEvent {
  std::string kind;
  uint16_t packetType = 0;
  uint32_t packetId = 0;
  uint16_t byteCount = 0;
  uint32_t apiNumber = 0;
  uint32_t status = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  std::string text;
  std::string detail;
};

struct KdSerialSummary {
  uint64_t bytesObserved = 0;
  uint64_t noiseBytes = 0;
  uint64_t packetsReceived = 0;
  uint64_t dataPacketsReceived = 0;
  uint64_t controlPacketsReceived = 0;
  uint64_t invalidPackets = 0;
  uint64_t checksumFailures = 0;
  uint64_t trailingByteFailures = 0;
  uint64_t duplicatePacketIds = 0;
  uint64_t ackPacketsSent = 0;
  uint64_t resendPacketsSent = 0;
  uint64_t resetPacketsReceived = 0;
  uint64_t resetPacketsSent = 0;
  uint64_t targetAcksReceived = 0;
  uint64_t targetResendsReceived = 0;
  uint64_t breakinsReceived = 0;
  uint64_t debugPrintPackets = 0;
  uint64_t debugPrintBytes = 0;
  uint64_t stateChangePackets = 0;
  uint64_t loadSymbolPackets = 0;
  uint64_t statusPackets = 0;
  uint64_t autoContinuesSent = 0;
  uint64_t unknownDataPackets = 0;
  uint16_t lastPacketType = 0;
  uint32_t lastPacketId = 0;
  uint32_t lastApiNumber = 0;
  uint32_t lastStatus = 0;
  std::string lastStatusText;
};

class KdSerialDebugger {
public:
  static constexpr uint32_t kInitialPacketId = 0x80800000u;
  static constexpr uint32_t kSyncPacketId = 0x00000800u;
  static constexpr uint32_t kPacketLeader = 0x30303030u;
  static constexpr uint32_t kControlPacketLeader = 0x69696969u;
  static constexpr uint32_t kBreakinPacket = 0x62626262u;
  static constexpr uint8_t kPacketTrailingByte = 0xAAu;

  static constexpr uint16_t kPacketTypeStateChange32 = 1;
  static constexpr uint16_t kPacketTypeStateManipulate = 2;
  static constexpr uint16_t kPacketTypeDebugIo = 3;
  static constexpr uint16_t kPacketTypeAcknowledge = 4;
  static constexpr uint16_t kPacketTypeResend = 5;
  static constexpr uint16_t kPacketTypeReset = 6;
  static constexpr uint16_t kPacketTypeStateChange64 = 7;
  static constexpr uint16_t kPacketTypePollBreakin = 8;
  static constexpr uint16_t kPacketTypeTraceIo = 9;
  static constexpr uint16_t kPacketTypeControlRequest = 10;
  static constexpr uint16_t kPacketTypeFileIo = 11;

  static constexpr uint32_t kDbgKdPrintStringApi = 0x00003230u;
  static constexpr uint32_t kDbgKdExceptionStateChange = 0x00003030u;
  static constexpr uint32_t kDbgKdLoadSymbolsStateChange = 0x00003031u;
  static constexpr uint32_t kDbgKdContinueApi = 0x00003136u;
  static constexpr uint32_t kDbgContinue = 0x00010002u;

  void PushBytes(const uint8_t *data, size_t size);
  void PushBytes(const std::string &bytes);

  void QueueHostReset(std::string_view reason);
  std::vector<uint8_t> PullReplies();

  const KdSerialSummary &Summary() const noexcept { return summary_; }
  const std::vector<KdSerialEvent> &Events() const noexcept { return events_; }
  const std::string &Transcript() const noexcept { return transcript_; }
  const std::string &PacketsJsonl() const noexcept { return packetsJsonl_; }

  static uint32_t Checksum(const uint8_t *data, size_t size) noexcept;
  static std::vector<uint8_t> EncodeControlPacket(uint16_t packetType,
                                                  uint32_t packetId);
  static std::vector<uint8_t> EncodeDataPacket(uint16_t packetType,
                                               uint32_t packetId,
                                               const std::vector<uint8_t> &payload);
  static std::vector<uint8_t> EncodeDebugPrintPacket(std::string_view text,
                                                     uint32_t packetId);
  static std::vector<uint8_t> EncodeStateChange64Packet(uint32_t newState,
                                                        uint32_t status,
                                                        std::string_view text,
                                                        uint32_t packetId);

private:
  struct ParsedPacket {
    uint32_t leader = 0;
    uint16_t packetType = 0;
    uint16_t byteCount = 0;
    uint32_t packetId = 0;
    uint32_t checksum = 0;
    std::vector<uint8_t> payload;
  };

  void TryDecode();
  void ProcessControlPacket(const ParsedPacket &packet);
  void ProcessDataPacket(const ParsedPacket &packet);
  void DecodeDebugIo(const ParsedPacket &packet);
  void DecodeStateChange(const ParsedPacket &packet, bool is64);
  void DecodeStateManipulate(const ParsedPacket &packet);
  void QueueControl(uint16_t packetType, uint32_t packetId);
  void QueueAutoContinue();
  void RecordEvent(KdSerialEvent event);
  void AppendTranscript(std::string_view line);

  std::vector<uint8_t> buffer_;
  std::vector<uint8_t> replies_;
  std::vector<uint8_t> lastSentPacket_;
  std::vector<KdSerialEvent> events_;
  std::string transcript_;
  std::string packetsJsonl_;
  KdSerialSummary summary_;
  uint32_t currentPacketId_ = kInitialPacketId | kSyncPacketId;
  uint32_t expectedRemotePacketId_ = kInitialPacketId;
};

} // namespace antimal::hv
