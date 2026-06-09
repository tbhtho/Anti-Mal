#pragma once

// Minimal TPM 2.0 CRB (Command/Response Buffer) MMIO stub.
//
// What this is for: Win11 24H2 winload's Code Integrity / VBS init path
// queries the UEFI TCG2 protocol for a present TPM. OVMF only installs
// TCG2 if it finds working CRB MMIO at the ACPI-advertised address and
// the TPM responds to TPM2_Startup. Without that, ci.dll / VBS init
// inside winload aborts and bootmgr renders 0xc0000225.
//
// What this is NOT: a real TPM. Only the boot-time command shapes used by
// OVMF/winload return structured payloads. Real PCR extends are discarded.
// Real random numbers come from a deterministic counter, not /dev/urandom.
// We are forging "TPM is present and healthy" so winload's existence
// check stops gating boot. Any real cryptographic operation that
// actually relies on the TPM's responses (BitLocker unlock, measured-
// boot attestation) WILL break — which is fine, AntiMal does not boot
// a sealed image.
//
// Layout: standard TPM PTP 1.05 CRB interface. The control area lives
// at GPA 0xFED40040 (which the ACPI TPM2 table advertises), the data
// buffer at 0xFED40080..0xFED40FFF. We map 4 KiB total at 0xFED40000.

#include "antimal/hv/Device.h"

#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace antimal::hv {

struct TpmPcrDigestTrace {
  uint16_t algorithm = 0;
  std::vector<uint8_t> inputDigest;
  std::vector<uint8_t> resultingPcr;
};

struct TpmPcrExtendTrace {
  uint64_t sequence = 0;
  uint32_t pcrIndex = 0;
  std::vector<TpmPcrDigestTrace> digests;
};

// The TPM identity words the device actually reports for TPM_PT_MANUFACTURER +
// VENDOR_STRING_1..4 (properties 0x105-0x109). Defined here as the SINGLE source
// of truth (the device's property table indexes this array, and the anti-evasion
// unit test asserts these exact bytes carry no sandbox-identifying ASCII) so the
// test guards the shipped value rather than a hand-copied mirror. Big-endian per
// the TPM wire: STMicroelectronics ("STM "), consistent with the Dell OptiPlex
// SMBIOS identity. NEVER let any of these decode to AntiMal/ANTIMAL/AMAL/Anti/Mal.
inline constexpr std::array<uint32_t, 5> kTpmIdentityWords = {
    0x53544D20u, // TPM_PT_MANUFACTURER  "STM "
    0x53544D20u, // VENDOR_STRING_1      "STM "
    0x53543333u, // VENDOR_STRING_2      "ST33"
    0x48545048u, // VENDOR_STRING_3      "HTPH"
    0x322E3200u, // VENDOR_STRING_4      "2.2\0"
};

class Tpm2CrbDevice final : public IMmioDevice {
public:
  static constexpr uint64_t kDefaultMmioBase = 0xFED40000ull;
  static constexpr uint64_t kMmioSize = 0x1000ull;
  static constexpr uint64_t kControlAreaOffset = 0x40ull;
  static constexpr uint64_t kDataBufferOffset = 0x80ull;
  static constexpr uint64_t kDataBufferSize = kMmioSize - kDataBufferOffset;

  explicit Tpm2CrbDevice(uint64_t mmioBase = kDefaultMmioBase);

  uint64_t MmioBase() const noexcept override { return mmioBase_; }
  uint64_t MmioLast() const noexcept override {
    return mmioBase_ + kMmioSize - 1;
  }

  bool OnRead(uint64_t gpa, uint8_t accessSize, uint64_t *outValue) override;
  bool OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) override;

  // Diagnostics — exposed for unit tests + run summaries.
  uint64_t Reads() const noexcept { return reads_; }
  uint64_t Writes() const noexcept { return writes_; }
  uint64_t CommandsProcessed() const noexcept { return commandsProcessed_; }
  uint32_t LastCommandCode() const noexcept { return lastCommandCode_; }
  uint32_t LastResponseCode() const noexcept { return lastResponseCode_; }
  uint64_t LastReadOffset() const noexcept { return lastReadOffset_; }
  uint64_t LastWriteOffset() const noexcept { return lastWriteOffset_; }
  const std::map<uint32_t, uint64_t> &CommandHistogram() const noexcept {
    return commandHistogram_;
  }
  const std::vector<uint32_t> &RecentCommands() const noexcept {
    return recentCommands_;
  }
  const std::vector<TpmPcrExtendTrace> &PcrExtendTrace() const noexcept {
    return pcrExtendTrace_;
  }
  const std::array<std::array<uint8_t, 20>, 24> &PcrSha1Bank()
      const noexcept {
    return pcrSha1_;
  }
  const std::array<std::array<uint8_t, 32>, 24> &PcrSha256Bank()
      const noexcept {
    return pcrSha256_;
  }
  // Host-side PCR extend, used by VirtualMachine when it pre-populates the
  // ACPI TPM 2.0 event log with pretend firmware measurements (e.g. the
  // mandatory PCR0..7 EV_SEPARATOR entries). Mirrors PCR_Extend in semantics
  // but bypasses the CRB command channel — see Tpm2CrbDevice.cpp::RunCommand.
  // algId: 0x0004 = SHA1, 0x000B = SHA256.
  bool ExtendInternal(uint32_t pcrIndex, uint16_t algId, const uint8_t *digest,
                      size_t digestSize);

  uint32_t InterfaceIdRegister() const noexcept { return interfaceId_; }
  uint8_t LocStateRegister() const noexcept { return locState_; }
  uint8_t LocStsRegister() const noexcept { return locSts_; }
  uint32_t CrbCtrlReq() const noexcept { return crbCtrlReq_; }
  uint32_t CrbCtrlSts() const noexcept { return crbCtrlSts_; }

private:
  // CRB Locality registers (offsets into MMIO base).
  // See Intel/TCG TPM PTP 1.05 §6.5 (CRB Idle/Ready) and §6.5.2 (Locality).
  static constexpr uint64_t kRegLocState        = 0x00; // 1 byte (we widen to 4-byte access)
  static constexpr uint64_t kRegLocCtrl         = 0x08; // 1 byte
  static constexpr uint64_t kRegLocSts          = 0x0C; // 1 byte
  static constexpr uint64_t kRegFifoIntfCap     = 0x14; // 4 bytes, FIFO alias
  static constexpr uint64_t kRegFifoStatusEx    = 0x1B; // 1 byte, FIFO alias
  static constexpr uint64_t kRegInterfaceId     = 0x30; // 4 bytes
  static constexpr uint64_t kRegVid             = 0x34; // 2 bytes
  static constexpr uint64_t kRegDid             = 0x36; // 2 bytes
  static constexpr uint64_t kRegCtrlExt         = 0x38; // 8 bytes
  static constexpr uint64_t kRegCtrlReq         = 0x40; // 4 bytes
  static constexpr uint64_t kRegCtrlSts         = 0x44; // 4 bytes
  static constexpr uint64_t kRegCtrlCancel      = 0x48; // 4 bytes
  static constexpr uint64_t kRegCtrlStart       = 0x4C; // 4 bytes
  static constexpr uint64_t kRegIntEnable       = 0x50; // 4 bytes
  static constexpr uint64_t kRegIntSts          = 0x54; // 4 bytes
  static constexpr uint64_t kRegCmdSize         = 0x58; // 4 bytes
  static constexpr uint64_t kRegCmdLAddr        = 0x5C; // 4 bytes
  static constexpr uint64_t kRegCmdHAddr        = 0x60; // 4 bytes
  static constexpr uint64_t kRegRspSize         = 0x64; // 4 bytes
  static constexpr uint64_t kRegRspLAddr        = 0x68; // 4 bytes
  static constexpr uint64_t kRegRspHAddr        = 0x6C; // 4 bytes

  // Bit definitions used by the state machine.
  static constexpr uint8_t  kLocCtrlRequestAccess    = 1u << 0;
  static constexpr uint8_t  kLocCtrlRelinquishAccess = 1u << 1;
  static constexpr uint8_t  kLocStsGranted           = 1u << 0;
  static constexpr uint8_t  kLocStateRegValidSts     = 1u << 7;
  static constexpr uint32_t kCtrlReqCmdReady         = 1u << 0;
  static constexpr uint32_t kCtrlReqGoIdle           = 1u << 1;
  static constexpr uint32_t kCtrlStsTpmSts           = 1u << 0;
  static constexpr uint32_t kCtrlStsTpmIdle          = 1u << 1;
  static constexpr uint32_t kCtrlStartGo             = 1u << 0;
  static constexpr uint32_t kInterfaceSelectorMask   = 0x3u << 17;

  // TPM2 wire constants (big-endian on the wire).
  static constexpr uint16_t kTpmStNoSessions = 0x8001;
  static constexpr uint16_t kTpmStSessions   = 0x8002;
  static constexpr uint32_t kTpmRcSuccess    = 0x00000000;

  uint64_t ReadRegisterWindow(uint64_t offset, uint8_t accessSize) const;
  void RunCommand();
  void ApplyPcrExtend(const uint8_t *command, uint32_t commandSize);
  std::vector<uint8_t> BuildPcrReadResponseBody(const uint8_t *command,
                                                uint32_t commandSize) const;
  void WriteSuccessResponseHeader(uint16_t responseTag,
                                  uint32_t additionalBodyBytes);
  void WriteSuccessResponseBody(uint16_t responseTag,
                                const std::vector<uint8_t> &body);
  static uint16_t ReadBe16(const uint8_t *p);
  static uint32_t ReadBe32(const uint8_t *p);
  static void WriteBe16(uint8_t *p, uint16_t v);
  static void WriteBe32(uint8_t *p, uint32_t v);

  uint64_t mmioBase_;

  // Locality-0 register file.
  uint8_t  locState_ = kLocStateRegValidSts;  // bit 7 = valid; activeLocality=0
  uint8_t  locCtrl_ = 0;
  uint8_t  locSts_ = 0;                       // bit 0 cleared until request
  uint32_t interfaceId_ = 0;
  uint64_t crbControlExtension_ = 0;
  uint32_t crbCtrlReq_ = 0;
  uint32_t crbCtrlSts_ = kCtrlStsTpmIdle;     // start idle
  uint32_t crbCtrlCancel_ = 0;
  uint32_t crbCtrlStart_ = 0;
  uint32_t crbIntEnable_ = 0;
  uint32_t crbIntSts_ = 0;
  uint32_t cmdSize_ = static_cast<uint32_t>(kDataBufferSize);
  uint32_t cmdLAddr_ = 0;
  uint32_t cmdHAddr_ = 0;
  uint32_t rspSize_ = static_cast<uint32_t>(kDataBufferSize);
  uint32_t rspLAddr_ = 0;
  uint32_t rspHAddr_ = 0;

  // Shared command/response buffer (also addressable directly via MMIO).
  std::array<uint8_t, kDataBufferSize> buffer_{};

  // Diagnostics.
  uint64_t reads_ = 0;
  uint64_t writes_ = 0;
  uint64_t commandsProcessed_ = 0;
  uint32_t lastCommandCode_ = 0;
  uint32_t lastResponseCode_ = 0;
  uint64_t lastReadOffset_ = 0;
  uint64_t lastWriteOffset_ = 0;
  uint32_t pcrUpdateCounter_ = 0;
  uint32_t randomCounter_ = 0xA5A5A5A5u;
  uint64_t clockTicks_ = 1;
  std::array<std::array<uint8_t, 20>, 24> pcrSha1_{};
  std::array<std::array<uint8_t, 32>, 24> pcrSha256_{};
  std::vector<TpmPcrExtendTrace> pcrExtendTrace_;
  std::map<uint32_t, uint64_t> commandHistogram_;
  std::vector<uint32_t> recentCommands_;
};

} // namespace antimal::hv
