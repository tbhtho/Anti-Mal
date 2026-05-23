#pragma once

// Minimal TPM 2.0 CRB (Command/Response Buffer) MMIO stub.
//
// What this is for: Win11 24H2 winload's Code Integrity / VBS init path
// queries the UEFI TCG2 protocol for a present TPM. OVMF only installs
// TCG2 if it finds working CRB MMIO at the ACPI-advertised address and
// the TPM responds to TPM2_Startup. Without that, ci.dll / VBS init
// inside winload aborts and bootmgr renders 0xc0000225.
//
// What this is NOT: a real TPM. Every command returns TPM_RC_SUCCESS
// with a zero-payload response. Real PCR extends are discarded. Real
// random numbers come from a deterministic counter, not /dev/urandom.
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
#include <vector>

namespace antimal::hv {

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
  static constexpr uint64_t kRegInterfaceId     = 0x30; // 4 bytes
  static constexpr uint64_t kRegIntfCapability  = 0x34; // 4 bytes
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

  // TPM2 wire constants (big-endian on the wire).
  static constexpr uint16_t kTpmStNoSessions = 0x8001;
  static constexpr uint32_t kTpmRcSuccess    = 0x00000000;

  void RunCommand();
  void WriteSuccessResponseHeader(uint32_t additionalBodyBytes);
  static uint16_t ReadBe16(const uint8_t *p);
  static uint32_t ReadBe32(const uint8_t *p);
  static void WriteBe16(uint8_t *p, uint16_t v);
  static void WriteBe32(uint8_t *p, uint32_t v);

  uint64_t mmioBase_;

  // Locality-0 register file.
  uint8_t  locState_ = kLocStateRegValidSts;  // bit 7 = valid; activeLocality=0
  uint8_t  locCtrl_ = 0;
  uint8_t  locSts_ = 0;                       // bit 0 cleared until request
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
};

} // namespace antimal::hv
