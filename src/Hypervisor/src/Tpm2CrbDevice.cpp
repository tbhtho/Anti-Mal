#include "antimal/hv/Tpm2CrbDevice.h"

#include <algorithm>
#include <cstring>

namespace antimal::hv {

namespace {

// Compose the IDENTIFIER reported in TPM_INTERFACE_ID_x for OVMF's
// Tcg2Pei / Tcg2Dxe probe. Layout (32-bit):
//   [3:0]   InterfaceType         = 1 (CRB)
//   [7:4]   InterfaceVersion      = 1 (CRB version 1)
//   [12:8]  CapLocality           = 5'b00001 (locality 0 only — we only emulate L0)
//   [16:13] CapCRBIdleBypass      = 0
//   [18:17] CapDataXferSizeSupport = 11b (64 byte)
//   [19]    CapFIFO               = 0
//   [20]    CapCRB                = 1
//   [26:21] Reserved 0
//   [28:27] InterfaceSelector     = 00 (current)
//   [29]    IntfSelLock           = 0
//   [31:30] Reserved 0
constexpr uint32_t kInterfaceIdValue =
    (1u << 0) |        // InterfaceType = CRB
    (1u << 4) |        // InterfaceVersion = 1
    (1u << 8) |        // CapLocality = locality 0
    (0x3u << 17) |     // CapDataXferSizeSupport = 64B
    (1u << 20);        // CapCRB = 1

// Legacy TPM_INTF_CAPABILITY (deprecated in PTP 1.05, but some drivers still
// peek). Same fields, slightly different bit layout — return a similarly
// sane value so callers that read either get a "real TPM" signal.
constexpr uint32_t kIntfCapabilityValue =
    (1u << 0) |        // InterfaceVersion = 1.21+
    (1u << 8) |        // InterfaceSelector capable
    (1u << 28);        // BurstCountStatic etc.

} // namespace

Tpm2CrbDevice::Tpm2CrbDevice(uint64_t mmioBase) : mmioBase_(mmioBase) {}

bool Tpm2CrbDevice::OnRead(uint64_t gpa, uint8_t accessSize,
                           uint64_t *outValue) {
  if (!outValue || gpa < mmioBase_ || gpa > MmioLast()) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  ++reads_;

  // Reads inside the shared data buffer: return whatever's there. This is the
  // window the host (us) wrote command responses into.
  if (offset >= kDataBufferOffset) {
    const uint64_t local = offset - kDataBufferOffset;
    if (local + accessSize > buffer_.size()) {
      *outValue = 0;
      return true;
    }
    uint64_t value = 0;
    std::memcpy(&value, buffer_.data() + local, accessSize);
    *outValue = value;
    return true;
  }

  // Locality register file.
  switch (offset & ~0x3ull) {
  case kRegLocState:
    // 8-bit register at byte offset 0; access can be byte/word/dword on
    // most drivers — splat the locState_ into the low byte and zero up.
    *outValue = static_cast<uint64_t>(locState_);
    return true;
  case kRegLocCtrl:
    *outValue = static_cast<uint64_t>(locCtrl_);
    return true;
  case kRegLocSts:
    *outValue = static_cast<uint64_t>(locSts_);
    return true;
  case kRegInterfaceId:
    *outValue = kInterfaceIdValue;
    return true;
  case kRegIntfCapability:
    *outValue = kIntfCapabilityValue;
    return true;
  case kRegCtrlReq:
    *outValue = crbCtrlReq_;
    return true;
  case kRegCtrlSts:
    *outValue = crbCtrlSts_;
    return true;
  case kRegCtrlCancel:
    *outValue = crbCtrlCancel_;
    return true;
  case kRegCtrlStart:
    *outValue = crbCtrlStart_;
    return true;
  case kRegIntEnable:
    *outValue = crbIntEnable_;
    return true;
  case kRegIntSts:
    *outValue = crbIntSts_;
    return true;
  case kRegCmdSize:
    *outValue = cmdSize_;
    return true;
  case kRegCmdLAddr:
    *outValue = cmdLAddr_;
    return true;
  case kRegCmdHAddr:
    *outValue = cmdHAddr_;
    return true;
  case kRegRspSize:
    *outValue = rspSize_;
    return true;
  case kRegRspLAddr:
    *outValue = rspLAddr_;
    return true;
  case kRegRspHAddr:
    *outValue = rspHAddr_;
    return true;
  default:
    *outValue = 0;
    return true;
  }
}

bool Tpm2CrbDevice::OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  if (gpa < mmioBase_ || gpa > MmioLast()) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  ++writes_;

  // Writes into the shared data buffer: store the bytes verbatim.
  if (offset >= kDataBufferOffset) {
    const uint64_t local = offset - kDataBufferOffset;
    if (local + accessSize > buffer_.size()) {
      return true;
    }
    std::memcpy(buffer_.data() + local, &value, accessSize);
    return true;
  }

  // Locality register file. Most CRB registers are write-anywhere within
  // their 4-byte slot; we accept any access size.
  switch (offset & ~0x3ull) {
  case kRegLocCtrl: {
    const uint8_t byte = static_cast<uint8_t>(value & 0xFFu);
    locCtrl_ = byte;
    // requestAccess: grant immediately (we are single-locality and never
    // contested). relinquishAccess: clear granted.
    if (byte & kLocCtrlRequestAccess) {
      locSts_ |= kLocStsGranted;
    }
    if (byte & kLocCtrlRelinquishAccess) {
      locSts_ &= static_cast<uint8_t>(~kLocStsGranted);
    }
    return true;
  }
  case kRegCtrlReq: {
    const auto v = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    crbCtrlReq_ = v;
    // cmdReady set by driver → we acknowledge readiness by clearing the
    // bit (CRB spec §6.5.1: driver writes 1 to request, TPM clears it
    // when ready). Also leave idle (we are ready, not idle).
    if (v & kCtrlReqCmdReady) {
      crbCtrlReq_ &= ~kCtrlReqCmdReady;
      crbCtrlSts_ &= ~kCtrlStsTpmIdle;
    }
    if (v & kCtrlReqGoIdle) {
      crbCtrlReq_ &= ~kCtrlReqGoIdle;
      crbCtrlSts_ |= kCtrlStsTpmIdle;
    }
    return true;
  }
  case kRegCtrlSts:
    // STS is mostly RO from the driver's perspective, but writing 1 to
    // tpmSts clears it (spec §6.5.1).
    if (value & kCtrlStsTpmSts) {
      crbCtrlSts_ &= ~kCtrlStsTpmSts;
    }
    return true;
  case kRegCtrlCancel:
    crbCtrlCancel_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegCtrlStart: {
    const auto v = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    crbCtrlStart_ = v;
    // Driver writes 1 to bit 0 to start command processing. We run the
    // command synchronously, write the response, then clear the start
    // bit and set tpmSts=0 (success) / tpmIdle=0 (busy=no).
    if (v & kCtrlStartGo) {
      RunCommand();
      crbCtrlStart_ &= ~kCtrlStartGo;
    }
    return true;
  }
  case kRegIntEnable:
    crbIntEnable_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegIntSts:
    // INT_STS: writing 1 clears the bit (RW1C semantics).
    crbIntSts_ &= ~static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegCmdSize:
    cmdSize_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegCmdLAddr:
    cmdLAddr_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegCmdHAddr:
    cmdHAddr_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegRspSize:
    rspSize_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegRspLAddr:
    rspLAddr_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  case kRegRspHAddr:
    rspHAddr_ = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return true;
  default:
    return true;
  }
}

void Tpm2CrbDevice::RunCommand() {
  ++commandsProcessed_;
  // Parse the request header (TPM2 command header is 10 bytes, big-endian):
  //   uint16  tag        (TPM_ST_NO_SESSIONS / TPM_ST_SESSIONS)
  //   uint32  commandSize
  //   uint32  commandCode
  if (buffer_.size() < 10) {
    lastResponseCode_ = kTpmRcSuccess;
    WriteSuccessResponseHeader(0);
    crbCtrlSts_ &= ~kCtrlStsTpmSts;
    return;
  }
  const uint32_t commandCode = ReadBe32(buffer_.data() + 6);
  lastCommandCode_ = commandCode;
  lastResponseCode_ = kTpmRcSuccess;

  // For the stub, EVERY command returns the canonical "no error, empty body"
  // response. That's enough to:
  //   - Pass TPM2_Startup (winload's first call).
  //   - Pass TPM2_SelfTest, TPM2_GetTestResult.
  //   - Pass TPM2_PCR_Extend (we silently discard the extend).
  //
  // Commands that NEED structured response data (TPM2_GetCapability,
  // TPM2_GetRandom, TPM2_PCR_Read) get an empty success body. Most
  // capability queries treat "missing property" as "zero", which is
  // acceptable for boot-time probes that just want "TPM is alive".
  WriteSuccessResponseHeader(0);
  crbCtrlSts_ &= ~kCtrlStsTpmSts;
}

void Tpm2CrbDevice::WriteSuccessResponseHeader(uint32_t additionalBodyBytes) {
  // 10-byte TPM2 response header, big-endian.
  const uint32_t totalSize = 10u + additionalBodyBytes;
  WriteBe16(buffer_.data() + 0, kTpmStNoSessions);
  WriteBe32(buffer_.data() + 2, totalSize);
  WriteBe32(buffer_.data() + 6, kTpmRcSuccess);
  rspSize_ = totalSize;
}

uint16_t Tpm2CrbDevice::ReadBe16(const uint8_t *p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t Tpm2CrbDevice::ReadBe32(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void Tpm2CrbDevice::WriteBe16(uint8_t *p, uint16_t v) {
  p[0] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  p[1] = static_cast<uint8_t>(v & 0xFFu);
}

void Tpm2CrbDevice::WriteBe32(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  p[3] = static_cast<uint8_t>(v & 0xFFu);
}

} // namespace antimal::hv
