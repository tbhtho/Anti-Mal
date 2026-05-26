#include "antimal/hv/Tpm2CrbDevice.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <utility>

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
    (0x3u << 11) |     // CapDataXferSizeSupport = 64B
    (1u << 14) |       // CapCRB = 1
    (0x1u << 17) |     // InterfaceSelector = CRB
    (0x1u << 24);      // Rid = 1

// Legacy TPM_INTF_CAPABILITY (deprecated in PTP 1.05, but some drivers still
// peek). Same fields, slightly different bit layout — return a similarly
// sane value so callers that read either get a "real TPM" signal.
constexpr uint32_t kFifoInterfaceCapabilityValue = 0;
constexpr uint8_t kFifoStatusExValue = 0;
constexpr uint16_t kVendorId = 0x1AF4; // Red Hat / QEMU virtio vendor ID.
constexpr uint16_t kDeviceId = 0x0001;

constexpr uint32_t kTpmCcHierarchyChangeAuth = 0x00000129;
constexpr uint32_t kTpmCcSelfTest = 0x00000143;
constexpr uint32_t kTpmCcStartup = 0x00000144;
constexpr uint32_t kTpmCcNvRead = 0x0000014E;
constexpr uint32_t kTpmCcGetCapability = 0x0000017A;
constexpr uint32_t kTpmCcGetRandom = 0x0000017B;
constexpr uint32_t kTpmCcPcrRead = 0x0000017E;
constexpr uint32_t kTpmCcReadClock = 0x00000181;
constexpr uint32_t kTpmCcPcrExtend = 0x00000182;

constexpr uint32_t kTpmCapAlgs = 0x00000000;
constexpr uint32_t kTpmCapCommands = 0x00000002;
constexpr uint32_t kTpmCapPcrs = 0x00000005;
constexpr uint32_t kTpmCapTpmProperties = 0x00000006;
constexpr uint32_t kTpmCapPcrProperties = 0x00000007;

constexpr uint16_t kTpmAlgSha1 = 0x0004;
constexpr uint16_t kTpmAlgSha256 = 0x000B;
constexpr uint16_t kTpmAlgSha384 = 0x000C;
constexpr uint16_t kTpmAlgSha512 = 0x000D;
constexpr uint32_t kTpmaAlgorithmHash = 1u << 2;

struct TpmProperty {
  uint32_t property;
  uint32_t value;
};

struct PcrSelection {
  uint16_t hash = kTpmAlgSha256;
  uint8_t sizeofSelect = 3;
  std::array<uint8_t, 3> pcrSelect{};
};

void AppendByte(std::vector<uint8_t> &out, uint8_t value) {
  out.push_back(value);
}

void AppendBe16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void AppendBe32(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void AppendBe64(std::vector<uint8_t> &out, uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
  }
}

void PatchBe32(std::vector<uint8_t> &out, size_t offset, uint32_t value) {
  if (offset + 4 > out.size()) {
    return;
  }
  out[offset + 0] = static_cast<uint8_t>((value >> 24) & 0xFFu);
  out[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFFu);
  out[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  out[offset + 3] = static_cast<uint8_t>(value & 0xFFu);
}

uint16_t ReadBe16Local(const uint8_t *p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t ReadBe32Local(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t DigestSizeForAlg(uint16_t hash) {
  switch (hash) {
  case kTpmAlgSha1:
    return 20;
  case kTpmAlgSha256:
    return 32;
  case kTpmAlgSha384:
    return 48;
  case kTpmAlgSha512:
    return 64;
  default:
    return 32;
  }
}

bool HashExtendDigest(const wchar_t *algorithm, const uint8_t *current,
                      size_t currentSize, const uint8_t *digest,
                      size_t digestSize, uint8_t *out, size_t outSize) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD objectBytes = 0;
  DWORD resultBytes = 0;
  bool ok = false;
  std::vector<uint8_t> hashObject;

  if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) < 0) {
    return false;
  }
  if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectBytes),
                        sizeof(objectBytes), &resultBytes, 0) < 0) {
    goto Done;
  }
  hashObject.resize(objectBytes);
  if (BCryptCreateHash(alg, &hash, hashObject.data(), objectBytes, nullptr, 0,
                       0) < 0) {
    goto Done;
  }
  if (BCryptHashData(hash, const_cast<PUCHAR>(current),
                     static_cast<ULONG>(currentSize), 0) < 0) {
    goto Done;
  }
  if (BCryptHashData(hash, const_cast<PUCHAR>(digest),
                     static_cast<ULONG>(digestSize), 0) < 0) {
    goto Done;
  }
  if (BCryptFinishHash(hash, out, static_cast<ULONG>(outSize), 0) < 0) {
    goto Done;
  }
  ok = true;

Done:
  if (hash) {
    BCryptDestroyHash(hash);
  }
  if (alg) {
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  return ok;
}

std::vector<uint8_t> BuildAlgCapability() {
  constexpr std::array<std::pair<uint16_t, uint32_t>, 4> kAlgs{{
      {kTpmAlgSha1, kTpmaAlgorithmHash},
      {kTpmAlgSha256, kTpmaAlgorithmHash},
      {kTpmAlgSha384, kTpmaAlgorithmHash},
      {kTpmAlgSha512, kTpmaAlgorithmHash},
  }};
  std::vector<uint8_t> out;
  AppendBe32(out, static_cast<uint32_t>(kAlgs.size()));
  for (const auto &[alg, attributes] : kAlgs) {
    AppendBe16(out, alg);
    AppendBe32(out, attributes);
  }
  return out;
}

std::vector<uint8_t> BuildCommandCapability(uint32_t property,
                                            uint32_t propertyCount) {
  constexpr std::array<uint32_t, 9> kCommands{{
      kTpmCcHierarchyChangeAuth,
      kTpmCcSelfTest,
      kTpmCcStartup,
      kTpmCcNvRead,
      kTpmCcGetCapability,
      kTpmCcGetRandom,
      kTpmCcPcrRead,
      kTpmCcReadClock,
      kTpmCcPcrExtend,
  }};

  const uint32_t maxCount = std::max<uint32_t>(propertyCount, 1);
  std::vector<uint8_t> out;
  AppendBe32(out, 0);
  uint32_t emitted = 0;
  for (const uint32_t command : kCommands) {
    if (command < property || emitted >= maxCount) {
      continue;
    }
    AppendBe32(out, command);
    ++emitted;
  }
  PatchBe32(out, 0, emitted);
  return out;
}

std::vector<uint8_t> BuildPcrCapability() {
  std::vector<uint8_t> out;
  AppendBe32(out, 2);
  AppendBe16(out, kTpmAlgSha1);
  AppendByte(out, 3);
  out.insert(out.end(), {0xFF, 0xFF, 0xFF});
  AppendBe16(out, kTpmAlgSha256);
  AppendByte(out, 3);
  out.insert(out.end(), {0xFF, 0xFF, 0xFF});
  return out;
}

std::vector<uint8_t> BuildTpmPropertyCapability(uint32_t property,
                                                uint32_t propertyCount) {
  constexpr std::array<TpmProperty, 44> kProperties{{
      {0x00000100, 0x322E3000}, // TPM_PT_FAMILY_INDICATOR: "2.0\0"
      {0x00000101, 0},
      {0x00000102, 0x00000138},
      {0x00000103, 1},
      {0x00000104, 2026},
      {0x00000105, 0x414D414C}, // TPM_PT_MANUFACTURER: "AMAL"
      {0x00000106, 0x416E7469}, // "Anti"
      {0x00000107, 0x4D616C20}, // "Mal "
      {0x00000108, 0x54504D32}, // "TPM2"
      {0x00000109, 0x53747562}, // "Stub"
      {0x0000010A, 0},
      {0x0000010B, 1},
      {0x0000010C, 0},
      {0x0000010D, 0x00000F80}, // TPM_PT_INPUT_BUFFER
      {0x0000010E, 3},
      {0x0000010F, 3},
      {0x00000110, 3},
      {0x00000111, 3},
      {0x00000112, 24}, // TPM_PT_PCR_COUNT
      {0x00000113, 3},  // TPM_PT_PCR_SELECT_MIN
      {0x00000114, 0xFFFF},
      {0x00000116, 0},
      {0x00000117, 0},
      {0x00000118, 0},
      {0x00000119, 1000},
      {0x0000011A, kTpmAlgSha256},
      {0x0000011B, 0x00000006},
      {0x0000011C, 128},
      {0x0000011D, 0},
      {0x0000011E, 0x00000F80}, // TPM_PT_MAX_COMMAND_SIZE
      {0x0000011F, 0x00000F80}, // TPM_PT_MAX_RESPONSE_SIZE
      {0x00000120, 64},         // TPM_PT_MAX_DIGEST
      {0x00000121, 1024},
      {0x00000122, 512},
      {0x00000129, 9}, // TPM_PT_TOTAL_COMMANDS
      {0x0000012A, 9},
      {0x0000012B, 0},
      {0x00000200, 0},
      {0x00000201, 0},
      {0x0000020C, 0},
      {0x0000020E, 0},
      {0x0000020F, 0},
      {0x00000210, 0},
      {0x00000211, 0},
  }};

  const uint32_t maxCount = std::max<uint32_t>(propertyCount, 1);
  std::vector<uint8_t> out;
  AppendBe32(out, 0);
  uint32_t emitted = 0;
  for (const auto &entry : kProperties) {
    if (entry.property < property || emitted >= maxCount) {
      continue;
    }
    AppendBe32(out, entry.property);
    AppendBe32(out, entry.value);
    ++emitted;
  }
  PatchBe32(out, 0, emitted);
  return out;
}

std::vector<uint8_t> BuildGetCapabilityResponse(const uint8_t *command,
                                                uint32_t commandSize) {
  uint32_t capability = kTpmCapTpmProperties;
  uint32_t property = 0;
  uint32_t propertyCount = 1;
  if (commandSize >= 22) {
    capability = ReadBe32Local(command + 10);
    property = ReadBe32Local(command + 14);
    propertyCount = ReadBe32Local(command + 18);
  }

  std::vector<uint8_t> data;
  switch (capability) {
  case kTpmCapAlgs:
    data = BuildAlgCapability();
    break;
  case kTpmCapCommands:
    data = BuildCommandCapability(property, propertyCount);
    break;
  case kTpmCapPcrs:
    data = BuildPcrCapability();
    break;
  case kTpmCapTpmProperties:
    data = BuildTpmPropertyCapability(property, propertyCount);
    break;
  case kTpmCapPcrProperties:
  default:
    AppendBe32(data, 0);
    break;
  }

  std::vector<uint8_t> body;
  AppendByte(body, 0); // moreData = NO
  AppendBe32(body, capability);
  body.insert(body.end(), data.begin(), data.end());
  return body;
}

std::vector<PcrSelection> ParsePcrSelections(const uint8_t *command,
                                             uint32_t commandSize) {
  std::vector<PcrSelection> selections;
  if (commandSize < 14) {
    return selections;
  }
  const uint32_t count = std::min<uint32_t>(ReadBe32Local(command + 10), 5);
  size_t offset = 14;
  for (uint32_t i = 0; i < count; ++i) {
    if (offset + 3 > commandSize) {
      break;
    }
    PcrSelection selection;
    selection.hash = ReadBe16Local(command + offset);
    const uint8_t requestedSelectBytes = command[offset + 2];
    selection.sizeofSelect = std::min<uint8_t>(requestedSelectBytes, 3);
    offset += 3;
    if (offset + requestedSelectBytes > commandSize) {
      break;
    }
    std::copy_n(command + offset, selection.sizeofSelect,
                selection.pcrSelect.begin());
    offset += requestedSelectBytes;
    selections.push_back(selection);
  }
  return selections;
}

std::vector<uint8_t> BuildGetRandomResponse(const uint8_t *command,
                                            uint32_t commandSize,
                                            uint32_t &randomCounter) {
  uint16_t requested = 32;
  if (commandSize >= 12) {
    requested = ReadBe16Local(command + 10);
  }
  const uint16_t returned = std::min<uint16_t>(requested, 64);
  std::vector<uint8_t> body;
  AppendBe16(body, returned);
  for (uint16_t i = 0; i < returned; ++i) {
    randomCounter = randomCounter * 1664525u + 1013904223u;
    body.push_back(static_cast<uint8_t>((randomCounter >> 24) & 0xFFu));
  }
  return body;
}

std::vector<uint8_t> BuildReadClockResponse(uint64_t &clockTicks) {
  clockTicks += 1000;
  std::vector<uint8_t> body;
  AppendBe64(body, clockTicks); // TPMS_TIME_INFO.time
  AppendBe64(body, clockTicks); // TPMS_CLOCK_INFO.clock
  AppendBe32(body, 0);          // resetCount
  AppendBe32(body, 0);          // restartCount
  AppendByte(body, 1);          // safe = YES
  return body;
}

std::vector<uint8_t> BuildSessionEmptyResponseBody() {
  std::vector<uint8_t> body;
  AppendBe32(body, 0); // parameterSize
  return body;
}

std::vector<uint8_t> BuildNvReadResponseBody() {
  std::vector<uint8_t> body;
  AppendBe32(body, 2); // parameterSize includes TPM2B_MAX_NV_BUFFER.size
  AppendBe16(body, 0); // empty NV buffer
  return body;
}

} // namespace

Tpm2CrbDevice::Tpm2CrbDevice(uint64_t mmioBase)
    : mmioBase_(mmioBase), interfaceId_(kInterfaceIdValue) {}

uint64_t Tpm2CrbDevice::ReadRegisterWindow(uint64_t offset,
                                           uint8_t accessSize) const {
  std::array<uint8_t, kDataBufferOffset> regs{};
  auto put = [&](uint64_t regOffset, uint64_t value, uint8_t width) {
    for (uint8_t i = 0; i < width && regOffset + i < regs.size(); ++i) {
      regs[static_cast<size_t>(regOffset + i)] =
          static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    }
  };

  put(kRegLocState, locState_, 4);
  put(kRegLocCtrl, locCtrl_, 4);
  put(kRegLocSts, locSts_, 4);
  put(kRegFifoIntfCap, kFifoInterfaceCapabilityValue, 4);
  put(kRegFifoStatusEx, kFifoStatusExValue, 1);
  put(kRegInterfaceId, interfaceId_, 4);
  put(kRegVid, kVendorId, 2);
  put(kRegDid, kDeviceId, 2);
  put(kRegCtrlExt, crbControlExtension_, 8);
  put(kRegCtrlReq, crbCtrlReq_, 4);
  put(kRegCtrlSts, crbCtrlSts_, 4);
  put(kRegCtrlCancel, crbCtrlCancel_, 4);
  put(kRegCtrlStart, crbCtrlStart_, 4);
  put(kRegIntEnable, crbIntEnable_, 4);
  put(kRegIntSts, crbIntSts_, 4);
  put(kRegCmdSize, cmdSize_, 4);
  put(kRegCmdLAddr, cmdLAddr_, 4);
  put(kRegCmdHAddr, cmdHAddr_, 4);
  put(kRegRspSize, rspSize_, 4);
  put(kRegRspLAddr, rspLAddr_, 4);
  put(kRegRspHAddr, rspHAddr_, 4);

  uint64_t value = 0;
  if (offset >= regs.size()) {
    return 0;
  }
  const uint8_t bytes = static_cast<uint8_t>(
      std::min<uint64_t>(accessSize, regs.size() - offset));
  std::memcpy(&value, regs.data() + offset, bytes);
  return value;
}

bool Tpm2CrbDevice::OnRead(uint64_t gpa, uint8_t accessSize,
                           uint64_t *outValue) {
  if (!outValue || gpa < mmioBase_ || gpa > MmioLast()) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  ++reads_;
  lastReadOffset_ = offset;

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

  if (offset < kDataBufferOffset) {
    *outValue = ReadRegisterWindow(offset, accessSize);
    return true;
  }

  *outValue = 0;
  return true;
}

bool Tpm2CrbDevice::OnWrite(uint64_t gpa, uint8_t accessSize, uint64_t value) {
  if (gpa < mmioBase_ || gpa > MmioLast()) {
    return false;
  }
  const uint64_t offset = gpa - mmioBase_;
  ++writes_;
  lastWriteOffset_ = offset;

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
  case kRegInterfaceId: {
    const auto requested = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    interfaceId_ = (interfaceId_ & ~kInterfaceSelectorMask) |
                   (requested & kInterfaceSelectorMask);
    return true;
  }
  case kRegCtrlExt:
    crbControlExtension_ = value;
    return true;
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
    if (accessSize == 8) {
      rspHAddr_ = static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFull);
    }
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
    WriteSuccessResponseHeader(kTpmStNoSessions, 0);
    crbCtrlSts_ &= ~kCtrlStsTpmSts;
    return;
  }
  const uint16_t requestTag = ReadBe16(buffer_.data());
  const uint32_t commandSize =
      std::min<uint32_t>(ReadBe32(buffer_.data() + 2),
                         static_cast<uint32_t>(buffer_.size()));
  const uint32_t commandCode = ReadBe32(buffer_.data() + 6);
  lastCommandCode_ = commandCode;
  lastResponseCode_ = kTpmRcSuccess;
  ++commandHistogram_[commandCode];
  recentCommands_.push_back(commandCode);
  constexpr size_t kMaxRecentCommands = 32;
  if (recentCommands_.size() > kMaxRecentCommands) {
    recentCommands_.erase(recentCommands_.begin(),
                          recentCommands_.begin() +
                              (recentCommands_.size() - kMaxRecentCommands));
  }

  std::vector<uint8_t> body;
  uint16_t responseTag = requestTag == kTpmStSessions ? kTpmStSessions
                                                      : kTpmStNoSessions;
  switch (commandCode) {
  case kTpmCcGetCapability:
    responseTag = kTpmStNoSessions;
    body = BuildGetCapabilityResponse(buffer_.data(), commandSize);
    break;
  case kTpmCcPcrRead:
    responseTag = kTpmStNoSessions;
    body = BuildPcrReadResponseBody(buffer_.data(), commandSize);
    break;
  case kTpmCcGetRandom:
    responseTag = kTpmStNoSessions;
    body = BuildGetRandomResponse(buffer_.data(), commandSize, randomCounter_);
    break;
  case kTpmCcReadClock:
    responseTag = kTpmStNoSessions;
    body = BuildReadClockResponse(clockTicks_);
    break;
  case kTpmCcPcrExtend:
    ApplyPcrExtend(buffer_.data(), commandSize);
    body = requestTag == kTpmStSessions ? BuildSessionEmptyResponseBody()
                                        : std::vector<uint8_t>{};
    break;
  case kTpmCcNvRead:
    body = requestTag == kTpmStSessions ? BuildNvReadResponseBody()
                                        : std::vector<uint8_t>{};
    break;
  default:
    body = requestTag == kTpmStSessions ? BuildSessionEmptyResponseBody()
                                        : std::vector<uint8_t>{};
    break;
  }

  WriteSuccessResponseBody(responseTag, body);
  crbCtrlSts_ &= ~kCtrlStsTpmSts;
}

void Tpm2CrbDevice::ApplyPcrExtend(const uint8_t *command,
                                   uint32_t commandSize) {
  if (!command || commandSize < 22) {
    return;
  }
  const uint32_t pcrHandle = ReadBe32(command + 10);
  if (pcrHandle >= pcrSha256_.size()) {
    return;
  }
  const uint32_t authSize = ReadBe32(command + 14);
  size_t offset = 18ull + authSize;
  if (offset + 4 > commandSize) {
    return;
  }

  const uint32_t digestCount = std::min<uint32_t>(ReadBe32(command + offset), 5);
  offset += 4;
  bool extended = false;
  TpmPcrExtendTrace trace;
  trace.sequence = static_cast<uint64_t>(pcrExtendTrace_.size() + 1);
  trace.pcrIndex = pcrHandle;
  for (uint32_t i = 0; i < digestCount; ++i) {
    if (offset + 2 > commandSize) {
      break;
    }
    const uint16_t hashAlg = ReadBe16(command + offset);
    offset += 2;
    const uint16_t digestSize = DigestSizeForAlg(hashAlg);
    if (offset + digestSize > commandSize) {
      break;
    }

    TpmPcrDigestTrace digestTrace;
    digestTrace.algorithm = hashAlg;
    digestTrace.inputDigest.assign(command + offset,
                                   command + offset + digestSize);
    if (hashAlg == kTpmAlgSha1) {
      std::array<uint8_t, 20> next{};
      if (HashExtendDigest(BCRYPT_SHA1_ALGORITHM,
                           pcrSha1_[pcrHandle].data(),
                           pcrSha1_[pcrHandle].size(), command + offset,
                           digestSize, next.data(), next.size())) {
        pcrSha1_[pcrHandle] = next;
        digestTrace.resultingPcr.assign(next.begin(), next.end());
        extended = true;
      }
    } else if (hashAlg == kTpmAlgSha256) {
      std::array<uint8_t, 32> next{};
      if (HashExtendDigest(BCRYPT_SHA256_ALGORITHM,
                           pcrSha256_[pcrHandle].data(),
                           pcrSha256_[pcrHandle].size(), command + offset,
                           digestSize, next.data(), next.size())) {
        pcrSha256_[pcrHandle] = next;
        digestTrace.resultingPcr.assign(next.begin(), next.end());
        extended = true;
      }
    }
    trace.digests.push_back(std::move(digestTrace));
    offset += digestSize;
  }

  if (!trace.digests.empty()) {
    pcrExtendTrace_.push_back(std::move(trace));
  }
  if (extended) {
    ++pcrUpdateCounter_;
  }
}

std::vector<uint8_t> Tpm2CrbDevice::BuildPcrReadResponseBody(
    const uint8_t *command, uint32_t commandSize) const {
  const auto inputSelections = ParsePcrSelections(command, commandSize);
  std::vector<PcrSelection> outputSelections;
  std::vector<std::pair<uint16_t, uint8_t>> digestRequests;

  for (const auto &input : inputSelections) {
    PcrSelection output = input;
    output.pcrSelect = {};
    bool hasSelection = false;
    for (uint8_t byteIndex = 0; byteIndex < input.sizeofSelect; ++byteIndex) {
      for (uint8_t bit = 0; bit < 8; ++bit) {
        if ((input.pcrSelect[byteIndex] & (1u << bit)) == 0) {
          continue;
        }
        const uint8_t pcrIndex = static_cast<uint8_t>(byteIndex * 8 + bit);
        if (pcrIndex >= pcrSha256_.size() || digestRequests.size() >= 8) {
          continue;
        }
        output.pcrSelect[byteIndex] |= static_cast<uint8_t>(1u << bit);
        digestRequests.emplace_back(input.hash, pcrIndex);
        hasSelection = true;
      }
    }
    if (hasSelection) {
      outputSelections.push_back(output);
    }
  }

  std::vector<uint8_t> body;
  AppendBe32(body, pcrUpdateCounter_);
  AppendBe32(body, static_cast<uint32_t>(outputSelections.size()));
  for (const auto &selection : outputSelections) {
    AppendBe16(body, selection.hash);
    AppendByte(body, selection.sizeofSelect);
    body.insert(body.end(), selection.pcrSelect.begin(),
                selection.pcrSelect.begin() + selection.sizeofSelect);
  }
  AppendBe32(body, static_cast<uint32_t>(digestRequests.size()));
  for (const auto &[alg, pcrIndex] : digestRequests) {
    AppendBe16(body, DigestSizeForAlg(alg));
    if (alg == kTpmAlgSha1) {
      body.insert(body.end(), pcrSha1_[pcrIndex].begin(),
                  pcrSha1_[pcrIndex].end());
    } else if (alg == kTpmAlgSha256) {
      body.insert(body.end(), pcrSha256_[pcrIndex].begin(),
                  pcrSha256_[pcrIndex].end());
    } else {
      body.insert(body.end(), DigestSizeForAlg(alg), 0);
    }
  }
  return body;
}

void Tpm2CrbDevice::WriteSuccessResponseHeader(uint16_t responseTag,
                                               uint32_t additionalBodyBytes) {
  // 10-byte TPM2 response header, big-endian.
  const uint32_t totalSize = 10u + additionalBodyBytes;
  WriteBe16(buffer_.data() + 0, responseTag);
  WriteBe32(buffer_.data() + 2, totalSize);
  WriteBe32(buffer_.data() + 6, kTpmRcSuccess);
  rspSize_ = totalSize;
}

void Tpm2CrbDevice::WriteSuccessResponseBody(
    uint16_t responseTag, const std::vector<uint8_t> &body) {
  const size_t bodyBytes = std::min(body.size(), buffer_.size() - 10);
  std::fill(buffer_.begin(), buffer_.end(), 0);
  WriteSuccessResponseHeader(responseTag, static_cast<uint32_t>(bodyBytes));
  if (bodyBytes > 0) {
    std::memcpy(buffer_.data() + 10, body.data(), bodyBytes);
  }
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
