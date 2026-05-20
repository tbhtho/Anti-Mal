#include "antimal/hv/MmioEmulator.h"

#include <cstring>

namespace antimal::hv {

namespace {

struct EmulationContext {
  Vcpu *vcpu;
  MmioBus *bus;
  bool *deviceOwned;
};

} // namespace

MmioEmulator::MmioEmulator() {
  WHV_EMULATOR_CALLBACKS callbacks{};
  callbacks.Size = sizeof(callbacks);
  callbacks.WHvEmulatorIoPortCallback = &MmioEmulator::IoPortCallback;
  callbacks.WHvEmulatorMemoryCallback = &MmioEmulator::MemoryCallback;
  callbacks.WHvEmulatorGetVirtualProcessorRegisters =
      &MmioEmulator::GetRegistersCallback;
  callbacks.WHvEmulatorSetVirtualProcessorRegisters =
      &MmioEmulator::SetRegistersCallback;
  callbacks.WHvEmulatorTranslateGvaPage = &MmioEmulator::TranslateGvaCallback;

  const HRESULT hr = WHvEmulatorCreateEmulator(&callbacks, &emulator_);
  if (FAILED(hr)) {
    emulator_ = nullptr;
  }
}

MmioEmulator::~MmioEmulator() {
  if (emulator_) {
    WHvEmulatorDestroyEmulator(emulator_);
    emulator_ = nullptr;
  }
}

bool MmioEmulator::TryEmulate(Vcpu &vcpu,
                              const WHV_RUN_VP_EXIT_CONTEXT &exit,
                              MmioBus &bus, bool *deviceOwned) {
  if (!emulator_) {
    return false;
  }
  EmulationContext ctx{};
  ctx.vcpu = &vcpu;
  ctx.bus = &bus;
  ctx.deviceOwned = deviceOwned;

  WHV_EMULATOR_STATUS status{};
  const HRESULT hr = WHvEmulatorTryMmioEmulation(
      emulator_, &ctx, &exit.VpContext, &exit.MemoryAccess, &status);
  if (FAILED(hr)) {
    return false;
  }
  return status.EmulationSuccessful != 0;
}

HRESULT CALLBACK MmioEmulator::IoPortCallback(
    VOID * /*context*/, WHV_EMULATOR_IO_ACCESS_INFO * /*io*/) {
  // We only invoke this emulator for MMIO; the IO port path is handled by
  // the main run loop via IoBus, so the emulator should never need this
  // callback. Returning E_NOTIMPL is harmless here because the WHP emulator
  // will surface it to TryMmioEmulation as a failure.
  return E_NOTIMPL;
}

HRESULT CALLBACK MmioEmulator::MemoryCallback(
    VOID *context, WHV_EMULATOR_MEMORY_ACCESS_INFO *mem) {
  if (!context || !mem) {
    return E_POINTER;
  }
  auto *ctx = static_cast<EmulationContext *>(context);
  if (!ctx->bus) {
    return E_NOT_VALID_STATE;
  }
  const uint8_t accessSize =
      mem->AccessSize == 0 ? 1 : mem->AccessSize > 8 ? 8 : mem->AccessSize;

  if (mem->Direction == 0) { // read
    uint64_t value = 0;
    const bool handled =
        ctx->bus->Read(mem->GpaAddress, accessSize, &value);
    std::memset(mem->Data, 0, sizeof(mem->Data));
    std::memcpy(mem->Data, &value, accessSize);
    if (ctx->deviceOwned) {
      *ctx->deviceOwned = handled;
    }
    return S_OK;
  }

  uint64_t value = 0;
  std::memcpy(&value, mem->Data, accessSize);
  const bool handled = ctx->bus->Write(mem->GpaAddress, accessSize, value);
  if (ctx->deviceOwned) {
    *ctx->deviceOwned = handled;
  }
  return S_OK;
}

HRESULT CALLBACK MmioEmulator::GetRegistersCallback(
    VOID *context, const WHV_REGISTER_NAME *names, UINT32 count,
    WHV_REGISTER_VALUE *values) {
  if (!context || !names || !values) {
    return E_POINTER;
  }
  auto *ctx = static_cast<EmulationContext *>(context);
  if (!ctx->vcpu) {
    return E_NOT_VALID_STATE;
  }
  return WHvGetVirtualProcessorRegisters(ctx->vcpu->Partition(),
                                         ctx->vcpu->Index(), names, count,
                                         values);
}

HRESULT CALLBACK MmioEmulator::SetRegistersCallback(
    VOID *context, const WHV_REGISTER_NAME *names, UINT32 count,
    const WHV_REGISTER_VALUE *values) {
  if (!context || !names || !values) {
    return E_POINTER;
  }
  auto *ctx = static_cast<EmulationContext *>(context);
  if (!ctx->vcpu) {
    return E_NOT_VALID_STATE;
  }
  return WHvSetVirtualProcessorRegisters(ctx->vcpu->Partition(),
                                         ctx->vcpu->Index(), names, count,
                                         values);
}

HRESULT CALLBACK MmioEmulator::TranslateGvaCallback(
    VOID *context, WHV_GUEST_VIRTUAL_ADDRESS gva, WHV_TRANSLATE_GVA_FLAGS flags,
    WHV_TRANSLATE_GVA_RESULT_CODE *translationResult,
    WHV_GUEST_PHYSICAL_ADDRESS *gpa) {
  if (!context || !translationResult || !gpa) {
    return E_POINTER;
  }
  auto *ctx = static_cast<EmulationContext *>(context);
  if (!ctx->vcpu) {
    return E_NOT_VALID_STATE;
  }
  WHV_TRANSLATE_GVA_RESULT result{};
  const HRESULT hr = WHvTranslateGva(ctx->vcpu->Partition(),
                                     ctx->vcpu->Index(), gva, flags, &result,
                                     gpa);
  *translationResult = result.ResultCode;
  return hr;
}

} // namespace antimal::hv
