#pragma once

// RAII wrapper around the Windows Hypervisor Platform instruction emulator.
// Used to decode and execute the MMIO instruction that caused the most recent
// memory exit, calling back into our MmioBus to satisfy the operation. The
// emulator handles every supported x86 memory access pattern (mov reg/mem,
// movzx, rep movs, etc.) so we don't have to roll our own decoder.

#include "antimal/hv/MmioBus.h"
#include "antimal/hv/Vcpu.h"
#include "antimal/hv/WhpHost.h"

#include <WinHvEmulation.h>

#include <cstdint>

namespace antimal::hv {

class MmioEmulator {
public:
  MmioEmulator();
  ~MmioEmulator();

  MmioEmulator(const MmioEmulator &) = delete;
  MmioEmulator &operator=(const MmioEmulator &) = delete;

  // Asks WHP's emulator to decode + execute the instruction described by
  // `exit` against the supplied MMIO bus. Returns true if the access was
  // emulated; on failure the caller should treat it as an unhandled MMIO.
  bool TryEmulate(Vcpu &vcpu, const WHV_RUN_VP_EXIT_CONTEXT &exit, MmioBus &bus,
                  bool *deviceOwned);

private:
  struct CallbackState {
    Vcpu *vcpu = nullptr;
    MmioBus *bus = nullptr;
    bool deviceOwned = false;
  };

  static HRESULT CALLBACK IoPortCallback(VOID *context,
                                         WHV_EMULATOR_IO_ACCESS_INFO *io);
  static HRESULT CALLBACK MemoryCallback(VOID *context,
                                         WHV_EMULATOR_MEMORY_ACCESS_INFO *mem);
  static HRESULT CALLBACK GetRegistersCallback(
      VOID *context, const WHV_REGISTER_NAME *names, UINT32 count,
      WHV_REGISTER_VALUE *values);
  static HRESULT CALLBACK SetRegistersCallback(
      VOID *context, const WHV_REGISTER_NAME *names, UINT32 count,
      const WHV_REGISTER_VALUE *values);
  static HRESULT CALLBACK TranslateGvaCallback(
      VOID *context, WHV_GUEST_VIRTUAL_ADDRESS gva,
      WHV_TRANSLATE_GVA_FLAGS flags,
      WHV_TRANSLATE_GVA_RESULT_CODE *translationResult,
      WHV_GUEST_PHYSICAL_ADDRESS *gpa);

  WHV_EMULATOR_HANDLE emulator_ = nullptr;
};

} // namespace antimal::hv
