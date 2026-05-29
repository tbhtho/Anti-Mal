#pragma once

// Virtual CPU wrapper. Each Vcpu corresponds to one WHV virtual processor on
// a parent WhpHost. The Run() call enters the guest until the CPU exits for
// any reason (HLT, IO port access, MMIO, interrupt window, etc.) and returns
// the exit context for the caller to dispatch.

#include "antimal/hv/WhpHost.h"

#include <cstdint>

namespace antimal::hv {

// A handful of canonical register names we set during reset / read back after
// a run. WHP exposes ~200 registers; we wrap only what Phase 1 needs and grow
// the list as later phases require it.
struct ResetState16BitRealMode {
  // CS:IP that the vCPU begins fetching from. Linear address = csBase + rip.
  uint16_t csSelector = 0;
  uint64_t csBase = 0;
  uint64_t rip = 0;
};

struct CpuidExitResult {
  uint32_t vcpuIndex = 0;
  uint32_t leaf = 0;
  uint32_t subleaf = 0;
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
  uint32_t defaultEax = 0;
  uint32_t defaultEbx = 0;
  uint32_t defaultEcx = 0;
  uint32_t defaultEdx = 0;
  bool overridden = false;
};

class Vcpu {
public:
  // Creates virtual processor `index` on `host`. Index must be < host's
  // processor count.
  Vcpu(const WhpHost &host, uint32_t index);
  ~Vcpu();

  Vcpu(const Vcpu &) = delete;
  Vcpu &operator=(const Vcpu &) = delete;

  uint32_t Index() const noexcept { return index_; }

  // Raw WHP partition handle. Exposed so helpers (the MMIO emulator wrapper)
  // can call WHP register / translation APIs directly without re-implementing
  // them on top of this class. Lifetime is owned by the WhpHost that created
  // this vCPU; do not destroy through this pointer.
  WHV_PARTITION_HANDLE Partition() const noexcept { return partition_; }

  // Configures CS, RIP, and RFLAGS for execution to begin in 16-bit real mode
  // at the requested linear address. All other state stays at WHP defaults
  // (which for a fresh vCPU is close to architectural CPU-reset state, modulo
  // CS.Base which we explicitly override).
  void SetRealModeStart(const ResetState16BitRealMode &state);

  // Configures the vCPU for the **x86 architectural CPU reset** that modern
  // firmware (OVMF, SeaBIOS, real PC BIOS chips on 386+) actually expects:
  //   CS.Selector = 0xF000
  //   CS.Base     = 0xFFFF0000   <-- top of 32-bit phys addr, NOT 0xF0000
  //   CS.Limit    = 0xFFFF
  //   CS.Attr     = 16-bit code, present
  //   RIP         = 0xFFF0
  //   RFLAGS      = 0x2
  // This makes the first fetch land at GPA 0xFFFFFFF0, which is where the
  // Firmware class places the reset vector. WHP's *default* vCPU state uses
  // the legacy 8086 convention (CS.Base=0xF0000, fetch at 0x000FFFF0), which
  // does not work for OVMF.
  void SetX86ResetState();

  // Marks an AP vCPU as startup-suspended until a guest INIT/SIPI sequence
  // wakes it through WHP's local APIC emulation. BSP vCPU 0 runs with this
  // clear.
  bool TrySetStartupSuspended(bool suspended) noexcept;

  // Reads RAX from the vCPU.
  uint64_t ReadRax();

  // Writes RAX. Used to deliver a result value back to the guest after an
  // `in` IO-port exit. The caller is responsible for honoring the access size
  // (1/2/4 bytes) by masking the high bits if appropriate.
  void WriteRax(uint64_t value);

  // Updates the string-IO registers after manually emulating INS/OUTS.
  void WriteRcxRsiRdi(uint64_t rcx, uint64_t rsi, uint64_t rdi);

  // Best-effort guest virtual to guest physical translation using the vCPU's
  // current paging state. Used for string IO buffers.
  bool TryTranslateGva(uint64_t gva, bool forWrite, uint64_t *gpa) noexcept;

  // Advances RIP by `bytes`, typically the InstructionLength from the most
  // recent exit context. Use after handling an IO-port / MMIO exit so the
  // next Run() resumes past the trapping instruction.
  void AdvanceRip(uint64_t bytes);

  // Diagnostic snapshot of CPU mode + control registers. Used by tests and
  // by future logging to figure out where in firmware boot the guest is.
  struct DiagState {
    uint64_t cs_base;
    uint16_t cs_selector;
    uint16_t cs_attributes;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t cr8;
    uint64_t efer;
    uint64_t idtr_base;
    uint16_t idtr_limit;
  };
  DiagState ReadDiagState();

  // Reads the xAPIC LVT timer register through WHP's APIC state blob when
  // local APIC emulation is enabled. Returns false when the host/API does not
  // expose that state for this vCPU.
  bool TryReadApicLvtTimer(uint32_t *value) noexcept;

  // Reads the full WHV_RUN_VP_EXIT_CONTEXT after a run.
  const WHV_RUN_VP_EXIT_CONTEXT &LastExit() const noexcept { return lastExit_; }

  // Handles a WHvRunVpExitReasonX64Cpuid exit using WHP's default CPUID
  // values as a base and applying AntiMal's VM-visible overrides.
  CpuidExitResult EmulateCpuidExit();

  // Enters the guest and runs until any exit. Returns the exit reason
  // (cached in LastExit() too). Throws WhpError on hypervisor call failure.
  WHV_RUN_VP_EXIT_REASON Run();

  // Best-effort cancellation for a currently-running WHvRunVirtualProcessor
  // call. Safe to call from a watchdog thread; failures are intentionally
  // ignored because cancellation is only used to recover diagnostics.
  void CancelRun() noexcept;

  // Best-effort fixed interrupt injection for firmware bring-up. This queues
  // an edge-triggered external interrupt to this vCPU's physical APIC id.
  HRESULT RequestFixedInterrupt(uint8_t vector) noexcept;
  bool TryRequestFixedInterrupt(uint8_t vector) noexcept;

  // Re-injects a page fault (#PF, vector 14) into the guest so the guest's own
  // IDT handler services it. Queues a pending exception event with the given
  // error code and faulting linear address (delivered as CR2). Used when WHP
  // intercepts a guest #PF that the host does not need to assist — e.g. kernel
  // demand paging, copy-on-write, or an SEH-protected probe (ProbeForRead
  // touching MmUserProbeAddress). On real hardware these faults are entirely
  // the guest's business; re-injecting keeps that transparent instead of
  // killing the VM. Returns false if the WHP register write fails.
  bool TryInjectPageFault(uint64_t faultingAddress, uint32_t errorCode) noexcept;

private:
  WHV_PARTITION_HANDLE partition_ = nullptr;
  uint32_t index_ = 0;
  uint32_t processorCount_ = 1;
  WHV_RUN_VP_EXIT_CONTEXT lastExit_{};
};

} // namespace antimal::hv
