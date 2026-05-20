#include "antimal/hv/Vcpu.h"

#include <algorithm>
#include <cstring>

namespace antimal::hv {

namespace {

void SetRegisters(WHV_PARTITION_HANDLE partition, uint32_t index,
                  const WHV_REGISTER_NAME *names,
                  const WHV_REGISTER_VALUE *values, UINT32 count) {
  const HRESULT hr =
      WHvSetVirtualProcessorRegisters(partition, index, names, count, values);
  if (FAILED(hr)) {
    throw WhpError("WHvSetVirtualProcessorRegisters failed", hr);
  }
}

void GetRegisters(WHV_PARTITION_HANDLE partition, uint32_t index,
                  const WHV_REGISTER_NAME *names, WHV_REGISTER_VALUE *values,
                  UINT32 count) {
  const HRESULT hr =
      WHvGetVirtualProcessorRegisters(partition, index, names, count, values);
  if (FAILED(hr)) {
    throw WhpError("WHvGetVirtualProcessorRegisters failed", hr);
  }
}

} // namespace

Vcpu::Vcpu(const WhpHost &host, uint32_t index)
    : partition_(host.Handle()), index_(index),
      processorCount_(host.ProcessorCount()) {
  if (index >= host.ProcessorCount()) {
    throw WhpError("Vcpu index >= processor count", E_INVALIDARG);
  }
  const HRESULT hr = WHvCreateVirtualProcessor(partition_, index_, 0);
  if (FAILED(hr)) {
    throw WhpError("WHvCreateVirtualProcessor failed", hr);
  }
  const WHV_REGISTER_NAME names[] = {WHvX64RegisterInitialApicId,
                                     WHvX64RegisterApicId};
  WHV_REGISTER_VALUE values[2]{};
  values[0].Reg64 = index_;
  values[1].Reg64 = index_;
  (void)WHvSetVirtualProcessorRegisters(partition_, index_, names, 2, values);
}

Vcpu::~Vcpu() {
  if (partition_) {
    WHvDeleteVirtualProcessor(partition_, index_);
    partition_ = nullptr;
  }
}

void Vcpu::SetRealModeStart(const ResetState16BitRealMode &state) {
  WHV_REGISTER_NAME names[] = {WHvX64RegisterCs, WHvX64RegisterRip,
                               WHvX64RegisterRflags};
  WHV_REGISTER_VALUE values[3]{};

  // Segment register layout: { Base, Limit, Selector, Attributes }.
  values[0].Segment.Base = state.csBase;
  values[0].Segment.Limit = 0xFFFFu;
  values[0].Segment.Selector = state.csSelector;
  // 16-bit code segment, present, S=1, Type=0xB (code, read, accessed).
  // Attributes bits: Type[3:0]=0xB, S=1, DPL=0, P=1, L=0, Db=0, G=0.
  // SegmentType / NonSystemSegment / Present.
  values[0].Segment.Attributes = 0x9Bu;

  values[1].Reg64 = state.rip;
  values[2].Reg64 = 0x2u; // bit 1 of RFLAGS is reserved must-be-1

  SetRegisters(partition_, index_, names, values, 3);
}

void Vcpu::SetX86ResetState() {
  ResetState16BitRealMode reset{};
  reset.csSelector = 0xF000u;
  reset.csBase = 0xFFFF0000ull;
  reset.rip = 0xFFF0u;
  SetRealModeStart(reset);
}

bool Vcpu::TrySetStartupSuspended(bool suspended) noexcept {
  if (!partition_) {
    return false;
  }
  WHV_REGISTER_NAME name = WHvRegisterInternalActivityState;
  WHV_REGISTER_VALUE value{};
  value.InternalActivity.StartupSuspend = suspended ? 1ull : 0ull;
  return SUCCEEDED(
      WHvSetVirtualProcessorRegisters(partition_, index_, &name, 1, &value));
}

uint64_t Vcpu::ReadRax() {
  WHV_REGISTER_NAME name = WHvX64RegisterRax;
  WHV_REGISTER_VALUE value{};
  GetRegisters(partition_, index_, &name, &value, 1);
  return value.Reg64;
}

void Vcpu::WriteRax(uint64_t value) {
  WHV_REGISTER_NAME name = WHvX64RegisterRax;
  WHV_REGISTER_VALUE v{};
  v.Reg64 = value;
  SetRegisters(partition_, index_, &name, &v, 1);
}

void Vcpu::WriteRcxRsiRdi(uint64_t rcx, uint64_t rsi, uint64_t rdi) {
  const WHV_REGISTER_NAME names[] = {WHvX64RegisterRcx, WHvX64RegisterRsi,
                                     WHvX64RegisterRdi};
  WHV_REGISTER_VALUE values[3]{};
  values[0].Reg64 = rcx;
  values[1].Reg64 = rsi;
  values[2].Reg64 = rdi;
  SetRegisters(partition_, index_, names, values, 3);
}

bool Vcpu::TryTranslateGva(uint64_t gva, bool forWrite,
                           uint64_t *gpa) noexcept {
  if (!partition_ || !gpa) {
    return false;
  }

  WHV_TRANSLATE_GVA_RESULT result{};
  WHV_GUEST_PHYSICAL_ADDRESS translated = 0;
  const auto flags = static_cast<WHV_TRANSLATE_GVA_FLAGS>(
      (forWrite ? WHvTranslateGvaFlagValidateWrite
                : WHvTranslateGvaFlagValidateRead) |
      WHvTranslateGvaFlagSetPageTableBits);
  const HRESULT hr = WHvTranslateGva(partition_, index_, gva, flags, &result,
                                     &translated);
  if (FAILED(hr) || result.ResultCode != WHvTranslateGvaResultSuccess) {
    return false;
  }
  *gpa = translated;
  return true;
}

void Vcpu::AdvanceRip(uint64_t bytes) {
  WHV_REGISTER_NAME name = WHvX64RegisterRip;
  WHV_REGISTER_VALUE value{};
  GetRegisters(partition_, index_, &name, &value, 1);
  value.Reg64 += bytes;
  SetRegisters(partition_, index_, &name, &value, 1);
}

void Vcpu::EmulateCpuidExit() {
  const auto &cpuid = lastExit_.CpuidAccess;
  const uint32_t leaf = static_cast<uint32_t>(cpuid.Rax);
  const uint32_t subleaf = static_cast<uint32_t>(cpuid.Rcx);

  uint32_t rax = static_cast<uint32_t>(cpuid.DefaultResultRax);
  uint32_t rbx = static_cast<uint32_t>(cpuid.DefaultResultRbx);
  uint32_t rcx = static_cast<uint32_t>(cpuid.DefaultResultRcx);
  uint32_t rdx = static_cast<uint32_t>(cpuid.DefaultResultRdx);

  switch (leaf) {
  case 0x00000001u:
    rcx &= ~(1u << 31); // Hide synthetic MSRs until we emulate them.
    rbx = (rbx & ~0xFF000000u) | ((index_ & 0xFFu) << 24);
    rbx = (rbx & ~0x00FF0000u) |
          ((std::min<uint32_t>(processorCount_, 0xFFu) & 0xFFu) << 16);
    if (processorCount_ > 1) {
      rdx |= (1u << 28);
    } else {
      rdx &= ~(1u << 28);
    }
    break;
  case 0x00000004u:
    // Deterministic cache parameters report cores-per-package in EAX[31:26].
    // Keep the host cache geometry but make the topology match our ACPI MADT.
    rax = (rax & ~(0x3Fu << 26)) |
          ((std::min<uint32_t>(processorCount_, 64u) - 1u) << 26);
    break;
  case 0x0000000Bu:
  case 0x0000001Fu: {
    const uint32_t count = std::max<uint32_t>(1, processorCount_);
    const auto ceilLog2 = [](uint32_t value) {
      uint32_t shift = 0;
      uint32_t n = value > 1 ? value - 1 : 0;
      while (n != 0) {
        ++shift;
        n >>= 1;
      }
      return shift;
    };
    if (processorCount_ <= 1 || subleaf > 1) {
      rax = 0;
      rbx = 0;
      rcx = subleaf;
      rdx = index_;
    } else if (subleaf == 0) {
      rax = 0; // No SMT siblings per core.
      rbx = 1;
      rcx = (1u << 8) | subleaf; // level type SMT.
      rdx = index_;
    } else {
      rax = ceilLog2(count);
      rbx = count;
      rcx = (2u << 8) | subleaf; // level type core.
      rdx = index_;
    }
    break;
  }
  case 0x80000008u:
    // Physical address bits [7:0], linear address bits [15:8]. OVMF's early
    // high-shadow copy uses a fixed 4G+ scratch window even when that range is
    // not advertised as guest RAM, so the guest must be allowed to install PTEs
    // that point just above 4G.
    rax = (rax & 0xFFFF0000u) | (48u << 8) | 36u;
    rcx = (rcx & ~0x000000FFu) |
          ((std::min<uint32_t>(processorCount_, 256u) - 1u) & 0xFFu);
    rcx &= ~0x0000FF00u;
    break;
  default:
    if (leaf >= 0x40000000u && leaf <= 0x400000FFu) {
      rax = 0;
      rbx = 0;
      rcx = 0;
      rdx = 0;
    }
    break;
  }

  const WHV_REGISTER_NAME names[] = {WHvX64RegisterRax, WHvX64RegisterRbx,
                                     WHvX64RegisterRcx, WHvX64RegisterRdx};
  WHV_REGISTER_VALUE values[4]{};
  values[0].Reg64 = rax;
  values[1].Reg64 = rbx;
  values[2].Reg64 = rcx;
  values[3].Reg64 = rdx;
  SetRegisters(partition_, index_, names, values, 4);
  AdvanceRip(lastExit_.VpContext.InstructionLength != 0
                 ? lastExit_.VpContext.InstructionLength
                 : 2);
}

Vcpu::DiagState Vcpu::ReadDiagState() {
  const WHV_REGISTER_NAME names[] = {
      WHvX64RegisterCs,    WHvX64RegisterRip, WHvX64RegisterRflags,
      WHvX64RegisterCr0,   WHvX64RegisterCr3, WHvX64RegisterCr4,
      WHvX64RegisterCr8,   WHvX64RegisterEfer, WHvX64RegisterIdtr,
  };
  WHV_REGISTER_VALUE values[9]{};
  GetRegisters(partition_, index_, names, values,
               static_cast<UINT32>(sizeof(names) / sizeof(names[0])));

  DiagState s{};
  s.cs_base       = values[0].Segment.Base;
  s.cs_selector   = values[0].Segment.Selector;
  s.cs_attributes = values[0].Segment.Attributes;
  s.rip           = values[1].Reg64;
  s.rflags        = values[2].Reg64;
  s.cr0           = values[3].Reg64;
  s.cr3           = values[4].Reg64;
  s.cr4           = values[5].Reg64;
  s.cr8           = values[6].Reg64;
  s.efer          = values[7].Reg64;
  s.idtr_base     = values[8].Table.Base;
  s.idtr_limit    = values[8].Table.Limit;
  return s;
}

bool Vcpu::TryReadApicLvtTimer(uint32_t *value) noexcept {
  if (!partition_ || !value) {
    return false;
  }

  // WHP returns the xAPIC page layout for the legacy interrupt-controller
  // state API. The LVT timer register lives at APIC offset 0x320.
  alignas(16) uint8_t apicPage[4096]{};
  UINT32 written = 0;
  const HRESULT hr = WHvGetVirtualProcessorInterruptControllerState(
      partition_, index_, apicPage, sizeof(apicPage), &written);
  if (FAILED(hr) || written < 0x324u) {
    return false;
  }

  std::memcpy(value, apicPage + 0x320u, sizeof(*value));
  return true;
}

WHV_RUN_VP_EXIT_REASON Vcpu::Run() {
  lastExit_ = {};
  const HRESULT hr = WHvRunVirtualProcessor(partition_, index_, &lastExit_,
                                            sizeof(lastExit_));
  if (FAILED(hr)) {
    throw WhpError("WHvRunVirtualProcessor failed", hr);
  }
  return lastExit_.ExitReason;
}

void Vcpu::CancelRun() noexcept {
  if (partition_) {
    (void)WHvCancelRunVirtualProcessor(partition_, index_, 0);
  }
}

HRESULT Vcpu::RequestFixedInterrupt(uint8_t vector) noexcept {
  if (!partition_) {
    return E_HANDLE;
  }

  WHV_INTERRUPT_CONTROL interrupt{};
  interrupt.Type = WHvX64InterruptTypeFixed;
  interrupt.DestinationMode = WHvX64InterruptDestinationModePhysical;
  interrupt.TriggerMode = WHvX64InterruptTriggerModeEdge;
  interrupt.TargetVtl = 0;
  interrupt.Destination = index_;
  interrupt.Vector = vector;

  return WHvRequestInterrupt(partition_, &interrupt, sizeof(interrupt));
}

bool Vcpu::TryRequestFixedInterrupt(uint8_t vector) noexcept {
  return SUCCEEDED(RequestFixedInterrupt(vector));
}

} // namespace antimal::hv
