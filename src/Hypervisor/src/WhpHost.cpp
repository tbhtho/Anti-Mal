#include "antimal/hv/WhpHost.h"

namespace antimal::hv {

namespace {

bool QueryHypervisorPresent() {
  WHV_CAPABILITY cap{};
  UINT32 written = 0;
  const HRESULT hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &cap,
                                      sizeof(cap), &written);
  if (FAILED(hr) || written < sizeof(cap.HypervisorPresent)) {
    return false;
  }
  return cap.HypervisorPresent != FALSE;
}

bool QueryLocalApicEmulationSupported() {
  WHV_CAPABILITY cap{};
  UINT32 written = 0;
  const HRESULT hr =
      WHvGetCapability(WHvCapabilityCodeFeatures, &cap, sizeof(cap), &written);
  if (FAILED(hr) || written < sizeof(cap.Features)) {
    return false;
  }
  return cap.Features.LocalApicEmulation != 0;
}

WHV_EXTENDED_VM_EXITS QueryExtendedVmExitSupport() {
  WHV_CAPABILITY cap{};
  UINT32 written = 0;
  const HRESULT hr = WHvGetCapability(WHvCapabilityCodeExtendedVmExits, &cap,
                                      sizeof(cap), &written);
  if (FAILED(hr) || written < sizeof(cap.ExtendedVmExits)) {
    return {};
  }
  return cap.ExtendedVmExits;
}

HRESULT ConfigureExtendedVmExits(WHV_PARTITION_HANDLE partition,
                                 WHV_EXTENDED_VM_EXITS supported,
                                 bool enablePageFaultExits) {
  WHV_EXTENDED_VM_EXITS exits{};
  if (supported.X64CpuidExit) {
    exits.X64CpuidExit = 1;
  }
  if (enablePageFaultExits && supported.ExceptionExit) {
    exits.ExceptionExit = 1;
  }
  if (exits.AsUINT64 == 0) {
    return S_OK;
  }
  HRESULT hr = WHvSetPartitionProperty(partition,
                                       WHvPartitionPropertyCodeExtendedVmExits,
                                       &exits, sizeof(exits));
  if (FAILED(hr) || !exits.ExceptionExit) {
    return hr;
  }

  UINT64 pageFaultOnly = 1ull << WHvX64ExceptionTypePageFault;
  return WHvSetPartitionProperty(partition,
                                 WHvPartitionPropertyCodeExceptionExitBitmap,
                                 &pageFaultOnly, sizeof(pageFaultOnly));
}

HRESULT ConfigureSyntheticCpuidLeaves(WHV_PARTITION_HANDLE) {
  // Leave synthetic hypervisor leaves unset. Vcpu::EmulateCpuidExit() hides
  // the 0x400000xx range until the matching synthetic MSRs are implemented.
  return S_OK;
}

} // namespace

bool WhpHost::IsAvailable() {
  return QueryHypervisorPresent();
}

WhpHost::WhpHost(uint32_t processorCount, bool enableLocalApicEmulation,
                 bool enablePageFaultExits)
    : processorCount_(processorCount) {
  if (processorCount == 0) {
    throw WhpError("processorCount must be >= 1", E_INVALIDARG);
  }
  if (!QueryHypervisorPresent()) {
    throw WhpError("Windows Hypervisor Platform not available (enable the "
                   "HypervisorPlatform Windows optional feature)",
                   E_NOT_VALID_STATE);
  }

  HRESULT hr = WHvCreatePartition(&partition_);
  if (FAILED(hr)) {
    throw WhpError("WHvCreatePartition failed", hr);
  }

  WHV_PARTITION_PROPERTY prop{};
  prop.ProcessorCount = processorCount;
  hr = WHvSetPartitionProperty(partition_, WHvPartitionPropertyCodeProcessorCount,
                               &prop, sizeof(prop));
  if (FAILED(hr)) {
    WHvDeletePartition(partition_);
    partition_ = nullptr;
    throw WhpError("WHvSetPartitionProperty(ProcessorCount) failed", hr);
  }

  if (enableLocalApicEmulation && QueryLocalApicEmulationSupported()) {
    WHV_PARTITION_PROPERTY apic{};
    apic.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
    hr = WHvSetPartitionProperty(
        partition_, WHvPartitionPropertyCodeLocalApicEmulationMode, &apic,
        sizeof(apic.LocalApicEmulationMode));
    if (FAILED(hr)) {
      WHvDeletePartition(partition_);
      partition_ = nullptr;
      throw WhpError("WHvSetPartitionProperty(LocalApicEmulationMode) failed",
                     hr);
    }
  }

  {
    // CPUID exits let Vcpu preserve WHP's default host-derived result for
    // each leaf and patch only the handful of values firmware/Windows need.
    const auto supportedExits = QueryExtendedVmExitSupport();
    (void)ConfigureExtendedVmExits(partition_, supportedExits,
                                   enablePageFaultExits);
  }

  // Keep synthetic CPUID leaves owned by the CPUID exit handler. It currently
  // hides the hypervisor range until the matching synthetic MSRs are modeled.
  if (FAILED(ConfigureSyntheticCpuidLeaves(partition_))) {
    // Non-fatal; continue with default CPUID behaviour.
  }

  hr = WHvSetupPartition(partition_);
  if (FAILED(hr)) {
    WHvDeletePartition(partition_);
    partition_ = nullptr;
    throw WhpError("WHvSetupPartition failed", hr);
  }
}

WhpHost::~WhpHost() {
  if (partition_) {
    WHvDeletePartition(partition_);
    partition_ = nullptr;
  }
}

} // namespace antimal::hv
