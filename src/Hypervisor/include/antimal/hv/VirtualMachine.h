#pragma once

// First reusable in-house VM runner. This factors the OVMF smoke-test run loop
// out of the test harness and composes the WHP partition, RAM, firmware, basic
// PC IO devices, serial console, and optional IDE disk.

#include "antimal/hv/BlockDevice.h"
#include "antimal/hv/BochsVbe.h"
#include "antimal/hv/Firmware.h"
#include "antimal/hv/AhciController.h"
#include "antimal/hv/E1000Device.h"
#include "antimal/hv/GuestMemory.h"
#include "antimal/hv/Hpet.h"
#include "antimal/hv/IoApic.h"
#include "antimal/hv/Tpm2CrbDevice.h"
#include "antimal/hv/IoBus.h"
#include "antimal/hv/KdSerialDebugger.h"
#include "antimal/hv/MmioBus.h"
#include "antimal/hv/MmioEmulator.h"
#include "antimal/hv/PcIoDevices.h"
#include "antimal/hv/Ps2Controller.h"
#include "antimal/hv/SerialConsole.h"
#include "antimal/hv/StorageController.h"
#include "antimal/hv/Vcpu.h"
#include "antimal/hv/WhpHost.h"

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace antimal::hv {

enum class VmNetworkMode {
  Disabled,
  HostOnly,
  Nat,
};

struct VmGuestImageInfo {
  bool valid = false;
  uint64_t base = 0;
  uint32_t sizeOfImage = 0;
  uint32_t entryPointRva = 0;
  uint32_t timeDateStamp = 0;
  uint16_t machine = 0;
  uint16_t subsystem = 0;
  std::string pdbPath;
};

struct VmRipHotspotImageInfo {
  uint64_t ripBucket = 0;
  uint64_t hits = 0;
  VmGuestImageInfo image;
  // 32 bytes captured at ripBucket so the host-side diagnostics can render a
  // raw disassembly window for the hottest loops without re-attaching to the
  // VM. ripBytesValid stays false when the guest mapping was gone by the time
  // the post-run summary collected the hotspots (e.g. transient firmware
  // images that have already been freed).
  bool ripBytesValid = false;
  uint8_t ripBytes[32]{};
};

struct VmApRunState {
  uint32_t index = 0;
  uint64_t rip = 0;
  uint16_t csSelector = 0;
  bool ripBytesValid = false;
  uint8_t ripBytes[32]{};
  // The image the AP was executing at the capture point — identifies which
  // driver/module the AP spins in during the 2-vCPU bring-up rendezvous (the
  // documented AP-race hang). Without this the AP RIP is a bare address.
  VmGuestImageInfo image;
};

struct VmRunSummary {
  bool started = false;
  bool completed = false;
  bool timedOut = false;
  bool crashed = false;
  bool fatal = false;
  bool idleLoop = false;
  bool halted = false;
  bool hostStopRequested = false;
  // True when the guest issued an ACPI S4/S5 shutdown via PIIX4 PM1a_CNT
  // (typically OVMF's ResetSystemRuntimeDxe responding to RT->ResetSystem
  // (EfiResetShutdown) from bootmgr or the OS). The run loop exits cleanly
  // when this fires instead of timing out.
  bool guestShutdown = false;
  // Count of guest-initiated platform resets serviced as reboots (0xCF9). Set by
  // the orchestrator's reboot loop (the VM is recreated from scratch per reboot
  // -- a real cold boot -- so the disk's setup progress carries forward without
  // any stale device/CPU/memory state).
  int guestReboots = 0;
  // Set by Run() when the guest requested a platform reset (0xCF9) and exited so
  // the orchestrator can recreate the VM and continue the (rebooting) boot.
  bool rebootRequested = false;
  uint8_t guestShutdownSleepType = 0;
  bool pm1SleepEnable = false;
  bool pm1HostStopRequested = false;
  uint8_t pm1SleepType = 0;
  uint16_t pm1ControlValue = 0;
  uint16_t pm1EnableValue = 0;
  uint64_t pm1aStatusReads = 0;
  uint64_t pm1SleepRequests = 0;
  uint32_t screenStateReached = 0; // richest ScreenState (0=unknown..3=rich)
  VmNetworkMode networkMode = VmNetworkMode::Disabled;
  int steps = 0;
  uint32_t processorCount = 1;
  int totalHlts = 0;
  uint64_t apVcpuExits = 0;
  uint64_t apHltExits = 0;
  uint64_t apCpuidExits = 0;
  uint64_t apUnhandledExits = 0;
  std::vector<VmApRunState> apStates;
  int timerInterruptsRequested = 0;
  int timerInterruptsInjected = 0;
  int keyboardScancodesInjected = 0;
  int ideInterruptsRequested = 0;
  int ideInterruptsInjected = 0;
  int ideInterruptsFailed = 0;
  int ideInterruptsIoApic = 0;
  int ideInterruptsPicFallback = 0;
  int ideInterruptsPending = 0;
  int ahciInterruptsRequested = 0;
  int ahciInterruptsInjected = 0;
  int ahciInterruptsFailed = 0;
  int pitInterruptsFailed = 0;
  int pitInterruptsIoApic = 0;
  int pitInterruptsPicFallback = 0;
  int pitInterruptsPending = 0;
  int rtcInterruptsFailed = 0;
  int rtcInterruptsIoApic = 0;
  int rtcInterruptsPicFallback = 0;
  int rtcInterruptsPending = 0;
  uint64_t ps2StatusReads = 0;
  uint64_t ps2DataReads = 0;
  uint64_t ps2CommandWrites = 0;
  uint64_t ps2DataWrites = 0;
  uint64_t ps2KeyboardBytesQueued = 0;
  uint64_t ps2KeyboardBytesRead = 0;
  uint64_t ps2MouseBytesQueued = 0;
  uint64_t ps2MouseBytesRead = 0;
  bool ps2KeyboardPortEnabled = true;
  bool ps2MousePortEnabled = true;
  bool ps2KeyboardScanningEnabled = true;
  int irqIoApicDeliveries = 0;
  int irqPicFallbackDeliveries = 0;
  int irqDeliveryFailures = 0;
  uint8_t masterPicVectorBase = 0;
  uint8_t slavePicVectorBase = 0;
  uint8_t masterPicMask = 0xFF;
  uint8_t slavePicMask = 0xFF;
  int watchdogCancellations = 0;
  int unhandledIo = 0;
  int unhandledMmio = 0;
  int unhandledOther = 0;
  uint64_t ioApicRaises = 0;
  uint64_t ioApicDeliveries = 0;
  uint64_t ioApicMaskedDrops = 0;
  uint64_t hpetReads = 0;
  uint64_t hpetWrites = 0;
  uint64_t fwCfgFileDirBytesRead = 0;
  uint64_t fwCfgE820BytesRead = 0;
  uint64_t fwCfgAcpiTableBytesRead = 0;
  uint64_t fwCfgTableLoaderBytesRead = 0;
  uint64_t fwCfgRsdpBytesRead = 0;
  uint64_t fwCfgSmbiosTableBytesRead = 0;
  uint64_t fwCfgSmbiosAnchorBytesRead = 0;
  uint64_t pageFaultAssists = 0;
  uint64_t lastPageFaultAssistGva = 0;
  uint64_t lastPageFaultAssistGpa = 0;
  // #PFs inside the firmware high-scratch aperture that were NOT assisted because
  // the guest had already entered the OS kernel (firmware assist disabled). They
  // are re-injected to the guest instead. >0 proves Windows faulted in the
  // aperture and the host correctly stayed out of its page tables -- the fix for
  // the intermittent 0x4E/0x1A MM bugchecks + "Preparing Windows" hang (2026-06-03).
  uint64_t pageFaultAssistsSuppressed = 0;
  // Guest #PFs that the host did not need to assist and instead re-injected
  // into the guest so its own IDT #PF handler services them (kernel demand
  // paging, copy-on-write, SEH-protected probes such as ProbeForRead touching
  // MmUserProbeAddress). Before re-injection these were treated as fatal.
  uint64_t pageFaultsReinjected = 0;
  uint64_t lastReinjectedFaultGva = 0;
  uint32_t lastReinjectedFaultErrorCode = 0;
  // Once the OS kernel runs, the firmware page-fault assist is off forever, so the
  // ONLY reason we intercept #PF (re-injecting every Windows fault) is gone. We then
  // clear the WHP exception-exit bitmap so the guest handles its own faults NATIVELY
  // -- removing the re-inject overhead AND the recurring-fault-fatal (a re-inject
  // that won't "take" loops to kMaxReinjectedFaultStreak and kills the boot). If WHP
  // rejects the runtime change, the re-inject path still services faults (safe).
  // disableHr is the HRESULT (0 = S_OK = #PF exits successfully disabled).
  bool pageFaultExitsDisabled = false;
  uint32_t pageFaultExitsDisableHr = 0;
  // Guest-RAM patches applied to OVMF's runtime "wait for tick to change" spin
  // (the Windows kernel calls a UEFI runtime service whose tick-wait deadlocks
  // because OVMF's timer ISR stops once the OS owns the interrupt controllers).
  // Gated by ANTIMAL_PROBE_FWSPIN_NOP; patches the back-jump to NOPs so the wait
  // returns. Touches disposable guest RAM only, never the base VHDX.
  uint64_t fwSpinPatches = 0;
  uint64_t lastFwSpinPatchGva = 0;
  uint32_t mmioReads = 0;
  uint32_t mmioWrites = 0;
  // Total WHvRunVpExitReasonMemoryAccess exits on the BSP, regardless of
  // whether the MMIO bus routes them. Zero here means no GPA in the MMIO gap
  // ever generated an exit — the gap may be mapped with RAM.
  uint64_t totalBspMemoryAccessExits = 0;
  uint64_t firstBspMemoryAccessGpa = 0;
  uint64_t lastBspMemoryAccessGpa = 0;
  // PIC initialization tracking — counts how many ICW1 writes we saw.
  uint32_t masterPicIcw1Writes = 0;
  uint32_t slavePicIcw1Writes = 0;
  uint8_t masterPicIcw2Value = 0;
  uint8_t slavePicIcw2Value = 0;
  // IOAPIC redirection table snapshot at summary time.
  uint64_t ioApicRedir[24]{};
  // Per-GSI count of guest writes to each redirection entry. Zero => the HAL
  // never programmed that GSI (its owning device never connected its IRQ).
  uint32_t ioApicWrites[24]{};
  // # of PCI-config selects of the IDE function (bus0/dev1/func1). Low =>
  // Windows pci.sys never enumerated the IDE; high => it probed it.
  uint32_t ideConfigSelects = 0;
  // WHP IOAPIC GPA probe result: 0=not probed, 1=unmap succeeded (WHP had it
  // mapped), 2=unmap failed (was genuinely unmapped), 3=remap succeeded.
  int whpIoApicGpaProbe = 0;
  // WHP MMIO gap coverage scan. Probes every 64-KiB-aligned page inside the
  // MMIO gap [0xFEC00000, 0xFEF00000) via WHvUnmapGpaRange. Bit N is set
  // when the page at (0xFEC00000 + N*0x10000) was mapped by WHP.
  uint64_t whpMmioGapBitmap = 0;
  // Whether the TPM2 ACPI table was included in the fw_cfg payload.
  bool tpm2TableEnabled = false;
  // TPM 2.0 event log advertisement from the ACPI TPM2 table. Non-zero
  // when the VM populated firmwareLowScratch with a TCG_EfiSpecIDEvent03
  // header and pointed LAML/LASA at it.
  uint32_t tpmEventLogLaml = 0;
  uint64_t tpmEventLogLasa = 0;
  uint64_t tpmCrbReads = 0;
  uint64_t tpmCrbWrites = 0;
  uint64_t tpmCrbCommands = 0;
  uint32_t tpmCrbLastCommand = 0;
  uint32_t tpmCrbLastResponse = 0;
  uint64_t tpmCrbLastReadOffset = 0;
  uint64_t tpmCrbLastWriteOffset = 0;
  std::map<uint32_t, uint64_t> tpmCrbCommandHistogram;
  std::vector<uint32_t> tpmCrbRecentCommands;
  std::vector<TpmPcrExtendTrace> tpmPcrExtendTrace;
  std::array<std::array<uint8_t, 20>, 24> tpmPcrSha1Bank{};
  std::array<std::array<uint8_t, 32>, 24> tpmPcrSha256Bank{};
  uint64_t lastCanceledRip = 0;
  uint8_t lastCanceledOpcode = 0;
  bool lastCanceledAtHlt = false;
  uint64_t lastUnhandledMmioGpa = 0;
  uint64_t lastUnhandledMmioGva = 0;
  uint32_t lastUnhandledMmioAccess = 0;
  uint8_t lastUnhandledMmioInstructionLength = 0;
  uint8_t lastExceptionType = 0;
  uint32_t lastExceptionErrorCode = 0;
  uint64_t lastExceptionParameter = 0;
  uint64_t fatalRip = 0;
  uint16_t fatalCsSelector = 0;
  bool fatalProcessNameValid = false;
  char fatalProcessName[16]{}; // guest EPROCESS.ImageFileName of the running thread
  uint64_t fatalCurrentProcess = 0; // EPROCESS pointer (0 if not resolved)
  // Self-debug for the EPROCESS walk (so one boot reveals the right offsets):
  uint64_t fatalKpcr = 0;           // chosen KPCR (KERNEL_GS_BASE / GS_BASE)
  uint64_t fatalCurrentThread = 0;  // KPCR.Prcb.CurrentThread
  bool fatalEprocBytesValid = false;
  uint64_t fatalEprocDumpBase = 0;  // GVA the dump starts at (eproc + 0x540)
  uint8_t fatalEprocBytes[160]{};   // raw EPROCESS bytes to locate ImageFileName
  bool fatalRipBytesValid = false;
  uint8_t fatalRipBytes[16]{};
  bool fatalRipWindowValid = false;
  uint64_t fatalRipWindowBase = 0;
  uint8_t fatalRipWindow[64]{};
  VmGuestImageInfo fatalRipImage;
  bool fatalRdxBytesValid = false;
  uint8_t fatalRdxBytes[32]{};
  bool fatalRsiBytesValid = false;
  uint8_t fatalRsiBytes[160]{};
  bool fatalRdiBytesValid = false;
  uint8_t fatalRdiBytes[160]{};
  bool fatalRspBytesValid = false;
  uint8_t fatalRspBytes[64]{};
  uint64_t fatalStackReturn[4]{};
  bool fatalStackReturnBytesValid[4]{};
  uint64_t fatalStackReturnWindowBase[4]{};
  uint8_t fatalStackReturnBytes[4][32]{};
  VmGuestImageInfo fatalStackReturnImage[4];
  // Deep stack scan: every kernel-image pointer found in the BSP stack at the
  // capture point, as RVAs relative to deepStackImageBase. Resolves the full
  // call chain (e.g. who called KeBugCheckEx) when symbolized against the PDB.
  uint64_t deepStackImageBase = 0;
  uint32_t deepStackCount = 0;
  uint64_t deepStackRvas[64]{};
  // KiBugCheckData readout [code, p1..p4], gated by ANTIMAL_BUGCHECK_DATA_RVA.
  bool bugCheckDataValid = false;
  uint64_t bugCheckData[5]{};
  // PsLoadedModuleList walk (gated by ANTIMAL_PSLOADEDMODULELIST_RVA): the
  // space-separated, load-ordered list of kernel modules present at the
  // bugcheck. The decisive 0x7B evidence -- did pciide/atapi/intelide load?
  std::string loadedModules;
  uint32_t loadedModuleCount = 0;
  // For 0x7B, bugcheck p1 interpreted as a PUNICODE_STRING: the device/ARC path
  // the I/O manager failed to open (empty if p1 was not a valid UNICODE_STRING).
  std::string bootDeviceFailPath;
  // For exception bugchecks (0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED), the
  // loaded module whose [DllBase, DllBase+SizeOfImage) contains the faulting RIP
  // (bugcheck p2), as "name+0xOFFSET" -- names the driver/component that threw.
  std::string faultingModule;
  // PnP devnode tree walk (gated by ANTIMAL_IOPROOTDEVICENODE_RVA): devnodes
  // with a non-zero CM_PROB_* problem code, and any IDE/ATA-related devnodes,
  // each as "[instancePath prob=N cstat=0xXXXXXXXX]". Tells WHY the IDE device
  // stack failed to start once we know the drivers loaded.
  uint32_t pnpVisitedNodes = 0;
  std::string pnpProblemNodes;
  std::string pnpIdeNodes;
  // Full devnode instance-path dump (capped): shows whether PCI0/the PCI bus
  // and its child devices are enumerated at all, vs. the IDE being skipped.
  std::string pnpAllNodes;
  // The PCIIDE\IDEChannel devnode's resource REQUIREMENTS (ResourceRequirements
  // @ _DEVICE_NODE+0x1B8, an _IO_RESOURCE_REQUIREMENTS_LIST) + its assigned
  // ResourceList/Translated pointers. The resource map proved NO device owns the
  // legacy IDE ports/IRQ14, so the prob=12 is a requirements-can't-be-satisfied
  // failure -- this shows WHAT the channel asks for (e.g. a relocatable
  // bus-master IO block we don't advertise) so the fix is evidence-based.
  std::string pnpIdeChannelReq;
  // Per-devnode assigned-resource map (ResourceList @ _DEVICE_NODE+0x1A0,
  // parsed as CM_RESOURCE_LIST): "[ip io=1F0+8,3F6+1 irq=14]". Answers which
  // STARTED device owns the legacy IDE ports / IRQ14 that the PCIIDE\IDEChannel
  // (prob=12 CM_PROB_NORMAL_CONFLICT) is fighting over -- the ground truth the
  // resource-guessing fixes were missing.
  std::string pnpResourceMap;
  uint64_t fatalRax = 0;
  uint64_t fatalRbx = 0;
  uint64_t fatalRcx = 0;
  uint64_t fatalRdx = 0;
  uint64_t fatalRsi = 0;
  uint64_t fatalR8 = 0;
  uint64_t fatalR9 = 0;
  uint64_t fatalR10 = 0;
  uint64_t fatalR11 = 0;
  uint64_t fatalR12 = 0;
  uint64_t fatalR13 = 0;
  uint64_t fatalR14 = 0;
  uint64_t fatalR15 = 0;
  uint64_t fatalRbp = 0;
  uint64_t fatalRsp = 0;
  uint64_t fatalRdi = 0;
  WHV_RUN_VP_EXIT_REASON fatalReason = WHvRunVpExitReasonNone;
  std::map<int, int> exitHistogram;
  std::map<uint32_t, int> cpuidLeafHistogram;
  std::vector<CpuidExitResult> cpuidSamples;
  std::map<uint16_t, int> ioPortHistogram;
  std::map<int, int> ideCommandHistogram;
  std::map<int, int> cmosReadHistogram;
  // BSP RIP samples captured from each vCPU exit, oldest-first. Useful for
  // spotting tight polling loops when the boot stalls — the trapping
  // instruction's RIP shows up many times in a short window.
  std::vector<uint64_t> recentRips;
  // BSP RIP hit count, bucketed by 16-byte alignment so adjacent RIPs in the
  // same instruction sequence coalesce. Top entries identify the hottest
  // loop body even when the firmware/kernel relocates code each run.
  std::map<uint64_t, uint64_t> ripHotspots;
  // End-of-run guest image attribution for the hottest BSP RIP buckets.
  // This catches a loader image that owned a busy loop even when the final
  // RIP alone lands in firmware UI code after a boot handoff failure.
  std::vector<VmRipHotspotImageInfo> ripHotspotImages;
  // Page-aligned PE images still resident in identity-mapped low RAM when the
  // run stops. Boot Manager can return to firmware recovery UI after a short
  // loader handoff, so final RIP and hotspot attribution are not enough by
  // themselves to prove whether a loader image was present.
  std::vector<VmGuestImageInfo> residentImages;
  // Low-RAM PE images observed while boot storage traffic advances. A failed
  // Boot Manager handoff can unload winload before the end-of-run resident
  // snapshot, so the run loop keeps the first identity found for each image
  // base as IDE commands make progress.
  std::vector<VmGuestImageInfo> observedImages;
  // Snapshot of the most recent CMOS / RTC port accesses (oldest first).
  // Mirrors PcIoDevices::RecentCmosAccesses(); duplicated into the summary
  // so the host-side diagnostics writer doesn't need to keep the live VM
  // alive to render it.
  std::vector<PcIoDevices::CmosAccess> recentCmosAccesses;
  bool ideSawRead = false;
  bool ideSawWrite = false;
  uint64_t ideMinReadLba = 0;
  uint64_t ideMaxReadEndLba = 0;
  uint64_t ideMinWriteLba = 0;
  uint64_t ideMaxWriteEndLba = 0;
  std::vector<IdeAccessRange> ideRecentAccesses;
  std::vector<std::string> legacyIrqDiagnostics;
  std::string serialOutput;
  std::string firmwareDebugOutput;
  std::string hostChannelOutput;
  uint64_t com1RegisterReads = 0;
  uint64_t com1RegisterWrites = 0;
  uint64_t com1DataReads = 0;
  uint64_t com1DataWrites = 0;
  uint64_t com1RxBytesQueued = 0;
  uint64_t com1RxBytesRead = 0;
  uint64_t com1RxBytesCleared = 0;
  uint64_t com1IerWrites = 0;
  uint64_t com1FcrWrites = 0;
  uint64_t com1LcrWrites = 0;
  uint64_t com1McrWrites = 0;
  uint64_t com1DllWrites = 0;
  uint64_t com1DlmWrites = 0;
  uint64_t com1IirReads = 0;
  uint64_t com1LsrReads = 0;
  uint8_t com1Ier = 0;
  uint8_t com1Fcr = 0;
  uint8_t com1Lcr = 0;
  uint8_t com1Mcr = 0;
  uint8_t com1Dll = 0;
  uint8_t com1Dlm = 0;
  bool com1Dlab = false;
  bool com1RxInterruptEnabled = false;
  bool com1RxDataReady = false;
  // COM2 (the host<->guest AMCH channel, 0x2F8) full register stats. Lets us tell
  // "Windows serial.sys never enumerated COM2" (all zero) from "it probed/initialized
  // the port but the agent never wrote data" (registerReads/lcrWrites/dllWrites > 0,
  // dataWrites == 0) -- the decisive split for the agent-telemetry diagnosis.
  SerialConsoleStats com2Stats{};
  uint64_t kdCom1RxQueuedBytes = 0;
  // KD named-pipe bridge (ANTIMAL_KD_PIPE) diagnostics: did a real debugger
  // attach, and did bytes flow each way? Distinguishes "guest never emitted KD"
  // from "bridge relayed but the debugger never synced".
  bool kdPipeActive = false;
  uint64_t kdPipeClientConnects = 0;
  uint64_t kdPipeBytesToDebugger = 0;
  uint64_t kdPipeBytesFromDebugger = 0;
  KdSerialSummary kdSummary;
  std::vector<KdSerialEvent> kdEvents;
  std::string kdTranscript;
  std::string kdPacketsJsonl;
  uint32_t ideCommandsIssued = 0;
  uint32_t ideIdentifyCommands = 0;
  uint32_t ideReadCommands = 0;
  uint32_t ideWriteCommands = 0;
  uint32_t ideAbortedCommands = 0;
  uint64_t ideSectorsRead = 0;
  uint64_t ideSectorsWritten = 0;
  // AHCI HBA activity (the PCI-native storage path that replaces compat IDE).
  uint64_t ahciCommandsIssued = 0;
  uint32_t ahciIdentifyCommands = 0;
  uint32_t ahciReadCommands = 0;
  uint32_t ahciWriteCommands = 0;
  uint64_t ahciSectorsRead = 0;
  uint64_t ahciSectorsWritten = 0;
  uint32_t ahciUnknownCommands = 0;
  uint32_t ahciLastCommand = 0;
  uint32_t ahciPortCmdWrites = 0;
  uint32_t ahciCiWrites = 0;
  uint64_t ahciAbarBase = 0;
  // Outbound Ethernet frames the guest transmitted through the e1000 NIC (only
  // populated when ANTIMAL_ENABLE_NIC). Raw bytes — the orchestrator runs the
  // PacketInspector over them (the Hypervisor layer can't depend on Common).
  std::vector<std::vector<uint8_t>> capturedNetworkFrames;
  uint64_t nicFramesTransmitted = 0;
  uint64_t nicFramesReceived = 0;   // frames the host sink delivered into the guest RX ring
  uint64_t nicFramesDropped = 0;    // inbound frames dropped (no free RX buffer / RX off)
  uint64_t nicRegisterWrites = 0;
  uint64_t pitIrqsDelivered = 0;
  uint64_t rtcIrqsDelivered = 0;
  uint32_t framesCaptured = 0;
  uint32_t eventsCaptured = 0;
  uint32_t artifactsCaptured = 0;
  // Measured live-display cadence (FramePacingStats::Summary()): achieved FPS vs
  // target, p50/p95/min/max inter-frame interval, on-target %, and blank-skips.
  // Empty for headless runs with no live-frame consumer. The diagnostics + the
  // path toward the 25-30 FPS goal.
  std::string liveFramePacingSummary;
};

struct VirtualMachineOptions {
  // Defaults are sized for a real Windows boot while keeping the first
  // working profile below 4 GiB. OVMF currently faults if it allocates into
  // our above-4G region, so high RAM remains opt-in until that path is proven.
  uint64_t lowRamBytes = 2048ull * 1024ull * 1024ull;
  uint64_t highRamBytes = 0;
  uint32_t processorCount = 1;
  // Hidden, non-E820 high mapping used only to satisfy OVMF's early fixed
  // high-shadow copy while we keep guest-visible high RAM disabled.
  uint64_t firmwareHighScratchBytes = 64ull * 1024ull * 1024ull;
  bool displayEnabled = false;
  // Expose the generated QEMU-style ACPI payload through fw_cfg so OVMF can
  // install the tables before Windows switches to its ACPI/APIC boot path.
  bool enableAcpiTables = true;
  // When true, attach the Bochs VBE framebuffer device + 16 MiB of guest
  // memory backing it. Production paths (detonate the user's sample) want
  // this so the firmware lights up GOP. Fast unit tests opt out so they
  // don't allocate the extra mapping or wait for OVMF's VGA scan.
  bool enableFramebuffer = true;
  // Include the TPM2 ACPI table in the fw_cfg payload. When WHP's LAPIC
  // emulation maps dummy pages over [0xFEC00000, 0xFEF00000), the TPM CRB
  // device is unreachable and advertising it via ACPI causes winload's
  // SpacebootInitialize to return STATUS_ILLEGAL_FUNCTION (0xC00000B9).
  // Default off until the TPM CRB is genuinely functional.
  bool enableTpm2Table = false;
  VmNetworkMode networkMode = VmNetworkMode::Disabled;
};

struct VmProgressSnapshot {
  int steps = 0;
  int totalHlts = 0;
  uint64_t ideCommandsIssued = 0;
  uint64_t ideSectorsRead = 0;
  uint64_t ideSectorsWritten = 0;
  uint32_t mmioReads = 0;
  uint32_t mmioWrites = 0;
  uint64_t ioApicDeliveries = 0;
  int timerInterruptsInjected = 0;
  int ideInterruptsInjected = 0;
  std::chrono::milliseconds elapsed{0};
  // Bytes written to COM1 since the last progress callback. Useful for
  // streaming OVMF / Windows boot log to the host UI.
  std::string newSerialBytes;
  // Bytes written to COM2 since the last progress callback. COM2 is the
  // first benign host<->guest channel for GuestAgent heartbeats.
  std::string newHostChannelBytes;
  // Top three IO ports by hit count, ordered descending by count. Useful for
  // diagnosing busy-wait spins on PM timer / PIT / PCI config.
  struct PortHit {
    uint16_t port = 0;
    uint64_t count = 0;
  };
  PortHit topPorts[3]{};
  // Snapshot of the legacy 0xB8000 VGA text framebuffer (80x25 character
  // cells, char in low byte, attribute in high byte). True when the buffer
  // has any non-zero byte — most modern OVMF builds run in GOP graphics mode
  // and never touch 0xB8000, but Windows bootloader and a few firmware paths
  // still use VGA text mode, so this is a cheap and useful "guest screen"
  // surface when it is populated.
  bool textFramebufferActive = false;
  uint16_t textFramebuffer[80 * 25] = {};
  // Current guest RIP + CS selector at the moment the snapshot was taken.
  // With CMOS / PM-timer spins the looping code stays at one RIP for
  // seconds at a time, which is enough to identify the kernel routine via
  // published Windows kernel PDBs.
  uint64_t currentRip = 0;
  uint16_t currentCsSelector = 0;
  // 32 bytes of guest code centered on RIP. The host translates the RIP via
  // the vCPU's paging state and copies the bytes here; consumers can hex-dump
  // the buffer to identify which instruction sequence the guest is looping
  // over. ripBytesValid is false when translation/copy fails (e.g. RIP not
  // currently mapped).
  bool ripBytesValid = false;
  uint8_t ripBytes[32]{};
  // Bochs VBE framebuffer info — width, height, bpp, and a host pointer the
  // host loop snapshot can render. The host pointer is valid as long as the
  // VirtualMachine instance that produced the snapshot is alive.
  bool framebufferEnabled = false;
  uint16_t framebufferWidth = 0;
  uint16_t framebufferHeight = 0;
  uint16_t framebufferBpp = 0;
  const uint8_t *framebufferHost = nullptr;
  size_t framebufferBytes = 0;
};

using VmProgressCallback = std::function<void(const VmProgressSnapshot &)>;

struct VmRunRequest {
  int maxSteps = 100000;
  std::chrono::milliseconds timeout{180000};
  VmNetworkMode networkMode = VmNetworkMode::Disabled;
  // Optional callback fired every `progressInterval` while the VM is running.
  // Callback is invoked from the host run-loop thread — keep it cheap; it
  // must not call back into the VirtualMachine instance.
  VmProgressCallback progressCallback;
  std::chrono::milliseconds progressInterval{1500};
  std::shared_ptr<std::atomic_bool> cancelRequested;
  // Optional probe input. Disabled by default. Scancodes are queued into the
  // emulated PS/2 controller after keyboardInjectAfter has elapsed. This is
  // intentionally primitive and is meant for boot UI probes such as pressing
  // Enter on Windows Recovery, not for general interactive control.
  std::vector<uint8_t> keyboardScancodes;
  std::chrono::milliseconds keyboardInjectAfter{0};
  // Sequenced keyboard bursts beyond the single-shot above. Each burst is
  // fired exactly once when its delay (relative to run start) has elapsed.
  // Use this to step through multi-screen boot UIs (e.g. recovery screen
  // F8 -> Startup Settings 7 -> disable driver signature enforcement).
  struct KeyboardBurst {
    std::chrono::milliseconds delay{0};
    std::vector<uint8_t> scancodes;
  };
  std::vector<KeyboardBurst> keyboardBursts;
  // Live interactive input (host->guest). When set, the run loop polls this file
  // for newly-appended raw Set-1 keyboard scancodes and injects them into the
  // PS/2 controller, giving the UI process real-time keyboard control of the VM.
  std::filesystem::path liveInputPath;
  // Live framebuffer publishing (guest->host). When set, the run loop mirrors the
  // Bochs VBE framebuffer into a named shared-memory section ~30x/s so the UI
  // process can render it straight to a <canvas> (no PNG encode / disk in the
  // path). Empty = disabled. This is the production "real VM display" channel.
  std::wstring liveFrameShmName;
};

class VirtualMachine {
public:
  VirtualMachine(const std::filesystem::path &firmwarePath,
                 IBlockDevice *ideDisk = nullptr,
                 VirtualMachineOptions options = {});

  VmRunSummary BootForSteps(int maxSteps = 100000);
  VmRunSummary Run(const VmRunRequest &request);
  void QueueCom2Bytes(const std::vector<uint8_t> &bytes) {
    com2_.QueueRxBytes(bytes);
  }
  // Host->guest payload delivered LAZILY by the run loop: dripped into COM2 in
  // small bursts, and only AFTER the guest agent starts transmitting (proof it
  // has opened COM2 and is actively draining the RX path). A one-shot ~100 KB
  // QueueCom2Bytes overruns the guest serial driver's RX in-queue before the
  // agent reads, silently dropping the front frame; pacing it post-handshake
  // avoids that. Used for the authorized-detonation execute payload (the small
  // healthcheck still goes via QueueCom2Bytes). Re-set per boot generation.
  void SetPacedCom2Payload(std::vector<uint8_t> bytes) {
    pacedCom2Payload_ = std::move(bytes);
    pacedCom2Cursor_ = 0;
  }
  std::string PullCom2Output() { return com2_.PullNew(); }
  void InjectKeyboardScancode(uint8_t scancode) {
    ps2_.InjectKeyboardScancode(scancode);
  }
  void InjectMousePacket(uint8_t buttons, int8_t dx, int8_t dy) {
    ps2_.InjectMousePacket(buttons, dx, dy);
  }

private:
  VmRunSummary RunLoop(int maxSteps,
                       std::chrono::steady_clock::time_point deadline,
                       const VmProgressCallback &progressCallback = nullptr,
                       std::chrono::milliseconds progressInterval =
                           std::chrono::milliseconds{1500},
                       std::shared_ptr<std::atomic_bool> cancelRequested = {},
                       std::vector<uint8_t> keyboardScancodes = {},
                       std::chrono::milliseconds keyboardInjectAfter =
                           std::chrono::milliseconds{0},
                       std::vector<VmRunRequest::KeyboardBurst>
                           keyboardBursts = {});
  void AttachDefaultDevices();
  void AttachIdeDisk(IBlockDevice *disk);
  void AttachAhciDisk(IBlockDevice *disk);
  void MaybeAttachNic();  // gated on ANTIMAL_ENABLE_NIC; default no-op.
  uint8_t *HostPointerForGpa(uint64_t gpa, size_t length) noexcept;
  bool ReadGuestMemory(uint64_t gva, void *buffer, size_t length);
  bool ReadGuestMemoryFor(Vcpu &vcpu, uint64_t gva, void *buffer,
                          size_t length);
  bool WriteGuestMemory(uint64_t gva, const void *buffer, size_t length);
  bool IdentifyGuestImage(uint64_t gva, VmGuestImageInfo *info);
  bool HandleStringIoPortAccess(const WHV_X64_IO_PORT_ACCESS_CONTEXT &io,
                                uint64_t rflags, bool *allPortsHandled);
  bool TryEmulateSimpleMmioAccess(const WHV_RUN_VP_EXIT_CONTEXT &exit,
                                  IMmioDevice *device, bool *isWrite);
  bool TryAssistFirmwarePageFault(uint64_t gva, uint32_t errorCode,
                                  uint64_t *mappedGpa);
  uint64_t AllocatePageTableAssistPage();

  static bool DeliverIoApicVector(void *context, uint32_t destination,
                                  uint8_t vector);

  WhpHost host_;
  GuestMemoryRegion lowRam_;
  std::unique_ptr<GuestMemoryRegion> highRam_;
  std::unique_ptr<GuestMemoryRegion> firmwareLowScratch_;
  std::unique_ptr<GuestMemoryRegion> firmwareUpperScratch_;
  std::unique_ptr<GuestMemoryRegion> framebuffer_;
  Firmware firmware_;
  Vcpu vcpu_;
  std::vector<std::unique_ptr<Vcpu>> apVcpus_;
  SerialConsole com1_;
  SerialConsole com2_;
  std::vector<uint8_t> pacedCom2Payload_;
  size_t pacedCom2Cursor_ = 0;
  PcIoDevices pcIo_;
  Ps2Controller ps2_;
  std::filesystem::path liveInputPath_; // live host->guest input file (framed)
  std::vector<uint8_t> liveInputRemainder_; // partial framed live-input record
  std::wstring liveFrameShmName_; // named shm section for the live framebuffer
  IoApic ioApic_;
  int whpIoApicGpaProbeResult_ = 0;
  uint64_t whpMmioGapBitmap_ = 0;
  HpetDevice hpet_;
  Tpm2CrbDevice tpm_;
  // True once the firmwareLowScratch region has been seeded with a
  // TCG_EfiSpecIDEvent03 header at kTpmEventLogGpa. The ACPI builder uses
  // this to decide whether to populate the LAML/LASA fields of the TPM2
  // table so winload's measured-boot path can locate the pre-boot log.
  bool tpmEventLogPopulated_ = false;
  bool tpm2TableEnabled_ = false;
  uint32_t tpmEventLogBytesWritten_ = 0;
  BochsVbeDevice vbe_;
  IoBus bus_;
  MmioBus mmioBus_;
  MmioEmulator mmioEmulator_;
  std::unique_ptr<IdeController> ide_;
  std::unique_ptr<IdeController> secondaryIde_;
  std::unique_ptr<AhciController> ahci_;
  std::unique_ptr<E1000Device> nic_;
  std::vector<std::vector<uint8_t>> capturedNetworkFrames_;
  static constexpr size_t kMaxCapturedFrames = 8192;
  uint64_t pageTableAssistBase_ = 0;
  uint64_t pageTableAssistNext_ = 0;
  uint64_t pageTableAssistLimit_ = 0;
  uint64_t highMappingBytes_ = 0;
};

} // namespace antimal::hv
