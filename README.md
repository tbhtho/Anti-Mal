# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [██████████████░░░] 80%

## Current Status

AntiMal has two major layers:

1. Static enrichment, which works today.
2. Dynamic detonation inside an AntiMal-owned Windows VM, which is actively being built on Windows Hypervisor Platform (WHP).

The scanner can already hash files, calculate entropy, parse PE metadata, mine strings and IOCs, apply rules/tags, and optionally call external tools such as YARA, capa, and Detect It Easy when those binaries are present. Threat-intel lookup support exists for MalwareBazaar and VirusTotal, but outbound intel is off by default.

The in-house VM has reached its biggest milestone yet: **it now boots Windows 11 24H2 all the way through the kernel and the full graphics/GUI stack to the "Getting ready" setup screen — the months-long `INACCESSIBLE_BOOT_DEVICE` (0x7B) storage wall is broken.** The WHP frontend creates a partition, runs vCPUs, maps RAM and OVMF firmware, emulates the PC hardware that OVMF and Windows need, exposes the boot disk through a **from-scratch in-house AHCI/SATA controller**, streams OVMF debug output, creates per-run copy-on-write overlays, and captures a real guest framebuffer PNG roughly every second.

A clean boot now runs the entire chain end to end — OVMF → `bootmgfw` → `winload.efi` → code-integrity → **ntoskrnl** → kernel Phase 0/1 → storage mount → service/session init → `win32k`/`dxgkrnl`/display → the **"Getting ready" screen** at 1280×800. Along the way it reads **~3.4 GB off the AHCI disk** (68K read commands) with **every one of 187,170 storage interrupts delivered**. Four major walls were cleared to get here:

1. `0xc0000225` code-integrity abort — cleared with a source-built TPM2-enabled OVMF (real `Tcg2Protocol` + in-house TPM 2.0 CRB stub) plus an overlay-only CI/VBS policy-off probe.
2. `0xc0430001` winload `SpacebootInitialize` wall — root-caused to a bug in *our own* ACPI checksum handling (all 8 ACPI tables now install; ntoskrnl/hal/ci/bootvid + all boot drivers load).
3. `0x7B INACCESSIBLE_BOOT_DEVICE` — root-caused to **two of our own bugs**: an ACPI `_HID` EISAID byte-order bug (so the OS never recognized the PCI root and never enumerated storage), then the realization that a compat-mode PCI IDE channel's *ISA-scope* resources (legacy ports + IRQ14) simply cannot be arbitrated for a device living in PCI scope. **The fix was to build a PCI-native AHCI controller** — its MMIO/PCI-interrupt resources arbitrate cleanly where the device lives, and `storahci.sys` binds and mounts the boot volume. (Diagnosed entirely via host-side guest-memory introspection — PnP devnode tree, `CM_RESOURCE_LIST`, resource-requirements walks — with no kernel debugger.)
4. Several hand-emulation gates: an OVMF runtime tick-wait spin, ACPI PM1 timer/status, IOAPIC interrupt routing, and page-fault re-injection.

**The one remaining boot gate is VM warm-reset.** After "Getting ready" (device specialize), Windows performs a normal first-boot **reboot** to continue to OOBE/login. The VM does not yet handle a guest-initiated reset, so the UEFI `ResetSystem` call no-ops and Windows falls into an `int 3` (surfacing as a `0x7E` bugcheck). The boot itself succeeded — the next step is to implement guest-reset → VM reboot so Windows completes setup into the login/desktop experience.

Real malware execution remains intentionally blocked. The project stages samples and creates reports, but `dynamic_execution_enabled = false` is the default and `sampleExecuted` stays false until the benign GuestAgent channel, overlay discard, artifact return, and report pipeline are proven end to end.

## What Works Today

- Win32 GUI: `AntiMal.exe`
- CLI scanner and report tools: `AntiMal.HostCli.exe`
- Static enrichment:
  - SHA-256
  - entropy
  - PE import and signature metadata
  - ASCII/UTF-16 string extraction
  - IOC mining for URLs, IPs, domains, registry paths, file paths, mutex hints, base64 blobs, and suspicious APIs
  - rule-based tracker tags
  - optional YARA/capa/DIE wrappers
  - optional MalwareBazaar/VirusTotal hash lookups
- JSON and self-contained HTML report generation
- In-house WHP VM that boots Windows 11 24H2 through the kernel + GUI stack to the "Getting ready" setup screen:
  - WHP host and vCPU wrappers; guest RAM and firmware mapping
  - source-built OVMF (release/debug, TPM2-enabled); serial debugcon capture
  - CMOS/RTC, PIT, PIC, LAPIC timer injection, IOAPIC (with `\_PIC` ACPI routing), HPET, fw_cfg, TPM 2.0 CRB stub, ACPI table generation
  - **from-scratch in-house AHCI/SATA controller** (PCI-native ABAR/MMIO + PCI-interrupt + command-list/FIS/PRDT DMA engine) against VHDX or raw/COW overlays — OVMF's AhciBusDxe and Windows' `storahci.sys` both drive it; a legacy PIIX4/IDE path (PIO + bus-master PRD DMA) also exists
  - the full Windows boot chain: OVMF → bootmgfw → winload → code-integrity → ntoskrnl → Phase 0/1 → **storage mount via AHCI** → service/session init → win32k/dxgkrnl/display → "Getting ready" (≈3.4 GB read off AHCI, 100% of storage interrupts delivered)
  - QEMU/Bochs VGA BAR sizing, Bochs VBE, OVMF GOP, and real guest framebuffer capture (boot spinner, "Getting ready", and BSOD screens visible in `guest-*.png`)
  - deep boot diagnostics from guest memory: `PsLoadedModuleList` walk, PnP devnode tree + `CM_RESOURCE_LIST`/resource-requirements parse, faulting-module identification, deep-stack + `KiBugCheckData` capture at the bugcheck
  - PS/2 scaffolding; COM2 host-channel codec and safe GuestAgent heartbeat mode

## What Is In Progress

The current milestone is "agent boot": carry the booted kernel past its last gate into the login/desktop experience so `AntiMal.GuestAgent.exe` can auto-start and send a COM2 heartbeat — proving the VM can run Windows code without executing the submitted sample.

The single active blocker is now **VM warm-reset**. After the kernel boots and Windows reaches the "Getting ready" device-specialize stage, it performs a *normal* first-boot **reboot** to continue to OOBE/login. The VM does not yet service a guest-initiated reset, so:

- Windows calls the UEFI `ResetSystem` runtime service to reboot.
- The VM has no reset handler, so the call returns instead of resetting (on real firmware it never returns).
- Control falls into ntoskrnl's `HalpPowerWriteResetCommand` `int 3` ("reset must never return"), which surfaces as a `0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` bugcheck.

This was pinpointed by mapping the `0x7E` faulting RIP to `ntoskrnl.exe!HalpPowerWriteResetCommand` via the kernel's own symbols — confirming the boot **succeeded** and the failure is purely the missing reboot path. Next step: implement guest-reset detection (reset port / ACPI reset) → VM warm-reset (vCPU reset-state + device re-init + re-run OVMF), so Windows completes its multi-phase setup into OOBE and the login/desktop.

The previous `0x7B` storage wall is **resolved** — see Current Status. It was cracked by switching the boot disk from the compat-mode PIIX4/IDE (whose ISA-scope legacy resources could not be arbitrated for a PCI-bus device) to a from-scratch PCI-native **AHCI** controller, after two of our own bugs (an ACPI EISAID byte-order bug and the IDETIM channel-decode gating) were found and fixed via guest-memory introspection.

After the boot reaches user mode, the remaining pipeline is: GuestAgent auto-start + COM2 heartbeat, a benign `healthcheck` job round-trip, and journal/screenshot/artifact return.

## Safety Model

AntiMal is meant for malware analysis, so safety beats speed.

- Network mode defaults to `disabled`.
- Threat-intel HTTP lookups are off unless explicitly enabled.
- The in-house VM stages samples but does not execute them by default.
- GuestAgent now heartbeats over COM2 when no executable job is authorized.
- Host-to-guest COM2 jobs are restricted to `kind=healthcheck` in this phase; submitted samples are staged but not launched.
- A future execution gate must prove:
  - benign GuestAgent connection
  - disposable overlay writes
  - overlay discard between runs
  - event journal return
  - screenshot/artifact return
  - timeout handling

## Build

Requirements:

- Windows x64
- Visual Studio 2022 C++ toolchain
- Windows SDK `10.0.26100.0`
- MSBuild
- Windows Hypervisor Platform optional feature for WHP tests and VM boot probes

Build all projects:

```powershell
msbuild AntiMal.sln /p:Configuration=Release /p:Platform=x64
```

Run tests:

```powershell
bin\x64\Release\AntiMal.Tests.exe
```

Some WHP and local-base tests print `SKIP:` when WHP, OVMF, or `C:\AntiMalRuns\_base\AntiMalBase.vhdx` is missing.

## First Run

Initialize config:

```powershell
bin\x64\Release\AntiMal.HostCli.exe init
```

Scan a file:

```powershell
bin\x64\Release\AntiMal.HostCli.exe scan C:\Path\To\File.exe --threshold 70
```

Stage and boot-probe a sample through the in-house VM path:

```powershell
$env:ANTIMAL_FIRMWARE_NAME = "OVMF-debug.fd"
bin\x64\Release\AntiMal.HostCli.exe detonate C:\Path\To\File.exe --network disabled --timeout-sec 180
```

This creates a run directory under `C:\AntiMalRuns`, writes `job.json`, `events.jsonl`, `report.json`, `report.html`, `serial.log`, `vm-summary.json`, `vm-diagnostics.txt`, and per-second `screenshots/guest-*.png` frames, and keeps sample execution blocked. The boot currently runs through the kernel and GUI stack (via the in-house AHCI disk) to the "Getting ready" setup screen, then stops at the not-yet-implemented VM warm-reset; the boot spinner, "Getting ready", and the resulting BSOD are all visible in the captured frames.

Before each in-house VM boot, AntiMal may apply a disposable overlay-only boot repair to the run disk (recovery disabled, boot-status policy set to ignore failed boots, `bootstat.dat` cleared, boot-storage services forced boot-start, CriticalDeviceDatabase IDE mappings added). The base VHDX is never mutated by this path. Set `ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH=1` to turn that diagnostic patch off for comparison probes.

The boot probe that reaches the GUI stack / "Getting ready" uses a set of overlay-only / firmware env flags (all scoped to the disposable run, never the base): `ANTIMAL_FIRMWARE_NAME=OVMF-debug.fd`, `ANTIMAL_PROBE_FWSPIN_NOP=1`, `ANTIMAL_PROBE_CI_POLICY_OFF=1`, `ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE=1`, `ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF=1`, `ANTIMAL_PROBE_BCD_LEGACY_CONTEXT=1`, `ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS=1`, `ANTIMAL_PROBE_SYSTEM_VBS_COMPAT=1`. Optional guest-introspection RVAs (Win11 24H2 ntoskrnl) add bugcheck/module/devnode capture: `ANTIMAL_BUGCHECK_DATA_RVA=0xF22740`, `ANTIMAL_PSLOADEDMODULELIST_RVA=0xEF50C0`, `ANTIMAL_IOPROOTDEVICENODE_RVA=0xF8B6A8`.

## Base Image

AntiMal does not ship Windows. You provide a Windows ISO and build a clean local base VHDX:

```powershell
powershell -ExecutionPolicy Bypass -File tools\New-AntiMalVmBase.ps1 `
  -WindowsIsoPath C:\Path\To\Windows.iso `
  -WorkspaceRoot C:\AntiMalRuns `
  -ConfigPath config\antimal.toml `
  -Provider local `
  -WriteConfig
```

The local builder uses built-in Windows tools: `diskpart`, `DISM`, and `bcdboot`. It does not launch a third-party VM manager. After `bcdboot`, the builder validates the base with an elevated PowerShell session. This is still useful for repair and GuestAgent installation, but the non-admin inspector can already confirm whether the ESP and BCD boot contract are coherent:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx
```

To repair UEFI boot files:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  -RepairBcd
```

`-RepairBcd` reruns `bcdboot`, restores `EFI\BOOT\BOOTX64.EFI`, pins `{bootmgr}` to the ESP, pins `{default}` `device`/`osdevice`/`path`/`systemroot` to the mounted Windows partition, re-inspects the BCD store, sets boot recovery policy so the sandbox base does not loop into recovery UI, marks boot storage services as boot-start, and adds CriticalDeviceDatabase mappings for the emulated PIIX IDE controller to `pciide`. It does not disable code integrity or signature checks.

To install the current GuestAgent into the base image for heartbeat testing:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  -GuestAgentPath bin\x64\Release\AntiMal.GuestAgent.exe
```

This copies the agent to `C:\AntiMal\AntiMal.GuestAgent.exe`, adds an automatic `AntiMalGuestAgent` service in the offline SYSTEM hive, and leaves a Run-key fallback for interactive logon scenarios.

You can also inspect the base VHDX without administrator privileges:

```powershell
bin\x64\Release\AntiMal.HostCli.exe base inspect `
  --vhdx C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  --dump-bcd C:\AntiMalRuns\_base\AntiMalBase-esp.bcd
```

This reads the VHDX through AntiMal's block device layer, parses GPT, parses the FAT32 ESP, checks the UEFI boot files, decodes the BCD registry hive, verifies the boot manager/default loader contract, parses the NTFS Windows partition, prints NTFS data-run/LBA ranges for boot files, verifies `winload.efi`, and decodes SYSTEM hive boot-storage service state. `base inspect --overlay <overlay.cow>` chains a copy-on-write overlay on top of the base (read-only) to show the post-patch view.

## Repository Layout

```text
src/Common/        shared types, scanner, reports, config, enrichment, journal
src/Hypervisor/    WHP VMM, firmware, devices, disks, ACPI, host channel
src/App/           Win32 GUI
src/HostCli/       command-line scan/detonate/report tool
src/GuestAgent/    in-guest agent, currently heartbeat-safe by default
src/Tests/         self-contained Expect() test binary
tools/             base-image, firmware, and validation scripts
firmware/          current private-checkpoint OVMF blobs
docs/              design docs and roadmap
rules/             tagger rules
```

## Roadmap

- 35%: complete. Static enrichment works; WHP/OVMF boot path reaches Windows Boot Manager.
- 45%: complete. Windows reaches `winload.efi` as identified loader code in guest RAM.
- 52%: complete. Source-built TPM2 OVMF + CI/VBS policy-off probe got winload past the `0xc0000225` code-integrity abort to the `0xc0430001` `SpacebootInitialize` / Kernel.BootEnvironment phase.
- **58%: complete. winload wall SHATTERED.** Root-caused the BootEnvironment abort to our own ACPI table builder pre-storing non-zero SDT checksums (OVMF's in-place recompute inverted them → only 1 table installed → no MADT). Leaving the checksum bytes zero installs all 8 ACPI tables, and **ntoskrnl + hal + ci + bootvid + every boot driver now load and execute.**
- **64%: complete. Live kernel.** ntoskrnl runs Phase 0/1 and renders the bootvid boot spinner. Cleared the OVMF runtime tick-wait spin (PM timer), ACPI PM1 timer/status emulation, IOAPIC-routed IDE IRQ delivery (`\_PIC` method), and page-fault re-injection.
- **68%: complete. 0x7B storage wall BROKEN.** Root-caused `INACCESSIBLE_BOOT_DEVICE` to two of our own bugs — an ACPI `_HID` EISAID byte-order bug (PCI root never recognized → no storage enumeration) and PIIX4 IDETIM channel-decode gating — then found a compat-mode PCI IDE channel's ISA-scope resources can't be arbitrated for a PCI-bus device. Built a **from-scratch PCI-native AHCI controller**; `storahci.sys` binds it and mounts the boot volume. Diagnosed via guest-memory introspection (PnP devnode tree + `CM_RESOURCE_LIST` + resource-requirements walks), no KD.
- **80%: in progress. Boots to the GUI stack.** Windows boots through ntoskrnl Phase 0/1 → AHCI storage mount → service/session init → win32k/dxgkrnl/display to the **"Getting ready"** screen (~3.4 GB read off AHCI, 100% of 187K storage interrupts delivered). Remaining gate: implement **VM warm-reset** so the normal first-boot reboot succeeds into OOBE/login (currently the missing reset path surfaces as a `0x7E`).
- 85%: VM warm-reset handled → Windows completes setup and reaches login/desktop in-house.
- 88%: GuestAgent auto-starts in user mode and sends a COM2 heartbeat.
- 91%: host sends a benign job to GuestAgent and receives journal/report artifacts.
- 94%: real screenshots/framebuffer and interactive input are usable end to end.
- 97%: disposable overlays, timeout handling, artifact return are hardened; network modes + live UI.
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
