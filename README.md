# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [████████████████░] 90%

> **For the authoritative, dated "where we are" status, read private development documentation (private documentation) first.** This section is the narrative; that file is the single source of truth.

## Current Status

AntiMal has two major layers:

1. **Static enrichment — ships today.** Hash, entropy, PE metadata, strings + IOC mining, rule/tag tracker, optional YARA/capa/DIE, optional MalwareBazaar/VirusTotal lookups (off by default), JSON + HTML reports.
2. **Dynamic "live sandbox" — software complete, runtime-gated.** The in-house WHP VM now boots Windows 11 25H2 **all the way to login and the desktop** (the desktop *has* been reached — that's how the desktop snapshot was made), a **WebView2 live console** UI is built, the **host↔guest telemetry pipeline** and **live keyboard+mouse input** are wired, and the GuestAgent is **installed in the base image**.

**The full boot chain works:** OVMF → `bootmgfw` → `winload.efi` → code-integrity → **ntoskrnl** → kernel Phase 0/1 → **AHCI storage mount** → win32k/dxgkrnl/display → OOBE → **VM warm-reset (guest reboot is serviced)** → interactive OOBE / account creation → **login → "Preparing Windows" → desktop**. Walls cleared to get here include: the `0xc0000225` code-integrity abort (source-built TPM2 OVMF), the `0xc0430001` winload wall (our own ACPI checksum bug), the **`0x7B INACCESSIBLE_BOOT_DEVICE`** storage wall (built a from-scratch PCI-native **AHCI** controller — `storahci.sys` binds it), VM warm-reset, the **injected-input garbling** (fixed by pacing keystrokes), and a **CET kernel hang** (Windows wedged enabling CET shadow stacks; fixed by masking CET in CPUID leaf 7 — the boot now reaches user mode and reboots normally).

**The one thing not yet closed is reliability:** reaching a stable logged-in desktop *every automated run* is intermittent — one run reaches the desktop / "Preparing Windows", the next stalls or reboot-loops. The remaining work is VMM systems engineering (1-vCPU first-logon stalls and a 2-vCPU AP-bringup SMP race). Boots are **bounded** — they time out cleanly via `--timeout-sec` (an earlier "watchdog wedge / boots run for hours" diagnosis was a host-side PowerShell-poller artifact, not the VM) — so the blocker is the *hang itself*, not runaway boots. See `private development documentation` for the exact failure modes and the ordered plan.

Real malware execution remains intentionally blocked. The project stages samples and creates reports, but `dynamic_execution_enabled = false` is the default and `sampleExecuted` stays false until the benign GuestAgent channel, overlay discard, artifact return, and report pipeline are proven end to end on a stable desktop.

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
- **WebView2 live console** (`AntiMal.exe`): the Win32 app is now a thin shell hosting a hardened WebView2 UI (`webui/`, vanilla HTML/CSS/JS), 8 sections all wired to a real C++ bridge — scan, config, reports, dashboard, browser-impact, and the live VM view (**Boot VM (live)** streams frames + accepts mouse/keyboard).
- **Host↔guest telemetry pipeline (3b):** in-guest process collector (`ProcessTelemetry`, unit-tested) → COM2/AMCH channel → host live-journaling to `events.jsonl` → UI Live Process Telemetry panel (`run.watch`). The `AntiMalGuestAgent` service is installed in the base image. *(Streams the moment a stable desktop is reached.)*
- **Live interaction (3c):** the running VM's framebuffer is streamed into the UI, and keyboard + mouse are injected back into the VM in real time via a framed `_live-input.bin` protocol. The live VM runs in a separate process from the UI (escape-isolation).
- In-house WHP VM that boots Windows 11 25H2 through the kernel + GUI stack + OOBE + **login to the desktop** (intermittently — see Current Status):
  - WHP host and vCPU wrappers; guest RAM and firmware mapping
  - source-built OVMF (release/debug, TPM2-enabled); serial debugcon capture
  - CMOS/RTC, PIT, PIC, LAPIC timer injection, IOAPIC (with `\_PIC` ACPI routing), HPET, fw_cfg, TPM 2.0 CRB stub, ACPI table generation
  - **from-scratch in-house AHCI/SATA controller** (PCI-native ABAR/MMIO + PCI-interrupt + command-list/FIS/PRDT DMA engine) against VHDX or raw/COW overlays — OVMF's AhciBusDxe and Windows' `storahci.sys` both drive it; a legacy PIIX4/IDE path (PIO + bus-master PRD DMA) also exists
  - the full Windows boot chain: OVMF → bootmgfw → winload → code-integrity → ntoskrnl → Phase 0/1 → **storage mount via AHCI** → service/session init → win32k/dxgkrnl/display → OOBE → **VM warm-reset** → account creation / **login** → "Preparing Windows" → **desktop** (reached intermittently)
  - **VM warm-reset**: guest-initiated reset (`0xCF9`/ACPI) recreates the VM (cold boot, overlay persists) so Windows' multi-phase first-boot reboots succeed
  - **paced host→guest keyboard + mouse injection** (the OOBE script types correctly, the login password is accepted) and a framed live-input channel for real-time UI interaction
  - QEMU/Bochs VGA BAR sizing, Bochs VBE, OVMF GOP, and real guest framebuffer capture (boot spinner, "Getting ready", and BSOD screens visible in `guest-*.png`)
  - deep boot diagnostics from guest memory: `PsLoadedModuleList` walk, PnP devnode tree + `CM_RESOURCE_LIST`/resource-requirements parse, faulting-module identification, deep-stack + `KiBugCheckData` capture at the bugcheck
  - PS/2 scaffolding; COM2 host-channel codec and safe GuestAgent heartbeat mode

## What Is In Progress

All of the dynamic-sandbox *software* is built (live console, telemetry pipeline, live input, agent deployed). The **one remaining gate is runtime reliability: the VM reaching a stable logged-in desktop on every automated run.** The desktop has been reached, but intermittently — so the agent doesn't yet auto-stream telemetry end-to-end (`hostChannelBytes` is still `0` because no automated run has held a stable desktop long enough for the agent service to connect).

Boots are **bounded** (the watchdog reliably fires `--timeout-sec`; every run shows `timedOut:true`). The blocker is the *hang itself*, not runaway boots. The failure modes (full detail + ordered plan in private development documentation (private documentation)):

1. **1-vCPU first-logon stall:** boots reach OOBE/login/"Preparing Windows" but the first-logon finalization hangs (a user-mode wait, RIP `0x7FF8…`). The hard part is *naming* what's hung — best unlocked by getting a real kernel debugger attached (KD-over-serial, partially set up) rather than guessing struct offsets. The VM has **no NIC**, which can stall network-dependent first-logon work (a virtual NIC, Milestone C.1, is a strong candidate fix and is needed anyway).
2. **2-vCPU AP-bringup race:** deterministically spins at a kernel SMP rendezvous (`ntkrnlmp+0x2916EC`) — an AP-bringup synchronization bug (confirmed *not* CET-related). 2-vCPU is the better long-term path because first-logon is heavy SMP work.

Once a stable desktop is reached, the baked agent service auto-starts → streams `process.*` over COM2 → `events.jsonl` → the UI panel, on a desktop you can see and drive — closing both 3b (live telemetry) and 3c (live interaction). Then re-snapshot `AntiMalDesktop.cow` from the agent-equipped desktop for fast seed-boots.

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
- **80%: complete. Boots to the GUI stack** (ntoskrnl Phase 0/1 → AHCI mount → win32k/dxgkrnl/display → "Getting ready").
- **85%: complete. VM warm-reset + login/desktop.** Guest-initiated reset (`0xCF9`/ACPI) is serviced (VM recreated, overlay persists), so Windows' first-boot reboots succeed → OOBE → account creation → **login → "Preparing Windows" → desktop** (reached, intermittently). Injected-input garbling fixed by **pacing**; a **CET kernel hang** (CPUID leaf 7) fixed so the boot reaches user mode.
- **88%: complete. Live console + telemetry + input software.** WebView2 UI + bridge; in-guest process collector + COM2/AMCH channel + host journaling + UI panel; live keyboard+mouse injection; GuestAgent installed in the base.
- **90%: in progress. Desktop-reach RELIABILITY** — the one remaining runtime gate. Boots are bounded (they time out cleanly) but reach the desktop only intermittently; closing it means diagnosing + fixing the first-logon "Preparing Windows" hang (best via a real kernel debugger) and/or the 2-vCPU AP rendezvous, plus likely a virtual NIC. See `private development documentation`.
- 93%: agent auto-streams `process.*` telemetry from a reliably-reached desktop → UI (3b live); live mouse/keyboard interaction proven on that desktop (3c live); re-snapshot the agent-equipped desktop.
- 96%: benign job round-trip, disposable-overlay discard, artifact return, timeout handling hardened; network modes + fake-internet.
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
