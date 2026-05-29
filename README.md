# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [████████████░░░░░] 68%

## Current Status

AntiMal has two major layers:

1. Static enrichment, which works today.
2. Dynamic detonation inside an AntiMal-owned Windows VM, which is actively being built on Windows Hypervisor Platform (WHP).

The scanner can already hash files, calculate entropy, parse PE metadata, mine strings and IOCs, apply rules/tags, and optionally call external tools such as YARA, capa, and Detect It Easy when those binaries are present. Threat-intel lookup support exists for MalwareBazaar and VirusTotal, but outbound intel is off by default.

The in-house VM has reached a major milestone: **it now boots Windows 11 24H2 to a live kernel.** The WHP frontend creates a partition, runs vCPUs, maps RAM and OVMF firmware, emulates the PC hardware that OVMF and Windows need, exposes an IDE disk (PIO + bus-master DMA), streams OVMF debug output, creates per-run copy-on-write overlays, and captures a real guest framebuffer PNG roughly every second.

A clean boot now runs the entire firmware-and-loader chain end to end — OVMF → `bootmgfw` → `winload.efi` → code-integrity → **ntoskrnl** — and the kernel itself starts executing. The two winload walls that used to stop the boot are solved:

1. The `0xc0000225` code-integrity abort was cleared with a source-built TPM2-enabled OVMF (a real `Tcg2Protocol` answered by an in-house TPM 2.0 CRB stub with stateful PCR banks + a TCG event log) plus an overlay-only CI/VBS policy-off probe.
2. The `0xc0430001` winload `SpacebootInitialize` / BootEnvironment wall was root-caused to a bug in *our own* ACPI table builder: we pre-stored non-zero SDT checksums, and OVMF's in-place checksum recompute then inverted them, so the OS saw only "1 table installed" and never found the MADT. Leaving the checksum bytes zero for the loader to fill made all 8 ACPI tables install correctly — and **ntoskrnl, hal, ci, bootvid, and every boot driver now load and execute.**

From there the kernel runs Phase 0 and Phase 1, renders the bootvid boot spinner, and reaches the storage-initialization stage. Several more hand-emulation gates were cleared to get this far: an OVMF runtime tick-wait spin (PM timer), ACPI PM1 timer/status emulation, IOAPIC-routed IDE IRQ delivery via a `\_PIC` ACPI method, and page-fault re-injection.

**The one remaining boot gate is `INACCESSIBLE_BOOT_DEVICE` (0x7B).** Custom VM instrumentation pinned it precisely: the IDE controller works (winload reads the full 205,822-sector OS image through it), and the kernel's pci.sys reads the IDE controller's PCI config tens of thousands of times — but the kernel's `pciide`/`atapi` storage miniport never accesses the IDE hardware, so the boot disk device object is never created and the boot-device-arrival wait times out. This is a kernel-side PnP/driver-load failure rather than a hardware-emulation gap: a real PIIX4 bus-master IDE DMA engine was added (OVMF boots cleanly through it) and ruled bus-master out as the cause. Cracking it next needs kernel-state introspection (e.g. walking `PsLoadedModuleList` at the bugcheck to see whether the storage driver even loads).

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
- In-house WHP VM that boots Windows 11 24H2 to a live kernel:
  - WHP host and vCPU wrappers; guest RAM and firmware mapping
  - source-built OVMF (release/debug, TPM2-enabled); serial debugcon capture
  - CMOS/RTC, PIT, PIC, LAPIC timer injection, IOAPIC (with `\_PIC` ACPI routing), HPET, fw_cfg, TPM 2.0 CRB stub, ACPI table generation
  - PIIX4/IDE storage (PIO **and** real bus-master PRD DMA) against VHDX or raw/COW overlays
  - the full Windows boot chain: OVMF → bootmgfw → winload → code-integrity → ntoskrnl, then kernel Phase 0/1 + the bootvid boot spinner (stops at the 0x7B storage-attach gate)
  - QEMU/Bochs VGA BAR sizing, Bochs VBE, OVMF GOP, and real guest framebuffer capture (boot spinner + kernel screens visible in `guest-*.png`)
  - deep boot diagnostics: per-GSI IOAPIC programming, IDE config-probe counts, deep-stack + KiBugCheckData capture at the bugcheck
  - PS/2 scaffolding; COM2 host-channel codec and safe GuestAgent heartbeat mode

## What Is In Progress

The current milestone is "agent boot": carry the live kernel past its last boot gate into user mode so `AntiMal.GuestAgent.exe` auto-starts and sends a COM2 heartbeat — proving the VM can boot Windows code without executing the submitted sample.

The single active blocker is the `INACCESSIBLE_BOOT_DEVICE` (0x7B) bugcheck. Diagnosis from custom VM instrumentation:

- `bugCheckData` is code `0x7B`, param2 `0xC0000034` (STATUS_OBJECT_NAME_NOT_FOUND): the boot disk device object is never created, so the boot volume name never resolves.
- The IDE controller works — winload reads the full 205,822-sector OS image via PIO — and the kernel's pci.sys reads the IDE's PCI config ~81,000 times (the boot-device-arrival wait loop).
- But the kernel never issues a single IDE *port* command (`ideCommandsIssued` stays at winload's count): `pciide`/`atapi` enumerate the controller but never touch the hardware. The disk is never created → arrival timeout → 0x7B.
- Four host-side hypotheses were attempted and ruled out as the cause: a `\_PIC` ACPI method, IOAPIC IDE IRQ routing, a clean compat-mode INT-pin config, and a full PIIX4 bus-master DMA engine (OVMF boots through it, but no DMA commands are issued, so bus-master is not the blocker).

Because the failure lives inside the kernel's PnP/driver-load path and is invisible from the host side, the next steps are kernel-state introspection:

- Walk `PsLoadedModuleList` from guest memory at the bugcheck to learn whether `pciide.sys`/`atapi.sys` even load (load-failure vs StartDevice-failure — splits the problem cleanly).
- Bring up kernel debugging (KD) over the already-wired COM1, which would expose the exact StartDevice/IRP failure. KD enablement currently regresses winload and needs its own fix first.

Boot-storage groundwork is already in place (overlay-only, never mutating the base VHDX): `pciide`/`intelide`/`atapi`/`disk`/`partmgr`/`mountmgr` are forced boot-start, CriticalDeviceDatabase mappings for the PIIX IDE controller (`pci#ven_8086&dev_7111`, `pci#cc_0101`) are injected, and the SYSTEM hive is refreshed clean.

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

This creates a run directory under `C:\AntiMalRuns`, writes `job.json`, `events.jsonl`, `report.json`, `report.html`, `serial.log`, `vm-summary.json`, `vm-diagnostics.txt`, and per-second `screenshots/guest-*.png` frames, and keeps sample execution blocked. The boot currently runs to the live kernel and the 0x7B storage-attach gate; the BSOD and the bootvid spinner are visible in the captured frames.

Before each in-house VM boot, AntiMal may apply a disposable overlay-only boot repair to the run disk (recovery disabled, boot-status policy set to ignore failed boots, `bootstat.dat` cleared, boot-storage services forced boot-start, CriticalDeviceDatabase IDE mappings added). The base VHDX is never mutated by this path. Set `ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH=1` to turn that diagnostic patch off for comparison probes.

The boot probe that reaches the live kernel uses a set of overlay-only / firmware env flags (all scoped to the disposable run, never the base): `ANTIMAL_FIRMWARE_NAME=OVMF-debug.fd`, `ANTIMAL_PROBE_FWSPIN_NOP=1`, `ANTIMAL_PROBE_CI_POLICY_OFF=1`, `ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE=1`, `ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF=1`, `ANTIMAL_PROBE_BCD_LEGACY_CONTEXT=1`, `ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS=1`, `ANTIMAL_PROBE_SYSTEM_VBS_COMPAT=1`.

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
- **68%: in progress. Last boot gate.** Kernel reaches storage-init and bugchecks `INACCESSIBLE_BOOT_DEVICE` (0x7B): pci.sys enumerates the IDE but `pciide`/`atapi` never attach, so the boot disk is never created. A real PIIX4 bus-master DMA engine was built (ruled bus-master out). Next: kernel-state introspection (`PsLoadedModuleList` walk / KD) to find the StartDevice failure.
- 72%: storage stack attaches → Windows reaches login/desktop in-house.
- 76%: GuestAgent auto-starts in user mode and sends a COM2 heartbeat.
- 82%: host sends a benign job to GuestAgent and receives journal/report artifacts.
- 88%: real screenshots/framebuffer and interactive input are usable end to end.
- 93%: disposable overlays, timeout handling, and artifact return are hardened.
- 97%: network modes, richer collectors, and live UI are added.
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
