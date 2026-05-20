# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [███████░░░░░░░░░░░] 35%

## Current Status

AntiMal has two major layers:

1. Static enrichment, which works today.
2. Dynamic detonation inside an AntiMal-owned Windows VM, which is actively being built on Windows Hypervisor Platform (WHP).

The scanner can already hash files, calculate entropy, parse PE metadata, mine strings and IOCs, apply rules/tags, and optionally call external tools such as YARA, capa, and Detect It Easy when those binaries are present. Threat-intel lookup support exists for MalwareBazaar and VirusTotal, but outbound intel is off by default.

The in-house VM path is past the toy stage but not finished. The WHP frontend can create a partition, run vCPUs, map RAM and OVMF firmware, emulate enough PC hardware for OVMF to boot, expose an IDE disk, stream OVMF debug output, create per-run copy-on-write overlays, and render host-side live progress frames. The current Windows boot probe reaches `bootmgfw.efi`, opens BCD and code-integrity policy files, performs real IDE reads/writes, brings up OVMF QemuVideo/GOP, and captures real guest framebuffer PNGs. The latest visible guest state is Windows Recovery error `0xc0000225`, so the remaining 45% blocker is now sharply identified as base/BCD boot repair before `winload.efi`, not a blind firmware or graphics hang.

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
- In-house WHP VM core:
  - WHP host and vCPU wrappers
  - guest RAM and firmware mapping
  - OVMF release/debug firmware blobs
  - serial debugcon capture
  - CMOS/RTC, PIT, PIC, LAPIC timer injection, IOAPIC, HPET, fw_cfg, ACPI table generation
  - PIIX/IDE PIO storage against VHDX or raw/COW overlays
  - QEMU/Bochs VGA BAR sizing, Bochs VBE, OVMF GOP, and real guest framebuffer capture
  - PS/2 scaffolding
  - COM2 host-channel codec and safe GuestAgent heartbeat mode

## What Is In Progress

The current milestone is "agent boot": get a benign Windows base image far enough into user mode that `AntiMal.GuestAgent.exe` auto-starts and sends a COM2 heartbeat to the host. That heartbeat proves the VM can boot Windows code without executing the submitted sample.

The active blockers are:

- Validate or repair the base VHDX boot files so `bootmgfw.efi` proceeds to `winload.efi`. The newest guest framebuffer shows Windows Recovery error `0xc0000225`, which is the strongest evidence so far that the next step is BCD/device repair on the base image.
- Keep the Windows boot manager contract visible in diagnostics after BCD and code-integrity policy loads. ACPI PM1/S5 metadata is no longer treated as the immediate blocker: the FADT advertises legacy and extended PM1 blocks, the PM1 control trap preserves byte writes, and only S4/S5 requests stop the VM.
- Continue interrupt diagnostics while boot repair is pending. Run diagnostics record pending IDE/PIT/RTC latches, IOAPIC redirection entries, PIC vector bases, PIC masks, and whether each interrupt was delivered by IOAPIC, PIC fallback, or failed routing.
- Install GuestAgent into the base image and auto-start it from the offline SYSTEM hive service entry. The older HKLM Run autostart remains as a fallback.
- Decode COM2 GuestAgent frames in the host report path, send a benign `healthcheck` job, and return `agent-health.json` once the guest service reaches user mode.

Latest local probe:

- `ANTIMAL_FIRMWARE_NAME=OVMF-debug.fd`
- `AntiMal.HostCli.exe detonate bin\x64\Release\AntiMal.Tests.exe --network disabled --timeout-sec 75`
- Run `cbcabd11-5cf8-4d3f-9c95-591faa484c59`
- Result: timed out before `winload`; `sampleExecuted=false`; `guestAgentConnected=false`; real framebuffer frames captured; guest screen shows Windows Recovery `0xc0000225`.
- Disk I/O is real: `ideCommandsIssued=530`, `ideReadCommands=515`, `ideSectorsRead=60017`, `ideWriteCommands=5`, and `ideSectorsWritten=38`.
- Interrupt routing is still blocked: `ideInterruptsRequested=40670`, `ideInterruptsInjected=0`, `ideInterruptsFailed=40670`, `irqIoApicDeliveries=0`, `irqPicFallbackDeliveries=0`, and `irqDeliveryFailures=2680187`.
- Legacy interrupt state is now explicit: IRQ0, IRQ3, IRQ4, IRQ8, IRQ14, and IRQ15 IOAPIC entries are masked; master/slave PIC vector bases are `0x00`; master/slave PIC masks are `0xff`.
- Boot milestones include fallback bootloader open, `bootmgfw` load, BCD open, and code-integrity policy open. OVMF QemuVideo/GOP now initializes at `1280x800x32`; the old 2 GiB VGA BAR resource conflict is fixed.
- This shell was not elevated, so the base validator/repair and offline GuestAgent service install could not be run here.

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

This currently creates a run directory under `C:\AntiMalRuns`, writes `job.json`, `events.jsonl`, `report.json`, `report.html`, `serial.log`, `vm-summary.json`, and `vm-diagnostics.txt`, and keeps sample execution blocked.

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

The local builder uses built-in Windows tools: `diskpart`, `DISM`, and `bcdboot`. It does not launch a third-party VM manager. After `bcdboot`, the builder validates the base with an elevated PowerShell session. This is currently the most important next manual/elevated step because the non-elevated probe reaches `bootmgfw` but not `winload`:

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

`-RepairBcd` reruns `bcdboot`, restores `EFI\BOOT\BOOTX64.EFI`, pins `{bootmgr}` to the ESP, pins `{default}` `device`/`osdevice`/`path`/`systemroot` to the mounted Windows partition, re-inspects the BCD store, and sets boot recovery policy so the sandbox base does not loop into recovery UI. It does not disable code integrity or signature checks.

To install the current GuestAgent into the base image for heartbeat testing:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  -GuestAgentPath bin\x64\Release\AntiMal.GuestAgent.exe
```

This copies the agent to `C:\AntiMal\AntiMal.GuestAgent.exe`, adds an automatic `AntiMalGuestAgent` service in the offline SYSTEM hive, and leaves a Run-key fallback for interactive logon scenarios.

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

- 35%: current checkpoint. Static enrichment works; WHP/OVMF boot path reaches Windows Boot Manager.
- 45%: Windows reaches `winload.efi` reliably from the AntiMal base VHDX.
- 55%: GuestAgent auto-starts in user mode and sends COM2 heartbeat.
- 65%: Host sends a benign job to GuestAgent and receives journal/report artifacts.
- 75%: Real screenshots/framebuffer and interactive input are usable.
- 85%: Disposable overlays, timeout handling, and artifact return are hardened.
- 95%: Network modes, richer collectors, and live UI are added.
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
