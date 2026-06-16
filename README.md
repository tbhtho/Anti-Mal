# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [█████████████████░] 92%

> **For the authoritative, dated "where we are" status, read private development documentation (private documentation) first** (and the latest session record [`historical session notes (not distributed)`](historical session notes (not distributed))). This section is the narrative; those files are the source of truth.

## Current Status

AntiMal has two major layers:

1. **Static enrichment — ships today.** Multi-hash + entropy, deep PE metadata, magic-byte file typing, **file-type-aware analyzers for scripts / `.lnk` / Office-OLE macros / archives**, strings + IOC mining with **obfuscated-C2 recovery** (XOR / base64 / PowerShell `-EncodedCommand`), rule/tag tracker, optional YARA/capa/DIE, optional MalwareBazaar/VirusTotal lookups (off by default), JSON + HTML reports.
2. **Dynamic "live sandbox" — boots to a real desktop, with a deep analysis pipeline; one blocker left.** The in-house WHP VM boots Windows 11 25H2 **to an actual desktop** (live-confirmed 2026-06-09: the console showed the bloom desktop with Recycle Bin + Edge icons at a live **`LIVE · 14 FPS`** readout, telemetry *Watching*), the **WebView2 live console** streams the framebuffer + accepts keyboard/mouse, and the **host↔guest telemetry pipeline streams live** (122 KB of `events.jsonl` captured on that boot).

**The full boot chain works:** OVMF → `bootmgfw` → `winload.efi` → code-integrity → **ntoskrnl** → kernel Phase 0/1 → **AHCI storage mount** → win32k/dxgkrnl/display → OOBE → **VM warm-reset (guest reboot is serviced)** → account creation → **login → "Preparing Windows" → desktop**. Walls cleared to get here: the `0xc0000225` code-integrity abort (source-built TPM2 OVMF), the `0xc0430001` winload wall (our own ACPI checksum bug), the **`0x7B INACCESSIBLE_BOOT_DEVICE`** storage wall (a from-scratch PCI-native **AHCI** controller — `storahci.sys` binds it), VM warm-reset, **injected-input garbling** (fixed by pacing), and a **CET kernel hang** (fixed by masking CET in CPUID leaf 7).

**The framing corrected (2026-06-09):** the blocker was never *boot reliability* — the VM reaches a desktop. The real issue was a **non-interactive, "frozen-screenshot" desktop**, now diagnosed cold to two causes: (1) the seed snapshot `AntiMalDesktop.cow` was captured **mid-first-logon** (`LastUsedUsername=defaultuser0`), so every boot resumes a half-provisioned Windows whose XAML/`twinui` shell (`ShellHost.exe`) crash-loops — **but it does reach a settled desktop if left ~15-30 min**, so the fix is a **re-snapshot of a settled desktop** (`tools\Promote-DesktopSnapshot.ps1`, backup-first, base untouched); and (2) **mouse clicks don't reliably land** (relative-PS/2-mouse desync). Also fixed this session: the live display no longer **freezes** on low-variance frames (`LiveFramePublishGate`). Full detail + resume steps in [`historical session notes (not distributed)`](historical session notes (not distributed)).

**Deep dynamic-analysis pipeline (built + reviewed this session, live on Detonate via per-run agent redeploy):** rich process telemetry (full path, command line, integrity, user/SID, session, start time, **exit codes**), persistence detection across 8 families with **ATT&CK tags**, an in-guest **WER crash decoder** (names the faulting module behind a crash), **dropped-file** SHA-256 + magic-byte type, **DLL-load / injection** detection (side-loaded/hijacked DLLs → T1574), a **scored, explainable behavioral verdict** (kills the `timeout==Malicious` false positive; signed-installer FP dampened), an **analyst-grade report** (process tree + persistence/drops/network/crashes/MITRE sections), and machine-readable **IOC export** (STIX 2.1 / MISP / CSV via `HostCli export`).

In-guest sample execution is **wired but gated off by default** behind a two-key gate: it arms only when `dynamic_execution_enabled = true` (config) **and** `--allow-execution` is passed to `detonate` (plus the guest's own arm). When armed, the host delivers the staged sample over COM2 (paced) and the GuestAgent launches it and streams its behavior. The live console's **Detonate Sample (live)** button self-arms the gate and deploys the execute-capable agent into the disposable overlay per run. See `historical design notes (not distributed)`.

## What Works Today

- Win32 GUI: `AntiMal.exe`
- CLI scanner and report tools: `AntiMal.HostCli.exe`
- Static enrichment:
  - multi-hash triage: **MD5 / SHA-1 / SHA-256 / imphash** + Shannon entropy
  - **deep PE parse**: imports, Authenticode signature, section table + per-section entropy, compile timestamp, overlay + embedded-PE (dropper) detection, exports, VERSIONINFO, TLS callbacks, .NET/CLR, Rich header, debug/PDB path
  - **magic-byte file-type identification** + masquerade detection (a PE wearing a `.pdf`/`.doc` extension; an OriginalFilename mismatch)
  - **file-type-aware analyzers** for the non-PE delivery formats malware actually ships in:
    - **scripts** (PowerShell / JScript / VBScript / batch / HTA / WSF): encoded commands, download cradles, LOLBin fetches, AMSI bypass, IEX/shell exec, hidden/bypass flags, char-code obfuscation — and **one-layer deobfuscation** that decodes a PowerShell `-EncodedCommand` and recovers the hidden C2
    - **`.lnk` shortcuts** (MS-SHLLINK): recovers the embedded command line + target and flags a shortcut that silently launches a LOLBin (powershell/cmd/mshta/rundll32/…)
    - **Office / OLE documents**: VBA-macro presence, auto-exec entry points, and embedded exploit objects (Equation Editor CVE-2017-11882 family)
    - **archives / OOXML** (zip family): macro-doc detection (`vbaProject.bin`) plus executable payloads, double-extension lures, and password-protected entries
    - **PDF**: `/JavaScript`, auto-actions (`/OpenAction`,`/AA`), `/Launch` external-program, `/EmbeddedFile`, and `/RichMedia` — with PDF name hex-escape de-obfuscation (`/J#61vaScript` → `/JavaScript`)
  - ASCII/UTF-16 string extraction + IOC mining for URLs, IPs, domains, registry paths, file paths, mutex hints, base64 blobs, and suspicious APIs
  - **obfuscated-C2 recovery**: single-byte XOR, multi-byte (2–4 byte repeating-key) XOR, and base64-wrapped URLs/IPs/domains the plaintext miner can't see
  - import-table → behavioral-capability mapping (anti-debug, keylogging, screen capture, injection, …)
  - rule-based tracker tags
  - optional YARA/capa/DIE wrappers
  - optional MalwareBazaar/VirusTotal hash lookups
- JSON and self-contained HTML report generation
- **WebView2 live console** (`AntiMal.exe`): the Win32 app is now a thin shell hosting a hardened WebView2 UI (`webui/`, vanilla HTML/CSS/JS), 8 sections all wired to a real C++ bridge — scan, config, reports, dashboard, browser-impact, and the live VM view (**Boot VM (live)** streams frames + accepts mouse/keyboard).
- **Host↔guest telemetry pipeline (3b) — streams live (confirmed 2026-06-09):** in-guest collectors → COM2/AMCH channel → host live-journaling to `events.jsonl` → UI Live Process Telemetry panel (`run.watch`). A live boot streamed 122 KB of real events (process tree, registry, files). The `AntiMalGuestAgent` service is installed in the base image.
- **Deep dynamic-analysis pipeline (2026-06-09, built + reviewed across 3 review passes; live on Detonate via per-run agent redeploy):**
  - process telemetry with full path, command line, integrity level, user/SID, session, start time, and **exit codes** (surfaces crash codes like `0xC0000409`)
  - **persistence** detection across 8 families (Run/Winlogon/Services/IFEO/AppInit/ActiveSetup/Startup/COM-hijack) with **MITRE ATT&CK** tags
  - in-guest **WER crash decoder** (`ANTIMAL_PROBE_KEEP_WER=1`) — names the faulting module + exception behind a crash
  - **dropped-file** SHA-256 + magic-byte file type; **DLL-load / injection** detection (side-loaded/hijacked DLLs from writable paths → T1574)
  - a **scored, explainable behavioral verdict** (per-signal rationale; kills the `timeout==Malicious` FP; raises the bar for signed installers)
  - an **analyst-grade report**: process tree + grouped Persistence / Dropped-Files / Network / Crashes / Module-Loads / MITRE sections
  - machine-readable **IOC export** — STIX 2.1 / MISP / CSV (`AntiMal.HostCli.exe export <run> --format stix|misp|csv`)
- **Live interaction (3c):** the VM framebuffer mirrors into the UI over a **zero-copy shared-memory → WebView2 `SharedBuffer` → `<canvas>`** path (live-confirmed at `LIVE · 14 FPS`; an on-screen fps readout shows live-vs-stalled). Keyboard + mouse, **host→guest clipboard paste**, **Ctrl+Alt+Del**, and paced login/text are injected via a framed `_live-input.bin` protocol; the live display no longer **freezes** on low-variance frames (`LiveFramePublishGate`). The live VM runs in a separate process from the UI (escape-isolation). *(Known live issue: relative-mouse clicks don't reliably land — see In Progress.)*
- **Console quality-of-life:** editable **Settings** page (writes back to `antimal.toml`), in-app **report viewer**, a **confirmation gate** before arming live detonation, a **minidump crash handler**, **GitHub Actions CI** (build + test on every push), `detonate --json` for automation, anti-evasion scrubbing of the sandbox-identifying disk/ACPI/**TPM** strings, and a controllable guest clock (no longer leaks host wall-clock).
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

The dynamic console, telemetry, live input, and the full analysis pipeline are built and (where possible) live-confirmed. **Two concrete, well-understood steps remain to make the desktop drivable** (full detail + commands in [`historical session notes (not distributed)`](historical session notes (not distributed))):

1. **Re-snapshot a settled desktop.** The current seed `AntiMalDesktop.cow` was captured mid-first-logon, so every boot resumes a half-provisioned Windows that crash-loops the shell until it eventually settles (~15-30 min). Seed-boot *copies* the snapshot into a per-run differencing overlay, so a run that reaches a settled desktop leaves a promotable image: **boot → wait for a fully settled desktop → `Stop` → `tools\Promote-DesktopSnapshot.ps1`** (backup-first, base untouched, reversible). Future boots then resume straight into the settled desktop — fast and stable.
2. **Make mouse clicks land.** On the live desktop the relative-PS/2 mouse doesn't reliably hit targets (couldn't dismiss a dialog). BochsVbe has no hardware cursor, so the guest's real software cursor should be in the captured frame — next step is to confirm one-vs-two cursors and either drop the synthetic cursor or add an absolute pointing device for 1:1 tracking.

After those: bake the current telemetry agent into the new snapshot (`base deploy-agent`), then validate the full **Detonate → telemetry → verdict → report → IOC** loop end-to-end on the settled desktop.

**Deeper frontier (not blocking the above):** a 2-vCPU AP-bringup SMP race (`ntkrnlmp+0x2916EC`; 1-vCPU is the reliable default), a guest-bindable NIC + fake-internet capture (designed — see `historical design notes (not distributed)`; recommended NIC is e1000e `8086:10D3`), real-time ETW telemetry, and a true RAM snapshot.

## Safety Model

AntiMal is meant for malware analysis, so safety beats speed.

- Network mode defaults to `disabled`.
- Threat-intel HTTP lookups are off unless explicitly enabled.
- The in-house VM stages samples but does not execute them by default.
- GuestAgent heartbeats over COM2 when no executable job is authorized.
- In-guest execution is behind a **two-key gate** (`dynamic_execution_enabled` config **and** per-run `--allow-execution`); with either key absent, the host sends only a `kind=healthcheck` job and submitted samples are staged but not launched.
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

This creates a run directory under `C:\AntiMalRuns`, writes `job.json`, `events.jsonl`, `report.json`, `report.html`, `serial.log`, `vm-summary.json`, `vm-diagnostics.txt`, and per-second `screenshots/guest-*.png` frames, and keeps sample execution blocked by default. By default the run **seed-boots from `AntiMalDesktop.cow`** (a desktop snapshot next to the base) and runs the full chain through the kernel + GUI stack (via the in-house AHCI disk) to the Windows **desktop**; `--cold` boots from the clean base instead (cold OOBE is slower/fragile). For an interactive session use **Boot VM (live)** / **Detonate Sample (live)** in `AntiMal.exe`. (Until the seed snapshot is re-captured from a fully settled desktop — see In Progress — the desktop crash-loops the shell for ~15-30 min before settling.)

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
- **90%: complete. Live-confirmed desktop + live display + live telemetry.** A real boot reached the Windows desktop (Recycle Bin + Edge icons) at a live `LIVE · 14 FPS` readout with 122 KB of telemetry streamed; root cause of the "frozen-screenshot" desktop diagnosed cold (mid-first-logon snapshot); the display-freeze fixed (`LiveFramePublishGate`). Additional historical session notes are not distributed.
- **92%: complete. Deep analysis pipeline + reporting.** Rich process/persistence/dropped-file/DLL-injection/crash telemetry → scored explainable verdict → analyst-grade report → STIX/MISP/CSV IOC export, all built and reviewed (3 passes).
- **92% → 95%: in progress. Drivable desktop.** Two concrete steps: re-snapshot a settled desktop (`tools\Promote-DesktopSnapshot.ps1`) so boots resume stable; fix the relative-mouse so clicks land (or add an absolute pointer).
- 98%: bake the telemetry agent into the new snapshot; validate the full Detonate → telemetry → verdict → report → IOC loop end-to-end on the settled desktop; network modes + fake-internet (designed).
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
