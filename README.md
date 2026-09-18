# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [██████████████████] 94%

> **For the authoritative, dated "where we are" status, read private development documentation (private documentation) first.** This section is the narrative; that file is the source of truth. Open work is tracked in private development documentation (private documentation) and private development documentation (private documentation).

## Current Status

AntiMal has two major layers:

1. **Static enrichment — ships today.** Multi-hash + entropy, deep PE metadata, magic-byte file typing, **file-type-aware analyzers for scripts / `.lnk` / Office-OLE macros / archives / PDF / RTF / ISO / OneNote**, strings + IOC mining with **obfuscated-C2 recovery** (XOR / base64 / base64-wrapped RC4 / PowerShell `-EncodedCommand`), Cobalt Strike beacon-config extraction, **auto YARA-rule generation**, rule/tag tracker, optional YARA/capa/DIE, optional MalwareBazaar/VirusTotal lookups (off by default), JSON + HTML reports.
2. **Dynamic detonation — works end-to-end.** A sample is staged into a disposable COW overlay; a seed-boot of the in-house WHP VM brings up the in-guest agent; the sample is delivered (COM2 for ≤8 MB, a second read-only AHCI disk for anything larger, or an **ISO the guest mounts and auto-runs**); it executes and its behavior streams back as `events.jsonl` → scored verdict → Any.Run-style `report.json` / `report.html` + screenshot filmstrip. Live-confirmed repeatedly, including a 2.3 GB Adobe-style installer (mounted ISO, UAC answered live, installer driven to completion) on 2026-09-17.
   - **The interactive desktop is reachable and drivable, with one intrinsic caveat:** the Win11 modern shell (`explorer`/`ShellHost`) crash-loops `0xC0000409` on this image — not fixable from a disposable overlay; the supported paths are the cmd-shell sidestep or a base rebuild with full OOBE automation (private development documentation (private documentation)). Detonation telemetry does **not** depend on a settled desktop.
   - **Agent tools:** `AntiMal.McpServer.exe` exposes the live VM to agents over stdio MCP (boot, screenshot, closed-loop coordinate clicks, keyboard, journal tail, process list, report), with CLI parity in `HostCli` (`vmstatus` / `vmframe` / `vmmouse` / `vmview` / `vminput`). Reference: private development documentation (private documentation).
   - **Contained network capture:** `--nic` attaches an emulated Intel 82574L (Win11 inbox driver) and routes guest frames through an in-process fake-internet sink (DHCP/DNS/ARP/ICMP/NTP/NBNS/LLMNR/HTTP) — **zero real egress, structurally**. DNS queries, TLS SNI and full packets land in `network.pcap` + the report. Default remains `network disabled`.
   - **Remaining frontier is polish + performance** (private development documentation (private documentation)): operator-visible progress during the invisible phases (stage/copy/mount), input-encoding bugs found live, a true unlimited time budget, CD-ROM/ATAPI + dirty-rect frames + faster storage, and a re-serviced base image.

**The full boot chain works:** OVMF → `bootmgfw` → `winload.efi` → code-integrity → **ntoskrnl** → kernel Phase 0/1 → **AHCI storage mount** → win32k/dxgkrnl/display → OOBE → **VM warm-reset (guest reboot is serviced)** → account creation → **login → "Preparing Windows" → desktop**. Walls cleared to get here: the `0xc0000225` code-integrity abort (source-built TPM2 OVMF), the `0xc0430001` winload wall (our own ACPI checksum bug), the **`0x7B INACCESSIBLE_BOOT_DEVICE`** storage wall (a from-scratch PCI-native **AHCI** controller — `storahci.sys` binds it), VM warm-reset, **injected-input garbling** (fixed by pacing), and a **CET kernel hang** (fixed by masking CET in CPUID leaf 7).

**The desktop caveat, precisely (corrected 2026-06-17):** the shell crash-loop is **intrinsic to this image** — it reproduces on a clean cold-OOBE desktop (456× explorer restarts, two distinct `__fastfail` signatures) and is **not fixable from a disposable overlay** (every IFEO/AppX-quieting edit was tried and refuted; removing the base WDAC `.cip` anchor breaks boot entirely). Evidence: private development documentation (private documentation). Working sidesteps: swap the Winlogon shell to `cmd.exe` (`ANTIMAL_PROBE_SHELL_CMD=1`) — a rock-solid console from which interactive apps launch — or rebuild the base with a complete `Autounattend.xml` (private development documentation (private documentation)). The live display is no longer a freeze/slideshow (shared-memory framebuffer + `LiveFramePublishGate`), and the pointer is closed-loop (`VmPointer`) — current input bugs and perf items live in private development documentation (private documentation).

**Deep dynamic-analysis pipeline (built + reviewed this session, live on Detonate via per-run agent redeploy):** rich process telemetry (full path, command line, integrity, user/SID, session, start time, **exit codes**), persistence detection across 8 families with **ATT&CK tags**, an in-guest **WER crash decoder** (names the faulting module behind a crash), **dropped-file** SHA-256 + magic-byte type, **DLL-load / injection** detection (side-loaded/hijacked DLLs → T1574), a **scored, explainable behavioral verdict** (kills the `timeout==Malicious` false positive; signed-installer FP dampened), an **analyst-grade report** (process tree + persistence/drops/network/crashes/MITRE sections), and machine-readable **IOC export** (STIX 2.1 / MISP / CSV via `HostCli export`).

In-guest sample execution is **gated off by default** behind a **three-key gate**: `dynamic_execution_enabled = true` (config) **and** `--allow-execution` on `detonate` **and** the guest key `ANTIMAL_ARM_GUEST_EXEC=1` (the GUI and the MCP server's `vm_boot` arm all three for you). When armed, the host delivers the staged sample — paced COM2 (≤8 MB), or a second read-only AHCI disk for larger files, or an ISO the guest mounts and auto-runs — and the GuestAgent launches it and streams its behavior. Full recipe: private development documentation (private documentation).

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
    - **RTF**: embedded OLE objects (`\objdata`), `\objupdate` auto-run-on-open, the Equation Editor exploit carrier (CVE-2017-11882 / CVE-2018-0802), an embedded PE decoded from the `\objdata` hex, and remote-object loads (CVE-2017-0199 / OLE2Link — recovers the URL moniker)
    - **ISO / IMG** (ISO9660): the MOTW-bypass delivery lure — flags an embedded `.lnk` + hidden executable and the small-image-with-payload shape
    - **OneNote** (`.one`): the 2023-24 malspam carrier — flags an embedded FileDataStore attachment, an embedded PE, and embedded script payloads
  - ASCII/UTF-16 string extraction + IOC mining for URLs, IPs, domains, registry paths, file paths, mutex hints, base64 blobs, and suspicious APIs
  - **obfuscated-C2 recovery**: single-byte XOR, multi-byte (2–4 byte repeating-key) XOR, base64-wrapped URLs/IPs/domains, and **base64-wrapped RC4 config** (the .NET-RAT scheme — tries each embedded ASCII string as the RC4 key, keeps only decryptions that yield a valid URL → near-zero false positives) the plaintext miner can't see
  - import-table → behavioral-capability mapping (anti-debug, keylogging, screen capture, injection, …)
  - rule-based tracker tags
  - optional YARA/capa/DIE wrappers
  - optional MalwareBazaar/VirusTotal hash lookups
- JSON and self-contained HTML report generation
- **WebView2 live console** (`AntiMal.exe`): the Win32 app is now a thin shell hosting a hardened WebView2 UI (`webui/`, vanilla HTML/CSS/JS), 8 sections all wired to a real C++ bridge — scan, config, reports, dashboard, browser-impact, and the live VM view (**Boot VM (live)** streams frames + accepts mouse/keyboard). The **same live session is drivable by agents/scripts**: `AntiMal.McpServer.exe` (stdio MCP) and `HostCli vmstatus|vmframe|vmmouse|vmview|vminput` — see private development documentation (private documentation).
- **Host↔guest telemetry pipeline (3b) — streams live (confirmed 2026-06-09):** in-guest collectors → COM2/AMCH channel → host live-journaling to `events.jsonl` → UI Live Process Telemetry panel (`run.watch`). A live boot streamed 122 KB of real events (process tree, registry, files). The `AntiMalGuestAgent` service is installed in the base image.
- **Deep dynamic-analysis pipeline (2026-06-09, built + reviewed across 3 review passes; live on Detonate via per-run agent redeploy):**
  - process telemetry with full path, command line, integrity level, user/SID, session, start time, and **exit codes** (surfaces crash codes like `0xC0000409`)
  - **persistence** detection across 8 families (Run/Winlogon/Services/IFEO/AppInit/ActiveSetup/Startup/COM-hijack) with **MITRE ATT&CK** tags
  - in-guest **WER crash decoder** (`ANTIMAL_PROBE_KEEP_WER=1`) — names the faulting module + exception behind a crash
  - **dropped-file** SHA-256 + magic-byte file type; **DLL-load / injection** detection (side-loaded/hijacked DLLs from writable paths → T1574)
  - a **scored, explainable behavioral verdict** (per-signal rationale; kills the `timeout==Malicious` FP; raises the bar for signed installers)
  - an **analyst-grade report**: process tree + grouped Persistence / Dropped-Files / Network / Crashes / Module-Loads / MITRE sections
  - machine-readable **IOC export** — STIX 2.1 / MISP / CSV / YARA (`AntiMal.HostCli.exe export <run> --format stix|misp|csv|yara`); `yara` emits an auto-generated hunt rule for the run's sample
- **Live interaction (3c):** the VM framebuffer mirrors into the UI over a **zero-copy shared-memory → WebView2 `SharedBuffer` → `<canvas>`** path (live-confirmed at `LIVE · 14 FPS`; an on-screen fps readout shows live-vs-stalled). Keyboard + mouse, **host→guest clipboard paste**, **Ctrl+Alt+Del**, and paced login/text are injected via a framed `_live-input.bin` protocol; the live display no longer **freezes** on low-variance frames (`LiveFramePublishGate`). The live VM runs in a separate process from the UI (escape-isolation). *(Known input issues, all listed in private development documentation (private documentation): `vminput --mouse` truncates deltas to int8 and uses PS/2 Y-sign; `vmmouse`'s cursor learn is defeated by Windows pointer acceleration; UAC's secure desktop needs the keyboard fallback.)*
- **Sample delivery beyond COM2:** the staged sample is exposed as a **second read-only AHCI disk** (`PaddedFileBlockDevice`, port 1) for anything >2 MB — no size cap, disk-speed transfer — and a delivered **`.iso` is mounted in-guest** (`Mount-DiskImage`) with a setup/installer auto-pick (`Set-up.exe`/`setup.exe`/…) and launched into the interactive desktop. This is what lets multi-gigabyte installers detonate at all.
- **Contained network capture:** emulated **Intel 82574L / e1000e** (`8086:10D3`, inbox driver) behind `ANTIMAL_ENABLE_NIC`/`--nic`; guest TX routes through the in-process **`FakeInternet`** sink (DHCP/DNS/ARP/ICMP/NTP/NBNS/LLMNR/HTTP 200) and replies are injected back — **the host never opens a socket**. Both directions are written to `network.pcap`; DNS + TLS **SNI** are surfaced as `network.*` events and `report.networkDomains`.
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

The dynamic pipeline (delivery → execution → telemetry → verdict → report → IOC) is built and live-confirmed. What remains is operator polish, input reliability, and performance — tracked with checkboxes in private development documentation (private documentation):

1. **Operator-visible progress.** During a run's invisible phases (host staging copy, in-guest ISO copy at ~10 MB/s, mount) the screen can sit on a static desktop for minutes. Add a phase/progress surface (delivery %, phase name, run id/fps, counters) to the live console, `vmview`, and the report.
2. **Input reliability.** Fix `vminput --mouse` int8 truncation + PS/2 Y-sign, make `vmmouse`'s cursor learn acceleration-aware, and add a UAC auto-answer path for unattended elevating samples.
3. **A re-serviced base image** (user-gated): rebuild from the Win11 ISO with a complete `Autounattend.xml` + clean `SetupComplete.cmd` to get a settled snapshot and capture the `__fastfail` subcode (the exact invariant the modern shell trips on). Procedure: private development documentation (private documentation).
4. **Performance:** CD-ROM/ATAPI so ISOs attach directly (kills the in-guest copy), dirty-rect frame publishing, screenshot dedupe/interval, faster storage, hardlink staging, and a true `--timeout-sec unlimited`.

**Deeper frontier (not blocking the above):** a 2-vCPU AP-bringup SMP race (`ntkrnlmp+0x2916EC`; 1-vCPU is the reliable default), real-time ETW telemetry, a true RAM snapshot, and a guest-trusted CA for TLS-body capture.

## Safety Model

AntiMal is meant for malware analysis, so safety beats speed.

- Network mode defaults to `disabled`.
- Threat-intel HTTP lookups are off unless explicitly enabled.
- The in-house VM stages samples but does not execute them by default.
- GuestAgent heartbeats over COM2 when no executable job is authorized.
- In-guest execution is behind a **three-key gate** (`dynamic_execution_enabled` config **and** per-run `--allow-execution` **and** the guest-side `ANTIMAL_ARM_GUEST_EXEC` arm); with any key absent, the host sends only a `kind=healthcheck` job and submitted samples are staged but not launched.
- Network is structurally contained: default mode is `disabled` (no NIC at all); `--nic` routes guest frames to an in-process fake-internet sink that **never opens a host socket**.
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

For an end-to-end, task-oriented walkthrough of the CLI (triage → config → yara-gen
→ detonate → report views → export → offline browsing), see
private development documentation (private documentation). For the `report.json` field
reference (for integrating with the output), see private development documentation (private documentation).

Scan a file:

```powershell
bin\x64\Release\AntiMal.HostCli.exe scan C:\Path\To\File.exe --threshold 70
```

Check whether this host can boot a guest and run the full workflow (WHP, OVMF,
base image, GuestAgent, workspace, enrichment tools) — actionable, with a
machine-readable mode for CI (exit 0 when ready, 1 on a hard blocker):

```powershell
bin\x64\Release\AntiMal.HostCli.exe doctor
bin\x64\Release\AntiMal.HostCli.exe doctor --json
```

Ask "is this a repacked variant of something I've already triaged?" with the
fuzzy (CTPH) hash — compare two files, or a file against a known digest:

```powershell
bin\x64\Release\AntiMal.HostCli.exe similarity A.exe B.exe
bin\x64\Release\AntiMal.HostCli.exe similarity A.exe --to 24576:abc...:def...
```

Turn a triaged sample into a hunting rule — `yara-gen` scans the file and emits
a ready-to-tune YARA rule from its most distinctive strings + imphash/sha256/PE
magic (IOC strings ranked first; common PE boilerplate filtered out):

```powershell
bin\x64\Release\AntiMal.HostCli.exe yara-gen suspicious.exe
bin\x64\Release\AntiMal.HostCli.exe yara-gen suspicious.exe --out hunt.yar --name MyFamily
```

See the recovered **malware configuration / C2** (Cobalt Strike beacon + XOR /
base64 / base64-wrapped-RC4 obfuscated C2) in one focused view — the analyst's
"what will this talk to?" question, answered statically:

```powershell
bin\x64\Release\AntiMal.HostCli.exe config suspicious.exe          # text
bin\x64\Release\AntiMal.HostCli.exe config suspicious.exe --json   # for automation
```

Generate a complete Any.Run-style report from a SYNTHETIC detonation — no VM,
firmware, or hardware required. This exercises the events → report.json →
report.html (+ filmstrip) pipeline end-to-end and is the documented local
simulation for environments where a live boot isn't available (the output is
clearly labeled as synthetic):

```powershell
bin\x64\Release\AntiMal.HostCli.exe simulate
# writes C:\AntiMalRuns\sim-detonation\{report.html,report.json,events.jsonl,screenshots\}
```

Compare two analysis reports — verdict/score changes plus added/removed
IOCs/findings/MITRE/tags (a determinism check, or variant comparison alongside
`similarity`). Exit 1 when material differences exist:

```powershell
bin\x64\Release\AntiMal.HostCli.exe report-diff <run-or-report-A> <run-or-report-B>
```

Browse, search, extract, and triage the guest's files **offline** from the disk
image (base VHDX + optional run overlay) — File-Explorer-style access with **no
boot**, which sidesteps the crash-looping in-guest modern shell. Reads the
post-detonation overlay too, so you can see exactly what a run left on disk:

```powershell
bin\x64\Release\AntiMal.HostCli.exe fs-ls   "\Users\analyst\Downloads"
bin\x64\Release\AntiMal.HostCli.exe fs-find "invoice" --max-results 50
bin\x64\Release\AntiMal.HostCli.exe fs-cat  "\Windows\System32\drivers\etc\hosts" --out hosts.txt
bin\x64\Release\AntiMal.HostCli.exe fs-scan "\Users\analyst\AppData\Local\Temp\dropped.exe"
#   add --overlay C:\AntiMalRuns\<run>\disk\overlay.cow to inspect a run's changes
bin\x64\Release\AntiMal.HostCli.exe reg-ls --hive software "Microsoft\Windows\CurrentVersion\Run" --values
```

For **live** in-guest browsing when the Win11 modern shell crash-loops, the
GuestAgent ships its own dependency-light file browser — launch it from the
cmd-shell sidestep: `AntiMal.GuestAgent.exe --file-browser [start-dir]` (a plain
Win32 ListView, no `explorer.exe`/AppX dependency).

Read a run's behavior summary, ranked detections, or measured desktop-usability
without opening the HTML (all support `--json` for automation), and aggregate
boot reliability across every run:

```powershell
bin\x64\Release\AntiMal.HostCli.exe report <run> --summary    # at-a-glance triage (+ --json for CI)
bin\x64\Release\AntiMal.HostCli.exe report <run> --why        # explainable verdict (per-signal rationale)
bin\x64\Release\AntiMal.HostCli.exe report <run> --detections
bin\x64\Release\AntiMal.HostCli.exe report <run> --crashes      # distinct process-crash fault signatures
bin\x64\Release\AntiMal.HostCli.exe report <run> --network      # contacted endpoints (service/bogon/C2 flags) + domains
bin\x64\Release\AntiMal.HostCli.exe report <run> --mitre        # ATT&CK techniques grouped by tactic
bin\x64\Release\AntiMal.HostCli.exe report <run> --usability
bin\x64\Release\AntiMal.HostCli.exe report <run> --timeline [--category process|registry|file|network|image] [--mitre] [--limit N]
bin\x64\Release\AntiMal.HostCli.exe boot-report
```

`boot-report` counts every attempted run — including ones that crashed/were
killed before a `report.json` was written — and, for those, falls back to the
live `events.jsonl` to recover how far the boot actually got (GuestAgent
telemetry proves OS-up). If such an orphaned run has useful telemetry, rebuild a
navigable report from its journal:

```powershell
bin\x64\Release\AntiMal.HostCli.exe rebuild-report <run-id-or-dir> --html
```

This reconstructs `report.json` (+ `report.html` with `--html`) from
`events.jsonl` using the same process-tree / MITRE / network / behavior-score
builders the live run uses, so a run whose report was never finalized still
yields an Any.Run-style report. It refuses to overwrite an existing
`report.json` unless `--force`.

Stage and boot-probe a sample through the in-house VM path:

```powershell
$env:ANTIMAL_FIRMWARE_NAME = "OVMF-debug.fd"
bin\x64\Release\AntiMal.HostCli.exe detonate C:\Path\To\File.exe --network disabled --timeout-sec 180
```

This creates a run directory under `C:\AntiMalRuns`, writes `job.json`, `events.jsonl`, `report.json`, `report.html`, `serial.log`, `vm-summary.json`, `vm-diagnostics.txt`, and per-second `screenshots/guest-*.png` frames, and keeps sample execution blocked by default. By default the run **seed-boots from `AntiMalDesktop.cow`** (a desktop snapshot next to the base) and runs the full chain through the kernel + GUI stack (via the in-house AHCI disk) to the Windows **desktop**; `--cold` boots from the clean base instead (cold OOBE is slower/fragile). For an interactive session use **Boot VM (live)** / **Detonate Sample (live)** in `AntiMal.exe`, or the agent tools in private development documentation (private documentation). Samples >2 MB ride a second read-only disk; a `.iso` sample is mounted in-guest and its installer auto-launched — this is how multi-gigabyte installers detonate. The desktop itself may sit in the documented modern-shell crash-loop; detonation telemetry does not depend on it (private development documentation (private documentation)).

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

For a **pass/fail readiness verdict** (e.g. before spending a 15-minute cold boot on a freshly rebuilt base), use `base validate` — it runs the same offline reads but returns a structured result: *critical* checks (ESP/FAT32, UEFI boot files, BCD→winload/\Windows, NTFS, `winload.efi`/`ntoskrnl.exe`/`hal.dll`/`ci.dll`, SYSTEM hive) gate the exit code, while *advisory* checks (the `{60FD87F8-…}.cip` CI anchor, deployed GuestAgent + service `ImagePath`, `AutoAdminLogon`, `SetupComplete.cmd`, unattend) are reported as warnings:

```powershell
bin\x64\Release\AntiMal.HostCli.exe base validate `
  --vhdx C:\AntiMalRuns\_base\AntiMalBase.vhdx --json
#   -> exit 0 = bootable; nonzero = a critical prerequisite is missing (named in the output).
```

See private development documentation (private documentation) for the full unblock plan this gates.

## Repository Layout

```text
src/Common/        shared types, scanner, reports, config, enrichment, journal, LiveVm/VmPointer
src/Hypervisor/    WHP VMM, firmware, devices, disks (AHCI boot + sample disk), ACPI, host channel
src/App/           Win32 GUI (WebView2 live console)
src/HostCli/       command-line scan/detonate/report/vm tool
src/GuestAgent/    in-guest agent (telemetry, execution, ISO mount, file browser, MiniShell)
src/McpServer/     stdio MCP server exposing the live VM to agents
src/DriverBridge/  dev-only IPC adapter to a separately-loaded lab helper (unreferenced by exes)
src/Tests/         self-contained Expect() test binary
tools/             base-image, firmware, and validation scripts
firmware/          current private-checkpoint OVMF blobs
docs/              design docs and roadmaps (CURRENT_STATE, INHOUSE_VM, ENRICHMENT, AGENT_TOOLS, …)
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
- **94%: complete. Full dynamic loop, end-to-end.** Disk-backed + ISO sample delivery (multi-GB installers detonate), contained fake-internet capture (`network.pcap`, DNS/SNI), agent tools (MCP server + `vmmouse`/`vmview`/`vminput`), and a live-driven installer run (2026-09-17).
- **94% → 97%: in progress. Operator polish + input + perf.** Progress UI for the invisible phases, input-encoding fixes, unlimited timeout, CD-ROM/dirty-rect/storage performance (private development documentation (private documentation)).
- 97% → 100%: a re-serviced base snapshot (settled desktop) and a fully interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
