# AntiMal

[![CI](https://github.com/tbhtho/Anti-Mal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tbhtho/Anti-Mal/actions/workflows/ci.yml)
[![License: not declared](https://img.shields.io/badge/License-not_declared-lightgrey.svg)](#license)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue.svg)

A Windows malware-analysis environment with an in-house VM, live observation, telemetry, reports, and optional static enrichment.

## Get started

No packaged release is published in this repository. Source setup requires Windows x64, the Visual Studio 2022 C++ toolchain, Windows SDK **10.0.26100.0**, and MSBuild. WHP-based VM work also requires Windows Hypervisor Platform, OVMF, and a separately prepared Windows base image. The project does not provide Windows installation media.

```powershell
msbuild AntiMal.sln /p:Configuration=Release /p:Platform=x64
bin\x64\Release\AntiMal.HostCli.exe init
```

Static enrichment is locked by default and can only be unlocked for an explicit invocation. Dynamic conclusions require observed evidence and stated coverage; a quiet run is not a safety certificate.

## Features

- In-house WHP-based VM with live display and input tools.
- Process and event telemetry, screenshots, network capture, and explainable reports.
- CLI, desktop interface, and scoped agent tooling.
- Optional YARA, capa, Detect It Easy, and threat-intelligence enrichment.


<details>
<summary>Full capability catalog</summary>


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

</details>

## Lab boundaries

For defensive research and local lab use. **Do not execute live malware on the host.** Network access defaults to disabled; the emulated fake-internet sink has no real egress. Guest execution requires all three gates: enabled configuration, per-run authorization, and guest-side arming. Keep threat-intelligence HTTP lookups opt-in, preserve base images and previous runs, and use only synthetic credentials in the isolated guest.

Boot reliability, input handling, operator progress, and performance remain active work. A quiet run or heuristic clean label is not a safety certificate. See current work (private documentation).

## License

No repository-wide license is declared in this checkout. Do not infer redistribution permission from source access; third-party materials retain their own terms.
