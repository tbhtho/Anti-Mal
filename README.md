# AntiMal

AntiMal is a defensive malware-analysis scaffold for Windows. The long-term goal is a local, open-source interactive sandbox for safely detonating suspicious Windows binaries without relying on Windows Sandbox, VirtualBox, VMware, or commercial services.

Overall progress: [█████████░░░░░░░░░] 45%

## Current Status

AntiMal has two major layers:

1. Static enrichment, which works today.
2. Dynamic detonation inside an AntiMal-owned Windows VM, which is actively being built on Windows Hypervisor Platform (WHP).

The scanner can already hash files, calculate entropy, parse PE metadata, mine strings and IOCs, apply rules/tags, and optionally call external tools such as YARA, capa, and Detect It Easy when those binaries are present. Threat-intel lookup support exists for MalwareBazaar and VirusTotal, but outbound intel is off by default.

The in-house VM path is past the toy stage but not finished. The WHP frontend can create a partition, run vCPUs, map RAM and OVMF firmware, emulate enough PC hardware for OVMF to boot, expose an IDE disk, stream OVMF debug output, create per-run copy-on-write overlays, and render host-side live progress frames. The current Windows boot probe reaches `bootmgfw.efi`, opens BCD and code-integrity policy files, applies overlay-only BCD/bootstat and SYSTEM boot-storage repairs, reads `winload.efi` and the SYSTEM hive from the Windows partition, identifies transient `winload_prod.pdb` loader code in guest RAM during the handoff, brings up OVMF QemuVideo/GOP, and captures real guest framebuffer PNGs. That proves the 45% gate. The latest visible guest state is still Windows Recovery error `0xc0000225`, so the next work is pushing from loader execution into kernel/driver reads and GuestAgent user mode.

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

The current milestone is "agent boot": get a benign Windows base image past the now-proven `winload` handoff far enough into user mode that `AntiMal.GuestAgent.exe` auto-starts and sends a COM2 heartbeat to the host. That heartbeat proves the VM can boot Windows code without executing the submitted sample.

The active blockers are:

- Push from proven loader execution to GuestAgent heartbeat. The disposable overlay BCD patch now writes `bootdebug=true`, `debugtype=0` (serial), `debugport=1` (COM1), and `baudrate=115200` onto both the `{default}` loader and the `{dbgsettings}` settings object, but winload still emits zero bytes to COM1. OVMF reports the COM1 UART device path correctly at `PciRoot(0x0)/Pci(0x1,0x0)/Serial(0x0)/Uart(115200,8,N,1)`, so the UART itself is wired - the next investigation step is verifying that the new BCD elements are byte-correctly readable by winload (overlay-aware base inspect, or extracting the patched BCD from the run COW for offline decode).
- Keep the Windows boot manager contract visible in diagnostics after BCD and code-integrity policy loads. ACPI PM1/S5 metadata is no longer treated as the immediate blocker: the FADT advertises legacy and extended PM1 blocks, the PM1 control trap preserves byte writes, and only S4/S5 requests stop the VM.
- Continue interrupt diagnostics while boot repair is pending. Run diagnostics record pending IDE/PIT/RTC latches, IOAPIC redirection entries, PIC vector bases, PIC masks, and whether each interrupt was delivered by IOAPIC, PIC fallback, or failed routing.
- Apply BCD recovery-policy and `bootstat.dat` cleanup to the disposable run overlay before boot. This is deliberately overlay-only: it can prove whether recovery-loop state is the blocker without mutating `C:\AntiMalRuns\_base\AntiMalBase.vhdx`.
- Repair the offline SYSTEM hive's boot device binding for the emulated PIIX IDE controller. The non-admin base inspector shows `pciide`, `intelide`, `atapi`, `disk`, `partmgr`, and `mountmgr` are already boot-start, but `CriticalDeviceDatabase` has no mapping for `pci#ven_8086&dev_7111` or the generic `pci#cc_0101` / `pci#cc_01018a` IDE class IDs. The elevated repair path and the disposable overlay probe both add those mappings to `pciide`; the latest overlay-only experiment did not move the Windows boot handoff past the current loader/SYSTEM read point, so this is now evidence rather than the only active suspect.
- Install GuestAgent into the base image and auto-start it from the offline SYSTEM hive service entry. The older HKLM Run autostart remains as a fallback.
- Decode COM2 GuestAgent frames in the host report path, send a benign `healthcheck` job, and return `agent-health.json` once the guest service reaches user mode.

Recent in-house tooling additions (one session, three pushed commits):

- The overlay BCD patcher can now allocate new registry cells, not just rename existing donor elements. `MutableHiveView::SetBinaryValue` plus `AddBcdElementRaw` are the new primitives; `PatchBcdDebugTransport` writes the four winload debug elements on `{default}`, and `PatchBcdDbgSettings` writes the three transport elements on `{dbgsettings}` when that object is present in the base BCD. Set `ANTIMAL_DISABLE_WINLOAD_DEBUG=1` to disable both for A/B comparison runs.
- Serial capture is split into three per-run files: `serial.log` carries COM1 only (winload + future ntoskrnl/kdcom debug), `serial-firmware.log` carries the OVMF debugcon stream (port 0x402), and `serial-merged.log` keeps the original combined view for back-compat.
- `AnalyzeBootSignals` now searches both streams for the existing firmware milestones and adds COM1-only winload markers (`OslMain`, `OslPrepareTarget`, `OslArchTransferToKernel`, `OslpLoadAllModules`, `BlImgLoadPEImage`, `BlImgVerifyHash`, `BlBdInitialize`, `Status: 0x`, `NTSTATUS 0x`, `FATAL`).
- `AntiMal.HostCli.exe base inspect` now lists every object under `\Objects`, not just `{bootmgr}` and `{default}`, with a full element inventory per object. `BcdObjectAlias` resolves `{dbgsettings}`, `{globalsettings}`, `{bootloadersettings}`, `{emssettings}`, `{resumeloadersettings}`, and `{defaultbootentry}` for readability.

Latest local probe:

- `ANTIMAL_FIRMWARE_NAME=OVMF-debug.fd`
- `AntiMal.HostCli.exe detonate bin\x64\Release\AntiMal.Tests.exe --network disabled --timeout-sec 90`
- Run `6ec31956-5a7b-4610-926f-0a34fdf29cdf` (with bootdebug + dbgsettings transport patches active).
- Result: timed out after the loader/SYSTEM-hive phase; `winloadReached=true`; `sampleExecuted=false`; `guestAgentConnected=false`; GuestAgent heartbeat has not started yet.
- The run emitted `vm.boot-overlay.patched` with all eleven patch flags `true`: default-loader `recoveryenabled=false`, `bootstatuspolicy=IgnoreAllFailures`, `bootstat.dat` zeroed, SYSTEM `CriticalDeviceDatabase` PIIX IDE mappings added, default-loader `bootdebug=true` + `debugtype=0` + `debugport=1` + `baudrate=115200`, and `{dbgsettings}` `debugtype` + `debugport` + `baudrate` added. The patched element IDs (`16000010`, `25000022`, `25000023`, `25000024`) are byte-resident in the overlay COW.
- `serial.log` is 0 bytes for that run (no winload COM1 output yet), `serial-firmware.log` carries the full 100 KB OVMF debugcon trace, and `serial-merged.log` mirrors the combined stream. OVMF reports the COM1 device path correctly at `Uart(115200,8,N,1)`, so the UART itself is wired; the next investigation step is verifying that the new BCD elements decode correctly when winload reads them.
- Disk I/O is now target-aware: `Windows\System32\winload.efi` is at LBA `12643640-12650175` and was read by 26 IDE commands; `Windows\System32\config\SYSTEM` is at LBA `29561144-29581623` and was read by 80 IDE commands.
- The same probe tracks later handoff files too. `ntoskrnl.exe`, `hal.dll`, `kdcom.dll`, `ci.dll`, SOFTWARE, `acpi.sys`, `pci.sys`, `pciide.sys`, `intelide.sys`, `atapi.sys`, `disk.sys`, `partmgr.sys`, `mountmgr.sys`, `classpnp.sys`, `volmgr*.sys`, `fvevol.sys`, and `Wdf01000.sys` all have known LBA targets but zero read commands in the latest run.
- Boot milestones include fallback bootloader open, `bootmgfw` load, BCD open, code-integrity policy open, `winload image identified`, `winload.efi data read`, and `SYSTEM hive data read`. Disk reads of `winload.efi` remain milestones, but only serial `winload` opens or an identified `winload` guest image may turn the VM boot event into `vm.boot.completed`. OVMF QemuVideo/GOP initializes at `1280x800x32`; the old 2 GiB VGA BAR resource conflict is fixed.
- The host now writes boot-file read targets and transient low-RAM image identities to `vm-diagnostics.txt`, `vm-summary.json`, `events.jsonl`, `report.json`, and the HTML report's dynamic summary. The latest run emits `vm.boot.completed` with `winloadReached=true` because `observedImage114ImagePdb` resolves to `winload_prod.pdb` during boot traffic; the final RIP and hottest stalled RIP buckets still resolve to `PcRtc.efi`, and the end-of-run resident sweep still finds only the live Boot Manager image at `0x10000000` with `bootmgfw.pdb`. PM1 S0 writes are diagnostics-only, while real S4/S5 requests still stop the host.
- Comparison run `b8f5e2fa-3f40-4e66-9b47-4f0cbcf3aad9` disabled the disposable overlay repair with `ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH=1` and still landed on the same Boot Manager `0xc0000225` class of failure. The overlay repair remains useful evidence and a base-health aid, but it is not the whole blocker.
- Input probe run `1fd10b41-1a65-4d1c-b29a-6f244f4502bb` queued Enter with `ANTIMAL_PROBE_PRESS_ENTER_SEC=92`. Diagnostics show two PS/2 scancodes injected, but the Boot Manager screen did not move and legacy IOAPIC/PIC IRQ delivery remained fully masked, so interactive boot-UI input is not proven yet.
- This shell was not elevated, so the base validator/repair and offline GuestAgent service install could not be run here.

Latest base image inspection:

- `AntiMal.HostCli.exe base inspect --vhdx C:\AntiMalRuns\_base\AntiMalBase.vhdx`
- Result: passed without elevation.
- GPT layout is readable through the in-house VHDX block device: MSR, EFI System Partition, and Windows/basic-data partition.
- ESP boot files are present: `EFI\BOOT\BOOTX64.EFI`, `EFI\Microsoft\Boot\bootmgfw.efi`, `EFI\Microsoft\Boot\BCD`, and `EFI\Microsoft\Boot\Fonts\wgl4_boot.ttf`.
- The internal BCD hive decoder verifies `{bootmgr}` on the ESP and the default Windows loader on the Windows/basic-data partition. `winload.efi`, `\Windows`, `device`, and `osdevice` all decode coherently. The base loader does not currently carry explicit `recoveryenabled` or `bootstatuspolicy` elements; the current run path patches those policy elements in the disposable overlay while leaving the base VHDX unchanged. Non-admin `bcdedit /store` still returns access denied against the dumped hive, but AntiMal can now inspect and patch the needed boot contract itself.
- The internal NTFS reader verifies `Windows\System32\winload.efi` (`3344880` bytes) and `Windows\System32\config\SYSTEM` (`10485760` bytes) directly from the Windows partition without mounting the VHDX.
- The internal SYSTEM hive decoder now inspects the offline boot storage contract. Current evidence: `pciide`, `intelide`, `atapi`, `disk`, `partmgr`, and `mountmgr` are all boot-start-ready, but the hive is missing CriticalDeviceDatabase bindings for the emulated Intel PIIX IDE controller (`pci#ven_8086&dev_7111`) and generic PCI IDE class IDs. This is the sharpest current suspect for the visible Windows Recovery `0xc0000225` after `winload.efi`/SYSTEM reads.
- VM preflight now carries that same base-health verdict into `events.jsonl`: `baseBootStorageInspected=true`, `baseBootStorageReady=false`, and `baseBootStorageDetails=controlSet=ControlSet001;storageCore=ready;ideService=ready;criticalDevice=needs-repair`. This warning does not block diagnostic probes, but it makes the repair target visible in every run.

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

Before each in-house VM boot, AntiMal may apply a disposable overlay-only boot repair to the run disk: default-loader recovery is disabled, boot status policy is set to ignore failed boots, and `bootstat.dat` is cleared if it exists. The base VHDX is not mutated by this path. Set `ANTIMAL_DISABLE_BOOT_OVERLAY_PATCH=1` to turn that diagnostic patch off for comparison probes.

Optional boot UI probe:

```powershell
$env:ANTIMAL_PROBE_PRESS_ENTER_SEC = "20"
bin\x64\Release\AntiMal.HostCli.exe detonate C:\Path\To\File.exe --network disabled --timeout-sec 180
Remove-Item Env:\ANTIMAL_PROBE_PRESS_ENTER_SEC
```

That injects a PS/2 Enter make/break into the guest after the requested delay. It is for Recovery/firmware UI diagnostics only and does not enable sample execution.

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

To repair only the offline SYSTEM boot-storage binding without rerunning `bcdboot`:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  -RepairBootStorage
```

To install the current GuestAgent into the base image for heartbeat testing:

```powershell
powershell -ExecutionPolicy Bypass -File tools\Test-AntiMalBaseBoot.ps1 `
  -BaseVhdxPath C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  -GuestAgentPath bin\x64\Release\AntiMal.GuestAgent.exe
```

This copies the agent to `C:\AntiMal\AntiMal.GuestAgent.exe`, adds an automatic `AntiMalGuestAgent` service in the offline SYSTEM hive, and leaves a Run-key fallback for interactive logon scenarios.

You can also inspect the base VHDX without administrator privileges. This path does not repair anything; it reads the VHDX through AntiMal's block device layer, parses GPT, parses the FAT32 ESP, checks the UEFI boot files, decodes the BCD registry hive, verifies the boot manager/default loader contract, parses the NTFS Windows partition, prints NTFS data-run/LBA ranges for boot files, verifies `winload.efi`, decodes SYSTEM hive boot-storage service state, and can dump the BCD hive for offline inspection:

```powershell
bin\x64\Release\AntiMal.HostCli.exe base inspect `
  --vhdx C:\AntiMalRuns\_base\AntiMalBase.vhdx `
  --dump-bcd C:\AntiMalRuns\_base\AntiMalBase-esp.bcd
```

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
- 45%: complete. Windows reaches `winload.efi` as identified loader code in guest RAM, not just a disk read.
- 55%: GuestAgent auto-starts in user mode and sends COM2 heartbeat.
- 65%: Host sends a benign job to GuestAgent and receives journal/report artifacts.
- 75%: Real screenshots/framebuffer and interactive input are usable.
- 85%: Disposable overlays, timeout handling, and artifact return are hardened.
- 95%: Network modes, richer collectors, and live UI are added.
- 100%: interactive malware sandbox MVP.

## Important Notes

This project is for defensive research and local lab use. Do not execute live malware on the host. Keep network disabled unless you are deliberately testing network capture in an isolated lab. The current GitHub checkpoint includes firmware blobs because the repository is private and this commit is meant to preserve the exact WHP/OVMF debug state.
