# Changelog

All notable changes to AntiMal are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Dates are ISO-8601.

This project has not cut a versioned release yet; entries are grouped by the work
that landed on `main`.

## [Unreleased]

### 2026-06-17 — interactive app reached in the VM: a web browser (Edge) runs in-guest
For the first time an interactive GUI application was launched and rendered inside the live VM,
on a guest where the Windows modern shell still crash-loops. The crashing component
(`explorer.exe`/ShellHost, `0xC0000409`) is not fixed but **sidestepped**: a new overlay-only,
opt-in patch swaps the Winlogon `Shell` for `cmd.exe` (a stable console shell with no AppX/modern-
shell dependency), and the app is launched from there.
- **`PatchOverlaySetShellCmd` / `ANTIMAL_PROBE_SHELL_CMD`** — same-size REG_SZ edit of
  `HKLM\SOFTWARE\…\Winlogon\Shell` (`explorer.exe` → `cmd.exe`) in the disposable overlay
  (base untouched). Live-verified: the guest shows a working `cmd` console instead of a black
  screen + ShellHost crash dialog.
- **`ANTIMAL_PROBE_RUN_CMD`** — deterministically launches an app by creating
  `HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun` (e.g. `start msedge`), so the cmd shell runs
  it the instant it starts (no keystroke timing/focus).
- **`ANTIMAL_PROBE_TYPE_CMD`** — fallback keystroke injector (types a command + Enter into the
  focused window); how Edge was first launched live.
- Proof: `private development documentation` (Microsoft Edge first-run page,
  full-screen in the guest). The static malware-analysis product was already complete; this
  additionally demonstrates reaching a real interactive in-guest GUI app.

### 2026-06-16 — static-engine breadth: file-type-aware analyzers (M3)
The static layer previously only deeply analyzed PE files and silently skipped the
non-PE formats malware ships in. This session adds dedicated, bounds-safe analyzers
and routes `ScanFile` to them by magic bytes. All TDD, no boots, build + tests green.
- **`.lnk` shortcut parsing (T67):** `ShellLinkParser` walks MS-SHLLINK and recovers
  the embedded command line + target; flags a shortcut that silently launches a LOLBin
  (powershell/cmd/mshta/rundll32/…).
- **Script analyzer (T70):** `ScriptAnalyzer` classifies PowerShell/JScript/VBScript/
  batch/HTA/WSF and flags encoded commands, download cradles, LOLBin fetches, AMSI
  bypass, IEX/shell exec, hidden/bypass flags, and char-code obfuscation. It
  **deobfuscates one layer** — `DecodePowerShellEncodedCommand` decodes a base64
  `-EncodedCommand` (UTF-16LE, ASCII fallback) and recovers the hidden C2 into the IOC set.
- **Container analyzer (T68):** `ContainerAnalyzer` detects VBA-macro presence (OLE
  storage names + OOXML `vbaProject.bin`), best-effort auto-exec entry points, OLE
  exploit objects (Equation Editor CVE-2017-11882), and walks a zip central directory to
  flag executable payloads, double-extension lures, and password-protected entries.
- **PDF maldoc analyzer (T69):** `PdfAnalyzer` flags `/JavaScript`, auto-actions
  (`/OpenAction`,`/AA`), `/Launch`, `/EmbeddedFile`, and `/RichMedia`, de-obfuscating PDF
  name hex-escapes (`/J#61vaScript` → `/JavaScript`) and using complete-name-token
  matching to limit false positives.
- **File-type routing (T48):** `ScanFile` dispatches by magic bytes and re-classifies
  `detectedType` (powershell/ooxml/pdf/…); `ScanPath` now sweeps scripts/shortcuts/docs/
  archives, not just `.exe/.dll/.scr/.sys/.bin`.
- **Cobalt Strike beacon-config extractor (T18 — static C2 extraction):** `ConfigExtractor`
  locates an embedded CS beacon config (XOR-encoded TLV, key 0x2e/0x69), decodes it, and
  recovers the C2 host(s)/port/user-agent/sleep/watermark **without detonation** — surfaced
  as a high-confidence `config.cobalt_strike` finding (→ Malicious) with the C2 merged into
  the IOC set. FP-guarded (a hit requires a valid port + C2, not just the signature). The
  marquee gap vs commercial sandboxes; first family of an extensible config-extraction layer.
- **Adversarial review + FP calibration:** a multi-pass adversarial review of the new
  untrusted-byte parsers found **zero memory-safety bugs** and 5 false-positive
  calibration issues, all fixed with regression tests (benign "Package" OLE object no
  longer accused of CVE-2017-11882; bare "VBA" no longer asserts a macro; benign installer
  zip and benign `Invoke-WebRequest` scripts stay below Suspicious; a `.lnk` borrowing
  cmd.exe's icon is no longer "weaponized").
- **UI/report:** the scan panel now surfaces the detected file type + a score-sorted
  findings table (Any.Run-style tracker rows). Fixed the CLI's "(by magic bytes)" type
  label, which is now content-classified for scripts/OOXML.
- All three parsers read fully untrusted bytes and are bounds-safe (oversize counts,
  corrupt headers, truncated buffers, zero-advance loops all unit-tested) + adversarially
  reviewed.

### 2026-06-13 — no-boot static/host-side sweep
- **PE parser depth (T47):** parse export table, VERSIONINFO, TLS callbacks,
  .NET/CLR, Rich header, and the debug/PDB path — all bounds-safe and surfaced as
  scan findings + JSON/HTML/CLI. Adversarially reviewed; FP-calibrated.
- **Tool-output hardening (T50):** `RunSubprocess` output cap (OOM guard); the
  YARA/capa/DIE output parsers are now exposed, offline-fixture-tested, length-
  capped, and tolerant of malformed/huge input. Fixed a real capa array-extraction
  bug (broke on `]` inside a value / nested arrays).
- **Workspace retention (T62):** `workspace_retention_runs` config + unit-tested
  pruning of the oldest non-live runs + retention-gated end-of-run overlay
  reclamation.
- Reconciled `PROJECT_BACKLOG.md` against the 2026-06-09 session; recorded that
  T49 is depth-only (no "signed lowers score" bug) and that the 06-09 telemetry
  depth is dormant on Detonate by default (fresh-agent deploy is opt-in).
- Added `THIRD-PARTY-NOTICES.md`.

### Earlier highlights (see git history for detail)
- **2026-06-09:** corrected framing (the VM reaches the desktop; the blocker was a
  frozen/non-interactive desktop) + display-freeze fix; scored explainable verdict
  (T07); detonation lock (T08); deep process/persistence/dropped-file telemetry
  (T11/T72/T51); IOC export STIX/MISP/CSV (T79); controllable guest clock (C01).
- **2026-06-08:** static enrichment depth (multi-hash, PE sections/entropy,
  file-type ID, overlay/dropper detection); live shared-memory framebuffer →
  WebView2 canvas; anti-evasion string scrub (T34); GitHub Actions CI (T17).
- **2026-06-05:** in-guest sample execution + COM2 telemetry pipeline proven
  end-to-end on a seed-boot.
- **2026-05-29 → 06-04:** in-house WHP VM boots Windows 11 25H2 to the desktop
  (ACPI-checksum fix, in-house AHCI controller, CET/page-fault boot fixes).
