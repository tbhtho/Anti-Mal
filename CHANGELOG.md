# Changelog

All notable changes to AntiMal are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Dates are ISO-8601.

This project has not cut a versioned release yet; entries are grouped by the work
that landed on `main`.

## [Unreleased]

### 2026-06-17 — boot diagnostics, behavioral classifiers, Any.Run-style report depth
A continued autonomous drive toward the complete in-house VM + sandbox. With the live-boot
desktop-reach frontier user-gated (see CURRENT_STATE.md), this advanced every other priority area —
diagnostics, telemetry classification, report depth, and reliability measurement — all pure +
unit-tested. A living `private development documentation` tracks done/remaining vs. the goal's priorities.
- **Boot-outcome classifier (`BootDiagnostics`, priority 3):** collapses a run's scattered boot
  signals into one stage (not-started / firmware / kernel / user-mode / desktop) + detail +
  remediation; surfaced in the report and `detonate` output.
- **Persistence classifier (`PersistenceClassifier`, T72):** names the autostart mechanism + MITRE
  from raw registry/file targets (Run/RunOnce/Services/IFEO/COM/AppInit/Winlogon/Scheduled-Task/
  Startup) — the report persistence panel gains a Mechanism column and classifies file events too.
- **Network classifier (`NetworkClassifier`):** port→service + private/public + known-C2/Tor/IRC/
  cleartext/exposed-service flags, shown in the report network panel.
- **Behavioral-timeline relative time (`EventTime`, T52):** "T+8s" offsets per event.
- **Detections summary (`DetectionSummary`):** a severity-ranked behavior list unifying static
  findings + persistence + suspicious network, rendered at the top of the report and via
  `report --detections [--json]`.
- **Boot-reliability aggregator (`boot-report`, T05):** scans every run's report.json and reports a
  per-stage histogram + desktop/user-mode reach rates — boot reliability is now measurable from the
  user's runs without this tool launching a boot. Now also counts attempted-but-incomplete runs (a
  `job.json` with no finalized `report.json`) instead of silently dropping them, and recovers their
  real reach from `events.jsonl` (GuestAgent telemetry = OS-up) — correcting an inflated success rate
  (on the dev workspace: 35 of 45 report-less runs were actually user-mode boots, not failures).
- **`rebuild-report` command:** reconstructs `report.json` (+ `report.html` with `--html`) from a
  run's `events.jsonl` when the host died before finalizing it. Uses the same pure builders the live
  run uses (process tree / MITRE / network / behavior score), marks the summary `recovered`, and sets
  the user-mode gate only when GuestAgent telemetry is present (honest: OS-up, not desktop). Refuses
  to clobber an existing report without `--force`. Turns orphaned telemetry runs into navigable
  Any.Run-style reports.
- **`boot-report` failure breakdown:** `--json` now emits `byCategory`, `byRemediation`, and the
  `incomplete` count; text mode prints the single most common actionable remediation across runs
  (the highest-leverage fix for the dominant failure mode).
- **`simulate --scenario rat`:** a sixth synthetic scenario — a remote-access trojan with persistent
  TLS C2, an interactive remote shell (T1219), keylogging (T1056.001), screen capture (T1113), and
  exfil over C2 (T1041) — spanning Execution→Persistence→Credential Access→Collection→C2→Exfil. Adds
  the ATT&CK techniques T1219/T1113 to the catalog (name + tactic).
- **ISO/IMG disk-image analyzer (`IsoAnalyzer`):** mounting a downloaded `.iso` bypasses
  Mark-of-the-Web, so ISO images became a top delivery vector (lure `.lnk` → hidden payload).
  `ScanFile` now detects ISO9660 (`CD001` at 0x8001) and routes to a heuristic analyzer that flags an
  embedded PE (DOS-stub anchor), an embedded shell-link (`.lnk` header), and the small-image-with-
  payload lure shape — without unsafe full directory-tree parsing. Unit-tested + in the malformed
  corpus; verified end-to-end (synthetic lure ISO → suspicious with the lnk+exe + small-lure findings).
- **RTF maldoc analyzer (`RtfAnalyzer`, T68-adjacent):** RTF was detected but not analyzed — now
  `ScanFile` routes `rtf` to a dedicated analyzer flagging embedded OLE objects (`\objdata`),
  `\objupdate` auto-run-on-open, the **Equation Editor** exploit carrier (CVE-2017-11882 /
  CVE-2018-0802, via the class name / CLSID in the decoded object), and an embedded PE (DOS-stub
  anchor in the `\objdata` hex), plus **CVE-2017-0199 / OLE2Link remote-object load** (recovers the
  http(s) URL from the object moniker, incl. UTF-16LE, and surfaces it as an IOC). Heuristic +
  bounds-safe; unit-tested + added to the malformed-input corpus; verified end-to-end (synthetic RTF
  → 100/malicious with all findings).
- **Bogon / non-routable C2 detection (`NetworkClassifier`):** a C2 endpoint in a reserved/
  non-routable range (0/8, 100.64/10 CGNAT, the RFC5737 TEST-NET blocks, 198.18/15, 224/4 multicast,
  240/4 reserved) is now flagged `bogon` + suspicious with a note — a real anomaly signal (sinkhole /
  placeholder / misconfig) the port-only classifier missed. Unit-tested across the ranges + negatives
  (real public IPs and hostnames are not bogons).
- **MITRE ATT&CK tactic grouping (kill-chain view):** `MitreCatalog` gains `MitreTechniqueTactic`
  (technique→tactic, with sub-technique→parent fallback and an "Other" catch-all so nothing is
  dropped). The report's MITRE panel now groups techniques by tactic in canonical kill-chain order
  (Execution→…→Impact), the way Any.Run presents the chain, and a new `report --mitre [--json]` CLI
  view does the same. Unit-tested.
- **Analyst-workflow smoke test (`tools/Smoke-AnalystWorkflow.ps1`):** an end-to-end, no-VM
  regression of the CLI glue unit tests can't reach — simulate → report --summary/--why/--crashes/
  --detections → export stix/misp/csv → yara-gen → config (synthetic RC4 round-trip) → triage, with
  14 asserted checks; CI-gateable. Verified all-green.
- **IOC defanging (`Defang`, `--defang`):** the standard threat-intel safe-share rendering
  (`hxxp://`, `1[.]2[.]3[.]4`, `[@]`) for recovered C2. Opt-in on the human-facing views — `config
  --defang` and `export --format csv --defang` — while STIX/MISP/`--json` keep live IOCs for machine
  ingestion. Pure + unit-tested. Reachable across **all surfaces**: the GUI config panel has a defang
  checkbox, and the self-contained **report HTML** has a "defang IOCs (safe to share)" toggle so a
  forwarded report can't trigger an accidental click.
- **GUI boot-reliability panel (`reliability.get` bridge):** the Reports page now shows a "Boot
  reliability" rollup (reach rates + per-stage histogram) computed by the shared `BootReliability`
  Common module — GUI parity for `boot-report`.
- **GUI "Recover config / C2" (`scan.config` bridge):** the scan panel gains a button that runs the
  config/C2 extractors (Cobalt Strike + XOR + base64-wrapped RC4) on the worker and lists the recovered
  Malware Configuration inline — GUI parity for the CLI `config` command (mirrors the `scan.yara` path).
- **`config` command — the "Malware Configuration" view:** runs every static config/C2 extractor
  (Cobalt Strike beacon + single/multi-byte XOR + base64-wrapped + base64-wrapped RC4) on a sample and
  presents only the recovered configuration in one focused, analyst-facing place (text + `--json`).
  Exit 0 when config was recovered, 1 when none. Verified: clean on a benign PE, recovers C2+key from
  a synthetic RC4-config sample.
- **Base64-wrapped RC4 config recovery (T18, `MineRc4WrappedConfig`):** the canonical .NET-RAT
  (AsyncRAT/Quasar/njRAT-style) scheme — config RC4-encrypted then base64'd, key a short ASCII string
  elsewhere in the binary. Family-agnostic: tries each embedded ASCII string (3–32 chars) as the RC4
  key against each base64 blob and keeps a result ONLY when the decryption yields a valid http(s) URL
  (same known-plaintext anchor as the XOR recovery → near-zero false positives, verified clean on a
  real benign PE). Bounded work; surfaced in scan findings + IOCs. Round-trip + negative unit tests.
- **`report --why` — explainable verdict in the terminal:** prints the per-signal "why this verdict"
  rationale (the `BehaviorScore` headline feature, previously only in the HTML report + raw JSON), so
  CLI/automation users get the same explainability. `--json` supported.
- **`triage <dir>` — risk-ranked bulk scan:** scans a folder and prints one compact line per file
  sorted by score (rank / score / verdict / sha256 / top-tag / file), the "which of these do I look at
  first?" workflow. `--json` for automation; exit 10 if any file is flagged.
- **In-guest analyst desktop (`AntiMal.GuestAgent.exe --shell`):** since the Win11 modern shell
  crash-loops in this VM, AntiMal now ships its own minimal desktop/launcher — a Win32 window with
  Files / Command Prompt / Web Browser launch buttons and a live process list (Toolhelp) with
  End-Task, depending on nothing the modern shell needs (user32/comctl32/shell32/toolhelp). One flag
  (`ANTIMAL_PROBE_SHELL`) swaps the Winlogon shell to cmd and AutoRun-launches it, so a seed boot
  lands in a usable analyst desktop. Also enlarged the in-guest **file browser** into a fuller
  File-Explorer replacement (editable address bar + Enter-navigate, Up/Refresh/Open/This-PC toolbar,
  drive listing, keyboard nav, ShellExecute Open). Both host-verified (build + window opens).
- **Crash-signature summary (`CrashSummary`, `report --crashes`):** collapses `process.crash`
  telemetry spam into distinct fault signatures — (image, NTSTATUS code + human name, faulting module
  + version + offset) with counts — for both the Win11 modern-shell wall and a detonated sample that
  crashes. Surfaced via `report --crashes [--json]` and a top-signature line in `report --summary`.
  Immediately useful: on a real run it revealed the 51 shell crashes are *two* signatures — 40×
  Explorer in `ucrtbase.dll` and 11× ShellHost in `ControlCenter.dll` — a distinction the prior
  count-only detection masked. Pure + unit-tested.
- **`report --summary` (T53-adjacent):** a compact at-a-glance triage view — verdict/score, boot
  stage, sample-executed, event count + per-category breakdown, process/MITRE/network/detection
  counts — without parsing the full report. `--json` emits a stable versioned (`schemaVersion:1`)
  summary object for dashboards/CI.
- **Filterable `report --timeline`:** `--category <c>`, `--mitre` (only events carrying a technique),
  and `--limit N` make a large telemetry stream triageable; the header shows matched/total. Also
  fixed a redundant `category.action` render (e.g. `process.process.running` → `process.running`).
- **`yara-gen` — auto-generated YARA rules (`YaraGen`):** scans a sample and emits a ready-to-tune
  hunt rule from its most distinctive strings (IOC URLs/domains/mutexes ranked first; PE boilerplate
  and import-table DLL names filtered) plus sha256/imphash/filetype meta and a PE-magic + filesize +
  `N of ($s*)` condition. Falls back to a magic/size/sha256 rule when no distinctive strings survive.
  Pure + deterministic + unit-tested; `antimal yara-gen <sample> [--out rule.yar] [--name R]`.
  Also reachable from the GUI: the scan panel gains a **Generate YARA rule** button (`scan.yara`
  bridge method, generated on a worker so a large file can't hang the UI) with copy-to-clipboard.
  And from the indicator-export workflow: `export <run> --format yara` emits a hunt rule for the
  run's sample alongside the existing STIX/MISP/CSV indicator formats.
- **Severity-ranked Detections summary (`DetectionSummary`):** unifies static findings + persistence
  + suspicious network into one ranked behavior list; in the report + `report --detections [--json]`.
- **Desktop-usability classifier (`UsabilityDiagnostics`):** measures which usability goals a run
  achieved (display/input/disk/exec/telemetry/browser/shell), DETECTS the Win11 modern-shell
  crash-loop, and surfaces the cmd-shell remediation; in the report + `report --usability [--json]`.
- **Offline guest file browsing + triage (`fs-ls`/`fs-cat`/`fs-find`/`fs-scan`):** browse, extract,
  recursively search, and extract-then-static-scan the guest's files straight from the disk image
  (base VHDX + optional run overlay) via the in-house NtfsReader — File-Explorer-style access and
  in-guest-artifact triage with NO boot, working around the crash-looping in-guest File Explorer.
- **Offline guest registry browsing (`reg-ls`):** extract + list/search a guest hive (SOFTWARE/
  SYSTEM/SAM/…) from the disk image — inspect Run keys / Services / persistence with no boot.
- **In-guest GUI file browser (`AntiMal.GuestAgent.exe --file-browser`):** a dependency-light Win32
  file browser with NO modern-shell dependency, launchable from the cmd-shell sidestep — working
  *live* file browsing in the guest even though the Win11 File Explorer crash-loops. Host-verifiable.
- **Command-line / LOLBin classifier (`CommandLineClassifier`):** flags encoded PowerShell, download
  cradles, rundll32/regsvr32/mshta proxy exec, certutil/bitsadmin ingress, vssadmin recovery
  inhibition, schtasks/sc persistence, etc. — in the Detections summary + inline in the process tree.
- **Built-in packer ID** (UPX/Themida/VMProtect/… by section signatures) and **enriched IOC export**
  (classifier-recognized persistence). Plus report-HTML structural + malformed-input robustness
  regression tests.

### 2026-06-17 — static-triage depth, analyst workflow CLIs, FPS instrumentation, local simulation
An autonomous no-boot sweep that broadens the static engine, adds analyst-workflow CLIs,
instruments the live display, and makes the report pipeline runnable end-to-end with no VM.
All increments TDD; build + `AntiMal.Tests` green.
- **CTPH fuzzy hash (T94/T14):** `FuzzyHash.{h,cpp}` — a self-contained context-triggered
  piecewise hash (the spamsum construction) for sample similarity/clustering, with a
  common-substring gate + block-size cap that prevent spurious high scores. `ScanResult.ctph`
  flows through report JSON/HTML/CLI like imphash. The last open multi-hash gap.
- **`similarity` command:** `antimal similarity <a> <b>` (and `--to <digest>`) prints both CTPH
  digests + a 0..100 score with a plain-English band — "is this a repacked variant?" without a
  full scan.
- **`doctor` preflight (T66):** `antimal doctor [--json]` reports host + workflow readiness
  (WHP, OVMF, base image, GuestAgent, workspace, enrichment tools, exec gate) with an actionable
  hint per failure; exit 0 when boot-ready, 1 on a hard blocker (CI-gateable).
- **Live-display frame-pacing diagnostics (FPS):** `FramePacing.h` — a pure, unit-tested
  `FramePacingStats` (achieved FPS, interval p50/p95/min/max, on-target %, blank-skips) wired
  into the VM publish loop and surfaced in `vm-diagnostics.txt`. The measured-diagnostics
  foundation for the 25-30 FPS goal.
- **`simulate` local detonation (documented simulation):** `antimal simulate` builds a complete,
  clearly-labeled SYNTHETIC stealer run (`Simulation.{h,cpp}`) and writes report.json +
  report.html + events.jsonl + a screenshot filmstrip — exercising the events → report → HTML
  pipeline end-to-end with no VM/firmware/hardware dependency. Real static hashes; deterministic.
  `--scenario stealer|ransomware|loader` covers the major behavior classes (e.g. ransomware:
  vssadmin shadow-delete + bulk .locked encryption + ransom note → T1486; loader: stage download
  + svchost hollowing → T1055.012), giving cross-behavior report + report-diff fixtures.
- **Authenticode signer name (T49):** `AuthenticodeSignerName` extracts the embedded PKCS#7
  signer's display name (e.g. "Microsoft Windows"); surfaced in `ScanResult.signerName` and the
  report/CLI. A Microsoft-signed binary reads very differently from one signed by an unknown
  publisher. Handles freed via RAII on every path.
- **MITRE technique names (`MitreCatalog`):** the report's ATT&CK chips now show the technique
  NAME (e.g. "Registry Run Keys / Startup Folder") with the full name on hover, not just the ID.
- **`report-diff` command (T78):** `antimal report-diff <A> <B>` shows verdict/score changes +
  added/removed IOCs/findings/MITRE/tags between two reports (determinism check / variant
  comparison; pairs with `similarity`). Pure `DiffReports` core, unit-tested.
- **Headless automation (C04):** `similarity`, `report-diff`, and `doctor` all emit stable
  machine-readable `--json` (shared JsonQuote helper), with branchable exit codes — scriptable /
  SOAR-integratable alongside `detonate --json`.
- **Shellcode / PIC detection (T93):** `DetectShellcode` flags position-independent shellcode by
  its anchored low-FP tells (GetPC `E8 00000000`+pop, PEB-walk `fs:[0x30]`/`gs:[0x60]`) in the
  places a PE parse never looks — non-PE payloads and PE overlays — with conservative FP gating.
- **Adversarial review hardening:** a multi-pass find→verify review of the session's new
  untrusted-input code confirmed + fixed 3 defense-in-depth issues — a CTPH block-size overflow /
  potential infinite loop on >64 GiB input, and an Authenticode handle leak on an allocation
  exception.
- **Housekeeping:** repaired a mojibake em-dash + forward-slashed the TOML paths in
  `config/antimal.toml`; completed the OOBE-automating base-build script (`BypassNRO` +
  `-FirstLogonShutdownSec` clean-shutdown for snapshot capture); fixed an unattended-run hang in
  `Test-AntiMalBaseBoot.ps1`.

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
