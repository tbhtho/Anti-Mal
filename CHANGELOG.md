# Changelog

All notable changes to AntiMal are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Dates are ISO-8601.

This project has not cut a versioned release yet; entries are grouped by the work
that landed on `main`.

## [Unreleased]

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
