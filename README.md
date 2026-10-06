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


## Lab boundaries

For defensive research and local lab use. **Do not execute live malware on the host.** Network access defaults to disabled; the emulated fake-internet sink has no real egress. Guest execution requires all three gates: enabled configuration, per-run authorization, and guest-side arming. Keep threat-intelligence HTTP lookups opt-in, preserve base images and previous runs, and use only synthetic credentials in the isolated guest.

Boot reliability, input handling, operator progress, and performance remain active work. A quiet run or heuristic clean label is not a safety certificate. See current work (private documentation).

## License

No repository-wide license is declared in this checkout. Do not infer redistribution permission from source access; third-party materials retain their own terms.
