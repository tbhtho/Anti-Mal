# Third-Party Notices

AntiMal redistributes, or builds upon, the third-party components listed below.
Each remains under its own license; the AntiMal license (see `LICENSE`, when
present) does not supersede them. This file is informational — the authoritative
license text for each component ships with that component's upstream project.

## Redistributed binaries / firmware

### TianoCore EDK2 / OVMF (UEFI firmware)
- **What:** The guest UEFI firmware image (`firmware/OVMF.fd`) is built from the
  TianoCore EDK2 project's OVMF platform. Build tooling lives under
  `external/edk2/` and `external/firmware-tools/`.
- **License:** BSD-2-Clause-Patent.
- **Upstream:** https://github.com/tianocore/edk2 — see `License.txt` there.
- **Note:** EDK2's CryptoPkg vendors OpenSSL (Apache License 2.0 in current
  releases). If a built OVMF image includes CryptoPkg, the OpenSSL terms apply to
  that portion.

### Microsoft Edge WebView2
- **What:** The WebView2 runtime loader (`external/webview2/`, vendored
  `Microsoft.Web.WebView2` 1.0.3967.48 from nuget.org) hosts the AntiMal console
  UI. `WebView2Loader.dll` is copied next to `AntiMal.exe`.
- **License:** Microsoft Software License Terms for the Microsoft Edge WebView2
  SDK / Runtime.
- **Upstream:** https://developer.microsoft.com/microsoft-edge/webview2/

## Optional, NOT redistributed

AntiMal's enrichment pipeline can shell out to **YARA**, **capa**, and
**Detect It Easy (`diec`)** when their binaries are present next to the
executable or under `tools\`. These are **not** bundled with AntiMal — the
operator supplies them — so AntiMal imposes no redistribution obligation for
them. Each carries its own license (YARA: BSD-3-Clause; capa: Apache-2.0;
Detect It Easy: MIT). When you bundle them in a distribution, include their
license texts here.

## Operating system

The dynamic-analysis VM boots a **Windows** guest from an image **you supply**
(your own licensed Windows media). AntiMal does not redistribute Windows or any
Microsoft operating-system component.
