# Third-Party Notices

AntiMal redistributes, or builds upon, the third-party components listed below.
Each remains under its own license. The [MIT License](LICENSE) for original
AntiMal code does not supersede those terms. Included license texts and upstream notices are
linked below. See the firmware inventory for the extent of the provenance checks
and any remaining gaps before redistributing those images.

## Redistributed binaries / firmware

### TianoCore EDK2 / OVMF (UEFI firmware)
- **What:** The OVMF images and variable-store image in `firmware/`. The
  [firmware inventory](firmware/PROVENANCE.md) records exact hashes, source/build
  evidence and remaining gaps for every file.
- **Main licenses:** Full [EDK2 BSD-2-Clause-Patent text](firmware/licenses/EDK2-LICENSE.txt)
  and [OVMF license, including specified MIT-covered files](firmware/licenses/OVMF-LICENSE.txt).
- **Verified source-built TPM2 image:** EDK2 commit
  `b03a21a63e3bd001f52c527e5a57feddb53a690b`. The retained build includes OpenSSL
  3.5.1 ([Apache-2.0 license](firmware/licenses/OPENSSL-LICENSE.txt)) and the
  LZMA SDK 19.00 decompressor ([public-domain notice](firmware/licenses/LZMA-SDK-README.txt)).
- **Limits:** Exact upstream nightly binaries were matched, but their EDK2 source
  revisions and full dependency/copyright manifests remain unresolved. The Arch
  reference image has not been matched to an exact upstream package.
  The notices above do not certify those images' complete licensing coverage.
- **Upstream:** https://github.com/tianocore/edk2

### Microsoft Edge WebView2 SDK
- **What:** SDK headers, the x64 loader DLL and its import library from
  `Microsoft.Web.WebView2` 1.0.3967.48. The loader is copied next to `AntiMal.exe`.
- **License:** Microsoft's BSD-style three-clause license. Full package
  [license](external/webview2/LICENSE.txt) and
  [notices](external/webview2/NOTICE.txt) are included.
- **Provenance:** All four files match the official NuGet package. See
  [version, source and hashes](external/webview2/PROVENANCE.md).
- **Runtime:** The separately installed WebView2 Runtime is not bundled here.
  Its terms are separate from the SDK license above.
- **Upstream:** https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.3967.48

## Optional, NOT redistributed

AntiMal's enrichment pipeline can shell out to **YARA**, **capa**, and
**Detect It Easy (`diec`)** when their binaries are present next to the
executable or under `tools\`. These are **not** bundled with AntiMal - the
operator supplies them - so AntiMal imposes no redistribution obligation for
them. Each carries its own license (YARA: BSD-3-Clause; capa: Apache-2.0;
Detect It Easy: MIT). When you bundle them in a distribution, include their
license texts here.

## Operating system

The dynamic-analysis VM boots a **Windows** guest from an image **you supply**
(your own licensed Windows media). AntiMal does not redistribute Windows or any
Microsoft operating-system component.

## Screenshots

The historical guest captures in `assets/screenshots/` depict Microsoft Windows,
Microsoft Edge and Adobe After Effects, alongside AntiMal's own benign test
fixture. Third-party application interfaces, trademarks and artwork remain the
property of their respective owners and are not covered by AntiMal's MIT license.
The images illustrate recorded guest activity; they imply no endorsement,
affiliation, security certification or right to redistribute those applications.
