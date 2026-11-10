# AntiMal Firmware Drop-in

The in-house hypervisor needs a UEFI firmware blob (OVMF) to boot a Windows
guest. This repository includes OVMF firmware images under this directory.
See the [image inventory and provenance limits](PROVENANCE.md). The images retain
their upstream licenses; see [license texts](licenses/) and the
[third-party notices](../THIRD-PARTY-NOTICES.md). You can also supply a compatible
build under the expected name.

## What to put here

| File           | Description                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
| `OVMF-tpm2.fd` | Source-built EDK2 OVMF with `TPM2_ENABLE=TRUE`, `SECURE_BOOT_ENABLE=TRUE`, and `FD_SIZE_4MB=TRUE`. Use this for Windows CI/VBS boot-contract probes. |
| `OVMF.fd`      | Combined x86_64 UEFI firmware image. Size must be a multiple of 4 KiB and ≤ 16 MiB. Typical sizes: 2 MiB (default EDK2 build) or 4 MiB (`FD_SIZE_4MB=TRUE`). |

The hypervisor maps `OVMF.fd` so its last byte sits at guest physical address
`0xFFFFFFFF`. With a 2 MiB blob that means GPA range `[0xFFE00000, 0x100000000)`;
with a 4 MiB blob, `[0xFFC00000, 0x100000000)`. The x86_64 reset vector at
`0xFFFFFFF0` lands inside the blob, so OVMF boots without any reset-state
overrides on our side.

## Where to get a known-good OVMF.fd

You have three reasonable options. Pick **one** and verify it before placing
the file here:

1. **Tianocore upstream EDK2 source**, build yourself. Highest assurance, most
   effort. See <https://github.com/tianocore/edk2> and `OvmfPkg` build docs.
2. **retrage's edk2-nightly** at <https://retrage.github.io/edk2-nightly/>.
   Daily builds of upstream EDK2. Preserve the licenses for the selected build.
   Look for `RELEASEX64_OVMF.fd` (release) or `DEBUGX64_OVMF.fd` (verbose
   serial output — useful while iterating Phase 3b).
3. **Linux distribution package** (`ovmf` on Debian/Ubuntu, `edk2-ovmf` on
   Fedora). Install in a VM/WSL, copy the `.fd` out. Hashes vary by distro
   build but are reproducible.

Whichever route you pick, **verify the SHA-256 hash against the source's
published value** before placing the file here. Firmware runs in the guest CPU
before any of AntiMal's protections engage; a tampered blob would have full
control of the guest.

## Building the TPM2 firmware locally

The download mode records the observed SHA-256 when `-PinHash` is omitted;
that record alone does not authenticate the upstream download. Supply an
independently verified `-PinHash` when fetching a prebuilt image.

`tools\Build-Firmware.ps1 -FromSource` builds OVMF from Tianocore EDK2 source
and installs `firmware\OVMF-tpm2.fd`. The default source build pins
`edk2-stable202605` and enables:

```powershell
-D TPM2_ENABLE=TRUE -D SECURE_BOOT_ENABLE=TRUE -D FD_SIZE_4MB=TRUE
```

Expected prerequisites:

- Visual Studio 2022 or 2019 with the C++ workload.
- Python 3.
- NASM.
- Intel ACPICA `iasl.exe`.

The script stages NASM/iASL under `external\firmware-tools\bin` so EDK2 sees
short, space-free tool paths. It also enables Git long-path support for the
EDK2 checkout and nested submodules; OpenSSL test vectors otherwise exceed the
default Windows path limit.

Use the TPM2 build without replacing the default firmware:

```powershell
$env:ANTIMAL_FIRMWARE_NAME = "OVMF-tpm2.fd"
bin\x64\Release\AntiMal.Tests.exe
```

If it proves better than the retrage blob, rerun the build with
`-InstallAsDefault` or copy the built blob to `OVMF.fd`.

## License attribution

EDK2 uses BSD-2-Clause-Patent, with additional licenses for some components.
The [EDK2 license](licenses/EDK2-LICENSE.txt) and
[OVMF license](licenses/OVMF-LICENSE.txt) are included. Preserve applicable
component licenses and notices alongside firmware when redistributing it.
A build's components and provenance determine which additional terms apply.

## After dropping the file

Re-run `bin\x64\Release\AntiMal.Tests.exe`. The Phase 3a firmware test
(`TestWhpFirmwareMapping`) will switch from `SKIP` to a real pass — it loads
the blob, maps it at the correct GPA, and verifies the host-side bytes round-
trip through the partition mapping. Phase 3b (actually running OVMF on the
vCPU) lands after that.
