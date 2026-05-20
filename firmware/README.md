# AntiMal Firmware Drop-in

The in-house hypervisor needs a UEFI firmware blob (OVMF) to boot a Windows
guest. The firmware is not redistributed in this repo because AntiMal is
upstream-agnostic — drop your preferred build in here under the expected name.

## What to put here

| File           | Description                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
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
   Daily builds of upstream EDK2 with published SHA-256 hashes. BSD-2 licensed.
   Look for `RELEASEX64_OVMF.fd` (release) or `DEBUGX64_OVMF.fd` (verbose
   serial output — useful while iterating Phase 3b).
3. **Linux distribution package** (`ovmf` on Debian/Ubuntu, `edk2-ovmf` on
   Fedora). Install in a VM/WSL, copy the `.fd` out. Hashes vary by distro
   build but are reproducible.

Whichever route you pick, **verify the SHA-256 hash against the source's
published value** before placing the file here. Firmware runs in the guest CPU
before any of AntiMal's protections engage; a tampered blob would have full
control of the guest.

## License attribution

EDK2 / OVMF is BSD-2-Clause. If we ever ship binaries, the corresponding
license text from <https://github.com/tianocore/edk2/blob/master/License.txt>
must be included alongside the blob.

## After dropping the file

Re-run `bin\x64\Release\AntiMal.Tests.exe`. The Phase 3a firmware test
(`TestWhpFirmwareMapping`) will switch from `SKIP` to a real pass — it loads
the blob, maps it at the correct GPA, and verifies the host-side bytes round-
trip through the partition mapping. Phase 3b (actually running OVMF on the
vCPU) lands after that.
