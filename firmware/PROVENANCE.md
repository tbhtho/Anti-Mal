# Firmware inventory and provenance

Checked 2026-11-10 against the files retained in this repository and the original
local source/build records. This is an inventory, not a security certification or
an exhaustive license audit. No firmware was executed for these checks.

All eight images match the original checkout byte-for-byte. Checksums identify
these copies; they do not independently authenticate an upstream publisher.

## OVMF-tpm2.fd

- Kind: Source-built EDK2 release.
- Size: 4,194,304 bytes.
- SHA-256: `6ba13088f093249586cb07a69a3d6df6b07b64162ef991b0b08c4728cc23266c`
- Evidence: The build record identifies EDK2 `b03a21a63e3bd001f52c527e5a57feddb53a690b` (`edk2-stable202605`), VS2022 RELEASE X64 with TPM2, Secure Boot and 4MB enabled. The image matches the retained build output byte-for-byte.

## OVMF-tpm2-secboot.fd

- Kind: Customized TPM2 image.
- Size: 4,194,304 bytes.
- SHA-256: `d80e6ccbc975df939eb25dab4ecb5215f04740253aa3e81765382817c3cb8306`
- Evidence: Differs from `OVMF-tpm2.fd` in 13,126 bytes, confined to offsets `0x64` through `0x33e3` in the variable-store area. All subsequent bytes are identical. Repository history describes Microsoft KEK/db enrollment; certificate origins and enrollment tooling were not independently verified.

## OVMF_VARS_enrolled.fd

- Kind: Variable-store extract.
- Size: 540,672 bytes.
- SHA-256: `d9b79109078c1ab1b8a138f34e834e7b043d4b43e8a97fe74ec85f139f8f1077`
- Evidence: Exactly the first 540,672 bytes of `OVMF-tpm2-secboot.fd`. The same enrollment-provenance limits apply.

## OVMF-debug.fd

- Kind: Nightly debug image.
- Size: 4,194,304 bytes.
- SHA-256: `816d125de06a3f0a3dc5965b25101bc636ba4580cc64b9fa675785917cb5e5ae`
- Evidence: Exact byte match to [`bin/DEBUGX64_OVMF.fd`](https://github.com/retrage/edk2-nightly/blob/6d3d5af120363700055717ba7a595abe7412b175/bin/DEBUGX64_OVMF.fd) at retrage/edk2-nightly commit `6d3d5af120363700055717ba7a595abe7412b175` (2026-05-19). Both Git blob identity and an independent upstream download SHA-256 match. The archived workflow builds X64 DEBUG with GCC and Secure Boot enabled; its exact EDK2 source commit and full dependency manifest remain unresolved. It does not match the retained local VS2022 DEBUG build.

## OVMF-debug-rtfix.fd

- Kind: Modified nightly debug image.
- Size: 4,194,304 bytes.
- SHA-256: `ed95f75cdf59067aba7acd2bbeed796e1110014c8e7982a830cce657beb61682`
- Evidence: Exactly one byte differs from `OVMF-debug.fd`: offset `0x3cc3bf`, `0x75` to `0xeb`. This identifies the exact base image and local byte change; the modification rationale/recipe and exact EDK2 source commit were not recovered.

## OVMF.fd

- Kind: Prebuilt release image.
- Size: 4,194,304 bytes.
- SHA-256: `de2d4a8f70e34476758e55b0e93fec5ad13f869f09653cea10009ee80bcc11b2`
- Evidence: Exact byte match to [`bin/RELEASEX64_OVMF.fd`](https://github.com/retrage/edk2-nightly/blob/d7650e934adab789a0591f9a76733c994c808ed7/bin/RELEASEX64_OVMF.fd) at retrage/edk2-nightly commit `d7650e934adab789a0591f9a76733c994c808ed7` (2026-05-15). Both Git blob identity and an independent upstream download SHA-256 match. Exact EDK2 source revision and full dependency manifest remain unresolved.

## OVMF.release.before-debug.fd

- Kind: Prebuilt release copy.
- Size: 4,194,304 bytes.
- SHA-256: `de2d4a8f70e34476758e55b0e93fec5ad13f869f09653cea10009ee80bcc11b2`
- Evidence: Byte-identical to `OVMF.fd`; the same provenance limits apply.

## OVMF-arch-tpm.fd

- Kind: Arch reference image.
- Size: 4,194,304 bytes.
- SHA-256: `f33f81c6fca726aa1923694cb0f3e86a60e36879779f809143f188e068b90d8e`
- Evidence: Repository history describes an Arch TPM-enabled OVMF reference image. Exact package version, download URL, source revision, packaging changes and publisher checksum were not recovered.

## Source-built TPM2 components

The build record is [OVMF-tpm2.fd.build.txt](OVMF-tpm2.fd.build.txt).
The recorded upstream [EDK2 commit](https://github.com/tianocore/edk2/tree/b03a21a63e3bd001f52c527e5a57feddb53a690b)
was present without tracked source changes when checked. Material dependencies
confirmed in its retained RELEASE build include:

- EDK2 / OVMF: [EDK2 license](licenses/EDK2-LICENSE.txt) and
  [OVMF package license](licenses/OVMF-LICENSE.txt).
- OpenSSL 3.5.1, commit
  [`aea7aaf2abb04789f5868cbabec406ea43aa84bf`](https://github.com/openssl/openssl/tree/aea7aaf2abb04789f5868cbabec406ea43aa84bf):
  [Apache-2.0 license](licenses/OPENSSL-LICENSE.txt). The upstream checkout has
  no top-level NOTICE file.
- LZMA SDK 19.00 decompressor: [upstream public-domain notice](licenses/LZMA-SDK-README.txt).
- EDK2 FAT driver, covered by BSD-2-Clause-Patent.

The checked-out submodule list is not a list of compiled components. These checks
identify the material dependencies above without asserting an exhaustive per-file
copyright inventory. License files were copied from the recorded source checkout.

## Retained images with incomplete provenance

The nightly images now have exact upstream binary matches, but their EDK2
source/dependency records remain incomplete. The Arch image still lacks an exact
package match. These images have incomplete dependency and copyright records. Adding the known EDK2/OVMF license texts does not establish
complete license coverage for those files. Before redistributing them, recover
the original package/build manifests and notices, or replace them with a reviewed,
reproducible build. The enrolled variable stores also need a certificate-source
record. These gaps are recorded rather than assigning an unverified origin.
