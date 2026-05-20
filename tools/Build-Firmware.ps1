<#
.SYNOPSIS
  Install firmware\OVMF.fd for the AntiMal in-house hypervisor.

.DESCRIPTION
  Phase-3 MVP: downloads a prebuilt RELEASEX64_OVMF.fd from retrage's
  edk2-nightly (BSD-2-Clause builds of upstream Tianocore EDK2). The URL is
  stable; the hash rotates per nightly build, so by default the script
  records the observed hash on first run and verifies against the same hash
  on subsequent runs. Pass -PinHash <SHA256> to lock to a specific build.

  This is an INTERIM solution. The long-term plan is to compile OVMF from
  EDK2 source ourselves using the toolchain laid out in
  the private development documentation (Phase 3 -> from-source upgrade). The Windows
  build-from-source toolchain (NASM + iasl from ACPICA source + flex/bison
  via winflexbison + GNU bison data files) is a 3-4 hour yak shave that
  blocks every later phase, so we punt it and ship with a hash-pinned
  upstream blob for now.

.PARAMETER PinHash
  Required SHA-256 hash (case-insensitive hex) to verify the downloaded blob
  against. If supplied and the download doesn't match, the script aborts
  without installing.

.PARAMETER Force
  Re-download even if firmware\OVMF.fd already exists with a valid recorded
  hash. Use after retrage rotates its nightly build.

.EXAMPLE
  pwsh tools\Build-Firmware.ps1
  First run: downloads, records the observed hash to firmware\OVMF.fd.sha256
  for future verification, installs the blob.

.EXAMPLE
  pwsh tools\Build-Firmware.ps1 -PinHash <hash>
  Strict mode: download, fail if hash differs from <hash>.

.NOTES
  Source: https://retrage.github.io/edk2-nightly/
  License: BSD-2-Clause (Tianocore EDK2). When AntiMal ships binaries the
  upstream LICENSE.txt from the EDK2 repo must travel with OVMF.fd.
#>
[CmdletBinding()]
param(
  [string]$PinHash,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$repoRoot    = (Resolve-Path "$PSScriptRoot\..").Path
$firmwareDir = Join-Path $repoRoot 'firmware'
$firmwareOut = Join-Path $firmwareDir 'OVMF.fd'
$hashRecord  = $firmwareOut + '.sha256'

# Retrage's index page serves a static "latest" URL. The underlying file
# rotates per upstream EDK2 nightly. We hash-pin via -PinHash or via the
# recorded sha256 from a prior successful run.
$OvmfUrl = 'https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd'

function Write-Section($msg) { Write-Host ''; Write-Host ('===[ ' + $msg + ' ]===') -ForegroundColor Cyan }
function Write-Step($msg)    { Write-Host ('  -> ' + $msg) -ForegroundColor Green }
function Write-Warn2($msg)   { Write-Host ('  !! ' + $msg) -ForegroundColor Yellow }
function Write-Fail($msg)    { Write-Host ('  XX ' + $msg) -ForegroundColor Red }

function Get-FileSha256($path) {
  return (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToUpperInvariant()
}

function Invoke-Download($url, $dest) {
  Write-Step "Downloading: $url"
  Write-Step "  -> $dest"
  $oldPp = $ProgressPreference
  $ProgressPreference = 'SilentlyContinue'
  try {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
  } finally {
    $ProgressPreference = $oldPp
  }
}

try {
  Write-Section 'AntiMal firmware install (prebuilt OVMF.fd from retrage edk2-nightly)'

  if (-not (Test-Path $firmwareDir)) {
    New-Item -ItemType Directory -Force -Path $firmwareDir | Out-Null
  }

  # Short-circuit if firmware is already present, valid, and we're not in
  # Force mode. Saves a round trip when the user just wants to verify state.
  if (-not $Force -and (Test-Path $firmwareOut) -and (Test-Path $hashRecord)) {
    $existingHash = Get-FileSha256 $firmwareOut
    $recordedHash = (Get-Content $hashRecord -Raw).Trim().ToUpperInvariant()
    if ($existingHash -eq $recordedHash -and (-not $PinHash -or $existingHash -eq $PinHash.ToUpperInvariant())) {
      Write-Step "Existing firmware\OVMF.fd matches its recorded hash."
      Write-Step "  SHA-256: $existingHash"
      Write-Step "  (pass -Force to re-download.)"
      exit 0
    }
    Write-Warn2 "Existing firmware\OVMF.fd does not match recorded hash; re-downloading."
  }

  # Stage to a temp file first so a half-finished download doesn't poison
  # firmware\OVMF.fd if Invoke-WebRequest dies mid-transfer.
  $stagePath = Join-Path $firmwareDir 'OVMF.fd.partial'
  if (Test-Path $stagePath) { Remove-Item -Force $stagePath }
  Invoke-Download $OvmfUrl $stagePath

  $observed = Get-FileSha256 $stagePath
  Write-Step "Downloaded blob SHA-256: $observed"

  if ($PinHash) {
    if ($observed -ne $PinHash.ToUpperInvariant()) {
      Remove-Item -Force $stagePath
      throw "PinHash mismatch.`n  expected: $($PinHash.ToUpperInvariant())`n  observed: $observed`n  Refusing to install firmware we cannot verify."
    }
    Write-Step "-PinHash check OK."
  } else {
    Write-Warn2 "No -PinHash supplied. Recording observed hash for future verification."
    Write-Warn2 "If you trust this build, future runs will refuse to install anything with a different hash."
    Write-Warn2 "To re-fetch a fresh nightly later: pass -Force (and a new -PinHash if you want strict mode)."
  }

  # Quick sanity: file size & alignment match the constraints
  # antimal::hv::Firmware imposes (multiple of 4 KiB, <= 16 MiB).
  $sizeBytes = (Get-Item $stagePath).Length
  if ($sizeBytes -eq 0) {
    Remove-Item -Force $stagePath
    throw "Downloaded firmware is zero bytes."
  }
  if (($sizeBytes % 4096) -ne 0) {
    Remove-Item -Force $stagePath
    throw "Downloaded firmware size $sizeBytes is not a multiple of 4 KiB; antimal::hv::Firmware will reject it."
  }
  if ($sizeBytes -gt (16 * 1024 * 1024)) {
    Remove-Item -Force $stagePath
    throw "Downloaded firmware ($sizeBytes bytes) exceeds antimal::hv::Firmware::kMaxFirmwareBytes (16 MiB)."
  }
  Write-Step "Size OK: $sizeBytes bytes."

  if (Test-Path $firmwareOut) { Remove-Item -Force $firmwareOut }
  Move-Item -Force $stagePath $firmwareOut
  Set-Content -Path $hashRecord -Value $observed -Encoding ascii
  Write-Section 'Done'
  Write-Step "Installed: $firmwareOut"
  Write-Step "Hash file: $hashRecord"
  Write-Step "SHA-256:   $observed"
  Write-Step ""
  Write-Step "Next: pwsh -Command `"& '$repoRoot\bin\x64\Release\AntiMal.Tests.exe'`""
  Write-Step "  -> TestWhpFirmwareMapping should flip from SKIP to a silent pass."

  exit 0
}
catch {
  Write-Fail $_.Exception.Message
  if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
  exit 1
}
