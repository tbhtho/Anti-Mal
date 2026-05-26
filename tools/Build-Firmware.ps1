<#
.SYNOPSIS
  Install firmware for the AntiMal in-house hypervisor.

.DESCRIPTION
  Default mode downloads a prebuilt RELEASEX64_OVMF.fd from retrage's
  edk2-nightly, hash-pins it, and installs it as firmware\OVMF.fd.

  -FromSource builds OVMF from Tianocore EDK2 source with TPM2 and Secure Boot
  enabled by default. That path is meant for the Windows 11 CI/VBS boot gate:
  it produces an OVMF build that can install Tcg2Protocol against AntiMal's
  TPM CRB stub instead of relying on distro/QEMU-specific prebuilt firmware.

.PARAMETER FromSource
  Clone/update external\edk2 and build OvmfPkgX64.dsc locally.

.PARAMETER Edk2Ref
  Branch, tag, or commit to check out when -FromSource is used.

.PARAMETER BuildTarget
  EDK2 build target: DEBUG, RELEASE, or NOOPT.

.PARAMETER Toolchain
  EDK2 toolchain tag. If omitted, the script picks VS2022 or VS2019 from the
  detected Visual Studio installation.

.PARAMETER EnableTpm2
  Add -D TPM2_ENABLE=TRUE to the EDK2 build. Defaults to true.

.PARAMETER EnableSecureBoot
  Add -D SECURE_BOOT_ENABLE=TRUE to the EDK2 build. Defaults to true.

.PARAMETER FdSize4Mb
  Add -D FD_SIZE_4MB=TRUE. Defaults to true for TPM/Secure Boot builds.

.PARAMETER OutputName
  Firmware filename under firmware\ for -FromSource. Defaults to
  OVMF-tpm2.fd. Default download mode always installs OVMF.fd.

.PARAMETER InstallAsDefault
  Also copy the source-built firmware to firmware\OVMF.fd after it passes the
  size/hash checks.

.PARAMETER CheckOnly
  In -FromSource mode, validate tools and print the build command without
  cloning/updating/building.

.PARAMETER PinHash
  Required SHA-256 hash (case-insensitive hex) to verify the downloaded or
  source-built blob against. If supplied and the blob does not match, the
  script aborts without installing.

.PARAMETER Force
  Re-download default prebuilt firmware, or allow refetching existing EDK2
  source metadata. The script still refuses to clobber dirty EDK2 source trees.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\Build-Firmware.ps1
  Downloads retrage RELEASEX64_OVMF.fd and installs firmware\OVMF.fd.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\Build-Firmware.ps1 -FromSource
  Builds firmware\OVMF-tpm2.fd from EDK2 with TPM2 + Secure Boot enabled.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\Build-Firmware.ps1 -FromSource -CheckOnly
  Verifies git/python/nasm/iasl/Visual Studio discovery and prints the command.

.NOTES
  Sources:
    retrage prebuilt OVMF: https://retrage.github.io/edk2-nightly/
    EDK2 source:           https://github.com/tianocore/edk2
    OVMF build guide:      https://www.tianocore.org/tianocore-wiki.github.io/development/tutorials-howto/how_to_build_ovmf.html
    iASL binary tools:     https://www.intel.com/content/www/us/en/developer/topic-technology/open/acpica/download.html
#>
[CmdletBinding()]
param(
  [string]$PinHash,
  [switch]$Force,
  [switch]$FromSource,
  [string]$Edk2Ref = 'edk2-stable202605',
  [ValidateSet('DEBUG', 'RELEASE', 'NOOPT')]
  [string]$BuildTarget = 'RELEASE',
  [string]$Toolchain,
  [bool]$EnableTpm2 = $true,
  [bool]$EnableSecureBoot = $true,
  [bool]$FdSize4Mb = $true,
  [string]$OutputName,
  [switch]$InstallAsDefault,
  [switch]$CheckOnly,
  [string]$NasmPath,
  [string]$IaslPath,
  [string]$PythonPath,
  [string]$VsInstallPath,
  [switch]$SkipSubmoduleUpdate
)

$ErrorActionPreference = 'Stop'

$repoRoot    = (Resolve-Path "$PSScriptRoot\..").Path
$firmwareDir = Join-Path $repoRoot 'firmware'
$firmwareOut = Join-Path $firmwareDir 'OVMF.fd'
$hashRecord  = $firmwareOut + '.sha256'
$externalDir = Join-Path $repoRoot 'external'
$toolBinDir  = Join-Path $externalDir 'firmware-tools\bin'
$edk2Dir     = Join-Path $externalDir 'edk2'

$OvmfUrl = 'https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd'
$Edk2Url = 'https://github.com/tianocore/edk2.git'

function Write-Section($msg) {
  Write-Host ''
  Write-Host ('===[ ' + $msg + ' ]===') -ForegroundColor Cyan
}

function Write-Step($msg) { Write-Host ('  -> ' + $msg) -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host ('  !! ' + $msg) -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host ('  XX ' + $msg) -ForegroundColor Red }

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

function Invoke-Native([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory) {
  $oldLocation = Get-Location
  try {
    if ($WorkingDirectory) {
      Set-Location -LiteralPath $WorkingDirectory
    }
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "$FilePath exited with code $LASTEXITCODE"
    }
  } finally {
    Set-Location $oldLocation
  }
}

function Resolve-Tool([string]$Name, [string]$ExplicitPath, [string]$Hint) {
  if ($ExplicitPath) {
    $resolved = Resolve-Path -LiteralPath $ExplicitPath -ErrorAction SilentlyContinue
    if ($resolved) {
      return $resolved.Path
    }
    throw "$Name was supplied as '$ExplicitPath' but that file does not exist."
  }

  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }

  throw "$Name was not found on PATH. $Hint"
}

function Find-VsInstall() {
  if ($VsInstallPath) {
    $resolved = Resolve-Path -LiteralPath $VsInstallPath -ErrorAction SilentlyContinue
    if (-not $resolved) {
      throw "VsInstallPath '$VsInstallPath' does not exist."
    }
    return $resolved.Path
  }

  $vswhereCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
    (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
  )

  foreach ($candidate in $vswhereCandidates) {
    if (Test-Path -LiteralPath $candidate) {
      $path = & $candidate -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
      if ($LASTEXITCODE -eq 0 -and $path) {
        return $path.Trim()
      }
    }
  }

  throw "Visual Studio C++ tools were not found. Install VS 2022/2019 with the Desktop development with C++ workload, or pass -VsInstallPath."
}

function Select-Toolchain([string]$VsPath) {
  if ($Toolchain) {
    return $Toolchain
  }
  if ($VsPath -match '2022') {
    return 'VS2022'
  }
  if ($VsPath -match '2019') {
    return 'VS2019'
  }
  Write-Warn2 "Could not infer VS year from '$VsPath'; defaulting to VS2022."
  return 'VS2022'
}

function Copy-ToolToFirmwareBin([string]$ToolPath) {
  New-Item -ItemType Directory -Force -Path $toolBinDir | Out-Null
  $dest = Join-Path $toolBinDir (Split-Path -Leaf $ToolPath)
  if ((Resolve-Path -LiteralPath $ToolPath).Path -ne $dest) {
    Copy-Item -Force -LiteralPath $ToolPath -Destination $dest
  }
  return $dest
}

function Test-FirmwareBlob([string]$Path) {
  $sizeBytes = (Get-Item -LiteralPath $Path).Length
  if ($sizeBytes -eq 0) {
    throw "Firmware is zero bytes."
  }
  if (($sizeBytes % 4096) -ne 0) {
    throw "Firmware size $sizeBytes is not a multiple of 4 KiB; antimal::hv::Firmware will reject it."
  }
  if ($sizeBytes -gt (16 * 1024 * 1024)) {
    throw "Firmware ($sizeBytes bytes) exceeds antimal::hv::Firmware::kMaxFirmwareBytes (16 MiB)."
  }
  Write-Step "Size OK: $sizeBytes bytes."
}

function Install-FirmwareBlob([string]$SourcePath, [string]$DestinationPath, [string]$Metadata) {
  Test-FirmwareBlob $SourcePath

  $observed = Get-FileSha256 $SourcePath
  Write-Step "Firmware SHA-256: $observed"
  if ($PinHash -and $observed -ne $PinHash.ToUpperInvariant()) {
    throw "PinHash mismatch.`n  expected: $($PinHash.ToUpperInvariant())`n  observed: $observed`n  Refusing to install firmware we cannot verify."
  }

  New-Item -ItemType Directory -Force -Path $firmwareDir | Out-Null
  Copy-Item -Force -LiteralPath $SourcePath -Destination $DestinationPath
  Set-Content -Path ($DestinationPath + '.sha256') -Value $observed -Encoding ascii
  if ($Metadata) {
    Set-Content -Path ($DestinationPath + '.build.txt') -Value $Metadata -Encoding ascii
  }

  Write-Step "Installed: $DestinationPath"
  Write-Step "Hash file: $DestinationPath.sha256"
  if ($Metadata) {
    Write-Step "Build note: $DestinationPath.build.txt"
  }
}

function Invoke-PrebuiltInstall() {
  Write-Section 'AntiMal firmware install (prebuilt OVMF.fd from retrage edk2-nightly)'

  if (-not (Test-Path $firmwareDir)) {
    New-Item -ItemType Directory -Force -Path $firmwareDir | Out-Null
  }

  if (-not $Force -and (Test-Path $firmwareOut) -and (Test-Path $hashRecord)) {
    $existingHash = Get-FileSha256 $firmwareOut
    $recordedHash = (Get-Content $hashRecord -Raw).Trim().ToUpperInvariant()
    if ($existingHash -eq $recordedHash -and (-not $PinHash -or $existingHash -eq $PinHash.ToUpperInvariant())) {
      Write-Step "Existing firmware\OVMF.fd matches its recorded hash."
      Write-Step "  SHA-256: $existingHash"
      Write-Step "  (pass -Force to re-download.)"
      return
    }
    Write-Warn2 "Existing firmware\OVMF.fd does not match recorded hash; re-downloading."
  }

  $stagePath = Join-Path $firmwareDir 'OVMF.fd.partial'
  if (Test-Path $stagePath) {
    Remove-Item -Force $stagePath
  }
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
  }

  Test-FirmwareBlob $stagePath
  if (Test-Path $firmwareOut) {
    Remove-Item -Force $firmwareOut
  }
  Move-Item -Force $stagePath $firmwareOut
  Set-Content -Path $hashRecord -Value $observed -Encoding ascii
  Write-Step "Installed: $firmwareOut"
  Write-Step "Hash file: $hashRecord"
}

function Get-Edk2BuildCommand(
  [string]$VsPath,
  [string]$VsToolchain,
  [string]$PythonExe,
  [string]$NasmExe,
  [string]$IaslExe,
  [string[]]$Defines
) {
  $vsDevCmd = Join-Path $VsPath 'Common7\Tools\VsDevCmd.bat'
  if (-not (Test-Path -LiteralPath $vsDevCmd)) {
    throw "VsDevCmd.bat was not found under '$VsPath'."
  }

  $nasmDir = Split-Path -Parent $NasmExe
  $iaslDir = Split-Path -Parent $IaslExe
  $defineText = ($Defines | ForEach-Object { "-D $_" }) -join ' '

  return @"
call "$vsDevCmd" -arch=x86 -host_arch=x64
set "PYTHON_COMMAND=$PythonExe"
set "NASM_PREFIX=$nasmDir\"
set "IASL_PREFIX=$iaslDir\"
set "PATH=$nasmDir;$iaslDir;%PATH%"
cd /d "$edk2Dir"
call edksetup.bat Rebuild
build -p OvmfPkg\OvmfPkgX64.dsc -a X64 -t $VsToolchain -b $BuildTarget $defineText
"@
}

function Assert-CleanEdk2Tree() {
  if (-not (Test-Path -LiteralPath (Join-Path $edk2Dir '.git'))) {
    return
  }

  $dirty = & git.exe -C $edk2Dir status --porcelain
  if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect EDK2 git status."
  }
  if ($dirty) {
    throw "external\edk2 has local changes. Commit/stash/remove them before the firmware build so the script does not overwrite your work."
  }
}

function Invoke-SourceBuild() {
  Write-Section 'AntiMal firmware build (source OVMF with TPM2/Secure Boot)'

  $gitExe = Resolve-Tool 'git.exe' $null 'Install Git for Windows.'
  $pythonExe = Resolve-Tool 'python.exe' $PythonPath 'Install Python 3 or pass -PythonPath.'
  $nasmExeRaw = Resolve-Tool 'nasm.exe' $NasmPath 'Install NASM or pass -NasmPath.'
  $iaslExeRaw = Resolve-Tool 'iasl.exe' $IaslPath 'Install Intel ACPICA iASL or pass -IaslPath. Official binary tools are linked from https://www.intel.com/content/www/us/en/developer/topic-technology/open/acpica/download.html'
  $vsPath = Find-VsInstall
  $vsToolchain = Select-Toolchain $vsPath

  $nasmExe = Copy-ToolToFirmwareBin $nasmExeRaw
  $iaslExe = Copy-ToolToFirmwareBin $iaslExeRaw

  $defines = @()
  if ($EnableTpm2) {
    $defines += 'TPM2_ENABLE=TRUE'
  }
  if ($EnableSecureBoot) {
    $defines += 'SECURE_BOOT_ENABLE=TRUE'
  }
  if ($FdSize4Mb) {
    $defines += 'FD_SIZE_4MB=TRUE'
  }

  Write-Step "git:      $gitExe"
  Write-Step "python:   $pythonExe"
  Write-Step "nasm:     $nasmExe"
  Write-Step "iasl:     $iaslExe"
  Write-Step "VS:       $vsPath"
  Write-Step "toolchain:$vsToolchain"
  Write-Step "EDK2 ref: $Edk2Ref"
  Write-Step "defines:  $(if ($defines.Count) { $defines -join ', ' } else { '(none)' })"

  $buildScript = Get-Edk2BuildCommand $vsPath $vsToolchain $pythonExe $nasmExe $iaslExe $defines
  if ($CheckOnly) {
    Write-Section 'CheckOnly build command'
    Write-Host $buildScript
    return
  }

  New-Item -ItemType Directory -Force -Path $externalDir | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $edk2Dir '.git'))) {
    if (Test-Path -LiteralPath $edk2Dir) {
      throw "external\edk2 exists but is not a git checkout. Move it aside or remove it before building firmware."
    }
    Invoke-Native $gitExe @('-c', 'core.longpaths=true', 'clone', $Edk2Url, $edk2Dir) $repoRoot
  } else {
    Assert-CleanEdk2Tree
    Invoke-Native $gitExe @('-C', $edk2Dir, 'fetch', '--tags', '--force') $repoRoot
  }

  Invoke-Native $gitExe @('-C', $edk2Dir, 'config', 'core.longpaths', 'true') $repoRoot
  Invoke-Native $gitExe @('-C', $edk2Dir, 'checkout', $Edk2Ref) $repoRoot

  if (-not $SkipSubmoduleUpdate) {
    Invoke-Native $gitExe @('-C', $edk2Dir, '-c', 'core.longpaths=true', 'submodule', 'update', '--init', '--recursive') $repoRoot
    Invoke-Native $gitExe @('-C', $edk2Dir, 'submodule', 'foreach', '--recursive', 'git config core.longpaths true') $repoRoot
  } else {
    Write-Warn2 'Skipping EDK2 submodule update because -SkipSubmoduleUpdate was supplied.'
  }

  $cmdPath = Join-Path $externalDir 'firmware-tools\build-ovmf.cmd'
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $cmdPath) | Out-Null
  Set-Content -Path $cmdPath -Value $buildScript -Encoding ascii
  Write-Step "Build script: $cmdPath"

  Invoke-Native 'cmd.exe' @('/d', '/c', $cmdPath) $repoRoot

  $buildLeaf = "${BuildTarget}_${vsToolchain}"
  $candidates = @(
    (Join-Path $edk2Dir "Build\OvmfX64\$buildLeaf\FV\OVMF.fd"),
    (Join-Path $edk2Dir "Build\OvmfX64\$buildLeaf\FV\OVMF_CODE.fd")
  )
  $built = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $built) {
    throw "EDK2 build completed but no OVMF.fd was found. Checked: $($candidates -join '; ')"
  }

  if (-not $OutputName) {
    $OutputName = 'OVMF-tpm2.fd'
  }
  $dest = Join-Path $firmwareDir $OutputName

  $gitCommit = (& $gitExe -C $edk2Dir rev-parse HEAD).Trim()
  $metadata = @(
    "source=$Edk2Url",
    "ref=$Edk2Ref",
    "commit=$gitCommit",
    "target=$BuildTarget",
    "toolchain=$vsToolchain",
    "defines=$($defines -join ' ')",
    "built=$((Get-Date).ToString('u'))",
    "sourceArtifact=$built"
  ) -join [Environment]::NewLine

  Install-FirmwareBlob $built $dest $metadata

  if ($InstallAsDefault) {
    Copy-Item -Force -LiteralPath $dest -Destination $firmwareOut
    Copy-Item -Force -LiteralPath ($dest + '.sha256') -Destination $hashRecord
    Copy-Item -Force -LiteralPath ($dest + '.build.txt') -Destination ($firmwareOut + '.build.txt')
    Write-Step "Also installed as default: $firmwareOut"
  } else {
    Write-Step "To test this build without replacing OVMF.fd:"
    Write-Step "  `$env:ANTIMAL_FIRMWARE_NAME='$OutputName'"
  }
}

try {
  if ($FromSource) {
    Invoke-SourceBuild
  } else {
    Invoke-PrebuiltInstall
  }

  Write-Section 'Done'
  Write-Step "Next: msbuild AntiMal.sln /p:Configuration=Release /p:Platform=x64"
  Write-Step "Then: bin\x64\Release\AntiMal.Tests.exe"
  exit 0
}
catch {
  Write-Fail $_.Exception.Message
  if ($_.ScriptStackTrace) {
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
  }
  exit 1
}
