<#
.SYNOPSIS
  Builds the benign detonation probe (samples\probe\antimal_probe.cpp) into
  bin\x64\Release\AntiMal.SampleProbe.exe.

.DESCRIPTION
  The probe is a self-contained Win32 program used to validate the in-guest
  sample-execution path with a known-harmless binary (see the private development documentation).
  It is built /MT (static CRT) so it runs on a clean Windows guest with no VC++
  redistributable, and is intentionally NOT part of AntiMal.sln (it must never
  link the analysis code; it is a *sample*, not a project artifact).

.NOTES
  Reproducible: locates vcvars64.bat via vswhere, then invokes cl.exe through a
  generated batch file (keeps quoting sane across PowerShell -> cmd -> cl).
#>
[CmdletBinding()]
param(
  [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root "samples\probe\antimal_probe.cpp"
$outDir = Join-Path $root "bin\x64\$Configuration"
$objDir = Join-Path $root "obj\SampleProbe\x64\$Configuration"
$exe = Join-Path $outDir "AntiMal.SampleProbe.exe"

if (-not (Test-Path $src)) { throw "probe source not found: $src" }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found at $vswhere" }
$install = & $vswhere -latest -products * `
  -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath
if (-not $install) { throw "no VS install with the C++ x64 toolset was found" }
$vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

# Generate a batch file so cmd.exe sees clean, fully-quoted arguments.
$batPath = Join-Path $objDir "build-probe.bat"
$bat = @"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /MT /W3 /std:c++17 /Fo"$objDir\\" /Fe"$exe" "$src" /link ws2_32.lib advapi32.lib
exit /b %errorlevel%
"@
Set-Content -Path $batPath -Value $bat -Encoding ASCII

& cmd.exe /c "`"$batPath`""
if ($LASTEXITCODE -ne 0) { throw "cl.exe build failed with exit code $LASTEXITCODE" }

if (-not (Test-Path $exe)) { throw "build reported success but $exe is missing" }
$fi = Get-Item $exe
Write-Host "Built $($fi.FullName)  ($($fi.Length) bytes)"
