# Attach-Kd.ps1 — boot the in-house VM and attach kd.exe the instant the KD
# named pipe appears (mimics VMware/Hyper-V "attach debugger before power-on",
# so kd and the guest both start fresh and align at INITIAL_PACKET_ID).
#
#   powershell -ExecutionPolicy Bypass -File tools\Attach-Kd.ps1 `
#       -ConnString "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect" `
#       -TimeoutSec 300 -Dump
param(
  [string]$ConnString = "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect",
  [int]$TimeoutSec = 300,
  [switch]$Dump,
  [string]$KdLog = "C:\AntiMalRuns\_kdA.log",
  [string]$KdCommand = "q",
  [int]$BreakinAt = 0
)

# Cache symbols locally so repeated runs don't re-download from the MS server.
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"

$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
Get-Process -Name AntiMal.HostCli,kd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"
if ($Dump) { $env:ANTIMAL_KD_DUMP="1" } else { $env:ANTIMAL_KD_DUMP=$null }
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS="250"
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON="1"; $env:ANTIMAL_PROBE_LOGIN_PASSWORD="AntiMal!23"
if ($BreakinAt -gt 0) { $env:ANTIMAL_KD_BREAKIN_AT="$BreakinAt" } else { $env:ANTIMAL_KD_BREAKIN_AT=$null }

$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

# Poll for the pipe and attach kd the instant it exists.
$kd = $null
for ($t = 0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    $bat = Join-Path $ws "_kdA.bat"
    Set-Content -Path $bat -Encoding ascii -Value @(
      '@echo off',
      ('"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k ' + $ConnString + ' -c "' + $KdCommand + '" -logo ' + $KdLog))
    $kd = Start-Process -FilePath "cmd.exe" -ArgumentList @('/c',$bat) -PassThru -NoNewWindow
    Write-Host ("kd attached at ~{0}s after VM start (pipe appeared)" -f $t)
    break
  }
  Start-Sleep -Milliseconds 500
}
if (-not $kd) { Write-Host "PIPE NEVER APPEARED" }

if (-not $vm.WaitForExit(($TimeoutSec + 40) * 1000)) { try { $vm.Kill() } catch {} }
Start-Sleep 3
Get-Process -Name kd -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "=== dump sizes ==="
foreach ($f in @("$ws\_kddump_to_dbg.bin","$ws\_kddump_from_dbg.bin")) {
  if (Test-Path $f) { Write-Host ($f + " = " + (Get-Item $f).Length + " bytes") } else { Write-Host ($f + " MISSING") }
}
