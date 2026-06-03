# Drive-KdHang.ps1 — boot the in-house VM and use KdDrive.exe to break into the
# RUNNING guest at timed intervals, dumping !running/!process so we can NAME the
# first-logon ("Preparing Windows") hang (a hang = no auto-break, so KdDrive
# sends Ctrl+Break itself).
#
#   powershell -ExecutionPolicy Bypass -File tools\Drive-KdHang.ps1 `
#       -Delays "150,250,350,430" -TimeoutSec 480 `
#       -Dump ".reload /f; !running -t; !process 0 0; .time"
param(
  [string]$Delays = "150,250,350,430",
  [int]$TimeoutSec = 480,
  [string]$Dump = ".reload /f; !running -t; !process 0 0; .time",
  [string]$KdLog = "C:\AntiMalRuns\_kdhang.log",
  [string]$Conn = "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect"
)

$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"; $env:ANTIMAL_KD_DUMP=$null
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS="250"
# autologon + login path (reaches "Preparing Windows" first-logon hang per memory)
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON="1"; $env:ANTIMAL_PROBE_LOGIN_PASSWORD="AntiMal!23"

$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

# Wait for the KD pipe, then hand kd to KdDrive (own process group for Ctrl+Break).
$attached = $false
for ($t=0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    Write-Host ("pipe up at ~{0}s; launching KdDrive (delays={1})" -f $t, $Delays)
    & "tools\KdDrive.exe" $Conn $KdLog $Delays $Dump
    $attached = $true
    break
  }
  Start-Sleep -Milliseconds 500
}
if (-not $attached) { Write-Host "PIPE NEVER APPEARED" }

if (-not $vm.WaitForExit(($TimeoutSec + 60) * 1000)) { try { $vm.Kill() } catch {} }
Start-Sleep 2
Get-Process -Name kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host ("=== KdDrive log: {0} ===" -f $KdLog)
if (Test-Path $KdLog) { Write-Host ("(" + (Get-Item $KdLog).Length + " bytes)") }