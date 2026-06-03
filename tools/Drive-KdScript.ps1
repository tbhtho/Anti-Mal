# Drive-KdScript.ps1 — boot the in-house VM and attach kd running a SCRIPT FILE
# (kd -c "$$><file"). The script sets an auto-logging breakpoint on process
# creation + continues, so kd logs the first-logon process timeline with NO
# Ctrl+Break and NO stdin driving (robust headlessly). The point where new
# processes stop appearing names where the boot stalls.
#
#   powershell -ExecutionPolicy Bypass -File tools\Drive-KdScript.ps1 -TimeoutSec 520
param(
  [int]$TimeoutSec = 520,
  [string]$KdLog = "C:\AntiMalRuns\_kdscript.log",
  [string]$Conn  = "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect"
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# kd script: load nt symbols, log every process creation (name+pid) then continue,
# also log thread-into-new-process. The bp command list ends in 'g' so the boot
# never stops — kd just narrates the process timeline into the log.
$script = Join-Path $ws "_kd.script"
Set-Content -Path $script -Encoding ascii -Value @(
  '.reload /f nt',
  '.echo ===SYMBOLS_LOADED===',
  '!process 0 0',
  '.echo ===INITIAL_PROCLIST_DONE===',
  'bp nt!PspInsertProcess "!process @rcx 0; g"',
  '.echo ===BP_SET===',
  'g'
)

$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"; $env:ANTIMAL_KD_DUMP=$null
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS="250"
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON="1"; $env:ANTIMAL_PROBE_LOGIN_PASSWORD="AntiMal!23"

$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

$attached = $false
for ($t=0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    $bat = Join-Path $ws "_kdscript.bat"
    Set-Content -Path $bat -Encoding ascii -Value @(
      '@echo off',
      ('"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k ' + $Conn + ' -c "$$<' + $script + '" -logo ' + $KdLog))
    Start-Process -FilePath "cmd.exe" -ArgumentList @('/c',$bat) -NoNewWindow
    Write-Host ("kd+script attached at ~{0}s" -f $t)
    $attached = $true
    break
  }
  Start-Sleep -Milliseconds 500
}
if (-not $attached) { Write-Host "PIPE NEVER APPEARED" }

if (-not $vm.WaitForExit(($TimeoutSec + 60) * 1000)) { try { $vm.Kill() } catch {} }
Start-Sleep 2
Get-Process -Name kd -ErrorAction SilentlyContinue | Stop-Process -Force
$sz = 0; if (Test-Path $KdLog) { $sz = (Get-Item $KdLog).Length }
Write-Host ("=== {0} ({1} bytes) ===" -f $KdLog, $sz)