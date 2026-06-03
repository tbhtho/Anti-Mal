# Prove-KdReads.ps1 — Phase 1 diagnostic: does a kd MEMORY READ round-trip over the
# KdPipeBridge complete AT A HEALTHY BREAK, independent of any hang state?
#
# Minimal-variable design (isolate the bridge): boot only far enough to init KD +
# sync (NO OOBE/login/seed automation), let kd run a script at the INITIAL sync
# break, and attempt SYMBOL-INDEPENDENT reads FIRST (`r`, `dd nt`, `db nt`) which
# test the read round-trip with no PDB dependency, then `!process 0 0`. Capture the
# raw KD byte stream both directions (ANTIMAL_KD_DUMP) and decode it.
#
# Interpretation:
#   - dd/db print the MZ/PE bytes at nt  -> reads WORK at a healthy break
#       => the documented read failure is hang-specific, NOT a pure bridge bug.
#   - "Unable to read ..."                -> reads FAIL at a healthy break
#       => PURE BRIDGE problem (round-trip), independent of any hang. Clean proof.
#   - Decode: a `MANIP:ReadVirtMem` packet in _from_dbg (kd's request) with NO
#       matching response in _to_dbg => kernel never answered (timing/not-broken-in).
#       Request + response present but kd still errored => latency (kd timed out).
#
#   powershell -ExecutionPolicy Bypass -File tools\Prove-KdReads.ps1 -TimeoutSec 300
param(
  [int]$TimeoutSec = 300,
  [string]$KdLog = "C:\AntiMalRuns\_kdreadprobe.log",
  [string]$Conn  = "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect",
  [switch]$Bonc   # break-on-connect: forces a healthy break so the script runs
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# kd script: runs at the initial sync break. Symbol-independent reads FIRST (the
# decisive bridge round-trip probe), then symbol-dependent !process. Ends in 'q'.
$script = Join-Path $ws "_kdreadprobe.script"
Set-Content -Path $script -Encoding ascii -Value @(
  '.echo ===ANTIMAL_PROBE_BEGIN===',
  'r',
  '.echo ===R_DONE===',
  'dd nt L8',
  '.echo ===DD_NT_DONE===',
  'db nt L20',
  '.echo ===DB_NT_DONE===',
  '.reload /f nt',
  '.echo ===RELOAD_DONE===',
  '!process 0 0',
  '.echo ===PROCLIST_DONE===',
  'lm',
  '.echo ===LM_DONE===',
  '!thread',
  '.echo ===THREAD_DONE===',
  '~*kb',
  '.echo ===STACKS_DONE===',
  '.echo ===ANTIMAL_PROBE_END===',
  'q'
)

# Minimal-variable env: OVMF-debug, 1 vCPU, CI off, winload+kernel KD debug, bridge
# + DUMP. NO seed, NO OOBE keys, NO autologon, NO login password, NO timed break-in.
$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"; $env:ANTIMAL_KD_DUMP="1"
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null; $env:ANTIMAL_PROBE_LOGIN_PASSWORD=$null
$env:ANTIMAL_KD_BREAKIN_AT=$null

Remove-Item "$ws\_kddump_to_dbg.bin","$ws\_kddump_from_dbg.bin" -ErrorAction SilentlyContinue

$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

$attached = $false
for ($t=0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    $bat = Join-Path $ws "_kdreadprobe.bat"
    $boncArg = ""
    if ($Bonc) { $boncArg = "-bonc " }
    Set-Content -Path $bat -Encoding ascii -Value @(
      '@echo off',
      ('"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k ' + $Conn + ' ' + $boncArg + '-c "$$<' + $script + '" -logo ' + $KdLog))
    Start-Process -FilePath "cmd.exe" -ArgumentList @('/c',$bat) -NoNewWindow
    Write-Host ("kd+readprobe attached at ~{0}s after VM start" -f $t)
    $attached = $true
    break
  }
  Start-Sleep -Milliseconds 500
}
if (-not $attached) { Write-Host "PIPE NEVER APPEARED" }

if (-not $vm.WaitForExit(($TimeoutSec + 60) * 1000)) { try { $vm.Kill() } catch {} }
Start-Sleep 2
Get-Process -Name kd -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n================= KD LOG ($KdLog) ================="
if (Test-Path $KdLog) { Get-Content $KdLog } else { Write-Host "NO KD LOG" }

Write-Host "`n================= DUMP SIZES ================="
foreach ($f in @("$ws\_kddump_to_dbg.bin","$ws\_kddump_from_dbg.bin")) {
  if (Test-Path $f) { Write-Host ($f + " = " + (Get-Item $f).Length + " bytes") } else { Write-Host ($f + " MISSING") }
}
Write-Host "`n===== DECODE _from_dbg (kd -> guest : REQUESTS) ====="
& '.\tools\Decode-KdStream.ps1' -Path "$ws\_kddump_from_dbg.bin" -Max 80
Write-Host "`n===== DECODE _to_dbg (guest -> kd : RESPONSES) ====="
& '.\tools\Decode-KdStream.ps1' -Path "$ws\_kddump_to_dbg.bin" -Max 80
