# Analyze-KdBugcheck.ps1 — Phase 2 diagnostic: boot the in-house VM under kd and,
# when the guest bugchecks (the kd-debug cold boot reaches specialize and faults
# in MEMORY MANAGEMENT: 0x4E PFN_LIST_CORRUPT / 0x1A MEMORY_MANAGEMENT), capture a
# full bugcheck analysis so we can decide REAL VMM memory bug vs kd-debug artifact.
#
# No -bonc: we WANT the boot to proceed and bugcheck; kd breaks at the bugcheck
# (DbgBreakPoint) and the -c script runs there.
#
#   powershell -ExecutionPolicy Bypass -File tools\Analyze-KdBugcheck.ps1 -TimeoutSec 360
param(
  [int]$TimeoutSec = 360,
  [string]$KdLog = "C:\AntiMalRuns\_kdbugcheck.log",
  [string]$Conn  = "com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect"
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# kd script runs at the bugcheck break. Capture code+args, full analysis, the
# current + all-thread stacks, and a VM/pool summary (memory-pressure signal).
# kd script runs at the bugcheck break (kd auto-breaks at the post-bugcheck
# DbgBreakPoint). It only fires if THIS boot bugchecks -- intermittent (~50%);
# retry until one is caught. (-bonc does NOT force a break on this target, so a
# clean boot never runs the script; only a bugcheck creates the break.)
$script = Join-Path $ws "_kdbugcheck.script"
Set-Content -Path $script -Encoding ascii -Value @(
  '.echo ===ANTIMAL_BUGCHECK_BEGIN===',
  '.bugcheck',
  '.echo ===BUGCHECK_CODE_DONE===',
  '!analyze -v',
  '.echo ===ANALYZE_DONE===',
  'kb',
  '.echo ===KB_DONE===',
  '~*kb',
  '.echo ===STACKS_DONE===',
  '!vm 1',
  '.echo ===VM_DONE===',
  '.echo ===ANTIMAL_BUGCHECK_END===',
  'q'
)

# Minimal-variable env: OVMF-debug, 1 vCPU, CI off, winload+kernel KD debug, bridge.
# NO seed, NO OOBE keys, NO autologon -- same config that reproduced the bugcheck.
$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"; $env:ANTIMAL_KD_DUMP="1"
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null; $env:ANTIMAL_PROBE_LOGIN_PASSWORD=$null
$env:ANTIMAL_KD_BREAKIN_AT=$null

$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

$attached = $false
for ($t=0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    $bat = Join-Path $ws "_kdbugcheck.bat"
    Set-Content -Path $bat -Encoding ascii -Value @(
      '@echo off',
      ('"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k ' + $Conn + ' -c "$$<' + $script + '" -logo ' + $KdLog))
    Start-Process -FilePath "cmd.exe" -ArgumentList @('/c',$bat) -NoNewWindow
    Write-Host ("kd attached at ~{0}s; waiting for guest bugcheck..." -f $t)
    $attached = $true
    break
  }
  Start-Sleep -Milliseconds 500
}
if (-not $attached) { Write-Host "PIPE NEVER APPEARED" }

if (-not $vm.WaitForExit(($TimeoutSec + 60) * 1000)) { try { $vm.Kill() } catch {} }
Start-Sleep 2
Get-Process -Name kd -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n================= KD BUGCHECK LOG ($KdLog) ================="
if (Test-Path $KdLog) { Get-Content $KdLog } else { Write-Host "NO KD LOG" }

# Also surface the host-side fatal state (RIP/CS/bytes) for cross-check.
$run = Get-ChildItem C:\AntiMalRuns -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "`n================= host vm-diagnostics (fatal state) ================="
Write-Host ("run: " + $run.Name)
$diag = Join-Path $run.FullName "vm-diagnostics.txt"
if (Test-Path $diag) {
  Get-Content $diag | Select-String -Pattern "fatalRip|fatalCs|fatalRipImagePdb|fatalRipBytes|guestReboots|timedOut|processorCount|ahciReadCommands|ahciSectorsRead|kdPipeClientConnects|kdPipeBytes" | ForEach-Object { $_.Line }
}
