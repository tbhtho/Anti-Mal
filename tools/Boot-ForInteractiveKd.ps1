# Boot-ForInteractiveKd.ps1 — boot the in-house VM ready for an INTERACTIVE kd
# session. Headless Ctrl+Break doesn't reach kd in a background context, but an
# interactive kd in a real terminal CAN break in (and kd's own read-retries are
# more patient than a scripted -c). This boots the VM and tells you exactly when
# and how to attach kd, then break in at the "Preparing Windows" first-logon hang
# to name the hung process/thread.
#
# USAGE:
#   1. Run this in one terminal:
#        powershell -ExecutionPolicy Bypass -File tools\Boot-ForInteractiveKd.ps1
#   2. The moment it prints "PIPE UP", run kd in a SECOND terminal (copy the
#      command it prints). Attach promptly so kd is present when the kernel inits
#      KD (~30-90s in).
#   3. Watch the VM frames in C:\AntiMalRuns\<runId>\screenshots\ (or just wait
#      ~4-6 min). When the screen sits on the "Preparing Windows" spinner, press
#      Ctrl+Break in the kd window, then run:
#        .reload /f
#        !process 0 0            (which processes exist / what's last)
#        !running -t             (the thread actually executing = the spinner)
#        !process -1 7           (full detail incl. stacks for the current process)
#        ~*kb                    (all thread stacks)
#      The hung user-mode process + its stack names the first-logon blocker.
param(
  [int]$TimeoutSec = 600
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
Get-Process -Name AntiMal.HostCli,kd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE="1"; $env:ANTIMAL_KD_DUMP=$null
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS="250"
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON="1"; $env:ANTIMAL_PROBE_LOGIN_PASSWORD="AntiMal!23"

$kdCmd = '"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k com:pipe,port=\\.\pipe\antimal-kd,resets=0,reconnect'

Write-Host "Booting in-house VM for interactive KD..."
$vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden

for ($t=0; $t -lt 60; $t++) {
  if (Test-Path "\\.\pipe\antimal-kd") {
    Write-Host ""
    Write-Host "==================== PIPE UP (attach kd NOW) ====================" -ForegroundColor Green
    Write-Host "In a SECOND terminal, first set the symbol path:"
    Write-Host '  set _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols'
    Write-Host "then run:"
    Write-Host "  $kdCmd"
    Write-Host ""
    Write-Host "When the VM screen sits on 'Preparing Windows', press Ctrl+Break in kd, then:"
    Write-Host "  .reload /f ; !process 0 0 ; !running -t ; ~*kb"
    Write-Host "=================================================================" -ForegroundColor Green
    break
  }
  Start-Sleep -Milliseconds 500
}
Write-Host ("VM pid=" + $vm.Id + " — frames in newest " + $ws + "\<runId>\screenshots\. Waiting up to " + ($TimeoutSec+40) + "s...")
if (-not $vm.WaitForExit(($TimeoutSec + 40) * 1000)) { try { $vm.Kill() } catch {} }
Write-Host "VM exited."
