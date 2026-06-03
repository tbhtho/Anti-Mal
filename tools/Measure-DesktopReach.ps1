# Measure-DesktopReach.ps1 — STEP 1 statistical desktop-reach measurement.
#
# Runs N cold boots in the REAL (non-debug) detonation config -- the CURRENT_STATE
# repro: OVMF-debug firmware (firmware serial only, NOT kernel-debug/kd, which perturbs
# timing), 1 vCPU, the compatibility shims our incomplete VMM needs (CI off, VBS compat,
# hypervisor-launch off, nointegritychecks, legacy context), and the paced OOBE automation
# (ANTIMAL_PROBE_OOBE_KEYS -> runs c:\antimal-oobe.cmd -> local admin + AutoLogon + reboot
# -> desktop). NO real kd attach, NO seed overlay (each boot is a fresh cold OOBE).
#
# For each boot it classifies the furthest stage reached and tabulates a success rate.
# The GOLD success signal is hostChannelBytes>0 / guestAgentConnected:true / process.*
# events -- the baked AntiMalGuestAgent Start=2 service streams over COM2 ONLY from the
# logged-in desktop (Windows OOBE defers auto-start services until OOBE completes), so it
# is hard proof of a rendered, logged-in desktop AND closes the 3b telemetry loop.
#
#   powershell -ExecutionPolicy Bypass -File tools\Measure-DesktopReach.ps1 -Boots 5 -TimeoutSec 1400
param(
  [int]$Boots = 5,
  [int]$TimeoutSec = 1400,
  [int]$OobeStartSec = 250
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# REAL detonation config (matches the private development documentation "How to reproduce"). NO kernel-debug.
$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_OOBE_KEYS="$OobeStartSec"
# Explicitly OFF: no kd, no seed, no login-password (cold OOBE creates the account itself).
$env:ANTIMAL_PROBE_WINLOAD_DEBUG=$null; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG=$null
$env:ANTIMAL_KD_PIPE=$null; $env:ANTIMAL_KD_DUMP=$null; $env:ANTIMAL_KD_BREAKIN_AT=$null
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_LOGIN_PASSWORD=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null

function Field([string[]]$c, [string]$k) {
  $m = $c | Select-String -Pattern ("^" + [regex]::Escape($k) + ":") | Select-Object -Last 1
  if ($m) { return ($m.Line -replace ("^" + [regex]::Escape($k) + ":\s*"), "").Trim() } else { return "" }
}
function AsInt($s) { $n = 0L; if ([int64]::TryParse(($s -replace '[^0-9]',''), [ref]$n)) { return $n } else { return 0L } }

$rows = @()
for ($i = 1; $i -le $Boots; $i++) {
  Write-Host ("=== desktop-reach boot {0}/{1} (timeout {2}s, oobe@{3}s) ===" -f $i, $Boots, $TimeoutSec, $OobeStartSec)
  $vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden
  if (-not $vm.WaitForExit(($TimeoutSec + 90) * 1000)) { try { $vm.Kill() } catch {} }
  Start-Sleep 2
  $run = Get-ChildItem $ws -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $diag = Join-Path $run.FullName "vm-diagnostics.txt"
  $evp  = Join-Path $run.FullName "events.jsonl"
  $shots = Join-Path $run.FullName "screenshots"
  if (-not (Test-Path $diag)) { Write-Host "  no vm-diagnostics for $($run.Name)"; continue }
  $c = Get-Content $diag

  # Frame evidence (a rendered desktop is a large late frame).
  $frameCount = 0; $maxFrameKB = 0
  if (Test-Path $shots) {
    $pngs = Get-ChildItem $shots -Filter "guest-*.png" -ErrorAction SilentlyContinue
    $frameCount = ($pngs | Measure-Object).Count
    if ($frameCount -gt 0) { $maxFrameKB = [int](($pngs | Measure-Object Length -Maximum).Maximum / 1024) }
  }

  # Telemetry / boot-stage evidence from the journal.
  $agentConnected = $false; $procEvents = 0; $bootStage = ""
  if (Test-Path $evp) {
    $ev = Get-Content $evp
    if ($ev | Select-String -Pattern '"guestAgentConnected"\s*:\s*"?true' -Quiet) { $agentConnected = $true }
    $procEvents = ($ev | Select-String -Pattern '"process\.(start|stop|running)"').Count
    $bs = $ev | Select-String -Pattern '"bootStage"\s*:\s*"([^"]+)"' | Select-Object -Last 1
    if ($bs -and $bs.Matches.Count -gt 0) { $bootStage = $bs.Matches[0].Groups[1].Value }
  }
  $hostChannelBytes = AsInt (Field $c "hostChannelBytes")

  # Classify furthest stage reached.
  $stage = "early"
  if     ($agentConnected -or $hostChannelBytes -gt 0 -or $procEvents -gt 0) { $stage = "DESKTOP+AGENT" }
  elseif ($bootStage -eq "logon-ui")                                         { $stage = "logon-ui" }
  elseif ($bootStage -eq "user-mode" -or $maxFrameKB -ge 500)               { $stage = "user-mode/preparing" }
  elseif ($bootStage -eq "kernel")                                           { $stage = "kernel" }
  elseif ($bootStage -ne "")                                                 { $stage = $bootStage }

  $rows += [PSCustomObject]@{
    boot=$i; run=$run.Name.Substring(0,8); stage=$stage; bootStage=$bootStage
    agent=$agentConnected; hostCh=$hostChannelBytes; procEv=$procEvents
    frames=$frameCount; maxKB=$maxFrameKB; reboots=(Field $c "guestReboots")
    timedOut=(Field $c "timedOut"); pfA=(Field $c "pageFaultAssists")
    pfS=(Field $c "pageFaultAssistsSuppressed"); fatalRip=(Field $c "fatalRip")
    fatalCs=(Field $c "fatalCsSelector"); fatalPdb=(Field $c "fatalRipImagePdb")
  }
  $rows[-1] | Format-List | Out-String | Write-Host
}

Write-Host "`n================= DESKTOP-REACH SUMMARY ================="
$rows | Format-Table boot,run,stage,reboots,frames,maxKB,hostCh,procEv,timedOut,fatalPdb -AutoSize | Out-String | Write-Host
$desktop = ($rows | Where-Object { $_.stage -eq "DESKTOP+AGENT" }).Count
$userPlus = ($rows | Where-Object { $_.stage -in @("DESKTOP+AGENT","logon-ui","user-mode/preparing") }).Count
Write-Host ("RENDERED-LOGGED-IN-DESKTOP (agent streamed): {0}/{1}" -f $desktop, $rows.Count)
Write-Host ("reached user-mode or beyond:                 {0}/{1}" -f $userPlus, $rows.Count)
Write-Host ("`nFor any DESKTOP+AGENT run, inspect screenshots\guest-*.png (largest) to visually confirm the desktop, and events.jsonl for process.* telemetry.")
