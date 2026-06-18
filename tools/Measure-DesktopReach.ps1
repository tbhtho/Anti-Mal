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
  [int]$OobeStartSec = 250,
  # When set to an AntiMalDesktop.cow snapshot path, each boot SEEDS from it (fast-boot
  # straight to the desktop) instead of a cold OOBE. The snapshot was made from a desktop
  # with AutoAdminLogon, so a paced Enter dismisses any lock screen; no OOBE automation.
  [string]$SeedOverlay = "",
  # Optional login password for a seed whose account is password-protected (not needed for
  # an AutoAdminLogon snapshot).
  [string]$LoginPassword = "",
  # Interactive: set ANTIMAL_LIVE_INPUT so the run is treated as a live session and is NOT
  # auto-stopped after the agent healthcheck -- the VM stays alive through the 120-360s login
  # window, so login can actually run. WITHOUT this the VM stops before login and you only
  # measure "OS up at the lock screen", not the interactive desktop.
  [switch]$Interactive,
  # NoPassword: patch the overlay for AutoAdminLogon (built-in Administrator, blank password)
  # instead of typing a password -- the hands-free "no password" path.
  [switch]$NoPassword,
  # When set, also write a machine-readable JSON summary (run count, desktop/os-up
  # rates, per-stage histogram, per-boot details) to this path. Feed it to
  # Validate-DesktopReach.ps1 to gate a reliability SLA in CI/automation.
  [string]$Json = ""
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
# Explicitly OFF: no kd perturbation.
$env:ANTIMAL_PROBE_WINLOAD_DEBUG=$null; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG=$null
$env:ANTIMAL_KD_PIPE=$null; $env:ANTIMAL_KD_DUMP=$null; $env:ANTIMAL_KD_BREAKIN_AT=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null
$mode = "cold"
if ($SeedOverlay -ne "" -and (Test-Path $SeedOverlay)) {
  # SEED mode: fast-boot from the desktop snapshot. No cold OOBE; dismiss a possible lock
  # screen with paced Enter starting at 30s (the snapshot has AutoAdminLogon).
  $mode = "seed"
  $env:ANTIMAL_SEED_OVERLAY = $SeedOverlay
  $env:ANTIMAL_PROBE_OOBE_KEYS = $null
  $env:ANTIMAL_PROBE_PRESS_ENTER_SEC = "30"
  if ($NoPassword) {
    # No password typed: AutoAdminLogon (Administrator, blank pw) via the overlay patch.
    $env:ANTIMAL_PROBE_OOBE_AUTOLOGON = "1"
    $env:ANTIMAL_PROBE_LOGIN_PASSWORD = $null
    $mode = "seed/no-password"
  } else {
    $env:ANTIMAL_PROBE_OOBE_AUTOLOGON = $null
    if ($LoginPassword -ne "") { $env:ANTIMAL_PROBE_LOGIN_PASSWORD = $LoginPassword }
    else { $env:ANTIMAL_PROBE_LOGIN_PASSWORD = $null }
  }
} else {
  # COLD mode: paced OOBE automation creates the account + AutoAdminLogon + reboot.
  $env:ANTIMAL_SEED_OVERLAY = $null
  $env:ANTIMAL_PROBE_OOBE_KEYS = "$OobeStartSec"
  $env:ANTIMAL_PROBE_PRESS_ENTER_SEC = $null
  $env:ANTIMAL_PROBE_LOGIN_PASSWORD = $null
}
# Interactive keep-alive: a live-input file makes the run NOT auto-stop after the agent
# probe, so the VM stays alive through the 120-360s login window (login can actually run).
if ($Interactive) {
  $li = Join-Path $ws "_measure-live-input.bin"
  if (-not (Test-Path $li)) { New-Item -ItemType File $li | Out-Null }
  $env:ANTIMAL_LIVE_INPUT = $li
  $mode = "$mode/interactive"
} else {
  $env:ANTIMAL_LIVE_INPUT = $null
}
Write-Host ("mode: {0}  (seed={1})" -f $mode, $(if ($SeedOverlay -ne "") { $SeedOverlay } else { "<none>" }))

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

  # A session-0 agent streams telemetry from the LOCK SCREEN too, so telemetry alone is
  # NOT proof of an interactive desktop. A rendered desktop is a distinctly large frame
  # (~1.2 MB w/ wallpaper+icons) vs the ~745 KB lock screen -- use the frame size to tell
  # them apart. Threshold 1000 KB sits cleanly between the two observed sizes.
  $osUp = ($agentConnected -or $hostChannelBytes -gt 0 -or $procEvents -gt 0)
  $desktopRendered = ($maxFrameKB -ge 1000)

  # Classify furthest stage reached (DESKTOP = telemetry AND a rendered desktop frame).
  $stage = "early"
  if     ($osUp -and $desktopRendered)        { $stage = "DESKTOP" }
  elseif ($osUp)                              { $stage = "os-up/lockscreen" }
  elseif ($bootStage -eq "logon-ui")          { $stage = "logon-ui" }
  elseif ($bootStage -eq "user-mode" -or $maxFrameKB -ge 500) { $stage = "user-mode/preparing" }
  elseif ($bootStage -eq "kernel")            { $stage = "kernel" }
  elseif ($bootStage -ne "")                  { $stage = $bootStage }

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
$desktop = ($rows | Where-Object { $_.stage -eq "DESKTOP" }).Count
$osUpCount = ($rows | Where-Object { $_.stage -in @("DESKTOP","os-up/lockscreen") }).Count
Write-Host ("RENDERED INTERACTIVE DESKTOP (telemetry + >=1MB frame): {0}/{1}" -f $desktop, $rows.Count)
Write-Host ("OS up / agent streaming (desktop OR lock screen):       {0}/{1}" -f $osUpCount, $rows.Count)
if (-not $Interactive) {
  Write-Host ("`nNOTE: not -Interactive -> the VM is auto-stopped after the agent probe, BEFORE the 120-360s login window, so 'os-up/lockscreen' is expected. Re-run with -Interactive to measure the actual desktop-reach.")
}
Write-Host ("`nFor any DESKTOP run, inspect screenshots\guest-*.png (largest) to visually confirm the desktop, and events.jsonl for process.* telemetry.")

# Machine-readable summary for the SLA gate (Validate-DesktopReach.ps1).
if ($Json -ne "") {
  $total = [Math]::Max($rows.Count, 1)
  $byStage = @{}
  foreach ($r in $rows) { if ($byStage.ContainsKey($r.stage)) { $byStage[$r.stage]++ } else { $byStage[$r.stage] = 1 } }
  $summary = [PSCustomObject]@{
    schemaVersion    = 1
    mode             = $mode
    runs             = $rows.Count
    desktopReached   = $desktop
    osUp             = $osUpCount
    desktopReachRate = [Math]::Round(100.0 * $desktop / $total, 1)
    osUpRate         = [Math]::Round(100.0 * $osUpCount / $total, 1)
    interactive      = [bool]$Interactive
    byStage          = $byStage
    details          = $rows
  }
  $summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $Json -Encoding utf8
  Write-Host ("`nWrote desktop-reach JSON summary: {0}" -f $Json)
}
