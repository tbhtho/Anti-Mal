<#
.SYNOPSIS
  Promote a settled-desktop run overlay into the seed snapshot (AntiMalDesktop.cow).

.DESCRIPTION
  The live VM seed-boots by COPYING _base\AntiMalDesktop.cow into a per-run
  disk\overlay.cow (a differencing VHDX on the untouched base) and booting that
  copy (see HyperVOrchestrator.cpp ~10723). So after a run has reached a FULLY
  SETTLED, stable desktop and the VM is stopped, that run's overlay.cow is a
  self-contained image whose disk state has first-logon already complete.

  This script promotes it: it backs up the current AntiMalDesktop.cow (timestamped,
  and records the path in .last-desktop-backup.txt) and copies the chosen run's
  overlay.cow over AntiMalDesktop.cow. Future seed-boots then resume straight into
  the settled desktop -- fast AND stable -- instead of re-running first-logon.

  SAFETY: the base VHDX is never touched. The old snapshot is always backed up
  first, so this is fully reversible (see the printed revert command).

.PARAMETER RunId
  The run directory under WorkspaceRoot whose overlay.cow to promote. If omitted,
  the most recently modified run dir that contains disk\overlay.cow is used.

.PARAMETER WorkspaceRoot
  Defaults to C:\AntiMalRuns.

.PARAMETER AlsoAgentSnapshot
  Also overwrite AntiMalDesktop.agent.cow with the same image (so the agent-seed
  matches). Off by default -- prefer re-running `base deploy-agent` to bake the
  current GuestAgent into the new snapshot.

.PARAMETER Force
  Skip the interactive confirmation.

.EXAMPLE
  # After Boot VM (live) reached a settled desktop and you clicked Stop:
  powershell -ExecutionPolicy Bypass -File tools\Promote-DesktopSnapshot.ps1
#>
[CmdletBinding()]
param(
  [string]$RunId,
  [string]$WorkspaceRoot = 'C:\AntiMalRuns',
  [switch]$AlsoAgentSnapshot,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

$baseDir = Join-Path $WorkspaceRoot '_base'
$seed    = Join-Path $baseDir 'AntiMalDesktop.cow'
if (-not (Test-Path $baseDir)) { Fail "base dir not found: $baseDir" }

# --- Resolve the run + its overlay -----------------------------------------
if ($RunId) {
  $runDir = Join-Path $WorkspaceRoot $RunId
  if (-not (Test-Path $runDir)) { Fail "run dir not found: $runDir" }
  $overlay = Join-Path $runDir 'disk\overlay.cow'
  if (-not (Test-Path $overlay)) { Fail "no overlay.cow under $runDir\disk" }
} else {
  $cand = Get-ChildItem -Path $WorkspaceRoot -Directory |
    Where-Object { $_.Name -notmatch '^_' } |
    ForEach-Object { Join-Path $_.FullName 'disk\overlay.cow' } |
    Where-Object { Test-Path $_ } |
    Get-Item | Sort-Object LastWriteTime -Descending
  if (-not $cand) { Fail "no run with disk\overlay.cow found under $WorkspaceRoot" }
  $overlay = $cand[0].FullName
  $runDir  = Split-Path (Split-Path $overlay -Parent) -Parent
}

$overlayItem = Get-Item $overlay
$overlayGB = [math]::Round($overlayItem.Length / 1GB, 2)

# --- Sanity: did this run actually reach a desktop? -------------------------
# A settled-desktop live frame is large (lots of detail); a blank/lockscreen
# frame is small. This is a hint, not a hard gate -- you watched it settle.
$shots = Join-Path $runDir 'screenshots'
$lastFrameKB = $null
if (Test-Path $shots) {
  $f = Get-ChildItem (Join-Path $shots 'guest-*.png'), (Join-Path $shots 'live.png') -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($f) { $lastFrameKB = [math]::Round($f.Length / 1KB, 0) }
}

Write-Host ""
Write-Host "Promote desktop snapshot" -ForegroundColor Cyan
Write-Host "  run dir        : $runDir"
Write-Host "  overlay        : $overlay ($overlayGB GB, modified $($overlayItem.LastWriteTime))"
Write-Host "  -> promotes to : $seed"
if ($lastFrameKB -ne $null) {
  $hint = if ($lastFrameKB -ge 200) { 'looks desktop-sized (good)' } else { 'SMALL -- may be a blank/lock frame, NOT a settled desktop!' }
  $col  = if ($lastFrameKB -ge 200) { 'Green' } else { 'Yellow' }
  Write-Host "  last frame     : ${lastFrameKB} KB ($hint)" -ForegroundColor $col
}
Write-Host ""
Write-Host "IMPORTANT: the VM must be STOPPED (overlay.cow closed/flushed) and the" -ForegroundColor Yellow
Write-Host "guest should have reached a FULLY SETTLED desktop before promoting." -ForegroundColor Yellow

if (-not $Force) {
  $ans = Read-Host "Proceed? (y/N)"
  if ($ans -notin @('y','Y','yes')) { Write-Host 'Aborted.'; exit 0 }
}

# --- Back up the current seed (reversible) ----------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (Test-Path $seed) {
  $bak = "$seed.bak-$stamp"
  Copy-Item $seed $bak -Force
  Set-Content -Path (Join-Path $baseDir '.last-desktop-backup.txt') -Value $bak -Encoding utf8
  Write-Host "Backed up current snapshot -> $bak" -ForegroundColor Green
} else {
  Write-Host "(no existing AntiMalDesktop.cow to back up)" -ForegroundColor Yellow
}

# --- Promote ----------------------------------------------------------------
Copy-Item $overlay $seed -Force
Write-Host "Promoted overlay -> $seed" -ForegroundColor Green

if ($AlsoAgentSnapshot) {
  $agentSeed = Join-Path $baseDir 'AntiMalDesktop.agent.cow'
  if (Test-Path $agentSeed) { Copy-Item $agentSeed "$agentSeed.bak-$stamp" -Force }
  Copy-Item $overlay $agentSeed -Force
  Write-Host "Also promoted -> $agentSeed" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Next Boot VM (live) should resume into the settled desktop." -ForegroundColor Cyan
Write-Host "To bake the current GuestAgent into the new snapshot, run:" -ForegroundColor DarkGray
Write-Host "  bin\x64\Release\AntiMal.HostCli.exe base deploy-agent ..." -ForegroundColor DarkGray
Write-Host "Revert if needed:" -ForegroundColor DarkGray
if (Test-Path "$seed.bak-$stamp") {
  Write-Host "  Copy-Item '$seed.bak-$stamp' '$seed' -Force" -ForegroundColor DarkGray
}
