# Validate-UnattendBase.ps1 — boot-validate a -Unattend base.
#
# Unlike Measure-DesktopReach (which drives the fragile typed OOBE script via
# ANTIMAL_PROBE_OOBE_KEYS), an -Unattend base bakes a Win11 oobeSystem answer file
# (autologon 'antimal' + Hide* OOBE screens), so it completes OOBE DETERMINISTICALLY
# with NO typed input. This validator therefore runs cold boots with OOBE_KEYS=null
# and checks for BOTH a rendered desktop (maxKB>=1000) AND live agent telemetry
# (com2DataWrites>0 / hostChannelBytes>0 / process.* events) over COM2.
#
#   powershell -ExecutionPolicy Bypass -File tools\Validate-UnattendBase.ps1 -Boots 1 -TimeoutSec 900
#   ... then, once it reaches DESKTOP+AGENT: re-run with -KeepConfig to switch the default base.
param(
  [string]$BaseDir = "C:\AntiMalRuns\_baseu",
  [int]$Boots = 1,
  [int]$TimeoutSec = 900,
  [switch]$KeepConfig   # leave config pointing at the new base (the actual switch); default restores
)
$ErrorActionPreference = "Stop"
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
$cfg = "config\antimal.toml"
$vhdx = Join-Path $BaseDir "AntiMalBase.vhdx"
if (-not (Test-Path $vhdx)) { throw "new base not found: $vhdx" }
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# Point the config at the new base (both vhdx + raw lines); back up the previous.
Copy-Item $cfg "$cfg.prevbase" -Force
$vhdxFwd = ($vhdx -replace '\\','/')
$rawFwd  = ((Join-Path $BaseDir "AntiMalBase.raw") -replace '\\','/')
$out = foreach ($ln in (Get-Content $cfg)) {
  if     ($ln -match '^base_vhdx_path\s*=') { 'base_vhdx_path = "' + $vhdxFwd + '"' }
  elseif ($ln -match '^base_disk_path\s*=') { 'base_disk_path = "' + $rawFwd + '"' }
  else   { $ln }
}
# BOM-less UTF-8: Set-Content -Encoding UTF8 (PS 5.1) writes a BOM that the C++ TOML
# parser does not strip, which makes base_vhdx_path on line 1 silently unparseable.
[System.IO.File]::WriteAllLines((Resolve-Path $cfg).Path, $out, (New-Object System.Text.UTF8Encoding $false))
Write-Host ("config base_vhdx_path -> {0}" -f $vhdxFwd)

# REAL detonation config (matches Measure-DesktopReach) MINUS OOBE_KEYS: the baked
# unattend completes OOBE deterministically, so no typed script is injected.
$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG=$null; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG=$null
$env:ANTIMAL_KD_PIPE=$null; $env:ANTIMAL_KD_DUMP=$null; $env:ANTIMAL_KD_BREAKIN_AT=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null
$env:ANTIMAL_SEED_OVERLAY=$null
$env:ANTIMAL_PROBE_OOBE_KEYS=$null              # deterministic unattend, NOT typed script
$env:ANTIMAL_PROBE_PRESS_ENTER_SEC="30"         # dismiss any stray initial screen (autologon = no password)
$env:ANTIMAL_PROBE_LOGIN_PASSWORD=$null

function Field([string[]]$c,[string]$k){ $m=$c|Select-String -Pattern ("^"+[regex]::Escape($k)+":")|Select-Object -Last 1; if($m){($m.Line -replace ("^"+[regex]::Escape($k)+":\s*"),"").Trim()}else{""} }
function AsInt($s){ $n=0L; if([int64]::TryParse(($s -replace '[^0-9]',''),[ref]$n)){$n}else{0L} }

$rows=@()
for ($i=1; $i -le $Boots; $i++) {
  Write-Host ("=== unattend-base boot {0}/{1} (timeout {2}s) ===" -f $i,$Boots,$TimeoutSec)
  $vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden
  if (-not $vm.WaitForExit(($TimeoutSec+90)*1000)) { try { $vm.Kill() } catch {} }
  Start-Sleep 2
  $run = Get-ChildItem $ws -Directory | Where-Object { $_.Name -match '^[0-9a-f]{8}-' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $diag = Join-Path $run.FullName "vm-diagnostics.txt"
  $evp  = Join-Path $run.FullName "events.jsonl"
  $shots= Join-Path $run.FullName "screenshots"
  if (-not (Test-Path $diag)) { Write-Host "  no vm-diagnostics for $($run.Name)"; continue }
  $c = Get-Content $diag
  $frameCount=0; $maxFrameKB=0
  if (Test-Path $shots){ $pngs=Get-ChildItem $shots -Filter "guest-*.png" -ErrorAction SilentlyContinue; $frameCount=($pngs|Measure-Object).Count; if($frameCount -gt 0){$maxFrameKB=[int](($pngs|Measure-Object Length -Maximum).Maximum/1024)} }
  $agentConnected=$false; $procEvents=0
  $com2Writes = AsInt (Field $c "com2DataWrites")
  $hostChannelBytes = AsInt (Field $c "hostChannelBytes")
  if (Test-Path $evp){ $ev=Get-Content $evp; if($ev|Select-String '"guestAgentConnected"\s*:\s*"?true' -Quiet){$agentConnected=$true}; $procEvents=($ev|Select-String '"process\.(start|stop|running)"').Count }
  $stage="early"
  if     ($agentConnected -or $hostChannelBytes -gt 0 -or $procEvents -gt 0 -or $com2Writes -gt 0){ $stage="DESKTOP+AGENT" }
  elseif ($maxFrameKB -ge 1000){ $stage="desktop(no-agent)" }
  elseif ($maxFrameKB -ge 500){ $stage="user-mode/preparing" }
  $rows += [PSCustomObject]@{ boot=$i; run=$run.Name.Substring(0,8); stage=$stage; frames=$frameCount; maxKB=$maxFrameKB; com2W=$com2Writes; hostCh=$hostChannelBytes; procEv=$procEvents; reboots=(Field $c "guestReboots"); timedOut=(Field $c "timedOut"); pfExitsDisabled=(Field $c "pageFaultExitsDisabled") }
  $rows[-1] | Format-List | Out-String | Write-Host
}
Write-Host "`n===== UNATTEND-BASE VALIDATION ====="
$rows | Format-Table boot,run,stage,reboots,frames,maxKB,com2W,hostCh,procEv,timedOut -AutoSize | Out-String | Write-Host
$ok = ($rows | Where-Object { $_.stage -eq "DESKTOP+AGENT" }).Count
$desk = ($rows | Where-Object { $_.maxKB -ge 1000 }).Count
Write-Host ("DESKTOP+AGENT (telemetry streamed): {0}/{1}" -f $ok, $rows.Count)
Write-Host ("rendered desktop (maxKB>=1000):     {0}/{1}" -f $desk, $rows.Count)

if (-not $KeepConfig) { Copy-Item "$cfg.prevbase" $cfg -Force; Write-Host "config RESTORED to previous base (pass -KeepConfig to switch the default)" }
else { Write-Host "config KEPT pointing at the new base (default switched)" }
