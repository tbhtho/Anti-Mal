# Verify-AssistFix.ps1 — statistical verification of the firmware-page-fault-assist
# gate fix (the 0x4E/0x1A MM-bugcheck + "Preparing Windows" root cause).
#
# Runs N minimal-variable boots (NO kd -- the bug is KD-independent; NO OOBE/seed)
# and tabulates the decisive counters from each run's vm-diagnostics:
#   pageFaultAssists            pre-fix: 148K-1.9M (assist firing DURING Windows).
#                               post-fix: small (firmware-phase only), then gated off.
#   pageFaultAssistsSuppressed  >0 proves Windows DID write-fault in the high-scratch
#                               aperture and the gate correctly re-injected it instead
#                               of corrupting Windows page tables.
#   guestReboots / fatalRip     how far the boot progressed.
#
#   powershell -ExecutionPolicy Bypass -File tools\Verify-AssistFix.ps1 -Boots 4 -TimeoutSec 320
param(
  [int]$Boots = 4,
  [int]$TimeoutSec = 420
)
$ws  = "C:\AntiMalRuns"
$bin = "bin\x64\Release"
Get-Process -Name AntiMal.HostCli,kd,KdDrive -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

# Same firmware/CI/BCD/VBS config as the failing runs, but NO kernel-debug + NO kd
# attach (isolates the firmware-assist variable) and NO OOBE/seed automation.
$env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS="1"; $env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT="1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF="1"; $env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT="1"
# Match the failing runs' kernel-debug config (this is what triggered the aperture
# faults) but use the in-house KD auto-ACK stub -- NO real kd attach (no stall, no
# perturbation). KD_PIPE unset => VirtualMachine uses the internal KdSerialDebugger.
$env:ANTIMAL_PROBE_WINLOAD_DEBUG="1"; $env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG="1"
$env:ANTIMAL_KD_PIPE=$null; $env:ANTIMAL_KD_DUMP=$null
$env:ANTIMAL_SEED_OVERLAY=$null; $env:ANTIMAL_PROBE_OOBE_KEYS=$null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON=$null; $env:ANTIMAL_PROBE_LOGIN_PASSWORD=$null
$env:ANTIMAL_KD_BREAKIN_AT=$null

function Field([string[]]$c, [string]$k) {
  # The summary is written by two diagnostic writers, so the same key can appear
  # twice; take the last (they agree). Return a scalar string.
  $m = $c | Select-String -Pattern ("^" + [regex]::Escape($k) + ":") | Select-Object -Last 1
  if ($m) { return ($m.Line -replace ("^" + [regex]::Escape($k) + ":\s*"), "").Trim() } else { return "" }
}
function AsInt($s) { $n = 0L; if ([int64]::TryParse(($s -replace '[^0-9]',''), [ref]$n)) { return $n } else { return 0L } }

$rows = @()
for ($i = 1; $i -le $Boots; $i++) {
  Write-Host ("=== boot {0}/{1} (timeout {2}s) ===" -f $i, $Boots, $TimeoutSec)
  $vm = Start-Process "$bin\AntiMal.HostCli.exe" -ArgumentList @("detonate","$bin\AntiMal.Tests.exe","--network","disabled","--timeout-sec","$TimeoutSec") -PassThru -WindowStyle Hidden
  if (-not $vm.WaitForExit(($TimeoutSec + 60) * 1000)) { try { $vm.Kill() } catch {} }
  Start-Sleep 2
  $run = Get-ChildItem $ws -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $d = Join-Path $run.FullName "vm-diagnostics.txt"
  if (-not (Test-Path $d)) { Write-Host "  no vm-diagnostics"; continue }
  $c = Get-Content $d
  $rows += [PSCustomObject]@{
    boot         = $i
    run          = $run.Name.Substring(0,8)
    pfAssists    = (Field $c "pageFaultAssists")
    pfSuppressed = (Field $c "pageFaultAssistsSuppressed")
    reboots      = (Field $c "guestReboots")
    timedOut     = (Field $c "timedOut")
    fatalPdb     = (Field $c "fatalRipImagePdb")
    fatalCs      = (Field $c "fatalCsSelector")
    fatalRip     = (Field $c "fatalRip")
  }
  $rows[-1] | Format-List | Out-String | Write-Host
}

Write-Host "`n================= SUMMARY ================="
$rows | Format-Table -AutoSize | Out-String | Write-Host
$assistedDuringOs = ($rows | Where-Object { (AsInt $_.pfAssists) -gt 50000 }).Count
$gateCaught       = ($rows | Where-Object { (AsInt $_.pfSuppressed) -gt 0 }).Count
Write-Host ("boots with >50K pageFaultAssists (assist firing during Windows = pre-fix symptom): {0}/{1}" -f $assistedDuringOs, $rows.Count)
Write-Host ("boots where the gate suppressed >=1 aperture fault (Windows faulted, gate held): {0}/{1}" -f $gateCaught, $rows.Count)
