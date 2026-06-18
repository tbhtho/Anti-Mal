# Validate-DesktopReach.ps1 — boot-reliability SLA gate (Criterion 7).
#
# Consumes the JSON written by `Measure-DesktopReach.ps1 -Json <path>` and
# returns a pass/fail verdict against a reliability SLA. The measurement itself
# (the live boots) is user-gated; THIS step is pure analysis, so it runs in CI or
# a script with zero live boots — it just grades the evidence the user collected.
#
#   powershell -ExecutionPolicy Bypass -File tools\Validate-DesktopReach.ps1 `
#     -Json reach.json -MinDesktopRate 90 -MinOsUpRate 95 -MinRuns 10
#
# Exit 0 = SLA met; exit 1 = SLA not met (or too few runs / unreadable input).
param(
  [Parameter(Mandatory = $true)][string]$Json,
  # Minimum % of runs that must reach a RENDERED desktop (telemetry + >=1MB frame).
  [double]$MinDesktopRate = 90,
  # Minimum % of runs that must at least reach OS-up (agent streaming / lock screen).
  [double]$MinOsUpRate = 95,
  # Minimum sample size for the rates to be meaningful.
  [int]$MinRuns = 10
)

if (-not (Test-Path $Json)) {
  Write-Host "FAIL: desktop-reach JSON not found: $Json"
  exit 1
}
try {
  $d = Get-Content $Json -Raw | ConvertFrom-Json
} catch {
  Write-Host "FAIL: could not parse $Json : $($_.Exception.Message)"
  exit 1
}

$runs = [int]$d.runs
$desktopRate = [double]$d.desktopReachRate
$osUpRate = [double]$d.osUpRate

Write-Host "Desktop-reach SLA validation ($Json)"
Write-Host ("  mode:          {0}" -f $d.mode)
Write-Host ("  runs:          {0}  (min {1})" -f $runs, $MinRuns)
Write-Host ("  desktop reach: {0}%  (min {1}%)  [{2}/{3}]" -f $desktopRate, $MinDesktopRate, $d.desktopReached, $runs)
Write-Host ("  os-up reach:   {0}%  (min {1}%)  [{2}/{3}]" -f $osUpRate, $MinOsUpRate, $d.osUp, $runs)
if ($d.byStage) {
  Write-Host "  by stage:"
  foreach ($p in $d.byStage.PSObject.Properties) {
    Write-Host ("    - {0}: {1}" -f $p.Name, $p.Value)
  }
}

$fail = @()
if ($runs -lt $MinRuns)          { $fail += "sample too small ($runs < $MinRuns runs)" }
if ($desktopRate -lt $MinDesktopRate) { $fail += "desktop reach $desktopRate% < $MinDesktopRate%" }
if ($osUpRate -lt $MinOsUpRate)  { $fail += "os-up reach $osUpRate% < $MinOsUpRate%" }

if ($fail.Count -eq 0) {
  Write-Host "`nSLA: PASS"
  exit 0
}
Write-Host "`nSLA: FAIL"
foreach ($f in $fail) { Write-Host "  - $f" }
Write-Host "  Review the failed boot and desktop-readiness checks before retrying."
exit 1
