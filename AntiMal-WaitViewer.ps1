# AntiMal - viewer waiter.
# Polls the live session and opens the VM window only once the guest actually
# paints a frame (a viewer started earlier exits immediately, which looks like
# "nothing happened"). Launched hidden by AntiMal.ps1; args: <hostCli> <seconds>
param(
  [Parameter(Mandatory = $true)][string]$HostCli,
  [int]$TimeoutSec = 1200
)
$log = Join-Path (Split-Path (Split-Path $HostCli -Parent) -Parent) '_mcp\launcher.log'
function Log([string]$m) {
  try {
    $dir = Split-Path $log -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Add-Content -Path $log -Value ((Get-Date -Format s) + ' waiter: ' + $m)
  } catch { }
}
Log "watching $HostCli for up to ${TimeoutSec}s"
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
  try {
    $raw = & $HostCli vmstatus --json 2>$null | Out-String
    if ($raw) {
      $s = $raw | ConvertFrom-Json
      if ($s -and $s.framePresent) {
        Log 'frame present -> opening viewer'
        Start-Process -FilePath $HostCli -ArgumentList 'vmview' -WindowStyle Normal | Out-Null
        exit 0
      }
    }
  } catch { Log ('status error: ' + $_.Exception.Message) }
  Start-Sleep -Seconds 5
}
Log 'timed out waiting for frames'
exit 1
