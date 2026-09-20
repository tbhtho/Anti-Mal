<# Runs native correctness tests with preserved logs, progress and a hard bound. #>
[CmdletBinding()]
param(
  [string]$Executable = (Join-Path $PSScriptRoot '../bin/x64/Release/AntiMal.Tests.exe'),
  [string]$Filter = '',
  [ValidateRange(1, 3600)][int]$TimeoutSeconds = 300,
  [string]$LogPrefix = (Join-Path $PSScriptRoot ('../logs/native-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$LogPrefix = [IO.Path]::GetFullPath($LogPrefix)
New-Item -ItemType Directory -Force -Path (Split-Path $LogPrefix -Parent) | Out-Null
$previousFilter = $env:ANTIMAL_TEST_FILTER
$clock = [Diagnostics.Stopwatch]::StartNew()
$process = $null
$exitCode = 1
$timedOut = $false
try {
  $env:ANTIMAL_TEST_FILTER = $Filter
  $process = Start-Process -FilePath $Executable -PassThru -WindowStyle Hidden `
    -WorkingDirectory (Split-Path $PSScriptRoot -Parent) `
    -RedirectStandardOutput "$LogPrefix.stdout.log" `
    -RedirectStandardError "$LogPrefix.stderr.log"
  Write-Host "Native tests PID=$($process.Id), filter='$Filter', timeout=${TimeoutSeconds}s"
  $nextProgress = 0
  while (-not $process.HasExited) {
    if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
      $timedOut = $true
      # Only this test process and its descendants; never match process names.
      & taskkill.exe /PID $process.Id /T /F | Out-Host
      $exitCode = 124
      break
    }
    if ($clock.Elapsed.TotalSeconds -ge $nextProgress) {
      $last = Get-Content -LiteralPath "$LogPrefix.stdout.log" -Tail 1 -ErrorAction SilentlyContinue
      Write-Host "[$([int]$clock.Elapsed.TotalSeconds)s] $last"
      $nextProgress += 15
    }
    Start-Sleep -Milliseconds 250
    $process.Refresh()
  }
  if (-not $timedOut) {
    $process.WaitForExit()
    $exitCode = $process.ExitCode
  }
  Get-Content -LiteralPath "$LogPrefix.stdout.log" -Tail 12 | Out-Host
  Get-Content -LiteralPath "$LogPrefix.stderr.log" -Tail 12 | Out-Host
  [ordered]@{
    executable = $Executable
    filter = $Filter
    pid = $process.Id
    exitCode = $exitCode
    timedOut = $timedOut
    elapsedSeconds = $clock.Elapsed.TotalSeconds
    stdout = "$LogPrefix.stdout.log"
    stderr = "$LogPrefix.stderr.log"
  } | ConvertTo-Json | Set-Content -LiteralPath "$LogPrefix.result.json"
} finally {
  $env:ANTIMAL_TEST_FILTER = $previousFilter
}
exit $exitCode
