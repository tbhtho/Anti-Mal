<# Checks independent fixture output against the preserved guest event stream. Never runs a sample. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Report,
  [Parameter(Mandatory)][string]$FixtureResults,
  [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
$reportData = Get-Content -Raw -LiteralPath $Report | ConvertFrom-Json
$resultsText = Get-Content -Raw -LiteralPath $FixtureResults
if ($resultsText -notmatch '(?m)^pid=(\d+)\r?$') { throw 'Missing fixture PID' }
$fixturePid = [uint32]$Matches[1]
$checks = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [bool]$Passed) {
  $checks.Add([pscustomobject]@{check=$Name; passed=$Passed})
}
Check 'fixture read completed' ($resultsText -match 'synthetic_read=1 bytes=45')
Check 'fixture HTTP failed DNS and completed' ($resultsText -match 'http_sent=0 error=12007' -and $resultsText -match 'complete=1')
Check 'VM offline and executed' ($reportData.dynamicSummary.sampleExecuted -and $reportData.dynamicSummary.completed -and $reportData.dynamicSummary.networkMode -eq 'disabled')
$events = @($reportData.events | Where-Object source -eq 'GuestETW')
Check 'independent kernel read event with fixture PID and path' (@($events | Where-Object { $_.action -eq 'file.read-attempt' -and $_.processId -eq $fixturePid -and $_.target -like '*\antimal-probe-sensitive\Login Data' -and $_.details.'data.IOSize' -eq '128' }).Count -gt 0)
Check 'independent attempted hostname with fixture PID' (@($events | Where-Object { $_.details.provider -eq 'Microsoft-Windows-DNS-Client' -and $_.processId -eq $fixturePid -and $_.target -eq 'antimal-webhook-probe.invalid' }).Count -gt 0)
Check 'sample root instance recorded' (@($reportData.events | Where-Object { $_.action -eq 'process.create' -and $_.processId -eq $fixturePid -and $_.details.startTime }).Count -eq 1)
if ($resultsText -match '(?m)^burst_reads=(\d+)\r?$') {
  $completedReads = [int]$Matches[1]
  $capturedReads = @($events | Where-Object { $_.action -eq 'file.read-attempt' -and $_.processId -eq $fixturePid -and $_.target -like '*\antimal-probe-sensitive\Login Data' -and $_.details.'data.IOSize' -eq '128' }).Count
  Check 'fixture completed 1024 synthetic burst reads' ($completedReads -eq 1024)
  Check 'every synthetic read captured including initial read' ($capturedReads -eq ($completedReads + 1))
}
if ($resultsText -match 'socket_connect=') {
  Check 'independent direct-IP attempt captured' (@($events | Where-Object { $_.details.provider -eq 'Microsoft-Windows-Winsock-AFD' -and $_.processId -eq $fixturePid -and $_.details.task -eq 'AfdConnectWithAddress' -and $_.details.'data.Address' -eq 'hex:020001bbc00002010000000000000000' }).Count -gt 0)
  Check 'ETW child PID and creation time preserved' (@($events | Where-Object { $_.category -eq 'process' -and $_.processId -eq $fixturePid -and $_.details.eventId -eq '1' -and $_.details.headerProcessId -ne [string]$fixturePid -and $_.details.startTime }).Count -eq 1)
}
foreach ($sensor in @('etw_dns','etw_sensitive_file','etw_process')) {
  $coverage = @($reportData.dynamicSummary.sensorCoverage | Where-Object sensor -eq $sensor)
  Check "$sensor enabled and loss counters zero" ($coverage.Count -eq 1 -and $coverage[0].supported -and $coverage[0].healthy -and $coverage[0].samples -gt 0 -and $coverage[0].dropped -eq 0)
}
Check 'finalization flush acknowledged' (@($reportData.events | Where-Object { $_.action -eq 'vm.storage.flush' -and $_.details.acknowledged -eq 'true' -and $_.details.outcome -eq 'complete' }).Count -gt 0)
$checks | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $Output
$failed = @($checks | Where-Object { -not $_.passed })
if ($failed.Count) { throw ('Guest evidence checks failed: ' + ($failed.check -join '; ')) }
Write-Host "Passed $($checks.Count) live evidence checks. This validates these fixture signals, not universal sensor coverage."
