<# Summarize captured runtime evidence only. No sample execution or static scan. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Report, [Parameter(Mandatory)][string]$Output)
$ErrorActionPreference = 'Stop'
$data = Get-Content -Raw -LiteralPath $Report | ConvertFrom-Json
$events = @($data.events | Where-Object source -eq 'GuestETW')
$dns = @($events | Where-Object { $_.details.provider -eq 'Microsoft-Windows-DNS-Client' -and $_.details.'data.QueryName' } | ForEach-Object {
  [pscustomobject]@{time=$_.timestampUtc; headerPid=$_.processId; clientPid=$_.details.'data.ClientPID'; name=$_.details.'data.QueryName'; status=$_.details.'data.Status'; queryStatus=$_.details.'data.QueryStatus'; eventId=$_.details.eventId}
})
$accesses = @($events | Where-Object { $_.category -eq 'file' -and $_.details.eventId -in @('12','15') } | Select-Object timestampUtc,action,processId,target,details)
$fileNames = @($events | Where-Object { $_.category -eq 'file' -and $_.details.eventId -notin @('12','15') } | Select-Object timestampUtc,action,processId,target,details)
$http = @($events | Where-Object { $_.category -eq 'network' -and $_.details.provider -ne 'Microsoft-Windows-DNS-Client' } | Select-Object timestampUtc,processId,target,details)
$summary = [ordered]@{
  runId=$data.runId
  scope='Captured machine-wide guest events; membership in this summary does not attribute an event to the sample. Request/lookup/open does not prove successful upload/read.'
  networkMode=$data.dynamicSummary.networkMode
  staticAnalysis=$data.scannerVerdict.staticAnalysisState
  dnsNames=@($dns.name | Sort-Object -Unique)
  dns=$dns
  selectedSensitivePathAccesses=$accesses
  fileNameMetadataOnly=$fileNames
  httpAndSocketEvents=$http
  etwCoverage=@($data.dynamicSummary.sensorCoverage | Where-Object sensor -like 'etw_*')
  errors=$data.errors
}
$summary | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $Output
Write-Host "Exported $($dns.Count) DNS records, $($accesses.Count) selected-file records and $($http.Count) HTTP/socket records."
