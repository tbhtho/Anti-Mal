<# Starts the existing MCP/GUI interactive workflow; never executes the sample on the host. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Sample,
  [string]$McpServer = (Join-Path $PSScriptRoot '../bin/x64/Release/AntiMal.McpServer.exe'),
  [string]$EntryPoint = 'Set-up.exe',
  [string]$PackageWorkspace = (Join-Path $env:LOCALAPPDATA 'AntiMal/packages'),
  [ValidateRange(0, 2592000)][int]$TimeoutSeconds = 0
)
$ErrorActionPreference = 'Stop'
$samplePath = (Resolve-Path -LiteralPath $Sample).Path
$serverPath = (Resolve-Path -LiteralPath $McpServer).Path
if ([IO.Directory]::Exists($samplePath)) {
  $packageOutput = Join-Path $PackageWorkspace ([Guid]::NewGuid().ToString())
  & (Join-Path $PSScriptRoot 'New-InvestigationPackage.ps1') -Source $samplePath -OutputDirectory $packageOutput -EntryPoint $EntryPoint | Out-Host
  $samplePath = Join-Path $packageOutput 'package.iso'
}
if (-not [IO.File]::Exists($samplePath)) { throw 'The sample is not a readable file or supported package directory.' }
if ([IO.Path]::GetExtension($samplePath).ToLowerInvariant() -notin @('.exe','.iso')) {
  throw 'This interactive launcher currently supports EXE files and ISO packages. Select an explicit supported entry point.'
}
$request = @{
  jsonrpc = '2.0'; id = 1; method = 'tools/call'
  params = @{ name = 'vm_boot'; arguments = @{
    sample = $samplePath; view = $true; allow_execution = $true
    timeout_sec = $TimeoutSeconds
  }}
} | ConvertTo-Json -Depth 6 -Compress
$start = [Diagnostics.ProcessStartInfo]::new($serverPath)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.EnvironmentVariables["ANTIMAL_KEEP_OVERLAYS"] = "1"
$start.WorkingDirectory = Split-Path $PSScriptRoot -Parent
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
try {
  if (-not $process.Start()) { throw 'Could not start the MCP server.' }
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  $process.StandardInput.WriteLine($request)
  $process.StandardInput.Close()
  if (-not $process.WaitForExit(30000)) {
    throw "Boot response timed out. Inspect vmstatus before retrying; a VM may have started. MCP PID=$($process.Id)."
  }
  $response = ($stdout.Result -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) | ConvertFrom-Json
  if ($response.error) { throw ($response.error | ConvertTo-Json -Compress) }
  if (-not $response.result.content) { throw "No boot response: $($stderr.Result)" }
  $result = $response.result.content[0].text | ConvertFrom-Json
  if (-not $result.ok) { throw ($result | ConvertTo-Json -Compress) }
  $result | ConvertTo-Json -Depth 5
} finally {
  $process.Dispose()
}
