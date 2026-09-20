[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be fresh.' }
$root = [IO.Path]::GetFullPath($EvidenceDirectory)
$source = Join-Path $root 'source'
[IO.Directory]::CreateDirectory((Join-Path $source 'resources/empty')) | Out-Null
[IO.File]::WriteAllText((Join-Path $source 'Set-up.exe'), 'Synthetic bytes; never executed')
$builder = Join-Path $PSScriptRoot 'New-InvestigationPackage.ps1'
$results = [Collections.Generic.List[object]]::new()
function MustReject([string]$Name, [scriptblock]$Action) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  if (-not $rejected) { throw "Expected rejection: $Name" }
  $results.Add(@{ check = $Name; passed = $true })
}
MustReject 'byte quota' { & $builder -Source $source -OutputDirectory (Join-Path $root 'oversize') -MaxBytes 1 }
MustReject 'nested output' { & $builder -Source $source -OutputDirectory (Join-Path $source 'output') }
$junction = Join-Path $root 'junction'
New-Item -ItemType Junction -Path $junction -Target $source | Out-Null
MustReject 'directory junction' { & $builder -Source $junction -OutputDirectory (Join-Path $root 'redirected') }
$good = Join-Path $root 'valid'
& $builder -Source $source -OutputDirectory $good | Out-Null
$manifest = Get-Content -LiteralPath (Join-Path $good 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.fileCount -ne 1 -or -not [IO.Directory]::Exists((Join-Path $good 'contents/resources/empty'))) { throw 'Empty directory or inventory lost.' }
$results.Add(@{ check = 'image and empty-directory preservation'; passed = $true })
MustReject 'existing evidence output' { & $builder -Source $source -OutputDirectory $good }
[IO.File]::WriteAllText((Join-Path $source 'install.exe'), 'Synthetic alternate entry')
MustReject 'ambiguous entry point' { & $builder -Source $source -EntryPoint install.exe -OutputDirectory (Join-Path $root 'ambiguous') }
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'results.json') -Encoding utf8
$results | ConvertTo-Json
