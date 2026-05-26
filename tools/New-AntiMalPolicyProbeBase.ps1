param(
  [string]$BaseVhdxPath = "C:\AntiMalRuns\_base\AntiMalBase.vhdx",
  [string]$ScratchRoot = "C:\AntiMalRuns\_scratch\policy-off",
  [switch]$Aggressive,
  [switch]$Force,
  [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DocumentedPolicyFiles = @(
  "{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}.cip",
  "{8F9CB695-5D48-48D6-A329-7202B44607E3}.cip"
)

$AggressivePolicyFiles = @(
  "{0283AC0F-FFF1-49AE-ADA1-8A933130CAD6}.cip",
  "{0939ED82-BFD5-4D32-B58E-D31D3C49715A}.cip",
  "{60FD87F8-4593-44A0-91B0-2E0DA022F248}.cip",
  "{1283AC0F-FFF1-49AE-ADA1-8A933130CAD6}.cip",
  "{1678656C-05EF-481F-BC5B-EBD8C991502D}.cip",
  "{1939ED82-BFD5-4D32-B58E-D31D3C49715A}.cip",
  "{2678656C-05EF-481F-BC5B-EBD8C991502D}.cip",
  "{5DAC656C-21AD-4A02-AB49-649917162E70}.cip"
)

function Resolve-CleanPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "Path cannot be empty."
  }
  return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Get-FreeDriveLetter {
  for ($i = [int][char]'Z'; $i -ge [int][char]'D'; --$i) {
    $letter = [char]$i
    if (-not (Test-Path -LiteralPath "${letter}:\")) {
      return $letter
    }
  }
  throw "No free drive letter is available for temporary VHDX mounting."
}

function Add-TemporaryAccessPath {
  param([Parameter(Mandatory = $true)]$Partition)

  $existing = @($Partition.AccessPaths | Where-Object { $_ -match '^[A-Z]:\\$' } | Select-Object -First 1)
  if ($existing.Count -gt 0) {
    return [pscustomobject]@{
      Root = $existing[0]
      Added = $false
      DiskNumber = $Partition.DiskNumber
      PartitionNumber = $Partition.PartitionNumber
    }
  }

  $letter = Get-FreeDriveLetter
  $root = "${letter}:\"
  Add-PartitionAccessPath -DiskNumber $Partition.DiskNumber `
    -PartitionNumber $Partition.PartitionNumber -AccessPath $root | Out-Null
  return [pscustomobject]@{
    Root = $root
    Added = $true
    DiskNumber = $Partition.DiskNumber
    PartitionNumber = $Partition.PartitionNumber
  }
}

function Remove-PolicyFile {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$RelativePath,
    [Parameter(Mandatory = $true)][string]$Location
  )

  $path = Join-Path $Root $RelativePath
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    $item = Get-Item -LiteralPath $path -Force
    Remove-Item -LiteralPath $path -Force
    return [ordered]@{
      location = $Location
      path = $path
      status = "deleted"
      bytes = $item.Length
    }
  }

  return [ordered]@{
    location = $Location
    path = $path
    status = "missing"
    bytes = 0
  }
}

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$baseFull = Resolve-CleanPath $BaseVhdxPath
$scratchRootFull = Resolve-CleanPath $ScratchRoot
$scratchFull = Join-Path $scratchRootFull "AntiMalBase-policy-off.vhdx"
$manifestPath = Join-Path $scratchRootFull "policy-off-manifest.json"

if (-not (Test-Path -LiteralPath $baseFull -PathType Leaf)) {
  throw "Base VHDX does not exist: $baseFull"
}
if ([IO.Path]::GetExtension($baseFull) -ine ".vhdx") {
  throw "BaseVhdxPath must point to a .vhdx file: $baseFull"
}
if ($baseFull -ieq (Resolve-CleanPath $scratchFull)) {
  throw "Scratch VHDX path must not equal the clean base path."
}
if ((Resolve-CleanPath $baseFull).StartsWith((Resolve-CleanPath $scratchRootFull), [StringComparison]::OrdinalIgnoreCase)) {
  throw "ScratchRoot must not contain the clean base VHDX."
}

if ($ValidateOnly) {
  [pscustomobject]@{
    baseVhdxPath = $baseFull
    scratchVhdxPath = $scratchFull
    aggressive = [bool]$Aggressive
    validateOnly = $true
  } | ConvertTo-Json -Depth 4
  return
}

if (-not (Test-IsAdministrator)) {
  throw "This script must run from an elevated PowerShell session to mount and edit the scratch VHDX."
}

New-Item -ItemType Directory -Force -Path $scratchRootFull | Out-Null
if (Test-Path -LiteralPath $scratchFull) {
  if (-not $Force) {
    throw "Scratch VHDX already exists: $scratchFull. Pass -Force to rebuild it."
  }
  Remove-Item -LiteralPath $scratchFull -Force
}

Copy-Item -LiteralPath $baseFull -Destination $scratchFull -Force

$mounted = $false
$accessPaths = @()
$results = @()
$policyFiles = @($DocumentedPolicyFiles)
if ($Aggressive) {
  $policyFiles += $AggressivePolicyFiles
}

try {
  Mount-DiskImage -ImagePath $scratchFull -Access ReadWrite | Out-Null
  $mounted = $true
  Start-Sleep -Milliseconds 500
  $disk = Get-DiskImage -ImagePath $scratchFull | Get-Disk
  $partitions = @(Get-Partition -DiskNumber $disk.Number)

  $esp = $partitions | Where-Object {
    $_.GptType -ieq "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
  } | Select-Object -First 1
  if ($esp) {
    $mount = Add-TemporaryAccessPath $esp
    $accessPaths += $mount
    foreach ($policyFile in $policyFiles) {
      $relative = Join-Path "EFI\Microsoft\Boot\CiPolicies\Active" $policyFile
      $results += Remove-PolicyFile -Root $mount.Root -RelativePath $relative -Location "ESP"
    }
  } else {
    $results += [ordered]@{
      location = "ESP"
      path = "EFI\Microsoft\Boot\CiPolicies\Active"
      status = "esp-not-found"
      bytes = 0
    }
  }

  $windowsPartitions = @($partitions | Where-Object {
    $_.GptType -ieq "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}"
  })
  $windowsRootFound = $false
  foreach ($partition in $windowsPartitions) {
    $mount = Add-TemporaryAccessPath $partition
    $accessPaths += $mount
    if (-not (Test-Path -LiteralPath (Join-Path $mount.Root "Windows\System32\CodeIntegrity") -PathType Container)) {
      continue
    }
    $windowsRootFound = $true
    foreach ($policyFile in $policyFiles) {
      $relative = Join-Path "Windows\System32\CodeIntegrity\CiPolicies\Active" $policyFile
      $results += Remove-PolicyFile -Root $mount.Root -RelativePath $relative -Location "Windows"
    }
    break
  }
  if (-not $windowsRootFound) {
    $results += [ordered]@{
      location = "Windows"
      path = "Windows\System32\CodeIntegrity\CiPolicies\Active"
      status = "windows-root-not-found"
      bytes = 0
    }
  }
} finally {
  foreach ($mount in $accessPaths) {
    if ($mount.Added) {
      Remove-PartitionAccessPath -DiskNumber $mount.DiskNumber `
        -PartitionNumber $mount.PartitionNumber -AccessPath $mount.Root `
        -ErrorAction SilentlyContinue
    }
  }
  if ($mounted) {
    Dismount-DiskImage -ImagePath $scratchFull | Out-Null
  }
}

$manifest = [ordered]@{
  baseVhdxPath = $baseFull
  scratchVhdxPath = $scratchFull
  aggressive = [bool]$Aggressive
  documentedPolicyFiles = $DocumentedPolicyFiles
  aggressivePolicyFiles = if ($Aggressive) { $AggressivePolicyFiles } else { @() }
  results = $results
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Policy-off scratch base ready:"
Write-Host "  $scratchFull"
Write-Host "Set ANTIMAL_PROBE_POLICY_OFF_BASE=$scratchFull for HostCli detonate."
Write-Output "SCRATCH_VHDX=$scratchFull"
