param(
  [string]$BaseVhdxPath = "C:\AntiMalRuns\_base\AntiMalBase.vhdx",
  [string]$GuestAgentPath = "",
  [switch]$RepairBcd
)

$ErrorActionPreference = "Stop"

function Get-FreeDriveLetter {
  $used = @{}
  Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    if ($_.Name.Length -eq 1) {
      $used[$_.Name.ToUpperInvariant()] = $true
    }
  }
  try {
    Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
      $used[([string]$_.DriveLetter).ToUpperInvariant()] = $true
    }
  } catch {
  }

  foreach ($letter in @("S", "W", "T", "U", "V", "X", "Y", "Z", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H", "G", "F", "E", "D")) {
    if (-not $used.ContainsKey($letter)) {
      return $letter
    }
  }
  throw "No free drive letter is available."
}

function Get-PartitionRoot($Partition, [System.Collections.Generic.List[string]]$AssignedLetters) {
  $volume = $null
  try {
    $volume = $Partition | Get-Volume -ErrorAction SilentlyContinue
  } catch {
  }

  if ($volume -and $volume.DriveLetter) {
    return "$($volume.DriveLetter):\"
  }

  $letter = Get-FreeDriveLetter
  Add-PartitionAccessPath -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -AccessPath "$letter`:\"
  $AssignedLetters.Add($letter) | Out-Null
  return "$letter`:\"
}

function Test-FilePresent([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label missing: $Path"
  }
  Write-Host "OK: $Label -> $Path"
}

function Install-GuestAgent([string]$WindowsRoot, [string]$AgentPath) {
  if (-not $AgentPath) {
    return
  }
  $AgentPath = [System.IO.Path]::GetFullPath($AgentPath)
  if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
    throw "GuestAgent binary does not exist: $AgentPath"
  }

  $agentDir = Join-Path $WindowsRoot "AntiMal"
  New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
  $dest = Join-Path $agentDir "AntiMal.GuestAgent.exe"
  Copy-Item -LiteralPath $AgentPath -Destination $dest -Force

  $hiveName = "AntiMalBaseSoftware"
  $hivePath = Join-Path $WindowsRoot "Windows\System32\Config\SOFTWARE"
  & reg.exe load "HKLM\$hiveName" $hivePath | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "reg load failed with exit code $LASTEXITCODE"
  }
  try {
    & reg.exe add "HKLM\$hiveName\Microsoft\Windows\CurrentVersion\Run" /v AntiMalGuestAgent /t REG_SZ /d "C:\AntiMal\AntiMal.GuestAgent.exe" /f | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "reg add failed with exit code $LASTEXITCODE"
    }
  } finally {
    & reg.exe unload "HKLM\$hiveName" | Out-Null
  }

  Write-Host "OK: installed GuestAgent autostart -> $dest"
}

function Find-PartitionRootWithFile($Partitions, [string]$RelativePath, [System.Collections.Generic.List[string]]$AssignedLetters) {
  foreach ($partition in $Partitions) {
    $root = Get-PartitionRoot $partition $AssignedLetters
    $candidate = Join-Path $root $RelativePath
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [pscustomobject]@{ Partition = $partition; Root = $root; Path = $candidate }
    }
  }
  return $null
}

$BaseVhdxPath = [System.IO.Path]::GetFullPath($BaseVhdxPath)
if (-not (Test-Path -LiteralPath $BaseVhdxPath -PathType Leaf)) {
  throw "Base VHDX does not exist: $BaseVhdxPath"
}

$imageMounted = $false
$assignedLetters = [System.Collections.Generic.List[string]]::new()

try {
  $access = if ($RepairBcd -or $GuestAgentPath) { "ReadWrite" } else { "ReadOnly" }
  Write-Host "Mounting base VHDX ($access): $BaseVhdxPath"
  Mount-DiskImage -ImagePath $BaseVhdxPath -Access $access | Out-Null
  $imageMounted = $true
  Start-Sleep -Milliseconds 500

  $diskImage = Get-DiskImage -ImagePath $BaseVhdxPath
  $disk = $diskImage | Get-Disk
  $partitions = @($disk | Get-Partition | Where-Object { $_.Type -ne "Reserved" })
  if ($partitions.Count -eq 0) {
    throw "No usable partitions found in $BaseVhdxPath"
  }

  $espCandidates = @(
    $partitions | Where-Object {
      ($_.GptType -and $_.GptType.ToString().ToLowerInvariant() -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}") -or
      ($_.Type -eq "System")
    }
  )
  if ($espCandidates.Count -eq 0) {
    $espCandidates = $partitions
  }

  $esp = Find-PartitionRootWithFile $espCandidates "EFI\Microsoft\Boot\BCD" $assignedLetters
  if (-not $esp) {
    $esp = Find-PartitionRootWithFile $partitions "EFI\Microsoft\Boot\BCD" $assignedLetters
  }

  $windows = Find-PartitionRootWithFile $partitions "Windows\System32\winload.efi" $assignedLetters

  if ($RepairBcd -and $windows -and (-not $esp)) {
    $espPartition = $espCandidates | Select-Object -First 1
    if (-not $espPartition) {
      throw "Cannot repair BCD because no EFI System Partition candidate exists."
    }
    $espRoot = Get-PartitionRoot $espPartition $assignedLetters
    Write-Host "Repairing UEFI boot files with bcdboot..."
    & bcdboot.exe (Join-Path $windows.Root "Windows") /s $espRoot /f UEFI
    if ($LASTEXITCODE -ne 0) {
      throw "bcdboot failed with exit code $LASTEXITCODE"
    }
    $esp = Find-PartitionRootWithFile @($espPartition) "EFI\Microsoft\Boot\BCD" $assignedLetters
  }

  if (-not $esp) {
    throw "EFI BCD store was not found. Rerun with -RepairBcd after confirming the Windows partition is present."
  }
  if (-not $windows) {
    throw "Windows loader was not found: \Windows\System32\winload.efi"
  }

  if ($RepairBcd) {
    $bcdPath = Join-Path $esp.Root "EFI\Microsoft\Boot\BCD"
    $fallbackPath = Join-Path $esp.Root "EFI\BOOT\BOOTX64.EFI"
    if ((-not (Test-Path -LiteralPath $bcdPath -PathType Leaf)) -or
        (-not (Test-Path -LiteralPath $fallbackPath -PathType Leaf))) {
      Write-Host "Repairing UEFI boot files with bcdboot..."
      & bcdboot.exe (Join-Path $windows.Root "Windows") /s $esp.Root /f UEFI
      if ($LASTEXITCODE -ne 0) {
        throw "bcdboot failed with exit code $LASTEXITCODE"
      }
    }
  }

  Install-GuestAgent $windows.Root $GuestAgentPath

  Test-FilePresent (Join-Path $esp.Root "EFI\Microsoft\Boot\BCD") "BCD store"
  Test-FilePresent (Join-Path $esp.Root "EFI\BOOT\BOOTX64.EFI") "fallback UEFI bootloader"
  Test-FilePresent (Join-Path $windows.Root "Windows\System32\winload.efi") "Windows OS loader"

  Write-Host ""
  Write-Host "AntiMal base boot validation passed."
  Write-Host "  ESP     : $($esp.Root)"
  Write-Host "  Windows : $($windows.Root)"
} finally {
  foreach ($letter in $assignedLetters) {
    try {
      Remove-PartitionAccessPath -DiskNumber $disk.Number -AccessPath "$letter`:\" -ErrorAction SilentlyContinue
    } catch {
    }
  }
  if ($imageMounted) {
    try {
      Dismount-DiskImage -ImagePath $BaseVhdxPath
    } catch {
      Write-Warning $_
    }
  }
}
