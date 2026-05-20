param(
  [string]$BaseVhdxPath = "C:\AntiMalRuns\_base\AntiMalBase.vhdx",
  [string]$GuestAgentPath = "",
  [switch]$RepairBcd
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Checked([string]$Tool, [string[]]$Arguments, [string]$Label) {
  Write-Host $Label
  $output = & $Tool @Arguments 2>&1 | Out-String
  if ($output.Trim().Length -gt 0) {
    Write-Host $output.TrimEnd()
  }
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
  return $output
}

function Test-BcdStore([string]$BcdPath) {
  Test-FilePresent $BcdPath "BCD store"
  $output = Invoke-Checked "bcdedit.exe" @("/store", $BcdPath, "/enum", "all") "Inspecting BCD store..."
  if ($output -notmatch "\{bootmgr\}") {
    throw "BCD validation failed: {bootmgr} entry is missing."
  }
  if (($output -notmatch "\{default\}") -and ($output -notmatch "winload\.efi")) {
    throw "BCD validation failed: no default Windows loader entry was found."
  }
  if ($output -notmatch "winload\.efi") {
    Write-Warning "BCD store did not print winload.efi explicitly; continuing because the loader file exists."
  }
}

function Repair-BcdStore([string]$WindowsRoot, [string]$EspRoot) {
  Write-Host "Repairing UEFI boot files with bcdboot..."
  Invoke-Checked "bcdboot.exe" @((Join-Path $WindowsRoot "Windows"), "/s", $EspRoot, "/f", "UEFI") "Running bcdboot..."

  $microsoftBoot = Join-Path $EspRoot "EFI\Microsoft\Boot\bootmgfw.efi"
  $fallbackDir = Join-Path $EspRoot "EFI\BOOT"
  $fallbackPath = Join-Path $fallbackDir "BOOTX64.EFI"
  if (Test-Path -LiteralPath $microsoftBoot -PathType Leaf) {
    New-Item -ItemType Directory -Force -Path $fallbackDir | Out-Null
    Copy-Item -LiteralPath $microsoftBoot -Destination $fallbackPath -Force
  }

  $bcdPath = Join-Path $EspRoot "EFI\Microsoft\Boot\BCD"
  Test-BcdStore $bcdPath
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "recoveryenabled", "No") "Disabling recovery auto-loop for sandbox base..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "bootstatuspolicy", "IgnoreAllFailures") "Setting bootstatuspolicy for sandbox base..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{bootmgr}", "timeout", "0") "Setting boot manager timeout..."
}

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

function Get-OfflineControlSet([string]$SystemHiveName) {
  $select = Get-ItemProperty -Path "HKLM:\$SystemHiveName\Select"
  $default = [int]$select.Default
  if ($default -le 0) {
    $default = 1
  }
  return "ControlSet{0:D3}" -f $default
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

  $softwareHiveName = "AntiMalBaseSoftware"
  $softwareHivePath = Join-Path $WindowsRoot "Windows\System32\Config\SOFTWARE"
  $systemHiveName = "AntiMalBaseSystem"
  $systemHivePath = Join-Path $WindowsRoot "Windows\System32\Config\SYSTEM"
  $softwareLoaded = $false
  $systemLoaded = $false
  try {
    Invoke-Checked "reg.exe" @("load", "HKLM\$softwareHiveName", $softwareHivePath) "Loading offline SOFTWARE hive..."
    $softwareLoaded = $true
    Invoke-Checked "reg.exe" @("add", "HKLM\$softwareHiveName\Microsoft\Windows\CurrentVersion\Run", "/v", "AntiMalGuestAgent", "/t", "REG_SZ", "/d", "`"C:\AntiMal\AntiMal.GuestAgent.exe`" --service", "/f") "Adding GuestAgent Run fallback..."

    Invoke-Checked "reg.exe" @("load", "HKLM\$systemHiveName", $systemHivePath) "Loading offline SYSTEM hive..."
    $systemLoaded = $true
    $controlSet = Get-OfflineControlSet $systemHiveName
    $serviceKey = "HKLM\$systemHiveName\$controlSet\Services\AntiMalGuestAgent"
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/f") "Creating GuestAgent service key..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "Type", "/t", "REG_DWORD", "/d", "16", "/f") "Configuring GuestAgent service type..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "Start", "/t", "REG_DWORD", "/d", "2", "/f") "Configuring GuestAgent service start..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "ErrorControl", "/t", "REG_DWORD", "/d", "1", "/f") "Configuring GuestAgent service error control..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "ImagePath", "/t", "REG_EXPAND_SZ", "/d", "`"C:\AntiMal\AntiMal.GuestAgent.exe`" --service", "/f") "Configuring GuestAgent service image path..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "DisplayName", "/t", "REG_SZ", "/d", "AntiMal Guest Agent", "/f") "Configuring GuestAgent service display name..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "ObjectName", "/t", "REG_SZ", "/d", "LocalSystem", "/f") "Configuring GuestAgent service account..."
    Invoke-Checked "reg.exe" @("add", $serviceKey, "/v", "Description", "/t", "REG_SZ", "/d", "AntiMal benign VM heartbeat and artifact channel", "/f") "Configuring GuestAgent service description..."
  } finally {
    if ($systemLoaded) {
      & reg.exe unload "HKLM\$systemHiveName" | Out-Null
    }
    if ($softwareLoaded) {
      & reg.exe unload "HKLM\$softwareHiveName" | Out-Null
    }
  }

  Write-Host "OK: installed GuestAgent service and Run fallback -> $dest"
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
if (-not (Test-IsAdmin)) {
  throw "Run this script from an elevated PowerShell prompt. Mount-DiskImage and offline registry edits require Administrator privileges."
}
if (-not (Test-Path -LiteralPath $BaseVhdxPath -PathType Leaf)) {
  throw "Base VHDX does not exist: $BaseVhdxPath"
}

$imageMounted = $false
$assignedLetters = [System.Collections.Generic.List[string]]::new()
$disk = $null

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
    Repair-BcdStore $windows.Root $espRoot
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
      Repair-BcdStore $windows.Root $esp.Root
    } else {
      Repair-BcdStore $windows.Root $esp.Root
    }
  }

  Install-GuestAgent $windows.Root $GuestAgentPath

  Test-FilePresent (Join-Path $esp.Root "EFI\Microsoft\Boot\BCD") "BCD store"
  Test-FilePresent (Join-Path $esp.Root "EFI\BOOT\BOOTX64.EFI") "fallback UEFI bootloader"
  Test-FilePresent (Join-Path $windows.Root "Windows\System32\winload.efi") "Windows OS loader"
  Test-BcdStore (Join-Path $esp.Root "EFI\Microsoft\Boot\BCD")

  Write-Host ""
  Write-Host "AntiMal base boot validation passed."
  Write-Host "  ESP     : $($esp.Root)"
  Write-Host "  Windows : $($windows.Root)"
} finally {
  foreach ($letter in $assignedLetters) {
    try {
      if ($disk) {
        Remove-PartitionAccessPath -DiskNumber $disk.Number -AccessPath "$letter`:\" -ErrorAction SilentlyContinue
      }
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
