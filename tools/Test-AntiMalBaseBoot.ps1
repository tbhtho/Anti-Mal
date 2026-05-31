param(
  [string]$BaseVhdxPath = "C:\AntiMalRuns\_base\AntiMalBase.vhdx",
  [string]$GuestAgentPath = "",
  [switch]$RepairBcd,
  [switch]$RepairBootStorage
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
  if ($output -notmatch "(?im)^\s*path\s+\\Windows\\system32\\winload\.efi\s*$") {
    throw "BCD validation failed: {default} does not point at \Windows\System32\winload.efi."
  }
  if ($output -notmatch "(?im)^\s*device\s+partition=") {
    throw "BCD validation failed: no partition-backed device entry was found."
  }
  if ($output -notmatch "(?im)^\s*osdevice\s+partition=") {
    throw "BCD validation failed: no partition-backed osdevice entry was found."
  }
}

function Format-BcdPartitionDevice([string]$Root) {
  $full = [System.IO.Path]::GetFullPath($Root)
  if ($full -match "^([A-Za-z]):\\?$") {
    return "partition=$($Matches[1]):"
  }
  throw "BCD partition device can only be set from a drive-letter root; got: $Root"
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
  $espDevice = Format-BcdPartitionDevice $EspRoot
  $windowsDevice = Format-BcdPartitionDevice $WindowsRoot
  Test-FilePresent $bcdPath "BCD store"
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{bootmgr}", "device", $espDevice) "Pinning boot manager to ESP partition..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "device", $windowsDevice) "Pinning Windows loader device..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "osdevice", $windowsDevice) "Pinning Windows loader OS device..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "path", "\Windows\System32\winload.efi") "Pinning Windows loader path..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "systemroot", "\Windows") "Pinning Windows system root..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "recoveryenabled", "No") "Disabling recovery auto-loop for sandbox base..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{default}", "bootstatuspolicy", "IgnoreAllFailures") "Setting bootstatuspolicy for sandbox base..."
  Invoke-Checked "bcdedit.exe" @("/store", $bcdPath, "/set", "{bootmgr}", "timeout", "0") "Setting boot manager timeout..."
  Test-BcdStore $bcdPath
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
  # Re-query so AccessPaths/DriveLetter reflect the current mount. Right after
  # Mount-DiskImage, Get-Volume can briefly report no DriveLetter even though the
  # partition already carries a persisted drive-letter access path from a prior
  # mount (e.g. the W:\ the DISM apply step left on it). Trying to Add another
  # letter then fails with "the requested access path is already in use", so use
  # the existing access path when there is one.
  $p = Get-Partition -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber
  # 1) Reuse an existing drive-letter access path that is actually reachable
  #    (the apply step persists e.g. W:\ on the Windows partition across mounts).
  foreach ($ap in @($p.AccessPaths)) {
    if ($ap -match '^[A-Za-z]:\\$' -and (Test-Path -LiteralPath $ap)) {
      return $ap.Substring(0, 3)
    }
  }
  $volume = $null
  try { $volume = $p | Get-Volume -ErrorAction SilentlyContinue } catch {}
  if ($volume -and $volume.DriveLetter -and (Test-Path -LiteralPath "$($volume.DriveLetter):\")) {
    return "$($volume.DriveLetter):\"
  }
  # 2) Assign a fresh letter, retrying past any "already in use" caused by a
  #    stale persisted access path left on the partition by a prior failed run.
  foreach ($letter in @("S","T","U","V","X","Y","Z","R","Q","P","O","N","M","L","K","J","I","H","G","F","E","D")) {
    if (Test-Path -LiteralPath "$letter`:\") { continue }
    try {
      Add-PartitionAccessPath -DiskNumber $p.DiskNumber -PartitionNumber $p.PartitionNumber -AccessPath "$letter`:\" -ErrorAction Stop
      $AssignedLetters.Add($letter) | Out-Null
      return "$letter`:\"
    } catch {
      continue
    }
  }
  # 3) Last resort: the volume-GUID access path is always valid while mounted.
  foreach ($ap in @($p.AccessPaths)) {
    if ($ap -like '\\?\Volume{*') { return $ap }
  }
  throw "Could not obtain a usable access path for partition $($p.PartitionNumber)."
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

function Repair-BootStorageDrivers([string]$WindowsRoot) {
  $systemHiveName = "AntiMalBaseSystemStorageRepair"
  $systemHivePath = Join-Path $WindowsRoot "Windows\System32\Config\SYSTEM"
  $systemLoaded = $false
  try {
    Invoke-Checked "reg.exe" @("load", "HKLM\$systemHiveName", $systemHivePath) "Loading offline SYSTEM hive for boot-storage repair..."
    $systemLoaded = $true
    $controlSet = Get-OfflineControlSet $systemHiveName

    foreach ($service in @("pciide", "intelide", "atapi", "disk", "partmgr", "mountmgr")) {
      $servicePsPath = "HKLM:\$systemHiveName\$controlSet\Services\$service"
      $serviceRegPath = "HKLM\$systemHiveName\$controlSet\Services\$service"
      if (-not (Test-Path -LiteralPath $servicePsPath)) {
        Write-Warning "Boot-storage service is not present in offline hive: $service"
        continue
      }
      Invoke-Checked "reg.exe" @("add", $serviceRegPath, "/v", "Start", "/t", "REG_DWORD", "/d", "0", "/f") "Marking $service as boot-start..."
      Invoke-Checked "reg.exe" @("add", $serviceRegPath, "/v", "ErrorControl", "/t", "REG_DWORD", "/d", "1", "/f") "Marking $service as normal-error boot service..."

      $startOverridePsPath = Join-Path $servicePsPath "StartOverride"
      if (Test-Path -LiteralPath $startOverridePsPath) {
        $startOverrideRegPath = "$serviceRegPath\StartOverride"
        Invoke-Checked "reg.exe" @("add", $startOverrideRegPath, "/v", "0", "/t", "REG_DWORD", "/d", "0", "/f") "Clearing $service StartOverride\0..."
      }
    }

    $criticalRoot = "HKLM\$systemHiveName\$controlSet\Control\CriticalDeviceDatabase"
    $piixIdeIds = @(
      "pci#ven_8086&dev_7111",
      "pci#ven_8086&dev_7111&cc_0101",
      "pci#ven_8086&dev_7111&cc_01018a",
      "pci#cc_0101",
      "pci#cc_01018a"
    )
    foreach ($id in $piixIdeIds) {
      $key = "$criticalRoot\$id"
      Invoke-Checked "reg.exe" @("add", $key, "/v", "Service", "/t", "REG_SZ", "/d", "pciide", "/f") "Adding CriticalDeviceDatabase mapping for $id..."
      Invoke-Checked "reg.exe" @("add", $key, "/v", "ClassGUID", "/t", "REG_SZ", "/d", "{4D36E96A-E325-11CE-BFC1-08002BE10318}", "/f") "Adding CriticalDeviceDatabase class for $id..."
    }
  } finally {
    if ($systemLoaded) {
      & reg.exe unload "HKLM\$systemHiveName" | Out-Null
    }
  }

  Write-Host "OK: repaired offline boot-storage services for the emulated PIIX IDE controller."
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
  $access = if ($RepairBcd -or $RepairBootStorage -or $GuestAgentPath) { "ReadWrite" } else { "ReadOnly" }
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

  if ($RepairBcd -or $RepairBootStorage) {
    Repair-BootStorageDrivers $windows.Root
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
