param(
  [Parameter(Mandatory = $true)]
  [string]$WindowsIsoPath,

  [string]$OutputVhdxPath = "C:\AntiMalRuns\_base\AntiMalBase.vhdx",
  [string]$WorkspaceRoot = "C:\AntiMalRuns",
  [string]$VmNamePrefix = "AntiMal",
  [string]$ConfigPath = "",
  [string]$GuestAgentPath = "",
  [int]$ImageIndex = 0,
  [int]$SizeGB = 80,

  [switch]$EnableFeatures,
  [switch]$CreateSwitches,
  [switch]$WriteConfig,
  [switch]$CreateBuilderVm,
  [switch]$StartBuilderVm,
  [switch]$Force,

  # Bake an autounattend.xml + AutoLogon into the base so first boot goes
  # straight to the desktop. RECOMMENDED for the sandbox: the in-house VM
  # otherwise stops at the interactive Win11 OOBE wizard, and 24H2 has no
  # in-OOBE skip for the forced network/MSA screen with networking disabled.
  # Creates a local admin 'antimal' / 'AntiMal!23' with auto-logon. Default
  # off = vanilla interactive OOBE.
  [switch]$Unattend,

  # When >0, bake a FirstLogonCommands entry that schedules a clean
  # `shutdown /s` this many seconds after the first logon. This lets the first
  # boot auto-complete OOBE + first-logon, settle, then cleanly power off --
  # leaving a CONSISTENT overlay to promote into the seed snapshot (no dirty
  # mid-run kill, which produces an unbootable image). 0 = off (stay running).
  [int]$FirstLogonShutdownSec = 0
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Escape-TomlString([string]$Value) {
  return $Value.Replace("\", "/").Replace('"', '\"')
}

function Write-AntiMalConfig {
  if (-not $ConfigPath) {
    return
  }

  $configDir = Split-Path -Parent $ConfigPath
  if ($configDir) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
  }

  $baseEscaped = Escape-TomlString ((Resolve-Path -LiteralPath $OutputVhdxPath).Path)
  $rawEscaped = Escape-TomlString ([System.IO.Path]::GetFullPath($RawOutputPath))
  $workspaceEscaped = Escape-TomlString ((Resolve-Path -LiteralPath $WorkspaceRoot).Path)
  $text = @"
# AntiMal MVP configuration.
base_vhdx_path = "$baseEscaped"
base_disk_path = "$rawEscaped"
base_disk_format = "raw"
workspace_root = "$workspaceEscaped"
vm_name_prefix = "$VmNamePrefix"
default_timeout_sec = 180
network_mode = "disabled"
driver_bridge_mode = "off"
vm_provider = "inhouse"
dynamic_execution_enabled = false
"@
  # BOM-less UTF-8: Set-Content -Encoding UTF8 on Windows PowerShell 5.1 prepends a
  # UTF-8 BOM. The C++ config loader now strips a leading BOM, but write it clean so
  # the file is correct for any reader.
  [System.IO.File]::WriteAllText($ConfigPath, $text, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Wrote config: $ConfigPath"
}

function Get-AvailableDriveLetters([int]$Count) {
  $used = @{}
  Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    if ($_.Name.Length -eq 1) {
      $used[$_.Name.ToUpperInvariant()] = $true
    }
  }
  try {
    Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
      $letter = ([string]$_.DriveLetter).ToUpperInvariant()
      $used[$letter] = $true
    }
  } catch {
  }

  $letters = New-Object System.Collections.Generic.List[string]
  foreach ($letter in @("S", "W", "T", "U", "V", "X", "Y", "Z", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H", "G", "F", "E", "D")) {
    if (-not $used.ContainsKey($letter)) {
      $letters.Add($letter)
      if ($letters.Count -eq $Count) {
        return @($letters)
      }
    }
  }
  throw "Could not find $Count free drive letters for local VHDX build."
}

function Invoke-DiskPart([string[]]$Commands) {
  $scriptPath = Join-Path $env:TEMP ("antimal-diskpart-{0}.txt" -f ([Guid]::NewGuid()))
  try {
    Set-Content -LiteralPath $scriptPath -Value ($Commands -join "`r`n") -Encoding ASCII
    $output = & diskpart.exe /s $scriptPath 2>&1
    if ($LASTEXITCODE -ne 0) {
      $output | ForEach-Object { Write-Host $_ }
      throw "diskpart failed with exit code $LASTEXITCODE"
    }
    return $output
  } finally {
    if (Test-Path -LiteralPath $scriptPath) {
      Remove-Item -LiteralPath $scriptPath -Force
    }
  }
}

function Get-IsoRoot([string]$Path) {
  $image = Mount-DiskImage -ImagePath $Path -PassThru
  Start-Sleep -Milliseconds 500
  $volume = $image | Get-Volume | Where-Object { $_.DriveLetter } | Select-Object -First 1
  if (-not $volume) {
    $volume = Get-DiskImage -ImagePath $Path | Get-Volume | Where-Object { $_.DriveLetter } | Select-Object -First 1
  }
  if (-not $volume) {
    throw "Mounted ISO did not expose a drive letter."
  }
  return "$($volume.DriveLetter):\"
}

function Get-WindowsImages([string]$ImageFile) {
  $output = & dism.exe /English /Get-WimInfo "/WimFile:$ImageFile" 2>&1
  if ($LASTEXITCODE -ne 0) {
    $output | ForEach-Object { Write-Host $_ }
    throw "DISM Get-WimInfo failed with exit code $LASTEXITCODE"
  }

  $images = @()
  $current = $null
  foreach ($line in $output) {
    if ($line -match "^Index\s*:\s*(\d+)") {
      if ($current) {
        $images += $current
      }
      $current = [pscustomobject]@{ ImageIndex = [int]$Matches[1]; ImageName = "" }
    } elseif ($line -match "^Name\s*:\s*(.+)$" -and $current) {
      $current.ImageName = $Matches[1].Trim()
    }
  }
  if ($current) {
    $images += $current
  }
  return @($images)
}

function Select-WindowsImageIndex([string]$ImageFile, [int]$RequestedIndex) {
  if ($RequestedIndex -gt 0) {
    return $RequestedIndex
  }

  $images = @(Get-WindowsImages $ImageFile)
  if ($images.Count -eq 0) {
    throw "No Windows images found in $ImageFile"
  }

  Write-Host "Windows images found:"
  foreach ($image in $images) {
    Write-Host ("  [{0}] {1}" -f $image.ImageIndex, $image.ImageName)
  }

  $preferred = $images | Where-Object { $_.ImageName -match "Pro" } | Select-Object -First 1
  if (-not $preferred) {
    $preferred = $images[0]
  }

  Write-Host ("Using image index {0}: {1}" -f $preferred.ImageIndex, $preferred.ImageName)
  return [int]$preferred.ImageIndex
}

function New-LocalVhdxLayout([string]$VhdxPath, [string]$SystemLetter, [string]$WindowsLetter) {
  $sizeMB = [int64]$SizeGB * 1024
  Invoke-DiskPart @(
    "create vdisk file=`"$VhdxPath`" maximum=$sizeMB type=expandable",
    "select vdisk file=`"$VhdxPath`"",
    "attach vdisk",
    "convert gpt",
    "create partition efi size=260",
    "format quick fs=fat32 label=SYSTEM",
    "assign letter=$SystemLetter",
    "create partition primary",
    "format quick fs=ntfs label=Windows",
    "assign letter=$WindowsLetter"
  ) | Out-Null
}

function Dismount-LocalVhdx([string]$VhdxPath) {
  try {
    Invoke-DiskPart @(
      "select vdisk file=`"$VhdxPath`"",
      "detach vdisk"
    ) | Out-Null
  } catch {
    Write-Warning $_
  }
}

function Apply-WindowsToMountedVhdx([string]$ImageFile, [int]$SelectedIndex, [string]$SystemLetter, [string]$WindowsLetter) {
  $systemRoot = "$SystemLetter`:"
  $windowsRoot = "$WindowsLetter`:\"

  Write-Host "Applying Windows image to $windowsRoot ..."
  & dism.exe /Apply-Image "/ImageFile:$ImageFile" "/Index:$SelectedIndex" "/ApplyDir:$windowsRoot"
  if ($LASTEXITCODE -ne 0) {
    throw "DISM Apply-Image failed with exit code $LASTEXITCODE"
  }

  Write-Host "Creating UEFI boot files..."
  & bcdboot.exe "$windowsRoot`Windows" /s $systemRoot /f UEFI
  if ($LASTEXITCODE -ne 0) {
    throw "bcdboot failed with exit code $LASTEXITCODE"
  }

  if ($Unattend) {
    Write-UnattendXml $windowsRoot
  }
}

# Writes a Windows 11 oobeSystem answer file into the applied image so first
# boot auto-completes OOBE (skipping the region/keyboard/network/MSA/EULA
# screens the in-house VM otherwise stalls on) and auto-logs-in a local admin
# straight to the desktop. Benign disposable analysis VM => a known throwaway
# password is fine. Windows Setup reads %WINDIR%\Panther\unattend.xml during the
# specialize + oobeSystem passes of an applied (DISM /Apply-Image) install.
function Write-UnattendXml([string]$WindowsRoot) {
  $pantherDir = Join-Path $WindowsRoot "Windows\Panther"
  New-Item -ItemType Directory -Force -Path $pantherDir | Out-Null
  $unattendPath = Join-Path $pantherDir "unattend.xml"

  # Optional: schedule a clean shutdown a fixed delay after first logon, so the
  # first boot self-completes OOBE + first-logon, settles, then powers off
  # cleanly -- leaving a consistent overlay to promote into the seed snapshot
  # (a mid-run kill leaves dirty NTFS -> the seed boot hangs/spins).
  $firstLogonBlock = ""
  if ($FirstLogonShutdownSec -gt 0) {
    $firstLogonBlock = @"
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c shutdown /s /f /t $FirstLogonShutdownSec</CommandLine>
          <Description>AntiMal: clean power-off after first-logon settle (for snapshot capture)</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
"@
  }

  # NOTE: @"..."@ (interpolating here-string) so $firstLogonBlock is substituted.
  # The XML itself contains no literal '$'. BypassNRO is set in specialize so
  # OOBE skips the forced "connect to a network" screen (the sandbox has no NIC).
  $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>ANTIMAL-VM</ComputerName>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
          <Description>Bypass OOBE network requirement (sandbox networking is disabled)</Description>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>0409:00000409</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UILanguageFallback>en-US</UILanguageFallback>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <TimeZone>Pacific Standard Time</TimeZone>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>antimal</Name>
            <DisplayName>AntiMal</DisplayName>
            <Group>Administrators</Group>
            <Password>
              <Value>AntiMal!23</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>antimal</Username>
        <LogonCount>999</LogonCount>
        <Password>
          <Value>AntiMal!23</Value>
          <PlainText>true</PlainText>
        </Password>
      </AutoLogon>
$firstLogonBlock
    </component>
  </settings>
</unattend>
"@
  [System.IO.File]::WriteAllText($unattendPath, $xml, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "OK: wrote autounattend (auto-logon 'antimal'; BypassNRO; firstLogonShutdown=${FirstLogonShutdownSec}s) -> $unattendPath"
}

function Resolve-GuestAgentPath {
  if ($GuestAgentPath) {
    return [System.IO.Path]::GetFullPath($GuestAgentPath)
  }

  $candidates = @(
    (Join-Path $PSScriptRoot "..\AntiMal.GuestAgent.exe"),
    (Join-Path $PSScriptRoot "..\bin\x64\Release\AntiMal.GuestAgent.exe"),
    (Join-Path $PSScriptRoot "..\..\bin\x64\Release\AntiMal.GuestAgent.exe")
  )
  foreach ($candidate in $candidates) {
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (Test-Path -LiteralPath $full -PathType Leaf) {
      return $full
    }
  }
  return ""
}

function Test-AntiMalBaseVhdx([string]$VhdxPath, [switch]$RepairBcd) {
  $validator = Join-Path $PSScriptRoot "Test-AntiMalBaseBoot.ps1"
  if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
    throw "Base validation script is missing: $validator"
  }

  Write-Host "Validating AntiMal base boot files..."
  $agent = Resolve-GuestAgentPath
  $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $validator, "-BaseVhdxPath", $VhdxPath)
  if ($RepairBcd) {
    $args += "-RepairBcd"
  }
  if ($agent) {
    $args += @("-GuestAgentPath", $agent)
  } else {
    Write-Warning "AntiMal.GuestAgent.exe was not found; base will validate but will not auto-start the agent."
  }
  & powershell.exe @args
  if ($LASTEXITCODE -ne 0) {
    throw "Base boot validation failed with exit code $LASTEXITCODE"
  }
}

if ($EnableFeatures -or $CreateSwitches -or $CreateBuilderVm -or $StartBuilderVm) {
  Write-Host "Local Build Base ignores VM feature/switch/builder flags. It creates only a local base disk."
}

$OutputVhdxPath = [System.IO.Path]::GetFullPath($OutputVhdxPath)
$WorkspaceRoot = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$outputDir = Split-Path -Parent $OutputVhdxPath
$RawOutputPath = Join-Path $outputDir "AntiMalBase.raw"
New-Item -ItemType Directory -Force -Path $WorkspaceRoot | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

if ((Test-Path -LiteralPath $OutputVhdxPath) -and -not $Force) {
  Write-Host "Local base VHDX already exists: $OutputVhdxPath"
  Write-Host "Reusing it. Pass -Force only when you intentionally want to rebuild and replace it."
  Test-AntiMalBaseVhdx $OutputVhdxPath
  if ($WriteConfig) {
    Write-AntiMalConfig
  }
  return
}

if (-not (Test-IsAdmin)) {
  throw "Run this script from an elevated PowerShell prompt."
}

if (-not (Test-Path -LiteralPath $WindowsIsoPath -PathType Leaf)) {
  throw "Windows ISO does not exist: $WindowsIsoPath"
}

if (Test-Path -LiteralPath $OutputVhdxPath) {
  Remove-Item -LiteralPath $OutputVhdxPath -Force
}

$isoMounted = $false
$vhdMounted = $false

try {
  $isoRoot = Get-IsoRoot $WindowsIsoPath
  $isoMounted = $true
  $letters = Get-AvailableDriveLetters 2
  $systemLetter = $letters[0]
  $windowsLetter = $letters[1]

  $wim = Join-Path $isoRoot "sources\install.wim"
  $esd = Join-Path $isoRoot "sources\install.esd"
  if (Test-Path -LiteralPath $wim) {
    $imageFile = $wim
  } elseif (Test-Path -LiteralPath $esd) {
    $imageFile = $esd
  } else {
    throw "Could not find sources\install.wim or sources\install.esd in the ISO."
  }

  $selectedIndex = Select-WindowsImageIndex $imageFile $ImageIndex
  Write-Host "Creating local VHDX with diskpart: $OutputVhdxPath"
  New-LocalVhdxLayout $OutputVhdxPath $systemLetter $windowsLetter
  $vhdMounted = $true
  Apply-WindowsToMountedVhdx $imageFile $selectedIndex $systemLetter $windowsLetter
} finally {
  if ($vhdMounted) {
    Dismount-LocalVhdx $OutputVhdxPath
  }
  if ($isoMounted) {
    Dismount-DiskImage -ImagePath $WindowsIsoPath
  }
}

Test-AntiMalBaseVhdx $OutputVhdxPath -RepairBcd

if ($WriteConfig) {
  Write-AntiMalConfig
}

Write-Host ""
Write-Host "Local base VHDX created: $OutputVhdxPath"
Write-Host "No VirtualBox, VMware, Hyper-V VM cmdlets, or VM manager was used."
Write-Host "Convert the VHDX to raw before in-house boot:"
Write-Host "  AntiMal.HostCli.exe base convert --vhdx `"$OutputVhdxPath`" --raw `"$RawOutputPath`""
Write-Host "Config provider is set to inhouse; sample execution remains safety-gated."
