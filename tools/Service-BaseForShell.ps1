<#
.SYNOPSIS
  Offline-service the base VHDX so the in-house VM reaches a STABLE interactive
  Windows shell (taskbar + Start), fixing the long-standing ucrtbase c0000409
  crash-loop. Requires HOST ADMIN (Mount-DiskImage + reg load). Base backed up
  first; never deletes the base.

.DESCRIPTION
  Root cause (decoded 2026-06-14): the base image enforces a signed WDAC policy
  "Microsoft Windows Endpoint Security Policy" {60FD87F8-4593-44A0-91B0-2E0DA022F248}
  whose AppX "Approved" deployment gate BLOCKS per-user registration of the inbox
  shell AppX (Microsoft.UI.Xaml.CBS / MicrosoftWindows.Client.CBS/Core, the
  taskbar/Start owners) with 0x80073D01 / 0xD0E90002 ("blocked by AppLocker" -- a
  generic message; the real AppLocker policy is EMPTY and SAC is Off). Every inbox
  package fails, even a manual admin user-context Add-AppxPackage -Register.

  This script applies the full fix to the OFFLINE base:
   1. [VERIFIED] unattend.xml (Panther + root) -> reliable auto-OOBE + AutoLogon
      'antimal' (cold boot reaches the desktop in ~672s, no flaky keyboard OOBE).
   2. [VERIFIED] FirstLogonCommands -> runs C:\antimal-as.cmd as antimal, BEFORE
      the shell, which re-registers the inbox shell AppX. (Active Setup does NOT
      execute on 25H2 autologon; FirstLogonCommands does.)
   3. [HYPOTHESIZED -- the remaining lever] delete the enforced EndpointSec .cip
      so winload doesn't load it -> no WDAC enforcement -> AppX deploy allowed.
      NOTE: ZEROING this file boot-fails (0xC0430001); DELETING (file absent) is
      hypothesized to differ. If the cold boot bugchecks 0xC0430001, restore the
      base from the backup and instead leave EndpointSec and pursue a clean base
      built from a standard ISO without this enterprise policy.

  Then cold-boot to verify: EXPLORER_C0000409_CRASHES -> 0 and a taskbar appears.
#>
[CmdletBinding()]
param(
  [string]$BaseVhdx = 'C:\AntiMalRuns\_base\AntiMalBase.vhdx',
  [switch]$SkipEndpointSecDelete,   # apply only the VERIFIED steps (unattend + re-register)
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
function Fail($m){ Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# --- admin gate ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail "Host Administrator required (Mount-DiskImage + reg load). Re-launch elevated."
}
if (-not (Test-Path $BaseVhdx)) { Fail "base not found: $BaseVhdx" }

# --- payloads ---
$unattend = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UILanguageFallback>en-US</UILanguageFallback><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC><SkipMachineOOBE>true</SkipMachineOOBE><SkipUserOOBE>true</SkipUserOOBE></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>antimal</Name><DisplayName>antimal</DisplayName><Group>Administrators</Group><Password><Value>AntiMal!23</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><Username>antimal</Username><Password><Value>AntiMal!23</Value><PlainText>true</PlainText></Password><LogonCount>10</LogonCount></AutoLogon>
      <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>C:\Windows\System32\cmd.exe /c C:\antimal-as.cmd</CommandLine><Description>Re-register inbox shell AppX</Description><RequiresUserInput>false</RequiresUserInput></SynchronousCommand></FirstLogonCommands>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
</unattend>
'@
$ascmd = "@echo off`r`necho activesetup fired %DATE% %TIME% as %USERNAME% > C:\antimal-as.log 2>&1`r`nC:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\antimal-regshell.ps1 >> C:\antimal-as.log 2>&1`r`necho as-done >> C:\antimal-as.log 2>&1`r`n"
$regshell = @'
$ErrorActionPreference='SilentlyContinue'
$log="C:\antimal-regshell.log"; function L($m){ ("{0} {1}" -f (Get-Date -Format HH:mm:ss),$m)|Out-File -Append -Encoding ascii $log }
L "=== re-register start user=$env:USERNAME ==="
function TryReg($p){ try{ Add-AppxPackage -Register -DisableDevelopmentMode -Path $p -ErrorAction Stop; L ("OK   "+(Split-Path (Split-Path $p) -Leaf)); $true }catch{ L ("FAIL "+(Split-Path (Split-Path $p) -Leaf)+" :: "+(($_.Exception.Message -split "`n")[0])); $false } }
$sa="C:\Windows\SystemApps"
$ok = TryReg "$sa\Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe\AppxManifest.xml"
if($ok){
  foreach($d in "MicrosoftWindows.Client.Core_cw5n1h2txyewy","MicrosoftWindows.Client.CBS_cw5n1h2txyewy","ShellExperienceHost_cw5n1h2txyewy","Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy","MicrosoftWindows.Client.FileExp_cw5n1h2txyewy"){ TryReg "$sa\$d\AppxManifest.xml" | Out-Null }
  Get-AppxPackage -AllUsers | ForEach-Object { try{ Add-AppxPackage -DisableDevelopmentMode -Register ($_.InstallLocation+"\AppxManifest.xml") -ErrorAction Stop }catch{} }
  L ("final pkg count: "+(Get-AppxPackage).Count); Stop-Process -Name explorer,StartMenuExperienceHost,ShellExperienceHost,sihost -Force -EA SilentlyContinue
}
L "=== done ok=$ok ==="
'@

# --- backup ---
$bak = "$BaseVhdx.bak-shellfix-$((Get-Date).ToString('yyyyMMddHHmmss'))"
if (-not $Force) { $a = Read-Host "Back up + service $BaseVhdx (backup -> $bak)? (y/N)"; if ($a -notin 'y','Y','yes'){ exit 0 } }
Write-Host "Backing up base -> $bak"; Copy-Item $BaseVhdx $bak -Force

# --- mount ---
$di = Mount-DiskImage -ImagePath $BaseVhdx -StorageType VHDX -Access ReadWrite -PassThru
try {
  $disk = $di | Get-DiskImage | Get-Disk
  $parts = Get-Partition -DiskNumber $disk.Number
  $win = $parts | Where-Object { $_.Size -gt 1GB }
  if (-not $win.DriveLetter) { Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $win.PartitionNumber -AssignDriveLetter; $win = Get-Partition -DiskNumber $disk.Number -PartitionNumber $win.PartitionNumber }
  $esp = $parts | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }
  if ($esp -and -not $esp.DriveLetter) { Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $esp.PartitionNumber -AssignDriveLetter; $esp = Get-Partition -DiskNumber $disk.Number -PartitionNumber $esp.PartitionNumber }
  $wl = $win.DriveLetter; $el = $esp.DriveLetter
  Write-Host "Windows=${wl}: ESP=${el}:"

  New-Item -ItemType Directory -Force "${wl}:\Windows\Panther" | Out-Null
  $unattend | Out-File "${wl}:\Windows\Panther\unattend.xml" -Encoding utf8
  $unattend | Out-File "${wl}:\unattend.xml" -Encoding utf8
  $ascmd    | Out-File "${wl}:\antimal-as.cmd" -Encoding ascii -NoNewline
  $regshell | Out-File "${wl}:\antimal-regshell.ps1" -Encoding ascii
  Write-Host "Placed unattend + FirstLogonCommands re-register payloads." -ForegroundColor Green

  if (-not $SkipEndpointSecDelete) {
    $g = '{60FD87F8-4593-44A0-91B0-2E0DA022F248}'
    foreach ($p in "${wl}:\Windows\System32\CodeIntegrity\CiPolicies\Active\$g.cip", "${el}:\EFI\Microsoft\Boot\CiPolicies\Active\$g.cip") {
      if (Test-Path $p) { Remove-Item $p -Force; Write-Host "Deleted EndpointSec .cip: $p" -ForegroundColor Yellow }
    }
    Write-Host "NOTE: if the cold boot bugchecks 0xC0430001, restore from $bak and re-run with -SkipEndpointSecDelete." -ForegroundColor Yellow
  }
} finally {
  [GC]::Collect(); Start-Sleep 2; Dismount-DiskImage -ImagePath $BaseVhdx | Out-Null
}
Write-Host "`nDone. COLD-boot to verify (no seed):" -ForegroundColor Cyan
Write-Host '  $env:ANTIMAL_FIRMWARE_NAME="OVMF-debug.fd"; $env:ANTIMAL_VCPU_COUNT="1"'
Write-Host '  $env:ANTIMAL_PROBE_CI_POLICY_OFF="1"; $env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE="1"'
Write-Host '  bin\x64\Release\AntiMal.HostCli.exe detonate bin\x64\Release\AntiMal.Tests.exe --network disabled --cold --timeout-sec 1300'
Write-Host "Verify: EXPLORER_C0000409_CRASHES -> 0, a guest-*.png with a taskbar; revert: Copy-Item '$bak' '$BaseVhdx' -Force"
