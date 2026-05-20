param(
  [Parameter(Mandatory = $true)]
  [string]$WindowsIsoPath,

  [string]$WorkspaceRoot = "C:\AntiMalRuns",
  [string]$VmNamePrefix = "AntiMal",
  [string]$ConfigPath = "",
  [string]$Provider = "auto",
  [switch]$EnableFeatures,
  [switch]$CreateSwitches,
  [switch]$WriteConfig,
  [switch]$CreateBuilderVm,
  [switch]$StartBuilderVm,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$requested = $Provider.ToLowerInvariant()
if (-not $requested) {
  $requested = "auto"
}

if ($requested -eq "auto") {
  $requested = "local"
}

if ($requested -eq "virtualbox" -or $requested -eq "vmware") {
  throw "Provider '$Provider' has been removed from AntiMal. Build Base will not launch third-party VM apps."
}

if ($requested -eq "hyperv") {
  Write-Warning "Build Base is local-only now. Ignoring provider '$Provider' and creating a local base disk."
  $requested = "local"
}

if ($requested -eq "local" -or $requested -eq "inhouse") {
  $script = Join-Path $scriptRoot "New-AntiMalBaseVhdx.ps1"
  $args = @{
    WindowsIsoPath = $WindowsIsoPath
    OutputVhdxPath = (Join-Path $WorkspaceRoot "_base\AntiMalBase.vhdx")
    WorkspaceRoot = $WorkspaceRoot
    VmNamePrefix = $VmNamePrefix
    ConfigPath = $ConfigPath
    WriteConfig = $WriteConfig
    Force = $Force
  }
  & $script @args
  return
}

throw "Unsupported provider: $Provider. Supported: auto, local, inhouse."
