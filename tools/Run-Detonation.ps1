<#
.SYNOPSIS
  Runs a live in-guest detonation of a (benign) sample with all three execution
  gate keys armed, via the reliable seed-boot path.

.DESCRIPTION
  The three-key detonation gate:
    1. config dynamic_execution_enabled = true   (host key 1)
    2. --allow-execution                          (host key 2 -> ANTIMAL_AUTHORIZE_EXECUTION)
    3. ANTIMAL_ARM_GUEST_EXEC=1                    (guest key 3 -> arms the disposable
                                                    overlay's SYSTEM hive offline)
  Seeds the run overlay from AntiMalDesktop.cow (the agent-equipped desktop
  snapshot) so the AntiMalGuestAgent service comes up at boot and receives the
  sample over COM2. The promoted snapshot and base VHDX are never written.

  USE A BENIGN SAMPLE ONLY.
#>
[CmdletBinding()]
param(
  [string]$Sample = "bin\x64\Release\AntiMal.SampleProbe.exe",
  [int]$TimeoutSec = 600,
  [string]$SeedOverlay = "C:\AntiMalRuns\_base\AntiMalDesktop.cow"
)
$ErrorActionPreference = "Stop"
$bin = "bin\x64\Release"
$ws = "C:\AntiMalRuns"
if (-not (Test-Path $Sample)) { throw "sample not found: $Sample" }
Get-Process -Name AntiMal.HostCli -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1

# Seed-boot detonation config (matches Measure-DesktopReach.ps1 seed mode). No kd.
$env:ANTIMAL_FIRMWARE_NAME = "OVMF-debug.fd"
$env:ANTIMAL_VCPU_COUNT = "1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF = "1"
$env:ANTIMAL_PROBE_CI_POLICY_OFF_AGGRESSIVE = "1"
$env:ANTIMAL_PROBE_BCD_NOINTEGRITYCHECKS = "1"
$env:ANTIMAL_PROBE_BCD_LEGACY_CONTEXT = "1"
$env:ANTIMAL_PROBE_BCD_HYPERVISOR_LAUNCH_OFF = "1"
$env:ANTIMAL_PROBE_SYSTEM_VBS_COMPAT = "1"
$env:ANTIMAL_SEED_OVERLAY = $SeedOverlay
$env:ANTIMAL_PROBE_PRESS_ENTER_SEC = "30"
$env:ANTIMAL_PROBE_WINLOAD_DEBUG = $null
$env:ANTIMAL_PROBE_BCD_KERNEL_DEBUG = $null
$env:ANTIMAL_PROBE_OOBE_KEYS = $null
$env:ANTIMAL_PROBE_OOBE_AUTOLOGON = $null
# Reach the logged-in desktop hands-free so SP5 can launch the sample VISIBLY in
# the interactive session (plaintext autologon fails on 25H2; type the password).
$env:ANTIMAL_PROBE_LOGIN_PASSWORD = "AntiMal!23"
# Third detonation key: arm the guest-side gate in THIS run's disposable overlay.
$env:ANTIMAL_ARM_GUEST_EXEC = "1"
# Deploy the freshly-built GuestAgent into the disposable overlay (so SP5 / agent
# changes take effect without re-snapshotting). Snapshot + base stay untouched.
$env:ANTIMAL_DEPLOY_FRESH_AGENT = "1"
$env:ANTIMAL_FRESH_AGENT_PATH = (Resolve-Path (Join-Path $bin "AntiMal.GuestAgent.exe")).Path

Write-Host ("Detonating {0} (timeout {1}s) -- execution armed: config + --allow-execution + ANTIMAL_ARM_GUEST_EXEC" -f $Sample, $TimeoutSec)
$vm = Start-Process "$bin\AntiMal.HostCli.exe" `
  -ArgumentList @("detonate", $Sample, "--network", "disabled", "--timeout-sec", "$TimeoutSec", "--allow-execution") `
  -PassThru -WindowStyle Hidden -Wait
Write-Host ("HostCli exited: {0}" -f $vm.ExitCode)
$run = Get-ChildItem $ws -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host ("RUN_DIR={0}" -f $run.FullName)
