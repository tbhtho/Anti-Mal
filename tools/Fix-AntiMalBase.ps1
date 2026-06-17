#Requires -RunAsAdministrator
<#
  Fix-AntiMalBase.ps1  --  remove the enforced WDAC "EndpointSec" policy from the
  AntiMal base image so the inbox shell AppX (taskbar/Start/ControlCenter) can
  register at first logon, fixing the explorer/ShellHost 0xC0000409 crash-loop.

  WHY: a deep root-cause + a 2026-06-17 headless re-confirmation proved the
  crash-loop is NOT fixable from a disposable overlay -- a signed, enforced WDAC
  policy ({60FD87F8-...}) baked into the BASE blocks the shell packages from
  registering. The only fix is on the base, which needs admin.

  WHAT IT DOES (all reversible / backed up):
    1. Backs up AntiMalBase.vhdx (full copy) -- so any boot-fail is recoverable.
    2. Mounts the base VHDX read/write.
    3. Reports the base's relevant state (the .cip, unattend, first-logon wiring).
    4. RENAMES the EndpointSec {60FD87F8-...}.cip to *.cip.disabled in BOTH the
       Windows partition AND the EFI System Partition (winload only loads *.cip,
       so a renamed file is ignored; rename back to undo). Rename, not delete.
    5. Stages a clean, no-hang shell-AppX re-register script for first logon
       (the previously-staged one hung on CiTool).
    6. Dismounts and prints next steps.

  RISK: the .cip removal has a small boot-fail chance (unverified). The full base
  backup in step 1 makes it fully recoverable. RUN AS ADMINISTRATOR.

  After running: cold-boot the base (NOT the seed) once to a settled desktop, then
  re-snapshot it as the new AntiMalDesktop.cow.
#>

$ErrorActionPreference = 'Stop'
$base    = 'C:\AntiMalRuns\_base\AntiMalBase.vhdx'
$cipName = '{60FD87F8-4593-44A0-91B0-2E0DA022F248}.cip'
$espGuid = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'  # EFI System Partition type

function Note($m) { Write-Host "  $m" }

Write-Host "=== Fix-AntiMalBase ===" -ForegroundColor Cyan
if (-not (Test-Path $base)) { throw "base VHDX not found: $base" }

# --- 1. Backup -------------------------------------------------------------
$bak = "$base.bak-cipfix-$(Get-Date -Format yyyyMMdd-HHmmss)"
Write-Host "[1/6] Backing up base (14 GB; a few minutes)..."
$free = (Get-PSDrive ($base.Substring(0,1))).Free
$size = (Get-Item $base).Length
if ($free -lt $size * 1.1) { throw "Not enough free space for a backup ($([math]::Round($size/1GB,1)) GB needed)." }
Copy-Item -LiteralPath $base -Destination $bak
Note "backup -> $bak"

# --- 2. Mount --------------------------------------------------------------
Write-Host "[2/6] Mounting base read/write..."
$img = Mount-DiskImage -ImagePath $base -Access ReadWrite -PassThru
Start-Sleep -Seconds 2
$diskNum = ($img | Get-DiskImage).Number
$cleanup = @()  # access paths to remove on exit
try {
  $parts = Get-Partition -DiskNumber $diskNum

  # locate the Windows partition (NTFS w/ \Windows\System32) and the ESP
  $winDrive = $null; $espDrive = $null
  foreach ($p in $parts) {
    $dl = $p.DriveLetter
    if (-not $dl) {
      # assign a temp letter so we can read it (ESP usually has none)
      try { $p | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop; $p = Get-Partition -DiskNumber $diskNum -PartitionNumber $p.PartitionNumber; $dl = $p.DriveLetter; if ($dl) { $cleanup += ,@($p.PartitionNumber, "$dl`:") } } catch {}
    }
    if (-not $dl) { continue }
    $root = "$dl`:\"
    if (Test-Path (Join-Path $root 'Windows\System32\config\SOFTWARE')) { $winDrive = "$dl`:" }
    if ($p.GptType -eq $espGuid -or (Test-Path (Join-Path $root 'EFI\Microsoft\Boot'))) { $espDrive = "$dl`:" }
  }
  Write-Host "[3/6] State:"
  Note "Windows partition: $winDrive"
  Note "EFI System Part. : $espDrive"
  if (-not $winDrive) { throw "Could not find the Windows partition on the mounted base." }

  # report the active CI policies + unattend/first-logon wiring
  $ciActive = Join-Path $winDrive 'Windows\System32\CodeIntegrity\CiPolicies\Active'
  if (Test-Path $ciActive) { Note "Active CI policies:"; Get-ChildItem $ciActive -Filter *.cip -EA SilentlyContinue | ForEach-Object { Note "   - $($_.Name)" } }
  foreach ($u in @('Windows\Panther\unattend.xml','unattend.xml','Windows\System32\Sysprep\unattend.xml')) {
    $up = Join-Path $winDrive $u; if (Test-Path $up) { Note "unattend present: $u" }
  }
  foreach ($f in @('antimal-regshell.ps1','antimal-as.cmd','antimal-oobe.cmd')) {
    $fp = Join-Path $winDrive $f; if (Test-Path $fp) { Note "first-logon script present: C:\$f" }
  }

  # --- 4. Disable the EndpointSec .cip (rename) ----------------------------
  Write-Host "[4/6] Disabling EndpointSec WDAC policy (rename .cip -> .cip.disabled)..."
  $targets = @()
  if ($winDrive) { $targets += Join-Path $winDrive ("Windows\System32\CodeIntegrity\CiPolicies\Active\" + $cipName) }
  if ($espDrive) { $targets += Join-Path $espDrive ("EFI\Microsoft\Boot\CiPolicies\Active\" + $cipName) }
  $disabledAny = $false
  foreach ($t in $targets) {
    if (Test-Path $t) {
      Rename-Item -LiteralPath $t -NewName ($cipName + '.disabled') -Force
      Note "disabled: $t"
      $disabledAny = $true
    } else { Note "not found (ok): $t" }
  }
  if (-not $disabledAny) { Note "WARNING: no {60FD87F8} .cip found to disable -- the policy may live elsewhere." }

  # --- 5. Stage a clean shell re-register (no CiTool hang) ------------------
  Write-Host "[5/6] Staging a clean first-logon shell-AppX re-register..."
  $reg = @'
$log = "C:\antimal-regshell.log"
"[$(Get-Date)] regshell start (post-WDAC-removal)" | Out-File $log -Append -Encoding utf8
try {
  $apps = Get-ChildItem "C:\Windows\SystemApps" -Directory -ErrorAction SilentlyContinue
  $order = $apps | Sort-Object { if ($_.Name -match 'UI\.Xaml') {0} elseif ($_.Name -match 'Client\.Core') {1} else {2} }, Name
  foreach ($a in $order) {
    $m = Join-Path $a.FullName "AppxManifest.xml"
    if (Test-Path $m) {
      try { Add-AppxPackage -Register $m -DisableDevelopmentMode -ErrorAction Stop; "OK   $($a.Name)" | Out-File $log -Append -Encoding utf8 }
      catch { "FAIL $($a.Name): $($_.Exception.Message)" | Out-File $log -Append -Encoding utf8 }
    }
  }
} catch { "ERROR: $($_.Exception.Message)" | Out-File $log -Append -Encoding utf8 }
"[$(Get-Date)] regshell done" | Out-File $log -Append -Encoding utf8
'@
  Set-Content -Path (Join-Path $winDrive 'antimal-regshell.ps1') -Value $reg -Encoding UTF8 -Force
  Note "wrote C:\antimal-regshell.ps1 (dependency-first, no CiTool, never hangs)"

} finally {
  # --- 6. Cleanup + dismount ----------------------------------------------
  Write-Host "[6/6] Dismounting..."
  foreach ($c in $cleanup) { try { Remove-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $c[0] -AccessPath $c[1] -ErrorAction SilentlyContinue } catch {} }
  Dismount-DiskImage -ImagePath $base | Out-Null
}

Write-Host ""
Write-Host "DONE. Base backup: $bak" -ForegroundColor Green
Write-Host "Next: COLD-boot the BASE (not the seed) once to a settled desktop, then re-snapshot." -ForegroundColor Yellow
Write-Host "  Keep this script's output for troubleshooting. To revert: delete the base and rename the .bak back, OR rename the .cip.disabled files back to .cip." -ForegroundColor Yellow
