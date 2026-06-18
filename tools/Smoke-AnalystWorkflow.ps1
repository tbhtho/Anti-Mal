<#
.SYNOPSIS
  End-to-end smoke test of the AntiMal HostCli analyst workflow (no VM/boot).

.DESCRIPTION
  Exercises the static + report-consuming CLI surface that unit tests can't reach
  (the CLI glue itself): simulate -> report --summary/--why/--crashes/--detections
  -> export (stix/misp/csv) -> yara-gen -> config -> triage. Asserts each stage
  produces the expected output. Pure host-side, no firmware/base/boot required.

  Exit codes 0 (clean), 1 (suspicious/no-config), and 10 (flagged) are all
  "command ran"; only exit 2 (usage/error) or a missing/unexpected output is a
  failure. Returns non-zero on any failed check (CI-gateable).

.PARAMETER Cli
  Path to AntiMal.HostCli.exe. Default: bin\x64\Release next to the repo root.
#>
param(
  [string]$Cli = (Join-Path $PSScriptRoot "..\bin\x64\Release\AntiMal.HostCli.exe")
)

$ErrorActionPreference = 'Stop'
$fail = 0
function Check($name, $cond) {
  if ($cond) { Write-Host "  [ok]   $name" }
  else { Write-Host "  [FAIL] $name" -ForegroundColor Red; $script:fail++ }
}

if (-not (Test-Path $Cli)) { Write-Error "HostCli not found: $Cli (build Release first)"; exit 2 }
$work = Join-Path $env:TEMP ("antimal-smoke-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $work | Out-Null
Write-Host "AntiMal analyst-workflow smoke test"
Write-Host "  cli:  $Cli"
Write-Host "  work: $work"

try {
  # 1) simulate -> a complete synthetic Any.Run-style report (no VM).
  $sim = Join-Path $work "sim"
  & $Cli simulate --scenario stealer --out $sim | Out-Null
  $report = Join-Path $sim "report.json"
  Check "simulate writes report.json" (Test-Path $report)
  Check "simulate writes report.html" (Test-Path (Join-Path $sim "report.html"))

  # 2) report views over the simulated run.
  $summary = (& $Cli report $report --summary --json) -join "`n"
  Check "report --summary --json emits schemaVersion" ($summary -match '"schemaVersion":1')
  Check "report --summary names a verdict" ($summary -match '"verdict":"malicious"')

  $why = (& $Cli report $report --why) -join "`n"
  Check "report --why prints a rationale" ($why -match 'Why:|SIMULATION')

  $det = (& $Cli report $report --detections) -join "`n"
  Check "report --detections lists detections" ($det -match 'Detections \(')

  & $Cli report $report --crashes | Out-Null
  Check "report --crashes runs (exit<>2)" ($LASTEXITCODE -ne 2)

  # 3) IOC export formats.
  foreach ($fmt in @('stix','misp','csv')) {
    $outF = Join-Path $work "ioc.$fmt"
    & $Cli export $report --format $fmt --out $outF | Out-Null
    Check "export --format $fmt writes output" ((Test-Path $outF) -and ((Get-Item $outF).Length -gt 0))
  }

  # 4) yara-gen on a real PE (the CLI itself).
  $yar = Join-Path $work "rule.yar"
  & $Cli yara-gen $Cli --out $yar | Out-Null
  Check "yara-gen writes a rule" (Test-Path $yar)
  Check "yara-gen rule is well-formed" (((Get-Content $yar -Raw) -match 'rule\s+\w+\s*\{') -and ((Get-Content $yar -Raw) -match 'condition:'))

  # 5) config on a synthetic base64-wrapped-RC4 sample (round-trips a real C2).
  function Rc4([byte[]]$k,[byte[]]$d){ $s=0..255;$j=0; for($i=0;$i -lt 256;$i++){$j=($j+$s[$i]+$k[$i%$k.Length])%256;$t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t}; $o=New-Object byte[] $d.Length;$x=0;$y=0; for($n=0;$n -lt $d.Length;$n++){$x=($x+1)%256;$y=($y+$s[$x])%256;$t=$s[$x];$s[$x]=$s[$y];$s[$y]=$t;$o[$n]=$d[$n] -bxor $s[($s[$x]+$s[$y])%256]}; return $o }
  $key='SmokeRc4Key12345'
  $cfg='url=http://smoke-c2.example/gate;port=4444'
  $b64=[Convert]::ToBase64String((Rc4 ([Text.Encoding]::ASCII.GetBytes($key)) ([Text.Encoding]::ASCII.GetBytes($cfg))))
  $sample=Join-Path $work "synthetic-rat.bin"
  $ms=New-Object IO.MemoryStream; $w=[Text.Encoding]::ASCII
  $ms.Write($w.GetBytes("benign filler header"),0,20);$ms.WriteByte(0)
  $ms.Write($w.GetBytes($key),0,$key.Length);$ms.WriteByte(0)
  $ms.Write($w.GetBytes($b64),0,$b64.Length);$ms.WriteByte(0)
  $ms.Write($w.GetBytes("trailing filler"),0,15)
  [IO.File]::WriteAllBytes($sample,$ms.ToArray())
  $conf = (& $Cli config $sample) -join "`n"
  Check "config recovers the synthetic RC4 C2" ($conf -match 'smoke-c2\.example')

  # 6) triage a folder (the bin dir) -> ranked output.
  $tri = (& $Cli triage (Split-Path $Cli) --no-yara --no-capa --no-die) -join "`n"
  Check "triage emits a ranked table" ($tri -match 'ranked by score')
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host ""
if ($fail -eq 0) { Write-Host "SMOKE PASS: all analyst-workflow checks green" -ForegroundColor Green; exit 0 }
else { Write-Host "SMOKE FAIL: $fail check(s) failed" -ForegroundColor Red; exit 1 }
