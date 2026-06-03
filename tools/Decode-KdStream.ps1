# Decode-KdStream.ps1 — offline decoder for a captured raw KD serial byte stream.
# Parses the KD wire framing so we can see exactly what each side sends and
# whether framing / checksum / trailer are valid (vs what kd.exe expects).
#
#   powershell -ExecutionPolicy Bypass -File tools\Decode-KdStream.ps1 -Path C:\AntiMalRuns\_kddump_to_dbg.bin -Max 40
param(
  [Parameter(Mandatory=$true)][string]$Path,
  [int]$Max = 40
)

$DATA_LEADER    = 0x30  # "0000"
$CONTROL_LEADER = 0x69  # "iiii"
$TRAILER        = 0xAA

$types = @{
  0='UNUSED'; 1='STATE_CHANGE32'; 2='STATE_MANIPULATE'; 3='DEBUG_IO';
  4='ACKNOWLEDGE'; 5='RESEND'; 6='RESET'; 7='STATE_CHANGE64';
  8='POLL_BREAKIN'; 9='TRACE_IO'; 10='CONTROL_REQUEST'; 11='FILE_IO'
}

if (-not (Test-Path $Path)) { Write-Host "MISSING: $Path"; exit 1 }
# Shared read so we can decode while the bridge still has the file open for write.
$fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$b = New-Object byte[] $fs.Length
[void]$fs.Read($b, 0, $b.Length)
$fs.Close()
Write-Host ("File: {0}  ({1} bytes)" -f $Path, $b.Length)

$i = 0; $n = $b.Length; $shown = 0; $stray = 0
$counts = @{}
$strayBytes = New-Object System.Collections.Generic.List[byte]

function IsLeader([byte[]]$buf, [int]$pos, [byte]$v) {
  if ($pos + 4 -gt $buf.Length) { return $false }
  return ($buf[$pos] -eq $v -and $buf[$pos+1] -eq $v -and $buf[$pos+2] -eq $v -and $buf[$pos+3] -eq $v)
}

while ($i -lt $n) {
  $isData = IsLeader $b $i $DATA_LEADER
  $isCtrl = IsLeader $b $i $CONTROL_LEADER
  if (-not ($isData -or $isCtrl)) {
    $stray++
    if ($strayBytes.Count -lt 64) { $strayBytes.Add($b[$i]) }
    $i++
    continue
  }
  # 16-byte header: leader(4) type(2) bytecount(2) packetid(4) checksum(4)
  if ($i + 16 -gt $n) { Write-Host ("  [truncated header at {0}]" -f $i); break }
  $type   = [BitConverter]::ToUInt16($b, $i+4)
  $bc     = [BitConverter]::ToUInt16($b, $i+6)
  $pktId    = [BitConverter]::ToUInt32($b, $i+8)
  $chk    = [BitConverter]::ToUInt32($b, $i+12)
  if ($types.ContainsKey([int]$type)) { $tname = $types[[int]$type] } else { $tname = "?$type" }
  if ($isData) { $kind = 'D' } else { $kind = 'C' }
  $key = $kind + ':' + $tname
  if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }

  $note = ""
  $adv = 16
  if ($isData) {
    # data + trailer; verify checksum = sum of data bytes
    if ($i + 16 + $bc + 1 -le $n) {
      $sum = 0
      for ($j = 0; $j -lt $bc; $j++) { $sum = ($sum + $b[$i+16+$j]) -band 0xFFFFFFFF }
      $trail = $b[$i+16+$bc]
      if ($sum -eq $chk) { $chkNote = 'OK' } else { $chkNote = ("BAD(calc=0x{0:X})" -f $sum) }
      if ($trail -eq $TRAILER) { $trlNote = 'OK' } else { $trlNote = ("0x{0:X2}" -f $trail) }
      $note = "chk:$chkNote trail:$trlNote"
      $adv = 16 + $bc + 1
    } else {
      $note = "DATA TRUNCATED (need $bc + trailer)"
      $adv = $n - $i
    }
  } else {
    $note = "(control)"
  }

  if ($shown -lt $Max) {
    Write-Host ("  @{0,-6} {1,-2} type={2,-16} bc={3,-5} id=0x{4:X8} chk=0x{5:X8} {6}" -f $i, $kind, $tname, $bc, $pktId, $chk, $note)
    $shown++
  }
  $i += $adv
}

Write-Host ""
Write-Host "=== packet-type counts ==="
$counts.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Key, $_.Value) }
Write-Host ("stray (non-leader) bytes: {0}" -f $stray)
if ($strayBytes.Count -gt 0) {
  Write-Host ("first stray bytes (hex): " + (($strayBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '))
}
