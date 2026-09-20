<# Creates a fresh, identity-recorded UDF package image. Never launches its contents. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Source,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [string]$EntryPoint = 'Set-up.exe',
  [long]$MaxBytes = 20GB,
  [int]$MaxFiles = 100000
)
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\','/')
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if ($outputRoot.StartsWith($sourceRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or $outputRoot -eq $sourceRoot) { throw 'Output must be outside the source package.' }
if (Test-Path -LiteralPath $outputRoot) { throw 'Choose a fresh output directory; existing evidence is not overwritten.' }
if ($EntryPoint -notin @('Set-up.exe','setup.exe','Autoplay.exe','install.exe')) { throw 'Current guest ISO dispatch requires a recognized root installer name.' }
if (-not [IO.File]::Exists((Join-Path $sourceRoot $EntryPoint))) { throw 'The selected root entry point is missing.' }
$selectedByGuest = @('Set-up.exe','setup.exe','Autoplay.exe','install.exe') | Where-Object { [IO.File]::Exists((Join-Path $sourceRoot $_)) } | Select-Object -First 1
if ($selectedByGuest -ine $EntryPoint) { throw "Guest dispatch would choose $selectedByGuest rather than $EntryPoint; ambiguous package refused." }
if ($MaxBytes -le 0 -or $MaxFiles -le 0) { throw 'Package limits must be positive.' }
# Enumerate manually: reject links/junctions before traversing a directory.
$pending = [Collections.Generic.Stack[string]]::new()
$pending.Push($sourceRoot)
$files = [Collections.Generic.List[object]]::new()
$directories = [Collections.Generic.List[string]]::new()
[int]$entryCount = 0
[long]$total = 0
while ($pending.Count) {
  $directory = $pending.Pop()
  if ([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse directory refused: $directory" }
  foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
    if (++$entryCount -gt $MaxFiles) { throw 'Package exceeds configured entry limit.' }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse entry refused: $($item.FullName)" }
    if ($item.PSIsContainer) { $directories.Add($item.FullName.Substring($sourceRoot.Length + 1)); $pending.Push($item.FullName); continue }
    $relative = $item.FullName.Substring($sourceRoot.Length + 1)
    if ($relative.Contains(':')) { throw 'Alternate streams are not supported.' }
    $total += $item.Length
    if ($total -gt $MaxBytes -or $files.Count -ge $MaxFiles) { throw 'Package exceeds configured byte/file limit.' }
    $files.Add([pscustomobject]@{ path = $relative; bytes = $item.Length; sha256 = '' })
  }
}
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$snapshot = Join-Path $outputRoot 'contents'
New-Item -ItemType Directory -Path $snapshot | Out-Null
foreach ($directory in $directories) { [IO.Directory]::CreateDirectory((Join-Path $snapshot $directory)) | Out-Null }
foreach ($file in $files) {
  $original = Join-Path $sourceRoot $file.path
  $copy = Join-Path $snapshot $file.path
  [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($copy)) | Out-Null
  # Deny concurrent writes/deletion while copying this file. Copy bounded bytes.
  $reader = [IO.File]::Open($original, 'Open', 'Read', 'Read')
  try {
    if ($reader.Length -ne $file.bytes) { throw "Source changed during inventory: $original" }
    $writer = [IO.File]::Open($copy, 'CreateNew', 'Write', 'None')
    try { $reader.CopyTo($writer, 1048576); $writer.Flush($true) } finally { $writer.Dispose() }
  } finally { $reader.Dispose() }
  $file.sha256 = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
}
if (-not ('AntiMal.PackageImageWriter' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
namespace AntiMal {
 public static class PackageImageWriter {
  public static void Write(object value, string path, long expected) {
   IStream stream = (IStream)value;
   IntPtr count = Marshal.AllocHGlobal(4);
   try {
    using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
     byte[] buffer = new byte[1048576]; long total = 0;
     while (true) {
      stream.Read(buffer, buffer.Length, count);
      int read = Marshal.ReadInt32(count);
      if (read == 0) break;
      if (read < 0 || read > buffer.Length || total + read > expected) throw new IOException("Image stream exceeded its declared size.");
      output.Write(buffer, 0, read); total += read;
     }
     if (total != expected) throw new IOException("Incomplete image stream.");
     output.Flush(true);
    }
   } finally { Marshal.FreeHGlobal(count); }
  }
 }
}
'@
}
$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.ChooseImageDefaultsForMediaType(12)
$image.FileSystemsToCreate = 4 # UDF: preserves Unicode names and large files.
$image.VolumeName = 'ANTIMAL_PACKAGE'
$image.FreeMediaBlocks = [int][Math]::Ceiling(($MaxBytes + 256MB) / 2048)
$image.Root.AddTree($snapshot, $false)
$result = $image.CreateResultImage()
$iso = Join-Path $outputRoot 'package.iso'
[AntiMal.PackageImageWriter]::Write($result.ImageStream, $iso, [long]$result.TotalBlocks * 2048)
$manifest = [ordered]@{
  source = $sourceRoot; entryPoint = $EntryPoint; fileCount = $files.Count
  sourceBytes = $total; files = $files; directories = $directories; image = $iso
  imageSha256 = (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant()
  scope = 'Full unnamed-stream snapshot; no source code execution or deep static analysis. ACLs and alternate streams are not package payload.'
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputRoot 'manifest.json') -Encoding utf8
[pscustomobject]$manifest | Select-Object source,entryPoint,fileCount,sourceBytes,image,imageSha256 | ConvertTo-Json
