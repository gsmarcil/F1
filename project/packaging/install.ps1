# Install garrett on this Windows machine from the published release bundle.
# From an elevated PowerShell:
#   irm https://gary23w.github.io/sentinels/install.ps1 | iex
# To join a fleet as well, set these first in the same window:
#   $env:GARRETT_SERVER = 'https://your-service'; $env:GARRETT_KEY = '<enrolment key>'
# It downloads garrett-windows.zip, checks it against the published SHA-256, and runs its installer.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell.' }
$base = if ($env:GARRETT_BASE) { $env:GARRETT_BASE } else { 'https://gary23w.github.io/sentinels' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('garrett-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $zip = Join-Path $work 'garrett-windows.zip'
  Invoke-WebRequest -UseBasicParsing -Uri "$base/garrett-windows.zip" -OutFile $zip
  # The checksum list is served as plain bytes, which Windows PowerShell hands back as a byte array, not text.
  $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content
  if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
  $want = ($sums -split "`n" | Where-Object { $_ -match ' garrett-windows\.zip\s*$' }) -replace '\s.*$', ''
  $have = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
  if (-not $want -or $want -ne $have) { throw 'The download does not match its published checksum. Nothing was installed.' }
  Expand-Archive -Path $zip -DestinationPath $work
  $arguments = @{}
  if ($env:GARRETT_SERVER) { $arguments.Server = $env:GARRETT_SERVER; $arguments.EnrollKey = $env:GARRETT_KEY }
  if ($env:GARRETT_MODE) { $arguments.Mode = $env:GARRETT_MODE }
  & (Join-Path $work 'garrett\deploy\install-windows.ps1') @arguments
} finally { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
