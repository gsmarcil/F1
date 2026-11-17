# garrett-service: your own Sentinel service on this Windows machine.
#
#   garrett-service.ps1 install [-Port 8443] [-Address <name or address other machines reach this one by>]
#   garrett-service.ps1 join       the commands that join other machines to this service
#   garrett-service.ps1 devices    the machines that report here
#   garrett-service.ps1 cases      the open cases
#   garrett-service.ps1 token      the operator token, for the API described in the README
#   garrett-service.ps1 remove     remove the service, its keys and its database
#
# Installed, the same commands are:  "C:\Program Files\garrett-service\garrett-service.cmd" join
# The service runs at startup as LOCAL SERVICE (a scheduled task named "garrett-service"), with the official
# Node.js from nodejs.org beside it, its own HTTPS certificate, and one inbound firewall rule for its port.
# Installing again upgrades the program and keeps the keys, the certificate and the database.
param(
  [ValidateSet('install', 'join', 'devices', 'cases', 'token', 'remove')][string]$Command = 'install',
  [int]$Port = 0,
  [string]$Address = ''
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell.' }
$nodeVersion = 'v24.22.3'
$nodeSum = '86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6'
$base = if ($env:GARRETT_BASE) { $env:GARRETT_BASE } else { 'https://gary23w.github.io/sentinels' }
$install = Join-Path $env:ProgramFiles 'garrett-service'
$data = Join-Path $env:ProgramData 'garrett-service'
$conf = Join-Path $data 'service.conf'
$node = Join-Path $install 'node.exe'

function Get-Setting([string]$name) {
  $found = Get-Content $conf | Where-Object { $_ -match ('^' + $name + '=') } | Select-Object -Last 1
  if ($found) { return $found.Substring($name.Length + 1) }
  return ''
}
function New-Key { $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); return -join ($bytes | ForEach-Object { $_.ToString('x2') }) }
function Invoke-Service([string]$path) { & $node --disable-warning=ExperimentalWarning (Join-Path $install 'ask.mjs') $conf $path }
function Show-Join {
  $pem = (Get-Content (Join-Path $data 'tls.crt') | Where-Object { $_ -notmatch '^-----' }) -join ''
  $pin = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Convert]::FromBase64String($pem)) | ForEach-Object { $_.ToString('x2') })
  $server = 'https://' + (Get-Setting 'ADDRESS') + ':' + (Get-Setting 'PORT')
  $key = (Get-Setting 'ENROLL_KEY') + '.' + $pin
  Write-Output 'Join a Linux or macOS machine (run on that machine):'
  Write-Output ''
  Write-Output "  curl -fsSL $base/install.sh | sudo sh -s -- --server $server --key $key"
  Write-Output ''
  Write-Output 'Join a Windows machine (elevated PowerShell on that machine):'
  Write-Output ''
  Write-Output "  `$env:GARRETT_SERVER='$server'; `$env:GARRETT_KEY='$key'; irm $base/install.ps1 | iex"
  Write-Output ''
  Write-Output 'Anyone who has these commands can add a machine to your service, so keep them private.'
  Write-Output "Machines must be able to reach $server. If they know this machine by another name or address, edit ADDRESS in $conf and run join again."
  Write-Output ('See what they report:  "' + (Join-Path $install 'garrett-service.cmd') + '" devices')
}

if ($Command -eq 'remove') {
  if (Get-ScheduledTask -TaskName 'garrett-service' -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName 'garrett-service' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'garrett-service' -Confirm:$false }
  Get-NetFirewallRule -DisplayName 'garrett-service' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Start-Sleep -Seconds 2
  if (Test-Path $data) { Remove-Item -Recurse -Force $data }
  if (Test-Path $install) {
    # This may be running from garrett-service.cmd in that folder, which cmd must still find when this returns:
    # everything else goes now, the folder itself a few seconds later.
    Get-ChildItem -Force $install | Where-Object { $_.Name -ne 'garrett-service.cmd' } | Remove-Item -Recurse -Force
    Start-Process cmd.exe -ArgumentList '/c', ('ping -n 3 127.0.0.1 >nul & rmdir /s /q "' + $install + '"') -WindowStyle Hidden -WorkingDirectory $env:SystemRoot
  }
  Write-Output 'The Sentinel service, its keys and its database were removed. Machines that reported to it protect themselves alone until they are enrolled somewhere else.'
  return
}
if ($Command -ne 'install') {
  if (-not (Test-Path $conf)) { throw 'The Sentinel service is not installed on this machine.' }
  switch ($Command) {
    'join' { Show-Join }
    'devices' { Invoke-Service '/v1/devices' }
    'cases' { Invoke-Service '/v1/cases?state=open' }
    'token' { Get-Setting 'ADMIN_TOKEN' }
  }
  return
}

# install
$here = $PSScriptRoot
if (Get-ScheduledTask -TaskName 'garrett-service' -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName 'garrett-service' -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
New-Item -ItemType Directory -Force -Path $install, (Join-Path $install 'src'), $data | Out-Null
if ($here -ne $install) {
  Copy-Item -Force (Join-Path $here 'serve.mjs'), (Join-Path $here 'sqlite.mjs'), (Join-Path $here 'ask.mjs'), (Join-Path $here 'schema.sql'), (Join-Path $here 'LICENSE'), (Join-Path $here 'garrett-service.ps1') $install
  Copy-Item -Force (Join-Path $here 'src\*.mjs') (Join-Path $install 'src')
}
Set-Content -Path (Join-Path $install 'garrett-service.cmd') -Encoding ascii -Value ('@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $install 'garrett-service.ps1') + '" %*')
# Node.js: the official build from nodejs.org, checked against the SHA-256 this installer was published with.
if (-not (Test-Path $node) -or (Get-FileHash -Algorithm SHA256 $node).Hash.ToLower() -ne $nodeSum) {
  Write-Output "Fetching Node.js $nodeVersion from nodejs.org ..."
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $fetched = Join-Path $install 'node.download'
  Invoke-WebRequest -UseBasicParsing -Uri "https://nodejs.org/dist/$nodeVersion/win-x64/node.exe" -OutFile $fetched
  if ((Get-FileHash -Algorithm SHA256 $fetched).Hash.ToLower() -ne $nodeSum) { Remove-Item -Force $fetched; throw 'The Node.js download does not match its published checksum. Nothing was started.' }
  Move-Item -Force $fetched $node
}
# Only SYSTEM, Administrators and the account the service runs as may read its keys and database.
icacls $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null
if (-not (Test-Path $conf)) {
  if (-not $Address) { $Address = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress }
  if (-not $Address) { $Address = $env:COMPUTERNAME }
  if (-not $Port) { $Port = 8443 }
  # The service's own certificate. Machines are given its SHA-256 with the join command and accept no other.
  $passphrase = New-Key
  $certificate = New-SelfSignedCertificate -Subject 'CN=garrett-service' -DnsName 'localhost', 'garrett-service' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(10) -CertStoreLocation 'Cert:\LocalMachine\My'
  try {
    Export-PfxCertificate -Cert $certificate -FilePath (Join-Path $data 'tls.pfx') -Password (ConvertTo-SecureString $passphrase -AsPlainText -Force) | Out-Null
    Set-Content -Path (Join-Path $data 'tls.crt') -Encoding ascii -Value @('-----BEGIN CERTIFICATE-----', [Convert]::ToBase64String($certificate.RawData, 'InsertLineBreaks'), '-----END CERTIFICATE-----')
  } finally { Remove-Item -Force ('Cert:\LocalMachine\My\' + $certificate.Thumbprint) }
  Set-Content -Path $conf -Encoding ascii -Value @(
    '# The Sentinel service on this machine. Restart the scheduled task "garrett-service" after a change.',
    "PORT=$Port", "ADDRESS=$Address",
    ('DATABASE=' + (Join-Path $data 'sentinel.db')),
    ('TLS_PFX=' + (Join-Path $data 'tls.pfx')), "TLS_PASSPHRASE=$passphrase", ('TLS_CERT=' + (Join-Path $data 'tls.crt')),
    '# Lets a machine enrol. The join command carries it.', ('ENROLL_KEY=' + (New-Key)),
    '# Lets you read cases and decide. Keep it to yourself.', ('ADMIN_TOKEN=' + (New-Key)),
    '# Encrypts case evidence in the database. Lose it and stored evidence cannot be read.', ('DATA_KEY=' + (New-Key)),
    '# What machines do about a hostile program: kill (the default), pause or report. See the README for the rest.', 'RESPONSE_MODE=')
} else {
  # An upgrade keeps everything; only what was asked for on the command line changes.
  $lines = Get-Content $conf
  if ($Port) { $lines = $lines -replace '^PORT=.*', "PORT=$Port" }
  if ($Address) { $lines = $lines -replace '^ADDRESS=.*', "ADDRESS=$Address" }
  Set-Content -Path $conf -Encoding ascii -Value $lines
}
$Port = [int](Get-Setting 'PORT')
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount
$run = New-ScheduledTaskAction -Execute $node -Argument ('--disable-warning=ExperimentalWarning "' + (Join-Path $install 'serve.mjs') + '" "' + $conf + '"')
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'garrett-service' -Action $run -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings -Force | Out-Null
Get-NetFirewallRule -DisplayName 'garrett-service' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'garrett-service' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Program $node | Out-Null
Start-ScheduledTask -TaskName 'garrett-service'
$ready = $false
foreach ($attempt in 1..30) {
  Start-Sleep -Seconds 1
  $ErrorActionPreference = 'Continue'
  Invoke-Service '/v1/pulse' 2>$null | Out-Null
  $ErrorActionPreference = 'Stop'
  if ($LASTEXITCODE -eq 0) { $ready = $true; break }
}
if (-not $ready) { throw 'The service did not start. Look at the scheduled task "garrett-service" in Task Scheduler.' }
Write-Output ''
Write-Output 'Your Sentinel service is running on this machine.'
Write-Output ''
Show-Join
