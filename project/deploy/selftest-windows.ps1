# Check on this Windows machine the two things that need administrator rights, and undo both.
# Run from an elevated PowerShell, from the repository:   .\deploy\selftest-windows.ps1
#
#  1. Fleet blocking: adds the "Garrett fleet block" firewall rules for one public test address (1.0.0.1), checks
#     that a connection to it is refused, removes the rules and checks that it connects again.
#  2. The installer: starts a local evaluation service (in memory, this machine only), installs garrett as SYSTEM
#     in report mode (it only watches), checks that it reports, then uninstalls it. Needs Node.js 22.5 or newer
#     and the agent built in this checkout (cd rust; cargo build --release --locked); without them, this part is
#     skipped and says so.
# Results are printed and written to selftest-windows.log beside this file's repository root.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell.' }
$root = Split-Path -Parent $PSScriptRoot
$log = Join-Path $root 'selftest-windows.log'
Set-Content -Path $log -Value ('garrett Windows self-test ' + (Get-Date -Format s)) -Encoding utf8
function Say([string]$text) { Write-Output $text; Add-Content -Path $log -Value $text -Encoding utf8 }
function Reaches([string]$address) {
  $client = New-Object Net.Sockets.TcpClient
  try { $wait = $client.BeginConnect($address, 80, $null, $null); $ok = $wait.AsyncWaitHandle.WaitOne(4000) -and $client.Connected; return $ok } catch { return $false } finally { $client.Close() }
}

# ---- 1. fleet blocking: the same two firewall rules the agent adds and removes
function Block([string[]]$list) {
  & netsh advfirewall firewall delete rule name="Garrett fleet block" | Out-Null
  $done = $true
  foreach ($direction in $(if ($list.Count) { 'out', 'in' } else { @() })) {
    & netsh advfirewall firewall add rule name="Garrett fleet block" "dir=$direction" action=block ("remoteip=" + ($list -join ',')) | Out-Null
    $done = ($LASTEXITCODE -eq 0) -and $done
  }
  $global:LASTEXITCODE = 0
  return $done
}
$before = Reaches '1.0.0.1'
$applied = Block @('1.0.0.1')
$rules = @(Get-NetFirewallRule -DisplayName 'Garrett fleet block' -ErrorAction SilentlyContinue).Count
$during = Reaches '1.0.0.1'
$removed = Block @()
$left = @(Get-NetFirewallRule -DisplayName 'Garrett fleet block' -ErrorAction SilentlyContinue).Count
$after = Reaches '1.0.0.1'
Say ("BLOCKING: before reachable=$before | block said $applied, rules=$rules | while blocked reachable=$during | unblock said $removed, rules left=$left | after reachable=$after")
Say ('BLOCKING RESULT: ' + $(if ($before -and -not $during -and $after -and $rules -eq 2 -and $left -eq 0) { 'PASS' } elseif (-not $before) { 'INCONCLUSIVE (the test address was not reachable to begin with)' } else { 'FAIL' }))

# ---- 2. the installer
$built = Join-Path $root 'rust\target\release\garrett.exe'
$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not (Test-Path $built)) { Say 'INSTALLER: skipped. Build the agent first: cd rust; cargo build --release --locked' }
elseif (-not $node) { Say 'INSTALLER: skipped, node.exe was not found.' }
else {
  $bytes = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
  $enroll = $hex.Substring(0, 48); $admin = $hex.Substring(48, 48)
  $env:SENTINEL_ENROLL_KEY = $enroll; $env:SENTINEL_ADMIN_TOKEN = $admin; $env:SENTINEL_RESPONSE_MODE = 'report'; $env:SENTINEL_WATCHLIST = 'off'; $env:SENTINEL_TOR_EXITS = 'off'
  $service = Start-Process -FilePath $node -ArgumentList 'local.mjs', '48991' -WorkingDirectory (Join-Path $root 'server') -WindowStyle Hidden -PassThru
  try {
    Start-Sleep -Seconds 3
    & (Join-Path $PSScriptRoot 'install-windows.ps1') -Server 'http://127.0.0.1:48991' -EnrollKey $enroll -Mode report | Out-Null
    Start-Sleep -Seconds 20
    $task = Get-ScheduledTask -TaskName 'garrett'
    $devices = (Invoke-RestMethod -Uri 'http://127.0.0.1:48991/v1/devices' -Headers @{ Authorization = "Bearer $admin" }).devices
    $map = (Invoke-RestMethod -Uri 'http://127.0.0.1:48991/v1/coverage' -Headers @{ Authorization = "Bearer $admin" }).devices
    $seen = $map | Select-Object -First 1
    Say ("INSTALLER: task state=$($task.State), runs as $($task.Principal.UserId) | watching=$($devices[0].watching), programs seen=$($devices[0].summary.processes) | administrator sight=$($seen.sees.privileged), Security log=$($seen.sees.directory_log) | gaps=$(@($seen.gaps).Count)")
    Say ('INSTALLER RESULT: ' + $(if ($task.State -eq 'Running' -and $devices[0].watching -and $devices[0].summary.processes -gt 0 -and $seen.sees.privileged) { 'PASS' } else { 'FAIL' }))
  } catch { Say ('INSTALLER RESULT: FAIL: ' + $_.Exception.Message) }
  finally {
    try { & (Join-Path $PSScriptRoot 'uninstall-windows.ps1') | Out-Null; Say ('UNINSTALL: task left=' + @(Get-ScheduledTask -TaskName 'garrett' -ErrorAction SilentlyContinue).Count + ', folders left=' + @((Join-Path $env:ProgramFiles 'garrett'), (Join-Path $env:ProgramData 'garrett') | Where-Object { Test-Path $_ }).Count) } catch { Say ('UNINSTALL: FAIL: ' + $_.Exception.Message) }
    Stop-Process -Id $service.Id -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SENTINEL_ENROLL_KEY, Env:SENTINEL_ADMIN_TOKEN, Env:SENTINEL_RESPONSE_MODE, Env:SENTINEL_WATCHLIST, Env:SENTINEL_TOR_EXITS -ErrorAction SilentlyContinue
  }
}
Say 'Done.'
