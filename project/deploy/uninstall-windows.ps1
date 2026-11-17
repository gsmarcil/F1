# Remove garrett from this machine: the scheduled task, its firewall rules, its program folder and its credential.
# Run from an elevated PowerShell:   .\uninstall-windows.ps1
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell.' }
if (Get-ScheduledTask -TaskName 'garrett' -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName 'garrett' -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'garrett' -Confirm:$false
}
# Whatever addresses the agent refused are let through again.
& netsh advfirewall firewall delete rule name="Garrett fleet block" | Out-Null
$global:LASTEXITCODE = 0  # netsh reports "no rules matched" as a failure; having none to delete is not one
Start-Sleep -Seconds 2
foreach ($folder in (Join-Path $env:ProgramFiles 'garrett'), (Join-Path $env:ProgramData 'garrett')) {
  if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
}
Write-Output 'garrett was removed. If this machine was enrolled, remove it on the service as well: POST /v1/devices/<id>/revoke'
