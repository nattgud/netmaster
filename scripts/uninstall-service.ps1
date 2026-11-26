#Requires -RunAsAdministrator
# Removes the NetMaster background task and its firewall rules. The folder and database (data\) are kept.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot

Stop-ScheduledTask -TaskName 'NetMaster' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'NetMaster' -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*-m netmaster*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like '*tray.pyw*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'NetMaster tray' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'NetMaster syslog' -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName 'NetMaster web *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Write-Host 'NetMaster is uninstalled. Sleep settings were not restored; change them in Power settings if needed.'
Write-Host 'If you published it with Tailscale: tailscale serve reset'
