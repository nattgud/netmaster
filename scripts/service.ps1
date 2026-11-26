#Requires -RunAsAdministrator
# Controls the NetMaster background task. Used by the tray icon (which asks for admin rights through UAC).
#   start | stop | restart        run or stop NetMaster now
#   autostart-on | autostart-off  start NetMaster with Windows or not
param(
    [Parameter(Mandatory)][ValidateSet('start', 'stop', 'restart', 'autostart-on', 'autostart-off')][string]$Action
)
$ErrorActionPreference = 'Stop'
$taskName = 'NetMaster'

function Stop-NetMaster {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    # run.ps1 starts python as a child process; stop that too (but not the tray icon).
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*-m netmaster*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Set-Autostart([bool]$on) {
    $task = Get-ScheduledTask -TaskName $taskName
    foreach ($t in $task.Triggers) { $t.Enabled = $on }
    Set-ScheduledTask -InputObject $task | Out-Null
}

switch ($Action) {
    'start' { Start-ScheduledTask -TaskName $taskName }
    'stop' { Stop-NetMaster }
    'restart' { Stop-NetMaster; Start-Sleep -Seconds 2; Start-ScheduledTask -TaskName $taskName }
    'autostart-on' { Set-Autostart $true }
    'autostart-off' { Set-Autostart $false }
}
