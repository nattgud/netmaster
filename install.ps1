# Installs or updates NetMaster from the latest GitHub release. Run in PowerShell:
#   irm https://raw.githubusercontent.com/nattgud/netmaster/main/install.ps1 | iex
# Optional: set $env:NETMASTER_DIR first to pick another folder (default: Program Files\NetMaster,
# or the folder of an existing install).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = 'nattgud/netmaster'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host 'NetMaster needs administrator rights to install. Accept the Windows prompt...'
    $self = Join-Path $env:TEMP 'netmaster-install.ps1'
    Invoke-RestMethod "https://raw.githubusercontent.com/$repo/main/install.ps1" -OutFile $self
    $envArg = if ($env:NETMASTER_DIR) { "`$env:NETMASTER_DIR='$env:NETMASTER_DIR'; " } else { '' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit',
        '-Command', "$envArg& '$self'"
    return
}

# Where to install: an existing NetMaster task wins, so updates land in the same place.
$dest = $env:NETMASTER_DIR
if (-not $dest) {
    $task = Get-ScheduledTask -TaskName 'NetMaster' -ErrorAction SilentlyContinue
    if ($task -and $task.Actions[0].WorkingDirectory) { $dest = $task.Actions[0].WorkingDirectory }
    else { $dest = Join-Path $env:ProgramFiles 'NetMaster' }
}
Write-Host "==> Installing NetMaster to $dest" -ForegroundColor Cyan

$tmp = Join-Path $env:TEMP "netmaster-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Write-Host '==> Downloading the latest release' -ForegroundColor Cyan
    $zip = Join-Path $tmp 'NetMaster.zip'
    Invoke-WebRequest "https://github.com/$repo/releases/latest/download/NetMaster.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive $zip (Join-Path $tmp 'x')

    # Stop the running version before files are replaced.
    Stop-ScheduledTask -TaskName 'NetMaster' -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*-m netmaster*' -or $_.CommandLine -like '*tray.pyw*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

    # Replace the code. data\, .venv and config.toml are kept.
    New-Item -ItemType Directory -Force $dest | Out-Null
    foreach ($d in 'netmaster', 'web', 'scripts') { Remove-Item -Recurse -Force (Join-Path $dest $d) -ErrorAction SilentlyContinue }
    Copy-Item (Join-Path $tmp 'x\*') $dest -Recurse -Force

    & (Join-Path $dest 'scripts\install-service.ps1')
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
