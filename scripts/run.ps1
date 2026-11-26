# Runs NetMaster and restarts it automatically if the process exits.
# Started by the scheduled task "NetMaster" (see install-service.ps1).
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
$log = Join-Path $root 'data\supervisor.log'
New-Item -ItemType Directory -Force (Join-Path $root 'data') | Out-Null

Set-Location $root
while ($true) {
    Add-Content -Path $log -Value "$(Get-Date -Format s) starting NetMaster" -Encoding utf8
    & $python -m netmaster *> $null
    Add-Content -Path $log -Value "$(Get-Date -Format s) NetMaster exited (code $LASTEXITCODE), restarting in 10 s" -Encoding utf8
    Start-Sleep -Seconds 10
}
