#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs NetMaster as a background task on this computer.

.DESCRIPTION
  1. Creates the Python environment (.venv) and installs the requirements.
  2. Opens the syslog port (UDP) in the firewall for router logs (private networks only).
  3. Registers the scheduled task "NetMaster", which starts at boot, runs as SYSTEM
     (no login needed) and restarts automatically if it crashes.
  4. Turns off sleep on AC power, so monitoring is not paused. Skip with -KeepSleep.

  Run it again after updates; it is safe to run several times.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1
#>
param(
    [switch]$KeepSleep,
    # Path to python.exe (3.11 or later). If left out, an installed Python is used (or installed with winget).
    [string]$Python,
    # Do not start the tray icon now (the Setup.exe starts it itself).
    [switch]$NoTrayStart
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
$taskName = 'NetMaster'

function Write-Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

# --- 1. Python ---
Write-Step 'Python environment'
function Test-Py([string[]]$cmd) {
    try { & $cmd[0] @($cmd | Select-Object -Skip 1) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null } catch { return $false }
    return -not $LASTEXITCODE
}
function Find-Python {
    if ($Python) { return , @($Python) }
    if ((Get-Command py -ErrorAction SilentlyContinue) -and (Test-Py @('py', '-3'))) { return , @('py', '-3') }
    $found = Get-ChildItem "$env:ProgramFiles\Python3*\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Directory.Name -replace '\D') } -Descending
    foreach ($f in $found) { if (Test-Py @($f.FullName)) { return , @($f.FullName) } }
    return $null
}
$basePy = $null
if (-not (Test-Path $venvPy)) {
    $basePy = Find-Python
    if (-not $basePy) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw 'Python 3.11 or later is missing. Install it from https://www.python.org and run this again.'
        }
        Write-Host 'Python is missing, installing Python 3.13 with winget...'
        winget install -e --id Python.Python.3.13 --scope machine --silent --accept-package-agreements --accept-source-agreements
        $basePy = Find-Python
        if (-not $basePy) { throw 'Python could not be installed. Install it from https://www.python.org and run this again.' }
    }
    if ($Python -and -not (Test-Py $basePy)) {
        throw "NetMaster needs Python 3.11 or later: $Python"
    }
}
function Invoke-BasePy { & $basePy[0] @($basePy | Select-Object -Skip 1) @args }
if (-not (Test-Path $venvPy)) {
    Invoke-BasePy -m venv (Join-Path $root '.venv')
    if ($LASTEXITCODE) { throw 'Could not create .venv' }
}
& $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE) { throw 'pip install failed' }
Write-Host "OK: $(& $venvPy --version)"

# --- Npcap (optional but recommended) ---
Write-Step 'Npcap'
if (Get-Service npcap -ErrorAction SilentlyContinue) {
    Write-Host 'OK: Npcap is installed (real-time protection against ARP spoofing and rogue DHCP servers).'
} else {
    Write-Warning ('Npcap is missing. NetMaster still works, but without real-time listening and the rogue ' +
        'DHCP server check. Install it from https://npcap.com and run this script again.')
}

# Ports come from NetMaster's own settings (data\settings.json, editable under Settings in the app).
Push-Location $root
$ports = & $venvPy -c 'from netmaster.config import load_config; c = load_config(); print(c.syslog_port, c.http_port)'
Pop-Location
$syslogPort, $httpPort = ($ports -split ' ') | ForEach-Object { [int]$_ }

# --- 2. Firewall ---
Write-Step "Firewall (UDP $syslogPort for router logs)"
$busy = Get-NetUDPEndpoint -LocalPort $syslogPort -ErrorAction SilentlyContinue |
    Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -ne 'python' }
if ($busy) {
    $who = (Get-Process -Id $busy[0].OwningProcess -ErrorAction SilentlyContinue).Path
    Write-Warning "UDP $syslogPort is already used by $who. Change the syslog port under Settings in the app."
}
$rule = Get-NetFirewallRule -DisplayName 'NetMaster syslog' -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -DisplayName 'NetMaster syslog' -Direction Inbound -Protocol UDP -LocalPort $syslogPort `
        -Action Allow -Profile Private | Out-Null
    Write-Host 'Rule created.'
} else {
    $rule | Set-NetFirewallRule -LocalPort $syslogPort
    Write-Host 'The rule already exists (port updated).'
}
$public = Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public'
if ($public) {
    Write-Warning (("The network '{0}' is marked Public, so the rule does not apply there. Switch it to Private with:`n" +
        "  Set-NetConnectionProfile -InterfaceAlias '{1}' -NetworkCategory Private") -f $public[0].Name, $public[0].InterfaceAlias)
}

# --- 3. Scheduled task ---
Write-Step "Scheduled task '$taskName'"
$runner = Join-Path $root 'scripts\run.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`"" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

$autostart = $true
$old = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($old) {
    # Keep the user's choice of "start with Windows" (set from the tray icon).
    $autostart = [bool]($old.Triggers | Where-Object { $_.Enabled })
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    # Stop any Python process left from the previous run.
    # (venv python starts the base Python as a child process, so match on the command line.)
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*-m netmaster*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'NetMaster network monitoring' -Force | Out-Null
if (-not $autostart) {
    $t = Get-ScheduledTask -TaskName $taskName
    foreach ($tr in $t.Triggers) { $tr.Enabled = $false }
    Set-ScheduledTask -InputObject $t | Out-Null
}
Start-ScheduledTask -TaskName $taskName
Write-Host ('The task is registered and started' + $(if ($autostart) { '.' } else { ' (autostart stays off).' }))

# --- Tray icon ---
Write-Step 'Tray icon'
$pyw = Join-Path $root '.venv\Scripts\pythonw.exe'
$trayScript = Join-Path $root 'scripts\tray.pyw'
$trayCmd = "`"$pyw`" `"$trayScript`""
# Close a running icon (it may be the old version).
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like '*tray.pyw*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
# Start at login for every user (each user can turn it off from the icon's menu).
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'NetMaster tray' -Value $trayCmd
Write-Host 'The icon starts when you log in.'
$desktopUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $NoTrayStart -and $desktopUser) {
    # Start it now on the desktop of the logged-in user, without admin rights (a one-time task).
    try {
        $once = 'NetMaster tray start'
        $a = New-ScheduledTaskAction -Execute $pyw -Argument "`"$trayScript`"" -WorkingDirectory $root
        $p = New-ScheduledTaskPrincipal -UserId $desktopUser -LogonType Interactive -RunLevel Limited
        $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
        Register-ScheduledTask -TaskName $once -Action $a -Principal $p -Settings $st -Force | Out-Null
        Start-ScheduledTask -TaskName $once
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName $once -Confirm:$false
        Write-Host "Started for $desktopUser (look in the taskbar corner)."
    } catch {
        Write-Warning "Could not start the icon now ($_). It starts at the next login."
    }
}

# --- 4. Sleep ---
if (-not $KeepSleep) {
    Write-Step 'Sleep'
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    Write-Host 'Sleep is turned off on AC power.'
}

# --- Check ---
Write-Step 'Check'
$ok = $false
foreach ($i in 1..20) {
    Start-Sleep -Seconds 1
    try { Invoke-RestMethod "http://127.0.0.1:$httpPort/api/auth/state" -TimeoutSec 2 | Out-Null; $ok = $true; break } catch {}
}
if ($ok) {
    Write-Host "NetMaster answers on http://localhost:$httpPort" -ForegroundColor Green
} else {
    Write-Warning "NetMaster does not answer yet. Look in $root\data\netmaster.log"
}

$ip = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
$code = $null
if ($ok) {
    try {
        $state = Invoke-RestMethod "http://127.0.0.1:$httpPort/api/auth/state" -TimeoutSec 3
        if ($state.setup_needed) { $code = (Invoke-RestMethod "http://127.0.0.1:$httpPort/api/auth/setup-code" -TimeoutSec 3).code }
    } catch {}
}
Write-Host @"

Done! Next steps:
  1. Open http://localhost:$httpPort on this computer, choose a password and follow the guide.
  2. Give this computer ($ip) a fixed address (DHCP reservation) in your router.
  3. Optional: let your router send its system log to $ip, port $syslogPort (UDP).
"@
if ($code) {
    Write-Host "`nSetup code: " -NoNewline
    Write-Host $code -ForegroundColor Yellow
    Write-Host 'You need it only if you set the password from another device. The tray icon shows it too.'
}
