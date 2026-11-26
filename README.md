# NetMaster

NetMaster watches your home network for **disruptions** and **intruders**, and alerts you in a web app (PWA) that works on both computers and phones. It runs on an always-on Windows computer in your home.

## What it does

| Area | How |
|---|---|
| Internet and router | Pings the main router and several internet targets. Tells "the router is unreachable" apart from "the internet is down", and one outage gives one alert, not five. |
| Access points | Pings every router and access point you list, and logs short freezes. |
| DNS | Asks the router's DNS and public DNS directly (bypassing the Windows cache) and alerts when lookups get slow or fail. |
| Call quality | Measures delay, jitter and packet loss every second, the things that make video calls stutter. |
| Speed | Short, light speed tests against Cloudflare, with a 24 h graph. |
| Device inventory | Finds every device (ARP via Npcap, otherwise a UDP sweep and the ARP table) with vendor and name. Devices seen during the first 30 minutes count as known; after that every new device raises an alert until you approve it. |
| Investigate | Finds out what an unknown device is: names, mDNS, UPnP, NetBIOS and open ports. |
| ARP spoofing and rogue DHCP | Learns the main router's MAC and alerts if someone else answers for its IP. Probes for rogue DHCP servers (needs Npcap). |
| DNS tampering | Checks that well-known names give the right answers and that made-up names are not redirected. |
| Exposure | Scans your devices for risky open ports, and checks what the internet can see on your public IP (Shodan InternetDB). |
| Programs on the server | Shows which programs on the NetMaster computer use the internet and where they connect, on a map (needs Npcap). |
| Router logs | Optional syslog receiver that turns logins, attacks, WAN drops, reboots and changed settings into events. |
| Notifications | Web Push to phones and computers, even when the app is closed. Every kind can be turned on or off. |
| Modules | Support for specific routers and services (TP-Link, NETGEAR, AdGuard Home, Home Assistant, Jellyfin ...) is installed from a built-in marketplace. See [modules/README.md](modules/README.md). |
| Home Assistant | The *Home Assistant (MQTT)* module sends security alerts (one fixed `event_type` per alert type, plus device triggers for the automation editor), the number of unknown devices, and the devices you pick (presence, IP, MAC, top 3 sites and an Internet pause switch) through your MQTT broker. |

The app is in English, Swedish, Chinese, Hindi, Spanish, Arabic and French (Settings → Account → Language).

## Install (Windows)

Pick one. Both install the same thing, and both can be run again to update (your data and settings are kept).

**A. Setup program.** Download `NetMaster-Setup.exe` from the [latest release](https://github.com/nattgud/netmaster/releases/latest) and run it.

**B. One line in PowerShell.**

```powershell
irm https://raw.githubusercontent.com/nattgud/netmaster/main/install.ps1 | iex
```

It asks for administrator rights, downloads the latest release to `C:\Program Files\NetMaster` (or the folder of an existing install; set `$env:NETMASTER_DIR` first to choose another) and runs the setup.

What the setup does:

- installs Python 3.13 with winget if no Python 3.11+ is found, creates `.venv` and installs the requirements
- opens the syslog port in the firewall (private networks only)
- registers a scheduled task **NetMaster** that starts with Windows, runs without anyone logged in and restarts itself if it crashes
- adds the **tray icon** and starts it at login
- turns off sleep on AC power (skip with `-KeepSleep` when running `scripts\install-service.ps1` by hand)
- prints the **setup code** at the end (see below)

Optional but recommended: install [Npcap](https://npcap.com) for real-time ARP/DHCP protection and per-program traffic, then run the setup again.

### The tray icon

The NetMaster icon in the taskbar corner shows whether NetMaster runs. Its menu can:

- open NetMaster in the browser
- show the setup code (click to copy) until a password is set
- start, stop and restart NetMaster (asks for administrator rights)
- turn **Start NetMaster with Windows** on or off
- turn **Show this icon at login** on or off (per user)

Closing the icon does not stop NetMaster. Start it again from the Start menu (*NetMaster tray icon*).

### From source

```powershell
git clone https://github.com/nattgud/netmaster C:\NetMaster
powershell -ExecutionPolicy Bypass -File C:\NetMaster\scripts\install-service.ps1   # as administrator
```

Uninstall with *Add or remove programs* (Setup.exe) or `scripts\uninstall-service.ps1`. The `data` folder is kept; delete it to remove everything. Logs are in `data\netmaster.log` and `data\supervisor.log`.

To run it by hand (for troubleshooting, with the task stopped):

```powershell
.venv\Scripts\python.exe -m netmaster
```

### Releases

Push a tag such as `v1.0.0`. The *Release* workflow builds `NetMaster-Setup.exe` (Inno Setup) and `NetMaster.zip` and publishes them.

## First start

Open **http://localhost:8000** on the NetMaster computer. You choose a password, and a short guide helps you check the network settings, install modules for your routers and services, and choose how to reach NetMaster from other devices.

Opening it from another device before a password is set asks for a setup code. The setup prints it at the end, and the tray icon shows it (it is also in `data\setup-code.txt`). Forgot the password? Run `python -m netmaster set-password` on that computer.

## Reaching NetMaster from your phone

Pick one (the guide can set up the first two):

- **Only this computer** (default, safest): NetMaster listens on `127.0.0.1`. Use one of the options below to reach it from elsewhere.
- **Your home network:** set *Listen on address* to `0.0.0.0` (Settings → General → Server). Open `http://<computer-ip>:8000` on your phone while at home. NetMaster opens the firewall for private networks only. Push notifications on phones need HTTPS, so they don't work this way.
- **Tailscale** (free, optional): reach NetMaster from anywhere with HTTPS and notifications. Install Tailscale on the computer and your phone, then press *Publish with Tailscale* in the guide, or run `tailscale serve --bg 8000`.
- **Your own reverse proxy or certificate:** point a reverse proxy (Caddy, nginx, IIS ...) at `127.0.0.1:8000`, or set *HTTPS certificate file* and *HTTPS key file* in Settings.

On the phone, choose **Add to Home Screen** (on iPhone this is needed for notifications, iOS 16.4 or later), then press **Enable notifications** in the app.

## Router logs (optional)

Modules read logs straight from supported routers. Any router that can send syslog can also send its log to the NetMaster computer, UDP port 5140 by default (Settings → General → Server). Give the NetMaster computer a fixed address (DHCP reservation) in your router first. Everything that comes in shows on the **Logs** tab. The rules in `netmaster/rules.py` turn known lines into events.

## Data and privacy

Everything stays on your computer, in `data/`: the SQLite database (`netmaster.db`), settings (`settings.json`), module settings (`modules.json`), module passwords (`secrets.json`), installed modules (`modules/`) and the push key (`vapid_private.pem`). Outside requests: the vendor list (wireshark.org, monthly), IP locations (ip-api.com), exposure lookups (Shodan InternetDB), speed tests (Cloudflare), and module downloads from the module source.

## Layout

```
netmaster/     the server (FastAPI)
  app.py         REST, WebSocket, login and static files
  modules.py     module marketplace, installer and runner
  sdk.py         what modules can use (see modules/README.md)
  auth.py        password, sessions and rate limiting
  config.py      settings (data/settings.json)
  monitors.py    ping and DNS monitoring
  inventory.py   devices and ARP protection
  guards.py      DHCP and DNS protection
  insights.py    traffic, port scans, exposure, speed tests, services, Wi-Fi
  hostflows.py   programs on the server that use the internet
  investigate.py "what is this device?"
  push.py        Web Push
  tray.py        the Windows tray icon
  syslog.py, rules.py   syslog receiver and log rules
web/           the PWA (plain JavaScript, no build step); translations in web/i18n/strings.tsv
modules/       the module marketplace (index.json + one folder per module), served straight from this repo
scripts/       install-service.ps1, uninstall-service.ps1, run.ps1, service.ps1, tray.pyw, build_module_index.py
installer/     Inno Setup script for NetMaster-Setup.exe
install.ps1    the one-line installer
```

## Translations

`web/i18n/strings.tsv` has one row per English text and one column per language. Text that is missing a translation is shown in English. To add a language, add a column and an entry in `LANGS` in `web/i18n.js`.
