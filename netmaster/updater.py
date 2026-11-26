"""Checks GitHub for a newer NetMaster release and updates in place.

The update runs as its own one-time scheduled task (SYSTEM), because it stops NetMaster on the way: it downloads
NetMaster.zip from that release, replaces netmaster/, web/ and scripts/ (data/ and .venv are kept) and runs
scripts/install-service.ps1, which installs new requirements and starts NetMaster again. Open apps reload
themselves when the new version answers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import __version__

log = logging.getLogger("netmaster.update")
REPO = "nattgud/netmaster"
CHECK_EVERY_S = 6 * 3600
ROOT = Path(__file__).resolve().parent.parent
UPDATE_TASK = "NetMaster update"

_SCRIPT = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dest = '{root}'
$log = Join-Path $dest 'data\update.log'
Start-Transcript -Path $log -Force | Out-Null
$tmp = Join-Path $env:TEMP "netmaster-update-$([guid]::NewGuid().ToString('N'))"
try {{
    New-Item -ItemType Directory -Force $tmp | Out-Null
    Write-Output 'Downloading NetMaster {version}'
    $zip = Join-Path $tmp 'NetMaster.zip'
    Invoke-WebRequest '{url}' -OutFile $zip -UseBasicParsing
    Expand-Archive $zip (Join-Path $tmp 'x')
    if (-not (Test-Path (Join-Path $tmp 'x\netmaster\__init__.py'))) {{ throw 'The download is not a NetMaster release' }}
    Write-Output 'Stopping NetMaster'
    Stop-ScheduledTask -TaskName 'NetMaster' -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*-m netmaster*' -or $_.CommandLine -like '*tray.pyw*' }} |
        ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}
    Start-Sleep 2
    Write-Output 'Replacing files'
    foreach ($d in 'netmaster', 'web', 'scripts') {{ Remove-Item -Recurse -Force (Join-Path $dest $d) -ErrorAction SilentlyContinue }}
    Copy-Item (Join-Path $tmp 'x\*') $dest -Recurse -Force
    & (Join-Path $dest 'scripts\install-service.ps1')
    Write-Output 'Done'
}} catch {{
    Write-Output "Update failed: $_"
    Start-ScheduledTask -TaskName 'NetMaster' -ErrorAction SilentlyContinue
}} finally {{
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
}}
"""


def _ver(v) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in str(v).lstrip("v").split("."))


class Updater:
    def __init__(self, events, data_dir: Path):
        self.events, self.data_dir = events, data_dir
        self.latest: dict | None = None   # {"version", "notes", "url", "published", "zip"}
        self.checked: float | None = None
        self.error: str | None = None
        self.updating: str | None = None  # the version being installed

    # The version we already told the user about, kept across restarts so each version gives one notification.
    def _told(self) -> str:
        try:
            return (self.data_dir / "update_notified.txt").read_text("utf-8").strip()
        except OSError:
            return ""

    def _set_told(self, version: str) -> None:
        try:
            (self.data_dir / "update_notified.txt").write_text(version, "utf-8")
        except OSError as e:
            log.info("Could not save update_notified.txt: %s", e)

    # ---------- checking ----------
    def _fetch(self) -> dict:
        req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest",
                                     headers={"User-Agent": "NetMaster", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            rel = json.loads(r.read(2_000_000))
        version = str(rel.get("tag_name") or "").lstrip("v")
        if not version:
            raise ValueError("The release has no version")
        zip_url = next((a.get("browser_download_url") for a in rel.get("assets") or []
                        if a.get("name") == "NetMaster.zip"), None)
        return {"version": version, "notes": (rel.get("body") or "")[:4000], "url": rel.get("html_url"),
                "published": rel.get("published_at"), "zip": zip_url}

    async def check(self) -> dict:
        try:
            self.latest = await asyncio.to_thread(self._fetch)
            self.error = None
        except Exception as e:
            self.error = f"Could not check for updates: {e}"
            log.info("%s", self.error)
        self.checked = time.time()
        if self.available and self._told() != self.latest["version"]:
            self._set_told(self.latest["version"])
            self.events.emit("system", "notice", f"NetMaster {self.latest['version']} is available",
                             f"You have {__version__}. Update under Settings → General.", "netmaster",
                             kind="netmaster_update")
        return self.status()

    async def run(self) -> None:
        await asyncio.sleep(30)  # let everything else start first
        while True:
            await self.check()
            await asyncio.sleep(CHECK_EVERY_S)

    @property
    def available(self) -> bool:
        return bool(self.latest) and _ver(self.latest["version"]) > _ver(__version__)

    @staticmethod
    def can_update() -> tuple[bool, str | None]:
        """Only a Windows install run by the NetMaster scheduled task can update itself."""
        if sys.platform != "win32":
            return False, "Automatic updates only work on Windows. Download the new version from GitHub."
        if not (ROOT / "scripts" / "install-service.ps1").exists():
            return False, "This copy has no install scripts. Update it the way you installed it."
        if (ROOT / ".git").exists():
            return False, "This is a git checkout (development copy). Update it with git."
        return True, None

    def status(self) -> dict:
        ok, why = self.can_update()
        return {"current": __version__, "latest": (self.latest or {}).get("version"), "available": self.available,
                "notes": (self.latest or {}).get("notes"), "url": (self.latest or {}).get("url"),
                "published": (self.latest or {}).get("published"), "checked": self.checked, "error": self.error,
                "can_update": ok, "why_not": why, "updating": self.updating}

    # ---------- updating ----------
    def start(self) -> None:
        ok, why = self.can_update()
        if not ok:
            raise ValueError(why)
        if not self.available:
            raise ValueError("You already have the latest version")
        if not self.latest.get("zip"):
            raise ValueError("The release has no NetMaster.zip")
        version = self.latest["version"]
        script = self.data_dir / "update.ps1"
        script.write_text(_SCRIPT.format(root=str(ROOT).replace("'", "''"), url=self.latest["zip"].replace("'", "''"),
                                         version=version, task=UPDATE_TASK), "utf-8-sig")
        ps = ("$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "
              f"'-NoProfile -ExecutionPolicy Bypass -File \"{script}\"'; "
              "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
              "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -AllowStartIfOnBatteries; "
              f"Register-ScheduledTask -TaskName '{UPDATE_TASK}' -Action $a -Principal $p -Settings $s -Force | Out-Null; "
              f"Start-ScheduledTask -TaskName '{UPDATE_TASK}'")
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True,
                           text=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode:
            raise RuntimeError(f"Could not start the update: {(r.stderr or r.stdout).strip()[-300:]}")
        self.updating = version
        self.events.emit("system", "info", f"Updating NetMaster to {version}",
                         "NetMaster restarts in a minute or two. Open pages reload by themselves.", "netmaster")
        log.info("Update to %s started", version)
