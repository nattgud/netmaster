"""Tray icon for Windows: shows whether NetMaster runs, opens the app, shows the setup code, starts and
stops the background task, and turns autostart on or off.

The icon runs as the logged-in user. NetMaster itself runs as a scheduled task under SYSTEM, so starting,
stopping and autostart go through scripts/service.ps1 with a UAC prompt.
Started by scripts/tray.pyw (with pythonw.exe, so there is no console window).
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import ssl
import subprocess
import threading
import time
import urllib.request
import webbrowser
import winreg
import xml.etree.ElementTree as ET
from pathlib import Path

import pystray
from PIL import Image

from .config import DATA_DIR, ROOT

TASK = "NetMaster"
RUN_NAME = "NetMaster tray"
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
NO_WINDOW = 0x08000000
log = logging.getLogger("netmaster.tray")


def _settings() -> dict:
    try:
        return json.loads((DATA_DIR / "settings.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _base_url() -> str:
    s = _settings()
    scheme = "https" if s.get("https_cert") and s.get("https_key") else "http"
    return f"{scheme}://localhost:{s.get('http_port') or 8000}"


def _get(path: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # our own server on this computer
    with urllib.request.urlopen(_base_url().replace("localhost", "127.0.0.1") + path, timeout=3, context=ctx) as r:
        return json.loads(r.read())


def _task_state() -> tuple[bool, bool | None]:
    """(task exists, autostart on). Autostart is None if the task cannot be read."""
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK, "/XML"], capture_output=True, creationflags=NO_WINDOW)
    if r.returncode:
        return False, None
    try:
        xml = r.stdout.decode("utf-16") if r.stdout[:2] in (b"\xff\xfe", b"\xfe\xff") else r.stdout.decode("utf-8", "replace")
        root = ET.fromstring(xml.strip())
        ns = {"t": root.tag.split("}")[0].strip("{")}
        triggers = root.find("t:Triggers", ns)
        if triggers is None or not len(triggers):
            return True, False
        return True, any((t.findtext("t:Enabled", "true", ns) or "true").lower() == "true" for t in triggers)
    except ET.ParseError:
        return True, None


def _tray_autostart() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY) as k:
            data, _ = winreg.QueryValueEx(k, RUN_NAME)
            return not (data and data[0] & 1)  # 02 = on, 03 = turned off by the user
    except OSError:
        return True


def _set_tray_autostart(on: bool) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY) as k:
        winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_BINARY, bytes([2 if on else 3]) + bytes(11))


def _elevated(action: str) -> None:
    script = ROOT / "scripts" / "service.ps1"
    args = f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}" -Action {action}'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", args, str(ROOT), 0)


class Tray:
    def __init__(self):
        img = Image.open(ROOT / "web" / "icons" / "icon-192.png").convert("RGBA").resize((64, 64))
        self.img_on = img
        grey = img.convert("LA").convert("RGBA")
        grey.putalpha(img.getchannel("A").point(lambda a: a * 0.6))
        self.img_off = grey
        self.running = False
        self.code = ""
        self.task_exists, self.autostart = False, None
        self.busy_until = 0.0
        self.notified_code = False
        self.icon = pystray.Icon("NetMaster", self.img_off, "NetMaster", self._menu())

    # ---------- menu ----------
    def _menu(self):
        M = pystray.MenuItem
        return pystray.Menu(
            M(lambda _: self._status_text(), None, enabled=False),
            M("Open NetMaster", self.open_app, default=True),
            M(lambda _: f"Setup code: {self.code} (click to copy)", self.copy_code, visible=lambda _: bool(self.code)),
            pystray.Menu.SEPARATOR,
            M("Start NetMaster", lambda: self.service("start"), visible=lambda _: self.task_exists and not self.running),
            M("Stop NetMaster", lambda: self.service("stop"), visible=lambda _: self.task_exists and self.running),
            M("Restart NetMaster", lambda: self.service("restart"), visible=lambda _: self.task_exists and self.running),
            M("Start NetMaster with Windows", self.toggle_autostart, checked=lambda _: bool(self.autostart),
              enabled=lambda _: self.task_exists and self.autostart is not None),
            M("Show this icon at login", self.toggle_tray, checked=lambda _: _tray_autostart()),
            pystray.Menu.SEPARATOR,
            M("Close this icon", self.quit),
        )

    def _status_text(self) -> str:
        if time.time() < self.busy_until:
            return "NetMaster: working…"
        if self.running:
            return "NetMaster is running" + (" (waiting for a password)" if self.code else "")
        return "NetMaster is stopped" if self.task_exists else "NetMaster is not installed as a service"

    # ---------- actions ----------
    def open_app(self, *_):
        webbrowser.open(_base_url())

    def copy_code(self, *_):
        subprocess.run(["clip"], input=self.code.encode("ascii"), creationflags=NO_WINDOW)
        self.icon.notify(f"Setup code {self.code} copied. Enter it when you open NetMaster on another device.", "NetMaster")

    def service(self, action: str):
        self.busy_until = time.time() + 15
        _elevated(action)
        self.icon.update_menu()

    def toggle_autostart(self, *_):
        self.service("autostart-off" if self.autostart else "autostart-on")

    def toggle_tray(self, *_):
        _set_tray_autostart(not _tray_autostart())
        self.icon.update_menu()

    def quit(self, *_):
        self.icon.stop()

    # ---------- status ----------
    def poll(self):
        last_task = 0.0
        while True:
            try:
                st = _get("/api/auth/state")
                self.running = True
                self.code = _get("/api/auth/setup-code").get("code", "") if st.get("setup_needed") else ""
            except Exception:
                self.running, self.code = False, ""
            if time.time() - last_task > 10 or time.time() < self.busy_until:
                self.task_exists, self.autostart = _task_state()
                last_task = time.time()
            if self.code and not self.notified_code:
                self.notified_code = True
                self.icon.notify(f"Open NetMaster to choose a password. Setup code for other devices: {self.code}",
                                 "NetMaster")
            self.icon.icon = self.img_on if self.running else self.img_off
            self.icon.title = self._status_text()
            self.icon.update_menu()
            time.sleep(3)

    def run(self):
        threading.Thread(target=self.poll, daemon=True).start()
        self.icon.run()


def main() -> None:
    logdir = Path(os.environ.get("LOCALAPPDATA", ROOT)) / "NetMaster"
    logdir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=logdir / "tray.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # One icon per user.
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\NetMasterTray")
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return
    try:
        Tray().run()
    except Exception:
        log.exception("tray crashed")
        raise


if __name__ == "__main__":
    main()
