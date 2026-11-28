# NetMaster modules

This folder is the module marketplace. NetMaster reads `index.json` from the module source (Settings → General → Server → *Module source*), lists every module under Settings → Modules, and downloads a module when you press **Install**. Nothing here is installed by default.

Only install modules you trust: a module runs inside NetMaster with the same rights.

## Writing a module

A module is a folder whose name is its id (lowercase letters, digits and `_`):

```
modules/my_router/
    module.json
    module.py
```

### module.json

```json
{
  "id": "my_router",
  "name": "My router",
  "version": "1.0.0",
  "author": "You",
  "description": "One or two sentences shown in the marketplace.",
  "provides": ["logs"],
  "requires": ["some-pypi-package>=1.0"],
  "files": ["module.py"],
  "settings": [
    {"key": "host", "label": "Router IP address", "type": "text", "default": "", "help": "Leave empty to use the main router."},
    {"key": "password", "label": "Password", "type": "password"},
    {"key": "interval_s", "label": "Read every (seconds)", "type": "number", "default": 60}
  ]
}
```

- `provides`: what the module adds. `logs`, `router`, `dns`, `service` or `smart_home` (see below).
- `requires`: pip packages, installed into NetMaster's Python environment when the module is installed.
- `files`: the files to download. `module.py` must define a class called `Module`.
- `settings`: the form the user fills in. Types: `text`, `password`, `number`, `bool`, `select` (0.2.8+). Passwords are stored apart from other settings and never sent back to the browser.

### module.py

```python
from netmaster.sdk import ModuleBase, Busy


class Module(ModuleBase):
    async def run(self):
        while True:
            try:
                text = await self.ctx.to_thread(read_log, self.settings["host"] or self.ctx.gateway,
                                                self.settings["password"])
                for line in text.splitlines():
                    self.ctx.add_log(line, self.settings["host"] or self.ctx.gateway)
                self.ok()            # shows "working" in the Modules list
            except Busy:
                raise                # someone else is logged in: NetMaster waits and tries later
            except Exception as e:
                self.error(e)        # shown in the Modules list
            await self.ctx.sleep(float(self.settings["interval_s"]))

    def status(self) -> dict:
        return {}                    # optional extra info for the UI
```

Blocking work (HTTP, sockets, libraries without async) goes through `await self.ctx.to_thread(fn, ...)`. If `run()` crashes, NetMaster restarts it after a while.

**Buttons (NetMaster 0.2.1+).** List them under `"actions"` in module.json, e.g. `[{"id": "test", "label": "Send a test", "help": "optional"}]`. They show in the module's card while it is on. Pressing one calls `async def action(self, action_id, value)`; return a short message, or raise to show an error. To show a list of choices next to the button, return `[{"value": ..., "label": ...}]` from `action_options(self, action_id)`.

**Never log the user out.** Many routers allow one admin at a time. If the device says someone else is logged in, raise `Busy` instead of forcing your way in.

### What `self.ctx` gives you

| | |
|---|---|
| `gateway`, `local_ip` | IP of the main router and of the NetMaster computer |
| `devices`, `device_by_ip(ip)` | the device inventory |
| `router_name(ip)` | the name the user gave a router |
| `add_log(line, host)` | add a router log line (it goes through the same rules as syslog) |
| `report_clients([...])` | connected clients and their traffic (for `router` modules) |
| `emit(category, severity, title, detail, key, kind)` | raise an event/alert. `kind` is a fixed id for the alert type (for automations) |
| `subscribe_events()` | an asyncio queue with every new event, including its `kind` |
| `traffic(mac)`, `top_domains(ip, hours, n)` | live traffic from the router module, most looked-up sites from the DNS module |
| `can_pause`, `paused()`, `protected()`, `await pause(mac, on)` | pause internet for a device through the router module (protected devices are refused) |
| `to_thread(fn, ...)`, `sleep(s)` | run blocking code, wait |
| `db`, `cfg`, `data_dir`, `log` | database, NetMaster settings (read only), a private folder, a logger |

Helpers in `netmaster.sdk`: `http_get(url, headers, timeout, verify_tls)` returns `(status, body)`, and `ServiceWatch(ctx, name, url)` gives up/down alerts for a web service. The full reference is the docstring at the top of [`netmaster/sdk.py`](../netmaster/sdk.py).

### What each `provides` means

- `logs`: call `ctx.add_log(...)` for each line.
- `router`: call `ctx.report_clients(...)`. Optional: `self.blocked`, `self.audit`, `self.public_ip`, and `block(mac, on, name)` for the "pause internet" button.
- `dns`: a DNS filter. Implement `top(hours)` and `device(ip, hours)`, optionally `rules()`, `add_rule(...)`, `remove_rule(...)`.
- `smart_home`: shares data with a smart-home system. Devices the user ticked "Show in ..." have `share` set in `ctx.devices()`. See [`ha_mqtt`](ha_mqtt/module.py).
- `service`: return `{"service": self.watch.status()}` from `status()` to show up in the Services panel.
  NetMaster 0.2.6+: return `{"services": [...]}` for several at once. Each may add `value` (short text for the card) and `detail` (the line under it). See [`certs`](certs/module.py).

Any module can also list what it watches in its card in Settings: return `{"rows": [{"label": ..., "value": ..., "state": "up" | "degraded" | "down"}]}` from `status()` (NetMaster 0.2.6+, at most 50).

Any module can also define `protect() -> {ip: reason}` for devices that must never be paused.

### NetMaster 0.2.7+: everything a module needs lives in its own folder

A module never needs changes to NetMaster itself. On top of the above:

- **Its own notification types.** List them under `"notifications"` in module.json:
  `[{"id": "power", "group": "Power", "label": "Power cut", "desc": "Shown under the label.", "match": "^UPS .+ is running on battery$", "default": true}]`.
  `match` is a regular expression on the event title. The type shows up under Settings → Notifications while the module is installed (its id becomes `<module>.<id>`).
- **Its own translations.** Add `strings.tsv` to `files`. The first column is the English text (header `en`), then one column per language with a 2-letter header (`sv`, `de`, ...). Use `{0}`, `{1}` for parts that change. It works like [`web/i18n/strings.tsv`](../web/i18n/strings.tsv), but a module's rows never replace the app's own texts. Translate at least every label, help text, button and alert title into Swedish. Avoid very general patterns such as `{0} is down`: they also catch other titles.
- **Graphs.** `self.ctx.record(key, value, label="", unit="")` stores a number (at most once a minute per key, kept 30 days). The module's card then shows a graph with the last 24 hours.
- **Info on a device.** Override `device_info(self, mac, ip)` and return `[{"label": ..., "value": ..., "state": ...}]` (or `None`). The rows show in that device's details. See [`ups`](ups/module.py).
- **Web APIs.** `HttpSession(base_url, verify_tls=False, auth=(user, pw), headers={...})` keeps cookies between calls, and `s.get(path)`, `s.post(path, json=...)`, `put`, `delete` return a response with `status`, `ok`, `text`, `json()` and `check()` (raises on 4xx/5xx). `http_request(method, url, ...)` does a single call. Both are blocking: run them with `ctx.to_thread`.
- **Choice lists (NetMaster 0.2.8+).** A setting of type `select` with `"options": [{"value": "udp", "label": "UDP"}, ...]` (or just `["udp", "tcp"]`) shows a drop-down list.
- **Everything the overview shows (NetMaster 0.2.8+).** `self.ctx.status()` returns the same dict as `GET /api/status`: targets with response times and loss, services, uptime checks, the last speed test and more. See [`prometheus`](prometheus/module.py).
- **Several routers.** Any number of `router` modules can run at once. Their client lists are merged, the blocked lists are combined, and "pause internet" goes to the router that can do it.

## Publishing

1. Add your folder under `modules/`.
2. Run `python scripts/build_module_index.py`. It checks every `module.json` and rebuilds `index.json` with a SHA-256 of each file, which NetMaster checks when it downloads.
3. Commit both the folder and `index.json`.

To test before publishing, set *Module source* to a local folder path (for example `C:\code\netmaster\modules`) and install from the marketplace as usual.
