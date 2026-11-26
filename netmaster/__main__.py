import logging
from logging.handlers import RotatingFileHandler

import uvicorn

from .config import load_config


def setup_logging(cfg) -> None:
    """Logs to a file (data/netmaster.log, rotating) and the console. Important when running as a background service."""
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = RotatingFileHandler(cfg.db_path.parent / "netmaster.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers = [fh, sh]
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)  # not every HTTP request


def _auth(cfg):
    from .auth import Auth
    from .config import DATA_DIR
    from .db import Database
    return Auth(Database(cfg.db_path), DATA_DIR)


def main() -> None:
    import sys
    cfg = load_config()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "set-password":
        import getpass
        pw = getpass.getpass("New NetMaster password: ")
        if pw != getpass.getpass("Repeat it: "):
            sys.exit("The passwords do not match.")
        try:
            _auth(cfg).set_password(pw)
        except ValueError as e:
            sys.exit(str(e))
        print("Password set. It takes effect at once.")
        return
    if cmd == "token":
        # A session for scripts: send it as "Authorization: Bearer <token>".
        print(_auth(cfg).new_session("command line"))
        return
    if cmd in ("-h", "--help", "help"):
        print("python -m netmaster               start NetMaster")
        print("python -m netmaster set-password  set or reset the login password")
        print("python -m netmaster token         create a login token for scripts")
        return
    setup_logging(cfg)
    if cfg.http_host not in ("127.0.0.1", "localhost", "::1"):
        _open_firewall(cfg.http_port)
    ssl = {"ssl_certfile": cfg.https_cert, "ssl_keyfile": cfg.https_key} if cfg.https_cert and cfg.https_key else {}
    uvicorn.run("netmaster.app:app", host=cfg.http_host, port=cfg.http_port, log_config=None, **ssl)


def _open_firewall(port: int) -> None:
    """Windows: let devices on private (home) networks reach the web port. Needs admin rights; skipped otherwise."""
    import subprocess
    import sys
    if sys.platform != "win32":
        return
    name = f"NetMaster web {port}"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        if subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                          capture_output=True, creationflags=flags).returncode != 0:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow",
                            "protocol=TCP", f"localport={port}", "profile=private"], capture_output=True, creationflags=flags)
    except OSError:
        pass


if __name__ == "__main__":
    main()
