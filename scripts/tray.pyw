"""Starts the NetMaster tray icon without a console window:  .venv\\Scripts\\pythonw.exe scripts\\tray.pyw"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netmaster.tray import main  # noqa: E402

main()
