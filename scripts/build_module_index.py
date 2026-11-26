"""Rebuilds modules/index.json (the marketplace list) from every modules/<id>/module.json.

Run it after adding or changing a module:  python scripts/build_module_index.py
It also stores a SHA-256 of every file, so NetMaster can check downloads.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netmaster.modules import validate_meta  # noqa: E402

out = []
for d in sorted((ROOT / "modules").iterdir()):
    if not (d / "module.json").is_file():
        continue
    meta = validate_meta(json.loads((d / "module.json").read_text("utf-8")))
    if meta["id"] != d.name:
        sys.exit(f"{d.name}: the folder name must equal the id ({meta['id']})")
    for f in meta["files"]:
        if not (d / f).is_file():
            sys.exit(f"{d.name}: missing file {f}")
    out.append({k: meta[k] for k in ("id", "name", "version", "author", "description", "provides", "requires") if k in meta}
               | {"sha256": {f: hashlib.sha256((d / f).read_bytes()).hexdigest() for f in ["module.json", *meta["files"]]}})
(ROOT / "modules" / "index.json").write_text(json.dumps({"modules": out}, indent=2, ensure_ascii=False) + "\n", "utf-8")
print(f"Wrote modules/index.json with {len(out)} modules")
