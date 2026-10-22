"""File browsing and transfer helpers (run in worker threads)."""
from __future__ import annotations

import os
import re
import string
import sys
import tempfile
import zipfile
from pathlib import Path

CHUNK = 256 * 1024


def default_download_dir() -> Path:
    d = Path.home() / "Downloads" / "ScreenHarbor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_dir(path: str) -> dict:
    """List a directory. An empty path lists drives (Windows) or "/"."""
    if not path:
        if sys.platform == "win32":
            drives = [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]
            return {"path": "", "parent": None, "home": str(Path.home()),
                    "entries": [{"n": d, "p": d, "d": True, "s": 0, "m": 0} for d in drives]}
        path = "/"
    p = Path(path).expanduser().resolve()
    entries = []
    with os.scandir(p) as it:
        for e in it:
            try:
                st = e.stat()
                is_dir = e.is_dir()
            except OSError:
                continue
            entries.append({"n": e.name, "p": str(Path(p, e.name)), "d": is_dir,
                            "s": 0 if is_dir else st.st_size, "m": int(st.st_mtime)})
    entries.sort(key=lambda x: (not x["d"], x["n"].lower()))
    parent = str(p.parent) if p.parent != p else ("" if sys.platform == "win32" else None)
    return {"path": str(p), "parent": parent, "home": str(Path.home()), "entries": entries}


_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_name(name: str) -> str:
    name = _BAD.sub("_", os.path.basename(str(name).replace("\\", "/"))).strip(" .")
    return name[:200] or "file"


def unique_path(directory: Path, name: str) -> Path:
    target = directory / name
    stem, suffix = target.stem, target.suffix
    n = 1
    while target.exists() or target.with_name(target.name + ".part").exists():
        target = directory / f"{stem} ({n}){suffix}"
        n += 1
    return target


def zip_dir(path: Path) -> Path:
    """Zip a folder into a temp file (fast compression); caller deletes it."""
    fd, tmp = tempfile.mkstemp(prefix="screenharbor-", suffix=".zip")
    os.close(fd)
    base = path.parent
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for root, _dirs, names in os.walk(path):
            for n in names:
                fp = Path(root, n)
                try:
                    z.write(fp, fp.relative_to(base))
                except (OSError, ValueError):
                    continue  # locked or vanished files are skipped
    return Path(tmp)
