"""Persistent host configuration (~/.screenharbor/host.json)."""
from __future__ import annotations

import json
import os
import secrets
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

_LEGACY_CONFIG_DIR = Path(os.environ.get("ANIDESK_HOME", Path.home() / ".anidesk"))
CONFIG_DIR = Path(os.environ.get("SCREENHARBOR_HOME", Path.home() / ".screenharbor"))
CONFIG_FILE = CONFIG_DIR / "host.json"
HISTORY_FILE = CONFIG_DIR / "connections.log"  # one JSON object per line, like AnyDesk's connection_trace.txt


def _migrate_legacy_config() -> None:
    """Copy old identity/settings once, preserving user's ID, key and history."""
    if CONFIG_DIR == _LEGACY_CONFIG_DIR or CONFIG_FILE.exists() or not _LEGACY_CONFIG_DIR.is_dir():
        return
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("host.json", "connections.log", "address-ed25519.key"):
        src, dst = _LEGACY_CONFIG_DIR / name, CONFIG_DIR / name
        if src.is_file() and not dst.exists():
            try:
                shutil.copy2(src, dst)
                if name.endswith(".key"):
                    os.chmod(dst, 0o600)
            except OSError:
                pass
    old_bin = _LEGACY_CONFIG_DIR / "bin"
    new_bin = CONFIG_DIR / "bin"
    if old_bin.is_dir() and not new_bin.exists():
        try:
            shutil.copytree(old_bin, new_bin)
        except OSError:
            pass

# No 0/O/1/l/I so passwords can be read out over the phone.
_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_password(n: int = 8) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def normalize_server(url: str) -> str:
    url = url.strip()
    if not url:
        return "ws://localhost:8080/ws"
    if url.startswith("http://"):
        url = "ws://" + url[7:]
    elif url.startswith("https://"):
        url = "wss://" + url[8:]
    elif not url.startswith(("ws://", "wss://")):
        url = "ws://" + url
    scheme, rest = url.split("://", 1)
    if "/" not in rest:
        rest += "/ws"
    return f"{scheme}://{rest}"


@dataclass
class Config:
    server: str = "ws://localhost:8080/ws"
    id: str = ""
    secret: str = ""  # proves ownership of the ID to the server
    # Permanent ("unattended") password, stored only as a salted PBKDF2 key.
    pw_salt: str = ""
    pw_key: str = ""
    ask: bool = True
    allow_input: bool = True
    allow_files: bool = True
    allow_clipboard: bool = True
    allow_terminal: bool = True  # shells + localhost TCP tunnels (SSH etc.)
    insecure_tls: bool = False
    extra: dict = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Config":
        _migrate_legacy_config()
        try:
            data = json.loads(CONFIG_FILE.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), "utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, CONFIG_FILE)
