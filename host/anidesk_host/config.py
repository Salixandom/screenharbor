"""Persistent host configuration (~/.anidesk/host.json)."""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("ANIDESK_HOME", Path.home() / ".anidesk"))
CONFIG_FILE = CONFIG_DIR / "host.json"

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
    insecure_tls: bool = False
    extra: dict = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Config":
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
