"""Signed stable addresses for changing Cloudflare quick-tunnel URLs.

The address is the SHA-256 fingerprint of a persistent Ed25519 public key. The
public ntfy topic is only a locator: each record is signed, so a topic writer
cannot substitute another host. The actual ScreenHarbor session still uses its
normal password-derived end-to-end encryption and host approval.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .config import CONFIG_DIR

DEFAULT_BOARD = "https://ntfy.sh"
REPUBLISH_EVERY = 4 * 3600
RECORD_TTL = 10 * 3600
ADDRESS_RE = re.compile(r"^(screen|ani)-([0-9a-f]{40})$", re.I)
_KEY_FILE = CONFIG_DIR / "address-ed25519.key"


def _keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    try:
        raw = _KEY_FILE.read_bytes()
        private = Ed25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
        try:
            fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # another ScreenHarbor process initialized the identity concurrently
            private = Ed25519PrivateKey.from_private_bytes(_KEY_FILE.read_bytes())
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
    public = private.public_key()
    return private, public


def public_bytes(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def address() -> str:
    _, public = _keypair()
    return "screen-" + hashlib.sha256(public_bytes(public)).hexdigest()[:40]


def _topic(addr: str, board: str = DEFAULT_BOARD) -> str:
    match = ADDRESS_RE.fullmatch(addr)
    if not match:
        raise ValueError("invalid ScreenHarbor stable address")
    topic = "screenharbor-" if match.group(1).lower() == "screen" else "anidesk-"
    return board.rstrip("/") + "/" + topic + match.group(2).lower()


def _valid_public_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or ""
        return (parsed.scheme == "https" and not parsed.username and not parsed.password and
                parsed.port is None and parsed.path in ("", "/") and not parsed.query and not parsed.fragment and
                bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host, re.I)))
    except ValueError:
        return False


def _canonical(record: dict) -> bytes:
    signed = {k: record[k] for k in ("v", "address", "state", "url", "id", "issued", "expires", "pub")}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()


def _send_record(record: dict, private: Ed25519PrivateKey, board: str) -> None:
    record = dict(record)
    record["sig"] = base64.b64encode(private.sign(_canonical(record))).decode()
    req = urllib.request.Request(_topic(record["address"], board), data=json.dumps(record).encode(), method="PUT",
                                 headers={"Content-Type": "application/json", "Title": "ScreenHarbor address update"})
    with urllib.request.urlopen(req, timeout=12) as response:
        if response.status // 100 != 2:
            raise OSError(f"directory publish failed: HTTP {response.status}")


def publish(url: str, host_id: str, board: str = DEFAULT_BOARD) -> str:
    private, public = _keypair()
    addr = "screen-" + hashlib.sha256(public_bytes(public)).hexdigest()[:40]
    now = int(time.time())
    record = {"v": 1, "address": addr, "state": "online", "url": url, "id": str(host_id), "issued": now,
              "expires": now + RECORD_TTL, "pub": base64.b64encode(public_bytes(public)).decode()}
    _send_record(record, private, board)
    legacy = dict(record, address="ani-" + addr.split("-", 1)[1])
    _send_record(legacy, private, board)
    return addr


def publish_offline(host_id: str, board: str = DEFAULT_BOARD) -> str:
    private, public = _keypair()
    addr = "screen-" + hashlib.sha256(public_bytes(public)).hexdigest()[:40]
    now = int(time.time())
    record = {"v": 1, "address": addr, "state": "offline", "url": "", "id": str(host_id),
              "issued": now, "expires": now + RECORD_TTL, "pub": base64.b64encode(public_bytes(public)).decode()}
    _send_record(record, private, board)
    legacy = dict(record, address="ani-" + addr.split("-", 1)[1])
    _send_record(legacy, private, board)
    return addr


def _verify(record: dict, addr: str) -> dict:
    match = ADDRESS_RE.fullmatch(addr)
    if not match or record.get("v") != 1 or record.get("address", "").lower() != addr.lower():
        raise ValueError("invalid address record")
    pub_raw = base64.b64decode(record["pub"], validate=True)
    if hashlib.sha256(pub_raw).hexdigest()[:40] != match.group(2).lower():
        raise ValueError("address public-key fingerprint mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(base64.b64decode(record["sig"], validate=True),
                                                          _canonical(record))
    except InvalidSignature as e:
        raise ValueError("invalid stable address signature") from e
    now = int(time.time())
    if not (now - 300 <= int(record["issued"]) <= now + 300 and now < int(record["expires"]) <= now + RECORD_TTL + 300):
        raise ValueError("stable address record has expired")
    if record.get("state") == "offline":
        if record["url"]:
            raise ValueError("invalid offline address record")
    elif record.get("state") != "online" or not _valid_public_url(record["url"]):
        raise ValueError("stable address points to an unsupported URL")
    if not re.fullmatch(r"\d{9,}", str(record["id"])):
        raise ValueError("stable address has an invalid host ID")
    return record


def resolve(addr: str, board: str = DEFAULT_BOARD) -> dict:
    """Fetch the most recent signed, unexpired mapping for a stable address."""
    url = _topic(addr, board) + "/json?poll=1&since=latest"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ScreenHarbor"})
    with urllib.request.urlopen(req, timeout=12) as response:
        body = response.read(256 * 1024).decode("utf-8", "replace")
    candidates = []
    for line in body.splitlines():
        try:
            msg = json.loads(line)
            payload = msg.get("message") if isinstance(msg, dict) else None
            if isinstance(payload, str):
                record = json.loads(payload)
            elif isinstance(payload, dict):
                record = payload
            else:
                record = msg
            candidates.append(_verify(record, addr))
        except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError):
            continue
    if not candidates:
        raise ValueError("no current signed record found for this address; the host may be offline")
    record = max(candidates, key=lambda rec: int(rec["issued"]))
    if record["state"] == "offline":
        raise ValueError("this ScreenHarbor address is currently offline")
    return record
