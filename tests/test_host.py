"""Unit tests for host internals:  python -m pytest tests  (or python tests/test_host.py)."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))

from screenharbor_host.capture import TILE, _dirty_tiles, _merge  # noqa: E402
from screenharbor_host.crypto import Channel, Handshake, password_key  # noqa: E402
from screenharbor_host.files import safe_name  # noqa: E402
from screenharbor_host import directory  # noqa: E402


def test_dirty_tiles_and_merge_cover_changes():
    h, w = 300, 500  # not tile-aligned on purpose
    a = np.zeros((h, w), np.uint32)
    b = a.copy()
    b[10, 10] = 1          # tile (0,0)
    b[70:140, 200:330] = 5  # spans several tiles
    b[h - 1, w - 1] = 9    # last partial tile
    mask = _dirty_tiles(b, a)
    rects = _merge(mask, h, w)
    covered = np.zeros((h, w), bool)
    for x, y, rw, rh in rects:
        assert rw > 0 and rh > 0 and x + rw <= w and y + rh <= h
        covered[y:y + rh, x:x + rw] = True
    assert covered[(a != b)].all(), "every changed pixel must be inside a rect"
    assert covered.sum() < h * w / 2, "unchanged areas should mostly be skipped"


def test_merge_joins_vertical_runs():
    mask = np.zeros((4, 4), bool)
    mask[0:3, 1:3] = True
    assert _merge(mask, 4 * TILE, 4 * TILE) == [(TILE, 0, 2 * TILE, 3 * TILE)]


def test_directory_resolves_ntfy_json_message_wrapper(monkeypatch):
    import io
    import json
    import time
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    addr = "screen-" + __import__("hashlib").sha256(public).hexdigest()[:40]
    now = int(time.time())
    record = {"v": 1, "address": addr, "state": "online", "url": "https://desk.example.com",
              "id": "123456789", "issued": now, "expires": now + 300,
              "pub": base64.b64encode(public).decode()}
    record["sig"] = base64.b64encode(private.sign(directory._canonical(record))).decode()
    event = {"event": "message", "message": json.dumps(record)}

    class Response(io.BytesIO):
        pass

    monkeypatch.setattr(directory.urllib.request, "urlopen",
                        lambda *args, **kwargs: Response((json.dumps(event) + "\n").encode()))
    assert directory.resolve(addr)["url"] == record["url"]


def test_channel_roundtrip_and_tamper_detection():
    salt = os.urandom(16)
    host, viewer = Handshake(), Handshake()
    key = password_key("secret pw", salt)
    h = host.derive(viewer.pub, key)
    # Build the viewer side by hand: keys are swapped relative to the host.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    shared = viewer._priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), host.pub))
    okm = HKDF(hashes.SHA256(), 64, key, b"screenharbor/v1" + host.pub + viewer.pub).derive(shared)
    v = Channel(send_key=okm[32:], recv_key=okm[:32])

    assert v.open(h.seal(b"hello")) == b"hello"
    assert h.open(v.seal(b"world")) == b"world"
    frame = bytearray(h.seal(b"x" * 100))
    frame[-1] ^= 1
    try:
        v.open(bytes(frame))
        raise AssertionError("tampered frame accepted")
    except Exception as e:
        assert not isinstance(e, AssertionError)
    replay = h.seal(b"once")
    v2 = Channel(send_key=okm[32:], recv_key=okm[:32])
    v2._rx_seq = 3  # replay is seq 2; receiver already moved past it
    try:
        v2.open(replay)
        raise AssertionError("replayed frame accepted")
    except ValueError:
        pass


def test_wrong_password_gives_different_keys():
    salt = os.urandom(16)
    host, viewer = Handshake(), Handshake()
    good = host.derive(viewer.pub, password_key("right", salt))
    bad = host.derive(viewer.pub, password_key("wrong", salt))  # same ECDH, wrong password
    try:
        bad.open(good.seal(b"data"))
        raise AssertionError("decrypted with wrong password")
    except Exception as e:
        assert not isinstance(e, AssertionError)


def test_safe_name():
    assert safe_name("../../etc/passwd") == "passwd"
    assert safe_name("C:\\Windows\\evil.exe") == "evil.exe"
    assert safe_name('a<b>:"c".txt') == "a_b___c_.txt"
    assert safe_name("...") == "file"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
