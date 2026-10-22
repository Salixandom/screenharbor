"""End-to-end session crypto shared with the web viewer (web/app.js).

Handshake (run through the relay, which only forwards bytes):

    host   -> viewer : {"t":"hello", "pub": P-256 point, "salts": [16-byte salt per accepted password]}
    viewer -> host   : {"t":"hello", "pub": P-256 point}
    viewer -> host   : one encrypted {"t":"auth"} frame per salt (host keeps the one that decrypts)

    shared = ECDH(host_priv, viewer_pub)
    pwk    = PBKDF2-SHA256(password, salt, 150000 iterations, 32 bytes)
    okm    = HKDF-SHA256(ikm=shared, salt=pwk, info="anidesk/v1"|host_pub|viewer_pub, 64 bytes)
    k_h2v  = okm[0:32]   k_v2h = okm[32:64]

Because the password is mixed into the key schedule it never travels over
the wire, and a relay that swaps in its own ECDH keys still cannot derive the
session keys without the password.

Every message afterwards is a binary frame:  seq (u64 BE) | AES-256-GCM(ct+tag)
with nonce = 0x00000000 | seq. Sequence numbers must arrive strictly in order,
which also rejects replays and reordering.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 150_000
INFO = b"anidesk/v1"


def password_key(password: str, salt: bytes) -> bytes:
    """Salted, stretched password key. Hosts may store this instead of the password."""
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, PBKDF2_ITERATIONS).derive(password.encode("utf-8"))


class Handshake:
    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = self._priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def derive(self, viewer_pub: bytes, pwk: bytes) -> "Channel":
        """Derive the host side of the channel (sends h2v, receives v2h)."""
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), viewer_pub)
        shared = self._priv.exchange(ec.ECDH(), peer)
        okm = HKDF(hashes.SHA256(), 64, pwk, INFO + self.pub + viewer_pub).derive(shared)
        return Channel(send_key=okm[:32], recv_key=okm[32:])


class Channel:
    def __init__(self, send_key: bytes, recv_key: bytes) -> None:
        self._tx = AESGCM(send_key)
        self._rx = AESGCM(recv_key)
        self._tx_seq = 0
        self._rx_seq = 0

    def seal(self, plaintext: bytes) -> bytes:
        hdr = struct.pack(">Q", self._tx_seq)
        self._tx_seq += 1
        return hdr + self._tx.encrypt(b"\0\0\0\0" + hdr, plaintext, None)

    def open(self, frame: bytes) -> bytes:
        """Decrypt one frame. Raises on tampering, replay or reordering."""
        if len(frame) < 8 + 16:
            raise ValueError("frame too short")
        (seq,) = struct.unpack_from(">Q", frame)
        if seq != self._rx_seq:
            raise ValueError("unexpected sequence number")
        pt = self._rx.decrypt(b"\0\0\0\0" + frame[:8], frame[8:], None)
        self._rx_seq += 1
        return pt
