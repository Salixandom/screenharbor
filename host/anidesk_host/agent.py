"""Host agent: keeps a control connection to the ID server and spawns sessions.

Mirrors AnyDesk's "main relay connection": the host stays registered under a
stable 9-digit ID; when a viewer asks for that ID the server sends us an
"incoming" notice and we open a dedicated session socket for it.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import ssl
import time

from websockets.asyncio.client import connect

from .config import Config, generate_password, normalize_server
from .crypto import password_key

log = logging.getLogger("anidesk")

MAX_SESSIONS = 4
LOCK_AFTER_FAILURES = 5
FAILURE_WINDOW = 300
LOCK_SECONDS = 60
TOKEN_TTL = 15 * 60  # reconnect tokens skip the Accept prompt for this long


class Agent:
    def __init__(self, cfg: Config, ui, session_password: str | None = None) -> None:
        self.cfg = cfg
        self.ui = ui
        self.sessions: set = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._failures: list[float] = []
        self._tokens: dict[str, float] = {}  # sha256(token) -> expiry
        self._ctrl_ws = None
        self.ident: tuple[str, str] = (cfg.id, cfg.secret)  # (id, secret) we're registered with
        self.relay = None   # EmbeddedRelay while sharing via link
        self.tunnel = None  # QuickTunnel while sharing via link
        self._wake = asyncio.Event()
        self._stop = False
        self._session_pw: str = ""
        self._session_secret: tuple[bytes, bytes] | None = None
        self.set_session_password(session_password or generate_password())

    # ------------------------------------------------------------ passwords
    @property
    def session_password(self) -> str:
        return self._session_pw

    def set_session_password(self, pw: str) -> None:
        salt = os.urandom(16)
        self._session_pw = pw
        self._session_secret = (salt, password_key(pw, salt))

    def set_permanent_password(self, pw: str | None) -> None:
        """Set (or clear, with None/"") the unattended-access password."""
        if pw:
            salt = os.urandom(16)
            self.cfg.pw_salt, self.cfg.pw_key = salt.hex(), password_key(pw, salt).hex()
        else:
            self.cfg.pw_salt = self.cfg.pw_key = ""
        self.cfg.save()

    def password_secrets(self) -> list[tuple[bytes, bytes]]:
        """(salt, key) pairs a viewer may authenticate against."""
        out = [self._session_secret]
        if self.cfg.pw_salt and self.cfg.pw_key:
            out.append((bytes.fromhex(self.cfg.pw_salt), bytes.fromhex(self.cfg.pw_key)))
        return out

    # ------------------------------------------------------ reconnect tokens
    def issue_token(self) -> str:
        tok = os.urandom(24).hex()
        now = time.time()
        self._tokens = {h: exp for h, exp in self._tokens.items() if exp > now}
        self._tokens[hashlib.sha256(tok.encode()).hexdigest()] = now + TOKEN_TTL
        return tok

    def check_token(self, tok) -> bool:
        """A valid token (already password-authenticated) skips the Accept prompt once."""
        if not isinstance(tok, str) or not tok:
            return False
        exp = self._tokens.pop(hashlib.sha256(tok.encode()).hexdigest(), 0)
        return exp > time.time()

    # ---------------------------------------------------- brute-force guard
    def record_failure(self, ip: str) -> None:
        now = time.time()
        self._failures = [t for t in self._failures if now - t < FAILURE_WINDOW] + [now]
        self.ui.log(f"Wrong password from {ip}")

    def is_locked(self) -> bool:
        now = time.time()
        recent = [t for t in self._failures if now - t < FAILURE_WINDOW]
        return len(recent) >= LOCK_AFTER_FAILURES and now - recent[-1] < LOCK_SECONDS

    # ---------------------------------------------------------- connection
    @property
    def server_url(self) -> str:
        return self.relay.url if self.relay else normalize_server(self.cfg.server)

    def connect_kwargs(self) -> dict:
        # No permessage-deflate: everything is encrypted (incompressible), so it would only burn CPU.
        kw = {"open_timeout": 15, "max_size": 64 * 1024 * 1024, "ping_interval": 20, "compression": None}
        if self.server_url.startswith("wss://") and self.cfg.insecure_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            kw["ssl"] = ctx
        return kw

    async def confirm(self, session) -> bool:
        if not self.cfg.ask or session.used_permanent_password:
            return True
        try:
            return await asyncio.wait_for(self.ui.ask(session), 60)
        except asyncio.TimeoutError:
            return False

    async def run(self) -> None:
        self.loop = asyncio.get_running_loop()
        backoff = 1
        while not self._stop:
            url = self.server_url
            self.ui.status(f"Connecting to {url} ...")
            try:
                async with connect(url, **self.connect_kwargs()) as ws:
                    self._ctrl_ws = ws
                    if url != self.server_url:
                        continue  # switched to/from share mode while we were connecting
                    secret = self.relay.host_secret if self.relay else self.cfg.secret
                    await ws.send(json.dumps({"t": "register", "id": self.cfg.id, "secret": secret,
                                              "name": socket.gethostname()}))
                    async for raw in ws:
                        if not isinstance(raw, str):
                            continue
                        await self._on_control(ws, json.loads(raw))
                        backoff = 1
                        if url != self.server_url:
                            break
            except Exception as e:  # noqa: BLE001 - keep reconnecting whatever happens
                log.debug("control connection failed", exc_info=True)
                if getattr(getattr(e, "rcvd", None), "code", None) == 4000:
                    # Another host logged in with our ID (copied config?). Don't fight over it.
                    self.ui.status("This ID was taken over by another computer. Retrying in 5 minutes "
                                   "(or press Apply).")
                    backoff = 300
                else:
                    self.ui.status(f"Offline ({type(e).__name__}: {e}). Retrying...")
            self._ctrl_ws = None
            if self._stop:
                break
            if url != self.server_url:
                continue
            self._wake = asyncio.Event()
            try:
                await asyncio.wait_for(self._wake.wait(), backoff)
            except asyncio.TimeoutError:
                pass
            backoff = 1 if backoff >= 300 else min(backoff * 2, 30)

    async def _on_control(self, ws, m: dict) -> None:
        t = m.get("t")
        if t == "registered":
            self.ident = (m["id"], m["secret"])
            if self.relay is None and m["id"] != self.cfg.id:
                self.cfg.id, self.cfg.secret = m["id"], m["secret"]
                self.cfg.save()
            self.ui.id_changed(m["id"])
            self.ui.status("Sharing via link - waiting for connections" if self.relay
                           else "Ready - waiting for connections")
        elif t == "incoming":
            if len(self.sessions) >= MAX_SESSIONS:
                await ws.send(json.dumps({"t": "reject", "sid": m.get("sid"), "reason": "Host is busy."}))
                return
            from .session import Session  # heavy imports (mss, pynput) only when needed

            s = Session(self, str(m.get("sid", "")), str(m.get("ip", "?")))
            asyncio.create_task(self._run_session(s))
        elif t == "error":
            self.ui.log(f"Server: {m.get('msg')}")

    async def _run_session(self, s) -> None:
        self.sessions.add(s)
        try:
            await s.run()
        finally:
            self.sessions.discard(s)

    # ------------------------------------------------------ share via link
    async def start_sharing(self, use_tunnel: bool = True) -> str:
        """Become our own server and (optionally) open a Cloudflare quick tunnel to it.

        Returns the public link (or the local relay URL when use_tunnel=False)."""
        from .tunnel import QuickTunnel

        await self.start_relay()
        if not use_tunnel:
            return self.relay.url
        self.tunnel = QuickTunnel(f"http://127.0.0.1:{self.relay.port}")
        try:
            url = await self.tunnel.start(progress=self.ui.status)
        except Exception:
            await self.stop_sharing()
            raise
        self.ui.log(f"Sharing link: {url}")
        return url

    async def start_relay(self) -> None:
        """Become our own server on 127.0.0.1 (and switch the control connection to it)."""
        from .relay import EmbeddedRelay

        if self.relay is None:
            self.relay = EmbeddedRelay()
            await self.relay.start()
            self.ui.log(f"Local relay: {self.relay.url}")
            self.reconnect()

    async def stop_sharing(self) -> None:
        if self.tunnel is not None:
            await self.tunnel.stop()
            self.tunnel = None
        if self.relay is not None:
            for s in list(self.sessions):
                await s.close()
            await self.relay.stop()
            self.relay = None
            self.reconnect()

    def reconnect(self) -> None:
        """Drop the control connection (or skip the retry wait); run() reconnects with the current config."""
        if self._ctrl_ws is not None:
            asyncio.create_task(self._ctrl_ws.close())
        self._wake.set()

    async def stop(self) -> None:
        self._stop = True
        await self.stop_sharing()
        for s in list(self.sessions):
            await s.close()
        if self._ctrl_ws is not None:
            await self._ctrl_ws.close()
