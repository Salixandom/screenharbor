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

from .config import HISTORY_FILE, Config, generate_password, normalize_server
from .crypto import password_key

log = logging.getLogger("screenharbor")

MAX_SESSIONS = 4
LOCK_AFTER_FAILURES = 5
FAILURE_WINDOW = 300
LOCK_SECONDS = 60
TOKEN_TTL = 15 * 60  # reconnect tokens skip the Accept prompt for this long
# Distinct, readable on dark and light backgrounds; assigned to viewers in join order.
COLORS = ["#4ea1ff", "#ffb02e", "#3fb950", "#d06cff", "#ff6a9a", "#2ad4c8", "#f2e94e", "#ff7b3a"]


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
        self.desktop_ok = True  # False on machines without a display: terminal-only sessions
        self._next_pid = 0
        self.relay = None   # EmbeddedRelay while sharing via link
        self.tunnel = None  # QuickTunnel while sharing via link
        self.stable_address: str | None = None
        self._directory_last_ok = False
        self._directory_last_publish = 0.0
        self._tunnel_watch: asyncio.Task | None = None
        self._directory_refresh: asyncio.Task | None = None
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
            if s.welcomed:
                self.trace("session", s, duration=int(time.time() - s.started))
                s.pointer = None
                self.pointer_moved(s)
                self.participants_changed()

    # -------------------------------------------------------- participants
    def assign_participant(self, s) -> None:
        self._next_pid += 1
        s.pid = f"p{self._next_pid}"
        used = {x.color for x in self.sessions if x.welcomed}
        s.color = next((c for c in COLORS if c not in used), COLORS[self._next_pid % len(COLORS)])

    def participants(self) -> list:
        return sorted((s for s in self.sessions if s.welcomed), key=lambda s: s.started)

    def broadcast(self, obj: dict, exclude=None) -> None:
        for s in self.participants():
            if s is not exclude:
                asyncio.create_task(self._safe_send(s, obj))

    @staticmethod
    async def _safe_send(s, obj) -> None:
        try:
            await s.send_json(obj)
        except Exception:
            pass

    def participants_changed(self) -> None:
        people = [{"p": "host", "name": socket.gethostname(), "host": True}] + [
            {"p": s.pid, "name": s.viewer_name, "color": s.color, "mode": s.mode, "since": int(s.started)}
            for s in self.participants()]
        for s in self.participants():
            asyncio.create_task(self._safe_send(s, {"t": "peers", "you": s.pid, "list": people}))
        self.ui.peers()

    def pointer_moved(self, src) -> None:
        """Share a viewer's mouse position with the host overlay and the other viewers on the same area."""
        g = src.geo
        if src.pointer is None or g is None:
            self.ui.pointer(src, None)
            self.broadcast({"t": "pcur", "p": src.pid, "x": None}, exclude=src)
            return
        ax, ay = g["x"] + src.pointer[0] * g["w"], g["y"] + src.pointer[1] * g["h"]
        self.ui.pointer(src, (int(ax), int(ay)))
        for s in self.participants():
            if s is src or s.geo is None:
                continue
            o = s.geo
            x, y = (ax - o["x"]) / o["w"], (ay - o["y"]) / o["h"]
            inside = 0 <= x <= 1 and 0 <= y <= 1
            asyncio.create_task(self._safe_send(s, {
                "t": "pcur", "p": src.pid, "name": src.viewer_name, "color": src.color,
                "x": round(x, 4) if inside else None, "y": round(y, 4) if inside else None}))

    def relay_chat(self, src, text: str) -> None:
        self.ui.chat(src, text)
        self.broadcast({"t": "chat", "s": text, "from": src.viewer_name, "color": src.color}, exclude=src)

    def host_chat(self, text: str) -> None:
        self.broadcast({"t": "chat", "s": text, "from": f"{socket.gethostname()} (host)"})

    # ------------------------------------------------------------- history
    def trace(self, event: str, s=None, **extra) -> None:
        """Append to the connection history (who, when, how, what)."""
        rec = {"ts": int(time.time()), "event": event}
        if s is not None:
            rec.update(name=s.viewer_name, ip=s.ip, method=s.method, mode=s.mode)
        rec.update(extra)
        try:
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            log.debug("could not write history", exc_info=True)
        self.ui.history(rec)

    # ------------------------------------------------------ share via link
    async def start_sharing(self, use_tunnel: bool = True, stable_address: bool = False,
                            tunnel_hostname: str | None = None, tunnel_token_file: str | None = None) -> str:
        """Become our own server and (optionally) open a Cloudflare quick tunnel to it.

        Returns the public link (or the local relay URL when use_tunnel=False)."""
        from .tunnel import NamedTunnel, QuickTunnel

        if bool(tunnel_hostname) != bool(tunnel_token_file):
            raise ValueError("custom hostname and Cloudflare token file must be provided together")
        await self.start_relay(port=8765 if tunnel_token_file else 0)
        if not use_tunnel:
            return self.relay.url
        local_http = f"http://127.0.0.1:{self.relay.port}"
        try:
            self.tunnel = (NamedTunnel(local_http, tunnel_hostname, tunnel_token_file)
                           if tunnel_token_file else QuickTunnel(local_http))
            url = await self.tunnel.start(progress=self.ui.status)
        except Exception:
            await self.stop_sharing()
            raise
        self.ui.log(f"Sharing link: {url}")
        if stable_address:
            deadline = time.monotonic() + 30
            while self.relay.host_id != self.ident[0] and time.monotonic() < deadline:
                await asyncio.sleep(0.1)
            if not self.relay.host_id:
                await self.stop_sharing()
                raise RuntimeError("the host did not register with its local relay")
            await self._publish_address(url)
            self._directory_refresh = asyncio.create_task(self._refresh_address_loop())
        self._tunnel_watch = asyncio.create_task(self._watch_tunnel())
        return url

    async def _publish_address(self, url: str) -> bool:
        from . import directory

        try:
            self.stable_address = await asyncio.to_thread(directory.publish, url, self.relay.host_id)
            self._directory_last_ok = True
            self._directory_last_publish = time.time()
            self.ui.log(f"Stable address: {self.stable_address}")
            return True
        except Exception as e:  # stable lookup failure must not stop ordinary sharing
            self._directory_last_ok = False
            self.ui.log(f"Stable address update failed: {e}")
            if self.stable_address is None:
                self.stable_address = directory.address()
            return False

    async def _refresh_address_loop(self) -> None:
        from . import directory

        while self.relay is not None and self.tunnel is not None:
            await asyncio.sleep(60)
            due = not self._directory_last_ok or time.time() - self._directory_last_publish >= directory.REPUBLISH_EVERY
            if due and self.tunnel and self.tunnel.url:
                await self._publish_address(self.tunnel.url)

    async def _watch_tunnel(self) -> None:
        while self.relay is not None and self.tunnel is not None:
            await asyncio.sleep(2)
            tunnel = self.tunnel
            if tunnel is None or tunnel._proc is None or tunnel._proc.returncode is None:
                continue
            self.ui.log("Cloudflare tunnel stopped; reconnecting with a new temporary URL...")
            while self.relay is not None and self.tunnel is tunnel:
                try:
                    url = await tunnel.start(progress=self.ui.status)
                    if self.stable_address:
                        await self._publish_address(url)
                    self.ui.log(f"Sharing link renewed: {url}")
                    if hasattr(self.ui, "sharing_update"):
                        fragment = f"#address={self.stable_address}" if self.stable_address else f"#id={self.relay.host_id}"
                        self.ui.sharing_update(f"{url}/{fragment}", tunnel.code)
                    break
                except Exception as e:
                    self.ui.log(f"Tunnel restart failed: {e}; retrying in 15 seconds")
                    await asyncio.sleep(15)

    async def start_relay(self, port: int = 0) -> None:
        """Become our own server on 127.0.0.1 (and switch the control connection to it)."""
        from .relay import EmbeddedRelay

        if self.relay is None:
            self.relay = EmbeddedRelay()
            await self.relay.start(port=port)
            self.ui.log(f"Local relay: {self.relay.url}")
            self.reconnect()

    async def stop_sharing(self) -> None:
        for task in (self._tunnel_watch, self._directory_refresh):
            if task:
                task.cancel()
        self._tunnel_watch = self._directory_refresh = None
        if self.stable_address and self.relay is not None and self.relay.host_id:
            try:
                from . import directory
                await asyncio.to_thread(directory.publish_offline, self.relay.host_id)
            except Exception as e:
                self.ui.log(f"Could not mark stable address offline: {e}")
        if self.tunnel is not None:
            await self.tunnel.stop()
            self.tunnel = None
        if self.relay is not None:
            for s in list(self.sessions):
                await s.close()
            await self.relay.stop()
            self.relay = None
            self.reconnect()
        self.stable_address = None
        self._directory_last_ok = False
        self._directory_last_publish = 0.0

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
