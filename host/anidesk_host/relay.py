"""Built-in relay for "share via link" mode: this host is its own AniDesk server.

Speaks exactly the same protocol as server/index.js (register / connect / attach,
then blind forwarding) and serves the web viewer, but only for this one host.
It listens on 127.0.0.1; a Cloudflare quick tunnel (tunnel.py) exposes it as
https://<words>.trycloudflare.com. Everything after pairing is end-to-end
encrypted between viewer and host, so neither this relay nor Cloudflare can read it.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import mimetypes
import secrets
import time
from pathlib import Path

from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response

log = logging.getLogger("anidesk")

PAIR_TIMEOUT = 20
SECURITY_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; connect-src 'self' ws: wss:; "
                                "style-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-cache"),
]


def find_web_dir() -> Path:
    for p in (Path(__file__).resolve().parent / "web", Path(__file__).resolve().parents[2] / "server" / "web"):
        if (p / "index.html").exists():
            return p
    raise FileNotFoundError("web viewer files not found (expected server/web next to host/)")


class EmbeddedRelay:
    def __init__(self, web_dir: Path | None = None) -> None:
        self.web_dir = (web_dir or find_web_dir()).resolve()
        self.host_secret = secrets.token_hex(24)  # only this process knows it
        self.host_id = ""
        self._host = None
        self._pending: dict[str, asyncio.Future] = {}
        self._attempts: dict[str, list[float]] = {}
        self._server = None
        self.port = 0

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/ws"

    async def start(self, port: int = 0) -> None:
        self._server = await serve(self._handler, "127.0.0.1", port, process_request=self._http,
                                   max_size=32 * 1024 * 1024, compression=None, ping_interval=20)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # ---------------------------------------------------------------- HTTP
    def _http(self, connection, request):
        path = request.path.split("?", 1)[0]
        if path == "/ws":
            return None  # continue with the WebSocket handshake
        if path == "/api/status":
            return self._response(200, b'{"ok":true,"mode":"embedded"}', "application/json")
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        file = (self.web_dir / rel).resolve()
        if self.web_dir not in file.parents or not file.is_file():
            return self._response(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return self._response(200, file.read_bytes(), ctype)

    @staticmethod
    def _response(status: int, body: bytes, ctype: str) -> Response:
        headers = Headers([("Content-Type", ctype), ("Content-Length", str(len(body))), *SECURITY_HEADERS])
        return Response(status, "OK" if status == 200 else "Not Found", headers, body)

    # ----------------------------------------------------------- WebSocket
    @staticmethod
    def _client_ip(ws) -> str:
        # Through the tunnel every client is 127.0.0.1; cloudflared passes the real address along.
        return ws.request.headers.get("CF-Connecting-IP") or ws.remote_address[0]

    def _allow(self, ip: str) -> bool:
        now = time.time()
        recent = [t for t in self._attempts.get(ip, []) if now - t < 60] + [now]
        self._attempts[ip] = recent
        return len(recent) <= 20

    async def _handler(self, ws) -> None:
        try:
            raw = await asyncio.wait_for(ws.recv(), 15)
            if not isinstance(raw, str) or len(raw) > 4096:
                return
            msg = json.loads(raw)
            t = msg.get("t")
            if t == "register":
                await self._on_host(ws, msg)
            elif t == "connect":
                await self._on_viewer(ws, msg)
            elif t == "attach":
                await self._on_attach(ws, msg)
        except (ConnectionClosed, asyncio.TimeoutError, ValueError):
            pass

    def _is_host(self, secret) -> bool:
        return isinstance(secret, str) and hmac.compare_digest(secret, self.host_secret)

    async def _on_host(self, ws, msg) -> None:
        if not self._is_host(msg.get("secret")):
            await ws.close(4003, "not this relay's host")
            return
        if self._host is not None:
            await self._host.close(4000, "replaced by new login")
        self._host = ws
        self.host_id = str(msg.get("id") or "") or str(secrets.randbelow(900_000_000) + 100_000_000)
        await ws.send(json.dumps({"t": "registered", "id": self.host_id, "secret": self.host_secret}))
        try:
            async for raw in ws:
                m = json.loads(raw) if isinstance(raw, str) else {}
                if m.get("t") == "reject" and m.get("sid") in self._pending:
                    fut = self._pending.pop(m["sid"])
                    if not fut.done():
                        fut.set_exception(LookupError(str(m.get("reason") or "Rejected by host.")))
                elif m.get("t") == "ping":
                    await ws.send('{"t":"pong"}')
        finally:
            if self._host is ws:
                self._host = None

    async def _on_viewer(self, ws, msg) -> None:
        ip = self._client_ip(ws)
        want = "".join(c for c in str(msg.get("id") or "") if c.isdigit())
        if not self._allow(ip):
            await ws.send(json.dumps({"t": "error", "msg": "Too many connection attempts, wait a minute."}))
            return
        if self._host is None or (want and want != self.host_id):
            await ws.send(json.dumps({"t": "error", "msg": "That ID is not online."}))
            return
        sid = secrets.token_hex(16)
        fut = asyncio.get_running_loop().create_future()
        self._pending[sid] = fut
        try:
            await self._host.send(json.dumps({"t": "incoming", "sid": sid, "ip": ip}))
            await ws.send('{"t":"waiting"}')
            peer, done = await asyncio.wait_for(fut, PAIR_TIMEOUT)
        except asyncio.TimeoutError:
            await ws.send(json.dumps({"t": "error", "msg": "Host did not answer."}))
            return
        except LookupError as e:
            await ws.send(json.dumps({"t": "error", "msg": str(e)}))
            return
        finally:
            self._pending.pop(sid, None)
        try:
            await peer.send('{"t":"paired"}')
            await ws.send('{"t":"paired"}')
            await self._pipe(ws, peer)
        finally:
            done.set()

    async def _on_attach(self, ws, msg) -> None:
        fut = self._pending.get(str(msg.get("sid") or ""))
        if fut is None or fut.done() or not self._is_host(msg.get("secret")):
            await ws.send(json.dumps({"t": "error", "msg": "unknown session"}))
            return
        done = asyncio.Event()
        fut.set_result((ws, done))
        await done.wait()  # keep this connection open until the viewer side finishes piping

    @staticmethod
    async def _pipe(a, b) -> None:
        async def forward(src, dst):
            async for m in src:
                await dst.send(m)  # awaiting send gives us backpressure for free

        tasks = [asyncio.create_task(forward(a, b)), asyncio.create_task(forward(b, a))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await a.close()
            await b.close()
