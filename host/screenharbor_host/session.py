"""One remote-control session with one viewer.

After pairing, everything is end-to-end encrypted (see crypto.py). Each
decrypted message starts with a kind byte:
    1 = JSON control, 2 = JPEG tile frame, 3 = file chunk (u32 id | data), 4 = H.264 frame,
    5 = terminal data (u32 id | bytes), 6 = TCP tunnel data (u32 id | bytes)

Modes: "desktop" (screen + input + everything) or "terminal" (shells and TCP tunnels
only: no screen capture, works on machines without a display).
"""
from __future__ import annotations

import asyncio
import base64
import collections
import json
import logging
import platform
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from . import files, terminal
from .crypto import Handshake

log = logging.getLogger("screenharbor")

K_JSON, K_FRAME, K_FILE, K_VIDEO, K_TERM, K_TCP = 1, 2, 3, 4, 5, 6
REFINE_AFTER = 0.4   # seconds of a static screen before the JPEG sharpening pass
ADAPT_EVERY = 2.0    # seconds between bitrate decisions
MIN_BITRATE = 300_000
MAX_BITRATE = 50_000_000
# H.264 bits per pixel per frame for the viewer's quality presets.
BPP = ((40, 0.025), (65, 0.05), (85, 0.09), (100, 0.15))


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _paste():
    try:
        import pyperclip
        return pyperclip.paste()
    except Exception:
        return None


def _copy(text: str) -> None:
    try:
        import pyperclip
        pyperclip.copy(text)
    except Exception:
        pass


class Session:
    def __init__(self, agent, sid: str, ip: str) -> None:
        self.agent = agent
        self.sid = sid
        self.ip = ip
        self.viewer_name = "viewer"
        self.used_permanent_password = False
        self.started = time.time()
        self.ws = None
        self.ch = None
        self.cap = None          # capture.Capturer (desktop mode only; imported lazily)
        self.geo: dict | None = None
        self._input = None       # inputctl.InputController, created on first use
        self.mode = "desktop"
        self.method = "password"  # how they got in: password | unattended | token
        self.pid = ""            # short participant id shown to others
        self.color = "#e8473f"
        self.pointer = None      # last (x, y) of this viewer's mouse, normalized to their monitor
        self.welcomed = False
        self._terms: dict = {}
        self._tcps: dict = {}
        self._pumps: set = set()
        self.monitor, self.scale, self.quality, self.fps = 1, 1, 60, 30
        self.codec_pref = "auto"
        self.viewer_codecs: set = {"jpeg"}
        self.codec = "jpeg"
        self.bitrate = 0          # current (adaptive) H.264 bitrate
        self._force = True
        self._inflight: collections.deque = collections.deque()  # (frame_no, bytes, sent_at)
        self._inflight_bytes = 0
        self._ack = asyncio.Event()
        self._frame_no = 0
        self._rtt = 0.0
        self._blocked = 0.0
        self._sent_bytes = 0
        self._send_lock = asyncio.Lock()
        self._ex = ThreadPoolExecutor(1, thread_name_prefix="screenharbor-capture")
        self._uploads: dict[int, dict] = {}
        self._downloads: dict[int, asyncio.Task] = {}
        self._last_clip = None
        self._last_cursor = None

    @property
    def label(self) -> str:
        return f"{self.viewer_name} ({self.ip})"

    @property
    def input(self):
        if self._input is None:
            from .inputctl import InputController  # needs a display; only import when used
            self._input = InputController()
        return self._input

    # --------------------------------------------------------------- send
    async def _send(self, kind: int, payload: bytes) -> None:
        async with self._send_lock:
            await self.ws.send(self.ch.seal(bytes([kind]) + payload))
        self._sent_bytes += len(payload)

    async def send_json(self, obj: dict) -> None:
        await self._send(K_JSON, json.dumps(obj, separators=(",", ":")).encode())

    async def chat(self, text: str) -> None:
        await self.send_json({"t": "chat", "s": text})

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()

    def _x(self, fn, *a):
        return asyncio.get_running_loop().run_in_executor(self._ex, fn, *a)

    # ---------------------------------------------------------- lifecycle
    async def run(self) -> None:
        try:
            async with connect(self.agent.server_url, **self.agent.connect_kwargs()) as ws:
                self.ws = ws
                if not await self._handshake():
                    return
                self.agent.ui.session_started(self)
                try:
                    await self._main()
                finally:
                    self.agent.ui.session_ended(self)
        except (ConnectionClosed, OSError, asyncio.TimeoutError):
            log.debug("session %s ended", self.sid[:8], exc_info=True)
        except Exception:
            log.exception("session %s failed", self.sid[:8])
        finally:
            if self._input is not None:
                self._input.release_all()
            for t in list(self._pumps):
                t.cancel()
            for pty in self._terms.values():
                pty.close()
            for w in self._tcps.values():
                w.close()
            for t in self._downloads.values():
                t.cancel()
            for u in self._uploads.values():
                u["fh"].close()
                u["tmp"].unlink(missing_ok=True)
            if self.cap is not None:
                self._ex.submit(self.cap.close)
            self._ex.shutdown(wait=False)

    async def _handshake(self) -> bool:
        ws, agent = self.ws, self.agent
        hid, secret = agent.ident
        await ws.send(json.dumps({"t": "attach", "sid": self.sid, "id": hid, "secret": secret}))
        m = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if m.get("t") != "paired":
            return False

        secrets = agent.password_secrets()
        hs = Handshake()
        await ws.send(json.dumps({
            "t": "hello", "v": 1, "pub": b64e(hs.pub), "salts": [b64e(salt) for salt, _ in secrets],
            "name": socket.gethostname(), "os": platform.system(),
        }))
        m = json.loads(await asyncio.wait_for(ws.recv(), 30))
        if m.get("t") != "hello":
            return False
        if agent.is_locked():
            await ws.send(json.dumps({"t": "error", "msg": "Too many wrong passwords. Try again in a minute."}))
            return False
        vpub = b64d(m["pub"])

        # The viewer sends one auth frame per advertised password salt.
        auth = None
        for i, (_, key) in enumerate(secrets):
            frame = await asyncio.wait_for(ws.recv(), 30)
            if auth is not None or not isinstance(frame, bytes):
                continue
            ch = hs.derive(vpub, key)
            try:
                pt = ch.open(frame)
                msg = json.loads(pt[1:]) if pt[:1] == bytes([K_JSON]) else {}
            except Exception:
                continue
            if msg.get("t") == "auth":
                auth, self.ch, self.used_permanent_password = msg, ch, i > 0
        if auth is None:
            agent.record_failure(self.ip)
            agent.trace("auth_failed", self)
            await ws.send(json.dumps({"t": "auth_failed"}))
            return False

        self.viewer_name = str(auth.get("name") or "viewer")[:40]
        self.viewer_codecs = {str(c) for c in auth.get("codecs") or ["jpeg"]}
        self.mode = "terminal" if auth.get("mode") == "terminal" or not agent.desktop_ok else "desktop"
        token_ok = agent.check_token(auth.get("token"))
        self.method = "token" if token_ok else "unattended" if self.used_permanent_password else "password"
        if not token_ok and not await agent.confirm(self):
            agent.trace("denied", self)
            await self.send_json({"t": "denied"})
            return False

        cfg = agent.cfg
        agent.assign_participant(self)
        welcome = {
            "t": "welcome", "name": socket.gethostname(), "os": platform.system(), "mode": self.mode,
            "you": self.pid, "color": self.color,
            "perms": {"input": cfg.allow_input, "files": cfg.allow_files, "clipboard": cfg.allow_clipboard,
                      "terminal": cfg.allow_terminal},
            "monitors": [], "encoder": None,
        }
        if self.mode == "desktop":
            from .capture import Capturer  # numpy/mss/av only when the screen is shared

            self.cap = await self._x(Capturer)
            welcome["monitors"] = await self._x(self.cap.monitors)
            welcome["encoder"] = self.cap.encoder_name
        await self.send_json(welcome)
        # Lets the viewer reconnect after a network drop without another Accept prompt.
        await self.send_json({"t": "token", "v": agent.issue_token()})
        self.welcomed = True
        agent.ui.log(f"Session started: {self.label} [{self.mode}, {self.method}]")
        return True

    async def _main(self) -> None:
        tasks = [asyncio.create_task(self._recv_loop())]
        if self.mode == "desktop":
            tasks += [asyncio.create_task(self._video_loop()), asyncio.create_task(self._stats_loop()),
                      asyncio.create_task(self._cursor_loop())]
            if self.agent.cfg.allow_clipboard:
                tasks.append(asyncio.create_task(self._clipboard_loop()))
        self.agent.participants_changed()
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, ConnectionClosed):
                log.error("session task failed", exc_info=exc)
        self.agent.ui.log(f"Session ended: {self.label}")

    # -------------------------------------------------------------- video
    def _target_bitrate(self, w: int, h: int) -> int:
        bpp = next(b for q, b in BPP if self.quality <= q)
        return int(max(MIN_BITRATE, min(MAX_BITRATE, w * h * self.fps * bpp)))

    def _pick_codec(self) -> str:
        if self.codec_pref == "jpeg" or "h264" not in self.viewer_codecs or self.cap.h264 is None:
            return "jpeg"
        if self.codec_pref == "auto" and self.cap.h264.software:
            return "jpeg"  # software H.264 at desktop resolutions costs most of a CPU core
        g = self.cap.geometry(self.monitor)
        return "h264" if self.cap.h264_ok(g["w"] // self.scale, g["h"] // self.scale) else "jpeg"

    def _window_full(self) -> bool:
        if self.codec == "h264":
            return len(self._inflight) >= 8 or self._inflight_bytes > max(300_000, self.bitrate // 8 * 3 // 10)
        return len(self._inflight) >= 3 or self._inflight_bytes > 2_000_000

    def _adapt(self, target: int, delivered_bps: float, blocked_ratio: float) -> None:
        """Congestion control: back off when acks lag, creep back up when the link is idle."""
        if self.bitrate == 0:
            self.bitrate = target
        elif blocked_ratio > 0.25 or self._rtt > 0.4:
            self.bitrate = int(max(MIN_BITRATE, min(self.bitrate * 0.7, delivered_bps * 0.85 or self.bitrate)))
        elif blocked_ratio < 0.05 and self._rtt < 0.15:
            self.bitrate = int(min(target, self.bitrate * 1.3))
        self.bitrate = min(self.bitrate, target)

    async def _video_loop(self) -> None:
        last_change = time.monotonic()
        refined = True
        window_start, window_sent = time.monotonic(), 0
        while True:
            if self._window_full():
                self._ack.clear()
                t = time.monotonic()
                try:
                    await asyncio.wait_for(self._ack.wait(), 5)
                except asyncio.TimeoutError:  # viewer stalled (tab hidden?) - resync with a keyframe
                    self._inflight.clear()
                    self._inflight_bytes = 0
                    self._force = True
                self._blocked += time.monotonic() - t
                continue
            t0 = time.monotonic()

            codec = self._pick_codec()
            if codec != self.codec:
                self.codec, self._force = codec, True
            g = self.cap.geometry(self.monitor)
            target = self._target_bitrate(g["w"] // self.scale, g["h"] // self.scale)
            if t0 - window_start >= ADAPT_EVERY:
                span = t0 - window_start
                self._adapt(target, (self._sent_bytes - window_sent) * 8 / span, self._blocked / span)
                window_start, window_sent, self._blocked = t0, self._sent_bytes, 0.0
            elif self.bitrate == 0 or self.bitrate > target:
                self.bitrate = target

            force, self._force = self._force, False
            monitor, scale = self.monitor, self.scale
            payload, (w, h), changed = await self._x(
                self.cap.frame, self._frame_no + 1, monitor, scale, self.codec, self.quality,
                self.bitrate, self.fps, force)
            if changed:
                self.geo = await self._x(self.cap.geometry, monitor)
                await self.send_json({"t": "screen", "w": w, "h": h, "monitor": monitor, "scale": scale,
                                      "codec": self.codec, "encoder": self.cap.encoder_name,
                                      "capture": self.cap.backend(monitor),
                                      "monitors": await self._x(self.cap.monitors)})
            kind = K_VIDEO if self.codec == "h264" else K_FRAME
            if payload is None and self.codec == "jpeg" and not refined and t0 - last_change > REFINE_AFTER:
                payload = await self._x(self.cap.refine, self._frame_no + 1)
                refined = True
            elif payload is not None:
                last_change, refined = t0, False
            if payload is not None:
                self._frame_no += 1
                self._inflight.append((self._frame_no, len(payload), time.monotonic()))
                self._inflight_bytes += len(payload)
                await self._send(kind, payload)
            await asyncio.sleep(max(0.0, 1 / self.fps - (time.monotonic() - t0)))

    async def _cursor_loop(self) -> None:
        """Report the host's real cursor ~30x/s, independent of video flow control."""
        while True:
            await asyncio.sleep(1 / 30)
            g = self.geo
            if not g:
                continue
            try:
                x, y = self.input.position()
            except Exception:
                continue
            pos = (round((x - g["x"]) / g["w"], 4), round((y - g["y"]) / g["h"], 4))
            if pos != self._last_cursor:
                self._last_cursor = pos
                await self.send_json({"t": "cur", "x": pos[0], "y": pos[1]})

    def _on_ack(self, f: int) -> None:
        now = time.monotonic()
        while self._inflight and self._inflight[0][0] <= f:
            _, size, sent = self._inflight.popleft()
            self._inflight_bytes -= size
            rtt = now - sent
            self._rtt = rtt if self._rtt == 0 else self._rtt * 0.8 + rtt * 0.2
        self._ack.set()

    async def _stats_loop(self) -> None:
        last = self._sent_bytes
        while True:
            await asyncio.sleep(2)
            sent, last = self._sent_bytes - last, self._sent_bytes
            await self.send_json({"t": "hstats", "codec": self.codec, "encoder": self.cap.encoder_name,
                                  "capture": self.cap.backend(self.monitor), "kbps": int(sent * 8 / 2000),
                                  "bitrate": self.bitrate if self.codec == "h264" else None,
                                  "rtt": int(self._rtt * 1000)})

    # ---------------------------------------------------------- clipboard
    async def _clipboard_loop(self) -> None:
        self._last_clip = await asyncio.to_thread(_paste)
        while True:
            await asyncio.sleep(1)
            cur = await asyncio.to_thread(_paste)
            if cur is not None and cur != self._last_clip:
                self._last_clip = cur
                if len(cur) <= 1_000_000:
                    await self.send_json({"t": "clip", "s": cur})

    # ------------------------------------------------------------ receive
    async def _recv_loop(self) -> None:
        async for frame in self.ws:
            if not isinstance(frame, bytes):
                continue
            pt = self.ch.open(frame)  # raises (ending the session) on tampering
            kind = pt[0]
            if kind == K_JSON:
                await self._on_json(json.loads(pt[1:]))
            elif kind == K_FILE:
                await self._on_upload_chunk(pt[1:])
            elif kind == K_TERM:
                tid, data = terminal.unframe(pt[1:])
                pty = self._terms.get(tid)
                if pty is not None:
                    pty.write(data)
            elif kind == K_TCP:
                tid, data = terminal.unframe(pt[1:])
                w = self._tcps.get(tid)
                if w is not None:
                    w.write(data)
                    await w.drain()

    async def _on_json(self, m: dict) -> None:
        t = m.get("t")
        cfg = self.agent.cfg
        if t == "ack":
            self._on_ack(int(m.get("f", 0)))
        elif t == "settings":
            self.quality = max(10, min(95, int(m.get("quality", self.quality))))
            self.fps = max(1, min(60, int(m.get("fps", self.fps))))
            self.scale = 2 if int(m.get("scale", self.scale)) == 2 else 1
            self.monitor = max(0, int(m.get("monitor", self.monitor)))
            codec = str(m.get("codec", self.codec_pref))
            self.codec_pref = codec if codec in ("auto", "h264", "jpeg") else "auto"
            self.bitrate = 0  # restart rate adaptation from the new target
        elif t in ("refresh", "key"):
            self._force = True
        elif t == "ping":
            await self.send_json({"t": "pong", "ts": m.get("ts")})
        elif t in ("mm", "md", "mu", "wh", "kd", "ku", "text", "kreset"):
            if cfg.allow_input and self.geo is not None and self.mode == "desktop":
                self._on_input(t, m)
                if t in ("mm", "md", "mu"):
                    self._set_pointer(m.get("x"), m.get("y"))
        elif t == "ptr":
            self._set_pointer(m.get("x"), m.get("y"))
        elif t in ("term_open", "term_resize", "term_close", "tcp_open", "tcp_close"):
            if cfg.allow_terminal:
                await self._on_terminal(t, m)
            else:
                err = "term_err" if t.startswith("term") else "tcp_err"
                await self.send_json({"t": err, "id": m.get("id"), "msg": "Terminal access is disabled on this host."})
        elif t == "clip":
            if cfg.allow_clipboard:
                s = str(m.get("s", ""))[:1_000_000]
                self._last_clip = s
                await asyncio.to_thread(_copy, s)
        elif t == "chat":
            self.agent.relay_chat(self, str(m.get("s", ""))[:4000])
        elif t in ("ls", "get", "fcancel", "put", "pend", "pabort"):
            if cfg.allow_files:
                await self._on_files(t, m)
            else:
                await self.send_json({"t": "ls_err", "path": "", "msg": "File transfer is disabled on this host."})

    def _on_input(self, t: str, m: dict) -> None:
        inp, geo = self.input, self.geo
        if t == "mm":
            inp.move(geo, m.get("x"), m.get("y"))
        elif t in ("md", "mu"):
            inp.button(geo, t == "md", m.get("b"), m.get("x"), m.get("y"))
        elif t == "wh":
            inp.wheel(m.get("dx", 0), m.get("dy", 0))
        elif t in ("kd", "ku"):
            inp.key(t == "kd", m.get("code"), m.get("key"))
        elif t == "text":
            inp.type_text(str(m.get("s", "")))
        elif t == "kreset":
            inp.release_keys()

    # ------------------------------------------------------- participants
    def _set_pointer(self, x, y) -> None:
        try:
            pos = (min(max(float(x), 0.0), 1.0), min(max(float(y), 0.0), 1.0))
        except (TypeError, ValueError):
            pos = None  # pointer left the screen
        if pos != self.pointer:
            self.pointer = pos
            self.agent.pointer_moved(self)

    # ----------------------------------------------------------- terminal
    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._pumps.add(task)
        task.add_done_callback(self._pumps.discard)

    @staticmethod
    def _size(m: dict) -> tuple[int, int]:
        return max(10, min(500, int(m.get("cols", 80)))), max(5, min(300, int(m.get("rows", 24))))

    async def _on_terminal(self, t: str, m: dict) -> None:
        tid = int(m.get("id", 0)) & 0xFFFFFFFF
        if t == "term_open":
            if len(self._terms) >= terminal.MAX_TERMINALS or tid in self._terms:
                await self.send_json({"t": "term_err", "id": tid, "msg": "Too many terminals."})
                return
            try:
                pty = terminal.Pty.spawn(*self._size(m))
            except Exception as e:
                await self.send_json({"t": "term_err", "id": tid, "msg": f"Could not start a shell: {e}"})
                return
            self._terms[tid] = pty
            self.agent.trace("terminal", self, detail=pty.shell)
            await self.send_json({"t": "term_opened", "id": tid, "shell": pty.shell})
            self._spawn(self._pump_pty(tid, pty))
        elif t == "term_resize":
            pty = self._terms.get(tid)
            if pty is not None:
                pty.resize(*self._size(m))
        elif t == "term_close":
            pty = self._terms.pop(tid, None)
            if pty is not None:
                pty.close()
        elif t == "tcp_open":
            port = int(m.get("port", 0))
            if not (0 < port < 65536) or len(self._tcps) >= terminal.MAX_TUNNELS or tid in self._tcps:
                await self.send_json({"t": "tcp_err", "id": tid, "msg": "invalid port or too many tunnels"})
                return
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 10)
            except Exception as e:
                await self.send_json({"t": "tcp_err", "id": tid, "msg": f"localhost:{port}: {e or type(e).__name__}"})
                return
            self._tcps[tid] = writer
            self.agent.trace("tunnel", self, detail=f"localhost:{port}")
            await self.send_json({"t": "tcp_opened", "id": tid})
            self._spawn(self._pump_tcp(tid, reader, writer))
        elif t == "tcp_close":
            w = self._tcps.pop(tid, None)
            if w is not None:
                w.close()

    async def _pump_pty(self, tid: int, pty) -> None:
        try:
            while data := await pty.read():
                await self._send(K_TERM, terminal.frame(tid, data))
        finally:
            if self._terms.pop(tid, None) is not None:
                pty.close()
            await self.send_json({"t": "term_closed", "id": tid})

    async def _pump_tcp(self, tid: int, reader, writer) -> None:
        try:
            while data := await reader.read(terminal.READ_CHUNK):
                await self._send(K_TCP, terminal.frame(tid, data))
        except (ConnectionError, OSError):
            pass
        finally:
            if self._tcps.pop(tid, None) is not None:
                writer.close()
            await self.send_json({"t": "tcp_closed", "id": tid})

    # -------------------------------------------------------------- files
    async def _on_files(self, t: str, m: dict) -> None:
        fid = int(m.get("id", 0)) & 0xFFFFFFFF
        if t == "ls":
            path = str(m.get("path", ""))
            try:
                listing = await asyncio.to_thread(files.list_dir, path)
                await self.send_json({"t": "ls", **listing})
            except OSError as e:
                await self.send_json({"t": "ls_err", "path": path, "msg": str(e)})
        elif t == "get":
            self._downloads[fid] = asyncio.create_task(self._download(fid, str(m.get("path", ""))))
        elif t == "fcancel":
            task = self._downloads.pop(fid, None)
            if task:
                task.cancel()
        elif t == "put":
            await self._begin_upload(fid, m)
        elif t in ("pend", "pabort"):
            u = self._uploads.pop(fid, None)
            if not u:
                return
            await asyncio.to_thread(u["fh"].close)
            if t == "pabort":
                u["tmp"].unlink(missing_ok=True)
                return
            u["tmp"].replace(u["target"])
            self.agent.ui.log(f"Received file {u['target']}")
            self.agent.trace("upload", self, detail=str(u["target"]))
            await self.send_json({"t": "pdone", "id": fid, "path": str(u["target"])})

    async def _download(self, fid: int, path: str) -> None:
        tmp_zip = None
        try:
            p = Path(path)
            name = p.name
            if await asyncio.to_thread(p.is_dir):
                await self.send_json({"t": "fprep", "id": fid})
                tmp_zip = await asyncio.to_thread(files.zip_dir, p)
                p, name = tmp_zip, (p.name or "drive") + ".zip"
            size = (await asyncio.to_thread(p.stat)).st_size
            fh = await asyncio.to_thread(open, p, "rb")
            try:
                await self.send_json({"t": "fstart", "id": fid, "name": name, "size": size})
                hdr = struct.pack(">I", fid)
                while chunk := await asyncio.to_thread(fh.read, files.CHUNK):
                    await self._send(K_FILE, hdr + chunk)
            finally:
                fh.close()
            await self.send_json({"t": "fend", "id": fid})
            self.agent.ui.log(f"Sent {path}")
            self.agent.trace("download", self, detail=f"{path} ({size} bytes)")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self.send_json({"t": "ferr", "id": fid, "msg": str(e)})
        finally:
            self._downloads.pop(fid, None)
            if tmp_zip is not None:
                tmp_zip.unlink(missing_ok=True)

    async def _begin_upload(self, fid: int, m: dict) -> None:
        try:
            d = Path(str(m["dir"])) if m.get("dir") else files.default_download_dir()
            if not d.is_dir():
                d = files.default_download_dir()
            target = files.unique_path(d, files.safe_name(m.get("name", "file")))
            tmp = target.with_name(target.name + ".part")
            fh = await asyncio.to_thread(open, tmp, "wb")
        except Exception as e:
            await self.send_json({"t": "perr", "id": fid, "msg": str(e)})
            return
        self._uploads[fid] = {"fh": fh, "tmp": tmp, "target": target}

    async def _on_upload_chunk(self, data: bytes) -> None:
        if len(data) < 4:
            return
        (fid,) = struct.unpack_from(">I", data)
        u = self._uploads.get(fid)
        if u:
            await asyncio.to_thread(u["fh"].write, data[4:])
