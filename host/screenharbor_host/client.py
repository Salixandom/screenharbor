"""screenharbor: reach a ScreenHarbor host from the command line.

    screenharbor term    <code|id>                 a shell on the host, in this terminal (no SSH server needed)
    screenharbor ssh     <code|id> [user]          real ssh through ScreenHarbor (host runs an SSH server)
    screenharbor forward <code|id> 2222:22         forward local port 2222 to the host's localhost:22
    screenharbor proxy   <code|id> 22              stdin/stdout <-> host's localhost:22 (ssh ProxyCommand)

<code|id> is a share code / link (gentle-river-moon-fox) or a 9-digit ID with --server.
The password is asked once (or read from SCREENHARBOR_PASSWORD). Everything is end-to-end
encrypted exactly like the web viewer; the host still asks before accepting unless
the unattended password is used.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from .config import normalize_server
from .crypto import INFO, Channel, password_key
from . import directory

K_JSON, K_TERM, K_TCP = 1, 5, 6


def say(msg: str) -> None:
    print(f"[screenharbor] {msg}", file=sys.stderr, flush=True)


class Failure(Exception):
    pass


def resolve(target: str, server: str | None) -> tuple[str, str, str]:
    """-> (websocket url, host id or "", short label)"""
    t = target.strip()
    address_link = re.search(r"#address=((?:screen|ani)-[0-9a-f]{40})", t, re.I)
    if address_link:
        addr = address_link.group(1)
        try:
            record = directory.resolve(addr)
        except ValueError as e:
            raise Failure(str(e)) from e
        return record["url"].replace("https://", "wss://") + "/ws", record["id"], addr.lower()
    digits = re.sub(r"[\s-]", "", t)
    if re.fullmatch(r"(?:screen|ani)-[0-9a-f]{40}", t, re.I):
        try:
            record = directory.resolve(t)
        except ValueError as e:
            raise Failure(str(e)) from e
        return record["url"].replace("https://", "wss://") + "/ws", record["id"], t.lower()
    if digits.isdigit() and len(digits) >= 9:
        if not server:
            raise Failure("a 9-digit ID needs --server ws(s)://your-server/ws (or use the share code)")
        return normalize_server(server), digits, digits
    m = re.match(r"^(?:https?://)?([a-z0-9-]+)\.trycloudflare\.com/?(?:#id=(\d+))?", t, re.I)
    code = m.group(1) if m else (t if re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)+", t, re.I) else None)
    if not code and t.lower().startswith("https://"):
        from urllib.parse import urlsplit
        try:
            u = urlsplit(t)
            if u.hostname and "." in u.hostname and not u.username and not u.password and not u.port and u.path in ("", "/") and not u.query:
                id_match = re.search(r"#id=(\d+)", t, re.I)
                return f"wss://{u.hostname}/ws", id_match.group(1) if id_match else "", u.hostname
        except ValueError:
            pass
    if not code:
        raise Failure(f"not a ScreenHarbor ID, share code or link: {target!r}")
    code = code.lower()
    return f"wss://{code}.trycloudflare.com/ws", (m.group(2) or "") if m else "", code


class Client:
    def __init__(self) -> None:
        self.ws = None
        self.ch: Channel | None = None
        self.welcome: dict = {}
        self._lock = asyncio.Lock()
        self._events: dict[tuple[str, int], asyncio.Future] = {}
        self.streams: dict[int, asyncio.Queue] = {}
        self._reader: asyncio.Task | None = None
        self._next = 0

    def new_id(self) -> int:
        self._next += 1
        return self._next

    async def open(self, url: str, hid: str, password: str, name: str, mode: str = "terminal") -> None:
        self.ws = await connect(url, open_timeout=20, max_size=64 * 1024 * 1024, compression=None, ping_interval=20)
        await self.ws.send(json.dumps({"t": "connect", "id": hid}))
        candidates: list[Channel] = []
        while True:
            raw = await asyncio.wait_for(self.ws.recv(), 90)
            if isinstance(raw, bytes):
                for c in candidates:
                    try:
                        pt = c.open(raw)
                    except Exception:
                        continue
                    self.ch = c
                    break
                if self.ch is None:
                    raise Failure("could not verify the host")
                msg = json.loads(pt[1:])
                if msg.get("t") == "denied":
                    raise Failure("the remote user declined the connection")
                if msg.get("t") != "welcome":
                    raise Failure(f"unexpected reply: {msg.get('t')}")
                self.welcome = msg
                break
            m = json.loads(raw)
            t = m.get("t")
            if t == "waiting":
                say("waiting for the host (they may need to click Accept)...")
            elif t == "error":
                raise Failure(m.get("msg") or "error")
            elif t == "auth_failed":
                raise Failure("wrong password")
            elif t == "hello":
                candidates = await self._handshake(m, password, name, mode)
        self._reader = asyncio.create_task(self._read_loop())

    async def _handshake(self, m: dict, password: str, name: str, mode: str) -> list[Channel]:
        priv = ec.generate_private_key(ec.SECP256R1())
        mine = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        host_pub = base64.b64decode(m["pub"])
        shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), host_pub))
        await self.ws.send(json.dumps({"t": "hello", "v": 1, "pub": base64.b64encode(mine).decode()}))
        auth = bytes([K_JSON]) + json.dumps({"t": "auth", "name": name, "codecs": [], "mode": mode}).encode()
        out = []
        for salt in (base64.b64decode(x) for x in m["salts"]):
            okm = HKDF(hashes.SHA256(), 64, password_key(password, salt), INFO + host_pub + mine).derive(shared)
            ch = Channel(send_key=okm[32:], recv_key=okm[:32])
            out.append(ch)
            await self.ws.send(ch.seal(auth))
        return out

    async def send(self, kind: int, payload: bytes) -> None:
        async with self._lock:
            await self.ws.send(self.ch.seal(bytes([kind]) + payload))

    async def send_json(self, obj: dict) -> None:
        await self.send(K_JSON, json.dumps(obj).encode())

    async def request(self, obj: dict, ok: str, err: str) -> dict:
        fut = asyncio.get_running_loop().create_future()
        self._events[(ok, obj["id"])] = fut
        self._events[(err, obj["id"])] = fut
        await self.send_json(obj)
        reply = await asyncio.wait_for(fut, 30)
        if reply["t"] == err:
            raise Failure(reply.get("msg") or err)
        return reply

    async def _read_loop(self) -> None:
        try:
            async for raw in self.ws:
                if not isinstance(raw, bytes):
                    continue
                pt = self.ch.open(raw)
                kind = pt[0]
                if kind in (K_TERM, K_TCP):
                    (sid,) = struct.unpack_from(">I", pt, 1)
                    q = self.streams.get(sid)
                    if q is not None:
                        q.put_nowait(pt[5:])
                elif kind == K_JSON:
                    m = json.loads(pt[1:])
                    t, sid = m.get("t"), m.get("id")
                    fut = self._events.pop((t, sid), None)
                    if fut is not None and not fut.done():
                        fut.set_result(m)
                    if t in ("term_closed", "tcp_closed") and sid in self.streams:
                        self.streams[sid].put_nowait(b"")
                    elif t == "chat":
                        say(f"chat from {m.get('from', 'host')}: {m.get('s')}")
        except ConnectionClosed:
            pass
        finally:
            for q in self.streams.values():
                q.put_nowait(b"")

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()


# ------------------------------------------------------------------ helpers
async def _stdin_chunks():
    """Yield raw bytes from stdin without blocking the event loop."""
    loop = asyncio.get_running_loop()
    if sys.platform == "win32":
        reader = sys.stdin.buffer.raw.read if hasattr(sys.stdin.buffer, "raw") else sys.stdin.buffer.read1
        while True:
            data = await loop.run_in_executor(None, reader, 4096)
            if not data:
                return
            yield data
    else:
        q: asyncio.Queue = asyncio.Queue()
        fd = sys.stdin.fileno()

        def readable():
            try:
                q.put_nowait(os.read(fd, 4096))
            except OSError:
                q.put_nowait(b"")
        loop.add_reader(fd, readable)
        try:
            while data := await q.get():
                yield data
        finally:
            loop.remove_reader(fd)


def _write_stdout(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


class _RawTerminal:
    """Put the local terminal in raw mode (and VT mode on Windows) for the duration."""

    def __enter__(self):
        self.saved = None
        if not sys.stdin.isatty():
            return self
        if sys.platform == "win32":
            import ctypes
            k = ctypes.windll.kernel32
            self.hin, self.hout = k.GetStdHandle(-10), k.GetStdHandle(-11)
            a, b = ctypes.c_uint(), ctypes.c_uint()
            k.GetConsoleMode(self.hin, ctypes.byref(a))
            k.GetConsoleMode(self.hout, ctypes.byref(b))
            self.saved = (a.value, b.value, k.GetConsoleCP(), k.GetConsoleOutputCP())
            k.SetConsoleCP(65001)
            k.SetConsoleOutputCP(65001)
            # VT input on; line input, echo and Ctrl+C processing off -> keys go to the remote shell.
            k.SetConsoleMode(self.hin, (a.value | 0x200) & ~(0x1 | 0x2 | 0x4))
            k.SetConsoleMode(self.hout, b.value | 0x4 | 0x1)
        else:
            import termios
            import tty
            self.saved = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        return self

    def __exit__(self, *exc):
        if self.saved is None:
            return
        if sys.platform == "win32":
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(self.hin, self.saved[0])
            k.SetConsoleMode(self.hout, self.saved[1])
            k.SetConsoleCP(self.saved[2])
            k.SetConsoleOutputCP(self.saved[3])
        else:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.saved)


async def _pipe_stream(c: Client, kind: int, sid: int, read_local, write_local) -> None:
    """Pump one stream both ways until either side closes."""
    async def up():
        async for chunk in read_local():
            await c.send(kind, struct.pack(">I", sid) + chunk)

    async def down():
        q = c.streams[sid]
        while data := await q.get():
            write_local(data)

    tasks = [asyncio.create_task(up()), asyncio.create_task(down())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()


# ----------------------------------------------------------------- commands
async def cmd_term(c: Client, args) -> int:
    cols, rows = shutil.get_terminal_size((100, 30))
    sid = c.new_id()
    c.streams[sid] = asyncio.Queue()
    opened = await c.request({"t": "term_open", "id": sid, "cols": cols, "rows": rows}, "term_opened", "term_err")
    say(f"connected to {c.welcome.get('name')} ({opened.get('shell')}). Exit the shell to disconnect.")

    async def watch_size():
        last = (cols, rows)
        while True:
            await asyncio.sleep(0.5)
            now = tuple(shutil.get_terminal_size(last))
            if now != last:
                last = now
                await c.send_json({"t": "term_resize", "id": sid, "cols": now[0], "rows": now[1]})

    sizer = asyncio.create_task(watch_size())
    try:
        with _RawTerminal():
            await _pipe_stream(c, K_TERM, sid, _stdin_chunks, _write_stdout)
    finally:
        sizer.cancel()
    return 0


async def cmd_proxy(c: Client, args) -> int:
    sid = c.new_id()
    c.streams[sid] = asyncio.Queue()
    await c.request({"t": "tcp_open", "id": sid, "port": args.port}, "tcp_opened", "tcp_err")
    await _pipe_stream(c, K_TCP, sid, _stdin_chunks, _write_stdout)
    return 0


async def cmd_forward(c: Client, args) -> int:
    local, _, remote = args.ports.partition(":")
    lport, rport = int(local), int(remote or local)

    async def handle(reader, writer):
        sid = c.new_id()
        c.streams[sid] = asyncio.Queue()
        try:
            await c.request({"t": "tcp_open", "id": sid, "port": rport}, "tcp_opened", "tcp_err")
        except Failure as e:
            say(str(e))
            writer.close()
            return

        async def read_local():
            while data := await reader.read(64 * 1024):
                yield data

        def write_local(data):
            writer.write(data)

        await _pipe_stream(c, K_TCP, sid, read_local, write_local)
        await c.send_json({"t": "tcp_close", "id": sid})
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", lport)
    say(f"forwarding localhost:{lport} -> {c.welcome.get('name')}:localhost:{rport}. Ctrl+C to stop.")
    async with server:
        await c._reader  # until the ScreenHarbor connection ends
    return 0


def run_ssh(args, password: str) -> int:
    ssh = shutil.which("ssh")
    if not ssh:
        raise Failure("no ssh client found (install OpenSSH)")
    url, hid, label = resolve(args.target, args.server)
    proxy = [sys.executable, "-m", "screenharbor_host.client", "proxy", args.target, str(args.port)]
    if args.server:
        proxy += ["--server", args.server]
    if sys.platform == "win32":
        # Windows OpenSSH runs this via CreateProcess, Git-for-Windows ssh via bash: forward slashes
        # in double quotes work for both (bash would eat the backslashes otherwise).
        proxy_cmd = " ".join(f'"{a.replace(chr(92), "/")}"' for a in proxy)
    else:
        proxy_cmd = shlex.join(proxy)
    dest = f"{args.user}@screenharbor" if args.user else "screenharbor"
    # OpenSSH keeps parsing options after the destination, so extra options and a remote command both fit here.
    extra = [a for a in args.ssh_args if a != "--"]
    cmd = [ssh, "-o", f"ProxyCommand={proxy_cmd}", "-o", f"HostKeyAlias=screenharbor-{label}", dest, *extra]
    env = {**os.environ, "SCREENHARBOR_PASSWORD": password}  # the proxy child reads it; never on a command line
    return subprocess.call(cmd, env=env)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="screenharbor", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", help="ID/relay server for 9-digit IDs, e.g. wss://example.com:8443/ws")
    ap.add_argument("--name", default=f"{getpass.getuser()}@{socket.gethostname()} (cli)", help="name shown to the host")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("term", "ssh", "forward", "proxy"):
        p = sub.add_parser(name)
        p.add_argument("target", help="share code, share link, or 9-digit ID")
        p.add_argument("--server", default=argparse.SUPPRESS)
        if name == "ssh":
            p.add_argument("user", nargs="?", help="login name on the host")
            p.add_argument("--port", type=int, default=22, help="SSH port on the host (default 22)")
            p.add_argument("ssh_args", nargs=argparse.REMAINDER, help="extra arguments passed to ssh")
        elif name == "forward":
            p.add_argument("ports", help="LOCAL:REMOTE, e.g. 2222:22 or 8080:3000")
        elif name == "proxy":
            p.add_argument("port", type=int)
    args = ap.parse_args(argv)
    args.server = getattr(args, "server", None)

    password = os.environ.get("SCREENHARBOR_PASSWORD") or getpass.getpass("ScreenHarbor password: ")
    try:
        if args.cmd == "ssh":
            sys.exit(run_ssh(args, password))
        url, hid, _ = resolve(args.target, args.server)

        async def go() -> int:
            c = Client()
            try:
                await c.open(url, hid, password, args.name)
                if not c.welcome.get("perms", {}).get("terminal"):
                    raise Failure("terminal/SSH access is disabled on that host")
                return await {"term": cmd_term, "proxy": cmd_proxy, "forward": cmd_forward}[args.cmd](c, args)
            finally:
                await c.close()

        sys.exit(asyncio.run(go()))
    except Failure as e:
        say(f"error: {e}")
        sys.exit(1)
    except (OSError, ConnectionClosed, asyncio.TimeoutError) as e:
        say(f"connection failed: {e or type(e).__name__}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
