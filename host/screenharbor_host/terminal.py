"""Remote shells (PTY) and localhost TCP forwarding for terminal/SSH access.

Terminal: a real pseudo-terminal running the user's shell (ConPTY via pywinpty on
Windows, the stdlib pty on Linux/macOS). Works without a desktop/display, so a
headless server can be reached through a share link with no SSH server or open ports.

TCP forwarding: the viewer asks for a port, we connect to 127.0.0.1:<port> on this
machine and pipe bytes both ways (e.g. port 22 for real ssh/scp/sftp/VS Code Remote).
Only this machine's loopback is reachable, never other hosts on its network.

Wire format (after the 1-byte kind): u32 stream id | bytes.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import struct
import sys
from pathlib import Path

log = logging.getLogger("screenharbor")

MAX_TERMINALS = 8
MAX_TUNNELS = 32
READ_CHUNK = 64 * 1024


def default_shell() -> list[str]:
    if sys.platform == "win32":
        pwsh = shutil.which("pwsh")
        return [pwsh or "powershell.exe", "-NoLogo"]
    shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
    return [shell, "-l"]


class Pty:
    """Common interface; use Pty.spawn()."""

    shell = ""

    @staticmethod
    def spawn(cols: int, rows: int) -> "Pty":
        return _WinPty(cols, rows) if sys.platform == "win32" else _PosixPty(cols, rows)

    async def read(self) -> bytes:  # b"" when the shell exited
        raise NotImplementedError

    def write(self, data: bytes) -> None:
        raise NotImplementedError

    def resize(self, cols: int, rows: int) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class _PosixPty(Pty):
    def __init__(self, cols: int, rows: int) -> None:
        import pty

        argv = default_shell()
        self.shell = argv[0]
        pid, fd = pty.fork()
        if pid == 0:  # child: become the shell
            try:
                os.chdir(Path.home())
                os.environ["TERM"] = "xterm-256color"
                os.environ["COLORTERM"] = "truecolor"
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.resize(cols, rows)
        self._queue: asyncio.Queue = asyncio.Queue()
        asyncio.get_running_loop().add_reader(fd, self._on_readable)

    def _on_readable(self) -> None:
        try:
            data = os.read(self.fd, READ_CHUNK)
        except OSError:
            data = b""
        if not data:
            asyncio.get_running_loop().remove_reader(self.fd)
        self._queue.put_nowait(data)

    async def read(self) -> bytes:
        return await self._queue.get()

    def write(self, data: bytes) -> None:
        os.write(self.fd, data)

    def resize(self, cols: int, rows: int) -> None:
        import fcntl
        import termios

        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def close(self) -> None:
        import signal

        try:
            asyncio.get_running_loop().remove_reader(self.fd)
        except Exception:
            pass
        self._queue.put_nowait(b"")  # wake whoever is waiting in read(): the terminal is gone
        for sig in (signal.SIGHUP, signal.SIGKILL):
            try:
                os.kill(self.pid, sig)
            except ProcessLookupError:
                break
        try:
            os.close(self.fd)
            os.waitpid(self.pid, os.WNOHANG)
        except OSError:
            pass


class _WinPty(Pty):
    def __init__(self, cols: int, rows: int) -> None:
        from winpty import PtyProcess

        argv = default_shell()
        self.shell = argv[0]
        env = {**os.environ, "TERM": "xterm-256color"}
        self.proc = PtyProcess.spawn(argv, dimensions=(rows, cols), cwd=str(Path.home()), env=env)

    async def read(self) -> bytes:
        while True:
            try:
                text = await asyncio.to_thread(self.proc.read, READ_CHUNK)
            except EOFError:
                return b""
            if text:
                return text.encode("utf-8", "replace")
            if not self.proc.isalive():
                return b""

    def write(self, data: bytes) -> None:
        self.proc.write(data.decode("utf-8", "replace"))

    def resize(self, cols: int, rows: int) -> None:
        self.proc.setwinsize(rows, cols)

    def close(self) -> None:
        try:
            self.proc.terminate(force=True)
        except Exception:
            pass


def frame(stream_id: int, data: bytes) -> bytes:
    return struct.pack(">I", stream_id) + data


def unframe(payload: bytes) -> tuple[int, bytes]:
    return struct.unpack_from(">I", payload)[0], payload[4:]
