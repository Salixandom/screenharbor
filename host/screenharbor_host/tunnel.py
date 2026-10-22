"""Cloudflare quick tunnel: expose the built-in relay as a temporary public HTTPS link.

Uses `cloudflared tunnel --url ...` (free, no Cloudflare account). If cloudflared
isn't installed, the official release binary is downloaded once into
~/.screenharbor/bin and checked against the SHA-256 published in the release notes.
The link (https://<random-words>.trycloudflare.com) dies when sharing stops.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from .config import CONFIG_DIR

log = logging.getLogger("screenharbor")

RELEASE_API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
URL_RE = re.compile(r"https://([a-z0-9-]+)\.trycloudflare\.com")


def _asset_name() -> str:
    m = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "i386": "386", "i686": "386", "x86": "386", "armv7l": "arm", "armv6l": "arm"}.get(m, "amd64")
    if sys.platform == "win32":
        return f"cloudflared-windows-{'386' if arch == '386' else 'amd64'}.exe"
    if sys.platform == "darwin":
        return f"cloudflared-darwin-{'arm64' if arch == 'arm64' else 'amd64'}.tgz"
    return f"cloudflared-linux-{arch}"


def find_cloudflared() -> str | None:
    found = shutil.which("cloudflared")
    if found:
        return found
    local = CONFIG_DIR / "bin" / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    return str(local) if local.exists() else None


def download_cloudflared(progress=lambda msg: None) -> str:
    """Fetch the official cloudflared release for this OS and verify its SHA-256."""
    asset = _asset_name()
    progress("Downloading cloudflared (one-time)...")
    req = urllib.request.Request(RELEASE_API, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "screenharbor"})
    with urllib.request.urlopen(req, timeout=30) as r:
        release = json.load(r)
    m = re.search(rf"^{re.escape(asset)}:\s*([0-9a-f]{{64}})\s*$", release.get("body", ""), re.M)
    if not m:
        raise RuntimeError(f"no published checksum for {asset}; install cloudflared manually")
    url = next(a["browser_download_url"] for a in release["assets"] if a["name"] == asset)

    bin_dir = CONFIG_DIR / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=bin_dir, suffix=".download")
    os.close(fd)
    try:
        h = hashlib.sha256()
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "screenharbor"}), timeout=120) as r, \
                open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                h.update(chunk)
                f.write(chunk)
        if h.hexdigest() != m.group(1):
            raise RuntimeError("cloudflared download failed its SHA-256 check")
        target = bin_dir / ("cloudflared.exe" if sys.platform == "win32" else "cloudflared")
        if asset.endswith(".tgz"):
            with tarfile.open(tmp) as t:
                member = t.getmember("cloudflared")
                with t.extractfile(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        else:
            os.replace(tmp, target)
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        log.info("installed %s (%s)", target, release.get("tag_name"))
        return str(target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _tie_to_parent_windows(pid: int) -> None:
    """Put the child in a Job Object that Windows kills when this process exits, even on a crash."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class EXTENDED(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    job = k32.CreateJobObjectW(None, None)
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
    proc = k32.OpenProcess(0x0001 | 0x0100, False, pid)  # PROCESS_TERMINATE | PROCESS_SET_QUOTA
    if not proc or not k32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(proc)):
        log.debug("could not tie cloudflared to this process (error %s)", ctypes.get_last_error())
    # The job handle is intentionally kept open: it closes (killing cloudflared) when we exit.
    _JOBS.append(job)


_JOBS: list = []


def _linux_pdeathsig() -> None:
    """Runs in the child before exec: get SIGTERM when the parent dies."""
    import ctypes
    import signal

    ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


class QuickTunnel:
    def __init__(self, local_http: str) -> None:
        self.local_http = local_http
        self.url: str | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._drain: asyncio.Task | None = None

    @property
    def code(self) -> str | None:
        m = URL_RE.match(self.url or "")
        return m.group(1) if m else None

    async def start(self, progress=lambda msg: None, timeout: float = 45) -> str:
        # A restarted quick tunnel gets a different hostname. Never let the
        # previous process's URL satisfy the new process's readiness check.
        self.url = None
        exe = find_cloudflared() or await asyncio.to_thread(download_cloudflared, progress)
        progress("Opening a Cloudflare tunnel...")
        flags: dict = {}
        if sys.platform == "win32":
            flags["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        elif sys.platform.startswith("linux"):
            flags["preexec_fn"] = _linux_pdeathsig
        self._proc = await asyncio.create_subprocess_exec(
            exe, "tunnel", "--no-autoupdate", "--url", self.local_http,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE, **flags)
        if sys.platform == "win32":
            try:
                _tie_to_parent_windows(self._proc.pid)
            except Exception:
                log.debug("job object setup failed", exc_info=True)
        async def wait_ready() -> None:
            registered = False
            while not (self.url and registered):
                line = await self._proc.stderr.readline()
                if not line:
                    raise RuntimeError("cloudflared exited before the tunnel was ready")
                text = line.decode(errors="replace")
                log.debug("cloudflared: %s", text.rstrip())
                m = URL_RE.search(text)
                if m and not self.url:
                    self.url = m.group(0)
                if "Registered tunnel connection" in text:
                    registered = True

        try:
            await asyncio.wait_for(wait_ready(), timeout)
        except BaseException:
            await self.stop()
            raise
        # Keep reading so cloudflared never blocks on a full stderr pipe.
        self._drain = asyncio.create_task(self._drain_stderr())
        return self.url

    async def _drain_stderr(self) -> None:
        while self._proc and await self._proc.stderr.readline():
            pass

    async def stop(self) -> None:
        if self._drain:
            self._drain.cancel()
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), 5)
            except asyncio.TimeoutError:
                self._proc.kill()
        self._proc = None
        self.url = None


class NamedTunnel(QuickTunnel):
    """Run a Cloudflare-managed tunnel using its protected token file."""

    def __init__(self, local_http: str, hostname: str, token_file: str) -> None:
        super().__init__(local_http)
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname, re.I):
            raise ValueError("enter a valid custom hostname, such as remote.example.com")
        token_path = os.path.abspath(os.path.expanduser(token_file))
        if not os.path.isfile(token_path):
            raise ValueError(f"Cloudflare tunnel token file not found: {token_path}")
        self.hostname = hostname.lower()
        self.token_file = token_path

    @property
    def code(self) -> str | None:
        return self.hostname

    async def start(self, progress=lambda msg: None, timeout: float = 60) -> str:
        exe = find_cloudflared() or await asyncio.to_thread(download_cloudflared, progress)
        progress(f"Connecting named Cloudflare tunnel for {self.hostname}...")
        flags: dict = {}
        if sys.platform == "win32":
            flags["creationflags"] = 0x08000000
        elif sys.platform.startswith("linux"):
            flags["preexec_fn"] = _linux_pdeathsig
        self._proc = await asyncio.create_subprocess_exec(
            exe, "tunnel", "--no-autoupdate", "run", "--token-file", self.token_file,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE, **flags)
        if sys.platform == "win32":
            try:
                _tie_to_parent_windows(self._proc.pid)
            except Exception:
                log.debug("job object setup failed", exc_info=True)

        async def wait_ready() -> None:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    raise RuntimeError("cloudflared exited before the named tunnel connected")
                text = line.decode(errors="replace")
                log.debug("cloudflared: %s", text.rstrip())
                if "Registered tunnel connection" in text:
                    return

        try:
            await asyncio.wait_for(wait_ready(), timeout)
        except BaseException:
            await self.stop()
            raise
        self.url = f"https://{self.hostname}"
        self._drain = asyncio.create_task(self._drain_stderr())
        return self.url
