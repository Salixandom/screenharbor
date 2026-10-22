"""Measure screen-update latency and resource use of a real host.

    uv run --project host python tests/measure.py            # local server
    uv run --project host python tests/measure.py --share    # through a Cloudflare share link

Latency: a small window on this machine flips black/white; we time how long until a
connected viewer *receives* the change (JPEG tiles) or has *decoded* it (H.264, with
FFmpeg, like the browser's WebCodecs would). Everything runs on one machine, so one
clock measures both ends. Add one display refresh (~8-16 ms) for "glass to glass".
"""
import argparse
import asyncio
import json
import os
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "host"))
from screenharbor_host.client import K_JSON, Client  # noqa: E402

K_FRAME, K_VIDEO = 2, 4
BOX = (200, 200, 320, 240)  # x, y, w, h on screen 1 (physical pixels)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rss(pids) -> float:
    total = 0
    for pid in pids:
        try:
            p = psutil.Process(pid)
            total += p.memory_info().rss + sum(c.memory_info().rss for c in p.children(recursive=True))
        except psutil.Error:
            pass
    return total / 2**20


def cpu(pids, seconds=3.0) -> float:
    procs = []
    for pid in pids:
        try:
            p = psutil.Process(pid)
            procs += [p, *p.children(recursive=True)]
        except psutil.Error:
            pass
    for p in procs:
        p.cpu_percent(None)
    time.sleep(seconds)
    return sum(p.cpu_percent(None) for p in procs if p.is_running())


class Flasher:
    """A borderless always-on-top box whose color we flip on demand (in its own Tk thread)."""

    def __init__(self):
        self.ready = threading.Event()
        self.flips: list[float] = []
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(10)

    def _run(self):
        import tkinter as tk
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        x, y, w, h = BOX
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.canvas = tk.Canvas(self.root, width=w, height=h, bg="black", highlightthickness=0)
        self.canvas.pack()
        self.white = False
        self.root.after(200, self.ready.set)
        self.root.mainloop()

    def flip(self) -> bool:
        done = threading.Event()

        def go():
            self.white = not self.white
            self.canvas.configure(bg="white" if self.white else "black")
            self.root.update_idletasks()
            self.root.update()
            self.flips.append(time.perf_counter())
            done.set()
        self.root.after(0, go)
        done.wait(5)
        return self.white


class Viewer(Client):
    """Desktop-mode client that acks frames and reports when the box changed."""

    def __init__(self, codec):
        super().__init__()
        self.codec = codec
        self.events: asyncio.Queue = asyncio.Queue()
        self.decoder = None

    async def _read_loop(self):
        import av
        import numpy as np
        async for raw in self.ws:
            if not isinstance(raw, bytes):
                continue
            pt = self.ch.open(raw)
            kind, body = pt[0], pt[1:]
            now = time.perf_counter()
            if kind == K_JSON:
                continue
            frame_no = struct.unpack_from(">I", body)[0]
            if kind == K_FRAME:
                n = struct.unpack_from(">H", body, 4)[0]
                off, hit = 6, False
                for _ in range(n):
                    x, y, w, h, _f, ln = struct.unpack_from(">HHHHBI", body, off)
                    off += 13 + ln
                    bx, by, bw, bh = BOX
                    hit = hit or not (x + w <= bx or bx + bw <= x or y + h <= by or by + bh <= y)
                if hit:
                    self.events.put_nowait(("hit", now, len(body)))
            elif kind == K_VIDEO:
                if self.decoder is None:
                    self.decoder = av.CodecContext.create("h264", "r")
                for fr in self.decoder.decode(av.Packet(body[5:])):
                    img = fr.to_ndarray(format="gray")
                    x, y, w, h = BOX
                    v = float(np.mean(img[y + 20:y + h - 20, x + 20:x + w - 20]))
                    self.events.put_nowait(("lum", time.perf_counter(), v))
            try:
                await self.send_json({"t": "ack", "f": frame_no})
            except Exception:
                return  # we closed the connection


async def latency(url, hid, pw, codec, flasher, rounds=12):
    v = Viewer(codec)
    await v.open(url, hid, pw, f"measure-{codec}", mode="desktop")
    # Re-auth sends no codecs; tell the host what we can decode, then settle.
    await v.send_json({"t": "settings", "quality": 60, "fps": 60, "scale": 1, "monitor": 1, "codec": codec})
    await asyncio.sleep(2.5)
    samples = []
    for _ in range(rounds):
        while not v.events.empty():
            v.events.get_nowait()
        white = await asyncio.to_thread(flasher.flip)
        t0 = flasher.flips[-1]
        try:
            while True:
                kind, t, val = await asyncio.wait_for(v.events.get(), 3)
                if t < t0:
                    continue
                if kind == "hit" or (kind == "lum" and ((val > 200) if white else (val < 50))):
                    samples.append((t - t0) * 1000)
                    break
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.4)
    await v.close()
    return samples


def start_host(url, home, password, *extra):
    py = ROOT / "host" / (".venv/Scripts/python.exe" if sys.platform == "win32" else ".venv/bin/python")
    env = {**os.environ, "SCREENHARBOR_HOME": home, "PYTHONUNBUFFERED": "1"}
    p = subprocess.Popen([str(py), "-m", "screenharbor_host", "--headless", "--no-ask", "--password", password,
                          "--server", url, *extra], cwd=ROOT / "host", env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    info = {}
    deadline = time.time() + 90
    for line in p.stdout:
        if m := re.search(r"ScreenHarbor ID: ([\d ]+)", line):
            info["id"] = m.group(1).replace(" ", "")
        if m := re.search(r"Code:\s+([a-z0-9-]+)", line):
            info["code"] = m.group(1)
        if "id" in info and ("--share" not in extra or "code" in info):
            break
        if time.time() > deadline:
            raise SystemExit("host did not start")
    threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
    return p, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", action="store_true", help="measure through a Cloudflare share link")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    home = tempfile.mkdtemp(prefix="screenharbor-measure-")
    procs = []
    try:
        if a.share:
            host, info = start_host("ws://127.0.0.1:9/ws", home, "Measure-pass-1", "--share")
            url, hid, srv = f"wss://{info['code']}.trycloudflare.com/ws", info["id"], None
            label = "Cloudflare share link"
        else:
            port = free_port()
            srv = subprocess.Popen([shutil.which("node"), "index.js", "--port", str(port), "--bind", "127.0.0.1",
                                    "--data-dir", os.path.join(home, "srv")], cwd=ROOT / "server",
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(srv)
            time.sleep(1)
            url = f"ws://127.0.0.1:{port}/ws"
            host, info = start_host(url, home, "Measure-pass-1")
            hid = info["id"]
            label = "local server"
        procs.append(host)
        time.sleep(2)
        pids = [host.pid]
        print(f"\n== {label}")
        print(f"host idle (no viewer):     RAM {rss(pids):6.0f} MB   CPU {cpu(pids):5.1f}%"
              + (f"    server RAM {rss([srv.pid]):.0f} MB" if srv else ""))

        flasher = Flasher()
        for codec in ("h264", "jpeg"):
            res = {}

            def bg():
                res["lat"] = asyncio.run(latency(url, hid, "Measure-pass-1", codec, flasher))
            t = threading.Thread(target=bg)
            t.start()
            time.sleep(4)
            mem, load = rss(pids), cpu(pids, 3)
            t.join()
            lat = res.get("lat") or []
            what = "decoded" if codec == "h264" else "received"
            if lat:
                print(f"{codec:>4} session: RAM {mem:6.0f} MB   CPU {load:5.1f}%   screen change -> {what}: "
                      f"median {statistics.median(lat):5.1f} ms, min {min(lat):5.1f}, max {max(lat):5.1f} "
                      f"({len(lat)} samples)")
            else:
                print(f"{codec:>4} session: RAM {mem:6.0f} MB   CPU {load:5.1f}%   (no latency samples)")
        print(f"host after sessions:       RAM {rss(pids):6.0f} MB")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
