"""Compare encode pipelines on repeatable scenes:  python tests/pipeline_bench.py [seconds]

Each scene starts from one real screenshot of this machine and is replayed
identically for every pipeline, so the numbers are comparable:
    idle      nothing changes
    typing    a small text-sized area changes every frame
    scrolling the whole page moves up 12 px per frame
    video     a 1280x720 area plays moving content
Reports frames sent, bandwidth, and host CPU (one core = 100%) for encoding.
Capture cost is listed separately at the end (it depends on the backend, not the scene).
"""
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
from anidesk_host import capture  # noqa: E402

SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 4.0
FPS = 30

g = capture.Grabber()
base, _ = g.grab(1)
base = np.ascontiguousarray(base).copy()
H, W = base.shape[:2]
g.close()
yy, xx = np.mgrid[0:720, 0:1280]


_cache: dict = {}


def scene(name, i):
    """Pre-generated (1 s loop) so the benchmark measures the encoder, not frame synthesis."""
    if name not in _cache:
        _cache.clear()
        _cache[name] = [_make(name, k) for k in range(FPS)]
    return _cache[name][i % FPS], (name != "idle" or i == 0)


def _make(name, i):
    f = base
    if name == "idle":
        return f
    f = base.copy()
    if name == "typing":
        x = 200 + (i * 14) % 1200
        f[300:330, x:x + 14] = (i * 37) % 255 + 1
    elif name == "scrolling":
        f = np.roll(base, -12 * i, axis=0)
    elif name == "video":
        t = i / FPS
        v = (np.sin(xx / 60 + t * 3) * np.cos(yy / 45 - t * 2) * 100 + 128).astype(np.uint8)
        f[200:920, 300:1580, 0] = v
        f[200:920, 300:1580, 1] = np.roll(v, i * 7, axis=1)
        f[200:920, 300:1580, 2] = 255 - v
    return np.ascontiguousarray(f)


def run(label, codec, gpu_signal, simple_jpeg=True):
    saved = capture.simplejpeg
    if not simple_jpeg:
        capture.simplejpeg = None
    cap = capture.Capturer()
    cap.grabber.close()
    results = []
    try:
        for name in ("idle", "typing", "scrolling", "video"):
            i = 0
            state = {"i": 0}

            def grab(_monitor, name=name):
                f, changed = scene(name, state["i"])
                state["i"] += 1
                if gpu_signal:  # DXGI tells us whether anything changed
                    return f, capture.CHANGED if changed else capture.UNCHANGED
                return f, capture.MAYBE

            cap.grabber.grab = grab
            cap._key = None
            bitrate = int(W * H * FPS * 0.05)
            frames = sent = 0
            cpu0, t0 = time.process_time(), time.perf_counter()
            while time.perf_counter() - t0 < SECONDS:
                ts = time.perf_counter()
                i += 1
                payload, _, _ = cap.frame(i, 1, 1, codec, 60, bitrate, FPS, False)
                if payload is None and codec == "jpeg":
                    payload = cap.refine(i)
                if payload:
                    frames += 1
                    sent += len(payload)
                time.sleep(max(0, 1 / FPS - (time.perf_counter() - ts)))
            wall = time.perf_counter() - t0
            results.append(f"{sent * 8 / wall / 1e6:6.2f} Mb/s {(time.process_time() - cpu0) / wall * 100:4.0f}%")
    finally:
        cap.jpeg.close()
        capture.simplejpeg = saved
    print(f"  {label:<34}" + "".join(f"{r:>18}" for r in results))


print(f"{W}x{H}, {SECONDS:.0f}s per scene, {FPS} fps. Each cell: bandwidth, host CPU for encoding")
print(f"  {'pipeline':<34}" + "".join(f"{s:>18}" for s in ("idle", "typing", "scrolling", "video")))
run("v0.1  JPEG tiles (Pillow)", "jpeg", gpu_signal=False, simple_jpeg=False)
run("v0.2  JPEG tiles (simplejpeg)", "jpeg", gpu_signal=True)
enc = capture.h264_encoder()
if enc:
    run(f"v0.2  H.264 {enc[0]}", "h264", gpu_signal=True)
    capture._probed = False
    os.environ["ANIDESK_ENCODER"] = "libx264"
    if capture.h264_encoder():
        run("v0.2  H.264 libx264 (software)", "h264", gpu_signal=True)

print("\nCapture cost per frame (median):")
import mss  # noqa: E402

s = mss.MSS() if hasattr(mss, "MSS") else mss.mss()
ts = []
for _ in range(20):
    t = time.perf_counter(); s.grab(s.monitors[1]); ts.append(time.perf_counter() - t)
print(f"  mss (v0.1, used on Linux/macOS)   {sorted(ts)[10] * 1000:5.1f} ms every frame, even when idle")
gr = capture.Grabber()
if gr.backend(1) == "dxgi":
    ts = []
    for _ in range(20):
        t = time.perf_counter(); gr.grab(1); ts.append(time.perf_counter() - t); time.sleep(0.03)
    print(f"  DXGI (v0.2, Windows)              {sorted(ts)[10] * 1000:5.1f} ms, ~0 when nothing changed")
gr.close()
