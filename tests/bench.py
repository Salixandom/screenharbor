"""Benchmark capture + encode paths on this machine:  python tests/bench.py [seconds]

Measures per-frame cost and output size so codec/capture choices are based on numbers.
"""
import io
import os
import statistics
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))

SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0


def timeit(fn, n=None, seconds=SECONDS):
    times, out = [], None
    end = time.perf_counter() + seconds
    while time.perf_counter() < end and (n is None or len(times) < n):
        t = time.perf_counter()
        out = fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1000, out, len(times)


def row(name, ms, extra=""):
    print(f"  {name:<44} {ms:7.1f} ms   {extra}")


print("== capture")
import mss  # noqa: E402

sct = getattr(mss, "MSS", mss.mss)()
mon = sct.monitors[1]
ms_, shot, _ = timeit(lambda: sct.grab(mon))
row(f"mss grab {shot.width}x{shot.height}", ms_)
frame = np.frombuffer(shot.bgra, np.uint8).reshape(shot.height, shot.width, 4).copy()
H, W = frame.shape[:2]

try:
    import dxcam  # noqa: E402

    cam = dxcam.create(output_color="BGRA")
    cam.grab()
    time.sleep(0.1)

    def dx():
        return cam.grab()  # returns None when nothing changed

    ms_, _, n = timeit(dx)
    row("dxcam (DXGI duplication) grab", ms_, "(None = no change, cheap)")
    del cam
except Exception as e:
    print("  dxcam unavailable:", e)

print("== full-frame JPEG encode (q=60)")
from PIL import Image  # noqa: E402


def pil():
    img = Image.frombuffer("RGB", (W, H), frame, "raw", "BGRX", 0, 1)
    b = io.BytesIO()
    img.save(b, "JPEG", quality=60, subsampling=2)
    return b.getvalue()


ms_, out, _ = timeit(pil)
row("Pillow (current)", ms_, f"{len(out) / 1024:.0f} KB")
try:
    import simplejpeg  # noqa: E402

    ms_, out, _ = timeit(lambda: simplejpeg.encode_jpeg(frame, quality=60, colorspace="BGRA", colorsubsampling="420", fastdct=True))
    row("simplejpeg BGRA direct (turbo, fastdct)", ms_, f"{len(out) / 1024:.0f} KB")
except Exception as e:
    print("  simplejpeg unavailable:", e)

print("== tile diff (2 consecutive grabs)")
from screenharbor_host.capture import _dirty_tiles, _merge  # noqa: E402

a32 = frame.view(np.uint32).reshape(H, W)
b = a32.copy()
b[100:300, 400:900] += 1
ms_, mask, _ = timeit(lambda: _dirty_tiles(a32, b))
row("dirty tile mask", ms_, f"{mask.sum()} dirty tiles")
ms_, rects, _ = timeit(lambda: _merge(mask, H, W))
row("merge rects", ms_, f"{len(rects)} rects")

print("== H.264 encoders (30 frames of the live screen, 1/2 res and full res)")
import av  # noqa: E402

for codec in ("h264_nvenc", "h264_qsv", "h264_amf", "h264_mf", "libx264"):
    for scale in (1, 2):
        w, h = (W // scale) & ~1, (H // scale) & ~1
        try:
            enc = av.CodecContext.create(codec, "w")
            enc.width, enc.height, enc.pix_fmt = w, h, "yuv420p"
            enc.time_base = __import__("fractions").Fraction(1, 30)
            enc.framerate = 30
            enc.bit_rate = 4_000_000
            enc.gop_size = 600
            enc.max_b_frames = 0
            opts = {"libx264": {"preset": "ultrafast", "tune": "zerolatency"},
                    "h264_nvenc": {"preset": "p1", "tune": "ull", "zerolatency": "1"},
                    "h264_qsv": {"preset": "veryfast", "async_depth": "1"},
                    "h264_amf": {"usage": "ultralowlatency"},
                    "h264_mf": {"rate_control": "cbr", "scenario": "display_remoting"}}[codec]
            enc.options = opts
            enc.open()
        except Exception as e:
            print(f"  {codec:<12} scale 1/{scale}: unavailable ({str(e)[:60]})")
            break
        src = frame[: h * scale : scale, : w * scale : scale]
        sizes, times = [], []
        for i in range(30):
            vf = av.VideoFrame.from_ndarray(np.ascontiguousarray(src), format="bgra")
            vf.pts = i
            t = time.perf_counter()
            pk = enc.encode(vf.reformat(format="yuv420p"))
            times.append(time.perf_counter() - t)
            sizes += [p.size for p in pk]
        row(f"{codec} {w}x{h} (static screen)", statistics.median(times) * 1000,
            f"first {sizes[0] / 1024 if sizes else 0:.0f} KB, then ~{statistics.median(sizes[1:]) if len(sizes) > 1 else 0:.0f} B/frame")
