"""Screen capture backends and encoders.

Capture
    Windows: DXGI Desktop Duplication (dxcam) for the primary monitor. The GPU
             tells us when nothing changed, so an idle desktop costs ~0 CPU.
    Others / other monitors: mss (XShm on X11, CoreGraphics on macOS, GDI on Windows).

Encoding (chosen per session)
    "h264": hardware H.264 when available (NVENC, AMF, QuickSync, VideoToolbox,
            Media Foundation), else libx264/openh264. The browser decodes it with
            WebCodecs. Much less bandwidth than JPEG for motion (video, scrolling,
            dragging windows).
    "jpeg": 64x64 dirty tiles, JPEG-encoded in parallel, then a sharp "refine"
            pass once the screen settles. Works in every browser.

Wire formats (after the 1-byte kind):
    K_FRAME (jpeg): u32 frame_no | u16 n | n * (u16 x, u16 y, u16 w, u16 h, u8 fmt=0, u32 len, bytes)
    K_VIDEO (h264): u32 frame_no | u8 flags (bit0 = keyframe) | Annex-B access unit
"""
from __future__ import annotations

import io
import logging
import os
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction

import mss
import numpy as np
from PIL import Image

try:
    import simplejpeg
except ImportError:  # optional speed-up
    simplejpeg = None

log = logging.getLogger("anidesk")

TILE = 64
REFINE_QUALITY = 90
FULL_FRAME_RATIO = 0.5  # above this share of dirty tiles, send one big rect
H264_MAX_DIM = 4096     # common H.264 encoder/decoder limit
UNCHANGED, MAYBE, CHANGED = 0, 1, 2


# ------------------------------------------------------------------ diffing
def _tile_grid(h: int, w: int) -> tuple[int, int]:
    return -(-h // TILE), -(-w // TILE)


def _dirty_tiles(a32: np.ndarray, b32: np.ndarray) -> np.ndarray:
    h, w = a32.shape
    th, tw = _tile_grid(h, w)
    diff = a32 != b32
    ph, pw = th * TILE - h, tw * TILE - w
    if ph or pw:
        diff = np.pad(diff, ((0, ph), (0, pw)))
    return diff.reshape(th, TILE, tw, TILE).any(axis=(1, 3))


def _merge(mask: np.ndarray, h: int, w: int) -> list[tuple[int, int, int, int]]:
    """Turn a tile mask into a short list of pixel rectangles."""
    rects: list[list[int]] = []  # [c0, c1, r0, r1) in tiles
    open_runs: dict[tuple[int, int], list[int]] = {}
    for r in range(mask.shape[0]):
        row = mask[r]
        runs = []
        c = 0
        n = row.shape[0]
        while c < n:
            if row[c]:
                s = c
                while c < n and row[c]:
                    c += 1
                runs.append((s, c))
            else:
                c += 1
        nxt = {}
        for run in runs:
            rect = open_runs.get(run)
            if rect is not None:
                rect[3] = r + 1
            else:
                rect = [run[0], run[1], r, r + 1]
                rects.append(rect)
            nxt[run] = rect
        open_runs = nxt
    out = []
    for c0, c1, r0, r1 in rects:
        x, y = c0 * TILE, r0 * TILE
        out.append((x, y, min(c1 * TILE, w) - x, min(r1 * TILE, h) - y))
    return out


# ------------------------------------------------------------------ capture
def _new_mss():
    return mss.MSS() if hasattr(mss, "MSS") else mss.mss()


class Grabber:
    """Picks the fastest capture backend per monitor. Thread-confined."""

    def __init__(self) -> None:
        self._sct = _new_mss()
        self._dx = None
        self._dx_mon: int | None = None  # mss monitor index served by DXGI
        self._dx_last: np.ndarray | None = None
        if sys.platform == "win32" and os.environ.get("ANIDESK_CAPTURE", "auto") != "mss":
            self._open_dxgi()

    def _open_dxgi(self) -> None:
        try:
            import dxcam

            m = re.search(r"Device\[(\d+)\] Output\[(\d+)\]: Res:\((\d+), (\d+)\).*Primary:True", dxcam.output_info())
            if not m:
                return
            dev, out, w, h = map(int, m.groups())
            for i, mon in enumerate(self._sct.monitors[1:], start=1):
                if mon["left"] == 0 and mon["top"] == 0 and mon["width"] == w and mon["height"] == h:
                    self._dx = dxcam.create(device_idx=dev, output_idx=out, output_color="BGRA", max_buffer_len=2)
                    self._dx_mon = i
                    break
        except Exception as e:  # missing package, remote desktop session, old GPU driver...
            log.info("DXGI capture unavailable, using mss: %s", e)
            self._dx = None

    @property
    def monitors(self) -> list[dict]:
        return self._sct.monitors

    def backend(self, monitor: int) -> str:
        return "dxgi" if self._dx is not None and monitor == self._dx_mon else "mss"

    def grab(self, monitor: int) -> tuple[np.ndarray | None, int]:
        """Return (BGRA frame, state): UNCHANGED, MAYBE (diff needed) or CHANGED (GPU says so)."""
        if self._dx is not None and monitor == self._dx_mon:
            try:
                f = self._dx.grab()
                if f is not None:
                    self._dx_last = f
                    return f, CHANGED
                if self._dx_last is not None:
                    return self._dx_last, UNCHANGED
            except Exception as e:  # desktop switch (UAC/lock screen), display mode change
                log.info("DXGI capture failed (%s); falling back to mss", e)
                self.close_dxgi()
        mons = self._sct.monitors
        mon = mons[monitor if 0 <= monitor < len(mons) else 1]
        shot = self._sct.grab(mon)
        return np.frombuffer(shot.bgra, np.uint8).reshape(shot.height, shot.width, 4), MAYBE

    def close_dxgi(self) -> None:
        if self._dx is not None:
            try:
                self._dx.release()
            except Exception:
                pass
        self._dx = None
        self._dx_last = None

    def close(self) -> None:
        self.close_dxgi()
        self._sct.close()


# ------------------------------------------------------------------- JPEG
class JpegTiles:
    def __init__(self) -> None:
        self._pool = ThreadPoolExecutor(4, thread_name_prefix="anidesk-jpeg")
        self.lowq: np.ndarray | None = None

    @staticmethod
    def _encode(arr: np.ndarray, rect, quality: int) -> bytes:
        x, y, w, h = rect
        sub = np.ascontiguousarray(arr[y:y + h, x:x + w])
        if simplejpeg is not None:
            return simplejpeg.encode_jpeg(sub, quality=quality, colorspace="BGRA",
                                          colorsubsampling="444" if quality >= 85 else "420", fastdct=True)
        img = Image.frombuffer("RGB", (w, h), sub, "raw", "BGRX", 0, 1)
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=quality, subsampling=0 if quality >= 85 else 2)
        return buf.getvalue()

    def pack(self, frame_no: int, arr: np.ndarray, rects, quality: int) -> bytes:
        if len(rects) > 1:
            datas = list(self._pool.map(lambda r: self._encode(arr, r, quality), rects))
        else:
            datas = [self._encode(arr, r, quality) for r in rects]
        parts = [struct.pack(">IH", frame_no, len(rects))]
        for rect, data in zip(rects, datas):
            parts.append(struct.pack(">HHHHBI", *rect, 0, len(data)))
            parts.append(data)
        return b"".join(parts)

    def close(self) -> None:
        self._pool.shutdown(wait=False)


# ------------------------------------------------------------------- H.264
# (name, low-latency options, quality options for a "CRF-like" level q; lower q = better).
# Constant quality capped by maxrate beats CBR: a static or barely-changing screen
# costs almost nothing, while motion is still bounded by the congestion-controlled cap.
_ENCODERS = [
    ("h264_nvenc", {"preset": "p1", "tune": "ull", "zerolatency": "1", "delay": "0"},
     lambda q: {"rc": "vbr", "cq": str(q)}),
    ("h264_amf", {"usage": "ultralowlatency"}, lambda q: {"rc": "cqp", "qp_i": str(q), "qp_p": str(q)}),
    ("h264_qsv", {"preset": "veryfast", "async_depth": "1"}, lambda q: {"global_quality": str(q)}),
    ("h264_videotoolbox", {"realtime": "1"}, lambda q: {}),
    ("h264_mf", {}, lambda q: {}),
    ("libx264", {"preset": "ultrafast", "tune": "zerolatency"}, lambda q: {"crf": str(q)}),
    ("libopenh264", {}, lambda q: {}),
]
DEFAULT_LEVEL = 28


def quality_level(quality: int) -> int:
    """Viewer quality preset (10..95) -> encoder quality level (lower = sharper)."""
    for limit, level in ((40, 32), (65, 28), (85, 24), (100, 20)):
        if quality <= limit:
            return level
    return DEFAULT_LEVEL


_probed: tuple | None | bool = False


def _wrap_bgra(arr: np.ndarray):
    """BGRA ndarray -> av.VideoFrame without copying the pixels when PyAV supports it."""
    import av

    if hasattr(av.VideoFrame, "from_numpy_buffer"):
        return av.VideoFrame.from_numpy_buffer(arr, format="bgra")
    return av.VideoFrame.from_ndarray(arr, format="bgra")


def _open_ctx(name: str, opts: dict, w: int, h: int, fps: int, bitrate: int, qopts: dict | None = None):
    import av

    ctx = av.CodecContext.create(name, "w")
    ctx.width, ctx.height = w, h
    fmts = [f.name for f in (ctx.codec.video_formats or [])]
    # Hardware encoders that take BGRA convert colors on the GPU: ~10x less host CPU.
    ctx.pix_fmt = next(f for f in ("bgra", "nv12", "yuv420p") if f in fmts or f == "yuv420p")
    ctx.time_base = Fraction(1, 1000)
    ctx.framerate = Fraction(fps, 1)
    ctx.bit_rate = bitrate
    ctx.gop_size = max(fps * 120, 600)  # keyframes come from re-opening on demand
    ctx.max_b_frames = 0
    ctx.options = {**opts, **(qopts or {}), "maxrate": str(bitrate), "bufsize": str(max(bitrate // 2, 200_000))}
    ctx.open()
    return ctx


def h264_encoder() -> tuple | None:
    """Find the best working H.264 encoder once (hardware first)."""
    global _probed
    if _probed is not False:
        return _probed
    _probed = None
    if os.environ.get("ANIDESK_CODEC") == "jpeg":
        return None
    try:
        import av
    except ImportError:
        log.info("PyAV not installed: H.264 disabled (pip install av)")
        return None
    forced = os.environ.get("ANIDESK_ENCODER")
    test = np.zeros((360, 640, 4), np.uint8)
    for name, opts, qfn in _ENCODERS:
        if forced and name != forced:
            continue
        if name not in av.codecs_available:
            continue
        for o, q in ((opts, qfn), ({}, lambda _q: {})):
            try:
                ctx = _open_ctx(name, o, 640, 360, 30, 1_000_000, q(DEFAULT_LEVEL))
                vf = _wrap_bgra(test)
                if ctx.pix_fmt != "bgra":
                    vf = vf.reformat(format=ctx.pix_fmt)
                vf.pts = 0
                pk = ctx.encode(vf)
                if not pk:
                    pk = ctx.encode(None)  # flush: encoders with lookahead fail our latency needs anyway
                if pk:
                    _probed = (name, o, q)
                    log.info("H.264 encoder: %s", name)
                    return _probed
            except Exception:
                continue
    log.info("no usable H.264 encoder; using JPEG tiles")
    return None


class H264:
    def __init__(self, name: str, opts: dict, qfn) -> None:
        self.name, self._opts, self._qfn = name, opts, qfn
        self.software = name in ("libx264", "libopenh264")
        self._ctx = None
        self._cfg = None
        self.bitrate = 0

    def _open(self, w, h, fps, bitrate, level) -> None:
        self._ctx = _open_ctx(self.name, self._opts, w, h, fps, bitrate, self._qfn(level))
        self._cfg = (w, h, fps, level)
        self.bitrate = bitrate
        self._t0 = time.monotonic()

    def encode(self, arr: np.ndarray, fps: int, bitrate: int, key: bool, level: int = DEFAULT_LEVEL) -> tuple[bytes, bool]:
        import av

        h, w = arr.shape[:2]
        w2, h2 = w & ~1, h & ~1
        if (w2, h2) != (w, h):
            arr = np.ascontiguousarray(arr[:h2, :w2])
        drift = abs(bitrate - self.bitrate) / max(self.bitrate, 1)
        if key or self._ctx is None or self._cfg != (w2, h2, fps, level) or drift > 0.2:
            self._open(w2, h2, fps, bitrate, level)  # a fresh encoder always starts with an IDR + SPS/PPS
            key = True
        vf = _wrap_bgra(arr)
        if self._ctx.pix_fmt != "bgra":
            vf = vf.reformat(format=self._ctx.pix_fmt)
        vf.pts = int((time.monotonic() - self._t0) * 1000)
        packets = self._ctx.encode(vf)
        data = b"".join(bytes(p) for p in packets)
        return data, key or any(p.is_keyframe for p in packets)


# ---------------------------------------------------------------- capturer
class Capturer:
    """Owns capture handles + encoders; must only be used from one thread."""

    def __init__(self) -> None:
        self.grabber = Grabber()
        self.jpeg = JpegTiles()
        enc = h264_encoder()
        self.h264 = H264(*enc) if enc else None
        self._prev: np.ndarray | None = None
        self._key = None
        self._tail = 0

    @property
    def encoder_name(self) -> str | None:
        return self.h264.name if self.h264 else None

    def monitors(self) -> list[dict]:
        out = []
        for i, m in enumerate(self.grabber.monitors):
            out.append({"i": i, "x": m["left"], "y": m["top"], "w": m["width"], "h": m["height"],
                        "label": "All screens" if i == 0 else f"Screen {i}"})
        return out

    def geometry(self, monitor: int) -> dict:
        mons = self.grabber.monitors
        m = mons[monitor if 0 <= monitor < len(mons) else 1]
        return {"x": m["left"], "y": m["top"], "w": m["width"], "h": m["height"]}

    def backend(self, monitor: int) -> str:
        return self.grabber.backend(monitor)

    @staticmethod
    def h264_ok(w: int, h: int) -> bool:
        return w <= H264_MAX_DIM and h <= H264_MAX_DIM

    def frame(self, frame_no: int, monitor: int, scale: int, codec: str, quality: int,
              bitrate: int, fps: int, force: bool):
        """Capture and encode. Returns (payload | None, (w, h), size_changed)."""
        raw, state = self.grabber.grab(monitor)
        if raw is None:
            return None, (0, 0), False
        arr = np.ascontiguousarray(raw[::scale, ::scale]) if scale > 1 else raw
        h, w = arr.shape[:2]
        key = (monitor, scale, h, w, codec)
        size_changed = key != self._key
        force = force or size_changed or (self._prev is None and codec == "jpeg")
        h264 = codec == "h264" and self.h264 is not None

        if force:
            self._key = key
            changed, mask = True, np.ones(_tile_grid(h, w), bool)
        elif state == UNCHANGED:
            changed, mask = False, None
        elif h264 and state == CHANGED:
            changed, mask = True, None  # no need to diff: the GPU reported a change
        elif self._prev is None or self._prev.shape != (h, w):
            changed, mask = True, np.ones(_tile_grid(h, w), bool)  # e.g. DXGI just fell back to mss
        else:
            mask = _dirty_tiles(arr.view(np.uint32).reshape(h, w), self._prev)
            changed = bool(mask.any())
        if changed and not h264:
            # Keep our own copy for diffing: capture backends may reuse their buffers.
            a32 = arr.view(np.uint32).reshape(h, w)
            self._prev = a32.copy() if raw is self.grabber._dx_last and arr is raw else a32
        elif changed and state == MAYBE:
            self._prev = arr.view(np.uint32).reshape(h, w)

        if h264:
            if not changed:
                if self._tail <= 0:
                    return None, (w, h), False
                self._tail -= 1  # a few repeat frames let CBR sharpen a static image
            else:
                self._tail = max(fps // 2, 5)
            data, is_key = self.h264.encode(arr, fps, bitrate, force, quality_level(quality))
            if not data:
                return None, (w, h), size_changed
            return struct.pack(">IB", frame_no, 1 if is_key else 0) + data, (w, h), size_changed

        if not changed:
            return None, (w, h), False
        if force:
            rects = [(0, 0, w, h)]
        else:
            rects = [(0, 0, w, h)] if mask.mean() > FULL_FRAME_RATIO else _merge(mask, h, w)
        j = self.jpeg
        if quality < REFINE_QUALITY:
            j.lowq = mask if j.lowq is None or j.lowq.shape != mask.shape else (j.lowq | mask)
        elif j.lowq is not None and j.lowq.shape == mask.shape:
            j.lowq &= ~mask
        return j.pack(frame_no, arr, rects, quality), (w, h), size_changed

    def refine(self, frame_no: int) -> bytes | None:
        """JPEG only: re-send tiles that were last sent at low quality, at high quality."""
        j = self.jpeg
        if self._prev is None or j.lowq is None or not j.lowq.any() or self._key is None or self._key[4] != "jpeg":
            return None
        h, w = self._prev.shape
        arr = self._prev.view(np.uint8).reshape(h, w, 4)
        rects = _merge(j.lowq, h, w)
        j.lowq = None
        return j.pack(frame_no, arr, rects, REFINE_QUALITY)

    def close(self) -> None:
        self.grabber.close()
        self.jpeg.close()
