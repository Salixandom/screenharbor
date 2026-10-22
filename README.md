# AniDesk

Open-source, self-hosted remote desktop in the spirit of AnyDesk. Share a
computer by ID and password, then control it from any browser (desktop or
phone): live screen, mouse and keyboard, files, clipboard, chat, screenshots
and recordings, all **end-to-end encrypted** so the relay server never sees
your session. No accounts, no session time limits, no "commercial use" nags.

```
 host agent (the PC being controlled) ──► AniDesk server (ID + relay) ◄── web viewer (any browser)
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how AnyDesk works
(including evidence from its own logs), how AniDesk maps onto it, and the
benchmarks behind the design.

## Quick start

You need [**uv**](https://docs.astral.sh/uv/getting-started/installation/), **Node.js 18+** and **GNU make**
(`choco install make` / `winget install GnuWin32.Make` on Windows; preinstalled or one package away on Linux/macOS).

```bash
make install     # once
```

### Easiest: share via link (no server, no port forwarding)

```bash
make share       # on the computer to be controlled
```

Click **Share via internet link**. The host becomes its own server and opens a free, temporary
[Cloudflare quick tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/)
(no account needed; `cloudflared` is downloaded once and checked against Cloudflare's published SHA-256). You get:

```
Link:     https://gentle-river-moon-fox.trycloudflare.com/#id=123456789
Code:     gentle-river-moon-fox      (type it into any AniDesk viewer)
Password: Ab3k9xQ2
```

Send the link (or code) plus the password. The other person opens it in any browser, on any network.
The link dies as soon as you press **Stop sharing** or close AniDesk. Console version: `make share-headless PASSWORD=...`.

### Permanent setup: run your own server

For always-on/unattended access, run the server somewhere reachable (a small VPS, `make docker-run`, or port 8443 forwarded):

```bash
make server                                  # on the machine everyone can reach
make host SERVER=wss://SERVER_IP:8443/ws     # on the computer to be controlled (add ARGS=--insecure for self-signed)
```

Then open **https://SERVER_IP:8443** in a browser and enter the ID and password shown by the host.
Testing on one machine? `make dev` then `make viewer`.

Run `make` on its own to list every command:

| Command | What it does |
|---|---|
| `make share` | **no server needed**: share through a temporary internet link + code |
| `make server` | ID/relay server + web viewer (HTTP 8080, HTTPS 8443) |
| `make host` | share this computer (window with ID, password, Accept prompt, chat) |
| `make headless PASSWORD=...` | share without a window, accept that password without asking |
| `make unattended PASSWORD=...` | run with a permanent unattended password (stored as a salted hash) |
| `make autostart [PASSWORD=...]` | start the host at login (Windows Run key / XDG autostart / LaunchAgent) |
| `make test` | unit tests + full end-to-end self test on private ports |
| `make bench` | measure capture/encoder pipelines on this machine |
| `make docker-build docker-run` | run the server in Docker with persistent IDs |

Options: `SERVER=`, `PASSWORD=`, `PORT=`, `HTTPS_PORT=`, `ARGS="--view-only --no-files ..."`.
Without make: `uv run --project host anidesk-host --help` and `node server/index.js --help`.

## Features

**Connecting**
- **Share via link**: no server, no router setup. Built-in relay + temporary Cloudflare tunnel, link or short code
- 9-digit IDs, session password, **Accept / Decline** prompt on the host
- **Unattended access** with a permanent password (salted PBKDF2 hash only, never stored in plain text)
- **Auto-reconnect** after network drops, with a single-use reconnect token so there's no second prompt
- Brute-force lockout (5 wrong passwords → 60 s), server rate limiting, permission switches (view-only, no files, no clipboard)
- If two computers end up with the same ID (copied config), they don't fight; the newer login wins

**Screen**
- **Hardware H.264** (NVIDIA NVENC, AMD AMF, Intel QuickSync, Apple VideoToolbox) decoded by the browser's WebCodecs,
  with **JPEG dirty tiles** as a universal fallback
- **DXGI desktop duplication** on Windows: ~0 CPU while the screen is idle
- Constant-quality rate control with congestion control (bitrate backs off when the link is slow)
- Quality / resolution / FPS / monitor selection, live stats (codec, fps, bitrate, round-trip time)
- Host cursor overlay, screenshot (PNG) and session **recording** (WebM) from the viewer

**Control**
- Full mouse and keyboard, special-key combos (Win, Alt+Tab, Ctrl+Shift+Esc...). In Chromium fullscreen, system keys pass through
- **Touch control** for phones/tablets: tap = click, long-press = right click, drag, two-finger scroll, on-screen keyboard

**Files & more**
- Remote file browser: download files or **whole folders as .zip**, upload by drag & drop.
  Big downloads stream straight to disk (Chromium) instead of filling RAM
- Two-way text clipboard sync, "type this text", chat

## How efficient is it?

Measured on the development PC (2560×1440 @ 30 fps, RTX 5060 Ti) with `make bench`, each pipeline replaying identical scenes:

| | idle | typing | scrolling | video |
|---|---|---|---|---|
| JPEG tiles (v0.1) | 1.1 Mb/s · 7% CPU | 0.6 · 8% | 35 · 34% | 9.8 · 28% |
| **H.264 NVENC (v0.2)** | **0.16 · 3%** | **0.22 · 6%** | **1.1 · 8%** | **1.6 · 18%** |

The H.264 path also gives better image quality (≈46 dB PSNR vs 39 dB for JPEG q60). Capture: DXGI costs 2.7 ms per *changed*
frame and nothing when idle; mss (Linux/macOS) costs ~20 ms per frame. Without a hardware encoder, "Auto" stays on JPEG tiles,
because software H.264 at 1440p uses most of a CPU core. You can still pick H.264 by hand for slow links (3–10× less bandwidth).

## Platform support

| | Windows | Linux | macOS |
|---|---|---|---|
| Host (capture + control) | ✓ tested (DXGI + NVENC) | ✓ tested on X11 (Xvfb, Ubuntu 24.04) | should work, **untested** (grant Screen Recording + Accessibility) |
| Share via link | ✓ tested over the internet | ✓ tested over the internet | should work, untested |
| Wayland desktops | | ✗ not yet (log in to an X11 session) | |
| Server | ✓ | ✓ (+ Docker) | ✓ |
| Viewer | Chrome/Edge ✓ tested · Firefox 130+ / Safari 16.4+ for H.264, JPEG elsewhere · phones/tablets via touch mode |

The host runs as your user, so it can't control UAC prompts, the lock screen or elevated windows.
Linux needs `xclip` (or `xsel`) for clipboard sync.

## License

MIT. Not affiliated with AnyDesk Software GmbH. "AnyDesk" is their trademark.
