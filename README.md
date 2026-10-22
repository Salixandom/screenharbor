# ScreenHarbor

Open-source, self-hosted remote desktop in the spirit of AnyDesk. Share a
computer by ID and password, then control it from any browser (desktop or
phone): live screen, mouse and keyboard, files, clipboard, chat, screenshots
and recordings, all **end-to-end encrypted** so the relay server never sees
your session. No accounts, no session time limits, no "commercial use" nags.

```
 host agent (the PC being controlled) ──► ScreenHarbor server (ID + relay) ◄── web viewer (any browser)
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how AnyDesk works
(including evidence from its own logs), how ScreenHarbor maps onto it, and the
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
Code:     gentle-river-moon-fox      (type it into any ScreenHarbor viewer)
Password: Ab3k9xQ2
```

Send the link (or code) plus the password. The other person opens it in any browser, on any network.
`make share` also publishes a stable address by default; the host renews its mapping when it restarts a
failed tunnel. Share that address from a persistent HTTPS ScreenHarbor viewer page (for example, one served
by your own server) to look up the current quick-tunnel URL. The address is signed and verified, while
the current URL and host ID are visible on the public noticeboard. The noticeboard only locates the host:
session traffic still uses Cloudflare and ScreenHarbor's normal password and end-to-end encryption. Neither
the noticeboard nor a quick tunnel has an uptime guarantee. Console version: `make share-headless PASSWORD=...`.

### Custom hostname: named Cloudflare Tunnel

For a URL that stays the same after host or tunnel restarts, use a Cloudflare account and a domain
managed in Cloudflare. Create a **remotely managed** tunnel in **Networking → Tunnels**, add a
published application route for `desk.example.com`, and set its service to
`http://127.0.0.1:8765`. Download the tunnel token to a local file that only your account can read
(Cloudflare token files require `cloudflared` 2025.4.0 or newer), then run:

```bash
make share-named TUNNEL_HOST=desk.example.com TOKEN_FILE=/path/to/tunnel-token
```

On Windows, use a quoted path such as `TOKEN_FILE="C:/Users/me/.screenharbor/tunnel-token"`.
The host starts `cloudflared`, reconnects it if it exits, and shares `https://desk.example.com`;
use the complete shared link (including its `#id=` or `#address=` fragment) in the browser or
command-line client so it knows which host ID to contact. The dashboard's local service port must
remain `8765`. The stable signed address remains available as an alternate lookup.

Named tunnels keep the hostname fixed; they do not keep the PC online. The PC must be powered on,
awake, connected to the internet, and running ScreenHarbor. `make share-autostart` starts at user
login, so it does not run before anyone signs in. For terminal-only access, a separately configured
system service can start at boot without a desktop login; screen sharing and input control still
need an active interactive desktop session. No software can control a PC while it is asleep or off.
Use the OS power settings to prevent sleep, and enable firmware "restore after power loss" if useful.

For a personal always-on setup after you sign in to the PC, use `make share-autostart PASSWORD="a long password"`.
It stores only a salted password hash, starts sharing at login, and publishes the stable address. Use
`make no-autostart` to remove the login startup entry. The PC must stay powered on, awake, and signed in;
this does not remove the need for a ScreenHarbor viewer page at a persistent HTTPS URL.
To start a named tunnel at login, add `ARGS="--tunnel-hostname desk.example.com --tunnel-token-file C:/Users/me/.screenharbor/tunnel-token"`.

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
| `make share` | **no server needed**: share through a temporary link + stable address |
| `make share-named TUNNEL_HOST=... TOKEN_FILE=...` | share through a fixed Cloudflare hostname |
| `make server` | ID/relay server + web viewer (HTTP 8080, HTTPS 8443) |
| `make host` | share this computer (window with ID, password, Accept prompt, chat) |
| `make headless PASSWORD=...` | share without a window, accept that password without asking |
| `make unattended PASSWORD=...` | run with a permanent unattended password (stored as a salted hash) |
| `make autostart [PASSWORD=...]` | start the host at login (Windows Run key / XDG autostart / LaunchAgent) |
| `make share-autostart PASSWORD=...` | start stable-address quick-tunnel sharing at login, unattended |
| `make test` | unit tests + full end-to-end self test on private ports |
| `make bench` | measure capture/encoder pipelines on this machine |
| `make measure` | measure screen-change latency and host RAM/CPU (`ARGS=--share` for Cloudflare) |
| `make term TARGET=...` | open a remote shell in this terminal |
| `make ssh TARGET=... ARGS="user"` | use OpenSSH through ScreenHarbor (host needs an SSH server) |
| `make forward TARGET=... PORTS=2222:22` | forward local port 2222 to host-local port 22 |
| `make proxy TARGET=... REMOTE_PORT=22` | provide a raw SSH ProxyCommand transport |
| `make history` | print recent local connection history |
| `make docker-build docker-run` | run the server in Docker with persistent IDs |

Options: `SERVER=`, `PASSWORD=`, `PORT=`, `HTTPS_PORT=`, `ARGS="--view-only --no-files ..."`.
Without make: `uv run --project host screenharbor-host --help` and `node server/index.js --help`.

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
- Live participant list with per-viewer colors and colored pointers shared across viewers

**Control**
- Full mouse and keyboard, special-key combos (Win, Alt+Tab, Ctrl+Shift+Esc...). In Chromium fullscreen, system keys pass through
- **Touch control** for phones/tablets: tap = click, long-press = right click, drag, two-finger scroll, on-screen keyboard

**Files & more**
- Remote file browser: download files or **whole folders as .zip**, upload by drag & drop.
  Big downloads stream straight to disk (Chromium) instead of filling RAM
- Two-way text clipboard sync, "type this text", chat
- In-browser remote shell with terminal resize and keyboard input

### Terminal and SSH client

The browser viewer has a Terminal button for a shell in the page. The installed `screenharbor` command-line
client also opens shells and adds OpenSSH and local port forwarding. The host must allow terminal access
(enabled by default), and still shows/records these connections like other sessions.

```bash
uv run --project host screenharbor term gentle-river-moon-fox
uv run --project host screenharbor forward gentle-river-moon-fox 2222:22
uv run --project host screenharbor ssh gentle-river-moon-fox my-user
```

For a 9-digit ID on your own server, add `--server wss://your-server:8443/ws`. A `screen-` stable address
can be used as the target by both the browser and CLI; browser users enter it on a persistent HTTPS
ScreenHarbor viewer page. The CLI asks for the
ScreenHarbor password securely; `SCREENHARBOR_PASSWORD` can supply it for scripts. `term` opens a remote shell,
`forward` maps a local port to a host-local TCP port, `ssh` runs the system OpenSSH client through ScreenHarbor,
and `proxy` implements its stdin/stdout ProxyCommand transport. For example, `forward ... 2222:22` lets
you connect separately with `ssh -p 2222 localhost`.

Host connection history is stored locally at `~/.screenharbor/connections.log` (platform-appropriate config
directory) and can be printed with `make history` or `uv run --project host screenharbor-host --history`.
The stable address signing key is stored in `~/.screenharbor/address-ed25519.key`; keep it with the host
configuration to preserve the address when moving to another machine. Stopping sharing publishes an
offline status, and the current tunnel URL is republished every few hours.

### Measuring latency and resource use

`make measure` runs a local screen-change latency and host RAM/CPU measurement. Use
`make measure ARGS=--share` to measure through a temporary Cloudflare link. It needs a visible desktop,
FFmpeg for H.264 decoding, and the development dependency `psutil`; numbers are specific to the test
machine, display, codec and network path.

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
| Viewer | Chrome/Edge tested · Firefox and Safari support the standards-based viewer; H.264 depends on browser WebCodecs/codec support, with JPEG fallback · phones/tablets via touch mode |

The host runs as your user, so it can't control UAC prompts, the lock screen or elevated windows.
Linux needs `xclip` (or `xsel`) for clipboard sync.

## License

MIT. Not affiliated with AnyDesk Software GmbH. "AnyDesk" is their trademark.
