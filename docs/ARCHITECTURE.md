# How AnyDesk works, and how AniDesk does it

This document has two halves: what we learned about AnyDesk (and RustDesk, the
best-known open-source alternative), and the design AniDesk uses as a result.
AniDesk is a clean-room implementation: it uses no AnyDesk code or protocol
details, only publicly observable behaviour.

## Part 1 — What AnyDesk does

### Sources

| Source | Kind of evidence |
|---|---|
| AnyDesk service log `C:\ProgramData\AnyDesk\ad_svc.trace` on a real machine | **Observed** runtime behaviour |
| AnyDesk config key *names* in `service.conf` / `system.conf` (values not read) | **Observed** on-disk state |
| `connection_trace.txt`, `file_transfer_trace.txt` | **Observed** session history format |
| REA static inspection of the AnyDesk 9.x PE (`inspect_pe_resources`, entropy scan) | **Observed**: the binary is packed (entropy 8.0 bits/byte), so its code and strings can't be read statically; only icons, version info and the DigiCert Authenticode chain are visible |
| AnyDesk security page / trust center, RustDesk docs, third-party reverse-engineering write-ups | **Documented / reported** |

### Connection model (observed in the service log)

1. **Always-on relay connection.** At startup the service ("ad_svc") opens a
   *main relay connection* to `relay-<hex>.net.anydesk.com:443`. If DNS or
   connect fails it falls back to `boot.net.anydesk.com`, which returns a
   **server list** ("Received a new server list (10 servers)"). Relays can
   refuse with `anynet_relay_full`, and the client moves to another one.
2. **Connect methods, in order:** `connect_proxy_443`, `connect_proxy_80`,
   `socks_proxy_443`, then direct (6 methods in total, "1/6".."3/6" are proxy
   variants and get skipped when there's no proxy).
   This is how AnyDesk gets through corporate firewalls: everything can
   ride on port 443/80.
3. **Transport security:** `Cipher: ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2`,
   `handshake - Using protocol version 3`. Each client imports its **own
   certificate + private key** (`ad.anynet.cert`, `ad.anynet.pkey`,
   `ad.anynet.fpr`) and checks it against 3 bundled CA certificates and CRLs.
   That is what lets both ends verify each other ("RSA-2048 key exchange" in
   AnyDesk's marketing; the logs show ECDSA certificates on the relay link).
4. **Direct path:** the service also **listens on TCP 7070** (IPv4 + IPv6) and
   tries **UPnP port forwarding** for 7070 so peers can connect without the
   relay, i.e. P2P when possible, relay otherwise.
5. **LAN discovery:** joins multicast group `239.255.102.18:50001` and
   broadcasts "Discovery client info" so nearby AnyDesk clients appear
   without an ID.
6. **Identity:** a numeric **ID** (`ad.anynet.id`), an optional **alias**,
   and a device-id hash. The relay maps ID → online client.
7. **Authorization:** `connection_trace.txt` records each incoming session as
   `User` (someone clicked *Accept*) or `Passwd` (unattended password).
   Passwords are stored per *permission profile* as `pwd` + `salt` (salted
   hash, not plaintext), and `token_salt` supports "remember me" tokens.
8. **Architecture:** the service is built from cooperative **fibers**
   (`main_relay_conn`, `relay_connector`, `tcp_acceptor`, `discovery`,
   `connection_mgr`) on one scheduler, with a separate front-end process
   for the UI.

### Screen, input and files (documented)

* **DeskRT codec:** AnyDesk's own codec, built for screen content (large flat
  areas, sharp edges, scrolling and translation). It is why AnyDesk feels fast
  on slow links. It is proprietary and was not inspected.
* **Input:** the service injects keyboard and mouse input as the
  logged-in user. It runs as a SYSTEM service so it can also control UAC and
  login screens (`permissions.sas` = secure-attention-sequence, Ctrl+Alt+Del).
* **File manager / clipboard file transfer:** a dedicated file-manager
  session type plus clipboard sync of text and files
  (`frontend_clipboard_files`).
* **Other:** Wake-on-LAN (`ad.wol_service`), session recording
  (`screen recordings/`), auto-update over the relay.

### RustDesk (open-source reference)

* `hbbs` = ID/rendezvous server (TCP/UDP 21116; registration, heartbeat, NAT
  hole-punch coordination). `hbbr` = relay (21117). WebSocket ports 21118/21119
  for the web client.
* Clients first try **UDP/TCP hole punching**, then IPv6 direct, then the relay.
* Ed25519 server key pinned in clients; sessions are end-to-end encrypted.
* Codecs: VP8/VP9/AV1/H.264/H.265 with hardware encoders when available.

## Part 2 — AniDesk design

```
 ┌──────────────┐  control WS (register, "incoming")  ┌───────────────────────┐
 │  Host agent  │ ───────────────────────────────────►│      AniDesk server   │
 │  (Python)    │  session WS per viewer              │  ID registry + relay  │
 │ capture/input│ ◄═══════ opaque E2E frames ═══════► │  + web viewer files   │
 └──────────────┘                                     └──────────▲────────────┘
                                                                 ║ opaque E2E frames
                                                      ┌──────────╨────────────┐
                                                      │ Web viewer (browser)  │
                                                      └───────────────────────┘
```

| AnyDesk concept | AniDesk equivalent |
|---|---|
| Main relay connection + numeric ID | Host keeps a control WebSocket to `/ws`; server assigns a 9-digit ID, persisted with a secret that proves ownership |
| Relay servers on 443 | One Node.js server; put it behind 443 (reverse proxy) to get through firewalls |
| Per-client cert + TLS | TLS to the server (optional) **plus** end-to-end ECDH P-256 + AES-256-GCM between host and viewer, so the server is blind |
| `User` vs `Passwd` authorization | Session password + **Accept prompt**, or **unattended password** (stored as salted PBKDF2 only), which skips the prompt |
| DeskRT | Hardware H.264 (WebCodecs in the browser) with capped constant quality; JPEG dirty tiles as fallback (see *Video pipeline*) |
| File manager | Encrypted remote file browser with download and upload (drag & drop), path-sanitised |
| Clipboard sync | Text clipboard both ways (auto when the browser allows, manual panel otherwise) |
| Chat | Built in, both directions |

### Session protocol

1. Viewer → server: `{"t":"connect","id":"123456789"}`.
   Server → host control socket: `{"t":"incoming","sid":…,"ip":…}`.
2. Host opens a **new** socket: `{"t":"attach","sid","id","secret"}`. The server
   pairs the two sockets, sends `paired` to both, and from then on only
   forwards bytes (with backpressure).
3. Host → viewer `hello {pub, salts[]}` (one salt per accepted password:
   session and, optionally, unattended).
   Viewer → host `hello {pub}` followed by one encrypted `auth` frame per salt.
4. Keys: `HKDF-SHA256(ECDH, salt=PBKDF2(password, salt, 150k), info="anidesk/v1"|hostPub|viewerPub)`
   → separate keys for each direction. Frames are `seq(u64) | AES-GCM`, and
   strictly increasing sequence numbers block replay and reordering.
5. If the password is wrong, decryption fails, the host logs it, and after
   5 failures in 5 minutes it locks for 60 s. If the password is right, it
   shows the accept prompt (unless the unattended password or a valid
   reconnect token was used) and sends `welcome` plus a fresh single-use
   reconnect `token` (valid 15 min; still requires the password).
6. Message kinds: `1` JSON control, `2` JPEG tile frame, `3` file chunk, `4` H.264 access unit.
   The viewer's `auth` lists the codecs it can decode (`h264` when WebCodecs supports it).

There are **no session time limits**. The only timers are: 20 s for the host
to answer a connection request, 60 s for someone to click Accept, and the
15-minute reconnect-token lifetime.

### Video pipeline (v0.2)

```
capture ─► change detection ─► encoder ─► encrypt ─► relay ─► decrypt ─► decoder ─► canvas
DXGI (Win, GPU says what changed)       NVENC/AMF/QSV/VT ─────────────► WebCodecs VideoDecoder
mss (Linux/macOS, tile diff)            JPEG tiles (simplejpeg) ──────► createImageBitmap
```

* **Capture.** On Windows, DXGI Desktop Duplication tells us when the desktop
  changed, so an idle screen costs nothing and changes cost 2.7 ms. mss
  (X11/macOS/GDI) costs ~20 ms per grab at 1440p and needs a 64×64 tile diff
  (2 ms) to detect changes.
* **Encoding.** Benchmarks (`tests/pipeline_bench.py`; quality as PSNR, table
  below) drove three decisions:
  1. **Capped constant quality, not CBR.** CBR padded every frame to the full
     bitrate (5.3 Mb/s for typing). NVENC `rc=vbr cq=28` with `maxrate` =
     0.38 Mb/s at higher quality (46 dB vs 39 dB for JPEG q60).
  2. **BGRA straight into the GPU encoder.** Letting NVENC convert colors cut
     host CPU from 29% to 2.6% of a core at 1440p30, and `from_numpy_buffer`
     avoids a 14 MB copy per frame.
  3. **Auto = hardware only.** Software x264 saves bandwidth but costs 60–80%
     of a core at 1440p, so "Auto" falls back to JPEG tiles. H.264 can still
     be forced from the viewer.
* **Keyframes** come from re-opening the encoder (always IDR + SPS/PPS), used
  on connect, resolution/codec change, decoder errors or a hidden tab. That
  avoids encoder-specific "force IDR" options.
* **Flow control.** The viewer acks each frame after it's drawn. The host keeps
  up to 8 H.264 frames (or 3 JPEG frames) / ~0.3 s of bytes in flight, measures
  RTT from acks, and every 2 s lowers the bitrate cap when acks lag (×0.7) or
  raises it when the link is idle (×1.3, up to the quality preset's target).

| 2560×1440, 30 fps | typing | scrolling | video |
|---|---|---|---|
| JPEG tiles q60 | 0.42 Mb/s, 39.4 dB | 45.5 Mb/s, 39.2 dB | 10.9 Mb/s, 40.3 dB |
| NVENC CBR 5.5 Mb/s | 5.32 Mb/s, 51.6 dB | 5.32 Mb/s, 51.6 dB | 5.36 Mb/s, 50.8 dB |
| **NVENC VBR cq=28 (chosen)** | **0.38 Mb/s, 46.4 dB** | **0.87 Mb/s, 46.0 dB** | **1.99 Mb/s, 46.3 dB** |
| x264 CRF 26 ultrafast | 0.50 Mb/s, 52.5 dB | 1.22 Mb/s, 48.9 dB | 4.17 Mb/s, 49.2 dB |

### Share via link (no server)

```
viewer browser ──HTTPS/WSS──► <words>.trycloudflare.com ══ Cloudflare tunnel ══► cloudflared ─► 127.0.0.1 relay ─► host
                              (TLS by Cloudflare)                                    (inside the host process)
```

* The host starts `relay.py`, a Python copy of the server protocol (register/connect/attach, then blind
  forwarding) that also serves the web viewer, bound to **127.0.0.1 only**. The selftest runs the full e2e
  suite against both relays to keep them identical.
* `cloudflared tunnel --url http://127.0.0.1:PORT` (a Cloudflare *quick tunnel*: free, no account, random
  hostname) makes it public. The binary is taken from PATH or downloaded once from Cloudflare's GitHub
  release and checked against the SHA-256 listed in the release notes.
* Only the host process can register with its relay (random in-memory secret), so nobody arriving through
  the tunnel can take over the host slot. Client IPs come from `CF-Connecting-IP` for rate limiting and the
  Accept prompt.
* `cloudflared` is tied to the host's lifetime: a Windows Job Object (`KILL_ON_JOB_CLOSE`) or Linux
  `PR_SET_PDEATHSIG`, so even a crashed or killed host never leaves a tunnel running. Verified on both.
* The share code is just the tunnel hostname: any AniDesk viewer accepts it in the ID field and connects
  to `wss://<code>.trycloudflare.com/ws` directly.

Trade-offs: Cloudflare terminates TLS and serves the viewer page. Session contents stay end-to-end
encrypted, but you are trusting Cloudflare (like any CDN) not to tamper with the page. Quick tunnels have
no uptime guarantee and are meant for ad-hoc use, so for permanent unattended access run your own server
(or a named Cloudflare tunnel on your own domain).

### Security notes and limits (be honest)

* The password never leaves the machines, and the server can't read or alter
  sessions. A **malicious server** could still MITM the ECDH exchange and then
  try to **guess the password offline** against a captured auth frame.
  PBKDF2 slows that down, but use long unattended passwords. A future version
  should use a PAKE (e.g. SPAKE2/OPAQUE) to remove this.
* The browser's WebCrypto requires a secure context: use `https://` (server
  `--https-port`) or `http://localhost`.
* The host runs as a normal user process, so it can't control UAC prompts,
  the lock screen or elevated windows (AnyDesk uses a SYSTEM service for that).
* The host always shows that a session is active (window title + list,
  console banner in headless mode). There is deliberately no stealth mode.

### Roadmap

* **P2P / direct connections** (WebRTC data channel or hole punching) so LAN and
  well-connected peers skip the relay. This is the biggest remaining latency win.
* GPU-side capture → encode (D3D11 textures straight into NVENC) to drop the last CPU copy
* Wayland capture (PipeWire portal) and input (libei)
* Windows service for UAC/lock-screen access; native desktop viewer
* Audio streaming (Opus), file copy/paste through the clipboard, address book
* LAN discovery (multicast, like AnyDesk's 239.255.102.18:50001)
* PAKE-based authentication to close the malicious-server offline-guessing gap
