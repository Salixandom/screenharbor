"""ScreenHarbor host entry point:  python -m screenharbor_host [--headless] ..."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys


def _dpi_aware() -> None:
    # Make capture and cursor coordinates use physical pixels on scaled displays.
    if sys.platform != "win32":
        return
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _has_display() -> bool:
    """Screen sharing needs a desktop; without one we still offer terminal + SSH tunnels."""
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        if os.environ.get("WAYLAND_DISPLAY"):
            print("[note] Wayland screen capture/input isn't supported yet: offering terminal access only. "
                  "Log in with an X11 session for screen sharing.", flush=True)
        else:
            print("[note] No display found: offering terminal access only (shell + SSH tunnels).", flush=True)
        return False
    return True


def _print_history(limit: int = 50) -> None:
    import json
    import time

    from .config import HISTORY_FILE

    try:
        lines = HISTORY_FILE.read_text("utf-8").splitlines()[-limit:]
    except OSError:
        print("No connection history yet.")
        return
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("ts", 0)))
        dur = f" {r['duration'] // 60}m{r['duration'] % 60:02d}s" if "duration" in r else ""
        detail = f"  {r['detail']}" if r.get("detail") else ""
        print(f"{when}  {r.get('event', ''):<11} {r.get('name', ''):<20} {r.get('ip', ''):<16} "
              f"{r.get('method', ''):<10} {r.get('mode', ''):<8}{dur}{detail}")


class ConsoleUI:
    def status(self, text): print(f"[status] {text}", flush=True)
    def id_changed(self, i): print(f"\n  ScreenHarbor ID: {' '.join(i[k:k + 3] for k in range(0, len(i), 3))}\n", flush=True)
    def log(self, text): print(f"[log] {text}", flush=True)
    def chat(self, s, text): print(f"[chat] {s.viewer_name}: {text}", flush=True)
    def session_started(self, s): print(f"[session] REMOTE SESSION ACTIVE: {s.label}", flush=True)
    def session_ended(self, s): print(f"[session] ended: {s.label}", flush=True)
    def peers(self): pass
    def pointer(self, s, pos): pass
    def history(self, rec): pass

    async def ask(self, session) -> bool:
        return False  # headless mode never auto-accepts unknown viewers


async def _headless(agent, a, pw: str) -> None:
    if a.share or a.share_local:
        await agent.start_relay(port=8765 if a.tunnel_token_file else 0)  # bind before connecting to the local relay
    run = asyncio.create_task(agent.run())
    if a.share or a.share_local:
        try:
            url = await agent.start_sharing(use_tunnel=not a.share_local, stable_address=a.stable_address,
                                            tunnel_hostname=a.tunnel_hostname,
                                            tunnel_token_file=a.tunnel_token_file)
        except Exception as e:
            print(f"[error] could not start sharing: {e}", flush=True)
        else:
            while not agent.ident[0] or agent.relay is None or agent.relay.host_id != agent.ident[0]:
                await asyncio.sleep(0.1)  # wait until we're registered with our own relay
            if a.share:
                code = agent.tunnel.code
                print("\n  ================= Share this =================", flush=True)
                fragment = f"#address={agent.stable_address}" if agent.stable_address else f"#id={agent.ident[0]}"
                print(f"  Link:     {url}/{fragment}", flush=True)
                print(f"  Code:     {code}   (type it into any ScreenHarbor viewer)", flush=True)
                if agent.stable_address:
                    print(f"  Address:  {agent.stable_address}   (resolves to the current link)", flush=True)
                print(f"  Password: {pw}", flush=True)
                print("  ===============================================\n", flush=True)
    try:
        await run
    finally:
        await agent.stop_sharing()


def main(argv=None) -> None:
    from .config import Config, generate_password

    ap = argparse.ArgumentParser(prog="screenharbor-host", description="Share this computer via ScreenHarbor.")
    ap.add_argument("--server", help="ID/relay server, e.g. ws://192.168.1.10:8080/ws")
    ap.add_argument("--password", help="session password (default: random, shown on screen)")
    ap.add_argument("--set-unattended-password", metavar="PW",
                    help="store a permanent password (salted hash only) for unattended access; '' clears it")
    ap.add_argument("--headless", action="store_true", help="no window; print ID and password to the console")
    ap.add_argument("--no-ask", action="store_true", help="accept the session password without a confirmation prompt")
    ap.add_argument("--view-only", action="store_true", help="do not allow mouse/keyboard control")
    ap.add_argument("--no-files", action="store_true", help="disable file transfer")
    ap.add_argument("--no-clipboard", action="store_true", help="disable clipboard sync")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate checks for wss:// servers "
                                                            "(sessions stay end-to-end encrypted)")
    ap.add_argument("--share", action="store_true",
                    help="no server needed: host a built-in relay and share it through a temporary Cloudflare "
                         "link (https://<words>.trycloudflare.com)")
    ap.add_argument("--stable-address", action="store_true",
                    help="publish a signed stable address that follows changing quick-tunnel URLs")
    ap.add_argument("--tunnel-hostname", help="custom hostname routed to this host by a named Cloudflare tunnel")
    ap.add_argument("--tunnel-token-file", help="file containing the remotely-managed Cloudflare tunnel token")
    ap.add_argument("--share-local", action="store_true", help=argparse.SUPPRESS)  # built-in relay only (tests)
    ap.add_argument("--terminal-only", action="store_true",
                    help="offer only terminal + SSH tunnels, never the screen (automatic without a display)")
    ap.add_argument("--no-terminal", action="store_true", help="disable terminal and TCP tunnel access")
    ap.add_argument("--history", action="store_true", help="print the connection history and exit")
    ap.add_argument("--install-autostart", action="store_true",
                    help="start the host at login with the other options given here, then exit")
    ap.add_argument("--uninstall-autostart", action="store_true", help="remove the login autostart entry")
    ap.add_argument("-v", "--verbose", action="store_true")
    raw = list(sys.argv[1:] if argv is None else argv)
    a = ap.parse_args(raw)

    if bool(a.tunnel_hostname) != bool(a.tunnel_token_file):
        ap.error("--tunnel-hostname and --tunnel-token-file must be provided together")
    if (a.tunnel_hostname or a.tunnel_token_file) and not a.share:
        ap.error("named Cloudflare tunnels require --share")

    if a.install_autostart or a.uninstall_autostart:
        from . import autostart
        if a.uninstall_autostart:
            print("Removed autostart:", autostart.uninstall())
            return
        if a.set_unattended_password is not None:
            # Store the salted hash now; never put the password itself into the autostart command.
            from .agent import Agent
            from .config import Config
            cfg = Config.load()
            if a.server and a.server != cfg.server:
                cfg.server, cfg.id, cfg.secret = a.server, "", ""
            Agent(cfg, None, "unused").set_permanent_password(a.set_unattended_password)
            print("Unattended password stored (salted hash only).")
        keep, skip = [], False
        for x in raw:
            if skip:
                skip = False
            elif x == "--set-unattended-password":
                skip = True
            elif x != "--install-autostart" and not x.startswith("--set-unattended-password="):
                keep.append(x)
        print("Installed autostart:", autostart.install(keep))
        return
    if a.history:
        _print_history()
        return
    desktop_ok = not a.terminal_only and _has_display()
    if not desktop_ok and not a.headless:
        a.headless = True  # no display means no window either

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(message)s")
    _dpi_aware()

    cfg = Config.load()
    if a.server:
        if a.server != cfg.server:
            cfg.id = cfg.secret = ""
        cfg.server = a.server
    if a.no_ask:
        cfg.ask = False
    if a.view_only:
        cfg.allow_input = False
    if a.no_files:
        cfg.allow_files = False
    if a.no_clipboard:
        cfg.allow_clipboard = False
    if a.no_terminal:
        cfg.allow_terminal = False
    if a.insecure:
        cfg.insecure_tls = True
    cfg.save()

    if a.headless:
        from .agent import Agent
        pw = a.password or generate_password()
        agent = Agent(cfg, ConsoleUI(), pw)
        agent.desktop_ok = desktop_ok
        if a.set_unattended_password is not None:
            agent.set_permanent_password(a.set_unattended_password)
        if cfg.ask:
            print("[note] headless mode cannot show prompts; use --no-ask to allow the session password.")
        print(f"  Session password: {pw}" + ("   (unattended password also set)" if cfg.pw_key else ""))
        try:
            asyncio.run(_headless(agent, a, pw))
        except KeyboardInterrupt:
            pass
        return

    from .gui import HostWindow
    w = HostWindow(cfg, a.password, share=a.share, tunnel_hostname=a.tunnel_hostname,
                   tunnel_token_file=a.tunnel_token_file)
    if a.set_unattended_password is not None:
        w.agent.set_permanent_password(a.set_unattended_password)
        w._refresh_perm_btn()
    w.run()


if __name__ == "__main__":
    main()
