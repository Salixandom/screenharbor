"""AniDesk host entry point:  python -m anidesk_host [--headless] ..."""
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


def _check_display() -> None:
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        if os.environ.get("WAYLAND_DISPLAY"):
            sys.exit("AniDesk needs an X11 session (Wayland screen capture/input is not supported yet). "
                     "Log in with 'GNOME on Xorg' / 'Plasma (X11)', or run under Xwayland with DISPLAY set.")
        sys.exit("No X display found (DISPLAY is not set).")


class ConsoleUI:
    def status(self, text): print(f"[status] {text}", flush=True)
    def id_changed(self, i): print(f"\n  AniDesk ID: {' '.join(i[k:k + 3] for k in range(0, len(i), 3))}\n", flush=True)
    def log(self, text): print(f"[log] {text}", flush=True)
    def chat(self, s, text): print(f"[chat] {s.viewer_name}: {text}", flush=True)
    def session_started(self, s): print(f"[session] REMOTE SESSION ACTIVE: {s.label}", flush=True)
    def session_ended(self, s): print(f"[session] ended: {s.label}", flush=True)

    async def ask(self, session) -> bool:
        return False  # headless mode never auto-accepts unknown viewers


async def _headless(agent, a, pw: str) -> None:
    if a.share or a.share_local:
        await agent.start_relay()  # before connecting, so we never try the normal server first
    run = asyncio.create_task(agent.run())
    if a.share or a.share_local:
        try:
            url = await agent.start_sharing(use_tunnel=not a.share_local)
        except Exception as e:
            print(f"[error] could not start sharing: {e}", flush=True)
        else:
            while not agent.ident[0] or agent.relay is None or agent.relay.host_id != agent.ident[0]:
                await asyncio.sleep(0.1)  # wait until we're registered with our own relay
            if a.share:
                code = agent.tunnel.code
                print("\n  ================= Share this =================", flush=True)
                print(f"  Link:     {url}/#id={agent.ident[0]}", flush=True)
                print(f"  Code:     {code}   (type it into any AniDesk viewer)", flush=True)
                print(f"  Password: {pw}", flush=True)
                print("  ===============================================\n", flush=True)
    try:
        await run
    finally:
        await agent.stop_sharing()


def main(argv=None) -> None:
    from .config import Config, generate_password

    ap = argparse.ArgumentParser(prog="anidesk-host", description="Share this computer via AniDesk.")
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
    ap.add_argument("--share-local", action="store_true", help=argparse.SUPPRESS)  # built-in relay only (tests)
    ap.add_argument("--install-autostart", action="store_true",
                    help="start the host at login with the other options given here, then exit")
    ap.add_argument("--uninstall-autostart", action="store_true", help="remove the login autostart entry")
    ap.add_argument("-v", "--verbose", action="store_true")
    raw = list(sys.argv[1:] if argv is None else argv)
    a = ap.parse_args(raw)

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
    _check_display()

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
    if a.insecure:
        cfg.insecure_tls = True
    cfg.save()

    if a.headless:
        from .agent import Agent
        pw = a.password or generate_password()
        agent = Agent(cfg, ConsoleUI(), pw)
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
    w = HostWindow(cfg, a.password, share=a.share)
    if a.set_unattended_password is not None:
        w.agent.set_permanent_password(a.set_unattended_password)
        w._refresh_perm_btn()
    w.run()


if __name__ == "__main__":
    main()
