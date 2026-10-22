"""Spin up a private server + headless host and run the e2e suites against them.

    uv run --project host python tests/selftest.py

Works the same on Windows, Linux and macOS. Uses free ports and a throwaway
config dir, so it never touches your real AniDesk ID or settings.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_host(url: str, home: str, *extra: str, want_relay: bool = False):
    env = {**os.environ, "ANIDESK_HOME": home, "PYTHONUNBUFFERED": "1"}
    p = subprocess.Popen([sys.executable, "-m", "anidesk_host", "--headless", "--server", url, *extra],
                         cwd=ROOT / "host", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + 30
    relay = None
    for line in p.stdout:
        r = re.search(r"Local relay: (ws://\S+)", line)
        if r:
            relay = r.group(1)
        m = re.search(r"AniDesk ID: ([\d ]+)", line)
        if m and (relay or not want_relay):
            # Keep draining output so the host never blocks on a full pipe.
            threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
            return p, m.group(1).replace(" ", ""), relay
        if time.time() > deadline:
            break
    p.kill()
    raise SystemExit("host did not register")


def e2e(*args: str) -> bool:
    print(f"\n$ node tests/e2e.mjs {' '.join(args)}", flush=True)
    return subprocess.run([NODE, str(ROOT / "tests" / "e2e.mjs"), *args], cwd=ROOT).returncode == 0


def main() -> int:
    if not NODE:
        print("node not found: install Node.js 18+")
        return 1
    port = free_port()
    url = f"ws://127.0.0.1:{port}/ws"
    data = tempfile.mkdtemp(prefix="anidesk-selftest-")
    procs = []
    try:
        srv = subprocess.Popen([NODE, "index.js", "--port", str(port), "--bind", "127.0.0.1",
                                "--data-dir", os.path.join(data, "server")],
                               cwd=ROOT / "server", stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        procs.append(srv)
        time.sleep(1)

        pw = "Selftest-pass-1"
        host, hid, _ = start_host(url, os.path.join(data, "h1"), "--no-ask", "--password", pw)
        procs.append(host)
        ok = e2e(url, hid, pw)

        # A host that asks before accepting: only unattended password or reconnect tokens get in.
        un = "Unattended-pass-2"
        host2, hid2, _ = start_host(url, os.path.join(data, "h2"), "--password", pw, "--set-unattended-password", un)
        procs.append(host2)
        ok = e2e(url, hid2, pw, un, "--prompt-host") and ok

        # "Share via link" mode: the host is its own server (built-in relay, no Node server involved).
        host3, hid3, relay = start_host("ws://127.0.0.1:9/ws", os.path.join(data, "h3"), "--no-ask",
                                        "--password", pw, "--share-local", want_relay=True)
        procs.append(host3)
        ok = e2e(relay, hid3, pw) and ok

        print("\nSELFTEST " + ("PASSED" if ok else "FAILED"))
        return 0 if ok else 1
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
