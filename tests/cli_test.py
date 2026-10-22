"""Exercise the `screenharbor` command-line client against a running host.

    python tests/cli_test.py <server-ws-url> <host-id> <password>
"""
import os
import socket
import subprocess
import sys
import threading
import time

URL, HID, PW = sys.argv[1:4]
CLI = [sys.executable, "-m", "screenharbor_host.client", "--server", URL]
ENV = {**os.environ, "SCREENHARBOR_PASSWORD": PW, "PYTHONUNBUFFERED": "1"}
results = []
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def ok(cond, msg):
    results.append(cond)
    print(f"  {'✓' if cond else '✗'} {msg}", flush=True)


def echo_server() -> int:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()

    def serve():
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=lambda c=conn: [c.sendall(d) for d in iter(lambda: c.recv(65536), b"")],
                             daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


port = echo_server()

# 1. proxy: stdin/stdout piped through the host to localhost:<port>
payload = os.urandom(300 * 1024)
p = subprocess.Popen(CLI + ["proxy", HID, str(port)], env=ENV, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
got = bytearray()


def reader():
    while len(got) < len(payload):
        chunk = p.stdout.read1(65536) if hasattr(p.stdout, "read1") else p.stdout.read(65536)
        if not chunk:
            break
        got.extend(chunk)


t = threading.Thread(target=reader, daemon=True)
t.start()
p.stdin.write(payload)
p.stdin.flush()
t.join(30)
p.kill()
ok(bytes(got) == payload, f"screenharbor proxy: {len(got) // 1024} KB echoed back intact")

# 2. forward: a local port that reaches the host's localhost:<port>
lport = free_port()
f = subprocess.Popen(CLI + ["forward", HID, f"{lport}:{port}"], env=ENV, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True)
deadline = time.time() + 30
for line in f.stdout:
    if "forwarding" in line or time.time() > deadline:
        break
good = True
for i in range(3):  # several connections over one ScreenHarbor session
    with socket.create_connection(("127.0.0.1", lport), timeout=15) as c:
        msg = f"hello-{i}".encode() * 1000
        c.sendall(msg)
        buf = b""
        while len(buf) < len(msg):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
        good = good and buf == msg
f.terminate()
ok(good, f"screenharbor forward {lport}:{port}: 3 connections echoed")

# 3. wrong password is reported clearly
bad = subprocess.run(CLI + ["proxy", HID, str(port)], env={**ENV, "SCREENHARBOR_PASSWORD": "nope"},
                     input=b"", capture_output=True, timeout=60)
ok(bad.returncode == 1 and b"wrong password" in bad.stderr, "wrong password gives a clear error")

# 4. interactive terminal (POSIX only: needs a pty to act like a person at a terminal)
if os.name == "posix":
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(CLI[0], CLI + ["term", HID], ENV)
    out = b""

    def wait_for(needle, timeout=20):
        global out
        end = time.time() + timeout
        while needle not in out and time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    break
        return needle in out

    wait_for(b"Exit the shell")
    time.sleep(1)
    os.write(fd, b'echo cli-""term-ok\r')
    ran = wait_for(b"cli-term-ok")
    os.write(fd, b"exit\r")
    end = time.time() + 15
    while time.time() < end and os.waitpid(pid, os.WNOHANG) == (0, 0):
        time.sleep(0.2)
    ok(ran, "screenharbor term: interactive shell ran a command and exited")

print("CLI TESTS " + ("PASSED" if all(results) else "FAILED"))
sys.exit(0 if all(results) else 1)
