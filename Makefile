# ScreenHarbor - type `make` to see everything you can do.
# Works on Linux, macOS and Windows (GNU make, from cmd, PowerShell or Git Bash).
# Needs: uv (https://docs.astral.sh/uv/) and Node.js 18+.

SERVER     ?= ws://localhost:8080/ws
PORT       ?= 8080
HTTPS_PORT ?= 8443
PASSWORD   ?=
ARGS       ?=
CLI_ARGS   ?=
TARGET     ?=
PORTS      ?=
REMOTE_PORT ?= 22

HOST := uv run --project host
PW   := $(if $(PASSWORD),--password "$(PASSWORD)",)

ifeq ($(OS),Windows_NT)
  OPEN := explorer
else ifeq ($(shell uname -s),Darwin)
  OPEN := open
else
  OPEN := xdg-open
endif

.DEFAULT_GOAL := help
.PHONY: help install server share share-headless share-autostart share-named named-share host headless unattended viewer dev test unit selftest bench measure cli term ssh forward proxy history \
        autostart no-autostart docker-build docker-run clean

help:
	$(info ScreenHarbor commands)
	$(info ----------------)
	$(info   make install       install everything - server packages and host Python env)
	$(info   make server        run the ID/relay server and web viewer on ports $(PORT) and $(HTTPS_PORT))
	$(info   make share         NO SERVER NEEDED: share via temporary link + stable address)
	$(info   make share-named TUNNEL_HOST=desk.example.com TOKEN_FILE=...  use a named Cloudflare tunnel)
	$(info   make share-headless  same, console only - needs PASSWORD=...)
	$(info   make share-autostart PASSWORD=...  start stable-link sharing at login, unattended)
	$(info   make host          share this computer through a server you run, window mode)
	$(info   make headless      share this computer, console only - needs PASSWORD=...)
	$(info   make unattended    store a permanent password for unattended access - needs PASSWORD=...)
	$(info   make viewer        open the web viewer in your browser)
	$(info   make dev           server and host together for local testing)
	$(info   make test          unit tests and full end-to-end self test)
	$(info   make bench         compare capture and encoder pipelines on this machine)
	$(info   make measure       measure screen latency, host RAM and CPU (ARGS=--share for Cloudflare))
	$(info   make cli CLI_ARGS=...  run screenharbor terminal / SSH / forwarding client)
	$(info   make term TARGET=...   open a remote terminal)
	$(info   make ssh TARGET=... [ARGS=...]  SSH through ScreenHarbor (host needs SSH server))
	$(info   make forward TARGET=... PORTS=2222:22  forward a local port)
	$(info   make proxy TARGET=... REMOTE_PORT=22  run SSH ProxyCommand transport)
	$(info   make history       print recent host connection history)
	$(info   make autostart     start the host at login - add PASSWORD=... for unattended)
	$(info   make no-autostart  remove the login autostart)
	$(info   make docker-build  build the server Docker image)
	$(info   make docker-run    run the server image with persistent IDs)
	$(info   make clean         remove installed packages and caches)
	$(info Options: SERVER=ws://host:8080/ws  PASSWORD=...  PORT=8080  HTTPS_PORT=8443  ARGS=extra-flags)
	$(info Example: make host SERVER=ws://192.168.1.10:8080/ws)
	@:

install:
	cd server && npm install
	uv sync --project host

server:
	cd server && node index.js --port $(PORT) --https-port $(HTTPS_PORT) $(ARGS)

host:
	$(HOST) screenharbor-host --server $(SERVER) $(PW) $(ARGS)

share:
	$(HOST) screenharbor-host --share --stable-address $(PW) $(ARGS)

share-headless:
	$(HOST) screenharbor-host --share --stable-address --headless --no-ask $(PW) $(ARGS)

share-autostart:
	$(if $(strip $(PASSWORD)),$(HOST) screenharbor-host --install-autostart --share --stable-address --headless --no-ask --set-unattended-password "$(PASSWORD)" $(ARGS),$(error share-autostart requires PASSWORD=...))

share-named:
	$(if $(strip $(TUNNEL_HOST)),,$(error share-named requires TUNNEL_HOST=desk.example.com))
	$(if $(strip $(TOKEN_FILE)),,$(error share-named requires TOKEN_FILE=path/to/token))
	$(HOST) screenharbor-host --share --stable-address --tunnel-hostname "$(TUNNEL_HOST)" --tunnel-token-file "$(TOKEN_FILE)" $(PW) $(ARGS)

named-share: share-named

headless:
	$(HOST) screenharbor-host --headless --no-ask --server $(SERVER) $(PW) $(ARGS)

unattended:
	$(HOST) screenharbor-host --headless --server $(SERVER) --set-unattended-password "$(PASSWORD)" $(ARGS)

viewer:
	$(OPEN) http://localhost:$(PORT)

dev:
	$(MAKE) -j2 server host

test: unit selftest

unit:
	$(HOST) python tests/test_host.py

selftest:
	$(HOST) python tests/selftest.py

bench:
	$(HOST) python tests/bench.py 2
	$(HOST) python tests/pipeline_bench.py 4

measure:
	uv run --project host --group dev python tests/measure.py $(ARGS)

cli:
	$(HOST) screenharbor $(CLI_ARGS)

term:
	$(HOST) screenharbor term $(TARGET) $(ARGS)

ssh:
	$(HOST) screenharbor ssh $(TARGET) $(ARGS)

forward:
	$(HOST) screenharbor forward $(TARGET) $(PORTS) $(ARGS)

proxy:
	$(HOST) screenharbor proxy $(TARGET) $(REMOTE_PORT) $(ARGS)

history:
	$(HOST) screenharbor-host --history

autostart:
	$(HOST) screenharbor-host --install-autostart --server $(SERVER) $(if $(PASSWORD),--headless --set-unattended-password "$(PASSWORD)",) $(ARGS)

no-autostart:
	$(HOST) screenharbor-host --uninstall-autostart

docker-build:
	docker build -t screenharbor-server server

docker-run:
	docker run -d --name screenharbor-server --restart unless-stopped -p $(PORT):8080 -p $(HTTPS_PORT):8443 -v screenharbor-data:/data screenharbor-server

clean:
	uv run --project host python -c "import shutil; [shutil.rmtree(p, True) for p in ('server/node_modules', 'host/.venv')]"
