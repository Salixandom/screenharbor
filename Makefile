# AniDesk - type `make` to see everything you can do.
# Works on Linux, macOS and Windows (GNU make, from cmd, PowerShell or Git Bash).
# Needs: uv (https://docs.astral.sh/uv/) and Node.js 18+.

SERVER     ?= ws://localhost:8080/ws
PORT       ?= 8080
HTTPS_PORT ?= 8443
PASSWORD   ?=
ARGS       ?=

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
.PHONY: help install server share share-headless host headless unattended viewer dev test unit selftest bench \
        autostart no-autostart docker-build docker-run clean

help:
	$(info AniDesk commands)
	$(info ----------------)
	$(info   make install       install everything - server packages and host Python env)
	$(info   make server        run the ID/relay server and web viewer on ports $(PORT) and $(HTTPS_PORT))
	$(info   make share         NO SERVER NEEDED: share via a temporary internet link and code)
	$(info   make share-headless  same, console only - needs PASSWORD=...)
	$(info   make host          share this computer through a server you run, window mode)
	$(info   make headless      share this computer, console only - needs PASSWORD=...)
	$(info   make unattended    store a permanent password for unattended access - needs PASSWORD=...)
	$(info   make viewer        open the web viewer in your browser)
	$(info   make dev           server and host together for local testing)
	$(info   make test          unit tests and full end-to-end self test)
	$(info   make bench         compare capture and encoder pipelines on this machine)
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
	$(HOST) anidesk-host --server $(SERVER) $(PW) $(ARGS)

share:
	$(HOST) anidesk-host --share $(PW) $(ARGS)

share-headless:
	$(HOST) anidesk-host --share --headless --no-ask $(PW) $(ARGS)

headless:
	$(HOST) anidesk-host --headless --no-ask --server $(SERVER) $(PW) $(ARGS)

unattended:
	$(HOST) anidesk-host --headless --server $(SERVER) --set-unattended-password "$(PASSWORD)" $(ARGS)

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

autostart:
	$(HOST) anidesk-host --install-autostart --server $(SERVER) $(if $(PASSWORD),--headless --set-unattended-password "$(PASSWORD)",) $(ARGS)

no-autostart:
	$(HOST) anidesk-host --uninstall-autostart

docker-build:
	docker build -t anidesk-server server

docker-run:
	docker run -d --name anidesk-server --restart unless-stopped -p $(PORT):8080 -p $(HTTPS_PORT):8443 -v anidesk-data:/data anidesk-server

clean:
	uv run --project host python -c "import shutil; [shutil.rmtree(p, True) for p in ('server/node_modules', 'host/.venv')]"
