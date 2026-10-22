#!/usr/bin/env node
'use strict';
/*
 * AniDesk server: ID registry (rendezvous) + blind relay + static web viewer.
 *
 * The server never sees session contents. Hosts and viewers run an
 * end-to-end ECDH + password-derived AES-GCM handshake *through* the relay,
 * so the server only shuffles opaque frames between two sockets.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const eq = a.indexOf('=');
    if (eq > 0) o[a.slice(2, eq)] = a.slice(eq + 1);
    else if (argv[i + 1] && !argv[i + 1].startsWith('--')) o[a.slice(2)] = argv[++i];
    else o[a.slice(2)] = true;
  }
  return o;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log(`AniDesk server

  --port <n>          HTTP/WS port (default 8080, env ANIDESK_PORT)
  --https-port <n>    Also serve HTTPS/WSS on this port (needed for the web
                      viewer when it is not opened via localhost)
  --tls-cert <file>   PEM certificate for HTTPS (default: auto self-signed)
  --tls-key <file>    PEM private key for HTTPS
  --bind <addr>       Bind address (default 0.0.0.0)
  --data-dir <dir>    Where IDs and generated certs are stored (default ./data)
  --trust-proxy       Use X-Forwarded-For for client IPs (behind a reverse proxy)
`);
  process.exit(0);
}

const PORT = +(args.port || process.env.ANIDESK_PORT || 8080);
const HTTPS_PORT = args['https-port'] ? +args['https-port'] : null;
const BIND = args.bind || '0.0.0.0';
const DATA_DIR = path.resolve(args['data-dir'] || path.join(__dirname, 'data'));
const WEB_DIR = path.join(__dirname, 'web');
const TRUST_PROXY = !!args['trust-proxy'];

const PAIR_TIMEOUT_MS = 20000;
const HIGH_WATER = 8 * 1024 * 1024;
const LOW_WATER = 1 * 1024 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true });

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------- ID registry
const idsFile = path.join(DATA_DIR, 'ids.json');
let ids = {};
try { ids = JSON.parse(fs.readFileSync(idsFile, 'utf8')); } catch { /* first run */ }
let saveTimer = null;
function saveIds() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFileSync(idsFile + '.tmp', JSON.stringify(ids, null, 1));
    fs.renameSync(idsFile + '.tmp', idsFile);
  }, 200);
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
function safeEqualHex(a, b) {
  const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function newId() {
  for (;;) {
    const id = String(crypto.randomInt(100000000, 1000000000)); // 9 digits
    if (!ids[id]) return id;
  }
}

/** id -> control socket of an online host */
const hosts = new Map();
/** sid -> { viewer, hostId, timer } */
const pending = new Map();

// --------------------------------------------------------------- rate limits
const buckets = new Map();
function allow(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.start > windowMs) { b = { start: now, n: 0 }; buckets.set(key, b); }
  return ++b.n <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now - b.start > 15 * 60000) buckets.delete(k);
}, 60000).unref();

// ------------------------------------------------------------------- relay
function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function relay(src, dst, data, isBinary) {
  if (dst.readyState !== WebSocket.OPEN) return;
  dst.send(data, { binary: isBinary });
  // Backpressure: stop reading from the sender while the receiver is slow.
  if (!src._paused && dst.bufferedAmount > HIGH_WATER) {
    src._paused = true;
    src._socket.pause();
    const t = setInterval(() => {
      if (dst.readyState !== WebSocket.OPEN || dst.bufferedAmount < LOW_WATER) {
        clearInterval(t);
        src._paused = false;
        if (src.readyState === WebSocket.OPEN) src._socket.resume();
      }
    }, 20);
  }
}

function pair(hostSession, viewer) {
  hostSession.role = 'session';
  hostSession.peer = viewer;
  viewer.peer = hostSession;
  send(hostSession, { t: 'paired' });
  send(viewer, { t: 'paired' });
}

function onControl(ws, msg) {
  switch (msg.t) {
    case 'register': {
      if (ws.role) return send(ws, { t: 'error', msg: 'already registered' });
      if (!allow('reg:' + ws.ip, 30, 60000)) return ws.close(4029, 'rate limited');
      let id = typeof msg.id === 'string' ? msg.id.replace(/\D/g, '') : '';
      let secret = typeof msg.secret === 'string' ? msg.secret : '';
      if (!(id && secret && ids[id] && safeEqualHex(ids[id].h, sha256(secret)))) {
        id = newId();
        secret = crypto.randomBytes(24).toString('hex');
        ids[id] = { h: sha256(secret), created: Date.now() };
      }
      ids[id].seen = Date.now();
      saveIds();
      const old = hosts.get(id);
      if (old && old !== ws) old.close(4000, 'replaced by new login');
      hosts.set(id, ws);
      ws.role = 'host';
      ws.hostId = id;
      ws.hostName = String(msg.name || '').slice(0, 64);
      send(ws, { t: 'registered', id, secret });
      log(`host ${id} online (${ws.ip})`);
      return;
    }
    case 'connect': {
      if (ws.role) return send(ws, { t: 'error', msg: 'invalid state' });
      if (!allow('conn:' + ws.ip, 20, 60000)) {
        send(ws, { t: 'error', msg: 'Too many connection attempts, wait a minute.' });
        return ws.close();
      }
      const id = String(msg.id || '').replace(/\D/g, '');
      const host = hosts.get(id);
      if (!host || host.readyState !== WebSocket.OPEN) {
        send(ws, { t: 'error', msg: 'That ID is not online.' });
        return ws.close();
      }
      const sid = crypto.randomBytes(16).toString('hex');
      ws.role = 'viewer';
      ws.sid = sid;
      const timer = setTimeout(() => {
        pending.delete(sid);
        send(ws, { t: 'error', msg: 'Host did not answer.' });
        ws.close();
      }, PAIR_TIMEOUT_MS);
      pending.set(sid, { viewer: ws, hostId: id, timer });
      send(host, { t: 'incoming', sid, ip: ws.ip });
      send(ws, { t: 'waiting' });
      log(`viewer ${ws.ip} -> ${id} (sid ${sid.slice(0, 8)})`);
      return;
    }
    case 'attach': {
      if (ws.role) return send(ws, { t: 'error', msg: 'invalid state' });
      const id = String(msg.id || '');
      const p = pending.get(String(msg.sid || ''));
      if (!p || p.hostId !== id || !ids[id] || !safeEqualHex(ids[id].h, sha256(String(msg.secret || '')))) {
        send(ws, { t: 'error', msg: 'unknown session' });
        return ws.close();
      }
      clearTimeout(p.timer);
      pending.delete(msg.sid);
      if (p.viewer.readyState !== WebSocket.OPEN) return ws.close();
      pair(ws, p.viewer);
      return;
    }
    case 'reject': {
      const p = pending.get(String(msg.sid || ''));
      if (!p || ws.role !== 'host' || p.hostId !== ws.hostId) return;
      clearTimeout(p.timer);
      pending.delete(msg.sid);
      send(p.viewer, { t: 'error', msg: String(msg.reason || 'Rejected by host.').slice(0, 200) });
      p.viewer.close();
      return;
    }
    case 'ping':
      return send(ws, { t: 'pong' });
    default:
      send(ws, { t: 'error', msg: 'unknown message' });
  }
}

function onConnection(ws, req) {
  ws.ip = (TRUST_PROXY && req.headers['x-forwarded-for']?.split(',')[0].trim()) || req.socket.remoteAddress;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (data, isBinary) => {
    if (ws.peer) return relay(ws, ws.peer, data, isBinary);
    if (isBinary || data.length > 4096) return ws.close(1003, 'expected control message');
    let msg;
    try { msg = JSON.parse(data.toString('utf8')); } catch { return ws.close(1003, 'bad json'); }
    if (!msg || typeof msg !== 'object') return ws.close(1003, 'bad message');
    onControl(ws, msg);
  });

  ws.on('close', () => {
    if (ws.peer && ws.peer.readyState === WebSocket.OPEN) ws.peer.close(1000, 'peer disconnected');
    if (ws.role === 'host' && hosts.get(ws.hostId) === ws) {
      hosts.delete(ws.hostId);
      log(`host ${ws.hostId} offline`);
    }
    if (ws.role === 'viewer' && pending.has(ws.sid)) {
      clearTimeout(pending.get(ws.sid).timer);
      pending.delete(ws.sid);
    }
  });
  ws.on('error', () => {});
}

// ------------------------------------------------------------- static files
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.json': 'application/json',
};
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; connect-src 'self' ws: wss:; style-src 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

function onRequest(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
    return res.end(JSON.stringify({ ok: true, hostsOnline: hosts.size, version: '0.1.0' }));
  }
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.join(WEB_DIR, path.normalize(p));
  if (!file.startsWith(WEB_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('not found'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      ...SECURITY_HEADERS,
    });
    res.end(buf);
  });
}

function attachWs(server) {
  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 32 * 1024 * 1024 });
  wss.on('connection', onConnection);
  const hb = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30000);
  wss.on('close', () => clearInterval(hb));
}

async function loadTls() {
  if (args['tls-cert'] && args['tls-key']) {
    return { cert: fs.readFileSync(args['tls-cert']), key: fs.readFileSync(args['tls-key']) };
  }
  const dir = path.join(DATA_DIR, 'tls');
  const certFile = path.join(dir, 'cert.pem'), keyFile = path.join(dir, 'key.pem');
  if (!fs.existsSync(certFile)) {
    const selfsigned = require('selfsigned');
    const pems = await Promise.resolve(selfsigned.generate([{ name: 'commonName', value: 'AniDesk' }], {
      keySize: 2048, days: 825, algorithm: 'sha256',
    }));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(certFile, pems.cert);
    fs.writeFileSync(keyFile, pems.private, { mode: 0o600 });
    log('generated self-signed certificate in', dir);
  }
  return { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
}

async function main() {
  const server = http.createServer(onRequest);
  attachWs(server);
  server.listen(PORT, BIND, () => log(`AniDesk server on http://${BIND}:${PORT}  (ws path /ws)`));
  if (HTTPS_PORT) {
    const tls = await loadTls();
    const s = https.createServer(tls, onRequest);
    attachWs(s);
    s.listen(HTTPS_PORT, BIND, () => log(`AniDesk server on https://${BIND}:${HTTPS_PORT}`));
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
