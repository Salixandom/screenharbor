// End-to-end protocol test: acts like the web viewer (same WebCrypto calls) against a
// running server + host.
//   node tests/e2e.mjs <server-url> <id> <password>
//   node tests/e2e.mjs <server-url> <id> <session-password> <unattended-password> --prompt-host
// --prompt-host: the host asks before accepting (headless hosts always decline), so only the
// unattended password or a reconnect token may get in.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';

// Node 18/20 compatibility: no global WebCrypto/WebSocket there, so fall back to node:crypto + ws.
const WebSocket = globalThis.WebSocket ?? createRequire(new URL('../server/', import.meta.url))('ws');

const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const PROMPT_HOST = process.argv.includes('--prompt-host');
const [url = 'ws://localhost:8080/ws', ID, PASSWORD, UNATTENDED] = args;
const subtle = (globalThis.crypto ?? webcrypto).subtle;
const te = new TextEncoder(), td = new TextDecoder();
const K_JSON = 1, K_FRAME = 2, K_FILE = 3, K_VIDEO = 4;
const b64e = (u8) => Buffer.from(u8).toString('base64');
const b64d = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const concat = (...p) => { const a = p.map((x) => (Array.isArray(x) ? Uint8Array.from(x) : x)); const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const nonce = (seq) => { const n = new Uint8Array(12); new DataView(n.buffer).setBigUint64(4, seq); return n; };

async function channel(shared, pwk, hostPub, myPub) {
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const okm = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: pwk, info: concat(te.encode('anidesk/v1'), hostPub, myPub) }, ikm, 512));
  const imp = (b) => subtle.importKey('raw', b, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const c = { rx: await imp(okm.slice(0, 32)), tx: await imp(okm.slice(32)), txSeq: 0n, rxSeq: 0n };
  c.seal = async (pt) => { const iv = nonce(c.txSeq++); return concat(iv.subarray(4), new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, c.tx, pt))); };
  c.open = async (buf) => { const u = new Uint8Array(buf); const seq = new DataView(u.buffer, u.byteOffset).getBigUint64(0); if (seq !== c.rxSeq) throw new Error('seq'); const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce(seq) }, c.rx, u.subarray(8))); c.rxSeq++; return pt; };
  return c;
}

function connect(password, { codecs = ['jpeg'], token = null } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const s = { ws, ch: null, cands: null, inbox: [], waiters: [] };
    let chain = Promise.resolve();
    const deliver = (m) => { const w = s.waiters.findIndex((x) => x.pred(m)); if (w >= 0) s.waiters.splice(w, 1)[0].res(m); else s.inbox.push(m); };
    s.next = (pred, ms = 10000) => {
      const i = s.inbox.findIndex(pred);
      if (i >= 0) return Promise.resolve(s.inbox.splice(i, 1)[0]);
      return new Promise((res, rej) => { s.waiters.push({ pred, res }); setTimeout(() => rej(new Error('timeout waiting')), ms); });
    };
    s.send = async (obj) => ws.send(await s.ch.seal(concat([K_JSON], te.encode(JSON.stringify(obj)))));
    s.sendRaw = async (pt) => ws.send(await s.ch.seal(pt));
    ws.onopen = () => ws.send(JSON.stringify({ t: 'connect', id: ID }));
    ws.onclose = () => deliver({ t: '__closed' });
    ws.onmessage = (ev) => { chain = chain.then(async () => {
      if (typeof ev.data === 'string') {
        const m = JSON.parse(ev.data);
        if (m.t === 'hello') {
          const hostPub = b64d(m.pub);
          const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
          const myPub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
          const hk = await subtle.importKey('raw', hostPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
          const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: hk }, kp.privateKey, 256));
          ws.send(JSON.stringify({ t: 'hello', v: 1, pub: b64e(myPub) }));
          s.cands = [];
          for (const salt of m.salts.map(b64d)) {
            const k = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
            const pwk = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 }, k, 256));
            const c = await channel(shared, pwk, hostPub, myPub);
            s.cands.push(c);
            ws.send(await c.seal(concat([K_JSON], te.encode(JSON.stringify({ t: 'auth', name: 'e2e-test', codecs, token })))));
          }
          resolve(s);
        } else deliver(m);
        return;
      }
      let pt;
      if (s.ch) pt = await s.ch.open(ev.data);
      else for (const c of s.cands) { try { pt = await c.open(ev.data); s.ch = c; break; } catch {} }
      if (!pt) throw new Error('undecryptable');
      const kind = pt[0], body = pt.subarray(1);
      if (kind === K_JSON) deliver(JSON.parse(td.decode(body)));
      else if (kind === K_FRAME) deliver({ t: '__frame', body: body.slice() });
      else if (kind === K_FILE) deliver({ t: '__file', body: body.slice() });
      else if (kind === K_VIDEO) deliver({ t: '__video', body: body.slice() });
    }).catch(reject); };
    setTimeout(() => reject(new Error('connect timeout')), 15000);
  });
}

const ok = (msg) => console.log('  ✓ ' + msg);
const frameNo = (fr) => new DataView(fr.body.buffer, fr.body.byteOffset).getUint32(0);
const t0 = Date.now();

// 1. wrong password is rejected
{
  const s = await connect('definitely-wrong');
  const m = await s.next((m) => m.t === 'auth_failed' || m.t === '__closed');
  assert.equal(m.t, 'auth_failed');
  ok('wrong password rejected');
}

if (PROMPT_HOST) {
  const s1 = await connect(PASSWORD);
  assert.equal((await s1.next((m) => m.t === 'denied' || m.t === 'welcome')).t, 'denied');
  ok('session password without Accept is declined');
  const s2 = await connect(UNATTENDED);
  await s2.next((m) => m.t === 'welcome');
  const tok = (await s2.next((m) => m.t === 'token')).v;
  s2.ws.close();
  ok('unattended password accepted without prompt');
  const s3 = await connect(PASSWORD, { token: tok });
  await s3.next((m) => m.t === 'welcome');
  s3.ws.close();
  ok('reconnect token skips the prompt');
  const s4 = await connect(PASSWORD, { token: tok });
  assert.equal((await s4.next((m) => m.t === 'denied' || m.t === 'welcome')).t, 'denied');
  ok('reconnect token is single-use');
  console.log(`\nAll prompt-host checks passed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  process.exit(0);
}

// 2. JPEG viewer: welcome, screen, frames
const s = await connect(PASSWORD, { codecs: ['jpeg'] });
const welcome = await s.next((m) => m.t === 'welcome');
ok(`welcome from ${welcome.name} (${welcome.os}), ${welcome.monitors.length - 1} monitor(s), encoder ${welcome.encoder}`);
const token = (await s.next((m) => m.t === 'token')).v;
assert.match(token, /^[0-9a-f]{48}$/);
const screen = await s.next((m) => m.t === 'screen');
assert.equal(screen.codec, 'jpeg', 'viewer without WebCodecs must get JPEG');
ok(`screen ${screen.w}x${screen.h} codec=${screen.codec} capture=${screen.capture}`);
const f = await s.next((m) => m.t === '__frame');
const dv = new DataView(f.body.buffer, f.body.byteOffset);
const first = { w: dv.getUint16(10), h: dv.getUint16(12), len: dv.getUint32(15) };
assert.equal(first.w, screen.w); assert.equal(first.h, screen.h);
const jpeg = f.body.subarray(19, 19 + first.len);
assert.equal(jpeg[0], 0xff); assert.equal(jpeg[1], 0xd8);
ok(`JPEG full frame: ${(f.body.length / 1024).toFixed(0)} KB`);
await s.send({ t: 'ack', f: frameNo(f) });

await s.send({ t: 'settings', quality: 40, fps: 30, scale: 2, monitor: 1, codec: 'jpeg' });
const sc2 = await s.next((m) => m.t === 'screen');
assert.equal(sc2.w, Math.ceil(screen.w / 2));
ok(`half-resolution switch -> ${sc2.w}x${sc2.h}`);

// Input injection: move the host's real cursor, then read it back from the host's cursor reports.
await s.send({ t: 'mm', x: 0.25, y: 0.75 });
const cur = await s.next((m) => m.t === 'cur' && Math.abs(m.x - 0.25) < 0.01 && Math.abs(m.y - 0.75) < 0.01, 5000);
ok(`mouse injection: host cursor now at (${cur.x}, ${cur.y})`);
(async () => {
  for (;;) {
    const fr = await s.next((m) => m.t === '__frame', 60000).catch(() => null);
    if (!fr) return;
    await s.send({ t: 'ack', f: frameNo(fr) }).catch(() => {});
  }
})();

// 3. files: listing, download, folder zip, upload
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anidesk-e2e-'));
const payload = new Uint8Array(700 * 1024).map((_, i) => (i * 31 + 7) & 255);
fs.writeFileSync(path.join(dir, 'source.bin'), payload);
fs.mkdirSync(path.join(dir, 'sub'));
fs.writeFileSync(path.join(dir, 'sub', 'a.txt'), 'hello');
fs.writeFileSync(path.join(dir, 'sub', 'b.txt'), 'world');
await s.send({ t: 'ls', path: dir });
const ls = await s.next((m) => m.t === 'ls' || m.t === 'ls_err');
if (ls.t === 'ls_err') {
  // The host is a different machine (e.g. reached through a share link): our temp files don't exist there.
  ok(`file tests skipped: host can't see this machine's temp dir (${ls.msg.slice(0, 50)})`);
} else {
  assert.ok(ls.entries.some((e) => e.n === 'source.bin'));
  ok(`listed ${ls.entries.length} entries in temp dir`);

  async function fetchFile(id, p) {
    await s.send({ t: 'get', id, path: p });
    const fstart = await s.next((m) => m.t === 'fstart' || m.t === 'ferr');
    assert.equal(fstart.t, 'fstart');
    const chunks = [];
    for (;;) {
      const m = await s.next((m) => m.t === '__file' || m.t === 'fend' || m.t === 'ferr');
      if (m.t !== '__file') { assert.equal(m.t, 'fend'); break; }
      chunks.push(m.body.subarray(4));
    }
    return { meta: fstart, data: Buffer.concat(chunks) };
  }
  const dl = await fetchFile(7, path.join(dir, 'source.bin'));
  assert.deepEqual(dl.data, Buffer.from(payload));
  ok('download: 700 KB file matches byte-for-byte');
  const zip = await fetchFile(8, path.join(dir, 'sub'));
  assert.equal(zip.meta.name, 'sub.zip');
  assert.equal(zip.data.subarray(0, 2).toString(), 'PK');
  assert.ok(zip.data.includes(Buffer.from('sub/a.txt')) && zip.data.includes(Buffer.from('sub/b.txt')));
  ok(`folder download: sub.zip (${zip.data.length} B) contains both files`);

  await s.send({ t: 'put', id: 9, name: '../evil/up loaded.bin', size: payload.length, dir });
  for (let o = 0; o < payload.length; o += 256 * 1024) await s.sendRaw(concat([K_FILE], [0, 0, 0, 9], payload.subarray(o, o + 256 * 1024)));
  await s.send({ t: 'pend', id: 9 });
  const pdone = await s.next((m) => m.t === 'pdone' || m.t === 'perr');
  assert.equal(pdone.t, 'pdone');
  assert.equal(path.dirname(pdone.path), dir, 'upload must stay in target dir (path traversal sanitized)');
  assert.deepEqual(fs.readFileSync(pdone.path), Buffer.from(payload));
  ok(`upload: stored as ${path.basename(pdone.path)} inside target dir, bytes match`);

}

await s.send({ t: 'chat', s: 'hello from e2e' });
const hs = await s.next((m) => m.t === 'hstats', 5000);
ok(`host stats: codec=${hs.codec} ${hs.kbps} kbit/s rtt=${hs.rtt} ms`);
s.ws.close();
fs.rmSync(dir, { recursive: true, force: true });

// 4. H.264 viewer (if the host has an encoder), reconnecting with the token
if (welcome.encoder) {
  const v = await connect(PASSWORD, { codecs: ['h264', 'jpeg'], token });
  await v.next((m) => m.t === 'welcome');
  ok('reconnect token accepted');
  // Ask for H.264 explicitly: "auto" stays on JPEG when only a software encoder exists.
  await v.send({ t: 'settings', quality: 60, fps: 30, scale: 1, monitor: 1, codec: 'h264' });
  const vs = await v.next((m) => m.t === 'screen' && m.codec === 'h264');
  const vf = await v.next((m) => m.t === '__video');
  const vdv = new DataView(vf.body.buffer, vf.body.byteOffset);
  assert.equal(vdv.getUint8(4) & 1, 1, 'first H.264 frame must be a keyframe');
  const au = vf.body.subarray(5);
  const nalTypes = [];
  for (let i = 0; i + 3 < au.length; i++) if (au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 1) nalTypes.push(au[i + 3] & 0x1f);
  assert.ok(nalTypes.includes(7) && nalTypes.includes(8) && nalTypes.includes(5), `need SPS/PPS/IDR, got ${nalTypes}`);
  fs.writeFileSync(path.join(os.tmpdir(), 'anidesk_key.h264'), au);
  ok(`H.264 keyframe via ${vs.encoder}: ${(au.length / 1024).toFixed(0)} KB, NAL types ${[...new Set(nalTypes)]}`);
  await v.send({ t: 'ack', f: frameNo(vf) });
  let bytes = 0, frames = 0;
  const end = Date.now() + 3000;
  while (Date.now() < end) {
    const fr = await v.next((m) => m.t === '__video', 4000).catch(() => null);
    if (!fr) break;
    bytes += fr.body.length; frames++;
    await v.send({ t: 'ack', f: frameNo(fr) });
  }
  ok(`H.264 steady state: ${frames} frames, ${(bytes * 8 / 3000).toFixed(0)} kbit/s over 3 s`);
  v.ws.close();
}

console.log(`\nAll e2e checks passed in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
process.exit(0);
