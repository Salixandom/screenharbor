'use strict';
/*
 * AniDesk web viewer.
 * Protocol and crypto must match host/anidesk_host/crypto.py and session.py.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const K_JSON = 1, K_FRAME = 2, K_FILE = 3, K_VIDEO = 4;
  const CHUNK = 256 * 1024;
  const MAX_RECONNECTS = 10;
  const te = new TextEncoder(), td = new TextDecoder();

  // ------------------------------------------------------------ helpers
  const b64e = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  function concat(...parts) {
    const arrs = parts.map((p) => (Array.isArray(p) ? Uint8Array.from(p) : p));
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const fmtSize = (n) => {
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
  };
  const fmtRate = (kbps) => (kbps >= 1000 ? (kbps / 1000).toFixed(1) + ' Mbit/s' : kbps + ' kbit/s');
  const fmtId = (id) => id.replace(/\D/g, '').replace(/(\d{3})(?=\d)/g, '$1 ');
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  const codeToKey = (code) => {
    let m = /^Key([A-Z])$/.exec(code); if (m) return m[1].toLowerCase();
    m = /^Digit(\d)$/.exec(code); if (m) return m[1];
    return code;
  };
  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = el('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
  const stamp = () => new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);

  /** RFC 6381 codec string from the SPS in an Annex-B access unit, e.g. "avc1.640033". */
  function avcCodec(data) {
    for (let i = 0; i + 6 < data.length; i++) {
      if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1 && (data[i + 3] & 0x1f) === 7) {
        return 'avc1.' + [data[i + 4], data[i + 5], data[i + 6]].map((b) => b.toString(16).padStart(2, '0')).join('');
      }
    }
    return 'avc1.42e01f';
  }

  let h264Support = null;
  async function supportedCodecs() {
    if (h264Support === null) {
      h264Support = false;
      try {
        if (typeof VideoDecoder !== 'undefined') {
          const r = await VideoDecoder.isConfigSupported({ codec: 'avc1.640033', optimizeForLatency: true });
          h264Support = !!r.supported;
        }
      } catch { /* not supported */ }
    }
    return h264Support ? ['h264', 'jpeg'] : ['jpeg'];
  }

  // ------------------------------------------------------------- crypto
  async function passwordKey(password, salt) {
    const k = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 }, k, 256));
  }

  class Channel {
    static async create(shared, pwk, hostPub, viewerPub) {
      const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
      const okm = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: pwk, info: concat(te.encode('anidesk/v1'), hostPub, viewerPub) },
        ikm, 512));
      const imp = (b) => crypto.subtle.importKey('raw', b, 'AES-GCM', false, ['encrypt', 'decrypt']);
      const c = new Channel();
      c.rx = await imp(okm.slice(0, 32)); // host -> viewer
      c.tx = await imp(okm.slice(32));    // viewer -> host
      c.txSeq = 0n; c.rxSeq = 0n;
      return c;
    }
    static nonce(seq) { const n = new Uint8Array(12); new DataView(n.buffer).setBigUint64(4, seq); return n; }
    async seal(pt) {
      const iv = Channel.nonce(this.txSeq++);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.tx, pt));
      return concat(iv.subarray(4), ct);
    }
    async open(buf) {
      const u8 = new Uint8Array(buf);
      if (u8.length < 24) throw new Error('short frame');
      const seq = new DataView(u8.buffer, u8.byteOffset, 8).getBigUint64(0);
      if (seq !== this.rxSeq) throw new Error('bad sequence');
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Channel.nonce(seq) }, this.rx, u8.subarray(8)));
      this.rxSeq++;
      return pt;
    }
  }

  // ------------------------------------------------------------- session
  const canvas = $('screen');
  const ctx = canvas.getContext('2d', { alpha: false, desynchronized: true });
  let current = null;
  let reconnectTimer = null;

  /** "123 456 789" -> same-origin server; share code / trycloudflare link -> that host's built-in relay. */
  function parseTarget(raw) {
    const s = raw.trim();
    const digits = s.replace(/[\s-]/g, '');
    if (/^\d{9,}$/.test(digits)) return { id: digits, label: fmtId(digits) };
    const m = /^(?:https?:\/\/)?([a-z0-9-]+)\.trycloudflare\.com\/?(?:#id=(\d+))?/i.exec(s);
    const code = m ? m[1].toLowerCase() : /^[a-z0-9]+(-[a-z0-9]+)+$/i.test(s) ? s.toLowerCase() : null;
    if (!code) return null;
    return { id: (m && m[2]) || '', label: code, ws: `wss://${code}.trycloudflare.com/ws` };
  }

  class Session {
    constructor(target, password, name, carry = {}) {
      this.target = target; this.id = target.id; this.password = password; this.name = name;
      this.token = carry.token || null;
      this.attempt = carry.attempt || 0;
      this.settings = carry.settings || { quality: 60, scale: 1, fps: 30, monitor: 1, codec: 'auto' };
      this.ch = null; this.candidates = null;
      this.rxChain = Promise.resolve(); this.txChain = Promise.resolve(); this.keyChain = Promise.resolve();
      this.active = false; this.viewOnly = false; this.perms = {};
      this.stats = { frames: 0, bytes: 0 };
      this.host = {};
      this.keysDown = new Set();
      this.wheel = { x: 0, y: 0 };
      this.fileId = 1; this.downloads = new Map(); this.uploads = new Map();
      this.fsPath = null; this.fsParent = null; this.fsHome = null;
      this.lastLocalClip = null; this.remoteClip = '';
      this.closedByUser = false; this.fatal = false;
      this.decoder = null; this.decoderCodec = null; this.pendingAcks = []; this.keyRequested = 0;
      this.cursor = null; this.lastLocalInput = 0;
    }

    start() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = this.ws = new WebSocket(this.target.ws || `${proto}//${location.host}/ws`);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => ws.send(JSON.stringify({ t: 'connect', id: this.id }));
      ws.onmessage = (ev) => {
        this.rxChain = this.rxChain.then(() => this.onMessage(ev.data))
          .catch((e) => this.fail('Secure channel error: ' + e.message));
      };
      ws.onclose = () => this.onClose();
      ws.onerror = () => {};
    }

    async onMessage(data) {
      if (typeof data === 'string') return this.onText(JSON.parse(data));
      if (this.ch) return this.onPlain(await this.ch.open(data));
      if (!this.candidates) return;
      for (const c of this.candidates) {
        try { const pt = await c.open(data); this.ch = c; this.candidates = null; return this.onPlain(pt); } catch { /* next */ }
      }
      throw new Error('could not verify host');
    }

    async onText(m) {
      switch (m.t) {
        case 'waiting': return status('Waiting for the remote computer...');
        case 'paired': return status('Securing connection...');
        case 'hello': return this.handshake(m);
        case 'auth_failed': this.fatal = true; return this.fail('Wrong password.');
        case 'error': return this.fail(m.msg || 'Error');
      }
    }

    async handshake(m) {
      const hostPub = b64d(m.pub);
      const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      const myPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
      const hostKey = await crypto.subtle.importKey('raw', hostPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: hostKey }, kp.privateKey, 256));
      this.ws.send(JSON.stringify({ t: 'hello', v: 1, pub: b64e(myPub) }));
      this.hostName = String(m.name || 'remote');
      status('Verifying password...');
      const auth = concat([K_JSON], te.encode(JSON.stringify({
        t: 'auth', name: this.name, codecs: await supportedCodecs(), token: this.token,
      })));
      const candidates = [];
      for (const salt of m.salts.map(b64d)) {
        const ch = await Channel.create(shared, await passwordKey(this.password, salt), hostPub, myPub);
        candidates.push(ch);
        this.ws.send(await ch.seal(auth));
      }
      this.candidates = candidates;
      if (!this.token) status('Waiting for the remote user to accept...');
    }

    // --------------------------------------------------------- sending
    sendPlain(pt) {
      this.txChain = this.txChain.then(async () => {
        const f = await this.ch.seal(pt);
        if (this.ws.readyState === WebSocket.OPEN) this.ws.send(f);
      });
      return this.txChain;
    }
    send(obj) { if (this.ch) return this.sendPlain(concat([K_JSON], te.encode(JSON.stringify(obj)))); }
    async drain() {
      await this.txChain;
      while (this.ws.readyState === WebSocket.OPEN && this.ws.bufferedAmount > 4 * CHUNK) await sleep(15);
    }
    key(down, code, key) {
      this.keyChain = this.keyChain.then(() => this.send({ t: down ? 'kd' : 'ku', code, key }));
    }
    sendSettings() { this.send({ t: 'settings', ...this.settings }); }

    // ------------------------------------------------------- receiving
    async onPlain(pt) {
      const kind = pt[0], body = pt.subarray(1);
      if (kind === K_JSON) return this.onJson(JSON.parse(td.decode(body)));
      if (kind === K_VIDEO) return this.decodeVideo(body);
      if (kind === K_FRAME) return this.drawFrame(body);
      if (kind === K_FILE) return this.onFileChunk(body);
    }

    onJson(m) {
      switch (m.t) {
        case 'welcome': return this.onWelcome(m);
        case 'token': this.token = m.v; return;
        case 'denied': this.fatal = true; return this.fail('The remote user declined the connection.');
        case 'screen': return this.onScreen(m);
        case 'hstats': this.host = m; return;
        case 'cur': this.cursor = m; return placeCursor();
        case 'clip': return this.onRemoteClip(m.s);
        case 'chat': return chatLine(this.hostName, m.s, false);
        case 'ls': return this.onListing(m);
        case 'ls_err': return toast(m.msg);
        case 'fprep': { const d = this.downloads.get(m.id); if (d) d.label.textContent = `⏳ Compressing ${d.name}…`; return; }
        case 'fstart': { const d = this.downloads.get(m.id); if (d) { d.size = m.size; d.name = m.name; d.label.textContent = `↓ ${m.name}`; } return; }
        case 'fend': return this.finishDownload(m.id);
        case 'ferr': return this.failTransfer(this.downloads, m.id, m.msg);
        case 'pdone': {
          const u = this.uploads.get(m.id);
          if (u) { u.label.textContent = `✓ ${u.name} → ${m.path}`; u.bar.remove(); this.uploads.delete(m.id); }
          if (this.fsPath !== null) this.ls(this.fsPath);
          return;
        }
        case 'perr': return this.failTransfer(this.uploads, m.id, m.msg);
      }
    }

    onWelcome(m) {
      this.active = true;
      this.attempt = 0;
      this.perms = m.perms || {};
      $('peer-name').textContent = `${m.name} · ${this.target.label} · end-to-end encrypted`;
      $('btn-files').disabled = !this.perms.files;
      $('btn-clip').disabled = !this.perms.clipboard;
      $('chk-viewonly').checked = this.viewOnly = !this.perms.input || $('chk-viewonly').checked && $('chk-viewonly').dataset.user === '1';
      $('chk-viewonly').disabled = !this.perms.input;
      const h264 = !!m.encoder && h264Support;
      $('sel-codec').querySelector('[value=h264]').disabled = !h264;
      $('sel-codec').value = h264 ? this.settings.codec : 'jpeg';
      this.fillMonitors(m.monitors, this.settings.monitor);
      saveRecent(this.target.ws ? this.target.label : this.id, m.name);
      showSession();
      overlay(null);
      this.sendSettings();
      this.statsTimer = setInterval(() => this.showStats(), 1000);
      canvas.focus();
    }

    fillMonitors(mons, sel) {
      const s = $('sel-monitor');
      s.replaceChildren(...(mons || []).map((mo) => {
        const o = el('option', null, `${mo.label} (${mo.w}×${mo.h})`); o.value = mo.i; return o;
      }));
      s.value = sel;
      s.classList.toggle('hidden', (mons || []).length <= 2);
    }

    onScreen(m) {
      if (canvas.width !== m.w || canvas.height !== m.h) { canvas.width = m.w; canvas.height = m.h; }
      this.settings.monitor = m.monitor;
      this.host.codec = m.codec; this.host.encoder = m.encoder; this.host.capture = m.capture;
      if (m.codec !== 'h264') this.resetDecoder();
      this.fillMonitors(m.monitors, m.monitor);
      layout();
    }

    // ------------------------------------------------- video: H.264
    resetDecoder() {
      if (this.decoder && this.decoder.state !== 'closed') { try { this.decoder.close(); } catch { /* ignore */ } }
      this.decoder = null; this.decoderCodec = null;
      for (const f of this.pendingAcks.splice(0)) this.send({ t: 'ack', f });
    }
    requestKey() {
      const now = performance.now();
      if (now - this.keyRequested > 1000) { this.keyRequested = now; this.send({ t: 'key' }); }
    }
    decodeVideo(body) {
      const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
      const frameNo = dv.getUint32(0), isKey = (dv.getUint8(4) & 1) === 1;
      const data = body.subarray(5);
      this.stats.bytes += body.length;
      if (isKey) {
        const codec = avcCodec(data);
        if (!this.decoder || this.decoder.state === 'closed' || codec !== this.decoderCodec) {
          this.resetDecoder();
          this.decoder = new VideoDecoder({
            output: (frame) => {
              ctx.drawImage(frame, 0, 0);
              frame.close();
              this.stats.frames++;
              const f = this.pendingAcks.shift();
              if (f !== undefined) this.send({ t: 'ack', f });
            },
            error: (e) => { console.warn('decoder error', e); this.resetDecoder(); this.requestKey(); },
          });
          this.decoder.configure({ codec, optimizeForLatency: true });
          this.decoderCodec = codec;
        }
      }
      if (!this.decoder || this.decoder.state !== 'configured') {
        this.send({ t: 'ack', f: frameNo }); // keep the host's window moving while we wait for a keyframe
        return this.requestKey();
      }
      this.pendingAcks.push(frameNo);
      this.decoder.decode(new EncodedVideoChunk({ type: isKey ? 'key' : 'delta', timestamp: frameNo * 1000, data }));
    }

    // ------------------------------------------------ video: JPEG tiles
    async drawFrame(body) {
      const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
      const frameNo = dv.getUint32(0), n = dv.getUint16(4);
      let off = 6;
      const rects = [];
      for (let i = 0; i < n; i++) {
        const x = dv.getUint16(off), y = dv.getUint16(off + 2), len = dv.getUint32(off + 9);
        off += 13;
        rects.push({ x, y, data: body.subarray(off, off + len) });
        off += len;
      }
      const bitmaps = await Promise.all(rects.map((r) => createImageBitmap(new Blob([r.data], { type: 'image/jpeg' }))));
      bitmaps.forEach((b, i) => { ctx.drawImage(b, rects[i].x, rects[i].y); b.close(); });
      this.stats.frames++; this.stats.bytes += body.length;
      this.send({ t: 'ack', f: frameNo });
    }

    showStats() {
      const { frames } = this.stats;
      const h = this.host;
      const codec = h.codec === 'h264' ? `H.264 (${(h.encoder || '').replace(/^h264_|^lib/, '')})` : 'JPEG';
      const parts = [codec, `${canvas.width}×${canvas.height}`, `${frames} fps`];
      if (h.kbps !== undefined) parts.push(fmtRate(h.kbps));
      if (h.rtt) parts.push(`${h.rtt} ms`);
      $('stats').textContent = parts.join(' · ');
      $('stats').title = `capture: ${h.capture || '?'}` + (h.bitrate ? ` · target ${fmtRate(Math.round(h.bitrate / 1000))}` : '');
      this.stats = { frames: 0, bytes: 0 };
    }

    // ------------------------------------------------------- clipboard
    onRemoteClip(s) {
      this.remoteClip = s;
      $('clip-remote').value = s;
      if ($('chk-autoclip').checked && navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(s).then(() => { this.lastLocalClip = s; }, () => {});
      }
    }
    async syncLocalClipboard() {
      if (!this.perms.clipboard || !$('chk-autoclip').checked || !navigator.clipboard?.readText) return;
      try {
        const s = await navigator.clipboard.readText();
        if (s && s !== this.lastLocalClip && s !== this.remoteClip) {
          this.lastLocalClip = s;
          await this.send({ t: 'clip', s });
        }
      } catch { /* permission denied - user can use the panel */ }
    }

    // ----------------------------------------------------------- files
    ls(path) { this.send({ t: 'ls', path }); }
    onListing(m) {
      this.fsPath = m.path; this.fsParent = m.parent; this.fsHome = m.home;
      $('fs-path').value = m.path || '(drives)';
      $('fs-up').disabled = m.parent === null || m.parent === undefined;
      const list = $('fs-list');
      list.replaceChildren(...m.entries.map((e) => {
        const li = el('li', e.d ? 'dir' : 'file');
        li.append(el('span', 'name', e.n), el('span', 'size', e.d ? '' : fmtSize(e.s)));
        if (e.d && m.path) {
          const z = el('button', 'zip', '⬇ zip');
          z.title = 'Download folder as .zip';
          z.onclick = (ev) => { ev.stopPropagation(); this.download(e.p, e.n + '.zip', 0); };
          li.append(z);
        }
        li.title = e.d ? 'Open folder' : 'Download';
        li.onclick = () => (e.d ? this.ls(e.p) : this.download(e.p, e.n, e.s));
        return li;
      }));
    }
    transferRow(text) {
      const li = el('li'); const label = el('div', null, text); const bar = el('progress');
      bar.max = 1; bar.value = 0; li.append(label, bar); $('transfers').prepend(li);
      return { label, bar };
    }
    async download(path, name, size) {
      // Stream straight to disk when the browser allows it (no RAM limit for big files).
      let writable = null;
      if (window.showSaveFilePicker) {
        try {
          writable = await (await window.showSaveFilePicker({ suggestedName: name })).createWritable();
        } catch (e) {
          if (e.name === 'AbortError') return;
        }
      }
      const id = this.fileId++;
      const row = this.transferRow(`↓ ${name}`);
      this.downloads.set(id, { name, size, got: 0, chunks: [], writable, wchain: Promise.resolve(), ...row });
      this.send({ t: 'get', id, path });
    }
    onFileChunk(body) {
      const id = new DataView(body.buffer, body.byteOffset, 4).getUint32(0);
      const d = this.downloads.get(id);
      if (!d) return;
      const chunk = body.slice(4);
      if (d.writable) d.wchain = d.wchain.then(() => d.writable.write(chunk));
      else d.chunks.push(chunk);
      d.got += chunk.length;
      d.bar.value = d.size ? d.got / d.size : 0;
    }
    async finishDownload(id) {
      const d = this.downloads.get(id);
      if (!d) return;
      this.downloads.delete(id);
      if (d.writable) { await d.wchain; await d.writable.close(); } else saveBlob(new Blob(d.chunks), d.name);
      d.label.textContent = `✓ ${d.name} (${fmtSize(d.got)})`; d.bar.remove();
    }
    failTransfer(map, id, msg) {
      const t = map.get(id);
      if (t) {
        t.label.textContent = `✗ ${t.name}: ${msg}`; t.bar.remove(); map.delete(id);
        if (t.writable) t.writable.abort().catch(() => {});
      }
    }
    async upload(fileList, dir) {
      for (const file of fileList) {
        const id = this.fileId++;
        const row = this.transferRow(`↑ ${file.name}`);
        this.uploads.set(id, { name: file.name, ...row });
        await this.send({ t: 'put', id, name: file.name, size: file.size, dir: dir || '' });
        const hdr = concat([K_FILE], u32(id));
        for (let o = 0; o < file.size; o += CHUNK) {
          if (!this.uploads.has(id) || this.ws.readyState !== WebSocket.OPEN) break;
          const buf = new Uint8Array(await file.slice(o, o + CHUNK).arrayBuffer());
          await this.sendPlain(concat(hdr, buf));
          await this.drain();
          row.bar.value = (o + buf.length) / file.size;
        }
        if (this.uploads.has(id)) await this.send({ t: 'pend', id });
      }
    }

    // ------------------------------------------------------------ end
    fail(msg) {
      this.error = msg;
      try { this.ws.close(); } catch { /* ignore */ }
    }
    onClose() {
      clearInterval(this.statsTimer);
      this.resetDecoder();
      const wasActive = this.active;
      this.active = false;
      if (current !== this) return;
      const retry = !this.closedByUser && !this.fatal && (wasActive || this.attempt > 0) && this.attempt < MAX_RECONNECTS;
      if (retry) return scheduleReconnect(this);
      current = null;
      stopRecording();
      overlay(null);
      showHome();
      status(this.error || (this.closedByUser ? 'Disconnected.' : wasActive ? 'The session ended.' : 'Connection closed.'), !!this.error);
    }
  }

  function scheduleReconnect(old) {
    const attempt = old.attempt + 1;
    const delay = Math.min(1000 * 2 ** (attempt - 1), 8000);
    overlay(`Connection lost — reconnecting (${attempt}/${MAX_RECONNECTS})…`);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      current = new Session(old.target, old.password, old.name, { token: old.token, settings: old.settings, attempt });
      current.start();
    }, delay);
  }

  // ----------------------------------------------------------- UI glue
  function status(text, err) {
    if (current && current.attempt > 0) return overlay(`Reconnecting… ${text}`);
    const s = $('home-status'); s.textContent = text; s.classList.toggle('err', !!err);
  }
  function overlay(text) {
    const o = $('overlay'); o.classList.toggle('hidden', !text); if (text) o.textContent = text;
  }
  let toastTimer;
  function toast(text) {
    const t = $('toast'); t.textContent = text; t.classList.remove('hidden');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
  }
  function showSession() { $('home').classList.add('hidden'); $('session').classList.remove('hidden'); layout(); }
  function showHome() {
    $('session').classList.add('hidden'); $('home').classList.remove('hidden');
    for (const p of document.querySelectorAll('.panel')) p.classList.add('hidden');
    $('connect-btn').disabled = false;
    $('rcursor').classList.add('hidden');
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  }
  function layout() {
    const st = $('stage');
    if (!canvas.width) return;
    const k = Math.min(st.clientWidth / canvas.width, st.clientHeight / canvas.height);
    canvas.style.width = Math.floor(canvas.width * k) + 'px';
    canvas.style.height = Math.floor(canvas.height * k) + 'px';
    placeCursor();
  }
  window.addEventListener('resize', layout);

  /** Show the host's cursor when the remote user moves it, or when we're only watching. */
  function placeCursor() {
    const c = $('rcursor');
    const s = current;
    if (!s || !s.cursor || !s.active) return c.classList.add('hidden');
    const idle = performance.now() - s.lastLocalInput > 1500;
    const inside = s.cursor.x >= 0 && s.cursor.y >= 0 && s.cursor.x <= 1 && s.cursor.y <= 1;
    if (!inside || !(s.viewOnly || idle)) return c.classList.add('hidden');
    const r = canvas.getBoundingClientRect(), st = $('stage').getBoundingClientRect();
    c.style.left = (r.left - st.left + s.cursor.x * r.width) + 'px';
    c.style.top = (r.top - st.top + s.cursor.y * r.height) + 'px';
    c.classList.remove('hidden');
  }

  function chatLine(who, text, me) {
    const d = el('div'); const w = el('b', me ? 'me' : null, who + ': ');
    d.append(w, document.createTextNode(text)); $('chat-log').append(d);
    $('chat-log').scrollTop = 1e9;
    if (!me && $('panel-chat').classList.contains('hidden')) { $('chat-badge').classList.remove('hidden'); toast(`${who}: ${text}`); }
  }

  function loadRecent() { try { return JSON.parse(localStorage.getItem('anidesk.recent')) || []; } catch { return []; } }
  function saveRecent(id, name) {
    const list = [{ id, name }, ...loadRecent().filter((r) => r.id !== id)].slice(0, 6);
    localStorage.setItem('anidesk.recent', JSON.stringify(list));
  }
  function renderRecent() {
    $('recent').replaceChildren(...loadRecent().map((r) => {
      const shown = /^\d+$/.test(r.id) ? fmtId(r.id) : r.id;
      const li = el('li'); li.append(el('span', null, shown), el('span', null, r.name || ''));
      li.onclick = () => { $('remote-id').value = shown; $('remote-pw').focus(); };
      return li;
    }));
  }

  // ---------------------------------------------------- connect form
  $('viewer-name').value = localStorage.getItem('anidesk.name') || '';
  const params = new URLSearchParams(location.hash.slice(1));
  if (params.get('id')) $('remote-id').value = fmtId(params.get('id'));
  renderRecent();

  $('connect-form').addEventListener('submit', (e) => {
    e.preventDefault();
    if (!window.isSecureContext || !crypto.subtle) {
      status('Encryption needs a secure page. Open this viewer via https:// (start the server with ' +
        '--https-port 8443) or via http://localhost.', true);
      return;
    }
    const target = parseTarget($('remote-id').value);
    if (!target) return status('Enter the 9-digit ID, or the share code / link from the other computer.', true);
    const name = $('viewer-name').value.trim() || 'Web viewer';
    localStorage.setItem('anidesk.name', $('viewer-name').value.trim());
    $('connect-btn').disabled = true;
    status('Connecting...');
    // The password stays in memory for this tab only, so a dropped session can reconnect.
    current = new Session(target, $('remote-pw').value, name);
    $('remote-pw').value = '';
    current.start();
  });

  // ------------------------------------------------------------ input
  const live = () => current && current.active;
  const canControl = () => live() && !current.viewOnly;
  const touched = () => { if (current) current.lastLocalInput = performance.now(); $('rcursor').classList.add('hidden'); };
  function posOf(clientX, clientY) {
    const r = canvas.getBoundingClientRect();
    return { x: (clientX - r.left) / r.width, y: (clientY - r.top) / r.height };
  }
  const pos = (e) => posOf(e.clientX, e.clientY);
  let pendingMove = null;
  function queueMove(p) {
    const first = !pendingMove;
    pendingMove = p;
    if (first) requestAnimationFrame(() => { if (pendingMove && current) current.send({ t: 'mm', ...pendingMove }); pendingMove = null; });
  }
  canvas.addEventListener('pointermove', (e) => {
    if (e.pointerType === 'touch' || !canControl()) return;
    touched();
    queueMove(pos(e));
  });
  canvas.addEventListener('pointerdown', (e) => {
    canvas.focus();
    if (e.pointerType === 'touch' || !canControl()) return;
    e.preventDefault();
    touched();
    canvas.setPointerCapture(e.pointerId);
    current.send({ t: 'md', b: e.button, ...pos(e) });
  });
  canvas.addEventListener('pointerup', (e) => {
    if (e.pointerType === 'touch' || !canControl()) return;
    e.preventDefault();
    current.send({ t: 'mu', b: e.button, ...pos(e) });
  });
  canvas.addEventListener('contextmenu', (e) => e.preventDefault());
  canvas.addEventListener('wheel', (e) => {
    if (!canControl()) return;
    e.preventDefault();
    const k = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 800 : 1;
    const w = current.wheel;
    w.x += e.deltaX * k; w.y += e.deltaY * k;
    const sx = Math.trunc(w.x / 100), sy = Math.trunc(w.y / 100);
    if (sx || sy) { w.x -= sx * 100; w.y -= sy * 100; current.send({ t: 'wh', dx: sx, dy: -sy }); }
  }, { passive: false });

  // Touch: tap = click, long-press = right click, drag = left-drag, two fingers = scroll.
  const touch = { start: null, last: null, dragging: false, long: null, longFired: false, two: null };
  const tpos = (t) => posOf(t.clientX, t.clientY);
  canvas.addEventListener('touchstart', (e) => {
    if (!canControl()) return;
    e.preventDefault();
    touched();
    clearTimeout(touch.long);
    if (e.touches.length >= 2) {
      if (touch.dragging) current.send({ t: 'mu', b: 0, ...touch.last });
      touch.dragging = false; touch.start = null;
      touch.two = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      return;
    }
    const p = tpos(e.touches[0]);
    Object.assign(touch, { start: p, last: p, dragging: false, longFired: false, two: null });
    current.send({ t: 'mm', ...p });
    touch.long = setTimeout(() => {
      if (!touch.dragging && touch.start) {
        touch.longFired = true;
        current.send({ t: 'md', b: 2, ...touch.start }); current.send({ t: 'mu', b: 2, ...touch.start });
      }
    }, 600);
  }, { passive: false });
  canvas.addEventListener('touchmove', (e) => {
    if (!canControl()) return;
    e.preventDefault();
    if (touch.two !== null && e.touches.length >= 2) {
      const y = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      const steps = Math.trunc((y - touch.two) / 30);
      if (steps) { touch.two += steps * 30; current.send({ t: 'wh', dx: 0, dy: steps }); }
      return;
    }
    if (!touch.start) return;
    const p = tpos(e.touches[0]);
    const r = canvas.getBoundingClientRect();
    if (!touch.dragging && Math.hypot((p.x - touch.start.x) * r.width, (p.y - touch.start.y) * r.height) > 10) {
      clearTimeout(touch.long);
      touch.dragging = true;
      current.send({ t: 'md', b: 0, ...touch.start });
    }
    touch.last = p;
    if (touch.dragging) queueMove(p);
  }, { passive: false });
  canvas.addEventListener('touchend', (e) => {
    if (!canControl()) return;
    e.preventDefault();
    clearTimeout(touch.long);
    if (e.touches.length) return;
    if (touch.dragging) current.send({ t: 'mu', b: 0, ...touch.last });
    else if (touch.start && !touch.longFired && touch.two === null) {
      current.send({ t: 'md', b: 0, ...touch.start }); current.send({ t: 'mu', b: 0, ...touch.start });
    }
    Object.assign(touch, { start: null, dragging: false, two: null });
  }, { passive: false });

  const typingInUi = (e) => e.target instanceof HTMLElement && e.target !== canvas &&
    ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName);
  window.addEventListener('keydown', (e) => {
    if (!canControl() || typingInUi(e)) return;
    e.preventDefault();
    touched();
    current.keysDown.add(e.code);
    if ((e.ctrlKey || e.metaKey) && e.code === 'KeyV') {
      const s = current;
      s.keyChain = s.keyChain.then(() => s.syncLocalClipboard());
    }
    current.key(true, e.code, e.key);
  });
  window.addEventListener('keyup', (e) => {
    if (!canControl() || !current.keysDown.has(e.code)) return;
    e.preventDefault();
    current.keysDown.delete(e.code);
    current.key(false, e.code, e.key);
  });
  window.addEventListener('blur', () => {
    if (live() && current.keysDown.size) { current.keysDown.clear(); current.send({ t: 'kreset' }); }
  });
  window.addEventListener('focus', () => { if (live()) current.syncLocalClipboard(); });

  // On-screen keyboard (phones/tablets): a hidden textarea receives the typed text.
  const kbd = $('kbd');
  const tap = (code, key) => { current.key(true, code, key); current.key(false, code, key); };
  kbd.addEventListener('beforeinput', (e) => {
    if (!canControl()) return;
    if (e.inputType === 'deleteContentBackward') { e.preventDefault(); tap('Backspace', 'Backspace'); }
    else if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') { e.preventDefault(); tap('Enter', 'Enter'); }
  });
  kbd.addEventListener('input', () => {
    if (kbd.value && canControl()) current.send({ t: 'text', s: kbd.value });
    kbd.value = '';
  });
  kbd.addEventListener('keydown', (e) => {
    if (!canControl()) return;
    const special = { Backspace: 1, Enter: 1, Tab: 1, Escape: 1, ArrowUp: 1, ArrowDown: 1, ArrowLeft: 1, ArrowRight: 1, Delete: 1 };
    if (special[e.key]) { e.preventDefault(); tap(e.code || e.key, e.key); }
  });
  $('btn-kbd').addEventListener('click', () => { kbd.focus(); });

  // ---------------------------------------------------------- toolbar
  const setting = (key, id, parse = Number) => $(id).addEventListener('change', () => {
    if (!live()) return;
    current.settings[key] = parse($(id).value);
    current.sendSettings();
    canvas.focus();
  });
  setting('quality', 'sel-quality');
  setting('scale', 'sel-scale');
  setting('fps', 'sel-fps');
  setting('monitor', 'sel-monitor');
  setting('codec', 'sel-codec', String);
  $('sel-keys').addEventListener('change', () => {
    const v = $('sel-keys').value; $('sel-keys').value = '';
    if (!v || !canControl()) return;
    const codes = v.split('+');
    for (const c of codes) current.key(true, c, codeToKey(c));
    for (const c of codes.reverse()) current.key(false, c, codeToKey(c));
    canvas.focus();
  });
  $('chk-viewonly').addEventListener('change', () => {
    $('chk-viewonly').dataset.user = $('chk-viewonly').checked ? '1' : '';
    if (current) { current.viewOnly = $('chk-viewonly').checked; placeCursor(); }
  });
  $('btn-disconnect').addEventListener('click', () => {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; const s = current; current = null; overlay(null); showHome(); status('Disconnected.'); stopRecording(); if (s) s.closedByUser = true; return; }
    if (current) { current.closedByUser = true; current.ws.close(); }
  });
  $('btn-full').addEventListener('click', async () => {
    if (document.fullscreenElement) return document.exitFullscreen();
    await $('session').requestFullscreen().catch(() => {});
    // In Chromium this lets Win/Alt+Tab/Esc reach the remote computer while fullscreen.
    navigator.keyboard?.lock?.().catch(() => {});
  });
  document.addEventListener('fullscreenchange', () => setTimeout(layout, 50));

  $('btn-shot').addEventListener('click', () => {
    if (!canvas.width) return;
    canvas.toBlob((b) => b && saveBlob(b, `anidesk-${current ? current.id : 'screen'}-${stamp()}.png`), 'image/png');
  });

  let recorder = null;
  function stopRecording() { if (recorder && recorder.state !== 'inactive') recorder.stop(); }
  $('btn-rec').addEventListener('click', () => {
    if (recorder && recorder.state !== 'inactive') return stopRecording();
    if (!window.MediaRecorder || !canvas.captureStream) return toast('Recording is not supported in this browser.');
    const type = ['video/webm;codecs=vp9', 'video/webm;codecs=vp8', 'video/webm', 'video/mp4']
      .find((t) => MediaRecorder.isTypeSupported(t));
    const chunks = [];
    recorder = new MediaRecorder(canvas.captureStream(30), { mimeType: type, videoBitsPerSecond: 6_000_000 });
    recorder.ondataavailable = (e) => e.data.size && chunks.push(e.data);
    recorder.onstop = () => {
      $('btn-rec').classList.remove('on'); $('btn-rec').textContent = '⏺ Rec';
      saveBlob(new Blob(chunks, { type }), `anidesk-${current ? current.id : 'session'}-${stamp()}.${type.includes('mp4') ? 'mp4' : 'webm'}`);
    };
    recorder.start(1000);
    $('btn-rec').classList.add('on'); $('btn-rec').textContent = '⏹ Stop';
    toast('Recording… press Stop to save the video.');
  });

  function togglePanel(id) {
    for (const p of document.querySelectorAll('.panel')) if (p.id !== id) p.classList.add('hidden');
    const p = $(id); p.classList.toggle('hidden');
    return !p.classList.contains('hidden');
  }
  for (const b of document.querySelectorAll('[data-close]')) b.addEventListener('click', () => { $(b.dataset.close).classList.add('hidden'); canvas.focus(); });
  $('btn-files').addEventListener('click', () => { if (togglePanel('panel-files') && current.fsPath === null) current.ls('~'); });
  $('btn-clip').addEventListener('click', () => togglePanel('panel-clip'));
  $('btn-chat').addEventListener('click', () => { if (togglePanel('panel-chat')) { $('chat-badge').classList.add('hidden'); $('chat-input').focus(); } });

  $('fs-up').addEventListener('click', () => { if (current.fsParent !== null) current.ls(current.fsParent); });
  $('fs-home').addEventListener('click', () => current.ls('~'));
  $('fs-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') current.ls($('fs-path').value); });
  $('fs-upload').addEventListener('change', (e) => { current.upload([...e.target.files], current.fsPath); e.target.value = ''; });
  const dz = $('dropzone');
  for (const target of [dz, $('stage')]) {
    target.addEventListener('dragover', (e) => { if (live() && current.perms.files) { e.preventDefault(); dz.classList.add('over'); } });
    target.addEventListener('dragleave', () => dz.classList.remove('over'));
    target.addEventListener('drop', (e) => {
      e.preventDefault(); dz.classList.remove('over');
      if (!live() || !current.perms.files) return;
      if ($('panel-files').classList.contains('hidden')) togglePanel('panel-files');
      current.upload([...e.dataTransfer.files], target === dz ? current.fsPath : '');
    });
  }

  $('clip-copy-local').addEventListener('click', () => navigator.clipboard?.writeText($('clip-remote').value).then(() => toast('Copied.'), () => toast('Browser blocked clipboard access.')));
  $('clip-send').addEventListener('click', () => { const s = $('clip-local').value; if (s) { current.send({ t: 'clip', s }); current.lastLocalClip = s; toast('Remote clipboard set.'); } });
  $('clip-type').addEventListener('click', () => { const s = $('clip-local').value; if (s && canControl()) current.send({ t: 'text', s }); });

  $('chat-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const s = $('chat-input').value.trim();
    if (!s || !live()) return;
    $('chat-input').value = '';
    current.send({ t: 'chat', s });
    chatLine('You', s, true);
  });

  // Pause decoding work while the tab is hidden; the host's window stalls and resyncs with a keyframe.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && live() && current.host.codec === 'h264') current.requestKey();
  });
})();
