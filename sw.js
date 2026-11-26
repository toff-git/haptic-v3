// Dekrypterer den krypterte Haptic-siden i nettleseren. Nøkkelen får den fra den passordlåste inngangen.
// Uten nøkkel slipper den alt rett gjennom, slik at innloggingssiden vises.
const BASE = '/haptic-v3/';
const LEVETID = 30 * 864e5; // nøkkelen huskes i 30 dager på denne maskinen
let tilstand = null, laster = null;
const lager = new Map(); // dekrypterte store filer (film), for spoling

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function db(modus, fn) {
  return new Promise((ok, feil) => {
    const r = indexedDB.open('haptic', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('n');
    r.onerror = () => feil(r.error);
    r.onsuccess = () => {
      const tx = r.result.transaction('n', modus);
      const q = fn(tx.objectStore('n'));
      tx.oncomplete = () => ok(q && q.result);
      tx.onerror = () => feil(tx.error);
    };
  });
}

async function dekrypter(key, buf) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12) }, key, new Uint8Array(buf, 12));
}

async function settNokkel(raw, versjon, tid) {
  const bytes = Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt']);
  const r = await fetch(BASE + 'm/' + versjon, { cache: 'no-cache' });
  if (!r.ok) throw new Error('kart ' + r.status);
  const kart = JSON.parse(new TextDecoder().decode(await dekrypter(key, await r.arrayBuffer())));
  tilstand = { key, kart };
  lager.clear();
  await db('readwrite', (s) => s.put({ raw, versjon, tid: tid || Date.now() }, 'k'));
}

async function hentTilstand() {
  if (tilstand) return tilstand;
  if (!laster) {
    laster = (async () => {
      try {
        const v = await db('readonly', (s) => s.get('k'));
        if (v && Date.now() - v.tid < LEVETID) await settNokkel(v.raw, v.versjon, v.tid);
        else if (v) await db('readwrite', (s) => s.delete('k'));
      } catch (e) {
        // gammel nøkkel (siden er publisert på nytt) eller ødelagt lager: glem den, vis innlogging
        tilstand = null;
        try { await db('readwrite', (s) => s.delete('k')); } catch (_) {}
      }
      return tilstand;
    })().finally(() => { laster = null; });
  }
  return laster;
}

self.addEventListener('message', (e) => {
  const d = e.data || {};
  const port = e.ports && e.ports[0];
  if (d.k) {
    e.waitUntil(settNokkel(d.k, d.v).then(
      () => port && port.postMessage('ok'),
      (err) => port && port.postMessage('feil: ' + err.message)));
  }
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);
  if (u.origin !== location.origin || !u.pathname.startsWith(BASE)) return;
  let rel;
  try { rel = decodeURIComponent(u.pathname.slice(BASE.length)); } catch (_) { return; }
  if (rel.startsWith('m/') || rel === 'sw.js' || rel === 'robots.txt') return;
  e.respondWith(svar(req, u, rel));
});

async function svar(req, u, rel) {
  const t = await hentTilstand();
  if (!t) return fetch(req);
  let treff = null, nokkel = null;
  if (rel === '' || rel.endsWith('/')) { nokkel = rel + 'index.html'; treff = t.kart[nokkel]; }
  if (!treff && t.kart[rel]) { nokkel = rel; treff = t.kart[rel]; }
  if (!treff && t.kart[rel + '/index.html']) {
    // mappe uten skråstrek: send videre med skråstrek så relative lenker stemmer
    return Response.redirect(u.origin + u.pathname + '/' + u.search + u.hash, 301);
  }
  if (!treff) return fetch(req);
  const [navn, type] = treff;
  let buf = lager.get(navn);
  if (!buf) {
    const r = await fetch(BASE + 'm/' + navn);
    if (!r.ok) return new Response('', { status: r.status });
    buf = await dekrypter(t.key, await r.arrayBuffer());
    if (buf.byteLength > 2e6) {
      lager.set(navn, buf);
      if (lager.size > 6) lager.delete(lager.keys().next().value);
    }
  }
  const hoder = { 'Content-Type': type, 'Accept-Ranges': 'bytes' };
  if (type.startsWith('text/html')) hoder['Cache-Control'] = 'no-store';
  const range = req.headers.get('range');
  const m = range && /bytes=(\d*)-(\d*)/.exec(range);
  if (m) {
    const n = buf.byteLength;
    let a = m[1] ? +m[1] : 0, b = m[2] ? +m[2] : n - 1;
    if (!m[1] && m[2]) { a = Math.max(0, n - +m[2]); b = n - 1; }
    b = Math.min(b, n - 1);
    if (a > b) return new Response('', { status: 416, headers: { 'Content-Range': `bytes */${n}` } });
    return new Response(buf.slice(a, b + 1), { status: 206, headers: {
      ...hoder, 'Content-Range': `bytes ${a}-${b}/${n}`, 'Content-Length': String(b - a + 1) } });
  }
  return new Response(buf, { headers: { ...hoder, 'Content-Length': String(buf.byteLength) } });
}
