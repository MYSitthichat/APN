/**
 * RelayVPN Zero-VPS Rendezvous Directory — Free Cloudflare Worker (0 baht/month!)
 * Optimized for Cloudflare Free Tier (100,000 Worker req/day, 1,000 KV writes/day).
 *
 * Setup:
 *   1. Create KV Namespace (e.g. RELAYVPN_PEERS) and bind it to this Worker as variable "PEERS".
 *   2. Attach your custom domain (e.g. rdv.yourdomain.com) under Settings -> Domains & Routes.
 *   3. Build RelayVPN with: .\scripts\build-all.ps1 -RendezvousURL "https://rdv.yourdomain.com"
 */

const memStore = new Map();
const regStore = new Map();     // last entry this isolate wrote per device (register path only)
const offlineStore = new Map(); // device id -> expiry ms of a cached "offline" presence answer
const PUNCH_TTL_SECONDS = 60;   // KV minimum TTL; punch requests are only useful for seconds
const MAX_PUNCHES = 5;
const TTL_SECONDS = 300;        // 5 minutes TTL (peers heartbeat every ~30s)
const PRESENCE_CACHE_MS = 15_000;
const KV_REFRESH_MS = 180_000;  // Skip redundant KV writes when endpoints haven't changed within 3 minutes
const GITHUB_REPO = 'MYSitthichat/APN';

// Signed registration (same format as internal/rendezvous/auth.go). A device signs
// register/unregister with the ECDSA P-256 key of its TLS certificate; an ID is bound to the
// first key that signs for it ('b:<id>'), so nobody else can redirect it to their endpoints.
const SIG_PREFIX = 'APN-RDV-v1';
const SIG_MAX_SKEW_MS = 24 * 3600 * 1000;
const BINDING_TTL_SECONDS = 30 * 24 * 3600;
const BINDING_REFRESH_MS = 7 * 24 * 3600 * 1000; // re-write the binding at most weekly (KV writes)
const BINDING_CACHE_MS = 10 * 60 * 1000;
const bindStore = new Map(); // id -> { data: {fp, signed_at} | null, expires }

// Field limits (same as the self-hosted server).
const MAX_NAME_LEN = 128;
const MAX_SHORT_LEN = 128;
const MAX_FP_LEN = 80;
const MAX_WS_URL_LEN = 512;
const MAX_UDP_ADDRS = 16;
const MAX_UDP_ADDR_LEN = 64;
const RELEASE_CACHE_MS = 20_000; // Short 20s cache; ?refresh=1 always bypasses immediately!

let cachedRelease = null;
let cachedReleaseExp = 0;

function matchPlatformAsset(filename) {
  const f = String(filename || '').toLowerCase();
  if (f.includes('windows-amd64') && f.endsWith('.exe')) return 'windows-amd64';
  if (f.includes('windows-arm64') && f.endsWith('.exe')) return 'windows-arm64';
  if (f.includes('linux-amd64')) return 'linux-amd64';
  if (f.includes('linux-arm64')) return 'linux-arm64';
  if (f.includes('linux-armv7')) return 'linux-armv7';
  if (f.includes('macos-arm64') || f.includes('darwin-arm64')) return 'darwin-arm64';
  if (f.includes('macos-amd64') || f.includes('darwin-amd64')) return 'darwin-amd64';
  return '';
}

async function fetchLatestRelease(env, forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedRelease && now < cachedReleaseExp) {
    return cachedRelease;
  }

  // 1) Primary (zero GitHub API rate limit + zero stale redirect cache!):
  // Resolve the live latest tag via /releases/latest (redirect: manual, cacheTtl: 0),
  // then fetch that exact tag's immutable latest.json!
  try {
    let tagURL = `https://github.com/${GITHUB_REPO}/releases/latest/download/latest.json`;
    const headRes = await fetch(`https://github.com/${GITHUB_REPO}/releases/latest?t=${now}`, {
      headers: { 'User-Agent': 'APN-AutoUpdater/1.2', 'Cache-Control': 'no-cache' },
      redirect: 'manual',
      cf: { cacheTtl: 0, cacheEverything: false },
    });
    const loc = headRes.headers.get('location') || '';
    const m = loc.match(/\/releases\/tag\/([^/?#]+)/);
    if (m && m[1]) {
      tagURL = `https://github.com/${GITHUB_REPO}/releases/download/${m[1]}/latest.json`;
    }
    const cdnRes = await fetch(tagURL, {
      headers: { 'User-Agent': 'APN-AutoUpdater/1.2', 'Cache-Control': 'no-cache' },
      redirect: 'follow',
      cf: { cacheTtl: 0, cacheEverything: false },
    });
    if (cdnRes.ok) {
      const txt = (await cdnRes.text()).replace(/^\uFEFF/, '');
      const parsed = JSON.parse(txt);
      if (parsed && parsed.version && parsed.assets) {
        parsed.repo = GITHUB_REPO;
        parsed.source = 'github-releases-cdn';
        cachedRelease = parsed;
        cachedReleaseExp = now + RELEASE_CACHE_MS;
        return parsed;
      }
    }
  } catch {}

  // 2) Fallback: GitHub Releases REST API (also reads native asset.digest sha256)
  try {
    const res = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases/latest`, {
      headers: {
        'User-Agent': 'APN-AutoUpdater/1.1',
        'Accept': 'application/vnd.github+json',
      },
    });
    if (res.ok) {
      const gh = await res.json();
      const ver = String(gh.tag_name || gh.name || '').replace(/^v/i, '').trim();
      const notes = String(gh.body || gh.name || '').trim();
      const ghAssets = Array.isArray(gh.assets) ? gh.assets : [];

      const assets = {};
      for (const a of ghAssets) {
        const key = matchPlatformAsset(a.name);
        if (!key || !a.browser_download_url) continue;
        const digest = String(a.digest || '').replace(/^sha256:/i, '');
        assets[key] = {
          url: a.browser_download_url,
          sha256: digest,
        };
      }

      const manifest = {
        version: ver,
        release_notes: notes,
        repo: GITHUB_REPO,
        source: 'github-releases-api',
        assets,
      };
      cachedRelease = manifest;
      cachedReleaseExp = now + RELEASE_CACHE_MS;
      return manifest;
    }
  } catch {}

  if (env && env.PEERS) {
    const raw = await env.PEERS.get('release:latest');
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        cachedRelease = parsed;
        cachedReleaseExp = now + 60_000;
        return parsed;
      } catch {}
    }
  }

  return {
    version: '1.1.2',
    release_notes: 'APN v1.1.2 — พร้อมรับอัปเดตอัตโนมัติจาก GitHub Releases (MYSitthichat/APN)',
    repo: GITHUB_REPO,
    source: 'default',
    assets: {},
  };
}

function normalizeID(raw) {
  return String(raw || '').replace(/\D/g, '');
}

function endpointsEqual(a, b) {
  if (!a || !b) return false;
  if (a.ws_url !== b.ws_url || a.fingerprint !== b.fingerprint) return false;
  if (Boolean(a.signed) !== Boolean(b.signed)) return false;
  const ua = a.udp_addrs || [];
  const ub = b.udp_addrs || [];
  if (ua.length !== ub.length) return false;
  for (let i = 0; i < ua.length; i++) {
    if (ua[i] !== ub[i]) return false;
  }
  return true;
}

async function putEntry(env, id, data) {
  memStore.set(id, { data, expires: Date.now() + PRESENCE_CACHE_MS });
  if (env && env.PEERS) {
    await env.PEERS.put('p:' + id, JSON.stringify(data), { expirationTtl: TTL_SECONDS });
  }
}

async function getEntry(env, id, bypassMemCache = false) {
  if (!bypassMemCache) {
    const cached = memStore.get(id);
    if (cached && Date.now() < cached.expires) {
      return cached.data;
    }
  }
  memStore.delete(id);
  if (env && env.PEERS) {
    const raw = await env.PEERS.get('p:' + id);
    if (raw) {
      const parsed = JSON.parse(raw);
      memStore.set(id, { data: parsed, expires: Date.now() + PRESENCE_CACHE_MS });
      return parsed;
    }
  }
  return null;
}

async function deleteEntry(env, id) {
  memStore.delete(id);
  regStore.delete(id);
  offlineStore.delete(id);
  if (env && env.PEERS) {
    await env.PEERS.delete('p:' + id);
  }
}

// Punch requests live under their own short-lived key ('q:<id>'), so a lookup never rewrites the
// device entry 'p:<id>'. Rewriting it from a possibly stale KV read could overwrite a newer
// ws_url (dead trycloudflare URL -> HTTP 530) and keep an offline device looking online.
async function addPunch(env, id, caller) {
  if (!env || !env.PEERS) return;
  const raw = await env.PEERS.get('q:' + id);
  let list = [];
  if (raw) {
    try { list = JSON.parse(raw) || []; } catch { list = []; }
  }
  list = [...list.slice(-(MAX_PUNCHES - 1)), caller];
  await env.PEERS.put('q:' + id, JSON.stringify(list), { expirationTtl: PUNCH_TTL_SECONDS });
}

async function takePunches(env, id) {
  if (!env || !env.PEERS) return [];
  const raw = await env.PEERS.get('q:' + id);
  if (!raw) return [];
  await env.PEERS.delete('q:' + id);
  try { return JSON.parse(raw) || []; } catch { return []; }
}

function b64ToBytes(s) {
  const bin = atob(String(s || ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function certFingerprint(der) {
  return 'sha256:' + toHex(await crypto.subtle.digest('SHA-256', der));
}

// Minimal DER reader: enough to find subjectPublicKeyInfo inside an X.509 certificate,
// because WebCrypto imports SPKI but not certificates.
function derTLV(buf, off) {
  if (off + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[off];
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3) throw new Error('bad DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr = 2 + n;
  }
  const end = off + hdr + len;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, hdr, end };
}

function spkiFromCert(der) {
  const cert = derTLV(der, 0);
  const tbsStart = cert.hdr;
  const tbs = derTLV(der, tbsStart);
  const fields = [];
  for (let p = tbsStart + tbs.hdr; p < tbs.end && fields.length < 8; ) {
    const t = derTLV(der, p);
    fields.push({ start: p, ...t });
    p = t.end;
  }
  // [0] version (optional), serial, signature alg, issuer, validity, subject, subjectPublicKeyInfo
  const i = fields[0] && fields[0].tag === 0xa0 ? 1 : 0;
  const spki = fields[i + 5];
  if (!spki || spki.tag !== 0x30) throw new Error('no SPKI');
  return der.slice(spki.start, spki.end);
}

function signedMessage(action, id, fingerprint, ts, wsURL, udpAddrs) {
  return [SIG_PREFIX, action, id, String(fingerprint || '').toLowerCase(), String(ts), wsURL || '', (udpAddrs || []).join(',')].join('\n');
}

// Returns null when the signature is valid, otherwise the reason.
async function verifySignature(body, action, id, wsURL, udpAddrs) {
  if (typeof body.cert !== 'string' || typeof body.sig !== 'string' || !Number.isFinite(body.ts)) {
    return 'missing signature fields';
  }
  let der;
  let sig;
  try {
    der = b64ToBytes(body.cert);
    sig = b64ToBytes(body.sig);
  } catch {
    return 'invalid certificate';
  }
  if (der.length === 0 || der.length > 4096) return 'invalid certificate';
  if ((await certFingerprint(der)) !== String(body.fingerprint || '').toLowerCase()) {
    return 'certificate does not match fingerprint';
  }
  if (Math.abs(Date.now() - body.ts) > SIG_MAX_SKEW_MS) return 'signature timestamp too far from server time';
  if (sig.length !== 64) return 'invalid signature';
  let key;
  try {
    key = await crypto.subtle.importKey('spki', spkiFromCert(der), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch {
    return 'invalid certificate';
  }
  const msg = new TextEncoder().encode(signedMessage(action, id, body.fingerprint, body.ts, wsURL, udpAddrs));
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, msg);
  return ok ? null : 'invalid signature';
}

async function getBinding(env, id) {
  const cached = bindStore.get(id);
  if (cached && Date.now() < cached.expires) return cached.data;
  let data = null;
  if (env && env.PEERS) {
    const raw = await env.PEERS.get('b:' + id);
    if (raw) {
      try { data = JSON.parse(raw); } catch { data = null; }
    }
  }
  bindStore.set(id, { data, expires: Date.now() + BINDING_CACHE_MS });
  return data;
}

async function putBinding(env, id, fp) {
  const data = { fp, signed_at: Date.now() };
  bindStore.set(id, { data, expires: Date.now() + BINDING_CACHE_MS });
  if (env && env.PEERS) {
    await env.PEERS.put('b:' + id, JSON.stringify(data), { expirationTtl: BINDING_TTL_SECONDS });
  }
}

// Same rules as checkClaim in internal/rendezvous/server.go. Returns null or [status, message].
function checkClaim(binding, live, fingerprint, signed) {
  const fp = String(fingerprint || '').toLowerCase();
  if (binding && binding.fp) {
    if (!signed) return [401, 'this device ID is bound to a signing key; unsigned registration refused (update APN)'];
    if (binding.fp !== fp) return [409, 'this device ID belongs to another device key'];
    return null;
  }
  if (live && String(live.fingerprint || '').toLowerCase() !== fp) {
    return [409, 'this device ID is online with another certificate'];
  }
  return null;
}

function checkRegisterFields(body) {
  const fp = String(body.fingerprint || '');
  const ws = String(body.ws_url || '');
  const udp = body.udp_addrs == null ? [] : body.udp_addrs;
  if (fp.length > MAX_FP_LEN) return 'fingerprint too long';
  if (ws.length > MAX_WS_URL_LEN) return 'ws_url too long';
  if (ws && !ws.startsWith('ws://') && !ws.startsWith('wss://')) return 'ws_url must be ws:// or wss://';
  if (!Array.isArray(udp) || udp.length > MAX_UDP_ADDRS) return 'too many udp_addrs';
  for (const a of udp) {
    if (typeof a !== 'string' || a.length > MAX_UDP_ADDR_LEN) return 'udp_addr too long';
  }
  return null;
}

const clip = (v, n) => String(v || '').slice(0, n);

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      // KV over quota or a transient KV error: always answer JSON so clients can fall back cleanly.
      return Response.json(
        { ok: false, error: 'Rendezvous ใช้งานไม่ได้ชั่วคราว: ' + String((err && err.message) || err) },
        { status: 503 }
      );
    }
  },
};

async function handleRequest(request, env) {
  {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/healthz') {
      return Response.json({
        status: 'ok',
        service: 'apn-rendezvous',
        kv_bound: Boolean(env && env.PEERS),
      });
    }

    if (request.method === 'GET' && path === '/api/releases/latest') {
      const force = url.searchParams.get('refresh') === '1';
      const manifest = await fetchLatestRelease(env, force);
      return Response.json(manifest, {
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache',
        },
      });
    }

    if (request.method === 'POST' && path === '/api/rendezvous/unregister') {
      const body = (await request.json().catch(() => null)) || {};
      const id = normalizeID(body.device_id);
      if (id.length < 6 || id.length > 16) {
        return Response.json({ ok: true });
      }
      let signedFP = '';
      if (body.sig || body.cert) {
        const err = await verifySignature(body, 'unregister', id, '', []);
        if (err) return Response.json({ ok: false, error: 'signature rejected: ' + err }, { status: 401 });
        signedFP = String(body.fingerprint || '').toLowerCase();
      }
      // Only the device that owns the ID may take it offline (see handleUnregister in server.go).
      const binding = await getBinding(env, id);
      const entry = await getEntry(env, id, true);
      let allowed = false;
      if (binding && binding.fp) {
        allowed = signedFP !== '' && signedFP === binding.fp;
      } else if (entry) {
        const entryFP = String(entry.fingerprint || '').toLowerCase();
        allowed = (signedFP !== '' && signedFP === entryFP) ||
          (signedFP === '' && !entry.signed && body.fingerprint && String(body.fingerprint).toLowerCase() === entryFP);
      }
      if (!entry) return Response.json({ ok: true });
      if (!allowed) return Response.json({ ok: false, error: 'not the owner of this device ID' }, { status: 403 });
      await deleteEntry(env, id);
      return Response.json({ ok: true });
    }

    if (request.method === 'POST' && path === '/api/rendezvous/presence') {
      const body = await request.json().catch(() => null);
      const rawIds = Array.isArray(body?.ids) ? body.ids.slice(0, 32) : [];
      const peers = {};
      await Promise.all(
        rawIds.map(async (raw) => {
          const id = normalizeID(raw);
          if (id.length < 6 || id.length > 16) return;
          const off = offlineStore.get(id);
          if (off && Date.now() < off) {
            peers[id] = { online: false };
            return;
          }
          const entry = await getEntry(env, id);
          if (!entry) {
            // Cache "offline" too, so every polling client does not cost a KV read for each offline peer.
            offlineStore.set(id, Date.now() + PRESENCE_CACHE_MS);
          }
          if (entry) {
            peers[id] = {
              online: true,
              name: entry.name || '',
              os: entry.os || '',
              updated_at: entry.updated_at || '',
            };
          } else {
            peers[id] = { online: false };
          }
        })
      );
      return Response.json({ ok: true, peers });
    }

    if (request.method === 'POST' && path === '/api/rendezvous/register') {
      const body = await request.json().catch(() => null);
      const id = normalizeID(body?.device_id);
      if (id.length < 6 || id.length > 16) {
        return Response.json({ ok: false, error: 'invalid device_id' }, { status: 400 });
      }
      const fieldErr = checkRegisterFields(body);
      if (fieldErr) return Response.json({ ok: false, error: fieldErr }, { status: 400 });
      const udpAddrs = body.udp_addrs || [];
      const wsURL = body.ws_url || '';

      let signed = false;
      if (body.sig || body.cert) {
        const err = await verifySignature(body, 'register', id, wsURL, udpAddrs);
        if (err) return Response.json({ ok: false, error: 'signature rejected: ' + err }, { status: 401 });
        signed = true;
      }

      // Only this device writes 'p:<id>', so the last entry this isolate wrote is authoritative.
      // KV is read only on a cold isolate (saves one KV read per heartbeat).
      const reg = regStore.get(id);
      const existing = reg && Date.now() - (reg.kv_written_at || 0) < KV_REFRESH_MS ? reg : await getEntry(env, id, true);
      const binding = await getBinding(env, id);
      const claimErr = checkClaim(binding, existing, body.fingerprint, signed);
      if (claimErr) return Response.json({ ok: false, error: claimErr[1] }, { status: claimErr[0] });

      const pendingPunches = [...(existing?.punches || []), ...(await takePunches(env, id))];
      const nowMs = Date.now();
      offlineStore.delete(id);
      const fpLower = String(body.fingerprint || '').toLowerCase();
      if (signed && (!binding || binding.fp !== fpLower || nowMs - (binding.signed_at || 0) >= BINDING_REFRESH_MS)) {
        await putBinding(env, id, fpLower);
      }
      const nextEntry = {
        device_id: id,
        peer_id: clip(body.peer_id, MAX_SHORT_LEN),
        name: clip(body.name, MAX_NAME_LEN),
        os: clip(body.os, MAX_SHORT_LEN),
        fingerprint: body.fingerprint || '',
        udp_addrs: udpAddrs,
        ws_url: wsURL,
        updated_at: new Date(nowMs).toISOString(),
        kv_written_at: nowMs,
        punches: [],
        signed,
      };

      // Only write to KV when endpoints changed, an old-format entry still holds punches, or the refresh interval elapsed
      const needsWrite =
        !existing ||
        (existing.punches || []).length > 0 ||
        !endpointsEqual(existing, nextEntry) ||
        nowMs - (existing.kv_written_at || 0) >= KV_REFRESH_MS;

      if (needsWrite) {
        await putEntry(env, id, nextEntry);
      } else {
        nextEntry.kv_written_at = existing.kv_written_at;
        memStore.set(id, { data: nextEntry, expires: nowMs + PRESENCE_CACHE_MS });
      }
      regStore.set(id, nextEntry);

      return Response.json({ ok: true, punch_requests: pendingPunches });
    }

    if (path.startsWith('/api/rendezvous/lookup/')) {
      const id = normalizeID(path.slice('/api/rendezvous/lookup/'.length));
      // Bypass per-isolate memStore on lookup so callers ALWAYS get the freshest live trycloudflare.com URL from KV!
      const entry = await getEntry(env, id, true);
      if (!entry) {
        return Response.json(
          { ok: false, error: 'ไม่พบเครื่องหมายเลขนี้ในระบบ Rendezvous (อาจออฟไลน์อยู่)' },
          { status: 404 }
        );
      }
      if (request.method === 'POST') {
        const caller = await request.json().catch(() => null);
        const addrs = Array.isArray(caller?.udp_addrs)
          ? caller.udp_addrs.filter((a) => typeof a === 'string' && a.length <= MAX_UDP_ADDR_LEN).slice(0, 8)
          : [];
        if (addrs.length) {
          await addPunch(env, id, {
            from_device_id: clip(normalizeID(caller.from_device_id), 16),
            udp_addrs: addrs,
          });
        }
      }
      const { punches, kv_written_at, ...publicEntry } = entry;
      return Response.json({ ok: true, entry: publicEntry });
    }

    return new Response('RelayVPN Rendezvous Directory Ready', { status: 200 });
  }
}
