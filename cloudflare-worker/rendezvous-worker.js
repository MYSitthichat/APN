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
const TTL_SECONDS = 600;        // 10 minutes TTL
const KV_REFRESH_MS = 300_000;  // Skip redundant KV writes when endpoints haven't changed within 5 minutes
const GITHUB_REPO = 'MYSitthichat/APN';
const RELEASE_CACHE_MS = 300_000; // Cache GitHub Releases API response for 5 minutes (0 KV writes!)

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

  // 1) Primary (zero GitHub API rate limit!): fetch latest.json directly from GitHub Releases CDN!
  try {
    const cdnRes = await fetch(`https://github.com/${GITHUB_REPO}/releases/latest/download/latest.json`, {
      headers: { 'User-Agent': 'APN-AutoUpdater/1.1' },
      redirect: 'follow',
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
  const ua = a.udp_addrs || [];
  const ub = b.udp_addrs || [];
  if (ua.length !== ub.length) return false;
  for (let i = 0; i < ua.length; i++) {
    if (ua[i] !== ub[i]) return false;
  }
  return true;
}

async function putEntry(env, id, data) {
  memStore.set(id, { data, expires: Date.now() + TTL_SECONDS * 1000 });
  if (env && env.PEERS) {
    await env.PEERS.put('p:' + id, JSON.stringify(data), { expirationTtl: TTL_SECONDS });
  }
}

async function getEntry(env, id) {
  const cached = memStore.get(id);
  if (cached && Date.now() < cached.expires) {
    return cached.data;
  }
  memStore.delete(id);
  if (env && env.PEERS) {
    const raw = await env.PEERS.get('p:' + id);
    if (raw) {
      const parsed = JSON.parse(raw);
      memStore.set(id, { data: parsed, expires: Date.now() + 60_000 });
      return parsed;
    }
  }
  return null;
}

async function deleteEntry(env, id) {
  memStore.delete(id);
  if (env && env.PEERS) {
    await env.PEERS.delete('p:' + id);
  }
}

export default {
  async fetch(request, env) {
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
      return Response.json(manifest);
    }

    if (request.method === 'POST' && path === '/api/rendezvous/unregister') {
      const body = await request.json().catch(() => null);
      const id = normalizeID(body?.device_id);
      if (id.length >= 6 && id.length <= 16) {
        await deleteEntry(env, id);
      }
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
          const entry = await getEntry(env, id);
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

      const existing = await getEntry(env, id);
      const pendingPunches = existing?.punches || [];
      const nowMs = Date.now();
      const nextEntry = {
        device_id: id,
        peer_id: body.peer_id || '',
        name: body.name || '',
        os: body.os || '',
        fingerprint: body.fingerprint || '',
        udp_addrs: body.udp_addrs || [],
        ws_url: body.ws_url || '',
        updated_at: new Date(nowMs).toISOString(),
        kv_written_at: nowMs,
        punches: [],
      };

      // Only write to KV when endpoints changed, punches were drained, or >5 minutes elapsed
      const needsWrite =
        !existing ||
        pendingPunches.length > 0 ||
        !endpointsEqual(existing, nextEntry) ||
        nowMs - (existing.kv_written_at || 0) >= KV_REFRESH_MS;

      if (needsWrite) {
        await putEntry(env, id, nextEntry);
      } else {
        nextEntry.kv_written_at = existing.kv_written_at;
        memStore.set(id, { data: nextEntry, expires: nowMs + TTL_SECONDS * 1000 });
      }

      return Response.json({ ok: true, punch_requests: pendingPunches });
    }

    if (path.startsWith('/api/rendezvous/lookup/')) {
      const id = normalizeID(path.slice('/api/rendezvous/lookup/'.length));
      const entry = await getEntry(env, id);
      if (!entry) {
        return Response.json(
          { ok: false, error: 'ไม่พบเครื่องหมายเลขนี้ในระบบ Rendezvous (อาจออฟไลน์อยู่)' },
          { status: 404 }
        );
      }
      if (request.method === 'POST') {
        const caller = await request.json().catch(() => null);
        if (caller?.udp_addrs?.length) {
          entry.punches = [...(entry.punches || []).slice(-4), caller];
          await putEntry(env, id, entry);
        }
      }
      return Response.json({ ok: true, entry });
    }

    return new Response('RelayVPN Rendezvous Directory Ready', { status: 200 });
  },
};
