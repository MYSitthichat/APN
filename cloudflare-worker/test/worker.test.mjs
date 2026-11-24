// Tests for rendezvous-worker.js against an in-memory KV mock. Run: node test/worker.test.mjs
// The signed requests in fixture.json are produced by the Go code (internal/rendezvous,
// TestWriteWorkerFixture), so this checks the Worker accepts exactly what the Go client signs.
import { readFileSync } from 'node:fs';
import worker from '../rendezvous-worker.js';

const fixture = JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url), 'utf8'));

// Signatures are only valid within 24h of their timestamp: run the Worker at fixture time.
const realNow = Date.now;
Date.now = () => fixture.ts;

const store = new Map();
let writes = 0;
let reads = 0;
let broken = false;
const env = {
  PEERS: {
    async get(k) { if (broken) throw new Error('KV get() limit exceeded'); reads++; return store.has(k) ? store.get(k) : null; },
    async put(k, v) { if (broken) throw new Error('KV put() limit exceeded'); writes++; store.set(k, v); },
    async delete(k) { writes++; store.delete(k); },
  },
};

async function call(method, path, body) {
  const res = await worker.fetch(new Request('https://rdv.test' + path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { 'content-type': 'application/json' },
  }), env);
  return { status: res.status, json: await res.json() };
}

let failed = 0;
function check(cond, msg) {
  if (cond) {
    console.log('ok   ', msg);
  } else {
    failed++;
    console.error('FAIL ', msg);
  }
}

// --- Signed registration and ID binding ---------------------------------------------------
const ID = fixture.owner_register.device_id;
let r = await call('POST', '/api/rendezvous/register', fixture.owner_register);
check(r.status === 200 && r.json.ok, 'owner signed register accepted');
check(JSON.parse(store.get('p:' + ID)).signed === true, 'entry stored as signed');
check(JSON.parse(store.get('b:' + ID)).fp === fixture.owner_register.fingerprint.toLowerCase(), 'ID bound to owner fingerprint');

r = await call('POST', '/api/rendezvous/register', { device_id: ID, fingerprint: 'sha256:attacker', ws_url: 'wss://evil.example/ws' });
check(r.status === 401, 'unsigned takeover of bound ID refused (401)');
r = await call('POST', '/api/rendezvous/register', fixture.attacker_register);
check(r.status === 409, 'signed takeover by another key refused (409)');

r = await call('POST', '/api/rendezvous/lookup/' + ID, {});
check(r.json.entry.fingerprint === fixture.owner_register.fingerprint, 'lookup still returns the owner');

const tampered = { ...fixture.owner_register, ws_url: 'wss://evil.example/ws' };
r = await call('POST', '/api/rendezvous/register', tampered);
check(r.status === 401, 'signature over different ws_url rejected (401)');

Date.now = () => fixture.ts + 25 * 3600 * 1000;
r = await call('POST', '/api/rendezvous/register', fixture.owner_register);
check(r.status === 401, 'signature older than 24h rejected (401)');
Date.now = () => fixture.ts;

r = await call('POST', '/api/rendezvous/unregister', { device_id: ID });
check(r.status === 403 && store.has('p:' + ID), 'anonymous unregister refused (403)');
r = await call('POST', '/api/rendezvous/unregister', fixture.attacker_unregister);
check(r.status === 403 && store.has('p:' + ID), 'unregister by another key refused (403)');
r = await call('POST', '/api/rendezvous/unregister', fixture.owner_unregister);
check(r.status === 200 && !store.has('p:' + ID), 'owner signed unregister removes the entry');
r = await call('POST', '/api/rendezvous/register', fixture.attacker_register);
check(r.status === 409, 'offline but bound ID still cannot be claimed by another key (409)');

// --- Legacy (unsigned) clients keep working but cannot be hijacked while online ------------
r = await call('POST', '/api/rendezvous/register', { device_id: '111222333', fingerprint: 'sha256:aaaa', udp_addrs: ['1.2.3.4:4433'] });
check(r.status === 200, 'legacy unsigned register accepted when ID is unbound');
r = await call('POST', '/api/rendezvous/register', { device_id: '111222333', fingerprint: 'sha256:bbbb' });
check(r.status === 409, 'legacy live entry cannot be replaced by another fingerprint (409)');
r = await call('POST', '/api/rendezvous/unregister', { device_id: '111222333', fingerprint: 'sha256:aaaa' });
check(r.status === 200 && !store.has('p:111222333'), 'legacy device unregisters with its own fingerprint');

// --- Field limits ---------------------------------------------------------------------------
r = await call('POST', '/api/rendezvous/register', { device_id: '222333444', fingerprint: 'fp', ws_url: 'https://not-ws.example' });
check(r.status === 400, 'non-websocket ws_url rejected (400)');
r = await call('POST', '/api/rendezvous/register', { device_id: '222333444', fingerprint: 'fp', ws_url: 'wss://' + 'a'.repeat(600) });
check(r.status === 400, 'over-long ws_url rejected (400)');
r = await call('POST', '/api/rendezvous/register', { device_id: '222333444', fingerprint: 'fp', name: 'n'.repeat(500) });
check(r.status === 200 && JSON.parse(store.get('p:222333444')).name.length === 128, 'over-long name stored truncated');

// --- Heartbeats, punches, presence, errors ----------------------------------------------------
const host = { device_id: '333444555', fingerprint: 'sha256:host', udp_addrs: ['1.2.3.4:4433'], ws_url: 'wss://a.trycloudflare.com' };
await call('POST', '/api/rendezvous/register', host);
const w1 = writes;
await call('POST', '/api/rendezvous/register', host);
check(writes === w1, 'unchanged heartbeat does not write KV');
await call('POST', '/api/rendezvous/lookup/333444555', { from_device_id: '999888777', udp_addrs: ['5.6.7.8:4433', 'x'.repeat(100)] });
check(JSON.parse(store.get('p:333444555')).ws_url === host.ws_url, 'lookup does not rewrite p:<id>');
r = await call('POST', '/api/rendezvous/register', host);
check(r.json.punch_requests.length === 1 && r.json.punch_requests[0].udp_addrs.length === 1, 'punch delivered, over-long address dropped');

const rd = reads;
await call('POST', '/api/rendezvous/presence', { ids: ['444555666'] });
r = await call('POST', '/api/rendezvous/presence', { ids: ['444555666'] });
check(r.json.peers['444555666'].online === false && reads === rd + 1, 'offline presence cached (1 KV read for 2 polls)');

broken = true;
r = await call('POST', '/api/rendezvous/lookup/123456789', { udp_addrs: ['1.1.1.1:1'] });
check(r.status === 503 && r.json.ok === false, 'KV failure returns JSON 503');

Date.now = realNow;
if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nALL PASSED');
