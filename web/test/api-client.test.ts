import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient, ApiError, NetworkError, filterLearnedNodes, MAX_NODES, type FetchLike } from '../src/api/index.ts';

const A = 'http://a.test:1', B = 'http://b.test:2', C = 'http://c.test:3';
type Call = { url: string; method: string; headers: Record<string, string> };

function mock(handler: (c: Call, n: number) => Response | Error): { f: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const f: FetchLike = async (url, init) => {
    const call = { url, method: init?.method ?? 'GET', headers: { ...(init?.headers as Record<string, string>) } };
    calls.push(call);
    const r = handler(call, calls.length);
    if (r instanceof Error) throw r;
    return r;
  };
  return { f, calls };
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const errBody = (code: string, extra = {}) => ({ error: { code, message: code, ...extra } });

test('fails over on network error, remembers the last good node', async () => {
  const { f, calls } = mock((c) => (c.url.startsWith(A) ? new TypeError('down') : json(200, { ok: 1 })));
  const api = new ApiClient({ nodes: [A, B, C], fetch: f });
  await api.request('GET', '/v1/health');
  assert.deepEqual(calls.map((c) => c.url), [A + '/v1/health', B + '/v1/health']);
  assert.equal(api.currentNode, B);
  calls.length = 0;
  await api.request('GET', '/v1/health');
  assert.deepEqual(calls.map((c) => c.url), [B + '/v1/health'], 'last good node is tried first');
});

test('fails over on 503, but not on other errors', async () => {
  let m = mock((c) => (c.url.startsWith(A) ? json(503, errBody('unavailable')) : json(200, {})));
  let api = new ApiClient({ nodes: [A, B], fetch: m.f });
  await api.request('GET', '/v1/health');
  assert.equal(m.calls.length, 2);
  m = mock(() => json(409, errBody('version_conflict', { current_version: 42 })));
  api = new ApiClient({ nodes: [A, B], fetch: m.f });
  await assert.rejects(() => api.request('PUT', '/x', {}, { mutation: true }), (e: unknown) => e instanceof ApiError && e.code === 'version_conflict' && e.currentVersion === 42);
  assert.equal(m.calls.length, 1, 'a definite answer is final');
});

test('all nodes down -> NetworkError', async () => {
  const m = mock(() => new TypeError('down'));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f });
  await assert.rejects(() => api.request('GET', '/v1/health'), NetworkError);
  assert.equal(m.calls.length, 2);
});

test('every mutation has a 32-hex Idempotency-Key, reused across failover and retry', async () => {
  const m = mock((c, n) => (n < 3 ? new TypeError('down') : json(200, { rev: 1 })));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f, mutationRetries: 0 });
  api.token = 'tok';
  // first logical call: both nodes fail (network error) -> outcome unknown
  await assert.rejects(() => api.request('POST', '/v1/vaults', {}, { auth: true, mutation: true, idempotencyKey: 'f'.repeat(32) }), (e: unknown) => e instanceof NetworkError && e.outcomeUnknown);
  // the caller retries with the same key
  await api.request('POST', '/v1/vaults', {}, { auth: true, mutation: true, idempotencyKey: 'f'.repeat(32) });
  const keys = m.calls.map((c) => c.headers['Idempotency-Key']);
  assert.equal(new Set(keys).size, 1);
  assert.match(keys[0]!, /^[0-9a-f]{32}$/);
  // typed endpoint methods generate their own distinct keys
  const m2 = mock(() => json(200, { rev: 1 }));
  const api2 = new ApiClient({ nodes: [A], fetch: m2.f });
  api2.token = 't';
  await api2.createVault({ vault_id: 'x', enc_meta: '', enc_roster: '', wrapped_key: { sender_id: 'y', blob: '' } });
  await api2.deleteVault('v');
  await api2.deleteItem('v', 'i', 3);
  const ks = m2.calls.map((c) => c.headers['Idempotency-Key']);
  assert.ok(ks.every((k) => /^[0-9a-f]{32}$/.test(k!)));
  assert.equal(new Set(ks).size, 3);
  assert.ok(m2.calls[2]!.url.endsWith('base_version=3'));
  assert.equal(m2.calls[2]!.headers['Authorization'], 'Bearer t');
  // reads carry no idempotency key
  await api2.listInvites();
  assert.equal(m2.calls[3]!.headers['Idempotency-Key'], undefined);
});

test('same key is sent to every node on failover of one call', async () => {
  const m = mock((c) => (c.url.startsWith(A) ? json(503, errBody('outcome_unknown')) : json(200, { rev: 2 })));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f });
  api.token = 't';
  await api.putItem('v', 'i', { blob: '', base_version: 0, key_epoch: 1 });
  assert.equal(m.calls.length, 2);
  assert.equal(m.calls[0]!.headers['Idempotency-Key'], m.calls[1]!.headers['Idempotency-Key']);
});

test('outcome_unknown surfaces as a typed error when no node confirms', async () => {
  const m = mock(() => json(503, errBody('outcome_unknown')));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f });
  api.token = 't';
  await assert.rejects(() => api.deleteVault('v'), (e: unknown) => e instanceof ApiError && e.code === 'outcome_unknown');
});

test('linearizable by default; consistency=stale only after every reachable node says unavailable', async () => {
  const m = mock((c) => {
    if (c.url.includes('consistency=stale')) return json(200, { rev: 5, stale: true });
    return c.url.startsWith(C) ? new TypeError('down') : json(503, errBody('unavailable'));
  });
  const api = new ApiClient({ nodes: [A, B, C], fetch: m.f });
  api.token = 't';
  const r = await api.sync();
  assert.equal(r.stale, true);
  assert.ok(api.lastStale);
  const urls = m.calls.map((c) => c.url);
  assert.ok(!urls[0]!.includes('stale'), 'first pass is linearizable');
  assert.ok(urls.slice(0, 3).every((u) => !u.includes('stale')));
  assert.ok(urls.slice(3).some((u) => u.includes('consistency=stale')));
});

test('stale fallback is never used for writes or for non-stale endpoints', async () => {
  const m = mock(() => json(503, errBody('unavailable')));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f });
  api.token = 't';
  await assert.rejects(() => api.putItem('v', 'i', { blob: '', base_version: 0, key_epoch: 1 }), (e: unknown) => e instanceof ApiError && e.code === 'unavailable');
  await assert.rejects(() => api.listInvites(), (e: unknown) => e instanceof ApiError && e.code === 'unavailable');
  assert.ok(m.calls.every((c) => !c.url.includes('stale')));
});

test('prelogin/login also fall back to stale; login stores the token', async () => {
  const m = mock((c) => {
    if (!c.url.includes('stale')) return json(503, errBody('unavailable'));
    return c.url.includes('login') && !c.url.includes('prelogin') ? json(200, { token: 'T', user_id: 'u', username: 'x', is_admin: false, expires_at: 1 }) : json(200, { kdf: {} });
  });
  const api = new ApiClient({ nodes: [A], fetch: m.f, unavailableRetries: 0 });
  await api.prelogin('x');
  const lr = await api.login('x', 'AAAA');
  assert.equal(lr.token, 'T');
  assert.equal(api.token, 'T');
});

test('401 on an authenticated call calls onUnauthorized; requests need a token', async () => {
  let called = 0;
  const m = mock(() => json(401, errBody('unauthorized')));
  const api = new ApiClient({ nodes: [A], fetch: m.f, onUnauthorized: () => called++ });
  await assert.rejects(() => api.sync(), ApiError); // no token: fails locally
  assert.equal(m.calls.length, 0);
  api.token = 'old';
  await assert.rejects(() => api.sync(), ApiError);
  assert.equal(called, 1);
});

test('refreshCluster learns nodes (http only when allowed) and reports them for persistence', async () => {
  const saved: string[][] = [];
  const body = { nodes: [{ id: 'n1', public_url: A + '/' }, { id: 'n2', public_url: B }, { id: 'n3', public_url: 'ftp://evil' }, { id: 'n4', public_url: 'garbage' }, { id: 'n5', public_url: 'https://s.test:9' }], leader_id: 'n1' };
  const m = mock(() => json(200, body));
  const api = new ApiClient({ nodes: [A], fetch: m.f, onNodesChanged: (n) => saved.push(n), allowInsecureLearned: true });
  await api.refreshCluster();
  assert.deepEqual(api.nodeUrls, [A, B, 'https://s.test:9']);
  assert.deepEqual(saved.at(-1), [A, B, 'https://s.test:9']);
  // page loaded over https: plain-http nodes are never learned
  const api2 = new ApiClient({ nodes: ['https://a.test:1'], fetch: mock(() => json(200, body)).f });
  await api2.refreshCluster();
  assert.deepEqual(api2.nodeUrls, ['https://a.test:1', 'https://s.test:9']);
});

test('filterLearnedNodes: https only unless allowed, well-formed origins, no downgrade, at most 16', () => {
  assert.deepEqual(filterLearnedNodes([], ['http://x.test', 'https://y.test/path?q=1', 'javascript:alert(1)', 'https://', '//z.test', 'HTTPS://W.TEST:443'], false), ['https://y.test', 'https://w.test']);
  assert.deepEqual(filterLearnedNodes(['https://a.test:8443'], ['http://a.test:8443', 'http://b.test'], true), ['https://a.test:8443', 'http://b.test'], 'no downgrade of a known https host');
  const many = Array.from({ length: 40 }, (_, i) => `https://n${i}.test`);
  assert.equal(filterLearnedNodes(['https://a.test'], many, false).length, MAX_NODES);
  assert.equal(filterLearnedNodes(['https://a.test'], many, false)[0], 'https://a.test', 'known nodes first');
});

test('the unknown-outcome flag is sticky across retry passes', async () => {
  // pass 1: a network error (the write may have landed); passes 2-3: a definite-looking 503 unavailable
  const m = mock((_c, n) => (n === 1 ? new TypeError('reset') : json(503, errBody('unavailable'))));
  const api = new ApiClient({ nodes: [A], fetch: m.f, retryDelayMs: 1, mutationRetries: 2 });
  api.token = 't';
  const err = await api.deleteVault('v').catch((e) => e);
  assert.ok(err instanceof NetworkError, 'not reported as "unavailable: nothing changed"');
  assert.equal(err.outcomeUnknown, true);
  assert.equal(m.calls.length, 3);
  assert.equal(new Set(m.calls.map((c) => c.headers['Idempotency-Key'])).size, 1);
  // control: only 503 unavailable the whole time -> a definite, typed "nothing changed"
  const m2 = mock(() => json(503, errBody('unavailable')));
  const api2 = new ApiClient({ nodes: [A], fetch: m2.f, retryDelayMs: 1 });
  api2.token = 't';
  await assert.rejects(() => api2.deleteVault('v'), (e: unknown) => e instanceof ApiError && e.code === 'unavailable');
});

test('sends no cookies and never caches', async () => {
  let seen: RequestInit | undefined;
  const api = new ApiClient({ nodes: [A], fetch: async (_u, init) => ((seen = init), json(200, {})) });
  await api.request('GET', '/v1/health');
  assert.equal(seen?.credentials, 'omit');
  assert.equal(seen?.cache, 'no-store');
});

test('per-node probe does not fail over', async () => {
  const m = mock((c) => (c.url.startsWith(A) ? new TypeError('x') : json(200, { node_id: 'b', role: 'leader' })));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f });
  const r = await api.probeNodes();
  assert.deepEqual(r.map((x) => x.ok), [false, true]);
});

test('ambiguous mutation failures are retried automatically with the same key', async () => {
  const m = mock((_c, n) => (n <= 2 ? new TypeError('down') : json(200, { rev: 9 })));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f, retryDelayMs: 1 });
  api.token = 't';
  const r = await api.deleteVault('v');
  assert.equal(r.rev, 9);
  assert.equal(m.calls.length, 3);
  assert.equal(new Set(m.calls.map((c) => c.headers['Idempotency-Key'])).size, 1);
  // plain "unavailable" means nothing changed: no automatic retry
  const m2 = mock(() => json(503, errBody('unavailable')));
  const api2 = new ApiClient({ nodes: [A], fetch: m2.f, retryDelayMs: 1 });
  api2.token = 't';
  await assert.rejects(() => api2.deleteVault('v'));
  assert.equal(m2.calls.length, 1);
});

test('sign-in and registration wait out "unavailable" from every node (e.g. right after a restart); other calls do not', async () => {
  const m = mock((_c, n) => (n <= 2 ? json(503, errBody('unavailable')) : json(200, { token: 'T', user_id: 'u', username: 'x', is_admin: false, expires_at: 1 })));
  const api = new ApiClient({ nodes: [A, B], fetch: m.f, retryDelayMs: 1 });
  const r = await api.register({} as never);
  assert.equal(r.token, 'T');
  assert.equal(m.calls.length, 3, 'one more pass after the first all-503 pass');
  assert.equal(new Set(m.calls.map((c) => c.headers['Idempotency-Key'])).size, 1, 'same key on every attempt');
  // still failing after the retries: surfaced as a typed "unavailable" (nothing changed)
  const m2 = mock(() => json(503, errBody('unavailable')));
  const api2 = new ApiClient({ nodes: [A], fetch: m2.f, retryDelayMs: 1, unavailableRetries: 3 });
  await assert.rejects(() => api2.login('x', 'AAAA'), (e: unknown) => e instanceof ApiError && e.code === 'unavailable');
  assert.equal(m2.calls.length, 1 + 3 + 1 /* + the stale fallback pass */);
  // an ordinary authenticated write is not retried this way
  const m3 = mock(() => json(503, errBody('unavailable')));
  const api3 = new ApiClient({ nodes: [A], fetch: m3.f, retryDelayMs: 1 });
  api3.token = 't';
  await assert.rejects(() => api3.deleteVault('v'));
  assert.equal(m3.calls.length, 1);
});
