// Repeatable performance measurement of the BUILT bundle in headless Chromium against the stub server.
//   npm run perf [-- --runs 3 --entries 2000 --small-only]
// Scenarios: "small" (default: 1 vault, 5 entries) and "large" (3 vaults, --entries entries). Real Argon2id
// parameters (64 MiB, t=3, p=4) are used; nothing is weakened. Prints medians over --runs as JSON.
// Timings are wall-clock on this machine: compare before/after on a quiet machine.
import { chromium } from 'playwright-core';
import { parseArgs } from 'node:util';
import { startStub } from './stub-server.ts';
import { ApiClient } from '../src/api/index.ts';
import { b64encode, defaultKdfParams, encryptItem, newId, newItem } from '../src/crypto/index.ts';
import { K, MemoryStore, Session } from '../src/vault/index.ts';

const { values: o } = parseArgs({ options: { runs: { type: 'string', default: '3' }, entries: { type: 'string', default: '2000' }, 'small-only': { type: 'boolean', default: false } } });
const RUNS = Number(o.runs);
const dist = new URL('../dist', import.meta.url).pathname;
const PW = 'perf correct horse battery staple';
const median = (a) => (a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : null);
const r1 = (n) => (n == null ? n : Math.round(n * 10) / 10);

async function seed(stub, name, nEntries, nVaults) {
  const deps = { api: new ApiClient({ nodes: [stub.url], allowInsecureLearned: true }), store: new MemoryStore() };
  const s = await Session.register(deps, { username: name, password: PW, inviteCode: stub.fake.bootstrapToken, kdf: defaultKdfParams() });
  const ids = [s.vaults[0].id];
  for (let i = 1; i < nVaults; i++) ids.push(await s.createVault(i === 1 ? 'Household' : `Project ${i}`));
  await s.sync();
  const first = [];
  for (let i = 0; i < nEntries; i++) {
    const vaultId = ids[i % ids.length];
    const sec = s.secrets.get(vaultId);
    const itemId = newId();
    const it = { ...newItem('login', Date.now()), name: `Site ${String(i * 7919 % nEntries).padStart(4, '0')} ${['bank', 'mail', 'shop', 'news', 'cloud'][i % 5]}`, username: `user${i}@example.com`, password: `pw-${i}-${'x'.repeat(16)}`, urls: [`https://site${i}.example.com/login`], notes: 'some notes about this account', tags: [`t${i % 9}`] };
    const blob = b64encode(encryptItem(sec.vk, { vaultId, itemId, epoch: sec.epoch }, it));
    await deps.api.putItem(vaultId, itemId, { blob, base_version: 0, key_epoch: sec.epoch });
    if (i < ids.length) first.push([vaultId, itemId]);
  }
  await s.sync();
  return { s, name, first };
}

const INIT = () => {
  const P = (window.__perf = { fetches: [], puts: [], gets: [], long: [] });
  const f = window.fetch;
  window.fetch = async (...a) => {
    const t0 = performance.now();
    const r = await f(...a);
    P.fetches.push({ url: String(a[0]?.url ?? a[0]).replace(location.origin, ''), t0, t1: performance.now() });
    return r;
  };
  const put = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...a) {
    const t0 = performance.now();
    const r = put.apply(this, a);
    P.puts.push({ t: t0, ms: performance.now() - t0 });
    return r;
  };
  const get = IDBObjectStore.prototype.get;
  IDBObjectStore.prototype.get = function (...a) {
    const t0 = performance.now();
    const r = get.apply(this, a);
    r.addEventListener('success', () => { const t1 = performance.now(); r.result; P.gets.push({ t: t0, ms: t1 - t0, deserMs: performance.now() - t1 }); });
    return r;
  };
  new PerformanceObserver((l) => l.getEntries().forEach((e) => P.long.push({ t: e.startTime, ms: e.duration }))).observe({ type: 'longtask', buffered: true });
  window.__flush = async () => { await new Promise((r) => { const c = new MessageChannel(); c.port1.onmessage = r; c.port2.postMessage(0); }); document.body.offsetHeight; return performance.now(); }; // render + style + layout, no paint
  window.__jank = (ms) => new Promise((resolve) => { // longest gap between main-thread turns over the next ms
    const ch = new MessageChannel(); let last = performance.now(), max = 0; const end = last + ms;
    ch.port1.onmessage = () => { const n = performance.now(); max = Math.max(max, n - last); last = n; if (n < end) ch.port2.postMessage(0); else resolve(max); };
    ch.port2.postMessage(0);
  });
  window.__frames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(performance.now()))));
  window.__heading = new Promise((r) => new MutationObserver((_, ob) => { if (document.querySelector('h1')?.textContent === 'Family Vault') { ob.disconnect(); r(performance.now()); } }).observe(document, { childList: true, subtree: true }));
};

async function ctxFor(browser, sw) {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 }, serviceWorkers: sw ? 'allow' : 'block' });
  await ctx.addInitScript(INIT);
  return ctx;
}

async function coldLoad(browser, stub) {
  const served = [];
  const hook = (req, res) => {
    const end = res.end;
    res.end = function (chunk, ...a) { if (!req.url.startsWith('/v1/')) served.push(chunk?.length ?? 0); return end.call(this, chunk, ...a); };
  };
  stub.server.prependListener('request', hook);
  const out = {};
  try {
    for (const sw of [false, true]) {
      const ctx = await ctxFor(browser, sw);
      const page = await ctx.newPage();
      if (sw) {
        await page.goto(stub.url + '/');
        await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
        await page.waitForTimeout(500);
      }
      served.length = 0;
      await page.goto(stub.url + '/');
      const t = await page.evaluate(() => window.__heading);
      out[sw ? 'sw' : 'nosw'] = { bytes: served.reduce((a, b) => a + b, 0), requests: served.length, headingMs: r1(t) };
      await ctx.close();
    }
  } finally {
    stub.server.removeListener('request', hook);
  }
  return out;
}

async function login(page, stub, name) {
  await page.goto(stub.url + '/');
  await page.getByLabel('Username').fill(name);
  await page.getByLabel('Master password').fill(PW);
  await page.locator('button[type=submit]').click();
  await page.locator('.entries, .start').first().waitFor({ timeout: 120_000 });
}

async function unlock(page, stub) {
  await page.goto(stub.url + '/');
  await page.getByLabel('Master password').waitFor();
  await page.getByLabel('Master password').fill(PW);
  await page.evaluate(() => { window.__perf.fetches.length = 0; window.__perf.puts.length = 0; window.__perf.long.length = 0; });
  const t0 = await page.evaluate(() => performance.now());
  await page.getByRole('button', { name: 'Unlock' }).click();
  await page.locator('.entry, .start').first().waitFor({ timeout: 120_000 });
  const t1 = await page.evaluate(() => window.__frames());
  return page.evaluate(([t0, t1]) => {
    const P = window.__perf;
    const f = (u) => P.fetches.find((x) => x.url.includes(u));
    const argon = f('/v1/login').t0 - f('/v1/prelogin').t1;
    const net = P.fetches.reduce((a, x) => a + (x.t1 - x.t0), 0);
    return { totalMs: t1 - t0, argonMs: argon, networkMs: net, otherMs: t1 - t0 - argon - net, afterSyncMs: t1 - f('/v1/sync').t1, idbPuts: P.puts.length, idbPutMs: P.puts.reduce((a, x) => a + x.ms, 0), longTaskMs: P.long.reduce((a, x) => a + x.ms, 0) };
  }, [t0, t1]);
}

const inPage = (page, fn, arg) => page.evaluate(fn, arg);

async function steady(page, seeded) {
  const res = {};
  res.dom = await inPage(page, () => ({ nodes: document.querySelectorAll('*').length, rows: document.querySelectorAll('.entries li').length }));
  const sync = async (label) => {
    const r = await inPage(page, async () => {
      const P = window.__perf;
      P.fetches.length = P.puts.length = P.gets.length = P.long.length = 0;
      const jank = window.__jank(400);
      document.dispatchEvent(new Event('visibilitychange'));
      const maxBlockMs = await jank;
      const sf = P.fetches.find((f) => f.url.includes('/v1/sync'));
      return { maxBlockMs, fetchMs: sf.t1 - sf.t0, idbPuts: P.puts.length, idbPutMs: P.puts.reduce((a, x) => a + x.ms, 0), idbGets: P.gets.length, idbGetMs: P.gets.reduce((a, x) => a + x.ms + x.deserMs, 0) };
    });
    res[label] = r;
  };
  await sync('syncUnchanged');
  const [vid, iid] = seeded.first[0];
  await seeded.s.updateItem(vid, iid, (it) => { it.notes = 'changed ' + Date.now(); });
  await sync('syncOneChanged');
  // search keystrokes: type a word then delete it
  res.keystrokeMs = await inPage(page, async () => {
    const el = document.getElementById('search');
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    const times = [];
    for (const v of ['s', 'si', 'sit', 'site', 'site ', 'site 0', 'site 00', 'site 001', 'site 00', 'site 0', 'site', 'si', 's', '']) {
      const t0 = performance.now();
      set.call(el, v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      times.push((await window.__flush()) - t0);
      await window.__frames();
    }
    return times;
  });
  res.keystrokeMedianMs = r1(median(res.keystrokeMs));
  res.keystrokeMaxMs = r1(Math.max(...res.keystrokeMs));
  delete res.keystrokeMs;
  const click = (sel, nth = 0) => inPage(page, async ([sel, nth]) => {
    const els = document.querySelectorAll(sel);
    const t0 = performance.now();
    els[Math.min(nth, els.length - 1)].click();
    const t1 = await window.__flush();
    await window.__frames();
    return t1 - t0;
  }, [sel, nth]);
  const links = await page.locator('.vault-link').count();
  const sw = [];
  for (let k = 0; k < 2; k++) for (let i = 0; i < links; i++) sw.push(await click('.vault-link', i));
  res.vaultSwitchMedianMs = r1(median(sw));
  await click('.vault-link', 0); // back to All entries
  res.openEntryMs = r1(median([await click('.entry', 3), await click('.entry', 10), await click('.entry', 4), await click('.entry', 11)]));
  // edit and save
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('Edited entry');
  res.saveMs = r1(await inPage(page, async () => {
    const t0 = performance.now();
    [...document.querySelectorAll('dialog[open] button')].find((b) => b.textContent.trim() === 'Save').click();
    while (document.querySelector('dialog[open]')) await new Promise((r) => setTimeout(r, 0));
    return (await window.__frames()) - t0;
  }));
  return res;
}

// Vault layer alone (no DOM): what a sync costs and how much decrypted work it reuses.
async function nodeSide(stub, seeded, name) {
  const store = new MemoryStore();
  const s = await Session.login({ api: new ApiClient({ nodes: [stub.url], allowInsecureLearned: true }), store }, { username: name, password: PW });
  const ms = async (f) => { const t = performance.now(); await f(); return r1(performance.now() - t); };
  const items = () => s.vaults.flatMap((v) => v.items);
  const before = new Set(items());
  const unchangedMs = await ms(() => s.sync());
  const [vid, iid] = seeded.first[0];
  await seeded.s.updateItem(vid, iid, (it) => { it.notes = 'node ' + Date.now(); });
  const changedMs = await ms(() => s.sync());
  const after = items();
  const cacheBytes = JSON.stringify(await store.get(K.sync(name))).length;
  s.lock();
  return { syncUnchangedMs: unchangedMs, syncOneChangedMs: changedMs, itemsReusedAfterOneChange: `${after.filter((i) => before.has(i)).length}/${after.length}`, cachedSyncBytes: cacheBytes };
}

async function scenario(browser, name, n, nv) {
  const stub = await startStub({ dist });
  const seeded = await seed(stub, name, n, nv);
  const node = await nodeSide(stub, seeded, name);
  const cold = [], unl = [], std = [];
  const ctx0 = await ctxFor(browser, false);
  const login0 = await ctx0.newPage();
  await login(login0, stub, name); // fills IndexedDB
  await login0.close();
  for (let i = 0; i < RUNS; i++) {
    const page = await ctx0.newPage();
    await page.goto(stub.url + '/'); // a lock screen: the cache is in IndexedDB
    unl.push(await unlock(page, stub));
    if (i === RUNS - 1) std.push(await steady(page, seeded));
    await page.close();
  }
  await ctx0.close();
  for (let i = 0; i < RUNS; i++) cold.push(await coldLoad(browser, stub));
  await stub.close();
  const med = (arr, f) => r1(median(arr.map(f)));
  return {
    entries: n, vaults: nv,
    coldLoad: { noSw: { bytes: cold[0].nosw.bytes, requests: cold[0].nosw.requests, headingMs: med(cold, (c) => c.nosw.headingMs) }, withSw: { bytes: cold[0].sw.bytes, requests: cold[0].sw.requests, headingMs: med(cold, (c) => c.sw.headingMs) } },
    unlock: Object.fromEntries(Object.keys(unl[0]).map((k) => [k, med(unl, (u) => u[k])])),
    vaultLayerNode: node,
    steady: std[0],
  };
}

const browser = await chromium.launch();
try {
  const out = { small: await scenario(browser, 'small', 5, 1) };
  if (!o['small-only']) out.large = await scenario(browser, 'large', Number(o.entries), 3);
  console.log(JSON.stringify(out, null, 1));
} finally {
  await browser.close();
}
