/// <reference lib="webworker" />
// Service worker: makes the app shell open with no server reachable.
//   * hashed assets (/assets/*): cache-first (their names change when content does)
//   * navigations / index.html:  network-first with a cache fallback, so a
//     deployed update is picked up when online and the app still opens offline
//   * /v1/* (the API), non-GET, cross-origin: never touched, never cached.
//     Ciphertext lives in IndexedDB under the app's control, not in a fetch cache.
// Integrity: every asset is verified against the build's SHA-256 manifest
// before it is cached; entries that do not match are purged on activation.
import { purgeMismatched, verifyAsset, type CacheLike, type Manifest } from './sw-integrity.ts';

const sw = self as unknown as ServiceWorkerGlobalScope;
declare const __MANIFEST__: Manifest;
declare const __BUILD_ID__: string;

const PREFIX = 'fv-shell-';
const CACHE = PREFIX + __BUILD_ID__;
const NAV_TIMEOUT_MS = 4000;

async function fetchVerified(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path, init);
  if (!res.ok) throw new Error('fetch failed');
  if (!(await verifyAsset(__MANIFEST__, path, await res.clone().arrayBuffer()))) throw new Error('integrity check failed');
  return res;
}

sw.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // Any asset that does not match the manifest aborts the install: no half-trusted shell.
      for (const path of Object.keys(__MANIFEST__)) await cache.put(path, await fetchVerified(path, { cache: 'reload' }));
      await sw.skipWaiting();
    })(),
  );
});

sw.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      for (const k of await caches.keys()) if (k.startsWith(PREFIX) && k !== CACHE) await caches.delete(k);
      await purgeMismatched(await caches.open(CACHE) as unknown as CacheLike, __MANIFEST__, sw.location.origin);
      await sw.clients.claim();
    })(),
  );
});

async function networkFirstShell(): Promise<Response> {
  const cache = await caches.open(CACHE);
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), NAV_TIMEOUT_MS);
    const res = await fetch(new Request('/', { cache: 'no-cache', signal: ctl.signal })).finally(() => clearTimeout(t));
    // Only an index.html identical to the one this worker was built with is cached; a newer deployment arrives with a new sw.js.
    if (res.ok && (await verifyAsset(__MANIFEST__, '/', await res.clone().arrayBuffer()))) {
      await cache.put('/', res.clone());
      return res;
    }
    if (res.ok) return res; // newer shell: serve it, do not cache it under this manifest
  } catch {
    /* offline or slow: fall through to the cached shell */
  }
  return (await cache.match('/')) ?? Response.error();
}

async function cacheFirst(req: Request, path: string): Promise<Response> {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(req);
  if (hit) return hit;
  const res = await fetch(req);
  if (res.ok && (await verifyAsset(__MANIFEST__, path, await res.clone().arrayBuffer()))) await cache.put(req, res.clone());
  return res;
}

sw.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== sw.location.origin) return;
  if (url.pathname.startsWith('/v1/') || url.pathname === '/sw.js') return;
  if (req.mode === 'navigate') event.respondWith(networkFirstShell());
  else if (url.pathname.startsWith('/assets/') || url.pathname === '/icon.svg' || url.pathname === '/manifest.webmanifest') event.respondWith(cacheFirst(req, url.pathname));
});
