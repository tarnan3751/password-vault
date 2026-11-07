// Integrity of cached assets for the service worker. The build embeds a
// manifest of {path: sha256 hex} into sw.js; a fetched asset is verified
// against it BEFORE it is cached, and cached entries that no longer match are
// discarded on activation. This keeps a corrupted or substituted response from
// being served from the cache indefinitely (a compromised node can still serve
// a different app version, which a new sw.js with a new manifest would carry).

export type Manifest = Readonly<Record<string, string>>;

export async function sha256Hex(bytes: ArrayBuffer | Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  let s = '';
  for (const b of d) s += (b < 16 ? '0' : '') + b.toString(16);
  return s;
}

/** True iff `path` is in the manifest and `bytes` hash to the recorded value. Unknown paths are NOT acceptable. */
export async function verifyAsset(manifest: Manifest, path: string, bytes: ArrayBuffer | Uint8Array): Promise<boolean> {
  const want = Object.hasOwn(manifest, path) ? manifest[path] : undefined;
  return want !== undefined && want === (await sha256Hex(bytes));
}

/** The subset of the Cache API used here, so the logic is testable without a browser. */
export interface CacheLike {
  keys(): Promise<readonly { url: string }[]>;
  match(req: { url: string } | string): Promise<{ clone(): { arrayBuffer(): Promise<ArrayBuffer> } } | undefined>;
  delete(req: { url: string } | string): Promise<boolean>;
}

/** Deletes every cached entry whose bytes do not match the manifest (or that is not in it). Returns the deleted paths. */
export async function purgeMismatched(cache: CacheLike, manifest: Manifest, origin: string): Promise<string[]> {
  const removed: string[] = [];
  for (const req of await cache.keys()) {
    const path = req.url.startsWith(origin) ? req.url.slice(origin.length) : req.url;
    const hit = await cache.match(req);
    const ok = hit ? await verifyAsset(manifest, path, await hit.clone().arrayBuffer()) : false;
    if (!ok) {
      await cache.delete(req);
      removed.push(path);
    }
  }
  return removed;
}
