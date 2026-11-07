import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { purgeMismatched, sha256Hex, verifyAsset, type CacheLike } from '../src/sw-integrity.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

test('sha256Hex matches node:crypto', async () => {
  assert.equal(await sha256Hex(enc('abc')), sha('abc'));
  assert.equal(await sha256Hex(new Uint8Array(0)), sha(''));
});

test('verifyAsset accepts only manifest paths with the exact bytes', async () => {
  const manifest = { '/assets/app-X.js': sha('good'), '/': sha('<html>') };
  assert.ok(await verifyAsset(manifest, '/assets/app-X.js', enc('good')));
  assert.ok(!(await verifyAsset(manifest, '/assets/app-X.js', enc('evil'))), 'modified bytes');
  assert.ok(!(await verifyAsset(manifest, '/assets/other.js', enc('good'))), 'path not in the manifest');
  assert.ok(!(await verifyAsset(manifest, '__proto__', enc('good'))), 'prototype keys are not manifest entries');
  assert.ok(!(await verifyAsset(manifest, 'toString', enc('good'))));
});

test('purgeMismatched deletes entries that changed or are unknown, keeps the good ones', async () => {
  const origin = 'https://v.test';
  const store = new Map<string, string>([
    [`${origin}/assets/a.js`, 'good-a'],
    [`${origin}/assets/b.js`, 'TAMPERED'],
    [`${origin}/assets/old.js`, 'whatever'],
    [`${origin}/`, '<html>'],
  ]);
  const cache: CacheLike = {
    async keys() { return [...store.keys()].map((url) => ({ url })); },
    async match(req) {
      const v = store.get(typeof req === 'string' ? req : req.url);
      return v === undefined ? undefined : { clone: () => ({ arrayBuffer: async () => enc(v).buffer as ArrayBuffer }) };
    },
    async delete(req) { return store.delete(typeof req === 'string' ? req : req.url); },
  };
  const manifest = { '/assets/a.js': sha('good-a'), '/assets/b.js': sha('good-b'), '/': sha('<html>') };
  const removed = await purgeMismatched(cache, manifest, origin);
  assert.deepEqual(removed.sort(), ['/assets/b.js', '/assets/old.js']);
  assert.deepEqual([...store.keys()].sort(), [`${origin}/`, `${origin}/assets/a.js`]);
});
