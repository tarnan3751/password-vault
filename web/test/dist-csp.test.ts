// Checks the BUILT bundle (web/dist, which is committed and embedded in the Go
// binary) against the server's Content-Security-Policy:
//   default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
//   img-src 'self' data:; connect-src 'self' <peers>; frame-ancestors 'none';
//   base-uri 'none'; form-action 'none'; object-src 'none'
// and that dist is exactly what `npm run build` produces from the current source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const web = new URL('..', import.meta.url).pathname;
const dist = join(web, 'dist');

function walk(d: string): string[] {
  return readdirSync(d).flatMap((n) => {
    const p = join(d, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  }).sort();
}
const files = () => walk(dist);
const read = (p: string) => readFileSync(p, 'utf8');
const treeHash = () => {
  const h = createHash('sha256');
  for (const f of files()) h.update(f.slice(dist.length)).update(readFileSync(f));
  return h.digest('hex');
};

test('dist has the expected shape', () => {
  const names = files().map((f) => f.slice(dist.length + 1));
  assert.ok(names.includes('index.html'));
  assert.ok(names.includes('sw.js'), 'service worker at the root scope');
  assert.ok(names.includes('manifest.webmanifest'));
  assert.ok(names.includes('icon.svg'));
  assert.equal(names.filter((n) => /^assets\/app-[A-Z0-9]+\.js$/.test(n)).length, 1, 'one hashed JS bundle');
  assert.equal(names.filter((n) => /^assets\/app-[A-Z0-9]+\.css$/.test(n)).length, 1, 'one hashed CSS file');
});

test('index.html: no inline script/style, no handlers, no style attributes, no remote URLs', () => {
  const html = read(join(dist, 'index.html'));
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length >= 1);
  for (const [, attrs, body] of scripts) {
    assert.match(attrs!, /\bsrc="\/assets\/[^"]+"/, 'every script is an external same-origin file');
    assert.equal(body!.trim(), '', 'no inline script body');
  }
  assert.ok(!/<style\b/i.test(html), 'no <style>');
  assert.ok(!/\sstyle\s*=/i.test(html), 'no style=""');
  assert.ok(!/\son[a-z]+\s*=/i.test(html), 'no inline event handlers');
  assert.ok(!/(?:href|src|action)\s*=\s*"\s*javascript:/i.test(html));
  assert.ok(!/(?:src|href|action)\s*=\s*"(?:https?:)?\/\//i.test(html), 'no absolute or protocol-relative URLs');
  assert.ok(!/<(?:iframe|object|embed|form|base)\b/i.test(html), 'nothing blocked by frame/base/form/object rules');
  for (const m of html.matchAll(/(?:src|href)="([^"]+)"/g)) assert.ok(m[1]!.startsWith('/'), m[1]);
});

const ALLOWED_URL = [
  /^http:\/\/www\.w3\.org\/(?:1998\/Math\/MathML|1999\/xhtml|2000\/svg)$/, // DOM namespace identifiers used by Preact, never fetched
  /^https?:\/\/$/, // bare scheme prefix used when normalising a typed server address
  /^https:\/\/vault\.example:8443$/, // input placeholder text
];

test('JS/CSS/SW contain no eval, new Function, or remote URLs', () => {
  const js = files().filter((f) => /\.(js|css)$/.test(f));
  assert.ok(js.length >= 3);
  for (const f of js) {
    const t = read(f);
    assert.ok(!/\beval\s*\(/.test(t), `${f}: eval(`);
    assert.ok(!/\bnew\s+Function\b/.test(t), `${f}: new Function`);
    assert.ok(!/\bFunction\s*\(\s*["'`]/.test(t), `${f}: Function("...")`);
    assert.ok(!/set(?:Timeout|Interval)\s*\(\s*["'`]/.test(t), `${f}: string timers`);
    assert.ok(!/@import/.test(t), `${f}: @import`);
    for (const m of t.matchAll(/(?:https?:)?\/\/[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s"'`)\\]*|https?:\/\/[^\s"'`)\\]*/g)) {
      const u = m[0];
      if (!u.startsWith('http')) {
        // "//host.tld/..." shows up in comments only; reject anything that looks like a protocol-relative URL
        assert.fail(`${f}: protocol-relative URL ${u}`);
      }
      assert.ok(ALLOWED_URL.some((re) => re.test(u)), `${f}: unexpected URL ${u}`);
    }
    if (f.endsWith('.css')) assert.ok(!/url\(\s*["']?(?!#)/.test(t) || /url\(\s*["']?data:/.test(t) === false, `${f}: external url()`);
  }
});

test('source has no inline style usage that would be blocked by style-src', () => {
  const src = walk(join(web, 'src')).filter((f) => /\.tsx?$/.test(f));
  for (const f of src) {
    const t = read(f);
    assert.ok(!/\bstyle\s*=\s*[{"']/.test(t), `${f}: style attribute`);
    assert.ok(!/dangerouslySetInnerHTML|innerHTML\s*=/.test(t), `${f}: raw HTML injection`);
    assert.ok(!/localStorage\.setItem\([^)]*(?:token|password|secret|private|loginkey|accountkey)/i.test(t), `${f}: secrets in localStorage`);
    assert.ok(!/console\.(?:log|debug|info|warn|error)/.test(t), `${f}: console output`);
  }
});

test('the production bundle contains no test-vector-only code', () => {
  const marker = 'fpv-testonly-module-do-not-bundle';
  for (const f of files().filter((f) => /\.(js|css|html)$/.test(f))) assert.ok(!read(f).includes(marker), `${f} contains the test-only module`);
  // nothing in src/ (the bundle's inputs) may import it
  for (const f of walk(join(web, 'src')).filter((f) => /\.tsx?$/.test(f))) {
    if (f.endsWith('testonly.ts')) continue;
    assert.ok(!/from\s+['"][^'"]*testonly/.test(read(f)), `${f} imports testonly`);
  }
  // and the names that only exist for vectors are absent from the minified output too
  const js = read(files().find((f) => /app-[A-Z0-9]+\.js$/.test(f))!);
  for (const n of ['sealWithNonce', 'wrapVaultKeyDeterministic', 'deriveMasterKeysUnsafeParams', 'x25519Raw', 'reencryptWithNonce']) assert.ok(!js.includes(n), n);
});

test('service worker carries an integrity manifest of the shell assets', () => {
  const sw = read(join(dist, 'sw.js'));
  const hashes = sw.match(/[0-9a-f]{64}/g) ?? [];
  assert.ok(hashes.length >= 5, 'one SHA-256 per shell asset');
  for (const [path, rel] of [['/', 'index.html'], ['/icon.svg', 'icon.svg']] as const) {
    assert.ok(sw.includes(createHash('sha256').update(readFileSync(join(dist, rel))).digest('hex')), `${path} hash embedded`);
  }
});

test('service worker never caches the API', () => {
  const sw = read(join(dist, 'sw.js'));
  assert.ok(sw.includes('/v1/'), 'mentions /v1/ to bypass it');
  assert.match(sw, /startsWith\("\/v1\/"\)/);
});

test('dist is up to date and the build is deterministic', () => {
  const before = treeHash();
  execFileSync(process.execPath, ['scripts/build.mjs'], { cwd: web, stdio: 'pipe' });
  assert.equal(treeHash(), before, 'rebuilding changed dist: run `npm run build` and commit web/dist');
});
