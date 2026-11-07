// Deterministic production build: src/ -> dist/ (committed; embedded into the Go binary).
// Same inputs always give byte-identical output (content-hashed names, no
// timestamps, no sourcemaps). Run: npm run build
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, 'dist');
await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, 'assets'), { recursive: true });

const common = { absWorkingDir: root, bundle: true, minify: true, legalComments: 'none', target: 'es2022', logLevel: 'warning', sourcemap: false };

const app = await build({
  ...common,
  entryPoints: ['src/main.tsx'],
  outdir: 'dist/assets',
  entryNames: 'app-[hash]',
  format: 'esm',
  metafile: true,
  // No `eval`/`new Function` may remain in the bundle (CSP has no 'unsafe-eval').
  define: { 'process.env.NODE_ENV': '"production"' },
});
const outs = Object.keys(app.metafile.outputs).map((f) => f.replace(/^dist\//, ''));
const js = outs.find((f) => f.endsWith('.js'));
const css = outs.find((f) => f.endsWith('.css'));
if (!js || !css) throw new Error('expected one JS and one CSS output');

await cp(join(root, 'public/icon.svg'), join(dist, 'icon.svg'));
await cp(join(root, 'public/manifest.webmanifest'), join(dist, 'manifest.webmanifest'));

const index = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#1f5f5b">
<meta name="referrer" content="no-referrer">
<title>Family Vault</title>
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="stylesheet" href="/${css}">
</head>
<body>
<div id="app"></div>
<noscript>Family Vault needs JavaScript: all encryption happens in your browser.</noscript>
<script type="module" src="/${js}"></script>
</body>
</html>
`;
await writeFile(join(dist, 'index.html'), index);

// SHA-256 manifest of every shell asset, embedded in sw.js (integrity check before caching).
const sha = async (rel) => createHash('sha256').update(await readFile(join(dist, rel))).digest('hex');
const manifest = { '/': await sha('index.html'), [`/${js}`]: await sha(js), [`/${css}`]: await sha(css), '/icon.svg': await sha('icon.svg'), '/manifest.webmanifest': await sha('manifest.webmanifest') };
const buildId = createHash('sha256').update(index).update(await readFile(join(dist, js))).update(await readFile(join(dist, css))).digest('hex').slice(0, 16);
await build({
  ...common,
  entryPoints: ['src/sw.ts'],
  outfile: 'dist/sw.js',
  format: 'iife',
  tsconfig: 'tsconfig.sw.json',
  define: { __MANIFEST__: JSON.stringify(manifest), __BUILD_ID__: JSON.stringify(buildId) },
});

async function walk(d) {
  const out = [];
  for (const e of await readdir(d, { withFileTypes: true })) {
    const p = join(d, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out.sort();
}
let total = 0;
for (const f of await walk(dist)) {
  const n = (await readFile(f)).length;
  total += n;
  console.log(`${String(n).padStart(9)}  ${relative(root, f)}`);
}
console.log(`${String(total).padStart(9)}  total (build ${buildId})`);
