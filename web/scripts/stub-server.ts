// A stand-in for vaultd for browser smoke tests: serves web/dist with the real
// Content-Security-Policy and SPA fallback, and implements the HTTP API with the
// in-memory fake from test/fake-server.ts. NOT the real server.
import { createServer, type Server } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { FakeServer } from '../test/fake-server.ts';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json',
};

export interface Stub {
  url: string;
  fake: FakeServer;
  server: Server;
  csp: string;
  close: () => Promise<void>;
}

export async function startStub(opts: { port?: number; dist: string; peers?: string[] }): Promise<Stub> {
  let fake!: FakeServer;
  let origin = '';
  const connect = ["'self'", ...(opts.peers ?? [])].join(' ');
  const csp = `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src ${connect}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', origin);
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    if (url.pathname.startsWith('/v1/')) {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v;
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined;
      const r = fake.handle(origin, req.method ?? 'GET', url.pathname, url.searchParams, headers, body);
      res.writeHead(r.status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type, Idempotency-Key', 'Access-Control-Allow-Methods': '*' });
      res.end(JSON.stringify(r.body));
      return;
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type, Idempotency-Key', 'Access-Control-Allow-Methods': '*' });
      res.end();
      return;
    }
    let file = join(opts.dist, normalize(url.pathname).replace(/^(\.\.[/\\])+/, ''));
    let ok = false;
    try {
      ok = (await stat(file)).isFile();
    } catch {
      /* fall through to SPA */
    }
    if (!ok) file = join(opts.dist, 'index.html'); // unknown non-/v1 paths fall back to the SPA
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] ?? 'application/octet-stream', 'Content-Security-Policy': csp, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-cache' });
    res.end(await readFile(file));
  });
  await new Promise<void>((r) => server.listen(opts.port ?? 0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  fake = new FakeServer([origin]);
  return { url: origin, fake, server, csp, close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const s = await startStub({ port: Number(process.env.PORT ?? 8099), dist: new URL('../dist', import.meta.url).pathname });
  console.log(`stub server on ${s.url}  bootstrap token: ${s.fake.bootstrapToken}`);
}
