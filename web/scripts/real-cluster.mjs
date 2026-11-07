// Starts a REAL three-node vaultd cluster on free loopback ports in a temp dir
// (plain-HTTP "insecure" mode, which vaultd permits on loopback only). Nothing
// here touches the repo's .dev directory or scripts/dev-cluster.sh ports.
// Always call stop(): it kills the processes and removes the temp dir.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));

async function freePorts(n) {
  const servers = [];
  const ports = [];
  for (let i = 0; i < n; i++) {
    const s = createServer();
    await new Promise((r) => s.listen(0, '127.0.0.1', r));
    ports.push(s.address().port);
    servers.push(s);
  }
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  return ports;
}

export function ensureBinary() {
  // The web UI is embedded in the binary, so always rebuild (incremental, a second or two when
  // nothing changed): a stale bin/vaultd would serve a stale web/dist.
  const bin = join(root, 'bin/vaultd');
  const r = spawnSync('go', ['build', '-o', bin, './cmd/vaultd'], { cwd: root, stdio: 'inherit' });
  if (r.status !== 0 && !existsSync(bin)) throw new Error('go build ./cmd/vaultd failed');
  if (r.status !== 0) console.warn('go build failed; using the existing bin/vaultd (its embedded web UI may be stale)');
  return bin;
}

export async function startCluster({ log = false } = {}) {
  const bin = ensureBinary();
  const dir = mkdtempSync(join(tmpdir(), 'fvault-real-'));
  const token = 'real-cluster-bootstrap-' + Math.random().toString(36).slice(2, 12);
  const ports = await freePorts(6);
  const peers = [0, 1, 2].map((i) => ({ id: `n${i + 1}`, peer_addr: `127.0.0.1:${ports[3 + i]}`, public_url: `http://127.0.0.1:${ports[i]}` }));
  const nodes = peers.map((p, i) => {
    const d = join(dir, `n${i + 1}`);
    mkdirSync(d, { recursive: true });
    const cfg = join(d, 'config.json');
    writeFileSync(cfg, JSON.stringify({
      node_id: p.id, data_dir: join(d, 'data'), client_listen: `127.0.0.1:${ports[i]}`, peer_listen: `127.0.0.1:${ports[3 + i]}`,
      peers, bootstrap_token: token, insecure: true,
    }, null, 2));
    return { id: p.id, url: p.public_url, cfg, proc: null };
  });
  const startNode = (n) => {
    n.proc = spawn(bin, ['run', '--config', n.cfg], { stdio: log ? 'inherit' : 'ignore' });
    n.proc.on('exit', () => (n.proc = null));
  };
  const stopNode = async (n) => {
    if (!n.proc) return;
    const p = n.proc;
    p.kill('SIGKILL');
    await new Promise((r) => (p.exitCode !== null ? r() : p.once('exit', r)));
    n.proc = null;
  };
  // "ready" = answering AND the cluster's init command has been applied on that node (only then are
  // registrations accepted; before that the API answers 503 "cluster is not initialized yet").
  const healthy = async (n) => {
    try {
      const r = await fetch(n.url + '/v1/health', { signal: AbortSignal.timeout(1500) });
      return r.ok && (await r.json()).initialized === true;
    } catch {
      return false;
    }
  };
  const waitFor = async (what, fn, ms = 30000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      if (await fn()) return;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`timeout waiting for ${what}`);
  };
  const cluster = {
    dir, token, nodes, urls: nodes.map((n) => n.url),
    kill: (i) => stopNode(nodes[i]),
    restart: async (i) => {
      await stopNode(nodes[i]);
      startNode(nodes[i]);
      await waitFor(`${nodes[i].id} ready`, () => healthy(nodes[i]));
    },
    killAll: () => Promise.all(nodes.map(stopNode)),
    /** start every node that is down, then wait until all are ready and a leader exists */
    startAll: async () => {
      for (const n of nodes) if (!n.proc) startNode(n);
      await Promise.all(nodes.map((n) => waitFor(`${n.id} ready`, () => healthy(n))));
      await cluster.waitForLeader();
    },
    waitForLeader: () => waitFor('a leader', async () => {
      for (const n of nodes) {
        try {
          const h = await (await fetch(n.url + '/v1/health', { signal: AbortSignal.timeout(1500) })).json();
          if (h.role === 'leader') return true;
        } catch { /* down */ }
      }
      return false;
    }),
    stop: async () => {
      await Promise.all(nodes.map(stopNode));
      rmSync(dir, { recursive: true, force: true });
    },
  };
  try {
    nodes.forEach(startNode);
    await Promise.all(nodes.map((n) => waitFor(`${n.id} ready (initialized)`, () => healthy(n))));
    await cluster.waitForLeader();
  } catch (e) {
    await cluster.stop();
    throw e;
  }
  return cluster;
}
