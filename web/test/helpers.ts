import { ApiClient } from '../src/api/index.ts';
import { newItem, randomBytes, type KdfParams } from '../src/crypto/index.ts';
import { MemoryStore, Session, type Deps } from '../src/vault/index.ts';
import { FakeServer } from './fake-server.ts';

export const URLS = ['http://n1.test:8001', 'http://n2.test:8002', 'http://n3.test:8003'];
/** The smallest parameters the client floor accepts: keeps the suite fast. */
export const cheap = (): KdfParams => ({ alg: 'argon2id', salt: randomBytes(16), time: 3, memory_kib: 65536, parallelism: 1 });
export const PW_A = 'alice correct horse battery staple';
export const PW_B = 'bob staple battery horse correct';
export const PW_C = 'carol purple monkey dishwasher lamp';

/** Mutates the JSON of /v1/sync answers (a lying server). `fn` returns a replacement or mutates in place. */
export interface Tamper {
  fn: ((j: any) => any) | null;
}

export function deps(server: FakeServer, store = new MemoryStore(), tamper?: Tamper, nodes = URLS): Deps & { store: MemoryStore } {
  const fetch = async (u: string, i?: RequestInit) => {
    const r = await server.fetch(u, i);
    if (!tamper?.fn || !u.includes('/v1/sync') || !r.ok) return r;
    const j = await r.json();
    return new Response(JSON.stringify(tamper.fn(j) ?? j), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  };
  return { api: new ApiClient({ nodes, fetch, retryDelayMs: 1, allowInsecureLearned: true }), store };
}

export async function world() {
  const server = new FakeServer(URLS);
  const aliceDeps = deps(server);
  const alice = await Session.register(aliceDeps, { username: 'Alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const invite = await alice.createInvite(24);
  const bobDeps = deps(server);
  const bob = await Session.register(bobDeps, { username: 'bob', password: PW_B, inviteCode: invite.code, kdf: cheap() });
  await alice.sync();
  await bob.sync();
  return { server, alice, bob, aliceDeps, bobDeps };
}

/** a's device marks b as verified after checking both sides display the same fingerprint (what the person does out of band). */
export async function verify(a: Session, b: Session): Promise<void> {
  const seen = a.contacts().find((c) => c.userId === b.userId)!;
  if (seen.fingerprint !== b.fingerprint) throw new Error('fingerprints differ');
  await a.markVerified(b.userId);
}

export function login(item: Partial<ReturnType<typeof newItem>> & { name: string }) {
  return { ...newItem('login', 0), ...item };
}

/** non-GET requests to vault endpoints since `mark` (for "nothing was written") */
export function writesSince(server: FakeServer, mark: number): string[] {
  return server.log.slice(mark).filter((l) => l.method !== 'GET' && l.path.startsWith('/v1/vaults')).map((l) => `${l.method} ${l.path}`);
}

export const priv = (s: Session) => s as unknown as { privateKey: Uint8Array; publicKey: Uint8Array; secrets: Map<string, { vk: Uint8Array; epoch: number }>; deps: { store: MemoryStore; api: ApiClient }; raw: any };
