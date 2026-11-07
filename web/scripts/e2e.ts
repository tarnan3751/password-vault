// End-to-end check of the REAL HTTP API using only src/api + src/vault (no UI).
//
//   npm run e2e -- --base http://127.0.0.1:8001 --bootstrap-token <t>
//
// Options:
//   --base <url>             any node of a running cluster (the others are learned from /v1/cluster)
//   --bootstrap-token <t>    registers the first user (only works on a cluster with no users)
//   --admin-user/--admin-password   use an existing admin instead of bootstrapping
//   --real                   start a temporary real vaultd cluster (needs ../bin/vaultd or Go) and run against it
//   --stub                   run against the in-memory stub from scripts/stub-server.ts
//                            (checks this script itself; NOT a test of the real server)
// Prints PASS/FAIL per step; exit code 1 if any step failed.
import { parseArgs } from 'node:util';
import { ApiClient, ApiError, newIdempotencyKey } from '../src/api/index.ts';
import { BackupError, newItem } from '../src/crypto/index.ts';
import { ConflictError, MemoryStore, NotVerifiedError, ReadOnlyError, Session, type Deps } from '../src/vault/index.ts';

const { values: args } = parseArgs({
  options: {
    base: { type: 'string' },
    'bootstrap-token': { type: 'string' },
    'admin-user': { type: 'string' },
    'admin-password': { type: 'string' },
    stub: { type: 'boolean', default: false },
    real: { type: 'boolean', default: false },
  },
});

let stopStub: (() => Promise<void>) | undefined;
let base = args.base;
let bootstrap = args['bootstrap-token'];
if (args.stub) {
  const { startStub } = await import('./stub-server.ts');
  const s = await startStub({ dist: new URL('../dist', import.meta.url).pathname });
  base = s.url;
  bootstrap = s.fake.bootstrapToken;
  stopStub = s.close;
  console.log(`(using in-memory stub server at ${base}; this validates the script, not the real server)`);
}
if (args.real) {
  // convenience: start a throw-away three-node vaultd cluster in a temp dir (see scripts/real-cluster.mjs)
  // @ts-expect-error plain JS helper without declarations
  const { startCluster } = await import('./real-cluster.mjs');
  const c = await startCluster();
  base = c.urls[0];
  bootstrap = c.token;
  stopStub = c.stop;
  console.log(`(using a temporary real cluster: ${c.urls.join(' ')})`);
}
if (!base) {
  console.error('usage: npm run e2e -- --base http://127.0.0.1:8001 --bootstrap-token <token>   (or --stub)');
  process.exit(2);
}
const BASE: string = base;

const sfx = Math.random().toString(36).slice(2, 7);
const PW_A = `alice e2e passphrase ${sfx} correct horse`;
const PW_B = `bob e2e passphrase ${sfx} staple battery`;
const PW_A2 = `alice NEW e2e passphrase ${sfx} purple monkey`;

const results: [string, boolean, string][] = [];
async function step(name: string, fn: () => Promise<void>, fatal = false): Promise<boolean> {
  const t0 = Date.now();
  try {
    await fn();
    results.push([name, true, '']);
    console.log(`PASS  ${name} (${Date.now() - t0} ms)`);
    return true;
  } catch (e) {
    const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    results.push([name, false, msg]);
    console.log(`FAIL  ${name}\n        ${msg}`);
    if (fatal) throw new Error('fatal step failed; aborting');
    return false;
  }
}
function must(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}
async function rejectsWith(fn: () => Promise<unknown>, test: (e: unknown) => boolean, what: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    if (test(e)) return;
    throw new Error(`${what}: wrong error ${e instanceof Error ? e.name + ': ' + e.message : e}`);
  }
  throw new Error(`${what}: expected a failure but it succeeded`);
}
const mkDeps = (): Deps => ({ api: new ApiClient({ nodes: [BASE], allowInsecureLearned: BASE.startsWith('http:') }), store: new MemoryStore() });
/** the person at a's device compares b's fingerprint (here: both are in this process) and verifies */
async function verifyBack(a: Session, b: Session): Promise<void> {
  const seen = a.contacts().find((c) => c.userId === b.userId);
  if (seen && !seen.verified && seen.fingerprint === b.fingerprint) await a.markVerified(b.userId);
}
const login = (n: string) => newItem('login', 0) && Object.assign(newItem('login', 0), { name: n });

let alice!: Session, bob!: Session, aliceName = '', bobName = '';
let sharedVault = '';
const itemIds: string[] = [];

try {
  await step('cluster: health and node discovery', async () => {
    const d = mkDeps();
    const h = await d.api.health();
    must(typeof h.node_id === 'string' && h.node_id, 'health has node_id');
    const c = await d.api.refreshCluster();
    must(c.nodes.length >= 1, 'cluster lists nodes');
    console.log(`        nodes: ${d.api.nodeUrls.join(', ')}  has_users=${h.has_users}`);
  });

  await step('register first user (alice) with the bootstrap token, becomes admin', async () => {
    if (args['admin-user']) {
      alice = await Session.login(mkDeps(), { username: args['admin-user'], password: args['admin-password'] ?? '' });
      aliceName = alice.username;
    } else {
      must(bootstrap, 'pass --bootstrap-token (or --admin-user/--admin-password)');
      aliceName = `alice-${sfx}`;
      alice = await Session.register(mkDeps(), { username: aliceName, password: PW_A, inviteCode: bootstrap });
    }
    must(alice.isAdmin, 'first user is an admin');
    must(alice.vaults.some((v) => v.personal), 'personal vault exists');
  }, true);

  let invite = '';
  await step('alice creates an invite', async () => {
    const r = await alice.createInvite(24);
    invite = r.code;
    must(/^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/.test(invite), 'invite code format');
    const list = await alice.listInvites();
    must(list.some((i) => i.invite_id === r.invite_id), 'invite is listed');
  }, true);

  await step('register bob with the invite', async () => {
    bobName = `bob-${sfx}`;
    bob = await Session.register(mkDeps(), { username: bobName, password: PW_B, inviteCode: invite });
    must(!bob.isAdmin, 'bob is not an admin');
  }, true);

  await step('invite is single-use', async () => {
    await rejectsWith(() => Session.register(mkDeps(), { username: `eve-${sfx}`, password: PW_B, inviteCode: invite }), (e) => e instanceof ApiError && e.code === 'invalid_invite', 'reuse');
  });

  await step('login with wrong password fails; right password works from a fresh device', async () => {
    await rejectsWith(() => Session.login(mkDeps(), { username: aliceName, password: 'nope nope nope' }), (e) => e instanceof Error && /Wrong username or password/.test(e.message), 'wrong pw');
    if (!args['admin-user']) {
      const dev2 = await Session.login(mkDeps(), { username: aliceName, password: PW_A });
      must(dev2.userId === alice.userId, 'same user');
    }
  });

  await step('alice creates a shared vault with two items', async () => {
    await alice.sync();
    sharedVault = await alice.createVault('E2E Family');
    itemIds.push(await alice.createItem(sharedVault, Object.assign(login('Netflix'), { username: 'family@example.com', password: 'nf-pass-1', urls: ['https://netflix.example'] })));
    itemIds.push(await alice.createItem(sharedVault, Object.assign(newItem('note', 0), { name: 'Wifi', notes: 'router password: hunter2', extra: [{ rawKey: '"x_future"', rawValue: '{ "keep" : 12345678901234567890 }' }] })));
    must(alice.vault(sharedVault)!.items.length === 2, 'two items');
  }, true);

  await step('sharing needs verification: alice refuses to wrap for an unverified bob; after comparing fingerprints she shares', async () => {
    await alice.sync();
    const look = alice.lookupUser(bobName);
    must(look.fingerprint === bob.fingerprint, 'alice and bob see the same 128-bit fingerprint for bob');
    await rejectsWith(() => alice.addMember(sharedVault, bobName, 'editor'), (e) => e instanceof NotVerifiedError, 'unverified');
    await alice.markVerified(look.userId);
    await alice.addMember(sharedVault, bobName, 'editor');
    must(alice.vault(sharedVault)!.members.some((m) => m.username === bobName && m.role === 'editor'), 'roster lists bob');
  }, true);

  await step('bob sees the vault as PENDING (nothing decrypted) until he verifies alice, then reads it', async () => {
    await bob.sync();
    const v = bob.vault(sharedVault);
    must(v && v.state === 'pending' && v.items.length === 0, 'pending, closed');
    must(v.pending!.senderFingerprint === alice.fingerprint, 'bob is shown alice\'s fingerprint');
    await bob.acceptPending(sharedVault);
    const o = bob.vault(sharedVault)!;
    must(o.state === 'open' && o.name === 'E2E Family', 'bob sees the vault name');
    must(o.items.length === 2 && o.items.every((i) => i.item), 'bob decrypts both items');
    must(o.items.find((i) => i.item?.name === 'Netflix')?.item?.password === 'nf-pass-1', 'password readable');
  }, true);

  await step('bob edits; alice sees the change; unknown fields survive', async () => {
    const id = itemIds[0]!;
    await bob.updateItem(sharedVault, id, (x) => void (x.password = 'nf-pass-2'));
    await alice.sync();
    const it = alice.vault(sharedVault)!.items.find((i) => i.id === id)!.item!;
    must(it.password === 'nf-pass-2' && it.password_history[0]?.password === 'nf-pass-1', 'edit + history visible');
    await bob.updateItem(sharedVault, itemIds[1]!, (x) => void (x.notes += ' (edited)'));
    await alice.sync();
    must(alice.vault(sharedVault)!.items.find((i) => i.id === itemIds[1])!.item!.extra[0]?.rawValue === '{ "keep" : 12345678901234567890 }', 'x_future preserved byte for byte through another client');
  });

  await step('optimistic concurrency: stale edit is a ConflictError, nothing overwritten', async () => {
    const id = itemIds[0]!;
    const opened = alice.vault(sharedVault)!.items.find((i) => i.id === id)!;
    await bob.updateItem(sharedVault, id, (x) => void (x.notes = 'bob was here'));
    await rejectsWith(() => alice.updateItem(sharedVault, id, (x) => void (x.password = 'alice-stale'), { base: opened }), (e) => e instanceof ConflictError, 'client-side base check');
    // and the server-side 409 itself (alice has NOT synced since bob's write)
    const stale = await Session.login(mkDeps(), { username: bobName, password: PW_B });
    await stale.acceptPending(sharedVault); // a second device of bob has no memory: pending until alice is verified there too
    await bob.updateItem(sharedVault, id, (x) => void (x.notes = 'bob again'));
    await rejectsWith(() => stale.updateItem(sharedVault, id, (x) => void (x.password = 'stale-write')), (e) => e instanceof ConflictError && e.theirs?.item?.notes === 'bob again', 'server 409 version_conflict');
    await alice.sync();
    must(alice.vault(sharedVault)!.items.find((i) => i.id === id)!.item!.password === 'nf-pass-2', 'password unchanged');
  });

  await step('idempotency: same Idempotency-Key replays the first result', async () => {
    const api = alice.api;
    const key = newIdempotencyKey();
    const { blobFor } = await import('./e2e-helpers.ts');
    const id = blobFor.newId();
    const body = { blob: blobFor.blob(alice, sharedVault, id), base_version: 0, key_epoch: alice.vault(sharedVault)!.keyEpoch };
    const r1 = await api.request<{ rev: number }>('PUT', `/v1/vaults/${sharedVault}/items/${id}`, body, { auth: true, mutation: true, idempotencyKey: key });
    const r2 = await api.request<{ rev: number }>('PUT', `/v1/vaults/${sharedVault}/items/${id}`, body, { auth: true, mutation: true, idempotencyKey: key });
    must(r1.rev === r2.rev, `replay returned the same rev (${r1.rev} vs ${r2.rev})`);
    // a different key for the same create is a genuine duplicate -> 409
    await rejectsWith(() => api.request('PUT', `/v1/vaults/${sharedVault}/items/${id}`, body, { auth: true, mutation: true }), (e) => e instanceof ApiError && e.code === 'version_conflict', 'new key conflicts');
    await alice.sync();
    itemIds.push(id);
  });

  await step('alice removes bob: ONE atomic rekey request (remove + new key + new roster)', async () => {
    const before = alice.vault(sharedVault)!.keyEpoch;
    bob.vault(sharedVault); // bob keeps his old copy in memory: it must be useless afterwards
    await bob.markVerified(alice.userId).catch(() => {});
    await verifyBack(alice, bob);
    await alice.removeMember(sharedVault, bob.userId);
    const v = alice.vault(sharedVault)!;
    must(v.keyEpoch === before + 1 && !v.rekeyRecommended, 'epoch bumped, rekey_recommended cleared');
    must(v.members.length === 1 && v.rosterStatus === 'ok' && v.items.every((i) => i.item), 'roster without bob; items still decrypt after rekey');
    must(v.items.find((i) => i.id === itemIds[0])!.item!.password === 'nf-pass-2', 'content intact');
  }, true);

  await step('bob can no longer read or write the vault', async () => {
    await bob.sync();
    must(!bob.vault(sharedVault), 'vault gone from bob\'s sync');
    // A well-formed (60-byte) blob: the server reports malformed input before
    // it checks permissions, so a too-short blob would never reach the check
    // this step is about.
    await rejectsWith(() => bob.api.putItem(sharedVault, itemIds[0]!, { blob: 'A'.repeat(80), base_version: 1, key_epoch: 1 }), (e) => e instanceof ApiError && (e.code === 'not_found' || e.code === 'forbidden'), 'bob write');
  });

  await step('alice changes her master password; old password and old token are dead', async () => {
    if (args['admin-user']) return void console.log('        (skipped: using an existing admin account)');
    const oldTok = alice.api.token!;
    await alice.changePassword(PW_A, PW_A2);
    const stale = new ApiClient({ nodes: [BASE] });
    stale.token = oldTok;
    await rejectsWith(() => stale.sync(), (e) => e instanceof ApiError && e.code === 'unauthorized', 'old token');
    await rejectsWith(() => Session.login(mkDeps(), { username: aliceName, password: PW_A }), (e) => e instanceof Error && /Wrong username or password/.test(e.message), 'old password');
    const again = await Session.login(mkDeps(), { username: aliceName, password: PW_A2 });
    must(again.vault(sharedVault)?.items.length === 3, 'all data readable with the new password');
  });

  await step('offline cache: unlock without the network from the cached sync', async () => {
    const store = (alice as unknown as { deps: { store: MemoryStore } }).deps.store;
    alice.lock();
    const dead = new ApiClient({ nodes: ['http://127.0.0.1:1'], timeoutMs: 2000 });
    const off = await Session.unlockOffline({ api: dead, store }, { username: aliceName, password: args['admin-user'] ? (args['admin-password'] ?? '') : PW_A2 });
    must(off.mode === 'offline' && off.vault(sharedVault)!.items.length === 3, 'cached data readable');
    await rejectsWith(() => off.createVault('nope'), (e) => e instanceof ReadOnlyError, 'offline write refused');
    alice = off;
  });

  await step('backup: export (separate passphrase) then import into new vaults', async () => {
    const live = await Session.login(mkDeps(), { username: aliceName, password: args['admin-user'] ? (args['admin-password'] ?? '') : PW_A2 });
    alice = live;
    const out = await live.exportBackup('e2e backup passphrase ' + sfx);
    must(out.items >= 3 && !out.text.includes('nf-pass-2') && !out.text.includes('hunter2'), 'ciphertext only');
    await rejectsWith(() => live.inspectBackup(out.text, 'wrong passphrase'), (e) => e instanceof BackupError && e.code === 'decrypt', 'wrong passphrase');
    const payload = await live.inspectBackup(out.text, 'e2e backup passphrase ' + sfx);
    const before = live.vaults.length;
    const res = await live.importBackup(payload);
    must(res.failed === 0 && res.items === out.items, `imported ${res.items}/${out.items}`);
    must(live.vaults.length === before + out.vaults, 'new vaults created');
    const copy = live.vaults.find((v) => v.name === 'E2E Family (restored)')!;
    must(copy.items.length === 3 && copy.items.some((i) => i.item?.password === 'nf-pass-2'), 'restored content');
    must(copy.id !== sharedVault, 'restored into a NEW vault id');
  });

  await step('revoke sessions: other devices are signed out', async () => {
    if (args['admin-user']) return void console.log('        (skipped)');
    const other = new ApiClient({ nodes: [BASE] });
    other.token = alice.api.token!;
    await alice.revokeSessions();
    await rejectsWith(() => other.sync(), (e) => e instanceof ApiError && e.code === 'unauthorized', 'old token after revoke');
    await alice.sync();
  });

  await step('admin: user list, cluster status', async () => {
    const st = await alice.clusterStatus();
    must(st.nodes.some((n) => n.ok), 'some node reachable');
    must(st.admin !== undefined, 'admin cluster endpoint answered');
    must(alice.directoryUsers().length >= 2, 'directory lists household members');
    console.log(`        nodes: ${st.nodes.map((n) => `${n.node}:${n.ok ? (n.health?.role ?? 'up') : 'DOWN'}`).join('  ')}`);
  });
} catch {
  /* a fatal step failed; summary below */
} finally {
  await stopStub?.();
}

const failed = results.filter((r) => !r[1]);
console.log(`\n${results.length - failed.length}/${results.length} steps passed${failed.length ? `; FAILED: ${failed.map((f) => f[0]).join('; ')}` : ''}`);
process.exit(failed.length ? 1 : 0);
