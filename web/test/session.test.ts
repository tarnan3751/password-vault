// Vault session logic against an in-memory fake of the (revised) server API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient } from '../src/api/index.ts';
import { BackupError, b64decode, b64encode, newItem, randomBytes, KdfParamsError, wrapVaultKey, encryptRoster, vaultKeyCommitment, encryptVaultMeta, encryptItem, type Roster } from '../src/crypto/index.ts';
import {
  ConflictError, IdentityMismatchError, InvalidSyncError, KeyMismatchError, MemoryStore, NoCacheError, NotVerifiedError, PermissionError, ReadOnlyError,
  RecoveryRefusedError, RollbackError, RosterUnreadableError, Session, UnlistedMemberError, WrongPasswordError, SessionExpiredError,
} from '../src/vault/index.ts';
import { FakeServer } from './fake-server.ts';
import { URLS, PW_A, PW_B, PW_C, cheap, deps, login, priv, verify, world, writesSince, type Tamper } from './helpers.ts';

const nothingWritten = (server: FakeServer, mark: number) => assert.deepEqual(writesSince(server, mark), [], 'nothing was written to any vault');

// ---------------------------------------------------------------- normal flows

test('register: personal vault with roster, bootstrap admin, trust recorded, items CRUD with history', async () => {
  const server = new FakeServer(URLS);
  const d = deps(server);
  const alice = await Session.register(d, { username: ' ALICE ', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  assert.equal(alice.username, 'alice');
  assert.ok(alice.isAdmin);
  assert.equal(alice.vaults.length, 1);
  const pv = alice.vaults[0]!;
  assert.ok(pv.personal && pv.name === 'Personal' && pv.role === 'owner' && pv.keyEpoch === 1 && pv.state === 'open' && pv.rosterStatus === 'ok');
  assert.deepEqual(pv.members.map((m) => [m.username, m.role, m.isSelf]), [['alice', 'owner', true]]);
  assert.equal(alice.trust.vaults.get(pv.id)!.epoch, 1);
  const sv = server.vaults.get(pv.id)!;
  assert.ok(sv.encRoster && sv.rosterVersion === sv.metaVersion);

  const id = await alice.createItem(pv.id, login({ name: 'Bank', username: 'a@x.org', password: 'pw1', urls: ['https://bank.example'], tags: ['fin'] }));
  await alice.updateItem(pv.id, id, (x) => void (x.password = 'pw2'));
  const it = alice.vault(pv.id)!.items[0]!;
  assert.equal(it.item!.password, 'pw2');
  assert.deepEqual(it.item!.password_history.map((h) => h.password), ['pw1']);
  await alice.deleteItem(pv.id, id);
  assert.equal(alice.vault(pv.id)!.items.length, 0);
  assert.ok(!JSON.stringify(sv).includes('Personal'));
  await assert.rejects(() => Session.register(deps(server), { username: 'carol', password: PW_C, inviteCode: 'NOPE', kdf: cheap() }), /invite|Invite|invalid/i);
});

test('registration refuses KDF parameters below the floor and passwords nobody checked', async () => {
  const server = new FakeServer(URLS);
  await assert.rejects(() => Session.register(deps(server), { username: 'x', password: 'pw', inviteCode: server.bootstrapToken, kdf: { ...cheap(), time: 2 } }), KdfParamsError);
  assert.equal(server.users.size, 0);
});

test('login: wrong password, unknown user, weak server-supplied KDF refused before any login key is sent', async () => {
  const { server } = await world();
  await assert.rejects(() => Session.login(deps(server), { username: 'alice', password: 'nope' }), WrongPasswordError);
  await assert.rejects(() => Session.login(deps(server), { username: 'ghost', password: 'nope' }), WrongPasswordError);
  assert.equal((await Session.login(deps(server), { username: 'ALICE', password: PW_A })).username, 'alice');
  server.kdfOverride = { alg: 'argon2id', salt: b64encode(randomBytes(16)), time: 1, memory_kib: 64, parallelism: 1 };
  server.log.length = 0;
  await assert.rejects(() => Session.login(deps(server), { username: 'alice', password: PW_A }), KdfParamsError);
  assert.ok(!server.log.some((l) => l.path === '/v1/login'), 'no login key was sent');
});

test('sharing needs a verified contact; a new share is PENDING on the other device until its sender is verified', async () => {
  const { server, alice, bob } = await world();
  const vid = await alice.createVault('Family');
  const i1 = await alice.createItem(vid, login({ name: 'Netflix', password: 'nf1' }));
  const mark = server.log.length;
  // 1. alice has never compared bob's fingerprint: refused, nothing sent
  const look = alice.lookupUser('bob');
  assert.equal(look.verified, false);
  assert.match(look.fingerprint, /^([0-9a-f]{4}-){7}[0-9a-f]{4}$/);
  assert.equal(look.fingerprint, bob.fingerprint, 'alice sees the fingerprint bob sees for himself');
  await assert.rejects(() => alice.addMember(vid, 'bob', 'viewer'), NotVerifiedError);
  nothingWritten(server, mark);
  // 2. verified: wrapped to the trust-store key, roster uploaded with the member
  await verify(alice, bob);
  await alice.addMember(vid, 'bob', 'editor');
  assert.deepEqual(alice.vault(vid)!.members.map((m) => [m.username, m.role]).sort(), [['alice', 'owner'], ['bob', 'editor']]);
  const put = server.log.filter((l) => l.method === 'PUT' && l.path.includes('/members/'));
  assert.equal(put.length, 1);
  // 3. bob has not verified alice: the vault is pending, NOTHING decrypted, nothing written by bob
  const mark2 = server.log.length;
  await bob.sync();
  let bv = bob.vault(vid)!;
  assert.equal(bv.state, 'pending');
  assert.equal(bv.items.length, 0);
  assert.equal(bv.pending!.senderName, 'alice');
  assert.equal(bv.pending!.senderFingerprint, alice.fingerprint);
  assert.equal(bv.pending!.replacedByNonOwner, false);
  assert.equal(bob.pendingShares().length, 1);
  await assert.rejects(() => bob.createItem(vid, login({ name: 'x' })), /not open/);
  nothingWritten(server, mark2);
  assert.equal(bob.trust.vaults.has(vid), false, 'nothing recorded for a pending vault');
  // 4. accepting verifies the sender and opens it
  await bob.acceptPending(vid);
  bv = bob.vault(vid)!;
  assert.equal(bv.state, 'open');
  assert.equal(bv.name, 'Family');
  assert.equal(bv.items.find((i) => i.id === i1)!.item!.password, 'nf1');
  assert.ok(bob.contacts().find((c) => c.userId === alice.userId)!.verified);
  assert.ok(bv.members.every((m) => !m.discrepancy));
  // 5. a SECOND device of bob has no memory: pending again, then accept there too
  const bob2 = await Session.login(deps(server), { username: 'bob', password: PW_B });
  assert.equal(bob2.vault(vid)!.state, 'pending');
  await bob2.acceptPending(vid);
  assert.equal(bob2.vault(vid)!.items.length, 1);
  // 6. roles: editor can edit, cannot manage; owner changes a role through the roster
  await bob.updateItem(vid, i1, (x) => void (x.password = 'nf2'));
  await assert.rejects(() => bob.renameVault(vid, 'x'), PermissionError);
  await alice.sync();
  assert.equal(alice.vault(vid)!.items[0]!.item!.password, 'nf2');
  await alice.setMemberRole(vid, bob.userId, 'viewer');
  assert.equal(server.vaults.get(vid)!.members.get(bob.userId)!.role, 'viewer');
  assert.equal(alice.vault(vid)!.members.find((m) => m.username === 'bob')!.role, 'viewer');
  await bob.sync();
  await assert.rejects(() => bob.updateItem(vid, i1, (x) => void (x.password = 'hax')), ReadOnlyError);
  await assert.rejects(() => alice.addMember(alice.vaults.find((v) => v.personal)!.id, 'bob', 'viewer'), PermissionError, 'personal vault cannot be shared');
});

test('remove member = ONE atomic rekey request with `remove` (no separate DELETE); roster and key change; unknown members survive', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  await verify(bob, alice);
  const vid = await alice.createVault('Family');
  const i1 = await alice.createItem(vid, { ...login({ name: 'Wifi', password: 'w' }), extra: [{ rawKey: '"x_future"', rawValue: '12345678901234567890' }] });
  await alice.addMember(vid, 'bob', 'editor');
  await bob.sync();
  const oldBlobs = [...server.vaults.get(vid)!.items.values()].map((i) => i.blob);
  const mark = server.log.length;
  // the plan lists exactly who gets the new key, before anything is sent
  const plan = alice.planRekey(vid, { remove: [bob.userId] });
  assert.deepEqual(plan.recipients.map((r) => r.username), ['alice']);
  assert.deepEqual(plan.removed.map((r) => r.username), ['bob']);
  assert.equal(plan.epoch, 2);
  nothingWritten(server, mark);
  // the new key's commitment is recorded in the trust store BEFORE the request goes out
  let recordedDuringRequest = 0;
  const realFetch = server.fetch;
  server.fetch = async (u, i) => {
    if (i?.method === 'POST' && u.endsWith('/rekey')) recordedDuringRequest = alice.trust.vaults.get(vid)!.epoch;
    return realFetch(u, i);
  };
  const progress: string[] = [];
  await alice.executeRekey(plan, (p) => progress.push(`${p.done}/${p.total}`));
  assert.equal(recordedDuringRequest, 2, 'epoch + commitment recorded before sending');
  const reqs = writesSince(server, mark);
  assert.deepEqual(reqs, [`POST /v1/vaults/${vid}/rekey`], 'a single atomic request, no DELETE member');
  const v = alice.vault(vid)!;
  assert.equal(v.keyEpoch, 2);
  assert.equal(v.rekeyRecommended, false);
  assert.deepEqual(v.members.map((m) => m.username), ['alice']);
  assert.equal(server.vaults.get(vid)!.members.has(bob.userId), false);
  assert.ok([...server.vaults.get(vid)!.items.values()].every((i) => !oldBlobs.includes(i.blob)), 'every item re-encrypted');
  assert.equal(v.items.find((i) => i.id === i1)!.item!.extra[0]!.rawValue, '12345678901234567890', 'unknown member kept byte for byte through the raw re-encryption');
  assert.ok(progress.length >= 3);
  await bob.sync();
  assert.equal(bob.vault(vid), undefined);
  // the removed member never gets the key back, even by asking for a "rekey" with himself listed
  assert.throws(() => bob.planRekey(vid), /not open/);
});

test('leave, then an owner rekeys: recipients exclude whoever the server no longer lists', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  await verify(bob, alice);
  const vid = await alice.createVault('V');
  await alice.createItem(vid, login({ name: 'a' }));
  await alice.addMember(vid, 'bob', 'editor');
  await bob.sync();
  await bob.leaveVault(vid);
  assert.equal(bob.vault(vid), undefined);
  await alice.sync();
  const v = alice.vault(vid)!;
  assert.ok(v.rekeyRecommended);
  assert.equal(v.members.find((m) => m.username === 'bob')!.discrepancy, 'left');
  const plan = alice.planRekey(vid);
  assert.deepEqual(plan.recipients.map((r) => r.username), ['alice']);
  await alice.executeRekey(plan);
  const v2 = alice.vault(vid)!;
  assert.equal(v2.keyEpoch, 2);
  assert.deepEqual(v2.members.map((m) => m.username), ['alice']);
  assert.equal(v2.rekeyRecommended, false);
});

test('concurrent edit -> ConflictError (no silent overwrite); explicit resolution', async () => {
  const { server, alice } = await world();
  const pv = alice.vaults[0]!.id;
  const id = await alice.createItem(pv, login({ name: 'Shared', password: 'p0' }));
  const alice2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  await alice2.updateItem(pv, id, (x) => void (x.password = 'from-device-2'));
  const err = await alice.updateItem(pv, id, (x) => void (x.password = 'from-device-1')).catch((e) => e);
  assert.ok(err instanceof ConflictError);
  assert.equal(err.mine!.password, 'from-device-1');
  assert.equal(err.theirs!.item!.password, 'from-device-2');
  assert.equal(alice.vault(pv)!.items[0]!.item!.password, 'from-device-2');
  await alice.resolveConflict(err, 'overwrite');
  assert.equal(alice.vault(pv)!.items[0]!.item!.password, 'from-device-1');
  await alice2.sync();
  await alice2.updateItem(pv, id, (x) => void (x.notes = 'edited'));
  await assert.rejects(() => alice.deleteItem(pv, id), (e: unknown) => e instanceof ConflictError && e.kind === 'delete' && e.theirs!.item!.notes === 'edited');
  assert.equal(alice.vault(pv)!.items.length, 1);
});

test('an editor open while another device saved gets a conflict, not a silent overwrite', async () => {
  const { server, alice } = await world();
  const pv = alice.vaults[0]!.id;
  const id = await alice.createItem(pv, login({ name: 'Doc', password: 'p0' }));
  const opened = alice.vault(pv)!.items.find((i) => i.id === id)!;
  const dev2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  await dev2.updateItem(pv, id, (x) => void (x.notes = 'dev2 note'));
  await alice.sync();
  await assert.rejects(() => alice.updateItem(pv, id, (x) => void (x.password = 'p-from-editor'), { base: opened }), (e: unknown) => e instanceof ConflictError && e.theirs!.item!.notes === 'dev2 note');
  assert.equal(alice.vault(pv)!.items[0]!.item!.password, 'p0');
});

test('stale key epoch is retried after a sync; a rekey-only version bump is rebased silently', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('E');
  const id = await alice.createItem(vid, login({ name: 'x', password: 'p' }));
  const other = await Session.login(deps(server), { username: 'alice', password: PW_A });
  await other.rekeyVault(vid);
  const id2 = await alice.createItem(vid, login({ name: 'new after rekey' }));
  assert.equal(alice.vault(vid)!.keyEpoch, 2);
  assert.ok(alice.vault(vid)!.items.some((i) => i.id === id2));
  await alice.updateItem(vid, id, (x) => void (x.notes = 'after rekey'));
  assert.equal(alice.vault(vid)!.items.find((i) => i.id === id)!.item!.notes, 'after rekey');
});

test('password change: new account block verified before the old key is dropped; old password dead everywhere, cache replaced', async () => {
  const { server, alice, aliceDeps } = await world();
  const dev2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  await assert.rejects(() => alice.changePassword('wrong', 'whatever'), WrongPasswordError);
  await alice.changePassword(PW_A, 'a brand new strong passphrase');
  assert.equal(alice.mode, 'online');
  await alice.createItem(alice.vaults[0]!.id, login({ name: 'after change' }));
  await assert.rejects(() => Session.login(deps(server), { username: 'alice', password: PW_A }), WrongPasswordError);
  const again = await Session.login(deps(server), { username: 'alice', password: 'a brand new strong passphrase' });
  assert.equal(again.vaults[0]!.items.length, 1);
  await assert.rejects(() => dev2.sync(), /session ended|sign in again/i);
  assert.ok(dev2.locked);
  alice.lock();
  // the cached account block was replaced: the OLD password no longer unlocks this device offline
  const dead = new ApiClient({ nodes: ['http://127.0.0.1:1'], timeoutMs: 100 });
  await assert.rejects(() => Session.unlockOffline({ api: dead, store: aliceDeps.store }, { username: 'alice', password: PW_A }), WrongPasswordError);
  const off = await Session.unlockOffline({ api: dead, store: aliceDeps.store }, { username: 'alice', password: 'a brand new strong passphrase' });
  assert.equal(off.mode, 'offline');
});

test('password change: if the server did not store the new key material, the old cache is kept and an error is raised', async () => {
  const { server, alice, aliceDeps } = await world();
  const before = JSON.stringify(await aliceDeps.store.get('sync:alice'));
  const realFetch = server.fetch;
  // a lying server acknowledges the change but keeps serving the OLD wrapped account key
  const t: Tamper = { fn: null };
  const old = server.users.get(alice.userId)!.wrapped;
  const d = deps(server, aliceDeps.store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  t.fn = (j) => { if (j.account) j.account.wrapped_account_key = old; };
  void realFetch;
  await assert.rejects(() => alice.changePassword(PW_A, 'a brand new strong passphrase'), /did not store the new password material/);
  assert.equal(JSON.stringify(await aliceDeps.store.get('sync:alice')), before, 'cache untouched');
});

test('offline unlock from cache: read-only, wrong password, no cache, then reconnect without retyping', async () => {
  const server = new FakeServer(URLS);
  const store = new MemoryStore();
  const alice = await Session.register(deps(server, store), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const pv = alice.vaults[0]!.id;
  await alice.createItem(pv, login({ name: 'Cached', password: 'secret-pw' }));
  alice.lock();
  assert.equal(alice.vaults.length, 0);
  await assert.rejects(() => alice.sync(), ReadOnlyError);
  for (const n of URLS) server.node(n).down = true;
  const off = await Session.unlockOffline(deps(server, store), { username: 'alice', password: PW_A });
  assert.equal(off.mode, 'offline');
  assert.equal(off.canWrite, false);
  assert.equal(off.vaults[0]!.items[0]!.item!.password, 'secret-pw');
  assert.equal(off.trustResetReason, null);
  await assert.rejects(() => off.createItem(pv, login({ name: 'no' })), (e: unknown) => e instanceof ReadOnlyError && e.reason === 'offline');
  assert.equal(await off.refresh(), 'offline');
  assert.equal((await off.exportBackup('some passphrase here')).items, 1, 'backup works offline');
  await assert.rejects(() => Session.unlockOffline(deps(server, store), { username: 'alice', password: 'wrong' }), WrongPasswordError);
  await assert.rejects(() => Session.unlockOffline(deps(server, store), { username: 'bob', password: PW_A }), NoCacheError);
  for (const n of URLS) server.node(n).down = false;
  assert.equal(await off.refresh(), 'online');
  await off.createItem(pv, login({ name: 'online again' }));
  assert.equal(off.vault(pv)!.items.length, 2);
});

test('failover across nodes; no-quorum read falls back to stale and disables writes', async () => {
  const server = new FakeServer(URLS);
  const alice = await Session.register(deps(server), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const pv = alice.vaults[0]!.id;
  server.node(URLS[0]!).down = true;
  server.node(URLS[1]!).down = true;
  await alice.createItem(pv, login({ name: 'via n3' }));
  assert.equal(alice.api.currentNode, URLS[2]);
  server.node(URLS[2]!).unavailable = true;
  assert.equal(await alice.refresh(), 'stale');
  assert.ok(!alice.canWrite);
  await assert.rejects(() => alice.createItem(pv, login({ name: 'nope' })), (e: unknown) => e instanceof ReadOnlyError && e.reason === 'stale');
  const dev2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  assert.equal(dev2.mode, 'stale');
  server.node(URLS[2]!).unavailable = false;
  assert.equal(await alice.refresh(), 'online');
});

test('a write with unknown outcome is retried with one idempotency key and applied once', async () => {
  const server = new FakeServer(URLS);
  const alice = await Session.register(deps(server), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const pv = alice.vaults[0]!.id;
  server.outcomeUnknownNext = 1;
  await alice.createItem(pv, login({ name: 'once' }));
  assert.equal(server.vaults.get(pv)!.items.size, 1);
  const puts = server.log.filter((l) => l.method === 'PUT' && l.path.includes('/items/'));
  assert.ok(puts.length >= 2);
  assert.equal(new Set(puts.map((p) => p.headers['idempotency-key'])).size, 1);
});

test('unreadable entries: shown as such, never block a rekey or an export, carried over unchanged, deletable by a writer', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('R');
  const good = await alice.createItem(vid, login({ name: 'ok', password: 'fine' }));
  const bad = await alice.createItem(vid, login({ name: 'bad' }));
  const sv = server.vaults.get(vid)!.items.get(bad)!;
  const garbage = b64encode(randomBytes(80));
  sv.blob = garbage;
  sv.version = ++server.rev;
  await alice.sync();
  assert.ok(alice.vault(vid)!.items.find((i) => i.id === bad)!.error);
  const out = await alice.exportBackup('export passphrase here');
  assert.equal(out.skipped, 1);
  assert.equal(out.items >= 1, true);
  await alice.rekeyVault(vid); // does not throw
  assert.equal(server.vaults.get(vid)!.items.get(bad)!.blob, garbage, 'garbage carried over unchanged');
  assert.equal(alice.vault(vid)!.items.find((i) => i.id === good)!.item!.password, 'fine');
  await alice.deleteItem(vid, bad);
  assert.equal(alice.vault(vid)!.items.length, 1);
});

test('roster repair: an unreadable roster is rebuilt through a rekey, only with verified contacts and a confirmed list', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  await verify(bob, alice);
  const vid = await alice.createVault('Fam');
  await alice.addMember(vid, 'bob', 'viewer');
  const sv = server.vaults.get(vid)!;
  sv.encRoster = b64encode(randomBytes(120));
  sv.rosterVersion = ++server.rev;
  sv.rev = server.rev;
  await alice.sync();
  let v = alice.vault(vid)!;
  assert.equal(v.state, 'open');
  assert.equal(v.rosterStatus, 'unreadable');
  assert.throws(() => alice.planRekey(vid), RosterUnreadableError);
  await assert.rejects(() => alice.addMember(vid, 'bob', 'editor'), RosterUnreadableError);
  // repair with an unverified recipient is refused
  alice.trust.contacts.get(bob.userId)!.verified = false;
  const plan0 = alice.planRekey(vid, { repair: true });
  assert.deepEqual(plan0.unverified.map((r) => r.username), ['bob']);
  const mark = server.log.length;
  await assert.rejects(() => alice.executeRekey(plan0), NotVerifiedError);
  nothingWritten(server, mark);
  await alice.markVerified(bob.userId);
  await alice.executeRekey(alice.planRekey(vid, { repair: true }));
  v = alice.vault(vid)!;
  assert.equal(v.rosterStatus, 'ok');
  assert.equal(v.keyEpoch, 2);
  assert.deepEqual(v.members.map((m) => [m.username, m.role]).sort(), [['alice', 'owner'], ['bob', 'viewer']]);
});

test('backup export -> import into new vaults; unknown members kept; wrong passphrase classified; local keys recorded', async () => {
  const { alice } = await world();
  const vid = await alice.createVault('Trip');
  await alice.createItem(vid, login({ name: 'Hotel <&> ✓', password: 'h1', notes: 'multi\nline' }));
  const pv = alice.vaults.find((v) => v.personal)!.id;
  await alice.createItem(pv, { ...newItem('note', 0), name: 'Note', extra: [{ rawKey: '"x_future"', rawValue: '{"deep" : [1,  2]}' }] });
  const out = await alice.exportBackup('separate passphrase ✓ words');
  assert.equal(out.vaults, 2);
  assert.equal(out.items, 2);
  assert.ok(!out.text.includes('Hotel'));
  await assert.rejects(() => alice.inspectBackup(out.text, 'wrong'), (e: unknown) => e instanceof BackupError && e.code === 'decrypt');
  await assert.rejects(() => alice.inspectBackup('{"hello":1}', 'x'), (e: unknown) => e instanceof BackupError && e.code === 'not_backup');
  const payload = await alice.inspectBackup(out.text, 'separate passphrase ✓ words');
  const before = alice.vaults.length;
  assert.deepEqual(await alice.importBackup(payload), { vaults: 2, items: 2, failed: 0 });
  assert.equal(alice.vaults.length, before + 2);
  const restored = alice.vaults.filter((v) => v.name.endsWith('(restored)'));
  assert.deepEqual(restored.map((v) => v.name).sort(), ['Personal (restored)', 'Trip (restored)']);
  assert.ok(restored.every((v) => v.state === 'open' && alice.trust.vaults.get(v.id)!.epoch === 1));
  assert.equal(restored.find((v) => v.name.startsWith('Trip'))!.items[0]!.item!.notes, 'multi\nline');
  assert.equal(restored.find((v) => v.name.startsWith('Personal'))!.items[0]!.item!.extra[0]!.rawValue, '{"deep" : [1,  2]}');
});

test('admin: invites, user disable/enable, admin flag, cluster status; non-admins refused', async () => {
  const { server, alice, bob } = await world();
  await assert.rejects(() => bob.createInvite(1), PermissionError);
  const inv = await alice.createInvite(1);
  assert.match(inv.code, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
  assert.ok((await alice.listInvites()).some((i) => i.invite_id === inv.invite_id));
  await alice.revokeInvite(inv.invite_id);
  await assert.rejects(() => Session.register(deps(server), { username: 'eve', password: PW_B, inviteCode: inv.code, kdf: cheap() }));
  await alice.setUserAdmin(bob.userId, true);
  assert.ok(alice.directoryUsers().find((u) => u.userId === bob.userId)!.isAdmin);
  await alice.setUserDisabled(bob.userId, true);
  await assert.rejects(() => Session.login(deps(server), { username: 'bob', password: PW_B }), WrongPasswordError);
  await alice.setUserDisabled(bob.userId, false);
  server.node(URLS[2]!).down = true;
  const st = await alice.clusterStatus();
  assert.deepEqual(st.nodes.map((n) => n.ok), [true, true, false]);
});

test('revoke sessions: other devices re-login with the password; a 401 on the revoke itself ends the session', async () => {
  const { server, alice } = await world();
  const dev2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  await alice.revokeSessions();
  await alice.sync();
  await dev2.sync();
  assert.ok(!dev2.locked);
  // an old session that can no longer be refreshed: treated as ended, master password required again
  const realFetch = server.fetch;
  server.fetch = async (u, i) => (u.endsWith('/revoke-sessions') ? new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'session too old' } }), { status: 401 }) : realFetch(u, i));
  await assert.rejects(() => alice.revokeSessions(), SessionExpiredError);
  assert.ok(alice.locked);
});

test('quota: 422 limit_exceeded surfaces the server message', async () => {
  const { server, alice } = await world();
  server.quota.vault = 2000;
  const pv = alice.vaults[0]!.id;
  const err = await alice.createItem(pv, login({ name: 'big', notes: 'x'.repeat(3000) })).catch((e) => e);
  assert.equal(err.code, 'limit_exceeded');
  assert.match(err.message, /quota/);
});

test('secrets never reach persistent storage or the wire in plaintext; the trust store is sealed', async () => {
  const server = new FakeServer(URLS);
  const store = new MemoryStore();
  const alice = await Session.register(deps(server, store), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const pv = alice.vaults[0]!.id;
  await alice.createItem(pv, login({ name: 'TopSecretName', password: 'TopSecretPassword' }));
  assert.deepEqual([...store.data.keys()].sort(), ['lastUser', 'nodes', `sync:alice`, `trust:${alice.userId}`].sort());
  const dump = JSON.stringify([...store.data.entries()]);
  for (const needle of [PW_A, 'TopSecretName', 'TopSecretPassword', alice.api.token!, 'alice' + '"verified"']) assert.ok(!dump.includes(needle), needle);
  assert.ok(store.data.get(`trust:${alice.userId}`) instanceof Uint8Array, 'sealed blob, not JSON');
  const wire = JSON.stringify(server.vaults.get(pv)) + JSON.stringify([...server.users.values()]);
  for (const needle of [PW_A, 'TopSecretName', 'TopSecretPassword']) assert.ok(!wire.includes(needle));
  assert.deepEqual(await store.get('nodes'), URLS);
});

test('a missing or unopenable trust store starts empty and says so; contacts are unverified again', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  const store = alice.api && priv(alice).deps.store;
  assert.ok(store.data.has(`trust:${alice.userId}`));
  alice.lock();
  // 1. tampered blob
  const blob = store.data.get(`trust:${alice.userId}`) as Uint8Array;
  blob[blob.length - 1]! ^= 1;
  const a2 = await Session.login(deps(server, store), { username: 'alice', password: PW_A });
  assert.equal(a2.trustResetReason, 'unopenable');
  assert.equal(a2.contacts().find((c) => c.userId === bob.userId)!.verified, false);
  a2.lock();
  // 2. deleted blob while a cache exists
  store.data.delete(`trust:${alice.userId}`);
  const a3 = await Session.login(deps(server, store), { username: 'alice', password: PW_A });
  assert.equal(a3.trustResetReason, 'missing');
  // a brand new device has no cache: that is normal, no notice
  const a4 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  assert.equal(a4.trustResetReason, null);
});

test('lock zeroes key material and drops views', async () => {
  const { alice } = await world();
  const k = priv(alice).privateKey;
  assert.ok(k.some((x) => x !== 0));
  alice.lock();
  assert.ok(k.every((x) => x === 0));
  assert.equal(alice.api.token, null);
  assert.equal(alice.vaults.length, 0);
});

// ---------------------------------------------------------------- the client REFUSES what the server must not do

test('REFUSE: account block or own directory entry that does not match the unlocked identity', async () => {
  for (const [what, fn] of [
    ['account user id', (j: any) => void (j.account.user_id = 'f'.repeat(32))],
    ['account username', (j: any) => void (j.account.username = 'mallory')],
    ['account public key', (j: any) => void (j.account.public_key = b64encode(randomBytes(32)))],
    ['directory username', (j: any) => void (j.directory.find((d: any) => d.user_id === j.account.user_id).username = 'mallory')],
    ['directory public key', (j: any) => void (j.directory.find((d: any) => d.user_id === j.account.user_id).public_key = b64encode(randomBytes(32)))],
    ['missing own entry', (j: any) => void (j.directory = j.directory.filter((d: any) => d.user_id !== j.account.user_id))],
  ] as [string, (j: any) => void][]) {
    const { server } = await world();
    const t: Tamper = { fn: null };
    const store = new MemoryStore();
    const alice = await Session.login(deps(server, store, t), { username: 'alice', password: PW_A });
    const cacheBefore = JSON.stringify(await store.get('sync:alice'));
    const viewsBefore = JSON.stringify(alice.vaults);
    const mark = server.log.length;
    server.rev++; // so the client does not get "unchanged"
    t.fn = (j) => void fn(j);
    await assert.rejects(() => alice.sync(), (e: unknown) => e instanceof IdentityMismatchError || e instanceof InvalidSyncError, what);
    assert.equal(JSON.stringify(await store.get('sync:alice')), cacheBefore, `${what}: cache untouched`);
    assert.equal(JSON.stringify(alice.vaults), viewsBefore, `${what}: views untouched`);
    nothingWritten(server, mark);
  }
});

test('REFUSE: login answer whose user id differs from the account block', async () => {
  const { server } = await world();
  const realFetch = server.fetch;
  server.fetch = async (u, i) => {
    const r = await realFetch(u, i);
    if (!u.endsWith('/v1/login')) return r;
    const j = await r.json();
    j.user_id = 'a'.repeat(32);
    return new Response(JSON.stringify(j), { status: 200 });
  };
  await assert.rejects(() => Session.login(deps(server), { username: 'alice', password: PW_A }), IdentityMismatchError);
});

test('REFUSE: malformed or duplicated directory/vault/item entries reject the whole sync', async () => {
  const cases: [string, (j: any) => void][] = [
    ['duplicate user id', (j) => void j.directory.push({ ...j.directory[0] })],
    ['duplicate username', (j) => void j.directory.push({ ...j.directory[0], user_id: 'c'.repeat(32) })],
    ['short public key', (j) => void (j.directory[j.directory.length - 1].public_key = b64encode(randomBytes(31)))],
    ['bad username', (j) => void (j.directory[j.directory.length - 1].username = 'Bad Name!')],
    ['bad user id', (j) => void (j.directory[j.directory.length - 1].user_id = 'XYZ')],
    ['duplicate vault', (j) => void j.vaults.push({ ...j.vaults[0] })],
    ['bad vault id', (j) => void (j.vaults[0].id = 'nope')],
    ['duplicate item', (j) => void j.vaults[0].items.push({ ...j.vaults[0].items[0] })],
    ['duplicate member', (j) => void j.vaults[0].members.push({ ...j.vaults[0].members[0] })],
    ['epoch 0', (j) => void (j.vaults[0].key_epoch = 0)],
  ];
  for (const [what, fn] of cases) {
    const { server, alice } = await world();
    const pv = alice.vaults[0]!.id;
    await alice.createItem(pv, login({ name: 'x' }));
    const t: Tamper = { fn: null };
    const store = new MemoryStore();
    const s = await Session.login(deps(server, store, t), { username: 'alice', password: PW_A });
    const cacheBefore = JSON.stringify(await store.get('sync:alice'));
    const mark = server.log.length;
    server.rev++;
    t.fn = (j) => void fn(j);
    await assert.rejects(() => s.sync(), InvalidSyncError, what);
    assert.equal(JSON.stringify(await store.get('sync:alice')), cacheBefore, `${what}: cache untouched`);
    assert.equal(s.vaults[0]!.items.length, 1, `${what}: views untouched`);
    nothingWritten(server, mark);
  }
});

test('REFUSE: a contact whose key or username changes is blocked; nothing is wrapped for them; the event persists', async () => {
  const { server, alice, bob, aliceDeps } = await world();
  await verify(alice, bob);
  const vid = await alice.createVault('Mine');
  server.users.get(bob.userId)!.publicKey = b64encode(randomBytes(32));
  server.rev++;
  await alice.sync();
  assert.equal(alice.mismatchWarnings.length, 1);
  assert.equal(alice.mismatchWarnings[0]!.kind, 'key');
  assert.equal(alice.mismatchWarnings[0]!.username, 'bob');
  const mark = server.log.length;
  assert.throws(() => alice.lookupUser('bob'), KeyMismatchError);
  await assert.rejects(() => alice.addMember(vid, 'bob', 'viewer'), KeyMismatchError);
  await assert.rejects(() => alice.markVerified(bob.userId), KeyMismatchError);
  nothingWritten(server, mark);
  assert.equal(alice.contacts().find((c) => c.userId === bob.userId)!.blocked, true);
  // dismissing hides the banner but the block is permanent
  await alice.dismissMismatch(alice.mismatchWarnings[0]!.id);
  assert.equal(alice.mismatchWarnings.length, 0);
  assert.throws(() => alice.lookupUser('bob'), KeyMismatchError);
  // survives a restart of the device
  alice.lock();
  const again = await Session.login(deps(server, aliceDeps.store), { username: 'alice', password: PW_A });
  assert.throws(() => again.lookupUser('bob'), KeyMismatchError);
  assert.equal(again.mismatchWarnings.length, 0, 'dismissal persisted too');
  // a username change is a mismatch as well
  const { server: s2, alice: a2, bob: b2 } = await world();
  s2.users.get(b2.userId)!.username = 'robert';
  s2.rev++;
  await a2.sync();
  assert.equal(a2.mismatchWarnings[0]!.kind, 'username');
  // ... and so is a known username appearing under a NEW user id
  const { server: s3, alice: a3 } = await world();
  const id = 'd'.repeat(32);
  s3.users.set(id, { ...s3.users.get([...s3.users.keys()][1]!)!, id, username: 'bob' });
  s3.users.delete([...s3.users.keys()][1]!);
  s3.users.get(id)!.username = 'bob';
  s3.rev++;
  await a3.sync();
  assert.ok(a3.mismatchWarnings.some((w) => w.userId === id), 'the new identity claiming "bob" is the offender');
});

test('REFUSE: a vault key from an UNVERIFIED sender stays pending (covered: nothing decrypted, nothing written, nothing recorded)', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  const vid = await alice.createVault('S');
  await alice.createItem(vid, login({ name: 'secret', password: 'pw' }));
  await alice.addMember(vid, 'bob', 'editor');
  const mark = server.log.length;
  await bob.sync();
  const v = bob.vault(vid)!;
  assert.equal(v.state, 'pending');
  assert.deepEqual(v.items, []);
  assert.equal(v.name, 'Shared by alice');
  assert.equal(bob.trust.vaults.has(vid), false);
  assert.equal(priv(bob).secrets.has(vid), false, 'no key retained as an open vault');
  nothingWritten(server, mark);
  // exporting does not leak it either
  assert.equal((await bob.exportBackup('some export passphrase')).vaults, 1);
});

test('REFUSE: a vault offered at a LOWER epoch, or the same epoch with a DIFFERENT key, is locked', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('C');
  await alice.createItem(vid, login({ name: 'x', password: 'pw' }));
  const store = priv(alice).deps.store;
  // the sync answer as it was at epoch 1
  const old = JSON.parse(JSON.stringify(priv(alice).raw));
  await alice.rekeyVault(vid);
  assert.equal(alice.vault(vid)!.keyEpoch, 2);
  const t: Tamper = { fn: null };
  const d = deps(server, store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  const trustBefore = JSON.stringify(alice.trust.vaults.get(vid));
  // lower epoch
  server.rev++;
  t.fn = (j) => { j.vaults = old.vaults; };
  await alice.sync();
  assert.equal(alice.vault(vid)!.state, 'locked');
  assert.equal(alice.vault(vid)!.locked, 'older_epoch');
  assert.equal(alice.recovery!.kind, 'epoch', 'offered as a deliberate-recovery case, never accepted automatically');
  assert.equal(alice.vault(vid)!.items.length, 0);
  assert.equal(JSON.stringify(alice.trust.vaults.get(vid)), trustBefore, 'trust record not weakened');
  // same epoch, different key (re-wrapped by the same sender, i.e. a plausible server forgery)
  server.rev++;
  t.fn = (j) => {
    const v = j.vaults.find((x: any) => x.id === vid);
    const evil = randomBytes(32);
    v.my_key.blob = b64encode(wrapVaultKey({ vaultKey: evil, ctx: { vaultId: vid, keyEpoch: v.key_epoch, senderId: alice.userId, recipientId: alice.userId }, senderPrivate: priv(alice).privateKey, recipientPublic: priv(alice).publicKey }));
  };
  const mark = server.log.length;
  await alice.sync();
  assert.equal(alice.vault(vid)!.locked, 'continuity');
  nothingWritten(server, mark);
});

test('REFUSE: a vault this device created comes back with a different key -> locked (the local key is never replaced)', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('Mine');
  const t: Tamper = { fn: null };
  const d = deps(server, priv(alice).deps.store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  server.rev++;
  t.fn = (j) => {
    const v = j.vaults.find((x: any) => x.id === vid);
    const evil = randomBytes(32);
    v.my_key.blob = b64encode(wrapVaultKey({ vaultKey: evil, ctx: { vaultId: vid, keyEpoch: 1, senderId: alice.userId, recipientId: alice.userId }, senderPrivate: priv(alice).privateKey, recipientPublic: priv(alice).publicKey }));
    v.enc_meta = b64encode(encryptVaultMeta(evil, { vaultId: vid, epoch: 1, meta: { name: 'EVIL' } }));
  };
  const mark = server.log.length;
  await alice.sync();
  assert.equal(alice.vault(vid)!.locked, 'continuity');
  assert.notEqual(alice.vault(vid)!.name, 'EVIL');
  await assert.rejects(() => alice.createItem(vid, login({ name: 'x' })), /not open/);
  nothingWritten(server, mark);
});

test('REFUSE: a member listed by the server but absent from the roster stops a rekey', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  const vid = await alice.createVault('V');
  await alice.createItem(vid, login({ name: 'x' }));
  // the server adds bob to the member list without the roster (and with a key for him it cannot make, so any bytes)
  server.vaults.get(vid)!.members.set(bob.userId, { role: 'editor', addedBy: alice.userId, key: { sender_id: alice.userId, blob: b64encode(randomBytes(105)) } });
  server.rev++;
  server.vaults.get(vid)!.rev = server.rev;
  await alice.sync();
  assert.equal(alice.vault(vid)!.members.find((m) => m.username === 'bob')!.discrepancy, 'unlisted');
  const mark = server.log.length;
  assert.throws(() => alice.planRekey(vid), UnlistedMemberError);
  assert.throws(() => alice.planRekey(vid, { remove: [bob.userId] }), UnlistedMemberError, 'even when removing: the roster does not describe the vault');
  await assert.rejects(() => alice.rekeyVault(vid), UnlistedMemberError);
  nothingWritten(server, mark);
});

test('REFUSE: an unverified roster member needs confirmation before a rekey (nothing sent until then)', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  const vid = await alice.createVault('V');
  await alice.addMember(vid, 'bob', 'editor');
  // alice's other device never verified bob
  const dev2 = await Session.login(deps(server), { username: 'alice', password: PW_A });
  assert.equal(dev2.vault(vid)!.state, 'open', 'own key: accepted without a comparison');
  const plan = dev2.planRekey(vid);
  assert.deepEqual(plan.recipients.map((r) => [r.username, r.verified]).sort(), [['alice', true], ['bob', false]]);
  assert.deepEqual(plan.unverified.map((r) => r.username), ['bob']);
  const mark = server.log.length;
  await assert.rejects(() => dev2.executeRekey(plan), NotVerifiedError);
  await assert.rejects(() => dev2.rekeyVault(vid), NotVerifiedError);
  nothingWritten(server, mark);
  await dev2.markVerified(bob.userId);
  await dev2.executeRekey(dev2.planRekey(vid));
  assert.equal(dev2.vault(vid)!.keyEpoch, 2);
  assert.deepEqual(dev2.vault(vid)!.members.map((m) => m.username).sort(), ['alice', 'bob']);
});

test('REFUSE: a roster that does not list the client (with its own key) locks the vault', async () => {
  const { server, alice, bob } = await world();
  const vid = await alice.createVault('V');
  await alice.createItem(vid, login({ name: 'x' }));
  const sec = { vk: priv(alice).secrets.get(vid)!.vk.slice() }; // copy: the live key is zeroed when a vault locks
  const evilRoster: Roster = { v: 1, members: [{ id: bob.userId, publicKey: randomBytes(32), role: 'owner' }] };
  const t: Tamper = { fn: null };
  const d = deps(server, priv(alice).deps.store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  server.rev++;
  t.fn = (j) => void (j.vaults.find((x: any) => x.id === vid).enc_roster = b64encode(encryptRoster(sec.vk, { vaultId: vid, epoch: 1 }, evilRoster)));
  const mark = server.log.length;
  const trustBefore = JSON.stringify(alice.trust.vaults.get(vid));
  await alice.sync();
  assert.equal(alice.vault(vid)!.locked, 'roster_missing_me');
  assert.equal(alice.vault(vid)!.items.length, 0);
  assert.equal(JSON.stringify(alice.trust.vaults.get(vid)), trustBefore);
  nothingWritten(server, mark);
  // right user id but a different key for us is refused as well
  server.rev++;
  t.fn = (j) => void (j.vaults.find((x: any) => x.id === vid).enc_roster = b64encode(encryptRoster(sec.vk, { vaultId: vid, epoch: 1 }, { v: 1, members: [{ id: alice.userId, publicKey: randomBytes(32), role: 'owner' }] })));
  await alice.sync();
  assert.equal(alice.vault(vid)!.locked, 'roster_missing_me');
});

test('REFUSE: a roster whose key for a contact disagrees with the trust store is a key mismatch', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  const vid = await alice.createVault('V');
  const sec = priv(alice).secrets.get(vid)!;
  const evil: Roster = { v: 1, members: [{ id: alice.userId, publicKey: priv(alice).publicKey, role: 'owner' as const }, { id: bob.userId, publicKey: randomBytes(32), role: 'editor' as const }].sort((a, b) => (a.id < b.id ? -1 : 1)) };
  const t: Tamper = { fn: null };
  const d = deps(server, priv(alice).deps.store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  server.rev++;
  t.fn = (j) => void (j.vaults.find((x: any) => x.id === vid).enc_roster = b64encode(encryptRoster(sec.vk, { vaultId: vid, epoch: 1 }, evil)));
  await alice.sync();
  assert.ok(alice.mismatchWarnings.some((w) => w.userId === bob.userId && w.kind === 'roster'));
  assert.throws(() => alice.lookupUser('bob'), KeyMismatchError);
});

test('REFUSE: KDF parameters weaker than the cached ones (no login key is sent)', async () => {
  const server = new FakeServer(URLS);
  const store = new MemoryStore();
  const strong = { ...cheap(), time: 4 };
  await Session.register(deps(server, store), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: strong });
  const prelogin = { alg: 'argon2id', salt: b64encode(strong.salt), time: 3, memory_kib: 65536, parallelism: 1 }; // passes the floor, weaker than cached t=4
  server.kdfOverride = prelogin;
  server.log.length = 0;
  await assert.rejects(() => Session.login(deps(server, store), { username: 'alice', password: PW_A }), KdfParamsError);
  assert.ok(!server.log.some((l) => l.path === '/v1/login'));
  // a device with no cache has nothing to compare with and accepts it (but the account then fails to open)
  server.kdfOverride = null;
  assert.equal((await Session.login(deps(server, store), { username: 'alice', password: PW_A })).username, 'alice');
});

test('REFUSE: a sync with a lower rev does not replace the cache or the views (rollback); a stale lower answer is ignored', async () => {
  const { server, alice } = await world();
  const pv = alice.vaults[0]!.id;
  await alice.createItem(pv, login({ name: 'one' }));
  const store = priv(alice).deps.store;
  const old = JSON.parse(JSON.stringify(priv(alice).raw));
  await alice.createItem(pv, login({ name: 'two' }));
  const cacheBefore = JSON.stringify(await store.get('sync:alice'));
  const t: Tamper = { fn: null };
  const d = deps(server, store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  server.rev++;
  t.fn = () => old;
  await assert.rejects(() => alice.sync(), RollbackError);
  assert.equal(JSON.stringify(await store.get('sync:alice')), cacheBefore);
  assert.equal(alice.vault(pv)!.items.length, 2);
  t.fn = () => ({ ...old, stale: true });
  await alice.sync(); // ignored silently, views and cache keep the newer data
  assert.equal(alice.mode, 'stale');
  assert.equal(JSON.stringify(await store.get('sync:alice')), cacheBefore);
  assert.equal(alice.vault(pv)!.items.length, 2);
});

test('REFUSE: a personal vault wrapped by someone else is a hard error', async () => {
  const { server, alice, bob } = await world();
  const pv = alice.vaults.find((v) => v.personal)!.id;
  const t: Tamper = { fn: null };
  const d = deps(server, priv(alice).deps.store, t);
  (priv(alice).deps as { api: ApiClient }).api = d.api;
  d.api.token = alice.api.token;
  server.rev++;
  t.fn = (j) => void (j.vaults.find((x: any) => x.id === pv).my_key.sender_id = bob.userId);
  await assert.rejects(() => alice.sync(), InvalidSyncError);
  assert.equal(alice.vault(pv)!.state, 'open', 'previous state kept');
});

test('REFUSE: a known vault whose key is replaced by a NON-OWNER is pending with the special wording flag', async () => {
  const { server, alice, bob } = await world();
  await verify(alice, bob);
  await verify(bob, alice);
  const vid = await alice.createVault('V');
  await alice.addMember(vid, 'bob', 'editor');
  await bob.sync();
  assert.equal(bob.vault(vid)!.state, 'open', 'bob verified alice, so the new share opened');
  // carol is a verified editor of the vault for bob; the server presents a new key "from carol" at epoch 2
  const inv = await alice.createInvite(1);
  const carol = await Session.register(deps(server), { username: 'carol', password: PW_C, inviteCode: inv.code, kdf: cheap() });
  await bob.sync();
  await bob.markVerified(carol.userId);
  const newVk = randomBytes(32);
  const t: Tamper = { fn: null };
  const d = deps(server, priv(bob).deps.store, t);
  (priv(bob).deps as { api: ApiClient }).api = d.api;
  d.api.token = bob.api.token;
  server.rev++;
  t.fn = (j) => {
    const v = j.vaults.find((x: any) => x.id === vid);
    v.key_epoch = 2;
    v.my_key = { sender_id: carol.userId, blob: b64encode(wrapVaultKey({ vaultKey: newVk, ctx: { vaultId: vid, keyEpoch: 2, senderId: carol.userId, recipientId: bob.userId }, senderPrivate: priv(carol).privateKey, recipientPublic: priv(bob).publicKey })) };
  };
  const mark = server.log.length;
  await bob.sync();
  const v = bob.vault(vid)!;
  assert.equal(v.state, 'pending');
  assert.equal(v.pending!.replacedByNonOwner, true);
  assert.equal(v.pending!.senderName, 'carol');
  assert.deepEqual(v.items, []);
  nothingWritten(server, mark);
  // while a rekey by a KNOWN OWNER at a higher epoch is accepted without a prompt
  const aliceWrap = b64encode(wrapVaultKey({ vaultKey: newVk, ctx: { vaultId: vid, keyEpoch: 2, senderId: alice.userId, recipientId: bob.userId }, senderPrivate: priv(alice).privateKey, recipientPublic: priv(bob).publicKey }));
  server.rev++;
  t.fn = (j) => {
    const x = j.vaults.find((y: any) => y.id === vid);
    x.key_epoch = 2;
    x.my_key = { sender_id: alice.userId, blob: aliceWrap };
    x.enc_roster = b64encode(encryptRoster(newVk, { vaultId: vid, epoch: 2 }, { v: 1, members: [alice, bob].map((s) => ({ id: s.userId, publicKey: priv(s).publicKey, role: s === alice ? 'owner' as const : 'editor' as const })).sort((a, b) => (a.id < b.id ? -1 : 1)) }));
    x.enc_meta = b64encode(encryptVaultMeta(newVk, { vaultId: vid, epoch: 2, meta: { name: 'V' } }));
    x.items = [];
  };
  await bob.sync();
  assert.equal(bob.vault(vid)!.state, 'open');
  assert.equal(bob.trust.vaults.get(vid)!.commit, vaultKeyCommitment({ vaultKey: newVk, vaultId: vid, epoch: 2 }));
  void encryptItem;
});

test('REFUSE: items cannot be replayed from another epoch (epoch is bound into the AAD)', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('V');
  const id = await alice.createItem(vid, login({ name: 'x', password: 'pw' }));
  const oldBlob = server.vaults.get(vid)!.items.get(id)!.blob;
  await alice.rekeyVault(vid);
  const it = server.vaults.get(vid)!.items.get(id)!;
  it.blob = oldBlob; // a server rolling an item back to its epoch-1 ciphertext
  it.version = ++server.rev;
  await alice.sync();
  assert.ok(alice.vault(vid)!.items[0]!.error, 'old-epoch ciphertext does not open under the new epoch');
});
void b64decode;

// ---------------------------------------------------------------- deliberate recovery (crypto.md §6.4)

async function restoreWorld() {
  const w = await world();
  const { server, alice, bob } = w;
  await verify(alice, bob);
  const inv = await alice.createInvite(1);
  const carol = await Session.register(deps(server), { username: 'carol', password: PW_C, inviteCode: inv.code, kdf: cheap() });
  await alice.sync();
  await bob.sync();
  await carol.sync();
  // alice shares V1 with bob (bob verifies alice -> opens it); carol shares V3 with bob (bob never verifies carol -> pending)
  const v1 = await alice.createVault('Family');
  await alice.createItem(v1, login({ name: 'Netflix', password: 'nf1' }));
  await alice.addMember(v1, 'bob', 'editor');
  await bob.sync();
  await bob.acceptPending(v1);
  await verify(carol, bob);
  const v3 = await carol.createVault('Carols');
  await carol.createItem(v3, login({ name: 'Secret', password: 'cs' }));
  await carol.addMember(v3, 'bob', 'viewer');
  await bob.sync();
  assert.equal(bob.vault(v3)!.state, 'pending');
  return { ...w, carol, v1, v3 };
}

test('RECOVERY: after the servers are restored from a backup the device is blocked, then accepts the restored state on purpose', async () => {
  const { server, alice, bob, v1, v3 } = await restoreWorld();
  const backup = server.snapshot();
  const backupRev = backup.rev;
  // more history after the backup, including a REKEY (epoch 2) that bob has seen
  await alice.rekeyVault(v1);
  await alice.createItem(v1, login({ name: 'Added later', password: 'x' }));
  await bob.sync();
  assert.equal(bob.vault(v1)!.keyEpoch, 2);
  assert.ok(bob.trust.highestRev > backupRev);
  const cacheBefore = JSON.stringify(await priv(bob).deps.store.get('sync:bob'));
  const verifiedBefore = bob.contacts().map((c) => [c.username, c.verified]);

  // the administrator restores the servers
  server.restore(backup);
  assert.ok(server.rev < bob.trust.highestRev);
  const mark = server.log.length;
  await assert.rejects(() => bob.sync(), RollbackError);
  assert.equal(bob.recovery!.kind, 'rev');
  assert.ok(bob.canAcceptRecovery);
  assert.equal(bob.canWrite, false, 'no writes while undecided');
  await assert.rejects(() => bob.createItem(v1, login({ name: 'nope' })), (e: unknown) => e instanceof ReadOnlyError && e.reason === 'recovery');
  assert.equal(bob.vault(v1)!.keyEpoch, 2, 'the cached (newer) state stays readable');
  assert.equal(bob.vault(v1)!.items.length, 2);
  assert.equal(JSON.stringify(await priv(bob).deps.store.get('sync:bob')), cacheBefore, 'cache not replaced before the decision');
  nothingWritten(server, mark);
  // refreshing again does not accept anything either
  await bob.refresh();
  assert.ok(bob.recovery);

  // the explicit action
  await bob.acceptRestoredState();
  assert.equal(bob.recovery, null);
  assert.ok(bob.canWrite);
  assert.equal(bob.vault(v1)!.state, 'open', 'a verified sender (alice) is accepted again as if first seen');
  assert.equal(bob.vault(v1)!.keyEpoch, 1);
  assert.deepEqual(bob.vault(v1)!.items.map((i) => i.item!.name), ['Netflix'], 'restored (older) content');
  assert.equal(bob.vault(v3)!.state, 'pending', 'a vault from an unverified sender is still pending');
  assert.deepEqual(bob.contacts().map((c) => [c.username, c.verified]), verifiedBefore, 'contacts and verified flags untouched');
  assert.equal(bob.trust.highestRev, server.rev);
  assert.equal(JSON.parse(JSON.stringify(await priv(bob).deps.store.get('sync:bob'))).sync.rev, server.rev, 'cache replaced');
  await bob.createItem(v1, login({ name: 'works again' }));
});

test('RECOVERY: a restore that leaves rev HIGHER but vaults at an older epoch is offered too (vault locked as older_epoch)', async () => {
  const { server, alice, v1 } = await restoreWorld();
  const backup = server.snapshot();
  await alice.rekeyVault(v1);
  assert.equal(alice.vault(v1)!.keyEpoch, 2);
  server.restore(backup);
  server.rev += 1000; // later activity pushed rev past what the device has seen
  await alice.sync();
  assert.equal(alice.vault(v1)!.locked, 'older_epoch');
  assert.equal(alice.recovery!.kind, 'epoch');
  assert.equal(alice.canWrite, false);
  await alice.acceptRestoredState();
  assert.equal(alice.vault(v1)!.state, 'open');
  assert.equal(alice.vault(v1)!.keyEpoch, 1);
  assert.equal(alice.recovery, null);
});

test('RECOVERY: never available when nothing looks restored, for a same-epoch different key, for key mismatches, or on a stale answer', async () => {
  // nothing wrong
  const w = await restoreWorld();
  await assert.rejects(() => w.bob.acceptRestoredState(), RecoveryRefusedError);

  // same epoch, different key: a forgery, not a restore
  {
    const { server, alice, v1 } = await restoreWorld();
    const store = priv(alice).deps.store;
    const t: Tamper = { fn: null };
    const d = deps(server, store, t);
    (priv(alice).deps as { api: ApiClient }).api = d.api;
    d.api.token = alice.api.token;
    server.rev++;
    t.fn = (j) => {
      const v = j.vaults.find((x: any) => x.id === v1);
      v.my_key.blob = b64encode(wrapVaultKey({ vaultKey: randomBytes(32), ctx: { vaultId: v1, keyEpoch: v.key_epoch, senderId: alice.userId, recipientId: alice.userId }, senderPrivate: priv(alice).privateKey, recipientPublic: priv(alice).publicKey }));
    };
    await alice.sync();
    assert.equal(alice.vault(v1)!.locked, 'continuity');
    assert.equal(alice.recovery, null, 'not offered');
    await assert.rejects(() => alice.acceptRestoredState(), RecoveryRefusedError);
    // even with a genuinely lower rev ALONGSIDE the forgery, accepting is refused and records stay intact
    const snapRec = JSON.stringify(alice.trust.vaults.get(v1));
    server.rev -= 5;
    alice.trust.highestRev = server.rev + 10;
    await assert.rejects(() => alice.sync(), RollbackError);
    assert.ok(alice.recovery);
    await assert.rejects(() => alice.acceptRestoredState(), RecoveryRefusedError);
    assert.equal(JSON.stringify(alice.trust.vaults.get(v1)), snapRec);
    assert.equal(alice.trust.highestRev, server.rev + 10, 'highest rev untouched by the refusal');
  }

  // key mismatch: no offer; the block and the event stay
  {
    const { server, alice, bob } = await restoreWorld();
    server.users.get(bob.userId)!.publicKey = b64encode(randomBytes(32));
    server.rev++;
    await alice.sync();
    assert.equal(alice.mismatchWarnings.length, 1);
    assert.equal(alice.recovery, null);
    await assert.rejects(() => alice.acceptRestoredState(), RecoveryRefusedError);
    assert.throws(() => alice.lookupUser('bob'), KeyMismatchError);
  }

  // a STALE older answer is simply ignored: no recovery state at all
  {
    const { server, alice } = await restoreWorld();
    const old = JSON.parse(JSON.stringify(priv(alice).raw));
    await alice.createVault('More');
    const d = deps(server, priv(alice).deps.store, { fn: () => ({ ...old, stale: true }) });
    (priv(alice).deps as { api: ApiClient }).api = d.api;
    d.api.token = alice.api.token;
    server.rev++;
    await alice.sync();
    assert.equal(alice.recovery, null);
  }
});

test('RECOVERY: contact mismatches recorded before a restore survive accepting it', async () => {
  const { server, alice, bob } = await restoreWorld();
  server.users.get(bob.userId)!.publicKey = b64encode(randomBytes(32));
  server.rev++;
  await alice.sync();
  assert.equal(alice.mismatchWarnings.length, 1);
  // a restore that brings back bob's ORIGINAL key and an older rev
  const backup = server.snapshot();
  server.users.get(bob.userId)!.publicKey = b64encode(bob.api && priv(bob).publicKey);
  server.restore({ ...backup, rev: 1 });
  server.users.get(bob.userId)!.publicKey = b64encode(priv(bob).publicKey);
  await assert.rejects(() => alice.sync(), RollbackError);
  await alice.acceptRestoredState();
  assert.equal(alice.contacts().find((c) => c.userId === bob.userId)!.blocked, true, 'the mismatch event is permanent');
  assert.equal(alice.mismatchWarnings.length, 1);
});

// ---------------------------------------------------------------- in-flight window (§6.4: record before send)

/** Runs `during` once, at the moment a request matching `match` is about to be forwarded (`when: 'before'`) or has been applied but not yet answered (`'after'`). */
function interleave(server: FakeServer, match: (u: string, i?: RequestInit) => boolean, when: 'before' | 'after', during: () => Promise<void>) {
  const real = server.fetch;
  let done = false;
  server.fetch = async (u, i) => {
    if (done || !match(u, i)) return real(u, i);
    done = true;
    if (when === 'before') {
      await during();
      return real(u, i);
    }
    const r = await real(u, i);
    await during();
    return r;
  };
}

for (const when of ['before', 'after'] as const) {
  test(`IN-FLIGHT create (${when}): a sync completing while createVault is being sent neither locks the vault nor replaces its key`, async () => {
    const { server, alice } = await world();
    let vid = '';
    let ran = false;
    interleave(server, (u, i) => i?.method === 'POST' && u.endsWith('/v1/vaults'), when, async () => {
      ran = true;
      await alice.sync();
    });
    vid = await alice.createVault('Mine');
    assert.ok(ran);
    const v = alice.vault(vid)!;
    assert.equal(v.state, 'open');
    assert.equal(v.name, 'Mine');
    const rec = alice.trust.vaults.get(vid)!;
    assert.equal(rec.epoch, 1);
    assert.equal(rec.commit, vaultKeyCommitment({ vaultKey: priv(alice).secrets.get(vid)!.vk, vaultId: vid, epoch: 1 }), 'still our own key');
    assert.equal(alice.trust.inflight.has(vid), false);
    await alice.createItem(vid, login({ name: 'ok' }));
  });

  test(`IN-FLIGHT rekey (${when}): a sync completing while the rekey is being sent neither locks the vault nor replaces the new key`, async () => {
    const { server, alice } = await world();
    const vid = await alice.createVault('V');
    await alice.createItem(vid, login({ name: 'x', password: 'pw' }));
    let ran = false;
    interleave(server, (u, i) => i?.method === 'POST' && u.endsWith('/rekey'), when, async () => {
      ran = true;
      await alice.sync();
      assert.notEqual(alice.vault(vid)!.state, 'locked', 'not locked in the middle either');
      assert.equal(alice.recovery, null);
    });
    await alice.rekeyVault(vid);
    assert.ok(ran);
    const v = alice.vault(vid)!;
    assert.equal(v.state, 'open');
    assert.equal(v.keyEpoch, 2);
    assert.equal(alice.recovery, null);
    const rec = alice.trust.vaults.get(vid)!;
    assert.equal(rec.epoch, 2);
    assert.equal(rec.commit, vaultKeyCommitment({ vaultKey: priv(alice).secrets.get(vid)!.vk, vaultId: vid, epoch: 2 }));
    assert.equal(v.items[0]!.item!.password, 'pw');
    assert.equal(alice.trust.inflight.has(vid), false);
  });
}

test('IN-FLIGHT: a rekey request that NEVER LANDED (network error, vault still at the old epoch) is recovered on the next sync, not a lock-out', async () => {
  const { server, alice } = await world();
  const vid = await alice.createVault('V');
  await alice.createItem(vid, login({ name: 'x', password: 'pw' }));
  const real = server.fetch;
  server.fetch = async (u, i) => {
    if (i?.method === 'POST' && u.endsWith('/rekey')) throw new TypeError('connection reset'); // never reaches the server
    return real(u, i);
  };
  const err = await alice.rekeyVault(vid).catch((e) => e);
  assert.ok(err instanceof Error);
  assert.equal(server.vaults.get(vid)!.epoch, 1, 'nothing happened server-side');
  assert.ok(alice.trust.inflight.has(vid), 'recorded before sending; outcome was unknown');
  server.fetch = real;
  await alice.sync();
  const v = alice.vault(vid)!;
  assert.equal(v.state, 'open', 'not locked');
  assert.equal(v.keyEpoch, 1);
  assert.equal(alice.recovery, null);
  assert.equal(alice.trust.vaults.get(vid)!.epoch, 1, 'record reverted to the previous epoch');
  assert.equal(alice.trust.inflight.has(vid), false);
  await alice.createItem(vid, login({ name: 'still works' }));
  await alice.rekeyVault(vid); // and a later rekey succeeds
  assert.equal(alice.vault(vid)!.keyEpoch, 2);
});

test('IN-FLIGHT: a create that never landed leaves no stale record behind', async () => {
  const { server, alice } = await world();
  const real = server.fetch;
  server.fetch = async (u, i) => {
    if (i?.method === 'POST' && u.endsWith('/v1/vaults')) throw new TypeError('connection reset');
    return real(u, i);
  };
  const before = alice.trust.vaults.size;
  await assert.rejects(() => alice.createVault('Ghost'));
  server.fetch = real;
  await alice.sync();
  assert.equal(alice.trust.vaults.size, before);
  assert.equal(alice.trust.inflight.size, 0);
});

test('CACHE: a decrypted entry is reused only while its ciphertext, version and metadata are unchanged', async () => {
  const server = new FakeServer(URLS);
  const tamper: Tamper = { fn: null };
  const alice = await Session.register(deps(server, undefined, tamper), { username: 'alice', password: PW_A, inviteCode: server.bootstrapToken, kdf: cheap() });
  const vid = alice.vaults[0]!.id;
  const a = await alice.createItem(vid, login({ name: 'A', password: 'pw-a' }));
  const first = alice.vault(vid)!.items.find((i) => i.id === a)!;
  await alice.createItem(vid, login({ name: 'B' }));
  assert.equal(alice.vault(vid)!.items.find((i) => i.id === a), first, 'unchanged entry: the same decrypted view is reused');
  // The server answers with other ciphertext for the same id AND version: it must be decrypted again, never served from the cache.
  const sec = priv(alice).secrets.get(vid)!;
  const forged = b64encode(encryptItem(sec.vk, { vaultId: vid, itemId: a, epoch: sec.epoch }, login({ name: 'A', password: 'forged' })));
  tamper.fn = (j) => void (j.vaults[0].items.find((i: any) => i.id === a).blob = forged);
  server.rev++; // a changed state, so the answer is not "unchanged"
  await alice.sync();
  const now = alice.vault(vid)!.items.find((i) => i.id === a)!;
  assert.notEqual(now, first);
  assert.equal(now.item!.password, 'forged');
  // Locking drops the views (and with them every cached plaintext).
  alice.lock();
  assert.deepEqual(alice.vaults, []);
});
