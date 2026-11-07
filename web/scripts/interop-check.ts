// Cross-implementation check: the browser client's own src/api + src/vault code
// against data written (and later read) by the Go client `fvault`.
// Driven by scripts/interop.sh; not meant to be run by hand.
//
//   node scripts/interop-check.ts --phase a --base URL --expect FILE --state FILE
//   node scripts/interop-check.ts --phase b --base URL --expect FILE --state FILE
//
// Phase a: log in as both users; bob's copy of the vault fvault shared is
//   PENDING until he verifies alice's fingerprint and accepts; verify every
//   decrypted field fvault wrote, check fingerprints, edit an item, create items
//   (one with an unknown field), share a vault of the browser's own with bob,
//   change bob's master password, remove bob from the first vault with the
//   atomic remove+rekey.
// Phase b (after fvault edited the item and read everything back): verify the
//   unknown field survived fvault's edit, the CLI's edit is visible, bob's old
//   password is dead and the new one works.
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { ApiClient } from '../src/api/index.ts';
import { newItem, type Item } from '../src/crypto/index.ts';
import { MemoryStore, Session, type Deps, type VaultView } from '../src/vault/index.ts';

const { values: args } = parseArgs({
  options: {
    phase: { type: 'string' },
    base: { type: 'string' },
    expect: { type: 'string' },
    state: { type: 'string' },
  },
});
if (!args.phase || !args.base || !args.expect || !args.state) {
  console.error('usage: interop-check.ts --phase a|b --base URL --expect FILE --state FILE');
  process.exit(2);
}
const BASE: string = args.base;
const STATE: string = args.state;

interface ExpItem {
  name: string;
  type: 'login' | 'note';
  username?: string;
  password?: string;
  urls?: string[];
  notes?: string;
  fields?: { name: string; value: string; hidden?: boolean }[];
}
interface Expect {
  alice: { user: string; password: string; fingerprint: string };
  bob: { user: string; password: string; newPassword: string; fingerprint: string };
  vaultName: string;
  browserVaultName: string;
  items: ExpItem[];
  personalItem: ExpItem;
  cliEditedNotes: string;
}
const E: Expect = JSON.parse(readFileSync(args.expect, 'utf8'));

let failed = 0;
async function step(name: string, fn: () => Promise<void>): Promise<boolean> {
  try {
    await fn();
    console.log(`PASS  ${name}`);
    return true;
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}\n        ${e instanceof Error ? e.message : String(e)}`);
    return false;
  }
}
function must(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}
function eq(got: unknown, want: unknown, what: string): void {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) throw new Error(`${what}: got ${g}, want ${w}`);
}

const mkDeps = (): Deps => ({ api: new ApiClient({ nodes: [BASE] }), store: new MemoryStore() });

function checkItem(got: Item | undefined, want: ExpItem, where: string): void {
  must(got, `${where}: item "${want.name}" not decrypted`);
  eq(got.type, want.type, `${where} ${want.name} type`);
  eq(got.name, want.name, `${where} name`);
  eq(got.username, want.username ?? '', `${where} ${want.name} username`);
  eq(got.password, want.password ?? '', `${where} ${want.name} password`);
  eq(got.urls, want.urls ?? [], `${where} ${want.name} urls`);
  eq(got.notes, want.notes ?? '', `${where} ${want.name} notes`);
  eq(got.fields.map((f) => ({ name: f.name, value: f.value, hidden: !!f.hidden })), (want.fields ?? []).map((f) => ({ name: f.name, value: f.value, hidden: !!f.hidden })), `${where} ${want.name} custom fields`);
}
function findItem(v: VaultView, name: string) {
  const it = v.items.find((i) => i.item?.name === name);
  must(it, `item "${name}" not found in vault "${v.name}"`);
  return it;
}
function sharedVault(s: Session, name = E.vaultName): VaultView {
  const v = s.vaults.find((x) => x.name === name);
  must(v, `vault "${name}" not visible to ${s.username}`);
  must(v.state === 'open', `vault is ${v.state}${v.locked ? ' (' + v.locked + ')' : ''}`);
  return v;
}

if (args.phase === 'a') {
  let alice!: Session, bob!: Session;
  await step('web client logs in as alice and bob (users registered by fvault)', async () => {
    alice = await Session.login(mkDeps(), { username: E.alice.user, password: E.alice.password });
    bob = await Session.login(mkDeps(), { username: E.bob.user, password: E.bob.password });
    eq(alice.fingerprint, E.alice.fingerprint, 'alice fingerprint as computed by the web client vs fvault');
    eq(bob.fingerprint, E.bob.fingerprint, 'bob fingerprint as computed by the web client vs fvault');
  });
  if (failed) process.exit(1);

  await step('alice reads every field of the items fvault wrote (non-ASCII, custom fields, notes)', async () => {
    const v = sharedVault(alice);
    eq(v.items.length, E.items.length, 'item count');
    for (const w of E.items) checkItem(findItem(v, w.name).item, w, 'alice');
    const p = alice.vaults.find((x) => x.personal)!;
    checkItem(findItem(p, E.personalItem.name).item, E.personalItem, 'alice/personal');
    eq(p.name, 'Personal', 'personal vault name');
    eq(v.members.map((m) => m.username).sort(), [E.alice.user, E.bob.user].sort(), 'roster members (written by fvault)');
  });

  await step('bob: the vault fvault shared is PENDING (nothing decrypted) until he verifies alice and accepts', async () => {
    const pend = bob.vaults.find((v) => v.state === 'pending');
    must(pend, 'no pending share on bob');
    eq(pend.items.length, 0, 'pending vault contents');
    eq(pend.pending?.senderName, E.alice.user, 'pending sender');
    eq(pend.pending?.senderFingerprint, E.alice.fingerprint, 'fingerprint shown for the sender (computed by the web client) vs fvault');
    await bob.acceptPending(pend.id);
    const v = sharedVault(bob);
    eq(v.role, 'editor', 'bob role');
    for (const w of E.items) checkItem(findItem(v, w.name).item, w, 'bob');
    eq(v.members.map((m) => m.username).sort(), [E.alice.user, E.bob.user].sort(), 'members');
  });

  await step('fingerprint of bob in alice\'s contacts agrees with fvault; alice verifies bob', async () => {
    const c = alice.contacts().find((x) => x.username === E.bob.user);
    must(c, 'bob is not in alice\'s contacts');
    eq(c.fingerprint, E.bob.fingerprint, 'bob fingerprint in alice contacts');
    must(!c.verified, 'a fresh web trust store must start with bob unverified');
    await alice.markVerified(c.userId);
  });

  const st: Record<string, string> = {};
  await step('alice edits the bank item (history is kept) and creates an item with an unknown field', async () => {
    const v = sharedVault(alice);
    const bank = E.items[0]!;
    const bi = findItem(v, bank.name);
    st.bankId = bi.id;
    st.bankNewPassword = 'bröwser-new-密码-' + Math.random().toString(36).slice(2, 8);
    await alice.updateItem(v.id, bi.id, (x) => void (x.password = st.bankNewPassword!));
    await alice.sync();
    const after = findItem(sharedVault(alice), bank.name).item!;
    eq(after.password_history[0]?.password, bank.password, 'history holds the password fvault wrote');
    const it = newItem('login', Date.now());
    Object.assign(it, {
      name: 'Browser item ß', username: 'web-user', password: 'p4ss-ü-🔑', urls: ['https://example.org/ü'], notes: 'made in the browser',
      extra: [{ rawKey: '"x_node_future"', rawValue: '{"n":1,"s":"ü","list":[true,null],"big":12345678901234567890}' }],
    });
    st.browserItemId = await alice.createItem(v.id, it);
    st.vaultId = v.id;
  });

  await step('alice creates a vault of her own, shares it with verified bob; bob (fvault side) accepts later', async () => {
    const id = await alice.createVault(E.browserVaultName);
    await alice.createItem(id, Object.assign(newItem('login', Date.now()), { name: 'Browser shared item', username: 'shared-user', password: 'shared-ü-pw-1', notes: 'wrapped by the web client' }));
    await alice.addMember(id, E.bob.user, 'editor');
    st.browserVaultId = id;
  });

  await step('bob (editor) creates an item through the web client', async () => {
    const v = sharedVault(bob);
    await bob.sync();
    st.bobItemId = await bob.createItem(v.id, Object.assign(newItem('note', Date.now()), { name: "Bob's note", notes: 'by bob in the browser' }));
  });

  await step('bob changes his master password in the browser (policy enforced)', async () => {
    await bob.changePassword(E.bob.password, E.bob.newPassword);
  });

  await step('alice removes bob: ONE atomic request rekeys the vault; it still decrypts', async () => {
    await alice.sync();
    const before = sharedVault(alice).keyEpoch;
    await alice.removeMember(st.vaultId!, bob.userId);
    const v = sharedVault(alice);
    eq(v.keyEpoch, before + 1, 'key epoch');
    must(!v.rekeyRecommended, 'rekey_recommended cleared');
    must(v.items.every((i) => i.item), 'every item decrypts under the new key');
    eq(v.items.length, E.items.length + 2, 'item count after rekey (fvault items + browser + bob)');
    eq(v.members.map((m) => m.username), [E.alice.user], 'roster after removal');
    st.epoch = String(v.keyEpoch);
  });

  writeFileSync(STATE, JSON.stringify(st));
} else {
  const st: Record<string, string> = JSON.parse(readFileSync(STATE, 'utf8'));
  await step('web client sees the unknown field that fvault edited around, and fvault\'s edit', async () => {
    const alice = await Session.login(mkDeps(), { username: E.alice.user, password: E.alice.password });
    const v = sharedVault(alice);
    const it = v.items.find((i) => i.id === st.browserItemId)?.item;
    must(it, 'browser item not decryptable after fvault edited it');
    eq(it.extra, [{ rawKey: '"x_node_future"', rawValue: '{"n":1,"s":"ü","list":[true,null],"big":12345678901234567890}' }], 'unknown top-level member preserved byte for byte by fvault');
    eq(it.notes, E.cliEditedNotes, 'notes edited by fvault');
    eq(it.password, 'p4ss-ü-🔑', 'password untouched by fvault edit');
    eq(it.password_history.length, 0, 'no history entry for a non-password edit');
    eq(v.keyEpoch, Number(st.epoch), 'epoch unchanged by fvault reads');
    const bank = findItem(v, E.items[0]!.name).item!;
    eq(bank.password, st.bankNewPassword, 'bank password written by the browser');
  });
  await step('bob: old password is dead, new password works, and the removed vault is gone from his view', async () => {
    let oldWorked = false;
    try {
      await Session.login(mkDeps(), { username: E.bob.user, password: E.bob.password });
      oldWorked = true;
    } catch {
      /* expected */
    }
    must(!oldWorked, 'the old password still logs in');
    const bob = await Session.login(mkDeps(), { username: E.bob.user, password: E.bob.newPassword });
    must(!bob.vaults.some((v) => v.name === E.vaultName), 'bob still sees the vault he was removed from');
  });
  await step('the vault fvault (as bob) accepted is readable in the browser by alice; bob\'s fvault write is visible', async () => {
    const alice = await Session.login(mkDeps(), { username: E.alice.user, password: E.alice.password });
    const v = sharedVault(alice, E.browserVaultName);
    const it = findItem(v, 'Browser shared item').item!;
    eq(it.password, 'shared-ü-pw-1', 'shared item password');
    const reply = v.items.find((i) => i.item?.name === 'Reply from fvault');
    must(reply, 'the item bob\'s fvault wrote into the browser-shared vault is missing');
  });
}

if (failed) {
  console.log(`\n${failed} check(s) failed`);
  process.exit(1);
}
