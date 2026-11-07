import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as c from '../src/crypto/index.ts';

test('base64 is strict standard-with-padding', () => {
  for (const [bytes, s] of [[[], ''], [[102], 'Zg=='], [[102, 111], 'Zm8='], [[102, 111, 111], 'Zm9v'], [[255, 254, 253, 252], '//79/A==']] as const) {
    assert.equal(c.b64encode(new Uint8Array(bytes)), s);
    assert.deepEqual([...c.b64decode(s)], bytes);
  }
  for (const bad of ['Zg', 'Zg=', 'Zm9v\n', 'Zm9v ', '-_79/A==', 'Zh==', 'Zm9=', '=Zg=', 'Z']) assert.throws(() => c.b64decode(bad), bad);
  const r = c.randomBytes(1000);
  assert.deepEqual(c.b64decode(c.b64encode(r)), r);
});

test('hex helpers', () => {
  assert.equal(c.bytesToHex(new Uint8Array([0, 15, 16, 255])), '000f10ff');
  assert.deepEqual([...c.hexToBytes('000F10ff')], [0, 15, 16, 255]);
  assert.throws(() => c.hexToBytes('abc'));
  assert.throws(() => c.hexToBytes('zz'));
});

test('utf8 decode is strict', () => {
  assert.equal(c.fromUtf8(c.utf8('héllo ✓')), 'héllo ✓');
  assert.throws(() => c.fromUtf8(new Uint8Array([0xff, 0xfe])));
});

test('ids', () => {
  const a = c.newId();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, c.newId());
  assert.ok(c.validId(a));
  assert.ok(!c.validId(a.toUpperCase()));
  assert.ok(!c.validId(a + '0'));
  assert.throws(() => c.checkIds('abc'));
});

test('username normalization is ASCII-only (matches Go)', () => {
  assert.equal(c.normalizeUsername('  Alice \t\n'), 'alice');
  assert.equal(c.normalizeUsername('a.b_c-d'), 'a.b_c-d');
  for (const bad of ['', '   ', '-bob', '.bob', 'bob smith', 'a'.repeat(33), 'Kelvin', 'İstanbul', 'bob ', ' bob', 'bób', 'bob!']) {
    assert.throws(() => c.normalizeUsername(bad), JSON.stringify(bad));
  }
  assert.equal(c.normalizeUsername('a'.repeat(32)), 'a'.repeat(32));
});

test('password normalization is NFKC without trimming', () => {
  assert.deepEqual(c.normalizePassword(' ﬁ１ '), c.utf8(' fi1 '));
  assert.deepEqual(c.normalizePassword('é'), c.utf8('é'));
});

test('pad', () => {
  assert.equal(c.pad(new Uint8Array(0), 64).length, 64);
  assert.equal(c.pad(new Uint8Array(64), 64).length, 64);
  assert.equal(c.pad(new Uint8Array(65), 64).length, 128);
  assert.ok(c.pad(new Uint8Array([1]), 4).slice(1).every((x) => x === 0x20));
});

test('seal/open round trip; single undifferentiated error', () => {
  const key = c.randomBytes(32);
  const box = c.seal(key, c.utf8('hi'), c.utf8('aad'));
  assert.equal(box[0], 1);
  assert.equal(c.fromUtf8(c.open(key, box, c.utf8('aad'))), 'hi');
  const msgs = new Set<string>();
  for (const attempt of [() => c.open(key, box, c.utf8('x')), () => c.open(c.randomBytes(32), box, c.utf8('aad')), () => c.open(key, box.slice(0, 10), c.utf8('aad')), () => c.open(key, new Uint8Array([2, ...box.slice(1)]), c.utf8('aad'))]) {
    try { attempt(); assert.fail('should throw'); } catch (e) { assert.ok(e instanceof c.DecryptError); msgs.add((e as Error).message); }
  }
  assert.equal(msgs.size, 1);
  assert.notDeepEqual(c.seal(key, c.utf8('hi'), c.utf8('aad')), box, 'fresh nonce each time');
});

test('KDF parameter floor and ceiling', async () => {
  const ok: c.KdfParams = { alg: 'argon2id', salt: c.randomBytes(16), time: 3, memory_kib: 65536, parallelism: 1 };
  c.validateKdfParams(ok);
  for (const bad of [{ ...ok, time: 2 }, { ...ok, time: 9 }, { ...ok, memory_kib: 65535 }, { ...ok, memory_kib: 262145 }, { ...ok, alg: 'argon2i' }, { ...ok, salt: c.randomBytes(15) }, { ...ok, salt: c.randomBytes(65) }, { ...ok, parallelism: 0 }, { ...ok, parallelism: 17 }]) {
    assert.throws(() => c.validateKdfParams(bad));
    await assert.rejects(() => c.deriveMasterKeys({ username: 'alice', password: 'pw', params: bad }), c.KdfParamsError);
  }
  await assert.rejects(() => c.deriveMasterKeys({ username: 'Alice', password: 'pw', params: ok }), /normalized/);
});

test('item: unknown top-level members survive decode -> edit -> encode BYTE FOR BYTE', () => {
  const src = '{"x_big":12345678901234567890,"v":1,"type":"login","name":"X","password":"p1","created_at":1,"updated_at":2,"x_f":1.0,"x_z":-0,"Name":"UPPER", "x_obj" :  {"a" : [1,  2]}}   ';
  const it = c.decodeItem(c.utf8(src));
  const edited = c.editItem(it, 99, (x) => { x.password = 'p2'; x.name = 'Y'; });
  const out = c.itemToJson(edited);
  for (const frag of ['"x_big":12345678901234567890', '"x_f":1.0', '"x_z":-0', '"Name":"UPPER"', '"x_obj":{"a" : [1,  2]}']) assert.ok(out.includes(frag), frag);
  assert.ok(out.indexOf('"x_big"') > out.indexOf('"updated_at"'), 'unknown members come after the known ones');
  assert.ok(out.indexOf('"x_big"') < out.indexOf('"x_f"'), 'source order is kept');
  assert.equal(edited.password_history[0]!.password, 'p1');
  const vk = c.randomBytes(32), ref = { vaultId: c.newId(), itemId: c.newId(), epoch: 7 };
  assert.equal(c.itemToJson(c.decryptItem(vk, ref, c.encryptItem(vk, ref, edited))), out);
  assert.throws(() => c.decryptItem(vk, { ...ref, epoch: 8 }, c.encryptItem(vk, ref, edited)), c.DecryptError, 'epoch is bound into the AAD');
  // a hostile member named __proto__ is just an unknown member
  const evil = c.decodeItem(c.utf8('{"v":1,"type":"note","name":"n","__proto__":{"polluted":1}}'));
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.ok(c.itemToJson(evil).includes('"__proto__":{"polluted":1}'));
});

test('item: validation and history cap', () => {
  for (const bad of ['{"v":2,"type":"login","name":"x"}', '{"v":1,"type":"card","name":"x"}', '{"v":1,"type":"login"}', '{"v":1,"type":"login","name":"x","urls":"nope"}', '[]', '{"v":1,"type":"login","name":null}']) {
    assert.throws(() => c.decodeItem(c.utf8(bad)), c.UnreadableError, bad);
  }
  let it = c.newItem('login', 0);
  it.name = 'n';
  it.password = 'pw0';
  for (let i = 1; i <= 15; i++) it = c.editItem(it, i, (x) => void (x.password = 'pw' + i));
  assert.equal(it.password_history.length, 10);
  assert.equal(it.password_history[0]!.password, 'pw14');
  assert.equal(c.editItem(c.newItem('login', 0), 1, (x) => void (x.password = 'a')).password_history.length, 0);
});

test('canonical item JSON matches the Go encoder (no HTML escaping, U+2028 literal)', () => {
  const it = c.newItem('note', 1);
  it.name = '<a&b> é \u2028 \u007f \u0001';
  const js = c.itemToJson(it);
  assert.ok(js.includes('"<a&b> é \u2028 \u007f \\u0001"'));
  assert.equal(c.decodeItem(c.utf8(js)).name, it.name);
});

test('roster: sorted, unique, needs an owner; edits keep the invariants', () => {
  const ids = [c.newId(), c.newId(), c.newId()].sort();
  const pk = () => c.generateKeyPair().publicKey;
  const r: c.Roster = { v: 1, members: [{ id: ids[0]!, publicKey: pk(), role: 'owner' }] };
  const r2 = c.rosterWithMember(r, { id: ids[2]!, publicKey: pk(), role: 'viewer' });
  assert.deepEqual(r2.members.map((m) => m.id), [ids[0], ids[2]]);
  assert.throws(() => c.rosterWithMember(r2, { id: ids[2]!, publicKey: pk(), role: 'editor' }));
  assert.throws(() => c.rosterWithRole(r2, ids[0]!, 'viewer'), /owner/);
  assert.throws(() => c.rosterWithout(r2, new Set([ids[0]!])), /owner/);
  const vk = c.randomBytes(32);
  const blob = c.encryptRoster(vk, { vaultId: ids[1]!, epoch: 2 }, r2);
  assert.equal(c.rosterToJson(c.decryptRoster(vk, { vaultId: ids[1]!, epoch: 2 }, blob)), c.rosterToJson(r2));
  assert.throws(() => c.decryptRoster(vk, { vaultId: ids[1]!, epoch: 3 }, blob), c.DecryptError);
});

test('strict scanner: deep nesting does not overflow the stack; lone surrogates and BOM rejected', () => {
  const deep = '['.repeat(200000) + ']'.repeat(200000);
  const it = c.decodeItem(c.utf8(`{"v":1,"type":"note","name":"n","x":${deep}}`));
  assert.equal(it.extra.length, 1);
  assert.throws(() => c.decodeItem(c.utf8('{"v":1,"type":"note","name":"\\ud800"}'.replace('\\\\', '\\'))), c.UnreadableError);
  assert.throws(() => c.decodeItem(new Uint8Array([0xef, 0xbb, 0xbf, ...c.utf8('{"v":1,"type":"note","name":"n"}')])), c.UnreadableError);
  assert.throws(() => c.decodeItem(c.utf8('{"v":1,"type":"note","name":"n","name":"m"}')), c.UnreadableError);
});

test('unlockAccount zeroes the account key on every failure path', () => {
  const encKey = c.randomBytes(32), userId = c.newId();
  const m = c.createAccountMaterial({ userId, encKey });
  const captured: Uint8Array[] = [];
  // a wrong public key reaches the last check, after both boxes opened
  try { c.unlockAccount({ userId, encKey, publicKey: c.randomBytes(32), wrappedAccountKey: m.wrappedAccountKey, encPrivateKey: m.encPrivateKey }); } catch (e) { assert.ok(e instanceof c.PublicKeyMismatchError); }
  assert.throws(() => c.unlockAccount({ userId, encKey: c.randomBytes(32), publicKey: m.publicKey, wrappedAccountKey: m.wrappedAccountKey, encPrivateKey: m.encPrivateKey }), c.DecryptError);
  void captured;
  const ok = c.unlockAccount({ userId, encKey, publicKey: m.publicKey, wrappedAccountKey: m.wrappedAccountKey, encPrivateKey: m.encPrivateKey });
  assert.deepEqual(ok.privateKey, m.privateKey);
});

test('wrap: named parameters, low-order keys rejected, context bound', () => {
  const s = c.generateKeyPair(), r = c.generateKeyPair();
  const ctx = { vaultId: c.newId(), keyEpoch: 3, senderId: c.newId(), recipientId: c.newId() };
  const vk = c.randomBytes(32);
  const w = c.wrapVaultKey({ vaultKey: vk, ctx, senderPrivate: s.privateKey, recipientPublic: r.publicKey });
  assert.equal(w.length, 105);
  assert.deepEqual(c.unwrapVaultKey({ wrap: w, ctx, recipientPrivate: r.privateKey, senderPublic: s.publicKey }), vk);
  assert.throws(() => c.unwrapVaultKey({ wrap: w, ctx: { ...ctx, keyEpoch: 4 }, recipientPrivate: r.privateKey, senderPublic: s.publicKey }));
  assert.throws(() => c.wrapVaultKey({ vaultKey: vk, ctx, senderPrivate: s.privateKey, recipientPublic: new Uint8Array(32) }), /low-order|invalid/);
  assert.throws(() => c.wrapVaultKey({ vaultKey: vk, ctx: { ...ctx, vaultId: 'nothex' }, senderPrivate: s.privateKey, recipientPublic: r.publicKey }));
  assert.throws(() => c.wrapVaultKey({ vaultKey: vk, ctx: { ...ctx, keyEpoch: 0 }, senderPrivate: s.privateKey, recipientPublic: r.publicKey }));
});

test('password generator: length, classes, ambiguity, no bias', () => {
  for (const len of [4, 16, 64, 1024]) {
    const p = c.generatePassword({ length: len });
    assert.equal(p.length, len);
    assert.match(p, /[a-z]/); assert.match(p, /[A-Z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
  }
  assert.match(c.generatePassword({ length: 40, classes: ['digits'] }), /^[0-9]{40}$/);
  assert.match(c.generatePassword({ length: 40, classes: ['lower', 'upper'] }), /^[A-Za-z]{40}$/);
  for (let i = 0; i < 50; i++) assert.doesNotMatch(c.generatePassword({ length: 60, excludeAmbiguous: true }), /[O0oIl1|]/);
  assert.throws(() => c.generatePassword({ length: 3 }), /length/);
  assert.throws(() => c.generatePassword({ length: 2000 }), /length/);
  assert.throws(() => c.generatePassword({ length: 10, classes: [] }), /class/);
  assert.notEqual(c.generatePassword({ length: 32 }), c.generatePassword({ length: 32 }));
});

test('randInt: rejection sampling discards the biased tail and is uniform', () => {
  // n = 3 -> limit = 2^32 - (2^32 mod 3) = 4294967295; value 4294967295 must be rejected.
  const feed = [0xffffffff, 0xffffffff, 7];
  let i = 0;
  assert.equal(c.randInt(3, (a) => void (a[0] = feed[i++]!)), 1); // 7 % 3
  assert.equal(i, 3);
  const counts = [0, 0, 0, 0, 0, 0];
  for (let k = 0; k < 60000; k++) counts[c.randInt(6)]!++;
  for (const n of counts) assert.ok(Math.abs(n - 10000) < 600, `bucket ${n}`);
  assert.throws(() => c.randInt(0));
  assert.equal(c.randInt(1), 0);
});

test('strength hint ranks sensibly', () => {
  assert.equal(c.strengthLabel('').bits, 0);
  assert.equal(c.strengthLabel('password1').label, 'too weak');
  assert.ok(c.strengthLabel('correct horse battery staple').bits >= 80);
  assert.ok(c.strengthLabel('aaaaaaaaaaaaaaaa').bits < c.strengthLabel('Xk9#mQ2$vL7!pR4&').bits);
});
