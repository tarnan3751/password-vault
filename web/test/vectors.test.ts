// The shared cross-language vectors (testvectors/crypto-v1.json): EVERY group.
// Every positive case must reproduce exactly; every negative case must be rejected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as c from '../src/crypto/index.ts';
import * as t from '../src/crypto/testonly.ts';
import { COMMON_PASSWORDS } from '../src/crypto/common-passwords.ts';

const V = JSON.parse(readFileSync(new URL('../../testvectors/crypto-v1.json', import.meta.url), 'utf8'));
const hx = c.hexToBytes;
const H = c.bytesToHex;
const eq = (a: Uint8Array, b: string, msg?: string) => assert.equal(H(a), b, msg as string);
const kdfOf = (k: { salt_hex: string; time: number; memory_kib: number; parallelism: number }): c.KdfParams => ({ alg: 'argon2id', salt: hx(k.salt_hex), time: k.time, memory_kib: k.memory_kib, parallelism: k.parallelism });
const dec = (s: string) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(s ? hx(s) : new Uint8Array());

test('group counts match testvectors/README.md', () => {
  assert.equal(V.suite, 'fpv/v1');
  assert.equal(V.schema_version, 1);
  const expected: Record<string, number> = {
    password_policy_common: 694, argon2id_published: 6, hkdf_sha256_published: 2, x25519_published: 6, xchacha20poly1305_published: 1,
    master_keys: 9, kdf_params_validation: 20, kdf_not_weaker: 8, box: 5, box_negative: 13, key_pairs: 5, fingerprints: 7,
    vault_key_wrap: 4, vault_key_wrap_negative: 19, padding: 11, vault_meta: 2, vault_meta_negative: 4, items: 5, items_negative: 6,
    rosters: 3, rosters_negative: 22, decoding_accept: 23, decoding_reject: 74, edit_preserve: 3, reencrypt: 8, vault_key_commitments: 5,
    local_trust: 3, local_trust_negative: 6, password_policy: 31, accounts: 1, accounts_negative: 9, backups: 1, backups_negative: 23,
  };
  for (const [g, n] of Object.entries(expected)) assert.equal(V[g].length, n, g);
  // every array group in the file is covered by this test file
  assert.deepEqual(Object.keys(V).filter((k) => Array.isArray(V[k])).sort(), Object.keys(expected).sort());
});

test('argon2id_published', async () => {
  for (const x of V.argon2id_published) eq(await c.argon2idRaw(hx(x.password_hex), hx(x.salt_hex), x.time, x.memory_kib, x.parallelism, x.out_len), x.expected_hex, x.id);
});

test('hkdf_sha256_published', () => {
  for (const x of V.hkdf_sha256_published) {
    const salt = hx(x.salt_hex);
    eq(extract(sha256, hx(x.ikm_hex), salt.length ? salt : undefined), x.prk_hex, x.id + ' prk');
    eq(c.hkdfSha256(hx(x.ikm_hex), hx(x.info_hex), x.length, salt.length ? salt : undefined), x.okm_hex, x.id + ' okm');
  }
});

test('x25519_published', () => {
  for (const x of V.x25519_published) eq(t.x25519Raw(hx(x.scalar_hex), hx(x.u_hex)), x.expected_hex, x.id);
});

test('xchacha20poly1305_published', () => {
  for (const x of V.xchacha20poly1305_published) {
    const box = t.sealWithNonce(hx(x.key_hex), hx(x.nonce_hex), hx(x.plaintext_hex), hx(x.aad_hex));
    eq(box.subarray(25), x.ciphertext_hex + x.tag_hex, x.id);
    eq(c.open(hx(x.key_hex), box, hx(x.aad_hex)), x.plaintext_hex);
  }
});

test('master_keys (username-bound Argon2 salt)', async () => {
  for (const x of V.master_keys) {
    eq(c.normalizePassword(x.password), x.normalized_password_hex, x.id + ' normalization');
    eq(c.utf8(x.password), x.password_hex, x.id + ' utf8');
    const params = kdfOf(x);
    eq(c.argonSalt(x.username, params.salt), x.argon_salt_hex, x.id + ' argon salt');
    const k = await t.deriveMasterKeysUnsafeParams({ username: x.username, password: x.password, params });
    eq(k.encKey, x.enc_key_hex, x.id + ' encKey');
    eq(k.loginKey, x.login_key_hex, x.id + ' loginKey');
    eq(await c.argon2idRaw(c.normalizePassword(x.password), c.argonSalt(x.username, params.salt), params.time, params.memory_kib, params.parallelism, 32), x.master_key_hex, x.id + ' MK');
    if (x.below_production_minimum) await assert.rejects(() => c.deriveMasterKeys({ username: x.username, password: x.password, params }), c.KdfParamsError, x.id);
    else eq((await c.deriveMasterKeys({ username: x.username, password: x.password, params })).encKey, x.enc_key_hex, x.id + ' validating');
  }
});

test('kdf_params_validation', () => {
  for (const x of V.kdf_params_validation) {
    const p: c.KdfParams = { alg: x.alg, salt: hx(x.salt_hex), time: x.time, memory_kib: x.memory_kib, parallelism: x.parallelism };
    if (x.valid) assert.doesNotThrow(() => c.validateKdfParams(p), x.id);
    else assert.throws(() => c.validateKdfParams(p), c.KdfParamsError, x.id);
  }
});

test('kdf_not_weaker', () => {
  const base = { alg: 'argon2id', salt: new Uint8Array(16), parallelism: 1 };
  for (const x of V.kdf_not_weaker) {
    const cached = { ...base, time: x.cached_time, memory_kib: x.cached_memory_kib };
    const offered = { ...base, time: x.offered_time, memory_kib: x.offered_memory_kib };
    if (x.acceptable) assert.doesNotThrow(() => c.checkKdfNotWeaker(cached, offered), x.id);
    else assert.throws(() => c.checkKdfNotWeaker(cached, offered), c.KdfParamsError, x.id);
  }
});

test('box / box_negative', () => {
  for (const x of V.box) {
    eq(t.sealWithNonce(hx(x.key_hex), hx(x.nonce_hex), hx(x.plaintext_hex), hx(x.aad_hex)), x.box_hex, x.id);
    eq(c.open(hx(x.key_hex), hx(x.box_hex), hx(x.aad_hex)), x.plaintext_hex, x.id + ' open');
  }
  for (const x of V.box_negative) assert.throws(() => c.open(hx(x.key_hex), hx(x.box_hex), hx(x.aad_hex)), c.DecryptError, x.id);
});

test('key_pairs', () => {
  for (const x of V.key_pairs) eq(c.publicKeyFromPrivate(hx(x.private_key_hex)), x.public_key_hex, x.id);
});

test('fingerprints (128-bit, identity-bound)', () => {
  for (const x of V.fingerprints) {
    const fp = c.fingerprint({ userId: x.user_id, username: x.username, publicKey: hx(x.public_key_hex) });
    assert.equal(fp, x.fingerprint, x.id);
    assert.match(fp, /^([0-9a-f]{4}-){7}[0-9a-f]{4}$/);
  }
});

test('vault_key_wrap / vault_key_wrap_negative', () => {
  for (const x of V.vault_key_wrap) {
    const ctx = { vaultId: x.vault_id, keyEpoch: x.key_epoch, senderId: x.sender_id, recipientId: x.recipient_id };
    assert.equal(new TextDecoder().decode(c.wrapAad(ctx)), x.aad, x.id + ' aad');
    eq(c.publicKeyFromPrivate(hx(x.sender_private_hex)), x.sender_public_hex);
    eq(c.publicKeyFromPrivate(hx(x.recipient_private_hex)), x.recipient_public_hex);
    eq(c.publicKeyFromPrivate(hx(x.ephemeral_private_hex)), x.ephemeral_public_hex);
    const w = t.wrapVaultKeyDeterministic({ vaultKey: hx(x.vault_key_hex), ctx, senderPrivate: hx(x.sender_private_hex), recipientPublic: hx(x.recipient_public_hex), ephemeralPrivate: hx(x.ephemeral_private_hex), nonce: hx(x.nonce_hex) });
    eq(w, x.wrap_hex, x.id);
    assert.equal(w.length, 105);
    eq(c.unwrapVaultKey({ wrap: hx(x.wrap_hex), ctx, recipientPrivate: hx(x.recipient_private_hex), senderPublic: hx(x.sender_public_hex) }), x.vault_key_hex, x.id + ' unwrap');
    const w2 = c.wrapVaultKey({ vaultKey: hx(x.vault_key_hex), ctx, senderPrivate: hx(x.sender_private_hex), recipientPublic: hx(x.recipient_public_hex) });
    eq(c.unwrapVaultKey({ wrap: w2, ctx, recipientPrivate: hx(x.recipient_private_hex), senderPublic: hx(x.sender_public_hex) }), x.vault_key_hex);
  }
  for (const x of V.vault_key_wrap_negative) {
    const ctx = { vaultId: x.vault_id, keyEpoch: x.key_epoch, senderId: x.sender_id, recipientId: x.recipient_id };
    assert.throws(() => c.unwrapVaultKey({ wrap: hx(x.wrap_hex), ctx, recipientPrivate: hx(x.recipient_private_hex), senderPublic: hx(x.sender_public_hex) }), x.id);
  }
});

test('padding', () => {
  for (const x of V.padding) eq(c.pad(hx(x.input_hex), x.n), x.padded_hex, x.id);
});

test('vault_meta / vault_meta_negative (epoch-bound AAD)', () => {
  for (const x of V.vault_meta) {
    assert.equal(x.aad, `fpv/v1/vault-meta|${x.vault_id}|${x.key_epoch}`);
    const pt = c.pad(c.utf8(x.plaintext_json), 64);
    assert.equal(pt.length, x.padded_length);
    eq(t.sealWithNonce(hx(x.key_hex), hx(x.nonce_hex), pt, c.utf8(x.aad)), x.blob_hex, x.id);
    const m = c.decryptVaultMeta(hx(x.key_hex), { vaultId: x.vault_id, epoch: x.key_epoch }, hx(x.blob_hex));
    assert.equal(c.vaultMetaToJson(m), x.plaintext_json, x.id + ' canonical re-encode');
    eq(t.sealMetaWithNonce({ vaultKey: hx(x.key_hex), vaultId: x.vault_id, epoch: x.key_epoch, name: m.name, extra: m.extra, nonce: hx(x.nonce_hex) }), x.blob_hex, x.id + ' re-seal');
  }
  for (const x of V.vault_meta_negative) assert.throws(() => c.decryptVaultMeta(hx(x.key_hex), { vaultId: x.vault_id, epoch: x.key_epoch }, hx(x.blob_hex)), c.DecryptError, x.id);
});

test('items / items_negative', () => {
  for (const x of V.items) {
    assert.equal(x.aad, `fpv/v1/item|${x.vault_id}|${x.item_id}|${x.key_epoch}`);
    const pt = c.pad(c.utf8(x.plaintext_json), 256);
    assert.equal(pt.length, x.padded_length);
    eq(t.sealWithNonce(hx(x.key_hex), hx(x.nonce_hex), pt, c.utf8(x.aad)), x.blob_hex, x.id);
    const it = c.decryptItem(hx(x.key_hex), { vaultId: x.vault_id, itemId: x.item_id, epoch: x.key_epoch }, hx(x.blob_hex));
    assert.equal(c.itemToJson(it), x.plaintext_json, x.id + ' canonical re-encode');
    eq(t.sealItemWithNonce({ vaultKey: hx(x.key_hex), vaultId: x.vault_id, itemId: x.item_id, epoch: x.key_epoch, item: it, nonce: hx(x.nonce_hex) }), x.blob_hex, x.id + ' re-seal');
  }
  const full = V.items.find((x: { id: string }) => x.id === 'item-login-full');
  const it = c.decryptItem(hx(full.key_hex), { vaultId: full.vault_id, itemId: full.item_id, epoch: full.key_epoch }, hx(full.blob_hex));
  assert.ok(c.itemToJson(c.editItem(it, 1, (v) => void (v.name = 'edited'))).includes(it.extra[0]!.rawKey + ':' + it.extra[0]!.rawValue), 'unknown member survives an edit byte for byte');
  for (const x of V.items_negative) assert.throws(() => c.decryptItem(hx(x.key_hex), { vaultId: x.vault_id, itemId: x.item_id, epoch: x.key_epoch }, hx(x.blob_hex)), c.DecryptError, x.id);
});

const decodeKind = (kind: string, pt: Uint8Array) => (kind === 'item' ? c.itemToJson(c.decodeItem(pt)) : kind === 'meta' ? c.vaultMetaToJson(c.decodeVaultMeta(pt)) : c.rosterToJson(c.decodeRoster(pt)));

test('rosters / rosters_negative', () => {
  for (const x of V.rosters) {
    assert.equal(x.aad, `fpv/v1/roster|${x.vault_id}|${x.key_epoch}`);
    const r = c.decryptRoster(hx(x.key_hex), { vaultId: x.vault_id, epoch: x.key_epoch }, hx(x.blob_hex));
    assert.equal(c.rosterToJson(r), x.plaintext_json, x.id);
    eq(t.sealRosterWithNonce({ vaultKey: hx(x.key_hex), vaultId: x.vault_id, epoch: x.key_epoch, roster: r, nonce: hx(x.nonce_hex) }), x.blob_hex, x.id + ' re-seal');
  }
  for (const x of V.rosters_negative) assert.throws(() => c.decryptRoster(hx(x.key_hex), { vaultId: x.vault_id, epoch: x.key_epoch }, hx(x.blob_hex)), x.id);
});

test('decoding_accept: canonical encoding is exactly the expected text and a fixed point', () => {
  for (const x of V.decoding_accept) {
    const pt = hx(x.plaintext_hex);
    const out = decodeKind(x.kind, pt);
    assert.equal(out, x.canonical_json, x.id);
    assert.equal(decodeKind(x.kind, c.utf8(out)), out, x.id + ' fixed point');
  }
});

test('decoding_reject', () => {
  for (const x of V.decoding_reject) assert.throws(() => decodeKind(x.kind, hx(x.plaintext_hex)), c.UnreadableError, x.id);
});

test('edit_preserve: unknown top-level members survive an edit byte for byte', () => {
  for (const x of V.edit_preserve) {
    const pt = hx(x.plaintext_hex);
    if (x.kind === 'item') {
      const it = c.decodeItem(pt);
      it.name = x.new_name;
      assert.equal(c.itemToJson(it), x.expected_json, x.id);
    } else {
      const m = c.decodeVaultMeta(pt);
      assert.equal(c.vaultMetaToJson({ name: x.new_name, extra: m.extra }), x.expected_json, x.id);
    }
  }
});

test('reencrypt: raw plaintext re-sealed, or the box returned unchanged', () => {
  for (const x of V.reencrypt) {
    const base = { oldKey: hx(x.old_key_hex), newKey: hx(x.new_key_hex), vaultId: x.vault_id, oldEpoch: x.old_epoch, newEpoch: x.new_epoch, blob: hx(x.input_blob_hex) };
    const r = x.kind === 'item' ? c.reencryptItem({ ...base, itemId: x.item_id }) : c.reencryptMeta(base);
    assert.equal(r.opened, x.opened, x.id);
    if (!x.opened) eq(r.blob, x.output_blob_hex, x.id + ' unchanged');
    else {
      // production re-seals with a fresh nonce: check by opening; the deterministic output is checked with the test-only variant
      const oldAad = x.kind === 'item' ? c.itemAad(x.vault_id, x.item_id, x.old_epoch) : c.vaultMetaAad(x.vault_id, x.old_epoch);
      const newAad = x.kind === 'item' ? c.itemAad(x.vault_id, x.item_id, x.new_epoch) : c.vaultMetaAad(x.vault_id, x.new_epoch);
      assert.deepEqual(c.open(base.newKey, r.blob, newAad), c.open(base.oldKey, base.blob, oldAad), x.id + ' same raw plaintext');
      eq(t.reencryptWithNonce({ oldKey: base.oldKey, newKey: base.newKey, oldAad, newAad, blob: base.blob, nonce: hx(x.nonce_hex) }).blob, x.output_blob_hex, x.id + ' deterministic');
    }
  }
});

test('vault_key_commitments', () => {
  for (const x of V.vault_key_commitments) assert.equal(c.vaultKeyCommitment({ vaultKey: hx(x.vault_key_hex), vaultId: x.vault_id, epoch: x.key_epoch }), x.commitment_hex, x.id);
});

test('local_trust / local_trust_negative', () => {
  for (const x of V.local_trust) {
    eq(c.localTrustKey(hx(x.account_key_hex)), x.trust_key_hex, x.id);
    assert.equal(x.aad, 'fpv/v1/local-trust|' + x.user_id);
    eq(t.sealLocalTrustWithNonce({ accountKey: hx(x.account_key_hex), userId: x.user_id, plaintext: hx(x.plaintext_hex), nonce: hx(x.nonce_hex) }), x.blob_hex, x.id);
    eq(c.openLocalTrust({ accountKey: hx(x.account_key_hex), userId: x.user_id, blob: hx(x.blob_hex) }), x.plaintext_hex, x.id + ' open');
  }
  for (const x of V.local_trust_negative) assert.throws(() => c.openLocalTrust({ accountKey: hx(x.account_key_hex), userId: x.user_id, blob: hx(x.blob_hex) }), c.DecryptError, x.id);
});

test('password_policy (+ common list module equals the vector array)', () => {
  assert.deepEqual([...COMMON_PASSWORDS], V.password_policy_common, 'src/crypto/common-passwords.ts is stale: run node scripts/gen-common-passwords.mjs');
  for (const x of V.password_policy) {
    const r = c.checkMasterPassword(x.password, x.username);
    assert.equal(r?.code ?? 'ok', x.expect, x.id);
    assert.equal(c.passwordHint(x.password) !== '', x.hint, x.id + ' hint');
  }
});

test('accounts / accounts_negative', async () => {
  for (const x of V.accounts) {
    const params = kdfOf(x.kdf);
    const k = await c.deriveMasterKeys({ username: x.username, password: x.password, params }); // validating variant: smallest accepted parameters
    eq(k.encKey, x.enc_key_hex);
    eq(k.loginKey, x.login_key_hex);
    const m = t.createAccountMaterialDeterministic({ userId: x.user_id, encKey: k.encKey, accountKey: hx(x.account_key_hex), privateKey: hx(x.private_key_hex), nonceWrapped: hx(x.nonce_wrapped_account_key_hex), nonceEncPrivate: hx(x.nonce_enc_private_key_hex) });
    eq(m.publicKey, x.public_key_hex);
    eq(m.wrappedAccountKey, x.wrapped_account_key_hex);
    eq(m.encPrivateKey, x.enc_private_key_hex);
    const u = c.unlockAccount({ userId: x.user_id, encKey: k.encKey, publicKey: hx(x.public_key_hex), wrappedAccountKey: hx(x.wrapped_account_key_hex), encPrivateKey: hx(x.enc_private_key_hex) });
    eq(u.accountKey, x.account_key_hex);
    eq(u.privateKey, x.private_key_hex);
    const pc = x.password_change;
    const nkeys = await c.deriveMasterKeys({ username: x.username, password: pc.new_password, params: kdfOf(pc.new_kdf) });
    eq(nkeys.encKey, pc.new_enc_key_hex);
    eq(nkeys.loginKey, pc.new_login_key_hex);
    const rewrapped = t.rewrapAccountKeyWithNonce({ userId: x.user_id, newEncKey: nkeys.encKey, accountKey: u.accountKey, nonce: hx(pc.new_nonce_hex) });
    eq(rewrapped, pc.new_wrapped_account_key_hex);
    eq(c.unlockAccount({ userId: x.user_id, encKey: nkeys.encKey, publicKey: hx(x.public_key_hex), wrappedAccountKey: rewrapped, encPrivateKey: hx(x.enc_private_key_hex) }).privateKey, x.private_key_hex);
  }
  for (const x of V.accounts_negative) {
    const k = await c.deriveMasterKeys({ username: x.username, password: x.password, params: kdfOf(x.kdf) });
    const cls = x.expect_error === 'public_key_mismatch' ? c.PublicKeyMismatchError : c.DecryptError;
    assert.throws(() => c.unlockAccount({ userId: x.user_id, encKey: k.encKey, publicKey: hx(x.public_key_hex), wrappedAccountKey: hx(x.wrapped_account_key_hex), encPrivateKey: hx(x.enc_private_key_hex) }), cls, x.id);
  }
});

test('backups / backups_negative', async () => {
  for (const x of V.backups) {
    const kdf = kdfOf(x.kdf);
    eq(await c.deriveBackupKey(x.passphrase, kdf), x.backup_key_hex, 'backup key (raw salt)');
    for (const pass of [x.passphrase, ...x.alternate_passphrases]) {
      const p = await c.decodeBackup(x.file, pass);
      assert.equal(c.payloadToJson(p), x.payload_json, 'payload re-encodes byte for byte');
    }
    const p = await c.decodeBackup(x.file, x.passphrase);
    const text = await t.encodeBackupDeterministic(p, x.passphrase, kdf, x.created_at, hx(x.nonce_hex));
    assert.deepEqual(JSON.parse(text), JSON.parse(x.file));
    // the production encoder produces a file the same decoder accepts
    assert.equal(c.payloadToJson(await c.decodeBackup(await c.encodeBackup(p, 'another passphrase', kdf), 'another passphrase')), x.payload_json);
  }
  for (const x of V.backups_negative) {
    await assert.rejects(() => c.decodeBackup(x.file, x.passphrase), (e: unknown) => e instanceof c.BackupError && e.code === x.expect_error, `${x.id} (want ${x.expect_error})`);
  }
});
void dec;
