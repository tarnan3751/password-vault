// TEST-VECTOR-ONLY entry points: fixed nonces, fixed ephemeral keys, a KDF
// without the parameter floor, raw X25519. NOTHING under src/ except tests and
// scripts may import this module; the production bundle must not contain it
// (test/dist-csp.test.ts greps the build for TESTONLY_MARKER). They exist so
// the shared vectors can pin deterministic outputs without putting a
// "nonce" parameter on any production function.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { accountKeyAad, privateKeyAad, type AccountMaterial } from './account.ts';
import { BOX_VERSION, NONCE_LEN } from './box.ts';
import { backupFileText, BACKUP_AAD, type BackupPayload, payloadToJson } from './backup.ts';
import { concat, utf8 } from './encoding.ts';
import { itemAad, ITEM_PAD_BLOCK, encodeItem, META_PAD_BLOCK, rosterAad, vaultMetaAad, vaultMetaToJson, type ExtraMember, type Item } from './item.ts';
import { argon2idRaw, argonSalt, deriveBackupKey, hkdfSha256, INFO_ENC_KEY, INFO_LOGIN_KEY, KDF_ALG, type KdfParams, type MasterKeys } from './kdf.ts';
import { publicKeyFromPrivate, dh } from './keys.ts';
import { pad } from './pad.ts';
import { localTrustAad, localTrustKey } from './trust.ts';
import { encodeRoster, type Roster } from './roster.ts';
import { deriveWrapKey, wrapAad, WRAP_LEN, WRAP_VERSION, type WrapContext } from './wrap.ts';
import { normalizePassword } from './ids.ts';
import { open } from './box.ts';
import { zero } from './encoding.ts';

export const TESTONLY_MARKER = 'fpv-testonly-module-do-not-bundle';

export function sealWithNonce(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('seal: key must be 32 bytes');
  if (nonce.length !== NONCE_LEN) throw new Error('seal: nonce must be 24 bytes');
  return concat(new Uint8Array([BOX_VERSION]), nonce, xchacha20poly1305(key, nonce, aad).encrypt(plaintext));
}

export function x25519Raw(scalar: Uint8Array, u: Uint8Array): Uint8Array {
  return x25519.scalarMult(scalar, u);
}

export async function deriveMasterKeysUnsafeParams(p: { username: string; password: string; params: KdfParams }): Promise<MasterKeys> {
  const k = p.params;
  if (k.alg !== KDF_ALG || k.time < 1 || k.parallelism < 1 || k.memory_kib < 8 * k.parallelism) throw new Error('cannot run argon2id with these parameters');
  const pw = normalizePassword(p.password);
  const mk = await argon2idRaw(pw, argonSalt(p.username, k.salt), k.time, k.memory_kib, k.parallelism, 32);
  zero(pw);
  const out = { encKey: hkdfSha256(mk, INFO_ENC_KEY), loginKey: hkdfSha256(mk, INFO_LOGIN_KEY) };
  zero(mk);
  return out;
}

export function wrapVaultKeyDeterministic(p: { vaultKey: Uint8Array; ctx: WrapContext; senderPrivate: Uint8Array; recipientPublic: Uint8Array; ephemeralPrivate: Uint8Array; nonce: Uint8Array }): Uint8Array {
  const aad = wrapAad(p.ctx);
  const pkE = publicKeyFromPrivate(p.ephemeralPrivate);
  const pkS = publicKeyFromPrivate(p.senderPrivate);
  const dh1 = dh({ privateKey: p.ephemeralPrivate, publicKey: p.recipientPublic });
  const dh2 = dh({ privateKey: p.senderPrivate, publicKey: p.recipientPublic });
  const key = deriveWrapKey(dh1, dh2, pkE, pkS, p.recipientPublic);
  const out = concat(new Uint8Array([WRAP_VERSION]), pkE, p.nonce, xchacha20poly1305(key, p.nonce, aad).encrypt(p.vaultKey));
  if (out.length !== WRAP_LEN) throw new Error('wrap has wrong length');
  return out;
}

export function createAccountMaterialDeterministic(p: { userId: string; encKey: Uint8Array; accountKey: Uint8Array; privateKey: Uint8Array; nonceWrapped: Uint8Array; nonceEncPrivate: Uint8Array }): AccountMaterial {
  return {
    accountKey: p.accountKey, privateKey: p.privateKey, publicKey: publicKeyFromPrivate(p.privateKey),
    wrappedAccountKey: sealWithNonce(p.encKey, p.nonceWrapped, p.accountKey, accountKeyAad(p.userId)),
    encPrivateKey: sealWithNonce(p.accountKey, p.nonceEncPrivate, p.privateKey, privateKeyAad(p.userId)),
  };
}

export const rewrapAccountKeyWithNonce = (p: { userId: string; newEncKey: Uint8Array; accountKey: Uint8Array; nonce: Uint8Array }): Uint8Array =>
  sealWithNonce(p.newEncKey, p.nonce, p.accountKey, accountKeyAad(p.userId));

export const sealItemWithNonce = (p: { vaultKey: Uint8Array; vaultId: string; itemId: string; epoch: number; item: Item; nonce: Uint8Array }): Uint8Array =>
  sealWithNonce(p.vaultKey, p.nonce, pad(encodeItem(p.item), ITEM_PAD_BLOCK), itemAad(p.vaultId, p.itemId, p.epoch));

export const sealMetaWithNonce = (p: { vaultKey: Uint8Array; vaultId: string; epoch: number; name: string; extra?: readonly ExtraMember[]; nonce: Uint8Array }): Uint8Array =>
  sealWithNonce(p.vaultKey, p.nonce, pad(utf8(vaultMetaToJson({ name: p.name, extra: p.extra })), META_PAD_BLOCK), vaultMetaAad(p.vaultId, p.epoch));

export const sealRosterWithNonce = (p: { vaultKey: Uint8Array; vaultId: string; epoch: number; roster: Roster; nonce: Uint8Array }): Uint8Array =>
  sealWithNonce(p.vaultKey, p.nonce, encodeRoster(p.roster), rosterAad(p.vaultId, p.epoch));

export function reencryptWithNonce(p: { oldKey: Uint8Array; newKey: Uint8Array; oldAad: Uint8Array; newAad: Uint8Array; blob: Uint8Array; nonce: Uint8Array }): { blob: Uint8Array; opened: boolean } {
  let pt: Uint8Array;
  try {
    pt = open(p.oldKey, p.blob, p.oldAad);
  } catch {
    return { blob: p.blob, opened: false };
  }
  return { blob: sealWithNonce(p.newKey, p.nonce, pt, p.newAad), opened: true };
}

export const sealLocalTrustWithNonce = (p: { accountKey: Uint8Array; userId: string; plaintext: Uint8Array; nonce: Uint8Array }): Uint8Array =>
  sealWithNonce(localTrustKey(p.accountKey), p.nonce, p.plaintext, localTrustAad(p.userId));

export async function encodeBackupDeterministic(payload: BackupPayload, passphrase: string, kdf: KdfParams, createdAtMs: number, nonce: Uint8Array): Promise<string> {
  const key = await deriveBackupKey(passphrase, kdf);
  return backupFileText(kdf, createdAtMs, sealWithNonce(key, nonce, utf8(payloadToJson(payload)), BACKUP_AAD));
}
