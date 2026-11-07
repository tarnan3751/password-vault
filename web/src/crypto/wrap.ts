import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concat, randomBytes, utf8 } from './encoding.ts';
import { checkEpoch, checkIds, epochStr } from './ids.ts';
import { dh, generateKeyPair, publicKeyFromPrivate } from './keys.ts';
import { hkdfSha256 } from './kdf.ts';
import { DecryptError, NONCE_LEN } from './box.ts';

export const WRAP_VERSION = 0x01;
export const WRAP_LEN = 105;
const INFO_WRAP = 'fpv/v1/vault-key-wrap';

export interface WrapContext {
  vaultId: string;
  keyEpoch: number;
  senderId: string;
  recipientId: string;
}

export function wrapAad(c: WrapContext): Uint8Array {
  checkIds(c.vaultId, c.senderId, c.recipientId);
  checkEpoch(c.keyEpoch);
  return utf8(`fpv/v1/vault-key|${c.vaultId}|${epochStr(c.keyEpoch)}|${c.senderId}|${c.recipientId}`);
}

export function deriveWrapKey(dh1: Uint8Array, dh2: Uint8Array, pkE: Uint8Array, pkS: Uint8Array, pkR: Uint8Array): Uint8Array {
  return hkdfSha256(concat(dh1, dh2), INFO_WRAP, 32, concat(pkE, pkS, pkR));
}

/** Authenticated ECIES wrap of a vault key for one recipient (crypto.md §6). Fresh ephemeral key and nonce. */
export function wrapVaultKey(p: { vaultKey: Uint8Array; ctx: WrapContext; senderPrivate: Uint8Array; recipientPublic: Uint8Array }): Uint8Array {
  if (p.vaultKey.length !== 32) throw new Error('vault key must be 32 bytes');
  const aad = wrapAad(p.ctx);
  const eph = generateKeyPair();
  const nonce = randomBytes(NONCE_LEN);
  const pkS = publicKeyFromPrivate(p.senderPrivate);
  const dh1 = dh({ privateKey: eph.privateKey, publicKey: p.recipientPublic });
  const dh2 = dh({ privateKey: p.senderPrivate, publicKey: p.recipientPublic });
  const key = deriveWrapKey(dh1, dh2, eph.publicKey, pkS, p.recipientPublic);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(p.vaultKey);
  const out = concat(new Uint8Array([WRAP_VERSION]), eph.publicKey, nonce, ct);
  if (out.length !== WRAP_LEN) throw new Error('internal: wrap has wrong length');
  for (const b of [dh1, dh2, key, eph.privateKey]) b.fill(0);
  return out;
}

/** Any failure (malformed, low-order, wrong keys or context) is a DecryptError. */
export function unwrapVaultKey(p: { wrap: Uint8Array; ctx: WrapContext; recipientPrivate: Uint8Array; senderPublic: Uint8Array }): Uint8Array {
  try {
    if (p.wrap.length !== WRAP_LEN || p.wrap[0] !== WRAP_VERSION) throw new DecryptError();
    const aad = wrapAad(p.ctx);
    const pkE = p.wrap.subarray(1, 33);
    const nonce = p.wrap.subarray(33, 33 + NONCE_LEN);
    const ct = p.wrap.subarray(33 + NONCE_LEN);
    const pkR = publicKeyFromPrivate(p.recipientPrivate);
    const dh1 = dh({ privateKey: p.recipientPrivate, publicKey: pkE });
    const dh2 = dh({ privateKey: p.recipientPrivate, publicKey: p.senderPublic });
    const key = deriveWrapKey(dh1, dh2, pkE, p.senderPublic, pkR);
    const vk = xchacha20poly1305(key, nonce, aad).decrypt(ct);
    for (const b of [dh1, dh2, key]) b.fill(0);
    if (vk.length !== 32) throw new DecryptError();
    return vk;
  } catch {
    throw new DecryptError();
  }
}
