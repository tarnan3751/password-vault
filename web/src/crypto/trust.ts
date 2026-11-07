import { sha256 } from '@noble/hashes/sha2.js';
import { open, seal } from './box.ts';
import { bytesToHex, concat, utf8 } from './encoding.ts';
import { checkIds, epochStr } from './ids.ts';
import { hkdfSha256 } from './kdf.ts';

/** SHA-256("fpv/v1/vault-key-commit|" + vaultID + "|" + epoch + "|" || VK) as lowercase hex (crypto.md §6.2). */
export function vaultKeyCommitment(p: { vaultKey: Uint8Array; vaultId: string; epoch: number }): string {
  checkIds(p.vaultId);
  return bytesToHex(sha256(concat(utf8(`fpv/v1/vault-key-commit|${p.vaultId}|${epochStr(p.epoch)}|`), p.vaultKey)));
}

export const localTrustKey = (accountKey: Uint8Array): Uint8Array => hkdfSha256(accountKey, 'fpv/v1/local-trust-key');
export const localTrustAad = (userId: string): Uint8Array => (checkIds(userId), utf8('fpv/v1/local-trust|' + userId));

/** Seals the local trust store under a key derived from the account key, so a locked device's store cannot be edited. */
export function sealLocalTrust(p: { accountKey: Uint8Array; userId: string; plaintext: Uint8Array }): Uint8Array {
  const k = localTrustKey(p.accountKey);
  const blob = seal(k, p.plaintext, localTrustAad(p.userId));
  k.fill(0);
  return blob;
}

export function openLocalTrust(p: { accountKey: Uint8Array; userId: string; blob: Uint8Array }): Uint8Array {
  const k = localTrustKey(p.accountKey);
  try {
    return open(k, p.blob, localTrustAad(p.userId));
  } finally {
    k.fill(0);
  }
}
