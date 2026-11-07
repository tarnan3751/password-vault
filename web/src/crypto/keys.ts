import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concat, isAllZero, randomBytes, utf8 } from './encoding.ts';
import { checkIds } from './ids.ts';

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** X25519(sk, basepoint). The private key is used as-is; clamping happens inside X25519. */
export function publicKeyFromPrivate(sk: Uint8Array): Uint8Array {
  if (sk.length !== 32) throw new Error('private key must be 32 bytes');
  return x25519.getPublicKey(sk);
}

export function keyPairFromPrivate(sk: Uint8Array): KeyPair {
  return { privateKey: sk, publicKey: publicKeyFromPrivate(sk) };
}

export function generateKeyPair(): KeyPair {
  return keyPairFromPrivate(randomBytes(32));
}

/**
 * X25519 Diffie-Hellman that rejects an all-zero result. Low-order public keys
 * produce an all-zero shared secret regardless of the private key, which
 * would make the "key" public knowledge (crypto.md §6). Named parameters: both
 * are 32-byte arrays and swapping them would be a silent bug.
 */
export function dh(p: { privateKey: Uint8Array; publicKey: Uint8Array }): Uint8Array {
  if (p.privateKey.length !== 32 || p.publicKey.length !== 32) throw new Error('x25519: keys must be 32 bytes');
  let out: Uint8Array;
  try {
    out = x25519.getSharedSecret(p.privateKey, p.publicKey);
  } catch {
    throw new Error('x25519: invalid public key');
  }
  if (isAllZero(out)) throw new Error('x25519: low-order public key');
  return out;
}

/**
 * Fingerprint (crypto.md §6.2): first 16 bytes of
 * SHA-256("fpv/v1/fingerprint|" + userID + "|" + username + "|" || publicKey),
 * as 32 lowercase hex characters in eight groups of four. It covers the
 * identity as well as the key, so a match means "this name, this account, this key".
 */
export function fingerprint(p: { userId: string; username: string; publicKey: Uint8Array }): string {
  checkIds(p.userId);
  const h = bytesToHex(sha256(concat(utf8(`fpv/v1/fingerprint|${p.userId}|${p.username}|`), p.publicKey)).subarray(0, 16));
  return h.match(/.{4}/g)!.join('-');
}
