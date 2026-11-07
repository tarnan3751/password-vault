import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concat, randomBytes } from './encoding.ts';

export const BOX_VERSION = 0x01;
export const NONCE_LEN = 24;
export const TAG_LEN = 16;
export const MIN_BOX_LEN = 1 + NONCE_LEN + TAG_LEN;

/**
 * The single error for every decryption failure (bad version, short input,
 * tag mismatch, wrong key, wrong AAD). Callers and UI must not be able to tell
 * the reasons apart.
 */
export class DecryptError extends Error {
  constructor() {
    super('decryption failed');
    this.name = 'DecryptError';
  }
}

/** box = 0x01 || nonce(24, fresh random) || XChaCha20-Poly1305(key, nonce, pt, aad) (crypto.md §3). */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('seal: key must be 32 bytes');
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return concat(new Uint8Array([BOX_VERSION]), nonce, ct);
}

export function open(key: Uint8Array, box: Uint8Array, aad: Uint8Array): Uint8Array {
  if (key.length !== 32 || box.length < MIN_BOX_LEN || box[0] !== BOX_VERSION) throw new DecryptError();
  try {
    return xchacha20poly1305(key, box.subarray(1, 1 + NONCE_LEN), aad).decrypt(box.subarray(1 + NONCE_LEN));
  } catch {
    throw new DecryptError();
  }
}
