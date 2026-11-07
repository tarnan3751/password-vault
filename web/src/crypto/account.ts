import { DecryptError, open, seal } from './box.ts';
import { equalBytes, randomBytes, utf8, zero } from './encoding.ts';
import { checkIds } from './ids.ts';
import { publicKeyFromPrivate } from './keys.ts';

export const accountKeyAad = (userId: string): Uint8Array => (checkIds(userId), utf8('fpv/v1/account-key|' + userId));
export const privateKeyAad = (userId: string): Uint8Array => (checkIds(userId), utf8('fpv/v1/private-key|' + userId));

export interface AccountMaterial {
  accountKey: Uint8Array;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  wrappedAccountKey: Uint8Array;
  encPrivateKey: Uint8Array;
}

export function createAccountMaterial(p: { userId: string; encKey: Uint8Array }): AccountMaterial {
  const accountKey = randomBytes(32);
  const privateKey = randomBytes(32);
  return {
    accountKey, privateKey, publicKey: publicKeyFromPrivate(privateKey),
    wrappedAccountKey: seal(p.encKey, accountKey, accountKeyAad(p.userId)),
    encPrivateKey: seal(accountKey, privateKey, privateKeyAad(p.userId)),
  };
}

export class PublicKeyMismatchError extends Error {
  constructor() {
    super("the account's public key does not match its private key");
    this.name = 'PublicKeyMismatchError';
  }
}

/**
 * Open wrappedAccountKey (success IS the offline password check), then the
 * private key, then verify it matches the account's public key (crypto.md §4).
 * Wrong password / username / user id / swapped blobs raise DecryptError. The
 * account key is zeroed on every failure path after it was opened.
 */
export function unlockAccount(p: { userId: string; encKey: Uint8Array; publicKey: Uint8Array; wrappedAccountKey: Uint8Array; encPrivateKey: Uint8Array }): { accountKey: Uint8Array; privateKey: Uint8Array } {
  const accountKey = open(p.encKey, p.wrappedAccountKey, accountKeyAad(p.userId));
  try {
    if (accountKey.length !== 32) throw new DecryptError();
    const privateKey = open(accountKey, p.encPrivateKey, privateKeyAad(p.userId));
    if (privateKey.length !== 32 || !equalBytes(publicKeyFromPrivate(privateKey), p.publicKey)) {
      const mismatch = privateKey.length === 32;
      zero(privateKey);
      throw mismatch ? new PublicKeyMismatchError() : new DecryptError();
    }
    return { accountKey, privateKey };
  } catch (e) {
    zero(accountKey);
    throw e;
  }
}

/** New wrappedAccountKey under a new encKey (password change; nothing else changes). */
export function rewrapAccountKey(p: { userId: string; newEncKey: Uint8Array; accountKey: Uint8Array }): Uint8Array {
  return seal(p.newEncKey, p.accountKey, accountKeyAad(p.userId));
}
