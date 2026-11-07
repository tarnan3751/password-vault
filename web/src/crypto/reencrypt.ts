import { open, seal } from './box.ts';
import { itemAad, vaultMetaAad } from './item.ts';

export interface Reencrypted {
  blob: Uint8Array;
  /** false: the box did not open under the old key/epoch and is returned unchanged */
  opened: boolean;
}

/**
 * Raw re-encryption for rekeys (crypto.md §5.3, §6.6): open the box, re-seal
 * the RAW plaintext bytes (padding included, nothing parsed) under the new key
 * and epoch. A box that does not open is carried over unchanged: it was
 * garbage and stays garbage, and it never blocks a rekey.
 */
function reencrypt(oldKey: Uint8Array, newKey: Uint8Array, oldAad: Uint8Array, newAad: Uint8Array, blob: Uint8Array): Reencrypted {
  let pt: Uint8Array;
  try {
    pt = open(oldKey, blob, oldAad);
  } catch {
    return { blob, opened: false };
  }
  const out = seal(newKey, pt, newAad);
  pt.fill(0);
  return { blob: out, opened: true };
}

export function reencryptItem(p: { oldKey: Uint8Array; newKey: Uint8Array; vaultId: string; itemId: string; oldEpoch: number; newEpoch: number; blob: Uint8Array }): Reencrypted {
  return reencrypt(p.oldKey, p.newKey, itemAad(p.vaultId, p.itemId, p.oldEpoch), itemAad(p.vaultId, p.itemId, p.newEpoch), p.blob);
}

export function reencryptMeta(p: { oldKey: Uint8Array; newKey: Uint8Array; vaultId: string; oldEpoch: number; newEpoch: number; blob: Uint8Array }): Reencrypted {
  return reencrypt(p.oldKey, p.newKey, vaultMetaAad(p.vaultId, p.oldEpoch), vaultMetaAad(p.vaultId, p.newEpoch), p.blob);
}
