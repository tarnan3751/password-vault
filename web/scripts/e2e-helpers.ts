// Tiny helpers for e2e.ts's raw-API idempotency check (a signed blob for a brand-new item id).
import { b64encode, encryptItem, newId, newItem } from '../src/crypto/index.ts';
import type { Session } from '../src/vault/index.ts';

export const blobFor = {
  newId,
  blob(s: Session, vaultId: string, itemId: string): string {
    const vk = (s as unknown as { secrets: Map<string, { vk: Uint8Array }> }).secrets.get(vaultId)!.vk;
    return b64encode(encryptItem(vk, { vaultId, itemId, epoch: (s as unknown as { vault(id: string): { keyEpoch: number } }).vault(vaultId).keyEpoch }, Object.assign(newItem('login', Date.now()), { name: 'idempotent' })));
  },
};
