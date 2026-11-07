// The local trust store (crypto.md §6.2): verified contacts, permanent
// key-mismatch events, per-vault accepted epoch + key commitment + owners, the
// highest stored rev. Sealed under a key derived from the account key and kept
// in IndexedDB: editable by nobody who does not have the account key. Missing
// or unopenable -> start empty (safe: everything becomes unverified again).
import { b64decode, b64encode, equalBytes, fingerprint, openLocalTrust, sealLocalTrust, utf8 } from '../crypto/index.ts';
import { K, type KeyValueStore } from './storage.ts';

export interface Contact {
  userId: string;
  username: string;
  publicKey: Uint8Array;
  verified: boolean;
}

export interface MismatchEvent {
  id: string;
  /** the user id the warning is about (the offender: its key/identity is refused) */
  userId: string;
  username: string;
  kind: 'key' | 'username' | 'userid' | 'roster';
  at: number;
  dismissed: boolean;
}

export interface VaultTrust {
  epoch: number;
  commit: string;
  owners: { id: string; pk: string }[];
}

export interface Inflight {
  prev?: VaultTrust;
  next: VaultTrust;
}

export type Observed = 'new' | 'same' | 'mismatch';

interface Persisted {
  v: 1;
  contacts: { id: string; username: string; pk: string; verified: boolean }[];
  mismatches: MismatchEvent[];
  vaults: ({ id: string } & VaultTrust)[];
  inflight: { id: string; prev?: VaultTrust; next: VaultTrust }[];
  highestRev: number;
}

export class TrustStore {
  /** Maps, never plain objects: keys come from a server. */
  readonly contacts = new Map<string, Contact>();
  readonly byUsername = new Map<string, string>();
  mismatches: MismatchEvent[] = [];
  readonly vaults = new Map<string, VaultTrust>();
  readonly inflight = new Map<string, Inflight>();
  highestRev = 0;
  /** Set when the stored blob was missing (for a known account) or did not open: tell the user. */
  resetReason: 'missing' | 'unopenable' | null = null;
  private dirty = false;

  private readonly store: KeyValueStore;
  private readonly accountKey: Uint8Array;
  private readonly userId: string;

  private constructor(store: KeyValueStore, accountKey: Uint8Array, userId: string) {
    this.store = store;
    this.accountKey = accountKey;
    this.userId = userId;
  }

  /** `hadCache`: this device already has a cached sync for the account, so a missing store is suspicious rather than normal. */
  static async load(store: KeyValueStore, accountKey: Uint8Array, userId: string, hadCache: boolean): Promise<TrustStore> {
    const t = new TrustStore(store, accountKey, userId);
    const blob = await store.get<Uint8Array>(K.trust(userId));
    if (blob === undefined) {
      if (hadCache) t.resetReason = 'missing';
      return t;
    }
    try {
      const pt = openLocalTrust({ accountKey, userId, blob });
      t.fromPersisted(JSON.parse(new TextDecoder().decode(pt)) as Persisted);
    } catch {
      t.resetReason = 'unopenable';
      t.contacts.clear();
      t.byUsername.clear();
      t.mismatches = [];
      t.vaults.clear();
      t.inflight.clear();
      t.highestRev = 0;
    }
    return t;
  }

  private fromPersisted(p: Persisted): void {
    if (p.v !== 1) throw new Error('trust store version');
    for (const c of p.contacts) {
      this.contacts.set(c.id, { userId: c.id, username: c.username, publicKey: b64decode(c.pk), verified: c.verified });
      this.byUsername.set(c.username, c.id);
    }
    this.mismatches = p.mismatches;
    for (const v of p.vaults) this.vaults.set(v.id, { epoch: v.epoch, commit: v.commit, owners: v.owners });
    for (const i of p.inflight) this.inflight.set(i.id, { prev: i.prev, next: i.next });
    this.highestRev = p.highestRev;
  }

  touch(): void {
    this.dirty = true;
  }

  async save(): Promise<void> {
    if (!this.dirty) return;
    const p: Persisted = {
      v: 1,
      contacts: [...this.contacts.values()].map((c) => ({ id: c.userId, username: c.username, pk: b64encode(c.publicKey), verified: c.verified })),
      mismatches: this.mismatches,
      vaults: [...this.vaults.entries()].map(([id, v]) => ({ id, ...v })),
      inflight: [...this.inflight.entries()].map(([id, i]) => ({ id, prev: i.prev, next: i.next })),
      highestRev: this.highestRev,
    };
    const blob = sealLocalTrust({ accountKey: this.accountKey, userId: this.userId, plaintext: utf8(JSON.stringify(p)) });
    await this.store.set(K.trust(this.userId), blob);
    this.dirty = false;
  }

  isBlocked(userId: string): boolean {
    return this.mismatches.some((m) => m.userId === userId);
  }

  private record(userId: string, username: string, kind: MismatchEvent['kind'], now: number): void {
    // one permanent event per (user, kind); repeated syncs do not stack warnings
    if (this.mismatches.some((m) => m.userId === userId && m.kind === kind)) return;
    this.mismatches.push({ id: `${now}-${this.mismatches.length}-${userId.slice(0, 8)}`, userId, username, kind, at: now, dismissed: false });
    this.dirty = true;
  }

  recordRosterMismatch(userId: string, username: string, now: number): void {
    this.record(userId, username, 'roster', now);
  }

  dismiss(eventId: string): void {
    const e = this.mismatches.find((m) => m.id === eventId);
    if (e && !e.dismissed) {
      e.dismissed = true;
      this.dirty = true;
    }
  }

  /**
   * First sight records the triple (unverified). Afterwards the triple never
   * changes: any difference is a mismatch, recorded permanently.
   */
  observe(userId: string, username: string, publicKey: Uint8Array, now: number): Observed {
    const c = this.contacts.get(userId);
    if (!c) {
      const owner = this.byUsername.get(username);
      if (owner !== undefined && owner !== userId) {
        this.record(userId, username, 'userid', now);
        return 'mismatch';
      }
      this.contacts.set(userId, { userId, username, publicKey: publicKey.slice(), verified: false });
      this.byUsername.set(username, userId);
      this.dirty = true;
      return 'new';
    }
    if (c.username !== username) {
      this.record(userId, username, 'username', now);
      return 'mismatch';
    }
    if (!equalBytes(c.publicKey, publicKey)) {
      this.record(userId, username, 'key', now);
      return 'mismatch';
    }
    return 'same';
  }

  setVerified(userId: string): boolean {
    const c = this.contacts.get(userId);
    if (!c || this.isBlocked(userId)) return false;
    if (!c.verified) {
      c.verified = true;
      this.dirty = true;
    }
    return true;
  }

  setVault(id: string, rec: VaultTrust): void {
    this.vaults.set(id, rec);
    this.dirty = true;
  }

  fingerprintOf(c: Contact): string {
    return fingerprint({ userId: c.userId, username: c.username, publicKey: c.publicKey });
  }
}
