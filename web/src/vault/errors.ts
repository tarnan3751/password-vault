import type { Item } from '../crypto/index.ts';
import type { ItemView } from './model.ts';

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** A write was attempted while offline or without quorum (read-only mode). */
export class ReadOnlyError extends VaultError {
  readonly reason: 'offline' | 'stale' | 'viewer' | 'locked' | 'recovery';
  constructor(reason: 'offline' | 'stale' | 'viewer' | 'locked' | 'recovery') {
    super(
      reason === 'offline'
        ? 'You are offline. Changes are off until a server can be reached.'
        : reason === 'stale'
          ? 'Most of the servers cannot be reached, so you are seeing the last copy a server has, which may be out of date. Changes are off until a majority of the servers can be reached.'
          : reason === 'recovery'
            ? 'The servers are showing older data than this device has seen. Changes are off until you accept the restored state or the servers show current data again.'
          : reason === 'viewer'
            ? 'You have read-only access to this vault.'
            : 'The vault is locked.',
    );
    this.reason = reason;
  }
}

export class PermissionError extends VaultError {}
export class NoCacheError extends VaultError {
  constructor() {
    super('There is no offline copy of this account on this device. Connect to a server to sign in.');
  }
}
export class WrongPasswordError extends VaultError {
  constructor() {
    super('Wrong username or password.');
  }
}
export class SessionExpiredError extends VaultError {
  constructor() {
    super('Your session ended (it expired, was revoked, or the password changed elsewhere). Please sign in again.');
  }
}

/** The server's answer violates the protocol rules of crypto.md §4/§6.2; the whole response was rejected. */
export class InvalidSyncError extends VaultError {
  constructor(why: string) {
    super(`The server sent data this app refuses to use (${why}). Nothing was changed.`);
  }
}

/** The account block or the directory disagrees with the identity this client unlocked (crypto.md §4). */
export class IdentityMismatchError extends VaultError {
  constructor(what: string) {
    super(`The server describes this account differently from what you unlocked (${what}). This is a serious problem: do not continue, and tell your administrator.`);
  }
}

/** A sync older than what this device has already seen. */
export class RollbackError extends VaultError {
  constructor() {
    super(
      'The servers are showing older data than this device has already seen. This is expected only if the administrator restored the servers from a backup; otherwise do not accept it. ' +
        'Your saved copy stays readable, and changes are disabled until you decide.',
    );
  }
}

/** Accepting the restored state is not allowed (this does not look like a restore) or not possible right now. */
export class RecoveryRefusedError extends VaultError {}

/**
 * A pinned (userID, username, publicKey) changed, or a roster disagrees with it.
 * The client refuses to wrap for, or accept a key from, this user (crypto.md §6.2).
 */
export class KeyMismatchError extends VaultError {
  readonly userId: string;
  readonly username: string;
  constructor(userId: string, username: string) {
    super(
      `WARNING: the identity or encryption key the server presents for "${username}" differs from what this device saw before. ` +
        'Someone may be trying to impersonate them. Nothing has been shared with, or accepted from, this identity. Call them or talk in person (not through this app) before doing anything else.',
    );
    this.userId = userId;
    this.username = username;
  }
}

/** The person at the device has not compared this user's fingerprint (crypto.md §6.5/§6.6). */
export class NotVerifiedError extends VaultError {
  readonly userIds: string[];
  constructor(users: { userId: string; username: string }[]) {
    super(`Compare the fingerprint of ${users.map((u) => u.username).join(', ')} with ${users.length === 1 ? 'them' : 'each of them'} before continuing.`);
    this.userIds = users.map((u) => u.userId);
  }
}

/** The server lists a member of the vault who is not in its authenticated roster (crypto.md §6.6). */
export class UnlistedMemberError extends VaultError {
  readonly userIds: string[];
  constructor(users: { userId: string; username: string }[]) {
    super(
      `Stopped: the server lists ${users.map((u) => u.username).join(', ')} as a member of this vault, but they are not in the vault's own member list (which the server cannot change). ` +
        'The server may be trying to slip in an extra person. Nothing was changed.',
    );
    this.userIds = users.map((u) => u.userId);
  }
}

export class RosterUnreadableError extends VaultError {
  constructor() {
    super("This vault's member list cannot be read, so its members cannot be changed and its key cannot be replaced normally. An owner can repair it.");
  }
}

/** Somebody else changed the item after we loaded it (409 version_conflict). Never overwritten silently. */
export class ConflictError extends VaultError {
  readonly vaultId: string;
  readonly itemId: string;
  readonly kind: 'create' | 'update' | 'delete';
  readonly mine: Item | null;
  readonly theirs: ItemView | null;
  readonly currentVersion: number;
  constructor(p: { vaultId: string; itemId: string; kind: 'create' | 'update' | 'delete'; mine: Item | null; theirs: ItemView | null; currentVersion: number }) {
    super('This entry was changed somewhere else while you were editing it.');
    this.vaultId = p.vaultId;
    this.itemId = p.itemId;
    this.kind = p.kind;
    this.mine = p.mine;
    this.theirs = p.theirs;
    this.currentVersion = p.currentVersion;
  }
}

/** Vault-level state changed under us; state was re-synced. */
export class StaleStateError extends VaultError {
  constructor(msg = 'The vault changed while you were working. It has been reloaded; please try again.') {
    super(msg);
  }
}
