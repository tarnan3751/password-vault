import type { Item } from '../crypto/index.ts';
import type { Role } from '../api/types.ts';

export type Mode = 'online' | 'stale' | 'offline';

export type LockReason =
  | 'undecryptable' // the wrapped key does not open (or the sender is unknown)
  | 'key_mismatch' // the sender's pinned key/identity changed
  | 'older_epoch' // offered at a LOWER epoch than this device accepted (what a server restore looks like; recoverable on purpose)
  | 'continuity' // same epoch with a different key (never a restore: hard error)
  | 'roster_missing_me'; // the roster does not list this client with its own key

export interface RecoveryState {
  /** why the servers look older: a lower rev, or vaults at older key epochs */
  kind: 'rev' | 'epoch';
  serverRev: number;
  knownRev: number;
}

export type Discrepancy = 'left' | 'unlisted' | 'role_differs';

export interface MemberView {
  userId: string;
  username: string;
  /** role per the roster (authenticated); per the server list when the roster is unreadable */
  role: Role;
  fingerprint: string;
  verified: boolean;
  blocked: boolean;
  isSelf: boolean;
  disabled: boolean;
  /**
   * left: in the roster but no longer listed by the server (loses access at the next rekey);
   * unlisted: listed by the server but not in the roster (ignored);
   * role_differs: the server's role differs from the roster's.
   */
  discrepancy?: Discrepancy;
}

export interface ItemView {
  id: string;
  version: number;
  updatedAt: number;
  updatedBy: string;
  /** Decrypted item; absent if it could not be decrypted (then `error` is set). */
  item?: Item;
  error?: string;
}

export interface PendingInfo {
  senderId: string;
  senderName: string;
  senderFingerprint: string;
  senderVerified: boolean;
  /** This device accepted the vault before and the sender was not one of its owners then (crypto.md §6.4). */
  replacedByNonOwner: boolean;
}

export interface VaultView {
  id: string;
  name: string;
  personal: boolean;
  keyEpoch: number;
  /** the server's view of this user's role (used only to decide what to offer; the roster is authoritative for display) */
  role: Role;
  rekeyRecommended: boolean;
  metaVersion: number;
  rosterVersion: number;
  rev: number;
  state: 'open' | 'pending' | 'locked';
  rosterStatus: 'ok' | 'unreadable';
  members: MemberView[];
  items: ItemView[];
  /** Set when state === 'locked' */
  locked?: LockReason;
  pending?: PendingInfo;
}

export interface UserLookup {
  userId: string;
  username: string;
  publicKey: Uint8Array;
  fingerprint: string;
  verified: boolean;
  disabled: boolean;
}

export interface ContactView {
  userId: string;
  username: string;
  fingerprint: string;
  verified: boolean;
  blocked: boolean;
  isSelf: boolean;
  isAdmin: boolean;
  disabled: boolean;
}

export interface RekeyRecipient {
  userId: string;
  username: string;
  role: Role;
  fingerprint: string;
  verified: boolean;
  isSelf: boolean;
}

export interface RekeyPlan {
  vaultId: string;
  vaultName: string;
  /** the new key epoch */
  epoch: number;
  removed: { userId: string; username: string }[];
  recipients: RekeyRecipient[];
  repair: boolean;
  /** recipients other than self who are not verified contacts: they must be verified before the rekey can run */
  unverified: RekeyRecipient[];
}
