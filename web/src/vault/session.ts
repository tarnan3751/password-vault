// Session logic with no DOM. A Session holds the unlocked key material in
// memory only (never in any storage) and turns the server's ciphertext into
// decrypted views, enforcing the client rules of crypto.md §4 and §6.2-§6.6.
// Where a rule is enforced is named in the comment above the function.

import { ApiClient } from '../api/client.ts';
import { ApiError, NetworkError } from '../api/errors.ts';
import type * as T from '../api/types.ts';
import {
  b64decode, b64encode, checkKdfNotWeaker, createAccountMaterial, decodeBackup, decryptItem, decryptRoster, decryptVaultMeta, defaultKdfParams,
  DecryptError, deriveMasterKeys, editItem, encodeBackup, encryptItem, encryptRoster, encryptVaultMeta, equalBytes, fingerprint, itemToJson,
  kdfFromWire, kdfToWire, newId, normalizeUsername, publicKeyFromPrivate, randomBytes, reencryptItem, reencryptMeta, rewrapAccountKey,
  rosterMember, rosterOwners, rosterWithMember, rosterWithRole, unlockAccount, unwrapVaultKey, validateKdfParams, vaultKeyCommitment,
  wrapVaultKey, zero, type BackupPayload, type ExtraMember, type Item, type KdfParams, type Roster, type Role,
} from '../crypto/index.ts';
import {
  ConflictError, IdentityMismatchError, InvalidSyncError, KeyMismatchError, NoCacheError, NotVerifiedError, PermissionError, ReadOnlyError,
  RecoveryRefusedError, RollbackError, RosterUnreadableError, SessionExpiredError, StaleStateError, UnlistedMemberError, VaultError, WrongPasswordError,
} from './errors.ts';
import type { ContactView, ItemView, LockReason, MemberView, Mode, PendingInfo, RecoveryState, RekeyPlan, RekeyRecipient, UserLookup, VaultView } from './model.ts';
import { K, type KeyValueStore } from './storage.ts';
import { TrustStore, type VaultTrust } from './trust-store.ts';
import { validateSync } from './validate.ts';

export interface Deps {
  api: ApiClient;
  store: KeyValueStore;
  now?: () => number;
}

interface CachedSync {
  sync: T.SyncResponse;
  savedAt: number;
}

interface VaultSecret {
  vk: Uint8Array;
  epoch: number;
  roster: Roster | null;
  metaExtra: ExtraMember[];
}

interface PendingKey {
  vk: Uint8Array;
  epoch: number;
  commit: string;
}

export interface Progress {
  phase: string;
  done: number;
  total: number;
}

interface RekeyOpts {
  remove?: string[];
  repair?: boolean;
}

/** Internal plan carried by RekeyPlan (not part of the public view type). */
interface PlanInternal extends RekeyPlan {
  opts: RekeyOpts;
  key: string;
}

const MAX_ITEM_BLOB = 64 * 1024;
/** What a decrypted ItemView was made from (key commitment + ciphertext); see evaluateVault. Weak keys: nothing outlives the views. */
const itemSig = new WeakMap<ItemView, string>();
const tick = () => new Promise<void>((r) => setTimeout(r, 0));
const sameBytes = (a: Uint8Array, b: Uint8Array) => equalBytes(a, b);

/** A failure after which the server definitely did not apply the request. */
function definite(e: unknown): boolean {
  if (e instanceof ApiError) return e.code !== 'outcome_unknown';
  if (e instanceof NetworkError) return !e.outcomeUnknown;
  return false;
}

/** A new vault owned by `owner`, with a fresh key at epoch 1: the request body and the trust record to store BEFORE sending (crypto.md §6.4). */
function newVaultRequest(owner: { id: string; publicKey: Uint8Array; privateKey: Uint8Array }, name: string): { req: T.CreateVaultRequest; rec: VaultTrust } {
  const vaultId = newId();
  const vk = randomBytes(32);
  const roster: Roster = { v: 1, members: [{ id: owner.id, publicKey: owner.publicKey, role: 'owner' }] };
  const req: T.CreateVaultRequest = {
    vault_id: vaultId,
    enc_meta: b64encode(encryptVaultMeta(vk, { vaultId, epoch: 1, meta: { name } })),
    enc_roster: b64encode(encryptRoster(vk, { vaultId, epoch: 1 }, roster)),
    wrapped_key: { sender_id: owner.id, blob: b64encode(wrapVaultKey({ vaultKey: vk, ctx: { vaultId, keyEpoch: 1, senderId: owner.id, recipientId: owner.id }, senderPrivate: owner.privateKey, recipientPublic: owner.publicKey })) },
  };
  const rec: VaultTrust = { epoch: 1, commit: vaultKeyCommitment({ vaultKey: vk, vaultId, epoch: 1 }), owners: [{ id: owner.id, pk: b64encode(owner.publicKey) }] };
  zero(vk);
  return { req, rec };
}

export class Session {
  readonly userId: string;
  /** the normalized username the user typed (never what the server says) */
  readonly username: string;
  isAdmin: boolean;
  mode: Mode;
  lastSyncedAt = 0;
  vaults: VaultView[] = [];
  readonly fingerprint: string;
  trust: TrustStore;

  private accountKey: Uint8Array | null;
  private privateKey: Uint8Array | null;
  private readonly publicKey: Uint8Array;
  private loginKey: Uint8Array | null;
  private raw: T.SyncResponse | null = null;
  private secrets = new Map<string, VaultSecret>();
  private pendingKeys = new Map<string, PendingKey>();
  private directory = new Map<string, T.DirectoryUser>();
  private listeners = new Set<() => void>();
  private relogin: Promise<void> | null = null;
  private _locked = false;
  /** >0 while this client is sending a vault creation / rekey: in-flight trust records must not be cleaned up by a concurrent sync. */
  private sending = 0;
  /** The last reason a refresh could not use the server's answer (validation, identity, rollback); shown by the UI. */
  syncProblem: VaultError | null = null;
  /** Set when the servers show OLDER data than this device has seen (crypto.md §6.4, deliberate recovery). Never cleared automatically except by a sync that no longer looks old. */
  recovery: RecoveryState | null = null;
  private deps: Required<Deps>;

  private constructor(deps: Deps, a: { userId: string; username: string; isAdmin: boolean; accountKey: Uint8Array; privateKey: Uint8Array; loginKey: Uint8Array; mode: Mode }, trust: TrustStore) {
    this.deps = { now: () => Date.now(), ...deps };
    this.userId = a.userId;
    this.username = a.username;
    this.isAdmin = a.isAdmin;
    this.accountKey = a.accountKey;
    this.privateKey = a.privateKey;
    // "My public key" is always the unlocked one, never a directory lookup (crypto.md §4).
    this.publicKey = publicKeyFromPrivate(a.privateKey);
    this.loginKey = a.loginKey;
    this.mode = a.mode;
    this.trust = trust;
    this.fingerprint = fingerprint({ userId: a.userId, username: a.username, publicKey: this.publicKey });
    this.trust.observe(this.userId, this.username, this.publicKey, this.deps.now());
    this.trust.setVerified(this.userId); // our own key needs no out-of-band check
  }

  get api(): ApiClient {
    return this.deps.api;
  }
  get locked(): boolean {
    return this._locked;
  }
  get canWrite(): boolean {
    return !this._locked && this.mode === 'online' && !this.recovery;
  }
  /** Only a pure "older" pattern (lower rev / older epochs) can be accepted; same-epoch-different-key or mismatches never. */
  get canAcceptRecovery(): boolean {
    return !!this.recovery && !this._locked && !this.vaults.some((v) => v.locked === 'continuity' || v.locked === 'key_mismatch');
  }
  get rev(): number {
    return this.raw?.rev ?? 0;
  }
  get servedBy(): string | undefined {
    return this.raw?.served_by;
  }
  /** Why the trust store started empty, if it did (the UI tells the user). */
  get trustResetReason(): 'missing' | 'unopenable' | null {
    return this.trust.resetReason;
  }
  /** Key-mismatch events the user has not dismissed yet. */
  get mismatchWarnings() {
    return this.trust.mismatches.filter((m) => !m.dismissed);
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private notify(): void {
    for (const l of [...this.listeners]) l();
  }

  // ------------------------------------------------------------------ entry points

  /** Create an account (first user: bootstrap token as invite code). Argon2id runs locally. */
  static async register(deps: Deps, p: { username: string; password: string; inviteCode: string; kdf?: KdfParams }): Promise<Session> {
    const username = normalizeUsername(p.username);
    const kdf = p.kdf ?? defaultKdfParams();
    const keys = await deriveMasterKeys({ username, password: p.password, params: kdf }); // enforces the parameter floor
    const userId = newId();
    const mat = createAccountMaterial({ userId, encKey: keys.encKey });
    const trust = await TrustStore.load(deps.store, mat.accountKey, userId, false);
    // The personal vault is created exactly as createVault does it; its epoch and
    // key commitment are recorded BEFORE the request is sent (crypto.md §6.4).
    const personal = newVaultRequest({ id: userId, publicKey: mat.publicKey, privateKey: mat.privateKey }, 'Personal');
    trust.setVault(personal.req.vault_id, personal.rec);
    const req: T.RegisterRequest = {
      invite_code: p.inviteCode.trim(),
      user_id: userId,
      username,
      kdf: kdfToWire(kdf),
      login_key: b64encode(keys.loginKey),
      public_key: b64encode(mat.publicKey),
      wrapped_account_key: b64encode(mat.wrappedAccountKey),
      enc_private_key: b64encode(mat.encPrivateKey),
      personal_vault: personal.req,
    };
    zero(keys.encKey);
    const lr = await deps.api.register(req);
    if (lr.user_id !== userId || lr.username !== username) throw new IdentityMismatchError('registration answer');
    trust.touch();
    await trust.save();
    const s = new Session(deps, { userId, username, isAdmin: lr.is_admin, accountKey: mat.accountKey, privateKey: mat.privateKey, loginKey: keys.loginKey, mode: 'online' }, trust);
    await deps.store.set(K.lastUser, username);
    await s.sync();
    void s.learnNodes();
    return s;
  }

  /**
   * Online sign-in. KDF parameters from prelogin must meet the floor AND not be
   * weaker than the ones cached for this account (crypto.md §2).
   */
  static async login(deps: Deps, p: { username: string; password: string }): Promise<Session> {
    const username = normalizeUsername(p.username);
    const cached = await deps.store.get<CachedSync>(K.sync(username));
    const pre = await deps.api.prelogin(username);
    const kdf = kdfFromWire(pre.kdf);
    validateKdfParams(kdf);
    if (cached?.sync.account) checkKdfNotWeaker(kdfFromWire(cached.sync.account.kdf), kdf);
    const keys = await deriveMasterKeys({ username, password: p.password, params: kdf });
    let lr: T.LoginResponse;
    try {
      lr = await deps.api.login(username, b64encode(keys.loginKey));
    } catch (e) {
      if (e instanceof ApiError && e.code === 'unauthorized') throw new WrongPasswordError();
      throw e;
    }
    const sync = await deps.api.sync();
    validateSync(sync);
    const acct = sync.account;
    // Own identity: the login answer, the account block and what we typed must agree.
    if (lr.user_id !== acct.user_id) throw new IdentityMismatchError('user id');
    if (acct.username !== username || lr.username !== username) throw new IdentityMismatchError('username');
    if (cached?.sync.account && (cached.sync.account.user_id !== acct.user_id || cached.sync.account.public_key !== acct.public_key)) {
      throw new IdentityMismatchError('this device knows the account under a different identity');
    }
    const s = await Session.fromAccount(deps, acct, keys.encKey, keys.loginKey, sync.stale ? 'stale' : 'online', !!cached);
    zero(keys.encKey);
    await s.applySync(sync);
    await deps.store.set(K.lastUser, username);
    void s.learnNodes();
    return s;
  }

  /** Unlock from the cached SyncResponse with no server. A wrong password fails the AEAD open. Read-only. */
  static async unlockOffline(deps: Deps, p: { username: string; password: string }): Promise<Session> {
    const username = normalizeUsername(p.username);
    const cached = await deps.store.get<CachedSync>(K.sync(username));
    if (!cached?.sync.account) throw new NoCacheError();
    validateSync(cached.sync);
    const acct = cached.sync.account;
    if (acct.username !== username) throw new NoCacheError();
    const keys = await deriveMasterKeys({ username, password: p.password, params: kdfFromWire(acct.kdf) });
    const s = await Session.fromAccount(deps, acct, keys.encKey, keys.loginKey, 'offline', true);
    zero(keys.encKey);
    s.lastSyncedAt = cached.savedAt;
    await s.applySync(cached.sync, { fromCache: true });
    return s;
  }

  static async lastUsername(store: KeyValueStore): Promise<string | undefined> {
    return store.get<string>(K.lastUser);
  }

  private static async fromAccount(deps: Deps, acct: T.Account, encKey: Uint8Array, loginKey: Uint8Array, mode: Mode, hadCache: boolean): Promise<Session> {
    let keys: { accountKey: Uint8Array; privateKey: Uint8Array };
    try {
      keys = unlockAccount({ userId: acct.user_id, encKey, publicKey: b64decode(acct.public_key), wrappedAccountKey: b64decode(acct.wrapped_account_key), encPrivateKey: b64decode(acct.enc_private_key) });
    } catch (e) {
      if (e instanceof DecryptError) throw new WrongPasswordError();
      throw e;
    }
    const trust = await TrustStore.load(deps.store, keys.accountKey, acct.user_id, hadCache);
    return new Session(deps, { userId: acct.user_id, username: acct.username, isAdmin: acct.is_admin, accountKey: keys.accountKey, privateKey: keys.privateKey, loginKey, mode }, trust);
  }

  private async learnNodes(): Promise<void> {
    try {
      await this.api.refreshCluster();
      await this.deps.store.set(K.nodes, this.api.nodeUrls);
    } catch {
      /* best effort */
    }
  }

  /** Drop every key from memory. The Session object is unusable afterwards. */
  lock(): void {
    if (this._locked) return;
    this._locked = true;
    zero(this.accountKey ?? undefined, this.privateKey ?? undefined, this.loginKey ?? undefined);
    for (const s of this.secrets.values()) zero(s.vk);
    for (const s of this.pendingKeys.values()) zero(s.vk);
    this.secrets.clear();
    this.pendingKeys.clear();
    this.accountKey = this.privateKey = this.loginKey = null;
    this.raw = null;
    this.vaults = [];
    this.directory.clear();
    this.api.token = null;
    this.notify();
  }

  // ------------------------------------------------------------------ sync / views

  /** Fetch current state (linearizable, else stale) and rebuild the decrypted views. Never discards the cache on failure. */
  async sync(): Promise<void> {
    this.assertUnlocked();
    // With an unresolved local create/rekey a full answer is needed to settle it, never "unchanged".
    const since = this.trust.inflight.size > 0 ? undefined : this.raw?.rev;
    const resp = await this.call(() => this.api.sync(since));
    await this.applySync(resp);
  }

  /** Like sync() but converts connectivity failure into a mode instead of throwing. Returns the resulting mode. */
  async refresh(): Promise<Mode> {
    if (this._locked) return this.mode;
    try {
      if (this.mode === 'offline' && !this.api.token) await this.reconnect();
      else await this.sync();
    } catch (e) {
      if (e instanceof NetworkError) this.setMode('offline');
      else if (e instanceof ApiError && e.code === 'unavailable') this.setMode('stale');
      else if (e instanceof SessionExpiredError) throw e;
      else if (e instanceof VaultError) {
        this.syncProblem = e;
        this.notify();
      } else throw e;
      return this.mode;
    }
    if (this.syncProblem) {
      this.syncProblem = null;
      this.notify();
    }
    return this.mode;
  }

  private async reconnect(): Promise<void> {
    await this.doLogin();
    await this.sync();
  }

  private async doLogin(): Promise<void> {
    if (!this.loginKey) throw new SessionExpiredError();
    try {
      const lr = await this.api.login(this.username, b64encode(this.loginKey));
      if (lr.user_id !== this.userId) throw new IdentityMismatchError('user id');
    } catch (e) {
      if (e instanceof ApiError && e.code === 'unauthorized') {
        this.lock();
        throw new SessionExpiredError();
      }
      throw e;
    }
  }

  private setMode(m: Mode): void {
    if (this.mode !== m) {
      this.mode = m;
      this.notify();
    }
  }

  /** Authenticated call: on 401 re-login once with the in-memory login key (token expiry), else lock. */
  private async call<R>(fn: () => Promise<R>): Promise<R> {
    this.assertUnlocked();
    try {
      return await fn();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'unauthorized') {
        this.relogin ??= this.doLogin().finally(() => (this.relogin = null));
        await this.relogin;
        return await fn();
      }
      throw e;
    }
  }

  private assertUnlocked(): void {
    if (this._locked) throw new ReadOnlyError('locked');
  }

  /** Writes: refuse when read-only; map connectivity failures to the right mode so the UI explains them. */
  private async write<R>(fn: () => Promise<R>): Promise<R> {
    this.assertUnlocked();
    if (this.recovery) throw new ReadOnlyError('recovery');
    if (this.mode === 'offline') throw new ReadOnlyError('offline');
    if (this.mode === 'stale') throw new ReadOnlyError('stale');
    try {
      return await this.call(fn);
    } catch (e) {
      if (e instanceof NetworkError && !e.outcomeUnknown) this.setMode('offline');
      else if (e instanceof ApiError && e.code === 'unavailable') this.setMode('stale');
      throw e;
    }
  }

  /**
   * Validates (§6.2), checks the identity (§4), updates the trust store and
   * rebuilds the views. Everything that can reject the response happens BEFORE
   * any state is replaced or cached, so a bad answer changes nothing.
   */
  private async applySync(resp: T.SyncResponse, o: { fromCache?: boolean } = {}): Promise<void> {
    if (resp.unchanged && this.raw) {
      this.lastSyncedAt = this.deps.now();
      this.setMode(resp.stale ? 'stale' : 'online');
      this.notify();
      return;
    }
    validateSync(resp);
    // A stale answer older than what we hold is ignored (the cache and the views keep the newer data).
    if (!o.fromCache && this.raw && resp.stale && resp.rev < this.raw.rev) {
      this.setMode('stale');
      return;
    }
    // Rollback: never go back to a lower rev than this device has already stored.
    this.checkIdentity(resp);
    if (!o.fromCache && resp.rev < this.trust.highestRev) {
      // Looks like a rollback; only the administrator restoring a backup makes it legitimate. We do not decide:
      // keep the cache and views, stop writing, and offer the explicit recovery action.
      this.recovery = { kind: 'rev', serverRev: resp.rev, knownRev: this.trust.highestRev };
      this.notify();
      throw new RollbackError();
    }

    const directory = new Map(resp.directory!.map((d) => [d.user_id, d] as const));
    const now = this.deps.now();
    for (const d of directory.values()) {
      if (d.user_id === this.userId) continue;
      this.trust.observe(d.user_id, d.username, b64decode(d.public_key), now);
    }
    this.commitViews(this.buildViews(resp, directory, !!resp.stale));
    this.raw = resp;
    this.directory = directory;
    this.isAdmin = resp.account!.is_admin;
    const older = this.vaults.some((v) => v.locked === 'older_epoch');
    this.recovery = older && !o.fromCache ? { kind: 'epoch', serverRev: resp.rev, knownRev: this.trust.highestRev } : o.fromCache ? this.recovery : null;
    if (resp.rev > this.trust.highestRev) {
      this.trust.highestRev = resp.rev;
      this.trust.touch();
    }
    await this.trust.save();
    if (!o.fromCache) {
      const key = K.sync(this.username);
      const prev = await this.deps.store.get<CachedSync>(key);
      // Never replace a cached sync with one of a lower rev (a stale or replayed answer must not erase newer data).
      if (!this.recovery && (!prev || resp.rev >= prev.sync.rev)) await this.deps.store.set(key, { sync: resp, savedAt: now } satisfies CachedSync);
      this.lastSyncedAt = now;
      this.mode = resp.stale ? 'stale' : 'online';
    }
    this.notify();
  }

  /** crypto.md §4: the account block and our own directory entry must carry exactly the unlocked identity. */
  private checkIdentity(resp: T.SyncResponse): void {
    const a = resp.account!;
    if (a.user_id !== this.userId) throw new IdentityMismatchError('user id');
    if (a.username !== this.username) throw new IdentityMismatchError('username');
    if (!equalBytes(b64decode(a.public_key), this.publicKey)) throw new IdentityMismatchError('public key');
    const me = (resp.directory ?? []).find((d) => d.user_id === this.userId);
    if (!me) throw new IdentityMismatchError('missing from the directory');
    if (me.username !== this.username || !equalBytes(b64decode(me.public_key), this.publicKey)) throw new IdentityMismatchError('directory entry');
  }

  private rebuild(): void {
    if (!this.raw) return;
    for (const d of this.directory.values()) if (d.user_id !== this.userId) this.trust.observe(d.user_id, d.username, b64decode(d.public_key), this.deps.now());
    this.commitViews(this.buildViews(this.raw, this.directory, !!this.raw.stale));
    this.notify();
  }

  /** Replaces the vault keys and views with freshly built ones; the old key copies are wiped. */
  private commitViews(built: ReturnType<Session['buildViews']>): void {
    for (const s of this.secrets.values()) zero(s.vk);
    for (const s of this.pendingKeys.values()) zero(s.vk);
    this.secrets = built.secrets;
    this.pendingKeys = built.pending;
    this.vaults = built.views;
  }

  private contactName(id: string, directory: Map<string, T.DirectoryUser>): string {
    return this.trust.contacts.get(id)?.username ?? directory.get(id)?.username ?? '(unknown user)';
  }

  private memberView(id: string, role: Role, pk: Uint8Array | undefined, directory: Map<string, T.DirectoryUser>, discrepancy?: MemberView['discrepancy']): MemberView {
    const c = this.trust.contacts.get(id);
    const key = pk ?? c?.publicKey;
    const username = this.contactName(id, directory);
    return {
      userId: id, username, role, fingerprint: key ? fingerprint({ userId: id, username, publicKey: key }) : '',
      verified: id === this.userId || c?.verified === true, blocked: this.trust.isBlocked(id), isSelf: id === this.userId,
      disabled: directory.get(id)?.disabled ?? false, discrepancy,
    };
  }

  private buildViews(resp: T.SyncResponse, directory: Map<string, T.DirectoryUser>, stale: boolean): { views: VaultView[]; secrets: Map<string, VaultSecret>; pending: Map<string, PendingKey> } {
    const prevItems = new Map<string, ItemView>();
    for (const v of this.vaults) for (const i of v.items) prevItems.set(`${v.id}:${v.keyEpoch}:${i.id}`, i);
    const secrets = new Map<string, VaultSecret>();
    const pending = new Map<string, PendingKey>();
    const views: VaultView[] = [];
    const seen = new Set<string>();
    for (const v of resp.vaults ?? []) {
      seen.add(v.id);
      const r = this.evaluateVault(v, directory, prevItems);
      views.push(r.view);
      if (r.secret) secrets.set(v.id, r.secret);
      if (r.pending) pending.set(v.id, r.pending);
    }
    // Local creations / rekeys that never landed (crypto.md §6.4: the trust record was written before sending).
    if (!stale && this.sending === 0) {
      for (const [id, inf] of [...this.trust.inflight]) {
        if (seen.has(id)) continue;
        if (inf.prev === undefined) this.trust.vaults.delete(id);
        this.trust.inflight.delete(id);
        this.trust.touch();
      }
    }
    return { views, secrets, pending };
  }

  /**
   * crypto.md §6.4 for one vault. Returns an open view with its key, a
   * pending view (key held in memory only, nothing decrypted), or a locked view.
   */
  private evaluateVault(v: T.Vault, directory: Map<string, T.DirectoryUser>, prevItems: Map<string, ItemView>): { view: VaultView; secret?: VaultSecret; pending?: PendingKey } {
    const me = this.userId;
    const S = v.my_key.sender_id;
    const epoch = v.key_epoch;
    const base: VaultView = {
      id: v.id, name: '(locked)', personal: v.personal, keyEpoch: epoch, role: v.my_role, rekeyRecommended: v.rekey_recommended,
      metaVersion: v.meta_version, rosterVersion: v.roster_version, rev: v.rev, state: 'locked', rosterStatus: 'ok', members: [], items: [],
    };
    const lock = (reason: LockReason): { view: VaultView } => ({ view: { ...base, state: 'locked', locked: reason } });

    // 1. Personal vault: the sender must be the user themself; anything else is a hard error.
    if (v.personal && S !== me) throw new InvalidSyncError('a personal vault was wrapped by someone else');

    // Resolve a rekey/creation this device sent before: if the server is still at the old epoch it did not land.
    const inf = this.sending === 0 ? this.trust.inflight.get(v.id) : undefined;
    if (inf) {
      if (epoch >= inf.next.epoch) this.trust.inflight.delete(v.id);
      else {
        if (inf.prev) this.trust.setVault(v.id, inf.prev);
        else this.trust.vaults.delete(v.id);
        this.trust.inflight.delete(v.id);
      }
      this.trust.touch();
    }

    // 2./3. Which public key may open this wrap: our own unlocked key, else the TRUST STORE's key for the sender.
    let senderPk: Uint8Array;
    let senderVerified = false;
    if (S === me) senderPk = this.publicKey;
    else {
      const c = this.trust.contacts.get(S);
      if (!c) return lock('undecryptable');
      if (this.trust.isBlocked(S)) return lock('key_mismatch');
      senderPk = c.publicKey;
      senderVerified = c.verified;
    }
    let vk: Uint8Array;
    try {
      vk = unwrapVaultKey({ wrap: b64decode(v.my_key.blob), ctx: { vaultId: v.id, keyEpoch: epoch, senderId: S, recipientId: me }, recipientPrivate: this.privateKey!, senderPublic: senderPk });
    } catch {
      return lock('undecryptable');
    }
    const commit = vaultKeyCommitment({ vaultKey: vk, vaultId: v.id, epoch });
    // While this client is sending a rekey, a concurrent sync may still see the OLD epoch: judge it against the previous record.
    const flying = this.trust.inflight.get(v.id);
    const rec = flying && epoch < flying.next.epoch ? flying.prev : this.trust.vaults.get(v.id);

    // 4. Continuity: lower epoch, or same epoch with a different key, is never accepted.
    if (rec && epoch < rec.epoch) {
      zero(vk);
      return lock('older_epoch');
    }
    if (rec && epoch === rec.epoch && commit !== rec.commit) {
      zero(vk);
      return lock('continuity');
    }
    let accepted = false;
    if (S === me) accepted = true; // only the holder of our private key can have produced a wrap that opens under our own public key
    else if (rec && rec.epoch === epoch) accepted = true; // unchanged (commitment matched above)
    else if (rec && rec.epoch < epoch && rec.owners.some((o) => o.id === S && o.pk === b64encode(senderPk))) accepted = true; // legitimate rekey by a known owner
    else if (!rec && senderVerified) accepted = true; // a new share from someone the user has verified
    if (!accepted) {
      const sc = this.trust.contacts.get(S)!;
      const info: PendingInfo = {
        senderId: S, senderName: sc.username, senderFingerprint: this.trust.fingerprintOf(sc), senderVerified: sc.verified,
        replacedByNonOwner: !!rec,
      };
      return { view: { ...base, name: `Shared by ${sc.username}`, state: 'pending', pending: info }, pending: { vk, epoch, commit } };
    }

    // Roster (§6.3): must open, and must list this client with its own key.
    let roster: Roster | null = null;
    let rosterStatus: VaultView['rosterStatus'] = 'ok';
    try {
      roster = decryptRoster(vk, { vaultId: v.id, epoch }, b64decode(v.enc_roster));
    } catch {
      rosterStatus = 'unreadable';
    }
    if (roster) {
      const mine = rosterMember(roster, me);
      if (!mine || !sameBytes(mine.publicKey, this.publicKey)) {
        zero(vk);
        return lock('roster_missing_me');
      }
      // The roster's keys are the members' keys: a disagreement with the contact triple is a key mismatch.
      for (const m of roster.members) {
        const c = this.trust.contacts.get(m.id);
        if (c && !sameBytes(c.publicKey, m.publicKey)) this.trust.recordRosterMismatch(m.id, c.username, this.deps.now());
      }
    }
    const owners: VaultTrust['owners'] = roster ? rosterOwners(roster).map((o) => ({ id: o.id, pk: b64encode(o.publicKey) })) : (rec?.owners ?? []);
    if (!(flying && epoch < flying.next.epoch) && (!rec || rec.epoch !== epoch || rec.commit !== commit || JSON.stringify(rec.owners) !== JSON.stringify(owners))) this.trust.setVault(v.id, { epoch, commit, owners });

    // Members: the roster is what is shown; differences from the server's list are labelled.
    const members: MemberView[] = [];
    const listed = new Map(v.members.map((m) => [m.user_id, m.role] as const));
    if (roster) {
      for (const m of roster.members) {
        const sr = listed.get(m.id);
        members.push(this.memberView(m.id, m.role, m.publicKey, directory, sr === undefined ? 'left' : sr !== m.role ? 'role_differs' : undefined));
      }
      for (const [id, role] of listed) if (!rosterMember(roster, id)) members.push(this.memberView(id, role, undefined, directory, 'unlisted'));
    } else {
      for (const [id, role] of listed) members.push(this.memberView(id, role, undefined, directory));
    }

    const view: VaultView = { ...base, state: 'open', rosterStatus, members };
    let metaExtra: ExtraMember[] = [];
    try {
      const meta = decryptVaultMeta(vk, { vaultId: v.id, epoch }, b64decode(v.enc_meta));
      view.name = meta.name;
      metaExtra = meta.extra;
    } catch {
      view.name = '(unreadable name)';
    }
    view.items = v.items.map((it): ItemView => {
      // Reuse an earlier decryption only if everything it depended on is identical: key (commitment), ciphertext, version and the
      // server's metadata. Anything else is decrypted again. The cache is the previous views, so lock() drops it with them.
      const sig = `${commit}\0${it.blob}`;
      const hit = prevItems.get(`${v.id}:${epoch}:${it.id}`);
      if (hit && itemSig.get(hit) === sig && hit.version === it.version && hit.updatedAt === it.updated_at && hit.updatedBy === it.updated_by) return hit;
      const iv: ItemView = { id: it.id, version: it.version, updatedAt: it.updated_at, updatedBy: it.updated_by };
      itemSig.set(iv, sig);
      try {
        iv.item = decryptItem(vk, { vaultId: v.id, itemId: it.id, epoch }, b64decode(it.blob));
      } catch {
        iv.error = 'This entry could not be read.';
      }
      return iv;
    });
    return { view, secret: { vk, epoch, roster, metaExtra } };
  }

  vault(id: string): VaultView | undefined {
    return this.vaults.find((v) => v.id === id);
  }
  pendingShares(): VaultView[] {
    return this.vaults.filter((v) => v.state === 'pending');
  }

  private rawVault(id: string): T.Vault {
    const v = this.raw?.vaults?.find((x) => x.id === id);
    if (!v) throw new VaultError('That vault is not available.');
    return v;
  }

  private mustVault(id: string): { view: VaultView; sec: VaultSecret } {
    const view = this.vault(id);
    const sec = this.secrets.get(id);
    if (!view || !sec || view.state !== 'open') throw new VaultError('That vault is not open on this device.');
    return { view, sec };
  }

  private requireRole(view: VaultView, ...roles: string[]): void {
    if (!roles.includes(view.role)) throw view.role === 'viewer' ? new ReadOnlyError('viewer') : new PermissionError('Only a vault owner can do that.');
  }

  // ------------------------------------------------------------------ deliberate recovery (§6.4)

  /**
   * The person at the device accepts the servers' (older) state after an
   * administrator restored a backup. Clears ONLY the highest rev and the per-vault
   * records (epoch, commitment, owners); contacts, verified flags and mismatch
   * events are untouched. Refused unless the pattern is purely "older" (a vault
   * at the same epoch with a different key, or a mismatch, is never a restore).
   * Re-evaluates every vault as if first seen: own keys and verified senders are
   * accepted, the rest become pending. Never automatic.
   */
  async acceptRestoredState(): Promise<void> {
    this.assertUnlocked();
    if (!this.recovery) throw new RecoveryRefusedError('Nothing to accept: the servers are not showing older data than this device has seen.');
    if (!this.canAcceptRecovery) throw new RecoveryRefusedError('This does not look like a restored backup, so it cannot be accepted.');
    const resp = await this.call(() => this.api.sync());
    validateSync(resp);
    if (resp.stale) throw new RecoveryRefusedError('Only an answer confirmed by a majority of the servers can be accepted. Try again when a majority of the servers can be reached.');
    this.checkIdentity(resp);
    for (const d of resp.directory ?? []) if (d.user_id !== this.userId) this.trust.observe(d.user_id, d.username, b64decode(d.public_key), this.deps.now());
    // A restore moves rev and epochs BACKWARD only: a vault at the same epoch with another key, or a blocked sender, refuses.
    for (const v of resp.vaults ?? []) {
      const rec = this.trust.vaults.get(v.id);
      const S = v.my_key.sender_id;
      const pk = S === this.userId ? this.publicKey : this.trust.contacts.get(S)?.publicKey;
      if (!rec || !pk || this.trust.isBlocked(S) || rec.epoch !== v.key_epoch) continue;
      try {
        const vk = unwrapVaultKey({ wrap: b64decode(v.my_key.blob), ctx: { vaultId: v.id, keyEpoch: v.key_epoch, senderId: S, recipientId: this.userId }, recipientPrivate: this.privateKey!, senderPublic: pk });
        const same = vaultKeyCommitment({ vaultKey: vk, vaultId: v.id, epoch: v.key_epoch }) === rec.commit;
        zero(vk);
        if (!same) throw new RecoveryRefusedError('A vault is offered at the same key version with a different key. That is not what a restore looks like, so nothing was accepted.');
      } catch (e) {
        if (e instanceof RecoveryRefusedError) throw e;
      }
    }
    this.trust.highestRev = 0;
    this.trust.vaults.clear();
    this.trust.inflight.clear();
    this.trust.touch();
    this.recovery = null;
    this.raw = null;
    await this.applySync(resp);
    // applySync keeps an existing newer cache; a restore deliberately replaces it
    await this.deps.store.set(K.sync(this.username), { sync: resp, savedAt: this.deps.now() } satisfies CachedSync);
  }

  // ------------------------------------------------------------------ pending shares (§6.4)

  /**
   * The person at the device has compared the sender's fingerprint (the UI
   * shows it and asks) and accepts the vault: the sender becomes a verified
   * contact and the epoch, key commitment and roster owners are recorded.
   */
  async acceptPending(vaultId: string): Promise<void> {
    const pk = this.pendingKeys.get(vaultId);
    const view = this.vault(vaultId);
    if (!pk || !view || view.state !== 'pending' || !view.pending) throw new VaultError('There is nothing to accept for that vault.');
    const sender = view.pending.senderId;
    let roster: Roster | null = null;
    try {
      roster = decryptRoster(pk.vk, { vaultId, epoch: pk.epoch }, b64decode(this.rawVault(vaultId).enc_roster));
    } catch {
      roster = null;
    }
    const mine = roster ? rosterMember(roster, this.userId) : undefined;
    if (roster && (!mine || !sameBytes(mine.publicKey, this.publicKey))) throw new VaultError('This shared vault does not list you with your own key, so it was not accepted.');
    if (!this.trust.setVerified(sender)) throw new KeyMismatchError(sender, view.pending.senderName);
    this.trust.setVault(vaultId, { epoch: pk.epoch, commit: pk.commit, owners: roster ? rosterOwners(roster).map((o) => ({ id: o.id, pk: b64encode(o.publicKey) })) : [] });
    await this.trust.save();
    this.rebuild();
  }

  // ------------------------------------------------------------------ contacts

  /** Explicit act of the person at the device: they compared the fingerprint with its owner (crypto.md §6.2). */
  async markVerified(userId: string): Promise<void> {
    const c = this.trust.contacts.get(userId);
    if (!c) throw new VaultError('That user is not known to this device.');
    if (!this.trust.setVerified(userId)) throw new KeyMismatchError(userId, c.username);
    await this.trust.save();
    this.rebuild();
  }

  async dismissMismatch(eventId: string): Promise<void> {
    this.trust.dismiss(eventId);
    await this.trust.save();
    this.notify();
  }

  contacts(): ContactView[] {
    return [...this.trust.contacts.values()]
      .map((c) => {
        const d = this.directory.get(c.userId);
        return {
          userId: c.userId, username: c.username, fingerprint: this.trust.fingerprintOf(c), verified: c.userId === this.userId || c.verified,
          blocked: this.trust.isBlocked(c.userId), isSelf: c.userId === this.userId, isAdmin: d?.is_admin ?? false, disabled: d?.disabled ?? false,
        };
      })
      .sort((a, b) => (a.isSelf === b.isSelf ? a.username.localeCompare(b.username) : a.isSelf ? -1 : 1));
  }

  /** Look up a household member for sharing. The key comes from the TRUST STORE (first sight = directory); blocked identities throw. */
  lookupUser(username: string): UserLookup {
    const name = normalizeUsername(username);
    const id = this.trust.byUsername.get(name);
    const c = id ? this.trust.contacts.get(id) : undefined;
    if (!c) {
      const offender = this.trust.mismatches.find((m) => m.username === name);
      if (offender) throw new KeyMismatchError(offender.userId, name);
      throw new VaultError(`There is no user "${name}" in this household.`);
    }
    if (this.trust.isBlocked(c.userId)) throw new KeyMismatchError(c.userId, c.username);
    return {
      userId: c.userId, username: c.username, publicKey: c.publicKey, fingerprint: this.trust.fingerprintOf(c), verified: c.verified,
      disabled: this.directory.get(c.userId)?.disabled ?? false,
    };
  }

  directoryUsers(): { userId: string; username: string; isAdmin: boolean; disabled: boolean; fingerprint: string; verified: boolean }[] {
    return this.contacts().map((c) => ({ userId: c.userId, username: c.username, isAdmin: c.isAdmin, disabled: c.disabled, fingerprint: c.fingerprint, verified: c.verified }));
  }

  // ------------------------------------------------------------------ items

  private encodeItemBlob(sec: VaultSecret, vaultId: string, itemId: string, item: Item): string {
    const blob = encryptItem(sec.vk, { vaultId, itemId, epoch: sec.epoch }, item);
    if (blob.length > MAX_ITEM_BLOB) throw new VaultError('This entry is too large (64 KiB limit).');
    return b64encode(blob);
  }

  async createItem(vaultId: string, item: Item): Promise<string> {
    const itemId = newId();
    const now = this.deps.now();
    item = { ...item, created_at: item.created_at || now, updated_at: now };
    await this.putItem(vaultId, itemId, item, 0, 'create');
    return itemId;
  }

  /** Apply `edit` to the current decrypted item (history + updated_at maintained, unknown members kept byte for byte). */
  async updateItem(vaultId: string, itemId: string, edit: (it: Item) => void, opts?: { base?: ItemView }): Promise<void> {
    const cur = this.vault(vaultId)?.items.find((i) => i.id === itemId);
    if (!cur?.item) throw new VaultError('That entry is not available.');
    const next = editItem(cur.item, this.deps.now(), edit);
    // An editor that was open while a background sync brought a different version must not overwrite it silently.
    const b = opts?.base;
    if (b && b.version !== cur.version && !(b.item && itemToJson(b.item) === itemToJson(cur.item))) {
      throw new ConflictError({ vaultId, itemId, kind: 'update', mine: next, theirs: cur, currentVersion: cur.version });
    }
    try {
      await this.putItem(vaultId, itemId, next, cur.version, 'update');
    } catch (e) {
      // A rekey bumps versions without changing content: rebase silently if the server's copy equals what the user started from.
      if (e instanceof ConflictError && e.kind === 'update' && e.theirs?.item && itemToJson(e.theirs.item) === itemToJson(cur.item)) {
        await this.putItem(vaultId, itemId, next, e.theirs.version, 'update');
        return;
      }
      throw e;
    }
  }

  /** Works for unreadable entries too: any member with write access may delete them (crypto.md §5.3). */
  async deleteItem(vaultId: string, itemId: string): Promise<void> {
    const { view } = this.mustVault(vaultId);
    this.requireRole(view, 'owner', 'editor');
    const cur = view.items.find((i) => i.id === itemId);
    if (!cur) throw new VaultError('That entry is not available.');
    await this.guardedItemWrite(vaultId, itemId, 'delete', null, async () => {
      await this.write(() => this.api.deleteItem(vaultId, itemId, cur.version));
    });
    await this.sync();
  }

  private async putItem(vaultId: string, itemId: string, item: Item, baseVersion: number, kind: 'create' | 'update'): Promise<void> {
    const { view } = this.mustVault(vaultId);
    this.requireRole(view, 'owner', 'editor');
    await this.guardedItemWrite(vaultId, itemId, kind, item, async () => {
      const { view: v2, sec } = this.mustVault(vaultId); // re-read: a key_epoch_mismatch retry runs after a sync
      await this.write(() => this.api.putItem(vaultId, itemId, { blob: this.encodeItemBlob(sec, vaultId, itemId, item), base_version: baseVersion, key_epoch: v2.keyEpoch }));
    });
    await this.sync();
  }

  /** key_epoch_mismatch -> sync and retry once; version_conflict -> sync and surface a ConflictError (never overwrite). */
  private async guardedItemWrite(vaultId: string, itemId: string, kind: 'create' | 'update' | 'delete', mine: Item | null, run: () => Promise<void>): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await run();
      } catch (e) {
        if (e instanceof ApiError && e.code === 'key_epoch_mismatch' && attempt === 0) {
          await this.sync();
          continue;
        }
        if (e instanceof ApiError && e.code === 'version_conflict') {
          await this.sync();
          const theirs = this.vault(vaultId)?.items.find((i) => i.id === itemId) ?? null;
          throw new ConflictError({ vaultId, itemId, kind, mine, theirs, currentVersion: theirs?.version ?? e.currentVersion ?? 0 });
        }
        throw e;
      }
    }
  }

  async resolveConflict(c: ConflictError, choice: 'overwrite' | 'discard'): Promise<void> {
    if (choice === 'discard') {
      await this.sync();
      return;
    }
    if (c.kind === 'delete') {
      if (c.theirs) await this.deleteItem(c.vaultId, c.itemId);
      return;
    }
    if (!c.mine) return;
    await this.putItem(c.vaultId, c.itemId, { ...c.mine, updated_at: this.deps.now() }, c.theirs?.version ?? 0, c.theirs ? 'update' : 'create');
  }

  // ------------------------------------------------------------------ vaults

  /**
   * Creates a vault with a locally generated key. Its epoch and key commitment
   * are recorded in the trust store BEFORE the request is sent and the local
   * key keeps being used: a later sync that offers a different key for this
   * vault and epoch fails the continuity rule (crypto.md §6.4).
   */
  async createVault(name: string): Promise<string> {
    this.assertUnlocked();
    const { req, rec } = newVaultRequest({ id: this.userId, publicKey: this.publicKey, privateKey: this.privateKey! }, name);
    const vaultId = req.vault_id;
    await this.recordBeforeSend(vaultId, undefined, rec);
    this.sending++;
    try {
      await this.write(() => this.api.createVault(req));
    } catch (e) {
      if (definite(e)) await this.revertRecord(vaultId, undefined);
      throw e;
    } finally {
      this.sending--;
    }
    this.trust.inflight.delete(vaultId);
    this.trust.touch();
    await this.sync();
    return vaultId;
  }

  private async recordBeforeSend(vaultId: string, prev: VaultTrust | undefined, next: VaultTrust): Promise<void> {
    this.trust.setVault(vaultId, next);
    this.trust.inflight.set(vaultId, { prev, next });
    await this.trust.save();
  }

  private async revertRecord(vaultId: string, prev: VaultTrust | undefined): Promise<void> {
    if (prev) this.trust.setVault(vaultId, prev);
    else this.trust.vaults.delete(vaultId);
    this.trust.inflight.delete(vaultId);
    this.trust.touch();
    await this.trust.save();
  }

  async renameVault(vaultId: string, name: string): Promise<void> {
    const { view, sec } = this.mustVault(vaultId);
    this.requireRole(view, 'owner');
    try {
      await this.write(() => this.api.updateVaultMeta(vaultId, { enc_meta: b64encode(encryptVaultMeta(sec.vk, { vaultId, epoch: sec.epoch, meta: { name, extra: sec.metaExtra } })), base_meta_version: view.metaVersion }));
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'version_conflict' || e.code === 'key_epoch_mismatch')) {
        await this.sync();
        throw new StaleStateError();
      }
      throw e;
    }
    await this.sync();
  }

  async deleteVault(vaultId: string): Promise<void> {
    const { view } = this.mustVault(vaultId);
    this.requireRole(view, 'owner');
    if (view.personal) throw new PermissionError('A personal vault cannot be deleted.');
    await this.write(() => this.api.deleteVault(vaultId));
    await this.sync();
  }

  // ------------------------------------------------------------------ sharing (§6.5)

  /**
   * Adds a member: the target must be a VERIFIED contact; the vault key is
   * wrapped to the trust store's key; the new roster (current authenticated
   * roster plus the member) is uploaded in the same request with compare-and-swap
   * on the roster version (re-synced and retried on version_conflict).
   */
  async addMember(vaultId: string, username: string, role: Role): Promise<void> {
    const first = this.mustVault(vaultId);
    this.requireRole(first.view, 'owner');
    if (first.view.personal) throw new PermissionError('A personal vault cannot be shared.');
    const target = this.lookupUser(username);
    if (target.disabled) throw new VaultError('That user is disabled.');
    if (!target.verified) throw new NotVerifiedError([target]);
    await this.retryOnConflict(async () => {
      const { view, sec } = this.mustVault(vaultId);
      if (!sec.roster) throw new RosterUnreadableError();
      const already = rosterMember(sec.roster, target.userId);
      if (already && already.role === role && view.members.some((m) => m.userId === target.userId && !m.discrepancy)) return;
      if (already) return this.setMemberRole(vaultId, target.userId, role);
      const roster = rosterWithMember(sec.roster, { id: target.userId, publicKey: target.publicKey, role });
      const wk = wrapVaultKey({ vaultKey: sec.vk, ctx: { vaultId, keyEpoch: sec.epoch, senderId: this.userId, recipientId: target.userId }, senderPrivate: this.privateKey!, recipientPublic: target.publicKey });
      await this.write(() =>
        this.api.putMember(vaultId, target.userId, {
          role, wrapped_key: { sender_id: this.userId, blob: b64encode(wk) }, key_epoch: sec.epoch,
          enc_roster: b64encode(encryptRoster(sec.vk, { vaultId, epoch: sec.epoch }, roster)), base_roster_version: view.rosterVersion,
        }),
      );
      await this.sync();
    });
  }

  /** Runs `attempt` (which reads the current state itself) up to four times, re-syncing after a version_conflict or key_epoch_mismatch. */
  private async retryOnConflict(attempt: () => Promise<void>): Promise<void> {
    for (let n = 0; ; n++) {
      try {
        return await attempt();
      } catch (e) {
        if (!(e instanceof ApiError && (e.code === 'version_conflict' || e.code === 'key_epoch_mismatch') && n < 3)) throw e;
        await this.sync();
      }
    }
  }

  async setMemberRole(vaultId: string, userId: string, role: Role): Promise<void> {
    await this.retryOnConflict(async () => {
      const { view, sec } = this.mustVault(vaultId);
      this.requireRole(view, 'owner');
      if (!sec.roster) throw new RosterUnreadableError();
      const roster = rosterWithRole(sec.roster, userId, role);
      await this.write(() =>
        this.api.putMember(vaultId, userId, { role, key_epoch: sec.epoch, enc_roster: b64encode(encryptRoster(sec.vk, { vaultId, epoch: sec.epoch }, roster)), base_roster_version: view.rosterVersion }),
      );
      await this.sync();
    });
  }

  /** A member leaves on their own. The roster keeps listing them until an owner rekeys. */
  async leaveVault(vaultId: string): Promise<void> {
    this.mustVault(vaultId);
    await this.write(() => this.api.deleteMember(vaultId, this.userId));
    await this.sync();
  }

  /** An owner cuts a member off immediately without a rekey (they still hold the old key until the next rekey). */
  async cutOffMember(vaultId: string, userId: string): Promise<void> {
    const { view } = this.mustVault(vaultId);
    this.requireRole(view, 'owner');
    if (userId === this.userId) throw new VaultError('Use "Leave this vault" to leave a vault.');
    await this.write(() => this.api.deleteMember(vaultId, userId));
    await this.sync();
  }

  // ------------------------------------------------------------------ rekey (§6.6)

  /**
   * Computes, locally and without sending anything, who would receive the new
   * key. Recipients = roster members, minus those being removed, minus those
   * the server no longer lists. If the server lists someone who is NOT in the
   * roster, it stops (UnlistedMemberError). Public keys and roles come from the
   * roster; every recipient other than the owner must be a verified contact
   * (reported in `unverified`; executeRekey refuses until they are verified).
   * `repair` rebuilds an unreadable roster from the server list (still only
   * with verified contacts).
   */
  planRekey(vaultId: string, opts: RekeyOpts = {}): RekeyPlan {
    return this.planInternal(vaultId, opts);
  }

  private planInternal(vaultId: string, opts: RekeyOpts): PlanInternal {
    const { view, sec } = this.mustVault(vaultId);
    this.requireRole(view, 'owner');
    const v = this.rawVault(vaultId);
    const me = this.userId;
    const listed = new Map(v.members.map((m) => [m.user_id, m.role] as const));
    const remove = new Set(opts.remove ?? []);
    if (remove.has(me)) throw new VaultError('You cannot remove yourself; use "Leave this vault" instead.');
    for (const id of remove) if (!listed.has(id)) throw new VaultError('That user is not a current member of the vault.');
    if (view.personal && remove.size > 0) throw new PermissionError('A personal vault has no other members.');
    if (!listed.has(me)) throw new VaultError('You are not listed as a member by the server.');

    const entries: { id: string; pk: Uint8Array; role: Role }[] = [];
    if (opts.repair) {
      if (sec.roster) throw new VaultError('This vault has a readable member list; repair is only for unreadable ones.');
      for (const [id, role] of listed) {
        if (remove.has(id)) continue;
        const c = this.trust.contacts.get(id);
        if (!c) throw new NotVerifiedError([{ userId: id, username: this.contactName(id, this.directory) }]);
        entries.push({ id, pk: id === me ? this.publicKey : c.publicKey, role });
      }
    } else {
      if (!sec.roster) throw new RosterUnreadableError();
      const unlisted = [...listed.keys()].filter((id) => !rosterMember(sec.roster!, id));
      if (unlisted.length) throw new UnlistedMemberError(unlisted.map((id) => ({ userId: id, username: this.contactName(id, this.directory) })));
      for (const m of sec.roster.members) if (listed.has(m.id) && !remove.has(m.id)) entries.push({ id: m.id, pk: m.publicKey, role: m.role });
    }
    const recipients: RekeyRecipient[] = entries.map((e) => {
      const c = this.trust.contacts.get(e.id);
      const self = e.id === me;
      const username = this.contactName(e.id, this.directory);
      // A roster key that disagrees with the contact triple is a mismatch: never verified.
      const keyOk = self ? sameBytes(e.pk, this.publicKey) : !!c && sameBytes(c.publicKey, e.pk) && !this.trust.isBlocked(e.id);
      return { userId: e.id, username, role: e.role, fingerprint: fingerprint({ userId: e.id, username, publicKey: e.pk }), verified: self ? keyOk : keyOk && c!.verified, isSelf: self };
    });
    if (!recipients.some((r) => r.isSelf && r.role === 'owner')) throw new VaultError('The new member list would have no owner.');
    return {
      vaultId, vaultName: view.name, epoch: view.keyEpoch + 1, repair: !!opts.repair,
      removed: [...remove].map((id) => ({ userId: id, username: this.contactName(id, this.directory) })),
      recipients, unverified: recipients.filter((r) => !r.isSelf && !r.verified), opts,
      key: JSON.stringify([v.rev, recipients.map((r) => [r.userId, r.role, r.fingerprint])]),
    };
  }

  /**
   * Executes a plan: new key at epoch+1, raw re-encryption of every box that
   * opens (others carried over), new roster, wraps for the recipients, ONE
   * atomic request with `remove`. The new key's commitment is recorded before
   * sending and the local key is kept (never replaced by a server-returned one).
   * If the world changed since the plan (server list, roster) it stops and the
   * user must look at a fresh plan.
   */
  async executeRekey(plan: RekeyPlan, onProgress?: (p: Progress) => void): Promise<void> {
    const opts = (plan as PlanInternal).opts ?? {};
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt > 0) await this.sync();
      const cur = this.planInternal(plan.vaultId, opts);
      const same = (a: RekeyPlan) => JSON.stringify(a.recipients.map((r) => [r.userId, r.role, r.fingerprint])) + JSON.stringify(a.removed.map((r) => r.userId));
      if (same(cur) !== same(plan)) throw new StaleStateError('The member list changed while you were confirming. Review the recipients again.');
      if (cur.unverified.length) throw new NotVerifiedError(cur.unverified);
      const { view, sec } = this.mustVault(plan.vaultId);
      const v = this.rawVault(plan.vaultId);
      const newEpoch = view.keyEpoch + 1;
      const newVk = randomBytes(32);
      const total = v.items.length + cur.recipients.length + 2;
      let done = 0;
      const report = (phase: string) => onProgress?.({ phase, done, total });
      report('Starting');
      const roster: Roster = { v: 1, members: [...cur.recipients].sort((a, b) => (a.userId < b.userId ? -1 : 1)).map((r) => ({ id: r.userId, publicKey: this.keyOf(r, sec), role: r.role })) };
      const prev = this.trust.vaults.get(plan.vaultId);
      const next: VaultTrust = { epoch: newEpoch, commit: vaultKeyCommitment({ vaultKey: newVk, vaultId: plan.vaultId, epoch: newEpoch }), owners: roster.members.filter((m) => m.role === 'owner').map((m) => ({ id: m.id, pk: b64encode(m.publicKey) })) };
      const meta = reencryptMeta({ oldKey: sec.vk, newKey: newVk, vaultId: plan.vaultId, oldEpoch: view.keyEpoch, newEpoch, blob: b64decode(v.enc_meta) });
      done++;
      const wrapped = new Map<string, T.WrappedKey>();
      for (const r of cur.recipients) {
        const pk = this.keyOf(r, sec);
        wrapped.set(r.userId, { sender_id: this.userId, blob: b64encode(wrapVaultKey({ vaultKey: newVk, ctx: { vaultId: plan.vaultId, keyEpoch: newEpoch, senderId: this.userId, recipientId: r.userId }, senderPrivate: this.privateKey!, recipientPublic: pk })) });
        done++;
        report('Encrypting the new key for each person');
      }
      const items: T.RekeyItem[] = [];
      for (const it of v.items) {
        const re = reencryptItem({ oldKey: sec.vk, newKey: newVk, vaultId: plan.vaultId, itemId: it.id, oldEpoch: view.keyEpoch, newEpoch, blob: b64decode(it.blob) });
        items.push({ id: it.id, blob: b64encode(re.blob) });
        done++;
        report('Re-encrypting entries');
        if (items.length % 25 === 0) await tick();
      }
      const req: T.RekeyRequest = {
        base_rev: v.rev, new_key_epoch: newEpoch, ...(cur.removed.length ? { remove: cur.removed.map((r) => r.userId) } : {}),
        enc_meta: b64encode(meta.blob), enc_roster: b64encode(encryptRoster(newVk, { vaultId: plan.vaultId, epoch: newEpoch }, roster)),
        wrapped_keys: Object.fromEntries(wrapped), items,
      };
      zero(newVk);
      await this.recordBeforeSend(plan.vaultId, prev, next);
      this.sending++;
      try {
        report('Uploading');
        await this.write(() => this.api.rekey(plan.vaultId, req));
      } catch (e) {
        if (definite(e)) await this.revertRecord(plan.vaultId, prev);
        if (e instanceof ApiError && e.code === 'version_conflict' && attempt < 3) continue;
        throw e;
      } finally {
        this.sending--;
      }
      this.trust.inflight.delete(plan.vaultId);
      this.trust.touch();
      await this.sync();
      onProgress?.({ phase: 'Done', done: total, total });
      return;
    }
    throw new StaleStateError();
  }

  private keyOf(r: RekeyRecipient, sec: VaultSecret): Uint8Array {
    if (r.isSelf) return this.publicKey;
    const fromRoster = sec.roster && rosterMember(sec.roster, r.userId)?.publicKey;
    return fromRoster ?? this.trust.contacts.get(r.userId)!.publicKey;
  }

  /** Owner-initiated removal IS this rekey: one atomic request removes the member and installs the new key for everyone else. */
  async removeMember(vaultId: string, userId: string, onProgress?: (p: Progress) => void): Promise<void> {
    if (userId === this.userId) return this.leaveVault(vaultId);
    await this.executeRekey(this.planRekey(vaultId, { remove: [userId] }), onProgress);
  }

  /** Rekey without removing anyone (after a leave, or on the server's rekey_recommended hint). */
  async rekeyVault(vaultId: string, onProgress?: (p: Progress) => void): Promise<void> {
    await this.executeRekey(this.planRekey(vaultId), onProgress);
  }

  // ------------------------------------------------------------------ account

  /**
   * Re-derives with a fresh salt, uploads the new wrapped account key, then
   * SYNCS and verifies that the account block now opens with the new key before
   * discarding it; the sync replaces the cached account block, so the old
   * password no longer unlocks this device offline (crypto.md §4).
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    if (!this.canWrite) throw new ReadOnlyError(this.mode === 'stale' ? 'stale' : 'offline');
    const acct = this.raw!.account!;
    const cur = await deriveMasterKeys({ username: this.username, password: currentPassword, params: kdfFromWire(acct.kdf) });
    const ok = equalBytes(cur.loginKey, this.loginKey!);
    zero(cur.encKey, cur.loginKey);
    if (!ok) throw new WrongPasswordError();
    const kdf = defaultKdfParams();
    const nk = await deriveMasterKeys({ username: this.username, password: newPassword, params: kdf });
    try {
      const wrapped = rewrapAccountKey({ userId: this.userId, newEncKey: nk.encKey, accountKey: this.accountKey! });
      await this.write(() => this.api.changePassword({ current_login_key: b64encode(this.loginKey!), new_kdf: kdfToWire(kdf), new_login_key: b64encode(nk.loginKey), new_wrapped_account_key: b64encode(wrapped) }));
      zero(this.loginKey!);
      this.loginKey = nk.loginKey;
      const resp = await this.call(() => this.api.sync());
      validateSync(resp);
      const a = resp.account;
      let opened: { accountKey: Uint8Array; privateKey: Uint8Array };
      try {
        opened = unlockAccount({ userId: this.userId, encKey: nk.encKey, publicKey: b64decode(a.public_key), wrappedAccountKey: b64decode(a.wrapped_account_key), encPrivateKey: b64decode(a.enc_private_key) });
      } catch {
        throw new VaultError('The server did not store the new password material correctly. Your old cached copy was kept; check the servers before trying again.');
      }
      zero(opened.accountKey, opened.privateKey);
      this.raw = null;
      await this.applySync(resp);
    } finally {
      zero(nk.encKey);
    }
  }

  /** Revoking can fail with 401 once the session is too old to refresh: treat it as an ended session (ask for the master password again). */
  async revokeSessions(): Promise<void> {
    this.assertUnlocked();
    try {
      await this.api.revokeSessions();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'unauthorized') {
        this.lock();
        throw new SessionExpiredError();
      }
      throw e;
    }
  }

  // ------------------------------------------------------------------ admin

  private requireAdmin(): void {
    if (!this.isAdmin) throw new PermissionError('Only an administrator can do that.');
  }
  async createInvite(ttlHours: number): Promise<T.CreateInviteResponse> {
    this.requireAdmin();
    return this.write(() => this.api.createInvite(ttlHours));
  }
  async listInvites(): Promise<T.Invite[]> {
    this.requireAdmin();
    return (await this.call(() => this.api.listInvites())).invites ?? [];
  }
  async revokeInvite(id: string): Promise<void> {
    this.requireAdmin();
    await this.write(() => this.api.deleteInvite(id));
  }
  async setUserDisabled(userId: string, disabled: boolean): Promise<void> {
    this.requireAdmin();
    await this.write(() => this.api.adminUpdateUser(userId, { disabled }));
    await this.sync();
  }
  async setUserAdmin(userId: string, isAdmin: boolean): Promise<void> {
    this.requireAdmin();
    await this.write(() => this.api.adminUpdateUser(userId, { is_admin: isAdmin }));
    await this.sync();
  }

  async clusterStatus(): Promise<{ nodes: Awaited<ReturnType<ApiClient['probeNodes']>>; admin?: T.AdminClusterResponse }> {
    const nodes = await this.api.probeNodes();
    let admin: T.AdminClusterResponse | undefined;
    if (this.isAdmin && this.api.token) {
      try {
        admin = await this.call(() => this.api.adminCluster());
      } catch {
        /* status page degrades gracefully */
      }
    }
    return { nodes, admin };
  }

  // ------------------------------------------------------------------ backups

  /** Works offline too. Unreadable entries, pending and locked vaults are counted in `skipped`; they never block the export of the rest. */
  async exportBackup(passphrase: string): Promise<{ text: string; filename: string; vaults: number; items: number; skipped: number }> {
    this.assertUnlocked();
    let skipped = 0;
    let items = 0;
    const payload: BackupPayload = { v: 1, exported_at: this.deps.now(), exported_by: this.username, vaults: [] };
    for (const v of this.vaults) {
      if (v.state !== 'open') { skipped++; continue; }
      const entries = [];
      for (const it of v.items) {
        if (it.item) { entries.push({ id: it.id, item: it.item }); items++; } else skipped++;
      }
      payload.vaults.push({ id: v.id, name: v.name, personal: v.personal, items: entries });
    }
    const text = await encodeBackup(payload, passphrase, defaultKdfParams(), this.deps.now());
    const d = new Date(this.deps.now()).toISOString().slice(0, 10);
    return { text, filename: `family-vault-backup-${d}.fpvbackup.json`, vaults: payload.vaults.length, items, skipped };
  }

  inspectBackup(text: string, passphrase: string): Promise<BackupPayload> {
    return decodeBackup(text, passphrase);
  }

  /** Restore every vault into NEW vaults with new IDs, each with a locally generated key (createVault records it before sending). */
  async importBackup(payload: BackupPayload, onProgress?: (p: Progress) => void): Promise<{ vaults: number; items: number; failed: number }> {
    let total = 0;
    for (const v of payload.vaults) total += v.items.length + 1;
    let done = 0;
    let items = 0;
    let failed = 0;
    for (const bv of payload.vaults) {
      const id = await this.createVault(`${bv.name} (restored)`);
      done++;
      onProgress?.({ phase: `Restoring ${bv.name}`, done, total });
      for (const e of bv.items) {
        const itemId = newId();
        try {
          const { view, sec } = this.mustVault(id);
          await this.write(() => this.api.putItem(id, itemId, { blob: this.encodeItemBlob(sec, id, itemId, e.item), base_version: 0, key_epoch: view.keyEpoch }));
          items++;
        } catch (err) {
          if (err instanceof NetworkError || (err instanceof ApiError && err.code === 'unavailable')) throw err;
          failed++;
        }
        done++;
        if (done % 10 === 0) onProgress?.({ phase: `Restoring ${bv.name}`, done, total });
      }
    }
    await this.sync();
    onProgress?.({ phase: 'Done', done: total, total });
    return { vaults: payload.vaults.length, items, failed };
  }
}
