// A small in-memory fake of the Family Vault HTTP API (docs/spec/api.md),
// faithful enough to exercise the client: auth, invites, vaults, members,
// optimistic concurrency, key epochs, atomic rekey, idempotency, and
// per-node outages (down / unavailable / stale reads).
//
// It never sees plaintext: it stores whatever base64 the client sends.

import { createHash, randomBytes } from 'node:crypto';

type J = Record<string, any>;

interface User {
  id: string; username: string; kdf: J; loginKey: string; publicKey: string; wrapped: string; encPriv: string;
  isAdmin: boolean; disabled: boolean; epoch: number; createdAt: number;
}
interface Vault {
  id: string; personal: boolean; epoch: number; encMeta: string; metaVersion: number; encRoster: string; rosterVersion: number; creator: string; rev: number; rekeyRecommended: boolean;
  members: Map<string, { role: string; addedBy: string; key: J }>;
  items: Map<string, { version: number; blob: string; updatedAt: number; updatedBy: string }>;
}

export interface NodeState {
  /** fetch rejects with a network error */
  down: boolean;
  /** answers 503 unavailable for linearizable reads and writes; serves ?consistency=stale */
  unavailable: boolean;
}

export class FakeServer {
  readonly bootstrapToken = 'bootstrap-secret';
  users = new Map<string, User>();
  invites = new Map<string, { id: string; createdBy: string; createdAt: number; expiresAt: number; usedBy?: string }>();
  vaults = new Map<string, Vault>();
  rev = 1;
  nodes = new Map<string, NodeState>();
  idem = new Map<string, { status: number; body: unknown }>();
  /** every request seen: {node, method, path, headers} for assertions */
  log: { node: string; method: string; path: string; headers: Record<string, string>; query: string }[] = [];
  /** if > 0, the next N mutating requests are APPLIED but reply 503 outcome_unknown */
  outcomeUnknownNext = 0;
  /** quotas (api.md §1): bytes per vault / per creating user / household */
  quota = { vault: 8 << 20, user: 16 << 20, cluster: 48 << 20 };
  /** hand out these KDF params from prelogin (to test weak-parameter refusal) */
  kdfOverride: J | null = null;
  clock = () => Date.now();

  constructor(urls: string[]) {
    for (const u of urls) this.nodes.set(u, { down: false, unavailable: false });
  }

  /** A deep copy of the replicated state, as an administrator's backup would hold it. */
  snapshot() {
    return structuredClone({ users: this.users, invites: this.invites, vaults: this.vaults, rev: this.rev });
  }

  /** Restore the servers from a backup: rev and key epochs legitimately go BACKWARD. Tokens stay valid (users' token epochs are in the copy). */
  restore(snap: ReturnType<FakeServer['snapshot']>): void {
    const c = structuredClone(snap);
    this.users = c.users;
    this.invites = c.invites;
    this.vaults = c.vaults;
    this.rev = c.rev;
  }

  node(url: string): NodeState {
    return this.nodes.get(url)!;
  }

  /** drop-in for global fetch */
  fetch = async (input: string, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(input);
    const node = url.origin;
    const st = this.nodes.get(node);
    if (!st || st.down) throw new TypeError('fetch failed');
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const body = typeof init.body === 'string' && init.body ? JSON.parse(init.body) : undefined;
    this.log.push({ node, method: init.method ?? 'GET', path: url.pathname, headers, query: url.search });
    const r = this.handle(node, init.method ?? 'GET', url.pathname, url.searchParams, headers, body);
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  };

  private usage(v: Vault): number {
    let n = b64len(v.encMeta) + b64len(v.encRoster);
    for (const i of v.items.values()) n += b64len(i.blob) + 128;
    return n;
  }

  /** returns a 422 error if growing `v` by `delta` bytes exceeds a quota (writes that do not grow are always accepted) */
  private quotaCheck(v: Vault | undefined, creator: string, delta: number) {
    if (delta <= 0) return null;
    const vaults = [...this.vaults.values()];
    if ((v ? this.usage(v) : 0) + delta > this.quota.vault) return this.err(422, 'limit_exceeded', 'vault storage quota exceeded');
    const user = vaults.filter((x) => x.creator === creator).reduce((n, x) => n + this.usage(x), 0);
    if (user + delta > this.quota.user) return this.err(422, 'limit_exceeded', 'per-user storage quota exceeded');
    if (vaults.reduce((n, x) => n + this.usage(x), 0) + delta > this.quota.cluster) return this.err(422, 'limit_exceeded', 'household storage quota exceeded');
    return null;
  }

  private err(status: number, code: string, message = code, extra: J = {}) {
    return { status, body: { error: { code, message, ...extra } } };
  }

  private userFromToken(h: Record<string, string>): User | null {
    const m = /^Bearer v1\.([0-9a-f]{32})\.(\d+)\.[0-9a-f]+$/.exec(h['authorization'] ?? '');
    if (!m) return null;
    const u = this.users.get(m[1]!);
    if (!u || u.disabled || u.epoch !== Number(m[2])) return null;
    return u;
  }

  private tokenFor(u: User): J {
    return { token: `v1.${u.id}.${u.epoch}.${randomBytes(8).toString('hex')}`, expires_at: this.clock() + 12 * 3600_000, user_id: u.id, username: u.username, is_admin: u.isAdmin };
  }

  private bump(v?: Vault): number {
    this.rev++;
    if (v) v.rev = this.rev;
    return this.rev;
  }

  handle(node: string, method: string, path: string, q: URLSearchParams, h: Record<string, string>, body: J | undefined): { status: number; body: unknown } {
    const st = this.nodes.get(node)!;
    const stale = q.get('consistency') === 'stale';
    const mutating = method !== 'GET';
    if (path === '/v1/health') return { status: 200, body: { node_id: node, role: st.unavailable ? 'candidate' : 'follower', leader_id: '', term: 1, commit_index: 1, applied_index: 1, initialized: true, has_users: this.users.size > 0, version: 'fake' } };
    if (path === '/v1/cluster') return { status: 200, body: { nodes: [...this.nodes.keys()].map((u, i) => ({ id: `n${i + 1}`, public_url: u })), leader_id: '' } };

    // linearizable operations need a quorum
    const staleOk = stale && ['/v1/prelogin', '/v1/login', '/v1/sync'].includes(path);
    if (st.unavailable && !staleOk) return this.err(503, 'unavailable', 'no quorum', { retry_after_ms: 500 });

    // idempotency
    const user = this.userFromToken(h);
    const idemKey = mutating ? h['idempotency-key'] : undefined;
    const idemId = idemKey ? `${user?.id ?? body?.user_id ?? '-'}:${idemKey}` : undefined;
    if (idemId && this.idem.has(idemId)) return this.idem.get(idemId)!;
    const res = this.route(node, method, path, q, h, body, user, stale);
    if (idemId && res.status < 300) this.idem.set(idemId, res);
    if (mutating && res.status < 300 && this.outcomeUnknownNext > 0) {
      this.outcomeUnknownNext--;
      return this.err(503, 'outcome_unknown', 'not confirmed');
    }
    return res;
  }

  private route(node: string, method: string, path: string, q: URLSearchParams, h: Record<string, string>, body: J | undefined, user: User | null, stale: boolean): { status: number; body: unknown } {
    const ok = (b: unknown) => ({ status: 200, body: JSON.parse(JSON.stringify(b)) });
    const mut = (v?: Vault, version?: number) => ok({ rev: this.bump(v), ...(version !== undefined ? { version: this.rev } : {}) });

    if (method === 'POST' && path === '/v1/prelogin') {
      const u = [...this.users.values()].find((x) => x.username === body?.username);
      const kdf = this.kdfOverride ?? u?.kdf ?? { alg: 'argon2id', salt: createHash('sha256').update('fake' + body?.username).digest().subarray(0, 16).toString('base64'), time: 3, memory_kib: 65536, parallelism: 4 };
      return ok({ kdf });
    }
    if (method === 'POST' && path === '/v1/login') {
      const u = [...this.users.values()].find((x) => x.username === body?.username);
      if (!u || u.disabled || u.loginKey !== body?.login_key) return this.err(401, 'unauthorized', 'invalid credentials');
      return ok(this.tokenFor(u));
    }
    if (method === 'POST' && path === '/v1/register') return this.register(body!);

    if (!user) return this.err(401, 'unauthorized', 'missing or invalid token');

    if (method === 'GET' && path === '/v1/sync') {
      const since = Number(q.get('since') ?? 0);
      if (since && since === this.rev) return ok({ rev: this.rev, unchanged: true, ...(stale ? { stale: true } : {}) });
      return ok(this.syncFor(user, node, stale));
    }
    if (method === 'POST' && path === '/v1/account/password') {
      if (user.loginKey !== body!.current_login_key) return this.err(401, 'unauthorized', 'wrong password');
      if (!this.kdfOk(body!.new_kdf)) return this.err(400, 'bad_request', 'kdf parameters out of bounds');
      user.kdf = body!.new_kdf; user.loginKey = body!.new_login_key; user.wrapped = body!.new_wrapped_account_key; user.epoch++;
      this.bump();
      return ok(this.tokenFor(user));
    }
    if (method === 'POST' && path === '/v1/account/revoke-sessions') {
      user.epoch++;
      this.bump();
      return ok(this.tokenFor(user));
    }
    if (method === 'POST' && path === '/v1/vaults') return this.createVault(user, body!);

    let m: RegExpExecArray | null;
    if ((m = /^\/v1\/vaults\/([0-9a-f]{32})(?:\/(meta|members\/([0-9a-f]{32})|rekey|items\/([0-9a-f]{32})))?$/.exec(path))) {
      const v = this.vaults.get(m[1]!);
      const mem = v?.members.get(user.id);
      if (!v || !mem) return this.err(404, 'not_found');
      const role = mem.role;
      const sub = m[2];
      if (!sub && method === 'DELETE') {
        if (role !== 'owner') return this.err(403, 'forbidden');
        if (v.personal) return this.err(403, 'forbidden', 'personal vault');
        this.vaults.delete(v.id);
        return mut();
      }
      if (sub === 'meta' && method === 'PUT') {
        if (role !== 'owner') return this.err(403, 'forbidden');
        if (body!.base_meta_version !== v.metaVersion) return this.err(409, 'version_conflict', 'meta changed', { current_version: v.metaVersion });
        v.encMeta = body!.enc_meta;
        const r = this.bump(v);
        v.metaVersion = r;
        return ok({ rev: r, version: r });
      }
      if (m[3]) {
        const target = m[3];
        if (method === 'PUT') {
          const bd = body!;
          if (!['owner', 'editor', 'viewer'].includes(bd.role) || !isBox(bd.enc_roster, 16384)) return this.err(400, 'bad_request', 'role and enc_roster required');
          if (bd.wrapped_key && (bd.wrapped_key.sender_id !== user.id || Buffer.from(bd.wrapped_key.blob, 'base64').length !== 105)) return this.err(400, 'bad_request', 'wrapped key');
          if (role !== 'owner') return this.err(403, 'forbidden');
          if (v.personal) return this.err(403, 'forbidden', 'personal vault');
          if (!this.users.has(target)) return this.err(404, 'not_found');
          if (bd.key_epoch !== v.epoch) return this.err(409, 'key_epoch_mismatch');
          const existing = v.members.get(target);
          if (!existing && !bd.wrapped_key) return this.err(400, 'bad_request', 'wrapped_key required');
          if (existing && bd.wrapped_key) return this.err(409, 'already_exists');
          if (existing && existing.role === 'owner' && bd.role !== 'owner' && [...v.members.values()].filter((x) => x.role === 'owner').length === 1) return this.err(403, 'forbidden', 'last owner');
          if (bd.base_roster_version !== v.rosterVersion) return this.err(409, 'version_conflict', 'roster changed', { current_version: v.rosterVersion });
          const q = this.quotaCheck(v, v.creator, b64len(bd.enc_roster) - b64len(v.encRoster));
          if (q) return q;
          if (!existing) v.members.set(target, { role: bd.role, addedBy: user.id, key: bd.wrapped_key });
          else existing.role = bd.role;
          v.encRoster = bd.enc_roster;
          const r = this.bump(v);
          v.rosterVersion = r;
          return ok({ rev: r, version: r });
        }
        if (method === 'DELETE') {
          const self = target === user.id;
          if (role !== 'owner' && !self) return this.err(403, 'forbidden');
          const t = v.members.get(target);
          if (!t) return this.err(404, 'not_found');
          if (t.role === 'owner' && [...v.members.values()].filter((x) => x.role === 'owner').length === 1) return this.err(403, 'forbidden', 'last owner');
          v.members.delete(target);
          v.rekeyRecommended = true;
          return mut(v);
        }
      }
      if (sub === 'rekey' && method === 'POST') {
        const b = body!;
        const remove: string[] = b.remove ?? [];
        if (!isBox(b.enc_meta, 4096) || !isBox(b.enc_roster, 16384)) return this.err(400, 'bad_request', 'enc_meta and enc_roster required');
        for (const w of Object.values<J>(b.wrapped_keys ?? {})) if (w.sender_id !== user.id || Buffer.from(w.blob, 'base64').length !== 105) return this.err(400, 'bad_request', 'wrapped key');
        const iids = (b.items ?? []).map((i: J) => i.id);
        if (new Set(iids).size !== iids.length) return this.err(400, 'bad_request', 'duplicate item');
        if (new Set(remove).size !== remove.length || remove.includes(user.id) || remove.some((x) => !/^[0-9a-f]{32}$/.test(x))) return this.err(400, 'bad_request', 'remove');
        if (role !== 'owner') return this.err(403, 'forbidden');
        if (b.base_rev !== v.rev || b.new_key_epoch !== v.epoch + 1) return this.err(409, 'version_conflict', 'vault changed', { current_version: v.rev });
        if (remove.some((x) => !v.members.has(x))) return this.err(400, 'bad_request', 'remove must be current members');
        if (v.personal && (remove.length || Object.keys(b.wrapped_keys ?? {}).length !== 1)) return this.err(403, 'forbidden', 'personal vault');
        const remaining = [...v.members.keys()].filter((x) => !remove.includes(x)).sort();
        if (JSON.stringify(Object.keys(b.wrapped_keys ?? {}).sort()) !== JSON.stringify(remaining)) return this.err(409, 'version_conflict', 'member set mismatch');
        if (JSON.stringify([...iids].sort()) !== JSON.stringify([...v.items.keys()].sort())) return this.err(409, 'version_conflict', 'item set mismatch');
        let delta = b64len(b.enc_meta) + b64len(b.enc_roster) - b64len(v.encMeta) - b64len(v.encRoster);
        for (const i of b.items) delta += b64len(i.blob) - b64len(v.items.get(i.id)!.blob);
        const q = this.quotaCheck(v, v.creator, delta);
        if (q) return q;
        const r = this.bump(v);
        for (const x of remove) v.members.delete(x);
        v.epoch = b.new_key_epoch;
        v.encMeta = b.enc_meta;
        v.encRoster = b.enc_roster;
        v.metaVersion = r;
        v.rosterVersion = r;
        for (const k of remaining) v.members.get(k)!.key = b.wrapped_keys[k];
        for (const i of b.items) {
          const cur = v.items.get(i.id)!;
          cur.blob = i.blob;
          cur.version = r;
        }
        v.rekeyRecommended = false;
        return ok({ rev: r });
      }
      if (m[4]) {
        const itemId = m[4];
        if (role === 'viewer') return this.err(403, 'forbidden');
        const cur = v.items.get(itemId);
        if (method === 'PUT') {
          if (Buffer.from(body!.blob, 'base64').length > 65536) return this.err(413, 'too_large');
          if (body!.key_epoch !== v.epoch) return this.err(409, 'key_epoch_mismatch');
          const base = body!.base_version;
          if (base === 0 ? !!cur : !cur || cur.version !== base) return this.err(409, 'version_conflict', 'item changed', { current_version: cur?.version ?? 0 });
          const q = this.quotaCheck(v, v.creator, b64len(body!.blob) + 128 - (cur ? b64len(cur.blob) + 128 : 0));
          if (q) return q;
          const r = this.bump(v);
          v.items.set(itemId, { version: r, blob: body!.blob, updatedAt: this.clock(), updatedBy: user.id });
          return ok({ rev: r, version: r });
        }
        if (method === 'DELETE') {
          const base = Number(q.get('base_version'));
          if (!cur || cur.version !== base) return this.err(409, 'version_conflict', 'item changed', { current_version: cur?.version ?? 0 });
          v.items.delete(itemId);
          return mut(v);
        }
      }
    }
    if (path.startsWith('/v1/invites') || path.startsWith('/v1/admin/')) {
      if (!user.isAdmin) return this.err(403, 'forbidden');
      if (method === 'POST' && path === '/v1/invites') {
        const code = randomBytes(20);
        const raw = base32(code);
        const canon = raw;
        const hash = createHash('sha256').update(canon).digest('hex');
        const id = hash.slice(0, 16);
        const ttl = (body?.ttl_hours || 72) * 3600_000;
        this.invites.set(hash, { id, createdBy: user.id, createdAt: this.clock(), expiresAt: this.clock() + ttl });
        this.bump();
        return ok({ invite_id: id, code: raw.match(/.{4}/g)!.join('-'), expires_at: this.clock() + ttl });
      }
      if (method === 'GET' && path === '/v1/invites') {
        return ok({ invites: [...this.invites.values()].map((i) => ({ invite_id: i.id, created_by: i.createdBy, created_at: i.createdAt, expires_at: i.expiresAt, used_by: i.usedBy })) });
      }
      if (method === 'DELETE' && (m = /^\/v1\/invites\/([0-9a-f]{16})$/.exec(path))) {
        for (const [k, i] of this.invites) if (i.id === m[1]) this.invites.delete(k);
        return mut();
      }
      if (method === 'PUT' && (m = /^\/v1\/admin\/users\/([0-9a-f]{32})$/.exec(path))) {
        const t = this.users.get(m[1]!);
        if (!t) return this.err(404, 'not_found');
        if (body!.disabled !== undefined) { t.disabled = body!.disabled; t.epoch++; }
        if (body!.is_admin !== undefined) t.isAdmin = body!.is_admin;
        return mut();
      }
      if (method === 'GET' && path === '/v1/admin/cluster') {
        return ok({ node_id: 'n1', role: 'leader', leader_id: 'n1', term: 1, commit_index: this.rev, applied_index: this.rev, last_log_index: this.rev, snapshot_index: 0, rev: this.rev, peers: [{ id: 'n2', match_index: this.rev, last_contact_ms: 12 }] });
      }
    }
    return this.err(404, 'not_found', 'no such route');
  }

  private kdfOk(k: J): boolean {
    return k?.alg === 'argon2id' && Buffer.from(k.salt ?? '', 'base64').length >= 16 && Buffer.from(k.salt, 'base64').length <= 64 &&
      k.memory_kib >= 65536 && k.memory_kib <= 262144 && k.time >= 3 && k.time <= 8 && k.parallelism >= 1 && k.parallelism <= 16;
  }

  private register(b: J) {
    if (!this.kdfOk(b.kdf)) return this.err(400, 'bad_request', 'kdf parameters out of bounds');
    if (!isBox(b.personal_vault?.enc_roster, 16384)) return this.err(400, 'bad_request', 'enc_roster required');
    const first = this.users.size === 0;
    let invite: [string, any] | undefined;
    if (first) {
      if (b.invite_code !== this.bootstrapToken) return this.err(403, 'invalid_invite');
    } else {
      const canon = String(b.invite_code).replace(/-/g, '').toUpperCase();
      const hash = createHash('sha256').update(canon).digest('hex');
      const inv = this.invites.get(hash);
      if (!inv || inv.usedBy || inv.expiresAt < this.clock()) return this.err(403, 'invalid_invite');
      invite = [hash, inv];
    }
    if ([...this.users.values()].some((u) => u.username === b.username) || this.users.has(b.user_id) || this.vaults.has(b.personal_vault.vault_id)) return this.err(409, 'already_exists');
    if (!/^[a-z0-9][a-z0-9._-]{0,31}$/.test(b.username)) return this.err(400, 'bad_request');
    const u: User = {
      id: b.user_id, username: b.username, kdf: b.kdf, loginKey: b.login_key, publicKey: b.public_key, wrapped: b.wrapped_account_key,
      encPriv: b.enc_private_key, isAdmin: first, disabled: false, epoch: 1, createdAt: this.clock(),
    };
    this.users.set(u.id, u);
    if (invite) invite[1].usedBy = u.id;
    const r = this.createVault(u, b.personal_vault, true);
    if (r.status >= 300) return r;
    return { status: 200, body: this.tokenFor(u) };
  }

  private createVault(user: User, b: J, personal = false) {
    if (!isBox(b.enc_roster, 16384) || !isBox(b.enc_meta, 4096)) return this.err(400, 'bad_request', 'enc_meta and enc_roster required');
    if (this.vaults.has(b.vault_id)) return this.err(409, 'already_exists');
    if (b.wrapped_key.sender_id !== user.id) return this.err(400, 'bad_request');
    const q = this.quotaCheck(undefined, user.id, b64len(b.enc_meta) + b64len(b.enc_roster));
    if (q) return q;
    const rev = this.bump();
    const v: Vault = {
      id: b.vault_id, personal, epoch: 1, encMeta: b.enc_meta, metaVersion: rev, encRoster: b.enc_roster, rosterVersion: rev, creator: user.id, rev, rekeyRecommended: false,
      members: new Map([[user.id, { role: 'owner', addedBy: user.id, key: b.wrapped_key }]]), items: new Map(),
    };
    this.vaults.set(v.id, v);
    return { status: 200, body: { rev, version: rev } };
  }

  private syncFor(u: User, node: string, stale: boolean): J {
    const vaults = [...this.vaults.values()]
      .filter((v) => v.members.has(u.id))
      .sort((a, b) => (a.id < b.id ? -1 : 1))
      .map((v) => ({
        id: v.id, personal: v.personal, key_epoch: v.epoch, enc_meta: v.encMeta, meta_version: v.metaVersion, enc_roster: v.encRoster, roster_version: v.rosterVersion, rev: v.rev,
        rekey_recommended: v.rekeyRecommended, my_role: v.members.get(u.id)!.role, my_key: v.members.get(u.id)!.key,
        members: [...v.members.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([id, m]) => ({ user_id: id, role: m.role, added_by: m.addedBy })),
        items: [...v.items.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([id, i]) => ({ id, version: i.version, blob: i.blob, updated_at: i.updatedAt, updated_by: i.updatedBy })),
      }));
    return {
      rev: this.rev, ...(stale ? { stale: true } : {}), served_by: node,
      account: { user_id: u.id, username: u.username, is_admin: u.isAdmin, kdf: u.kdf, public_key: u.publicKey, wrapped_account_key: u.wrapped, enc_private_key: u.encPriv, created_at: u.createdAt },
      directory: [...this.users.values()].map((x) => ({ user_id: x.id, username: x.username, public_key: x.publicKey, is_admin: x.isAdmin, disabled: x.disabled })),
      vaults,
    };
  }
}

function b64len(s: string): number {
  return Buffer.from(s, 'base64').length;
}
function isBox(s: unknown, max: number): boolean {
  return typeof s === 'string' && b64len(s) >= 41 && b64len(s) <= max;
}

function base32(b: Uint8Array): string {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, val = 0, out = '';
  for (const x of b) {
    val = (val << 8) | x; bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}
