import { bytesToHex, randomBytes } from '../crypto/encoding.ts';
import { ApiError, NetworkError } from './errors.ts';
import type * as T from './types.ts';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ApiClientOptions {
  /** Node base URLs, e.g. "https://a.example:8443". The first is tried first. */
  nodes: string[];
  fetch?: FetchLike;
  /** Per-request timeout (login/register run an Argon2id on the server). */
  timeoutMs?: number;
  /** Extra passes over all nodes after an ambiguous mutation failure (same Idempotency-Key). Default 2. */
  mutationRetries?: number;
  /** Extra passes while every node answers 503 unavailable, for sign-in/registration only. Default 4 (about 6 s with the default delay). */
  unavailableRetries?: number;
  /** Base delay between those passes; doubles each time. Default 400 ms. */
  retryDelayMs?: number;
  /**
   * Allow plain-http nodes learned from /v1/cluster. Set only when the page
   * itself was loaded over http (development); otherwise learned nodes must be https.
   */
  allowInsecureLearned?: boolean;
  /** Called whenever the node list is learned/changed so callers can persist it. */
  onNodesChanged?: (nodes: string[]) => void;
  /** Called with every outcome so the UI can show "which node is serving". */
  onServed?: (info: ServedInfo) => void;
  /** Called on a 401 for an authenticated request (token expired/revoked). */
  onUnauthorized?: () => void;
}

export interface ServedInfo {
  node: string;
  stale: boolean;
}

export function normalizeNodeUrl(u: string): string | null {
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

export const MAX_NODES = 16;

/**
 * Which URLs a server-supplied node list may add (crypto/threat model: a
 * lying node must not steer the client, and its bearer token, to arbitrary
 * hosts): well-formed http(s) origins only, https unless `allowHttp`, never a
 * downgrade of a host:port already known over https, at most MAX_NODES in
 * total (known nodes first). CSP connect-src is a second line of defence.
 */
export function filterLearnedNodes(known: readonly string[], learned: readonly string[], allowHttp: boolean): string[] {
  const out = [...known];
  const httpsHosts = new Set(known.filter((u) => u.startsWith('https://')).map((u) => u.slice(8)));
  for (const raw of learned) {
    const o = normalizeNodeUrl(raw);
    if (o === null || out.includes(o)) continue;
    const https = o.startsWith('https://');
    if (!https && !allowHttp) continue;
    if (!https && httpsHosts.has(o.slice(7))) continue;
    if (out.length >= MAX_NODES) break;
    out.push(o);
    if (https) httpsHosts.add(o.slice(8));
  }
  return out;
}

export function newIdempotencyKey(): string {
  return bytesToHex(randomBytes(16));
}

interface ReqOpts {
  auth?: boolean;
  /** Mutations get an Idempotency-Key, generated once and reused across every retry/failover. */
  mutation?: boolean;
  idempotencyKey?: string;
  /** Allow falling back to ?consistency=stale when no node can confirm a quorum. */
  staleOk?: boolean;
  /** Retry (with backoff, a few seconds in total) while EVERY node answers 503 unavailable, e.g. right after a server restart. Only for requests where "unavailable" means nothing changed. */
  retryUnavailable?: boolean;
  query?: Record<string, string | number>;
}

export class ApiClient {
  private nodes: string[];
  private good = 0; // index of the last node that answered
  private fetchImpl: FetchLike;
  private timeoutMs: number;
  private opts: ApiClientOptions;
  token: string | null = null;
  /** True if the most recent read was served by the stale fallback. */
  lastStale = false;

  constructor(opts: ApiClientOptions) {
    const nodes = opts.nodes.map(normalizeNodeUrl).filter((x): x is string => x !== null);
    if (nodes.length === 0) throw new Error('at least one valid node URL is required');
    this.nodes = [...new Set(nodes)];
    this.opts = opts;
    this.fetchImpl = opts.fetch ?? ((i, init) => globalThis.fetch(i, init));
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  get nodeUrls(): string[] {
    return [...this.nodes];
  }

  get currentNode(): string {
    return this.nodes[this.good % this.nodes.length]!;
  }

  setNodes(urls: string[]): void {
    const norm = [...new Set(urls.map(normalizeNodeUrl).filter((x): x is string => x !== null))];
    if (norm.length === 0) return;
    const cur = this.currentNode;
    this.nodes = norm;
    const i = norm.indexOf(cur);
    this.good = i >= 0 ? i : 0;
    this.opts.onNodesChanged?.(this.nodeUrls);
  }

  /** Learn every node from the one we can reach and remember them (failover list). */
  async refreshCluster(): Promise<T.ClusterResponse> {
    const c = await this.request<T.ClusterResponse>('GET', '/v1/cluster');
    // Keep the node we are currently talking to and any we already know: a
    // lying node must not be able to strand us by returning an empty list, and
    // CSP connect-src restricts which origins the browser will contact anyway.
    const learned = (c.nodes ?? []).map((n) => (n && typeof n.public_url === 'string' ? n.public_url : ''));
    const merged = filterLearnedNodes(this.nodes, learned, this.opts.allowInsecureLearned === true);
    if (merged.length !== this.nodes.length) this.setNodes(merged);
    return c;
  }

  // -- core transport --------------------------------------------------------

  private order(): string[] {
    const n = this.nodes.length;
    return Array.from({ length: n }, (_, i) => this.nodes[(this.good + i) % n]!);
  }

  private async once(node: string, method: string, path: string, body: unknown, headers: Record<string, string>, query: string): Promise<Response> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(node + path + query, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctl.signal,
        credentials: 'omit', // bearer token only, never cookies
        cache: 'no-store',
      });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Try the last good node first, then the others. A network error or a 503
   * moves on to the next node; any other response is final. Mutations carry
   * the SAME Idempotency-Key on every attempt, so a retry after an ambiguous
   * failure is applied once.
   */
  async request<R>(method: string, path: string, body?: unknown, o: ReqOpts = {}): Promise<R> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (o.auth) {
      if (!this.token) throw new ApiError(401, { code: 'unauthorized', message: 'not signed in' });
      headers['Authorization'] = 'Bearer ' + this.token;
    }
    if (o.mutation) headers['Idempotency-Key'] = o.idempotencyKey ?? newIdempotencyKey();

    // Sticky across passes: a write that may have landed in pass 1 must never be
    // reported as "nothing was changed" because pass 2 only saw plain 503s.
    let everUnknown = false;
    const run = async (stale: boolean): Promise<{ value: R } | { failure: Failure }> => {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(o.query ?? {})) params.set(k, String(v));
      if (stale) params.set('consistency', 'stale');
      const q = params.size ? '?' + params.toString() : '';
      const failure: Failure = { sawUnavailable: false, sawUnknown: everUnknown, last: undefined };
      for (const node of this.order()) {
        let res: Response;
        try {
          res = await this.once(node, method, path, body, headers, q);
        } catch (e) {
          // Network error / timeout: for a mutation we cannot know whether it landed.
          if (o.mutation) failure.sawUnknown = everUnknown = true;
          failure.last = e;
          continue;
        }
        const text = await res.text().catch(() => '');
        if (res.ok) {
          this.good = this.nodes.indexOf(node);
          this.lastStale = stale;
          this.opts.onServed?.({ node, stale });
          if (text === '') return { value: undefined as R };
          try {
            return { value: JSON.parse(text) as R };
          } catch {
            throw new NetworkError('the server sent an unreadable response');
          }
        }
        let err: ApiError;
        try {
          err = new ApiError(res.status, (JSON.parse(text) as T.ErrorBody).error);
        } catch {
          err = new ApiError(res.status, { code: res.status === 503 ? 'unavailable' : 'internal', message: `server error (${res.status})` });
        }
        if (res.status === 503) {
          if (err.code === 'outcome_unknown') failure.sawUnknown = everUnknown = true;
          else failure.sawUnavailable = true;
          failure.last = err;
          continue; // another node may reach the leader
        }
        this.good = this.nodes.indexOf(node);
        if (res.status === 401 && o.auth) this.opts.onUnauthorized?.();
        throw err;
      }
      return { failure };
    };

    let r = await run(false);
    // A mutation whose outcome is unknown (network error / outcome_unknown) is
    // retried with the SAME key: the server applies it at most once.
    const retries = this.opts.mutationRetries ?? 2;
    for (let i = 0; i < retries && 'failure' in r && o.mutation && r.failure.sawUnknown; i++) {
      await new Promise((res) => setTimeout(res, (this.opts.retryDelayMs ?? 400) * 2 ** i));
      r = await run(false);
    }
    // Right after a restart every node may say "unavailable" for a second or two: wait it out for sign-in/registration.
    const upTo = this.opts.unavailableRetries ?? 4;
    for (let i = 0; i < upTo && 'failure' in r && o.retryUnavailable && r.failure.sawUnavailable && !r.failure.sawUnknown; i++) {
      await new Promise((res) => setTimeout(res, (this.opts.retryDelayMs ?? 400) * 2 ** i));
      r = await run(false);
    }
    // Linearizable read impossible (no quorum): accept a stale read from any
    // node that answered "unavailable", but only for endpoints that allow it.
    if ('failure' in r && o.staleOk && r.failure.sawUnavailable && !r.failure.sawUnknown) r = await run(true);
    if ('value' in r) return r.value;

    const f = r.failure;
    if (f.last instanceof ApiError && !f.sawUnknown && !(f.last.code === 'outcome_unknown')) throw f.last; // unavailable: nothing changed
    if (f.last instanceof ApiError && f.last.code === 'outcome_unknown') throw f.last;
    throw new NetworkError(
      o.mutation ? 'could not reach any server; the change may or may not have been saved' : 'could not reach any server',
      o.mutation && f.sawUnknown,
    );
  }

  // -- public endpoints ------------------------------------------------------

  health(node?: string): Promise<T.HealthResponse> {
    if (node) return this.probe(node);
    return this.request('GET', '/v1/health');
  }

  /** One-shot probe of a specific node, never failing over (used for the cluster status view). */
  private async probe(node: string): Promise<T.HealthResponse> {
    const res = await this.once(node, 'GET', '/v1/health', undefined, {}, '');
    if (!res.ok) throw new NetworkError(`node answered ${res.status}`);
    return (await res.json()) as T.HealthResponse;
  }

  async probeNodes(): Promise<{ node: string; ok: boolean; health?: T.HealthResponse; ms: number }[]> {
    return Promise.all(
      this.nodes.map(async (node) => {
        const t0 = Date.now();
        try {
          const health = await this.probe(node);
          return { node, ok: true, health, ms: Date.now() - t0 };
        } catch {
          return { node, ok: false, ms: Date.now() - t0 };
        }
      }),
    );
  }

  cluster = () => this.request<T.ClusterResponse>('GET', '/v1/cluster');
  prelogin = (username: string) => this.request<T.PreloginResponse>('POST', '/v1/prelogin', { username } satisfies T.PreloginRequest, { staleOk: true, retryUnavailable: true });

  /** A request whose answer is a new session: its token becomes the client's token. */
  private async startSession(path: string, body: unknown, opts: Parameters<ApiClient['request']>[3]): Promise<T.LoginResponse> {
    const r = await this.request<T.LoginResponse>('POST', path, body, opts);
    this.token = r.token;
    return r;
  }

  register = (req: T.RegisterRequest) => this.startSession('/v1/register', req, { mutation: true, retryUnavailable: true });
  login = (username: string, loginKeyB64: string) =>
    this.startSession('/v1/login', { username, login_key: loginKeyB64 } satisfies T.LoginRequest, { staleOk: true, retryUnavailable: true });

  // -- authenticated ---------------------------------------------------------

  sync(since?: number): Promise<T.SyncResponse> {
    return this.request('GET', '/v1/sync', undefined, { auth: true, staleOk: true, query: since ? { since } : undefined });
  }

  changePassword = (req: T.ChangePasswordRequest) => this.startSession('/v1/account/password', req, { auth: true, mutation: true });
  revokeSessions = () => this.startSession('/v1/account/revoke-sessions', undefined, { auth: true, mutation: true });

  createVault = (req: T.CreateVaultRequest) => this.request<T.MutationResponse>('POST', '/v1/vaults', req, { auth: true, mutation: true });
  updateVaultMeta = (vault: string, req: T.UpdateVaultMetaRequest) => this.request<T.MutationResponse>('PUT', `/v1/vaults/${vault}/meta`, req, { auth: true, mutation: true });
  deleteVault = (vault: string) => this.request<T.MutationResponse>('DELETE', `/v1/vaults/${vault}`, undefined, { auth: true, mutation: true });
  putMember = (vault: string, user: string, req: T.PutMemberRequest) => this.request<T.MutationResponse>('PUT', `/v1/vaults/${vault}/members/${user}`, req, { auth: true, mutation: true });
  deleteMember = (vault: string, user: string) => this.request<T.MutationResponse>('DELETE', `/v1/vaults/${vault}/members/${user}`, undefined, { auth: true, mutation: true });
  rekey = (vault: string, req: T.RekeyRequest) => this.request<T.MutationResponse>('POST', `/v1/vaults/${vault}/rekey`, req, { auth: true, mutation: true });
  putItem = (vault: string, item: string, req: T.PutItemRequest) => this.request<T.MutationResponse>('PUT', `/v1/vaults/${vault}/items/${item}`, req, { auth: true, mutation: true });
  deleteItem = (vault: string, item: string, baseVersion: number) =>
    this.request<T.MutationResponse>('DELETE', `/v1/vaults/${vault}/items/${item}`, undefined, { auth: true, mutation: true, query: { base_version: baseVersion } });

  createInvite = (ttlHours: number) => this.request<T.CreateInviteResponse>('POST', '/v1/invites', { ttl_hours: ttlHours } satisfies T.CreateInviteRequest, { auth: true, mutation: true });
  listInvites = () => this.request<T.ListInvitesResponse>('GET', '/v1/invites', undefined, { auth: true });
  deleteInvite = (id: string) => this.request<T.MutationResponse>('DELETE', `/v1/invites/${id}`, undefined, { auth: true, mutation: true });
  adminUpdateUser = (user: string, req: T.AdminUpdateUserRequest) => this.request<T.MutationResponse>('PUT', `/v1/admin/users/${user}`, req, { auth: true, mutation: true });
  adminCluster = () => this.request<T.AdminClusterResponse>('GET', '/v1/admin/cluster', undefined, { auth: true });
}

interface Failure {
  sawUnavailable: boolean;
  sawUnknown: boolean;
  last: unknown;
}
