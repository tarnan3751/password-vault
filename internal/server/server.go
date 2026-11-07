// Package server is the client-facing HTTP API of a vault node
// (docs/spec/api.md): authentication, tokens, rate limiting, the mapping of
// requests to replicated commands, linearizable reads, CORS/CSP and the
// embedded web UI.
//
// Security model in brief: every node can verify every token (they are
// HMACs under the replicated cluster key); every write is re-authorized by
// the state machine against the state it executes on; reads are
// linearizable (Raft ReadIndex) unless the client explicitly asks for a
// stale fallback. Secrets that pass through (login keys, tokens, invite
// codes, the bootstrap token, request bodies) are never logged.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
)

// Config configures a Server.
type Config struct {
	NodeID             string
	Raft               raft.Node
	FSM                *fsm.FSM
	Peers              []api.ClusterNode // all nodes incl. self, with public URLs (for /v1/cluster, CORS and CSP)
	BootstrapToken     string            // empty => bootstrap registration disabled on this node
	TokenTTL           time.Duration     // default 12h
	ProposeTimeout     time.Duration     // default 10s
	ReadTimeout        time.Duration     // default 5s (ReadBarrier)
	WebFS              fs.FS             // static web UI root (index.html, assets...). nil => a minimal placeholder page
	TrustedProxyHeader string            // "" => use the socket peer address for rate limiting; else e.g. "X-Forwarded-For"
	Version            string
	Logger             *slog.Logger
	Now                func() time.Time // nil => time.Now (injectable for tests)
	Rand               io.Reader        // nil => crypto/rand

	// TrustedProxies lists the CIDRs (or single addresses) of reverse
	// proxies whose TrustedProxyHeader is believed. Only used when
	// TrustedProxyHeader is set; empty => loopback only (127.0.0.0/8, ::1/128).
	TrustedProxies []string
	// MaxSessionAge bounds how long after the login key was last proven
	// (login, register, password change) a session may be refreshed through
	// revoke-sessions. Default 30 days.
	MaxSessionAge time.Duration
	// StaleReadWindow bounds `consistency=stale`: such reads are refused once
	// this node has not known a leader for longer than this. Default 7 days;
	// negative disables stale reads entirely.
	StaleReadWindow time.Duration
}

// Defaults for the optional durations.
const (
	DefaultTokenTTL        = 12 * time.Hour
	DefaultMaxSessionAge   = 30 * 24 * time.Hour
	DefaultStaleReadWindow = 7 * 24 * time.Hour
)

// MinBootstrapTokenLen is the shortest accepted bootstrap token. Whoever
// presents it first becomes the household admin, so it must not be
// guessable.
const MinBootstrapTokenLen = 16

// Rate limits (api.md §3.4).
const (
	loginFailuresPerUser = 10
	loginFailuresPerIP   = 30
	registerPerIP        = 10
	rateWindow           = 5 * time.Minute
	maxTrackedKeys       = 10000
)

// Server serves the client API of one node.
type Server struct {
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	rand    io.Reader
	api     *http.ServeMux
	handler http.Handler

	origins map[string]bool
	csp     string

	bootstrapHash []byte // SHA-256 of the bootstrap token; nil if disabled
	argonSem      chan struct{}
	argonWait     time.Duration
	dummy         fsm.Verifier // verified against for unknown users, so timing does not reveal existence

	limLoginUser *limiter
	limLoginIP   *limiter
	limRegister  *limiter

	trustedProxies []netip.Prefix
	lastLeader     atomic.Int64 // UnixNano of the last time this node knew a leader

	webMu    sync.Mutex
	webFiles map[string]*staticFile // prepared files of WebFS, by name

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	startOnce sync.Once
	closeOnce sync.Once
}

// New validates cfg and builds a Server. Call Start to begin background
// work and Handler to serve requests.
func New(cfg Config) (*Server, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("server: NodeID is required")
	}
	if cfg.Raft == nil || cfg.FSM == nil {
		return nil, errors.New("server: Raft and FSM are required")
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = DefaultTokenTTL
	}
	if cfg.MaxSessionAge <= 0 {
		cfg.MaxSessionAge = DefaultMaxSessionAge
	}
	if cfg.StaleReadWindow == 0 {
		cfg.StaleReadWindow = DefaultStaleReadWindow
	}
	if cfg.ProposeTimeout <= 0 {
		cfg.ProposeTimeout = 10 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	s := &Server{
		cfg:          cfg,
		log:          cfg.Logger.With("node", cfg.NodeID),
		now:          cfg.Now,
		rand:         &lockedReader{r: cfg.Rand},
		origins:      map[string]bool{},
		webFiles:     map[string]*staticFile{},
		argonSem:     make(chan struct{}, argonSlots),
		argonWait:    argonQueueWait,
		limLoginUser: newLimiter(loginFailuresPerUser, rateWindow, maxTrackedKeys),
		limLoginIP:   newLimiter(loginFailuresPerIP, rateWindow, maxTrackedKeys),
		limRegister:  newLimiter(registerPerIP, rateWindow, maxTrackedKeys),
	}
	s.cfg.Peers = append([]api.ClusterNode(nil), cfg.Peers...)
	proxies := cfg.TrustedProxies
	if cfg.TrustedProxyHeader != "" && len(proxies) == 0 {
		proxies = []string{"127.0.0.0/8", "::1/128"}
	}
	for _, p := range proxies {
		pfx, err := parsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("server: trusted proxy %q: %w", p, err)
		}
		s.trustedProxies = append(s.trustedProxies, pfx)
	}
	s.cfg.TrustedProxies = append([]string(nil), cfg.TrustedProxies...)
	s.lastLeader.Store(cfg.Now().UnixNano())
	var connect []string
	for _, p := range s.cfg.Peers {
		o, err := originOf(p.PublicURL)
		if err != nil {
			return nil, fmt.Errorf("server: peer %q: %w", p.ID, err)
		}
		if !s.origins[o] {
			s.origins[o] = true
			connect = append(connect, o)
		}
	}
	s.csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; " +
		"connect-src " + strings.Join(append([]string{"'self'"}, connect...), " ") +
		"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
	if cfg.BootstrapToken != "" {
		if len(cfg.BootstrapToken) < MinBootstrapTokenLen {
			return nil, fmt.Errorf("server: bootstrap token must be at least %d characters", MinBootstrapTokenLen)
		}
		h := sha256.Sum256([]byte(cfg.BootstrapToken))
		s.bootstrapHash = h[:]
		s.cfg.BootstrapToken = "" // keep only the hash in memory
	}
	salt, err := s.randomBytes(fsm.VerifierSaltBytes)
	if err != nil {
		return nil, fmt.Errorf("server: random: %w", err)
	}
	hash, err := s.randomBytes(fsm.VerifierHashBytes)
	if err != nil {
		return nil, fmt.Errorf("server: random: %w", err)
	}
	s.dummy = verifierParams(salt)
	s.dummy.Hash = hash
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.routes()
	s.handler = s.middleware(http.HandlerFunc(s.route))
	return s, nil
}

// originOf returns the ASCII serialization of a URL's origin as browsers
// send it in the Origin header (lower-case scheme and host, default port
// omitted).
func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("public_url %q must be an absolute http(s) URL", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// Handler returns the HTTP handler for the client listener.
func (s *Server) Handler() http.Handler { return s.handler }

// Start launches background work: making sure the cluster key exists, and
// garbage-collecting rate-limiter state. It is safe to call more than once.
func (s *Server) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(3)
		go s.initLoop()
		go s.gcLoop()
		go s.leaderLoop()
	})
}

// Close stops background work. In-flight requests are not affected.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.wg.Wait()
	})
	return nil
}

// initLoop proposes `init` with a fresh random key whenever the local state
// is uninitialized. Several nodes may race; the state machine keeps the
// first key applied and ignores the rest, so this is harmless.
func (s *Server) initLoop() {
	defer s.wg.Done()
	backoff := 100 * time.Millisecond
	for {
		wait := time.Second
		if !s.cfg.FSM.Initialized() {
			if err := s.proposeInit(); err != nil {
				s.log.Debug("cluster key initialization pending", "err", err.Error())
				wait = backoff
				backoff = min(backoff*2, 5*time.Second)
			} else {
				backoff = 100 * time.Millisecond
			}
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Server) proposeInit() error {
	key, err := s.randomBytes(fsm.ClusterKeyBytes)
	if err != nil {
		return err
	}
	reqID, err := s.randomHex(16)
	if err != nil {
		return err
	}
	cmd, err := fsm.EncodeCommand(reqID, s.now().UnixMilli(), "", 0, &fsm.InitArgs{ClusterKey: key})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ProposeTimeout)
	defer cancel()
	_, err = s.cfg.Raft.Propose(ctx, cmd)
	return err
}

// leaderLoop samples whether this node knows a leader, to bound how long a
// node cut off from the cluster keeps serving stale reads.
func (s *Server) leaderLoop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		s.sampleLeader()
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) sampleLeader() {
	if s.cfg.Raft.Status().LeaderID != "" {
		s.lastLeader.Store(s.now().UnixNano())
	}
}

// staleAllowed reports whether a `consistency=stale` read may be served.
// Stale reads exist so that a lone surviving node stays readable; but a
// node cut off from the cluster would otherwise keep honouring passwords
// and sessions revoked elsewhere forever, so the window is bounded.
func (s *Server) staleAllowed() *apiError {
	if s.cfg.StaleReadWindow < 0 {
		return errUnavailable("stale reads are disabled on this node")
	}
	s.sampleLeader()
	last := time.Unix(0, s.lastLeader.Load())
	if s.now().Sub(last) > s.cfg.StaleReadWindow {
		return errUnavailable("stale read window has elapsed: this node has not seen a cluster leader for longer than " +
			s.cfg.StaleReadWindow.String())
	}
	return nil
}

func (s *Server) gcLoop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			now := s.now()
			s.limLoginUser.gc(now)
			s.limLoginIP.gc(now)
			s.limRegister.gc(now)
		}
	}
}

// BuildBackup waits for a linearizable read point and dumps the replicated
// state. The cluster key is deliberately omitted (see fsm.BackupSnapshot):
// a backup file must not be usable to forge sessions.
func (s *Server) BuildBackup(ctx context.Context) (*api.ServerBackup, error) {
	rctx, cancel := context.WithTimeout(ctx, s.cfg.ReadTimeout)
	defer cancel()
	if err := s.cfg.Raft.ReadBarrier(rctx); err != nil {
		return nil, fmt.Errorf("server: read barrier: %w", err)
	}
	return s.buildBackup()
}

func (s *Server) buildBackup() (*api.ServerBackup, error) {
	state, rev, err := s.cfg.FSM.BackupSnapshot()
	if err != nil {
		return nil, err
	}
	return &api.ServerBackup{
		Format: "fpv-server-backup", Version: 1, CreatedAt: s.now().UnixMilli(),
		NodeID: s.cfg.NodeID, Rev: rev, State: state,
	}, nil
}

func (s *Server) randomHex(n int) (string, error) {
	b, err := s.randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) isBootstrapToken(code string) bool {
	if s.bootstrapHash == nil {
		return false
	}
	// Comparing fixed-size digests keeps the comparison constant-time and
	// independent of the token's length.
	h := sha256.Sum256([]byte(code))
	return subtle.ConstantTimeCompare(h[:], s.bootstrapHash) == 1
}

// ---------------------------------------------------------------------------
// Routing and middleware
// ---------------------------------------------------------------------------

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/health", s.handleHealth)
	m.HandleFunc("GET /v1/cluster", s.handleCluster)
	m.HandleFunc("POST /v1/prelogin", s.handlePrelogin)
	m.HandleFunc("POST /v1/register", s.handleRegister)
	m.HandleFunc("POST /v1/login", s.handleLogin)
	m.HandleFunc("GET /v1/sync", s.handleSync)
	m.HandleFunc("POST /v1/account/password", s.handleChangePassword)
	m.HandleFunc("POST /v1/account/revoke-sessions", s.handleRevokeSessions)
	m.HandleFunc("POST /v1/vaults", s.handleCreateVault)
	m.HandleFunc("PUT /v1/vaults/{vault}/meta", s.handleUpdateVaultMeta)
	m.HandleFunc("DELETE /v1/vaults/{vault}", s.handleDeleteVault)
	m.HandleFunc("PUT /v1/vaults/{vault}/members/{user}", s.handlePutMember)
	m.HandleFunc("DELETE /v1/vaults/{vault}/members/{user}", s.handleRemoveMember)
	m.HandleFunc("POST /v1/vaults/{vault}/rekey", s.handleRekey)
	m.HandleFunc("PUT /v1/vaults/{vault}/items/{item}", s.handlePutItem)
	m.HandleFunc("DELETE /v1/vaults/{vault}/items/{item}", s.handleDeleteItem)
	m.HandleFunc("POST /v1/invites", s.handleCreateInvite)
	m.HandleFunc("GET /v1/invites", s.handleListInvites)
	m.HandleFunc("DELETE /v1/invites/{invite_id}", s.handleRevokeInvite)
	m.HandleFunc("PUT /v1/admin/users/{user}", s.handleAdminUpdateUser)
	m.HandleFunc("GET /v1/admin/cluster", s.handleAdminCluster)
	m.HandleFunc("GET /v1/admin/backup", s.handleAdminBackup)
	s.api = m
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w, r)
	if p := r.URL.Path; p == "/v1" || strings.HasPrefix(p, "/v1/") {
		s.serveAPI(w, r)
		return
	}
	r.Pattern = "static"
	s.serveStatic(w, r)
}

const corsAllowMethods = "GET, POST, PUT, DELETE, OPTIONS"

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	allowed := origin != "" && s.origins[origin]
	if allowed {
		// Exact-match allow-list, no credentials: bearer tokens are sent
		// explicitly, so there are no ambient credentials to protect, and a
		// page from any other origin simply cannot read responses.
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Expose-Headers", "Retry-After, X-Request-Id")
	}
	if r.Method == http.MethodOptions {
		r.Pattern = "OPTIONS /v1/"
		switch {
		case origin == "":
			h.Set("Allow", corsAllowMethods)
			w.WriteHeader(http.StatusNoContent)
		case !allowed:
			s.fail(w, errForbidden("origin not allowed"))
		default:
			h.Set("Access-Control-Allow-Methods", corsAllowMethods)
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if path.Clean(r.URL.Path) != r.URL.Path {
		r.Pattern = "unmatched"
		s.fail(w, errNotFound("no such endpoint"))
		return
	}
	if _, pattern := s.api.Handler(r); pattern == "" {
		r.Pattern = "unmatched"
		if allow := s.allowedMethods(r); len(allow) > 0 {
			h.Set("Allow", strings.Join(allow, ", "))
			s.fail(w, newAPIError(http.StatusMethodNotAllowed, api.CodeBadRequest, "method not allowed"))
			return
		}
		s.fail(w, errNotFound("no such endpoint"))
		return
	}
	s.api.ServeHTTP(w, r)
}

func (s *Server) allowedMethods(r *http.Request) []string {
	var out []string
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		c := r.WithContext(r.Context())
		c.Method = m
		if _, p := s.api.Handler(c); p != "" {
			out = append(out, m)
		}
	}
	return out
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// middleware assigns a request id, recovers from panics and writes one log
// line per request. The line deliberately contains only the method, the
// route PATTERN (never the raw path or query), status, duration, node and
// request id: no headers, bodies, tokens or ids from the URL.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := fmt.Sprintf("%016x", mrand.Uint64())
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.Header().Set("X-Request-Id", rid)
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				s.log.Error("handler panic", "req_id", rid, "pattern", r.Pattern, "panic_type", fmt.Sprintf("%T", p))
				if !rec.wrote {
					s.fail(rec, errInternal())
				}
			}
			pattern := r.Pattern
			if pattern == "" {
				pattern = "unmatched"
			}
			s.log.Info("request", "method", r.Method, "pattern", pattern, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "req_id", rid)
		}()
		next.ServeHTTP(rec, r)
	})
}

// ---------------------------------------------------------------------------
// Consensus helpers
// ---------------------------------------------------------------------------

// barrier makes the next local read linearizable.
func (s *Server) barrier(ctx context.Context) *apiError {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ReadTimeout)
	defer cancel()
	if err := s.cfg.Raft.ReadBarrier(ctx); err != nil {
		s.log.Debug("read barrier failed", "err", err.Error())
		return errUnavailable("cannot confirm the latest state (no quorum)")
	}
	return nil
}

const (
	proposeBackoffMin = 20 * time.Millisecond
	proposeBackoffMax = 500 * time.Millisecond
)

// propose submits cmd and retries THE SAME BYTES on ErrNoLeader and
// ErrUnknownOutcome until ProposeTimeout. Re-proposing is safe because the
// state machine de-duplicates by (caller, req_id): if an earlier attempt
// did commit, the retry is answered with that attempt's result.
// Final failure is `unavailable` only if every attempt certainly did not
// reach a log; otherwise the outcome is unknown.
func (s *Server) propose(ctx context.Context, cmd []byte) ([]byte, *apiError) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ProposeTimeout)
	defer cancel()
	certainlyNotApplied := true
	delay := proposeBackoffMin
	for {
		res, err := s.cfg.Raft.Propose(ctx, cmd)
		if err == nil {
			return res, nil
		}
		stopped := errors.Is(err, raft.ErrStopped)
		if !errors.Is(err, raft.ErrNoLeader) && !(stopped && !errors.Is(err, raft.ErrUnknownOutcome)) {
			certainlyNotApplied = false
		}
		s.log.Debug("propose attempt failed", "err", err.Error())
		if stopped {
			break
		}
		wait := delay/2 + time.Duration(mrand.Int64N(int64(delay/2)+1))
		delay = min(delay*2, proposeBackoffMax)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	if certainlyNotApplied {
		return nil, errUnavailable("no leader or quorum; nothing was changed")
	}
	return nil, errOutcomeUnknown()
}

func outcomeOf(res []byte) (*fsm.Outcome, *apiError) {
	r, err := fsm.DecodeResult(res)
	if err != nil {
		return nil, errInternal()
	}
	if r.Err != nil {
		return nil, fromFSM(r.Err)
	}
	return r.OK, nil
}

// idempotencyKey returns the request's req_id: the client's Idempotency-Key
// if given (explicit=true), otherwise a fresh random one.
func (s *Server) idempotencyKey(r *http.Request) (reqID string, explicit bool, ae *apiError) {
	vals := r.Header.Values("Idempotency-Key")
	if len(vals) == 0 {
		id, err := s.randomHex(16)
		if err != nil {
			return "", false, errInternal()
		}
		return id, false, nil
	}
	if len(vals) > 1 {
		return "", false, errBadRequest("multiple Idempotency-Key headers")
	}
	v := strings.ToLower(strings.TrimSpace(vals[0]))
	if !fsm.ValidID(v) {
		return "", false, errBadRequest("Idempotency-Key must be 32 hex characters")
	}
	return v, true, nil
}

// submit validates args, then proposes them on behalf of p (nil for
// anonymous commands) and returns the outcome.
func (s *Server) submit(r *http.Request, p *principal, args fsm.Args) (*fsm.Outcome, *apiError) {
	reqID, explicit, ae := s.idempotencyKey(r)
	if ae != nil {
		return nil, ae
	}
	return s.submitWithID(r, p, args, reqID, explicit)
}

func (s *Server) submitWithID(r *http.Request, p *principal, args fsm.Args, reqID string, explicit bool) (*fsm.Outcome, *apiError) {
	uid, ep := "", uint64(0)
	if p != nil {
		uid, ep = p.uid, p.ep
	}
	if e := args.Validate(uid); e != nil {
		return nil, fromFSM(e)
	}
	cmd, err := fsm.EncodeCommand(reqID, s.now().UnixMilli(), uid, ep, args)
	if err != nil {
		return nil, errInternal()
	}
	if p != nil && s.revokedLocally(*p) {
		// The token is certainly stale. If this is the retry of a request
		// that itself revoked it (password change, revoke-sessions,
		// disabling oneself), answer with the recorded result, as the
		// idempotency contract promises; anything else is unauthorized.
		if explicit {
			if res, ok := s.cfg.FSM.CachedResult(cmd); ok {
				return outcomeOf(res)
			}
		}
		return nil, errUnauthorized("session is no longer valid")
	}
	res, ae := s.propose(r.Context(), cmd)
	if ae != nil {
		return nil, ae
	}
	return outcomeOf(res)
}

// authenticate verifies the bearer token's MAC and expiry. State-dependent
// checks (epoch, disabled) happen against the replicated state: after the
// read barrier for reads, at apply time for writes.
func (s *Server) authenticate(r *http.Request) (principal, *apiError) {
	h := r.Header.Get("Authorization")
	const scheme = "bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return principal{}, errUnauthorized("missing bearer token")
	}
	key := s.cfg.FSM.ClusterKey()
	if key == nil {
		// Some node minted this token, so the cluster is initialized and this
		// node is lagging. 401 would make the client throw away a good token;
		// 503 makes it fail over.
		return principal{}, errUnavailable("this node has not caught up with the cluster yet")
	}
	c, err := parseToken(key, strings.TrimSpace(h[len(scheme):]), s.now(), s.cfg.MaxSessionAge)
	if err != nil {
		return principal{}, errUnauthorized("invalid or expired token")
	}
	return principal{uid: c.UID, ep: c.Ep, at: c.At}, nil
}

// revokedLocally is the fast pre-proposal check for writes. Epochs only
// grow, so a token older than the local epoch is certainly revoked. A token
// NEWER than the local view (or for a user the node has not seen yet) only
// means this node lags; the state machine decides.
func (s *Server) revokedLocally(p principal) bool {
	u, ok := s.cfg.FSM.LookupUserByID(p.uid)
	return ok && p.ep < u.TokenEpoch
}

// sessionOK is the authoritative check against a (linearizable) view.
func sessionOK(v *fsm.View, p principal) (fsm.UserAuth, bool) {
	u, ok := v.UserByID(p.uid)
	if !ok || u.Disabled || u.TokenEpoch != p.ep {
		return fsm.UserAuth{}, false
	}
	return u, true
}

// issueToken mints a session token for the given account state. authAt is
// when the login key was last proven (now, except for revoke-sessions); the
// token never outlives authAt + MaxSessionAge.
func (s *Server) issueToken(uid, username string, isAdmin bool, ep uint64, authAt int64) (*api.LoginResponse, *apiError) {
	key := s.cfg.FSM.ClusterKey()
	if key == nil {
		return nil, errUnavailable("cluster is not initialized yet")
	}
	now := s.now()
	exp := min(now.Add(s.cfg.TokenTTL).Unix(), authAt+int64(s.cfg.MaxSessionAge/time.Second))
	if exp <= now.Unix() {
		return nil, errUnauthorized("session is too old; log in again")
	}
	tok := mintToken(key, tokenClaims{UID: uid, Ep: ep, Iat: now.Unix(), Exp: exp, At: authAt})
	return &api.LoginResponse{Token: tok, ExpiresAt: exp * 1000, UserID: uid, Username: username, IsAdmin: isAdmin}, nil
}
