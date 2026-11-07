// Package client is the Go client of Family Vault: a low-level HTTP API client
// with failover (API) and a crypto-aware Session on top of it. All
// cryptography goes through internal/vaultcrypto; nothing here loads code or
// configuration from a server.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// maxNodes bounds the node list: /v1/cluster comes from a server we may not
// fully trust, so it must not be able to grow our list without limit.
const maxNodes = 16

// maxResponse caps what we read from a server (a sync of a full household is
// well below this).
const maxResponse = 256 << 20

// Options configures an API client.
type Options struct {
	// Nodes are base URLs ("https://host:8443"). The first is tried first.
	Nodes []string
	// HTTPClient is used for all requests; nil => NewHTTPClient(HTTPOptions{}).
	HTTPClient *http.Client
	// AllowInsecure permits plain http:// node URLs. It is for local
	// development only: tokens and login keys would cross the network in clear.
	AllowInsecure bool
	// Timeout per HTTP attempt (login/register run an Argon2id on the server).
	// Default 30s.
	Timeout time.Duration
	// MutationRetries is the number of EXTRA passes over all nodes after an
	// ambiguous failure of a mutation (same Idempotency-Key). Default 2.
	MutationRetries int
	// RetryDelay is the base delay between those passes; it doubles each time.
	// Default 400ms.
	RetryDelay time.Duration
	// UnavailableRetry is how long Register, Login and Prelogin keep retrying
	// (with backoff) while the servers answer 503 unavailable, e.g. right after
	// start-up before a leader and the cluster key exist. Default 5s; negative
	// disables.
	UnavailableRetry time.Duration
	// OnNodesChanged is called when the node list changes so it can be persisted.
	OnNodesChanged func(nodes []string)
}

// HTTPOptions configures NewHTTPClient.
type HTTPOptions struct {
	// CAFile is a PEM file with the household CA. When set, it REPLACES the
	// system roots unless WithSystemRoots is also set: a household that runs
	// its own CA should not also trust every public CA for its own servers.
	CAFile          string
	WithSystemRoots bool
	// Transport overrides the base transport (tests wrap it to inject faults).
	// TLS settings are still applied to *http.Transport values.
	Transport http.RoundTripper
}

// NewHTTPClient builds the http.Client used for talking to nodes. It never
// follows redirects (a redirect could move a bearer token to another host) and
// never sends cookies.
func NewHTTPClient(o HTTPOptions) (*http.Client, error) {
	tr := o.Transport
	if tr == nil {
		tr = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
		}
	}
	if o.CAFile != "" {
		pemBytes, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		var pool *x509.CertPool
		if o.WithSystemRoots {
			pool, err = x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
		} else {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificate", o.CAFile)
		}
		ht, ok := tr.(*http.Transport)
		if !ok {
			return nil, errors.New("a CA file cannot be combined with a custom non-HTTP transport")
		}
		ht = ht.Clone()
		ht.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		tr = ht
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// NormalizeNodeURL returns the canonical origin of a node URL.
func NormalizeNodeURL(raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return "", fmt.Errorf("refusing plain http:// server %q: your password-derived login key and session token would cross the network unencrypted (use https, or allow it explicitly for local development with --insecure)", raw)
		}
	default:
		return "", fmt.Errorf("invalid server URL %q (need https://host:port)", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// API is the low-level client: typed methods for every endpoint plus
// failover, idempotent retries and the stale-read fallback. It is safe for
// concurrent use.
type API struct {
	opts Options
	hc   *http.Client

	mu          sync.Mutex
	nodes       []string
	good        int
	token       string
	servedBy    string
	servedStale bool
}

// New creates an API client.
func New(o Options) (*API, error) {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MutationRetries < 0 {
		o.MutationRetries = 0
	} else if o.MutationRetries == 0 {
		o.MutationRetries = 2
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = 400 * time.Millisecond
	}
	if o.UnavailableRetry == 0 {
		o.UnavailableRetry = 5 * time.Second
	}
	a := &API{opts: o, hc: o.HTTPClient}
	if a.hc == nil {
		hc, err := NewHTTPClient(HTTPOptions{})
		if err != nil {
			return nil, err
		}
		a.hc = hc
	}
	for _, n := range o.Nodes {
		u, err := NormalizeNodeURL(n, o.AllowInsecure)
		if err != nil {
			return nil, err
		}
		a.nodes = appendUnique(a.nodes, u)
	}
	if len(a.nodes) == 0 {
		return nil, errors.New("at least one server URL is required")
	}
	return a, nil
}

func appendUnique(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// Nodes returns the current node list.
func (a *API) Nodes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.nodes...)
}

// CurrentNode returns the node that answered last.
func (a *API) CurrentNode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nodes[a.good%len(a.nodes)]
}

// LastServed reports which node served the last successful call and whether
// it was a stale-fallback read.
func (a *API) LastServed() (node string, stale bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.servedBy, a.servedStale
}

// SetToken sets the bearer token (e.g. restored from the token cache).
func (a *API) SetToken(t string) {
	a.mu.Lock()
	a.token = t
	a.mu.Unlock()
}

// Token returns the current bearer token ("" if none).
func (a *API) Token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}

// SetNodes replaces the node list, keeping the current node first if it is
// still present. URLs that are not acceptable (plain http without
// AllowInsecure) are dropped.
func (a *API) SetNodes(urls []string) {
	var norm []string
	for _, u := range urls {
		if n, err := NormalizeNodeURL(u, a.opts.AllowInsecure); err == nil {
			norm = appendUnique(norm, n)
		}
	}
	if len(norm) == 0 {
		return
	}
	if len(norm) > maxNodes {
		norm = norm[:maxNodes]
	}
	a.mu.Lock()
	cur := a.nodes[a.good%len(a.nodes)]
	changed := len(norm) != len(a.nodes)
	if !changed {
		for i := range norm {
			if norm[i] != a.nodes[i] {
				changed = true
			}
		}
	}
	a.nodes = norm
	a.good = 0
	for i, n := range norm {
		if n == cur {
			a.good = i
		}
	}
	cb := a.opts.OnNodesChanged
	out := append([]string(nil), norm...)
	a.mu.Unlock()
	if changed && cb != nil {
		cb(out)
	}
}

// RefreshCluster learns the other nodes from GET /v1/cluster and remembers
// them. Nodes we already know are kept: a lying node must not be able to
// strand us by returning a short list.
func (a *API) RefreshCluster(ctx context.Context) (*api.ClusterResponse, error) {
	c, err := a.Cluster(ctx)
	if err != nil {
		return nil, err
	}
	known := a.Nodes()
	merged := []string{a.CurrentNode()}
	for _, n := range c.Nodes {
		if u, ok := a.acceptLearned(n.PublicURL, merged[0]); ok {
			merged = appendUnique(merged, u)
		}
	}
	for _, n := range known {
		merged = appendUnique(merged, n)
	}
	a.SetNodes(merged)
	return c, nil
}

// acceptLearned decides whether a URL advertised by /v1/cluster may join the
// node list. The list comes from a server we may not fully trust and every
// node we add receives our bearer token, so: it must be a well-formed bare
// origin (no credentials, path or query), https unless the user configured an
// insecure http server, and never a scheme downgrade from the node we are
// talking to.
func (a *API) acceptLearned(raw, current string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	n, err := NormalizeNodeURL(raw, a.opts.AllowInsecure)
	if err != nil {
		return "", false
	}
	if strings.HasPrefix(n, "http://") && !strings.HasPrefix(current, "http://") {
		return "", false
	}
	return n, true
}

// ---------------------------------------------------------------------------
// Idempotency keys
// ---------------------------------------------------------------------------

type idemKey struct{}

// WithIdempotencyKey makes mutations made with the returned context use key
// instead of a fresh one. A caller that retries a logical operation itself
// uses this to keep the key across its own retries.
func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, idemKey{}, key)
}

// NewIdempotencyKey returns a fresh 32-hex key.
func NewIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// Core transport
// ---------------------------------------------------------------------------

type reqOpts struct {
	auth     bool
	mutation bool
	// staleOk allows the consistency=stale fallback (prelogin/login/sync only).
	staleOk bool
	query   url.Values
	timeout time.Duration
}

type failure struct {
	sawUnavailable bool
	sawUnknown     bool
	last           error     // most recent failure of any kind
	lastAPI        *APIError // most recent 5xx answer from a node
}

func (a *API) order() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.nodes)
	out := make([]string, n)
	for i := range out {
		out[i] = a.nodes[(a.good+i)%n]
	}
	return out
}

func (a *API) markGood(node string) {
	a.mu.Lock()
	for i, n := range a.nodes {
		if n == node {
			a.good = i
		}
	}
	a.mu.Unlock()
}

// definitelyNotSent reports whether a transport error happened before any
// request bytes could have reached the server (the connection was never
// established), so even a mutation is certainly not applied.
func definitelyNotSent(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do performs one logical call. Reads and writes go to the last good node
// first, then the others; a network error, timeout or 503 moves on to the
// next node, any other answer is final. A mutation carries the SAME
// Idempotency-Key on every attempt, so a retry after an ambiguous failure is
// applied at most once.
func (a *API) do(ctx context.Context, method, path string, body, out any, o reqOpts) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	hdr := http.Header{}
	if payload != nil {
		hdr.Set("Content-Type", "application/json")
	}
	if o.auth {
		tok := a.Token()
		if tok == "" {
			return &APIError{Status: 401, Code: api.CodeUnauthorized, Message: "not signed in"}
		}
		hdr.Set("Authorization", "Bearer "+tok)
	}
	if o.mutation {
		key, _ := ctx.Value(idemKey{}).(string)
		if key == "" {
			key = NewIdempotencyKey()
		}
		hdr.Set("Idempotency-Key", key)
	}
	if o.timeout <= 0 {
		o.timeout = a.opts.Timeout
	}

	run := func(stale bool) (*failure, error) {
		q := url.Values{}
		for k, v := range o.query {
			q[k] = v
		}
		if stale {
			q.Set("consistency", "stale")
		}
		qs := ""
		if len(q) > 0 {
			qs = "?" + q.Encode()
		}
		f := &failure{}
		for _, node := range a.order() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			status, respBody, err := a.once(ctx, node, method, path+qs, payload, hdr, o.timeout)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if o.mutation && !definitelyNotSent(err) {
					f.sawUnknown = true
				}
				f.last = &NetworkError{Msg: "could not reach " + node + ": " + shortNetErr(err), Err: err}
				continue
			}
			if status >= 200 && status < 300 {
				if out != nil && len(respBody) > 0 {
					if err := json.Unmarshal(respBody, out); err != nil {
						// The server applied it but we cannot read the answer.
						f.sawUnknown = f.sawUnknown || o.mutation
						f.last = &NetworkError{Msg: "the server sent an unreadable response", Err: err}
						continue
					}
				}
				a.markGood(node)
				a.mu.Lock()
				a.servedBy, a.servedStale = node, stale
				a.mu.Unlock()
				return nil, nil
			}
			ae := parseAPIError(status, respBody)
			if status == http.StatusServiceUnavailable || status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
				// Another node may reach the leader.
				if ae.Code == api.CodeOutcomeUnknown || status != http.StatusServiceUnavailable {
					f.sawUnknown = f.sawUnknown || o.mutation
				}
				if ae.Code != api.CodeOutcomeUnknown {
					f.sawUnavailable = true
				}
				f.last, f.lastAPI = ae, ae
				continue
			}
			a.markGood(node)
			return nil, ae
		}
		return f, nil
	}

	f, err := run(false)
	if err != nil {
		return err
	}
	// A mutation whose outcome is unknown is retried with the same key. The
	// "unknown" flag is sticky across passes: a later pass that merely sees
	// "unavailable" proves nothing about an earlier attempt that may have landed.
	sticky := false
	for i := 0; f != nil && o.mutation && (f.sawUnknown || sticky) && i < a.opts.MutationRetries; i++ {
		sticky = sticky || f.sawUnknown
		if err := sleepCtx(ctx, a.opts.RetryDelay<<uint(i)); err != nil {
			return err
		}
		if f, err = run(false); err != nil {
			return err
		}
	}
	if f != nil && f.sawUnknown {
		sticky = true
	}
	// No node could confirm a quorum: accept a stale read from any node that
	// answered "unavailable", but only for the endpoints that allow it.
	if f != nil && o.staleOk && f.sawUnavailable && !o.mutation {
		if f, err = run(true); err != nil {
			return err
		}
	}
	if f == nil {
		return nil
	}
	// A definite answer from some node is more informative than a refused
	// connection to another: prefer it.
	if ae := f.lastAPI; ae != nil {
		if ae.Code == api.CodeOutcomeUnknown || !sticky {
			return ae // unavailable: nothing was changed; outcome_unknown: retry later with the same key
		}
	}
	msg := "could not reach any server"
	if o.mutation && sticky {
		msg = "could not confirm the change with any server; it may or may not have been saved"
	}
	if ae := f.lastAPI; ae != nil {
		return &NetworkError{Msg: msg + " (" + ae.Error() + ")", OutcomeUnknown: o.mutation && sticky, Err: ae}
	}
	var ne *NetworkError
	if errors.As(f.last, &ne) {
		return &NetworkError{Msg: msg + " (" + ne.Msg + ")", OutcomeUnknown: o.mutation && sticky, Err: ne.Err}
	}
	return &NetworkError{Msg: msg, OutcomeUnknown: o.mutation && sticky}
}

func shortNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}

func (a *API) once(ctx context.Context, node, method, pathQuery string, payload []byte, hdr http.Header, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, node+pathQuery, rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fvault")
	res, err := a.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return 0, nil, err
	}
	return res.StatusCode, b, nil
}

func parseAPIError(status int, body []byte) *APIError {
	var eb api.ErrorBody
	if json.Unmarshal(body, &eb) == nil && eb.Error.Code != "" {
		ae := &APIError{Status: status, Code: eb.Error.Code, Message: eb.Error.Message}
		if eb.Error.CurrentVersion != nil {
			ae.CurrentVersion, ae.HasCurrentVersion = *eb.Error.CurrentVersion, true
		}
		if eb.Error.RetryAfterMs > 0 {
			ae.RetryAfter = time.Duration(eb.Error.RetryAfterMs) * time.Millisecond
		}
		return ae
	}
	code := api.CodeInternal
	if status == http.StatusServiceUnavailable || status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
		code = api.CodeUnavailable
	}
	return &APIError{Status: status, Code: code, Message: "server error (" + strconv.Itoa(status) + ")"}
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

// HealthOf probes one specific node without failing over.
func (a *API) HealthOf(ctx context.Context, node string) (*api.HealthResponse, time.Duration, error) {
	t0 := time.Now()
	status, body, err := a.once(ctx, node, http.MethodGet, "/v1/health", nil, http.Header{}, 5*time.Second)
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusOK {
		return nil, 0, parseAPIError(status, body)
	}
	var h api.HealthResponse
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, 0, err
	}
	return &h, time.Since(t0), nil
}

// Health asks any node for its health.
func (a *API) Health(ctx context.Context) (h *api.HealthResponse, err error) {
	h = new(api.HealthResponse)
	return h, a.do(ctx, "GET", "/v1/health", nil, h, reqOpts{})
}

// Cluster returns the node list a server advertises.
func (a *API) Cluster(ctx context.Context) (*api.ClusterResponse, error) {
	c := new(api.ClusterResponse)
	return c, a.do(ctx, "GET", "/v1/cluster", nil, c, reqOpts{})
}

// retryUnavailable repeats fn while it fails with 503 unavailable (nothing was
// changed, so repeating is safe; a mutation keeps its Idempotency-Key through
// ctx) for up to a.opts.UnavailableRetry.
func (a *API) retryUnavailable(ctx context.Context, fn func(context.Context) error) error {
	err := fn(ctx)
	if a.opts.UnavailableRetry < 0 || !IsCode(err, api.CodeUnavailable) {
		return err
	}
	deadline := time.Now().Add(a.opts.UnavailableRetry)
	for d := 200 * time.Millisecond; time.Now().Before(deadline); d *= 2 {
		if serr := sleepCtx(ctx, d); serr != nil {
			return serr
		}
		if err = fn(ctx); !IsCode(err, api.CodeUnavailable) {
			return err
		}
	}
	return err
}

// Prelogin fetches the KDF parameters for a username (stale fallback allowed).
func (a *API) Prelogin(ctx context.Context, username string) (*api.PreloginResponse, error) {
	r := new(api.PreloginResponse)
	return r, a.retryUnavailable(ctx, func(ctx context.Context) error {
		return a.do(ctx, "POST", "/v1/prelogin", api.PreloginRequest{Username: username}, r, reqOpts{staleOk: true})
	})
}

// PreloginLinearizable is Prelogin WITHOUT the stale fallback; it succeeds
// only if a quorum is reachable, which is how `fvault status` tells
// "online" from "stale" without a password.
func (a *API) PreloginLinearizable(ctx context.Context, username string) error {
	return a.do(ctx, "POST", "/v1/prelogin", api.PreloginRequest{Username: username}, new(api.PreloginResponse), reqOpts{})
}

// Register creates an account and stores the returned token.
func (a *API) Register(ctx context.Context, req *api.RegisterRequest) (*api.LoginResponse, error) {
	r := new(api.LoginResponse)
	ctx = WithIdempotencyKey(ctx, NewIdempotencyKey())
	if err := a.retryUnavailable(ctx, func(ctx context.Context) error {
		return a.do(ctx, "POST", "/v1/register", req, r, reqOpts{mutation: true})
	}); err != nil {
		return nil, err
	}
	a.SetToken(r.Token)
	return r, nil
}

// Login exchanges the login key for a token (stale fallback allowed) and
// stores the token.
func (a *API) Login(ctx context.Context, username string, loginKey []byte) (*api.LoginResponse, error) {
	r := new(api.LoginResponse)
	if err := a.retryUnavailable(ctx, func(ctx context.Context) error {
		return a.do(ctx, "POST", "/v1/login", api.LoginRequest{Username: username, LoginKey: loginKey}, r, reqOpts{staleOk: true})
	}); err != nil {
		return nil, err
	}
	a.SetToken(r.Token)
	return r, nil
}

// ---------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------

// Sync fetches the caller's complete visible state. since==0 always returns
// the full state; otherwise a matching rev returns Unchanged.
func (a *API) Sync(ctx context.Context, since uint64) (*api.SyncResponse, error) {
	q := url.Values{}
	if since > 0 {
		q.Set("since", strconv.FormatUint(since, 10))
	}
	r := new(api.SyncResponse)
	return r, a.do(ctx, "GET", "/v1/sync", nil, r, reqOpts{auth: true, staleOk: true, query: q})
}

// ChangePassword changes the password and stores the fresh token.
func (a *API) ChangePassword(ctx context.Context, req *api.ChangePasswordRequest) (*api.LoginResponse, error) {
	r := new(api.LoginResponse)
	if err := a.do(ctx, "POST", "/v1/account/password", req, r, reqOpts{auth: true, mutation: true}); err != nil {
		return nil, err
	}
	a.SetToken(r.Token)
	return r, nil
}

// RevokeSessions revokes all older tokens and stores the fresh one.
func (a *API) RevokeSessions(ctx context.Context) (*api.LoginResponse, error) {
	r := new(api.LoginResponse)
	if err := a.do(ctx, "POST", "/v1/account/revoke-sessions", nil, r, reqOpts{auth: true, mutation: true}); err != nil {
		return nil, err
	}
	a.SetToken(r.Token)
	return r, nil
}

func (a *API) mut(ctx context.Context, method, path string, body any, timeout time.Duration) error {
	return a.do(ctx, method, path, body, new(api.MutationResponse), reqOpts{auth: true, mutation: true, timeout: timeout})
}

func (a *API) CreateVault(ctx context.Context, req *api.CreateVaultRequest) error {
	return a.mut(ctx, "POST", "/v1/vaults", req, 0)
}

func (a *API) UpdateVaultMeta(ctx context.Context, vault string, req *api.UpdateVaultMetaRequest) error {
	return a.mut(ctx, "PUT", "/v1/vaults/"+vault+"/meta", req, 0)
}

func (a *API) DeleteVault(ctx context.Context, vault string) error {
	return a.mut(ctx, "DELETE", "/v1/vaults/"+vault, nil, 0)
}

func (a *API) PutMember(ctx context.Context, vault, user string, req *api.PutMemberRequest) error {
	return a.mut(ctx, "PUT", "/v1/vaults/"+vault+"/members/"+user, req, 0)
}

func (a *API) DeleteMember(ctx context.Context, vault, user string) error {
	return a.mut(ctx, "DELETE", "/v1/vaults/"+vault+"/members/"+user, nil, 0)
}

// Rekey submits an atomic rekey; the body can be up to 32 MiB so it gets a long timeout.
func (a *API) Rekey(ctx context.Context, vault string, req *api.RekeyRequest) error {
	return a.mut(ctx, "POST", "/v1/vaults/"+vault+"/rekey", req, 5*time.Minute)
}

func (a *API) PutItem(ctx context.Context, vault, item string, req *api.PutItemRequest) error {
	return a.mut(ctx, "PUT", "/v1/vaults/"+vault+"/items/"+item, req, 0)
}

func (a *API) DeleteItem(ctx context.Context, vault, item string, baseVersion uint64) error {
	q := url.Values{"base_version": {strconv.FormatUint(baseVersion, 10)}}
	return a.do(ctx, "DELETE", "/v1/vaults/"+vault+"/items/"+item, nil, new(api.MutationResponse), reqOpts{auth: true, mutation: true, query: q})
}

func (a *API) CreateInvite(ctx context.Context, ttlHours int) (*api.CreateInviteResponse, error) {
	r := new(api.CreateInviteResponse)
	return r, a.do(ctx, "POST", "/v1/invites", api.CreateInviteRequest{TTLHours: ttlHours}, r, reqOpts{auth: true, mutation: true})
}

func (a *API) ListInvites(ctx context.Context) (*api.ListInvitesResponse, error) {
	r := new(api.ListInvitesResponse)
	return r, a.do(ctx, "GET", "/v1/invites", nil, r, reqOpts{auth: true})
}

func (a *API) DeleteInvite(ctx context.Context, id string) error {
	return a.mut(ctx, "DELETE", "/v1/invites/"+id, nil, 0)
}

func (a *API) AdminUpdateUser(ctx context.Context, user string, req *api.AdminUpdateUserRequest) error {
	return a.mut(ctx, "PUT", "/v1/admin/users/"+user, req, 0)
}

func (a *API) AdminCluster(ctx context.Context) (*api.AdminClusterResponse, error) {
	r := new(api.AdminClusterResponse)
	return r, a.do(ctx, "GET", "/v1/admin/cluster", nil, r, reqOpts{auth: true})
}

func (a *API) AdminBackup(ctx context.Context) (*api.ServerBackup, error) {
	r := new(api.ServerBackup)
	return r, a.do(ctx, "GET", "/v1/admin/backup", nil, r, reqOpts{auth: true, timeout: 5 * time.Minute})
}

// NodeProbe is the result of probing one node.
type NodeProbe struct {
	URL     string
	OK      bool
	Err     string
	Latency time.Duration
	Health  *api.HealthResponse
}

// ProbeNodes asks every known node for its health, concurrently, without
// failing over (used by `fvault status`).
func (a *API) ProbeNodes(ctx context.Context) []NodeProbe {
	nodes := a.Nodes()
	out := make([]NodeProbe, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, d, err := a.HealthOf(ctx, n)
			out[i] = NodeProbe{URL: n, OK: err == nil, Latency: d, Health: h}
			if err != nil {
				out[i].Err = shortNetErr(err)
			}
		}()
	}
	wg.Wait()
	return out
}
