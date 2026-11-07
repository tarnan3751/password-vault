package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// fastKDF is the cheapest set of parameters the client accepts (64 MiB, t=3)
// with p=1 instead of the default p=4. The production default is exercised by
// TestDefaultKDF and by the cmd/fvault black-box tests.
func fastKDF() api.KDFParams {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return api.KDFParams{Alg: vaultcrypto.KDFAlgArgon2id, Salt: salt, Time: vaultcrypto.MinTime, MemoryKiB: vaultcrypto.MinMemoryKiB, Parallelism: 1}
}

// device is one "installation": its own state dir, API client and deps.
type device struct {
	t     *testing.T
	store *Store
	api   *API
	deps  Deps
}

type deviceOpt func(*deviceCfg)

type deviceCfg struct {
	rt      http.RoundTripper
	nodes   []string
	delay   time.Duration
	retries int
}

func withTransport(rt http.RoundTripper) deviceOpt { return func(c *deviceCfg) { c.rt = rt } }
func withNodes(n ...string) deviceOpt              { return func(c *deviceCfg) { c.nodes = n } }

func newDevice(t *testing.T, cl *clienttest.Cluster, opts ...deviceOpt) *device {
	t.Helper()
	curT = t
	cfg := &deviceCfg{nodes: cl.URLs()[:1], delay: 5 * time.Millisecond, retries: 3}
	for _, o := range opts {
		o(cfg)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "home"))
	if err != nil {
		t.Fatal(err)
	}
	hc, err := NewHTTPClient(HTTPOptions{Transport: cfg.rt})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Options{Nodes: cfg.nodes, HTTPClient: hc, AllowInsecure: true, RetryDelay: cfg.delay, MutationRetries: cfg.retries,
		OnNodesChanged: func(n []string) {
			_ = store.UpdateConfig(func(c *Config) { c.Servers = n })
		}})
	if err != nil {
		t.Fatal(err)
	}
	return &device{t: t, store: store, api: a, deps: Deps{API: a, Store: store, CacheToken: true, KDF: fastKDF}}
}

func (d *device) register(user, pw, code string) *Session {
	d.t.Helper()
	s, err := Register(context.Background(), d.deps, RegisterParams{Username: user, Password: pw, InviteCode: code})
	if err != nil {
		d.t.Fatalf("register %s: %v", user, err)
	}
	return s
}

func (d *device) login(user, pw string) *Session {
	d.t.Helper()
	s, err := Login(context.Background(), d.deps, user, pw)
	if err != nil {
		d.t.Fatalf("login %s: %v", user, err)
	}
	return s
}

// fresh returns a second device (own state dir and API client) of the same cluster.
func (d *device) fresh(cl *clienttest.Cluster, opts ...deviceOpt) *device {
	return newDevice(d.t, cl, opts...)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// curT is the running test (tests in this package are not parallel); mv lets
// multi-value calls be wrapped: mv(f()).
var curT *testing.T

func mv[T any](v T, err error) T {
	curT.Helper()
	if err != nil {
		curT.Fatal(err)
	}
	return v
}

func loginItem(name string) *vaultcrypto.Item {
	return &vaultcrypto.Item{V: 1, Type: vaultcrypto.ItemTypeLogin, Name: name}
}

func (s *Session) item(t *testing.T, vaultID, itemID string) *vaultcrypto.Item {
	t.Helper()
	v := s.Vault(vaultID)
	if v == nil {
		t.Fatalf("vault %s not visible", vaultID)
	}
	for _, it := range v.Items {
		if it.ID == itemID {
			if it.Item == nil {
				t.Fatalf("item %s undecryptable", itemID)
			}
			return it.Item
		}
	}
	t.Fatalf("item %s not in vault", itemID)
	return nil
}

func personalVault(t *testing.T, s *Session) *VaultView {
	t.Helper()
	for _, v := range s.Vaults() {
		if v.Personal {
			return v
		}
	}
	t.Fatal("no personal vault")
	return nil
}

// faultRT wraps a transport with test hooks.
type faultRT struct {
	base http.RoundTripper
	// dropResponse, if it returns true for a request, performs the request for
	// real and then returns an error instead of the response (the write landed
	// but the client never learns).
	dropResponse func(*http.Request) bool
	// rewrite may change a response body.
	rewrite func(*http.Request, *http.Response) (*http.Response, error)
	calls   atomic.Int64
	// writes counts requests that could change server state (everything except
	// GET, prelogin and login): "nothing was written" assertions use it.
	writes atomic.Int64
	// logins counts POST /v1/login requests.
	logins atomic.Int64
}

func (f *faultRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls.Add(1)
	if r.URL.Path == "/v1/login" {
		f.logins.Add(1)
	}
	if r.Method != http.MethodGet && r.URL.Path != "/v1/prelogin" && r.URL.Path != "/v1/login" {
		f.writes.Add(1)
	}
	base := f.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if f.dropResponse != nil && f.dropResponse(r) {
		resp.Body.Close()
		return nil, fmt.Errorf("injected: connection reset while reading response")
	}
	if f.rewrite != nil {
		return f.rewrite(r, resp)
	}
	return resp, nil
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(s string, subs ...string) string {
	for _, x := range subs {
		if x != "" && strings.Contains(s, x) {
			return x
		}
	}
	return ""
}

// hostile rewrites sync responses (and nothing else) with a function that can
// be swapped at any time, to play a lying server against the real one.
type hostile struct {
	faultRT
	mu sync.Mutex
	fn func(*api.SyncResponse)
	// prelogin, if set, rewrites prelogin answers.
	pre func(*api.PreloginResponse)
}

func newHostile() *hostile {
	h := &hostile{}
	h.rewrite = h.doRewrite
	return h
}

func (h *hostile) set(fn func(*api.SyncResponse)) {
	h.mu.Lock()
	h.fn = fn
	h.mu.Unlock()
}

func (h *hostile) setPre(fn func(*api.PreloginResponse)) {
	h.mu.Lock()
	h.pre = fn
	h.mu.Unlock()
}

func (h *hostile) doRewrite(r *http.Request, resp *http.Response) (*http.Response, error) {
	h.mu.Lock()
	fn, pre := h.fn, h.pre
	h.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/sync" && fn != nil:
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var sr api.SyncResponse
		if json.Unmarshal(body, &sr) != nil || sr.Unchanged || sr.Account == nil {
			return replaceBody(resp, body), nil
		}
		fn(&sr)
		nb, _ := json.Marshal(sr)
		return replaceBody(resp, nb), nil
	case r.URL.Path == "/v1/prelogin" && pre != nil:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var pr api.PreloginResponse
		if json.Unmarshal(body, &pr) != nil {
			return replaceBody(resp, body), nil
		}
		pre(&pr)
		nb, _ := json.Marshal(pr)
		return replaceBody(resp, nb), nil
	}
	return resp, nil
}

func replaceBody(resp *http.Response, b []byte) *http.Response {
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Del("Content-Length")
	return resp
}

func findVault(r *api.SyncResponse, id string) *api.Vault {
	for i := range r.Vaults {
		if r.Vaults[i].ID == id {
			return &r.Vaults[i]
		}
	}
	return nil
}

// verifyBy marks `other` as verified on s by comparing fingerprints, the way a
// person would.
func (s *Session) verifyUser(t *testing.T, name string) *UserInfo {
	t.Helper()
	u, err := s.ResolveUser(name)
	must(t, err)
	must(t, s.MarkVerified(u.UserID))
	return mv(s.ResolveUser(name))
}
