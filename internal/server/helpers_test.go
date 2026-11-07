package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
)

// ---------------------------------------------------------------------------
// Fake raft.Node
// ---------------------------------------------------------------------------

type stepKind int

const (
	stepOK           stepKind = iota // apply and return the result
	stepNoLeader                     // ErrNoLeader, not applied
	stepUnknown                      // ErrUnknownOutcome, not applied
	stepApplyUnknown                 // applied, but report ErrUnknownOutcome
	stepStopped                      // ErrStopped with nothing in flight
	stepForge                        // not applied; return step.result as the apply result
)

type step struct {
	kind   stepKind
	delay  time.Duration
	result []byte
}

// fakeNode applies proposals straight to the state machine. A script of
// steps (consumed one per Propose call) injects failures; when the script
// is empty, `fallback` is used.
type fakeNode struct {
	mu         sync.Mutex
	applyMu    sync.Mutex
	sm         *fsm.FSM
	index      uint64
	script     []step
	fallback   step
	proposals  int
	applies    int
	barrierErr error
	barriers   int
	onBarrier  func() // run (once) inside the next ReadBarrier
	onPropose  func() // run (once) at the start of the next Propose
	status     raft.Status
}

func newFakeNode(sm *fsm.FSM) *fakeNode {
	return &fakeNode{sm: sm, status: raft.Status{ID: "n1", Role: raft.Leader, LeaderID: "n1", Term: 3, CommitIndex: 10, LastApplied: 10}}
}

func (n *fakeNode) push(steps ...step) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.script = append(n.script, steps...)
}

func (n *fakeNode) setFallback(s step) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.fallback = s
}

func (n *fakeNode) setBarrierErr(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.barrierErr = err
}

func (n *fakeNode) counts() (proposals, applies, barriers int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.proposals, n.applies, n.barriers
}

func (n *fakeNode) apply(cmd []byte) []byte {
	n.applyMu.Lock()
	defer n.applyMu.Unlock()
	n.mu.Lock()
	n.index++
	idx := n.index
	n.applies++
	n.mu.Unlock()
	return n.sm.Apply(idx, cmd)
}

func (n *fakeNode) Propose(ctx context.Context, cmd []byte) ([]byte, error) {
	n.mu.Lock()
	st := n.fallback
	if len(n.script) > 0 {
		st, n.script = n.script[0], n.script[1:]
	}
	n.proposals++
	hook := n.onPropose
	n.onPropose = nil
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	if st.delay > 0 {
		select {
		case <-time.After(st.delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", raft.ErrUnknownOutcome, ctx.Err())
		}
	}
	switch st.kind {
	case stepForge:
		return st.result, nil
	case stepStopped:
		return nil, raft.ErrStopped
	case stepNoLeader:
		return nil, raft.ErrNoLeader
	case stepUnknown:
		return nil, fmt.Errorf("%w: leadership lost", raft.ErrUnknownOutcome)
	case stepApplyUnknown:
		n.apply(cmd)
		return nil, fmt.Errorf("%w: reply lost", raft.ErrUnknownOutcome)
	}
	return n.apply(cmd), nil
}

func (n *fakeNode) ReadBarrier(ctx context.Context) error {
	n.mu.Lock()
	hook := n.onBarrier
	n.onBarrier = nil
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.barriers++
	return n.barrierErr
}

func (n *fakeNode) setLeader(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.status.LeaderID = id
}

func (n *fakeNode) setOnPropose(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onPropose = f
}

func (n *fakeNode) setOnBarrier(f func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onBarrier = f
}

func (n *fakeNode) Status() raft.Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := n.status
	st.LastApplied = n.index
	return st
}

func (n *fakeNode) Stop() error { return nil }

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const testBootstrapToken = "bootstrap-token-0123456789abcdef"

var testPeers = []api.ClusterNode{
	{ID: "n1", PublicURL: "https://n1.vault.test:8443"},
	{ID: "n2", PublicURL: "https://N2.Vault.Test:443/"},
	{ID: "n3", PublicURL: "http://192.168.1.20:8080"},
}

type env struct {
	t     *testing.T
	sm    *fsm.FSM
	node  *fakeNode
	srv   *Server
	ts    *httptest.Server
	clock *fakeClock
	logs  *syncBuffer
}

func newEnv(t *testing.T, mut ...func(*Config)) *env {
	t.Helper()
	sm := fsm.New()
	e := &env{
		t: t, sm: sm, node: newFakeNode(sm),
		clock: &fakeClock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)},
		logs:  &syncBuffer{},
	}
	cfg := Config{
		NodeID: "n1", Raft: e.node, FSM: sm, Peers: testPeers, BootstrapToken: testBootstrapToken,
		ProposeTimeout: 500 * time.Millisecond, ReadTimeout: 200 * time.Millisecond, Version: "test",
		Logger: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    e.clock.Now,
	}
	for _, m := range mut {
		m(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		e.ts.Close()
		_ = srv.Close()
	})
	return e
}

// initCluster applies an init command directly (Start does the same in the
// background; see TestStartInitializesClusterKey).
func (e *env) initCluster() {
	e.t.Helper()
	cmd, _ := fsm.EncodeCommand(strings.Repeat("0", 31)+"1", e.clock.Now().UnixMilli(), "", 0,
		&fsm.InitArgs{ClusterKey: bytes.Repeat([]byte{0x42}, 32)})
	e.node.apply(cmd)
	if !e.sm.Initialized() {
		e.t.Fatal("init failed")
	}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) errBody(t *testing.T) api.ErrorDetail {
	t.Helper()
	var eb api.ErrorBody
	if err := json.Unmarshal(r.body, &eb); err != nil || eb.Error.Code == "" {
		t.Fatalf("status %d without an ErrorBody: %s", r.status, r.body)
	}
	return eb.Error
}

type reqOpt func(*http.Request)

func withKey(k string) reqOpt { return func(r *http.Request) { r.Header.Set("Idempotency-Key", k) } }
func withToken(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}
func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func (e *env) do(method, path string, body any, opts ...reqOpt) resp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	res, err := e.ts.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, header: res.Header, body: b}
}

// call performs a request, requires the status and decodes the body.
func (e *env) call(method, path string, body any, want int, out any, opts ...reqOpt) resp {
	e.t.Helper()
	r := e.do(method, path, body, opts...)
	if r.status != want {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, r.status, want, r.body)
	}
	if want >= 300 {
		r.errBody(e.t)
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			e.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return r
}

func (e *env) callErr(method, path string, body any, wantStatus int, wantCode string, opts ...reqOpt) api.ErrorDetail {
	e.t.Helper()
	r := e.call(method, path, body, wantStatus, nil, opts...)
	d := r.errBody(e.t)
	if d.Code != wantCode {
		e.t.Fatalf("%s %s: code %q, want %q (%s)", method, path, d.Code, wantCode, d.Message)
	}
	return d
}

// ---------------------------------------------------------------------------
// Client-side test data
// ---------------------------------------------------------------------------

type account struct {
	id, name, personal string
	loginKey           []byte
	kdf                api.KDFParams
	token              string
	isAdmin            bool
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randID() string { return hex.EncodeToString(randBytes(16)) }

func box(n int) []byte {
	b := randBytes(n)
	b[0] = 1
	return b
}

func wrapped(sender string) api.WrappedKey { return api.WrappedKey{SenderID: sender, Blob: box(105)} }

func clientKDF() api.KDFParams {
	return api.KDFParams{Alg: "argon2id", Salt: randBytes(16), Time: 3, MemoryKiB: 65536, Parallelism: 4}
}

func newAccount(name string) *account {
	return &account{id: randID(), name: name, personal: randID(), loginKey: randBytes(32), kdf: clientKDF()}
}

func (a *account) registerReq(code string) api.RegisterRequest {
	return api.RegisterRequest{
		InviteCode: code, UserID: a.id, Username: a.name, KDF: a.kdf, LoginKey: a.loginKey,
		PublicKey: randBytes(32), WrappedAccountKey: box(73), EncPrivateKey: box(73),
		PersonalVault: api.CreateVaultRequest{VaultID: a.personal, EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(a.id)},
	}
}

func (e *env) register(a *account, code string, opts ...reqOpt) {
	e.t.Helper()
	var lr api.LoginResponse
	e.call("POST", "/v1/register", a.registerReq(code), 200, &lr, opts...)
	if lr.UserID != a.id || lr.Username != a.name || lr.Token == "" {
		e.t.Fatalf("register response: %+v", lr)
	}
	a.token, a.isAdmin = lr.Token, lr.IsAdmin
}

func (e *env) login(a *account) {
	e.t.Helper()
	var lr api.LoginResponse
	e.call("POST", "/v1/login", api.LoginRequest{Username: a.name, LoginKey: a.loginKey}, 200, &lr)
	a.token = lr.Token
}

func (e *env) invite(admin *account) api.CreateInviteResponse {
	e.t.Helper()
	var ir api.CreateInviteResponse
	e.call("POST", "/v1/invites", api.CreateInviteRequest{}, 200, &ir, withToken(admin.token))
	return ir
}

func (e *env) sync(a *account) api.SyncResponse {
	e.t.Helper()
	var sr api.SyncResponse
	e.call("GET", "/v1/sync", nil, 200, &sr, withToken(a.token))
	return sr
}

// rosterOf returns the current roster version and key epoch of a vault as
// seen by a (member).
func (e *env) rosterOf(a *account, vid string) (uint64, uint32) {
	e.t.Helper()
	v, _ := vaultOf(e.sync(a), vid)
	return v.RosterVersion, v.KeyEpoch
}

func vaultOf(sr api.SyncResponse, id string) (api.Vault, bool) {
	for _, v := range sr.Vaults {
		if v.ID == id {
			return v, true
		}
	}
	return api.Vault{}, false
}

// household bootstraps alice (admin) and invites bob.
func (e *env) household() (alice, bob *account) {
	e.t.Helper()
	e.initCluster()
	alice, bob = newAccount("alice"), newAccount("bob")
	e.register(alice, testBootstrapToken)
	e.register(bob, e.invite(alice).Code)
	return alice, bob
}
