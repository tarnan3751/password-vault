package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
)

// newVaultArgs builds a create_vault command for owner.
func newVaultArgs(vid string, meta []byte, owner string) *fsm.CreateVaultArgs {
	return &fsm.CreateVaultArgs{VaultID: vid, EncMeta: meta, EncRoster: box(rosterBytes), WrappedKey: wrapped(owner)}
}

// rosterBytes is the size of the roster newVaultArgs stores.
const rosterBytes = 64

// sameSize returns a fresh box as long as b (nil for nil).
func sameSize(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return box(len(b))
}

// applyAs applies a command directly through the fake node (fast setup).
func (e *env) applyAs(a *account, ep uint64, args fsm.Args) *fsm.Outcome {
	e.t.Helper()
	cmd, err := fsm.EncodeCommand(randID(), e.clock.Now().UnixMilli(), a.id, ep, args)
	if err != nil {
		e.t.Fatal(err)
	}
	r, err := fsm.DecodeResult(e.node.apply(cmd))
	if err != nil || r.Err != nil {
		e.t.Fatalf("%s: %v %+v", args.Op(), err, r.Err)
	}
	return r.OK
}

// TestRekeyOfFullVaultsFitsBodyLimit: a vault at the per-vault byte cap
// (max-size items) and one at the item-count cap (small items, also filling
// the byte cap) can each be rekeyed through the HTTP handler within the
// 32 MiB rekey body limit.
func TestRekeyOfFullVaultsFitsBodyLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two 8 MiB vaults")
	}
	e := newEnv(t, func(c *Config) { c.ProposeTimeout = 30 * time.Second })
	alice, bob := e.household()
	cases := []struct {
		name  string
		owner *account
		count int
		size  int
	}{
		{"max-size items", alice, 0, fsm.MaxItemBlobBytes},
		{"10000 items", bob, fsm.MaxItemsPerVault, 0},
	}
	for _, tc := range cases {
		vid := randID()
		meta := box(64)
		e.applyAs(tc.owner, 1, newVaultArgs(vid, meta, tc.owner.id))
		var blobs []int
		budget := int64(fsm.MaxVaultBytes) - int64(len(meta)) - rosterBytes
		if tc.count == 0 { // as many max-size items as fit, then one remainder item
			for budget >= fsm.ItemOverheadBytes+int64(tc.size) {
				blobs = append(blobs, tc.size)
				budget -= fsm.ItemOverheadBytes + int64(tc.size)
			}
			if budget-fsm.ItemOverheadBytes >= fsm.MinBoxBytes {
				blobs = append(blobs, int(budget-fsm.ItemOverheadBytes))
			}
		} else { // exactly the item cap, sized to also fill the byte cap
			per := budget/int64(tc.count) - fsm.ItemOverheadBytes
			for i := 0; i < tc.count; i++ {
				blobs = append(blobs, int(per))
			}
		}
		for _, n := range blobs {
			e.applyAs(tc.owner, 1, &fsm.PutItemArgs{VaultID: vid, ItemID: randID(), Blob: box(n), KeyEpoch: 1})
		}
		v, _ := vaultOf(e.sync(tc.owner), vid)
		rk := api.RekeyRequest{
			BaseRev: v.Rev, NewKeyEpoch: v.KeyEpoch + 1, EncMeta: sameSize(v.EncMeta), EncRoster: sameSize(v.EncRoster),
			WrappedKeys: map[string]api.WrappedKey{tc.owner.id: wrapped(tc.owner.id)},
		}
		for _, it := range v.Items {
			rk.Items = append(rk.Items, api.RekeyItem{ID: it.ID, Blob: box(len(it.Blob))})
		}
		body, _ := json.Marshal(rk)
		t.Logf("%s: %d items, vault usage at cap (%d bytes), rekey body %d bytes (%.1f MiB of %d MiB)",
			tc.name, len(v.Items), fsm.MaxVaultBytes, len(body), float64(len(body))/(1<<20), maxRekeyBody>>20)
		if len(body) > maxRekeyBody {
			t.Fatalf("%s: rekey body %d exceeds the limit", tc.name, len(body))
		}
		var mr api.MutationResponse
		e.call("POST", "/v1/vaults/"+vid+"/rekey", body, 200, &mr, withToken(tc.owner.token))
		if v2, _ := vaultOf(e.sync(tc.owner), vid); v2.KeyEpoch != v.KeyEpoch+1 || len(v2.Items) != len(v.Items) {
			t.Fatalf("%s: rekey not applied", tc.name)
		}
	}
}

func TestReplayProofsAreRateLimited(t *testing.T) {
	// Every request comes through a trusted local proxy from a different
	// client address, so only the per-username budget can stop the guessing.
	e := newEnv(t, func(c *Config) { c.TrustedProxyHeader = "X-Forwarded-For" })
	alice, bob := e.household()
	ip := 0
	from := func() reqOpt {
		ip++
		return withHeader("X-Forwarded-For", fmt.Sprintf("198.51.%d.%d", ip/250, ip%250+1))
	}

	key := randID()
	req := api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: randBytes(32), NewWrappedAccountKey: box(73)}
	e.call("POST", "/v1/account/password", req, 200, nil, withToken(bob.token), withKey(key), from())
	p0, _, _ := e.node.counts()
	codes := map[int]int{}
	for i := 0; i < 15; i++ {
		bad := req
		bad.NewLoginKey = randBytes(32)
		codes[e.do("POST", "/v1/account/password", bad, withToken(bob.token), withKey(key), from()).status]++
	}
	if codes[401] != loginFailuresPerUser || codes[429] != 15-loginFailuresPerUser {
		t.Fatalf("change-password replays: %v", codes)
	}
	// Even the right key is now refused until the budget refills.
	e.callErr("POST", "/v1/account/password", req, 429, api.CodeRateLimited, withToken(bob.token), withKey(key), from())
	if p, _, _ := e.node.counts(); p != p0 {
		t.Fatal("replays reached Propose")
	}
	e.clock.Advance(rateWindow)
	var lr api.LoginResponse
	e.call("POST", "/v1/account/password", req, 200, &lr, withToken(bob.token), withKey(key), from())

	// Register replays share the same per-username budget.
	carol := newAccount("carol")
	reg := carol.registerReq(e.invite(alice).Code)
	rk := randID()
	e.call("POST", "/v1/register", reg, 200, nil, withKey(rk), from())
	codes = map[int]int{}
	for i := 0; i < 12; i++ {
		bad := reg
		bad.LoginKey = randBytes(32)
		codes[e.do("POST", "/v1/register", bad, withKey(rk), from()).status]++
	}
	if codes[401] != loginFailuresPerUser || codes[429] != 2 {
		t.Fatalf("register replays: %v", codes)
	}
}

func TestTokensAreOnlyMintedForTheCaller(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	forged := func(uid, name string) []byte {
		b, _ := json.Marshal(fsm.Result{OK: &fsm.Outcome{Rev: 99, UserID: uid, Username: name, Epoch: 7,
			Verifier: &fsm.Verifier{Salt: make([]byte, 16), Time: 2, MemoryKiB: 19456, Parallelism: 1, Hash: make([]byte, 32)}}})
		return b
	}
	// revoke-sessions answered with somebody else's account.
	e.node.push(step{kind: stepForge, result: forged(alice.id, "alice")})
	e.callErr("POST", "/v1/account/revoke-sessions", nil, 500, api.CodeInternal, withToken(bob.token))
	// register answered with a different user id.
	carol := newAccount("carol")
	code := e.invite(alice).Code
	e.node.push(step{kind: stepForge, result: forged(alice.id, "alice")})
	e.callErr("POST", "/v1/register", carol.registerReq(code), 500, api.CodeInternal)
	// change-password answered with a different user id.
	e.node.push(step{kind: stepForge, result: forged(alice.id, "alice")})
	e.callErr("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: randBytes(32), NewWrappedAccountKey: box(73)},
		500, api.CodeInternal, withToken(bob.token))
	if n := strings.Count(e.logs.String(), "SECURITY: refusing to mint a token"); n != 3 {
		t.Fatalf("expected 3 loud log lines, got %d", n)
	}
}

func tokenAt(t *testing.T, tok string) tokenClaims {
	t.Helper()
	raw, err := b64url.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c tokenClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAbsoluteSessionLifetime(t *testing.T) {
	if d := newEnv(t).srv.cfg.MaxSessionAge; d != 30*24*time.Hour {
		t.Fatalf("default MaxSessionAge %v", d)
	}
	e := newEnv(t, func(c *Config) { c.MaxSessionAge = 48 * time.Hour })
	_, bob := e.household()
	e.login(bob)
	t0 := e.clock.Now().Unix()
	if c := tokenAt(t, bob.token); c.At != t0 || c.Iat != t0 {
		t.Fatalf("login token claims: %+v", c)
	}
	// Refreshing through revoke-sessions keeps the auth time...
	tok := bob.token
	for i := 0; i < 4; i++ {
		e.clock.Advance(11 * time.Hour)
		var lr api.LoginResponse
		e.call("POST", "/v1/account/revoke-sessions", nil, 200, &lr, withToken(tok))
		tok = lr.Token
		if c := tokenAt(t, tok); c.At != t0 {
			t.Fatalf("refresh %d reset the auth time: %+v", i, c)
		}
		if i == 3 && lr.ExpiresAt != (t0+48*3600)*1000 {
			t.Fatalf("refreshed token outlives the session: expires_at %d", lr.ExpiresAt)
		}
	}
	// ...so the session ends 48 h after the login, refreshed or not.
	e.clock.Advance(4*time.Hour + time.Second) // t0 + 48h + 1s
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(tok))
	e.callErr("POST", "/v1/account/revoke-sessions", nil, 401, api.CodeUnauthorized, withToken(tok))
	// Proving the login key again starts a new session.
	e.login(bob)
	if c := tokenAt(t, bob.token); c.At != e.clock.Now().Unix() {
		t.Fatalf("login after expiry: %+v", c)
	}
	var lr api.LoginResponse
	newKey := randBytes(32)
	e.clock.Advance(11 * time.Hour)
	e.call("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: newKey, NewWrappedAccountKey: box(73)}, 200, &lr, withToken(bob.token))
	if c := tokenAt(t, lr.Token); c.At != e.clock.Now().Unix() {
		t.Fatalf("password change must reset the auth time: %+v", c)
	}
	// Tokens without the claim are invalid.
	legacy := mintToken(e.sm.ClusterKey(), tokenClaims{UID: bob.id, Ep: tokenAt(t, lr.Token).Ep, Iat: e.clock.Now().Unix(), Exp: e.clock.Now().Add(time.Hour).Unix()})
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(legacy))
	e.call("GET", "/v1/sync", nil, 200, nil, withToken(lr.Token))
}

func TestTrustedProxies(t *testing.T) {
	sm := fsm.New()
	mk := func(proxies ...string) *Server {
		s, err := New(Config{NodeID: "n1", Raft: newFakeNode(sm), FSM: sm, TrustedProxyHeader: "X-Forwarded-For", TrustedProxies: proxies})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	key := func(s *Server, peer, xff string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return s.clientIP(r)
	}
	s := mk("10.0.0.0/8", "192.0.2.10")
	for _, c := range []struct{ peer, xff, want string }{
		{"203.0.113.5:1", "1.2.3.4", "203.0.113.5"},                       // untrusted peer: header ignored
		{"10.0.0.1:1", "6.6.6.6, 198.51.100.7", "198.51.100.7"},           // right-most untrusted
		{"10.0.0.1:1", "6.6.6.6, 198.51.100.7, 10.9.9.9", "198.51.100.7"}, // skip trusted hops
		{"192.0.2.10:1", "198.51.100.7,192.0.2.10", "198.51.100.7"},
		{"10.0.0.1:1", "10.0.0.3, 10.0.0.2", "10.0.0.3"},        // all trusted
		{"10.0.0.1:1", "garbage, 198.51.100.7", "198.51.100.7"}, // client junk on the left
		{"10.0.0.1:1", "198.51.100.7, garbage", "10.0.0.1"},     // broken chain: the proxy
		{"10.0.0.1:1", "", "10.0.0.1"},                          // no header
		{"10.0.0.1:1", "2001:db8::1, [2001:db8:0:0:1::9]:443", "2001:db8::/64"},
	} {
		if got := key(s, c.peer, c.xff); got != c.want {
			t.Errorf("peer %s xff %q: %q, want %q", c.peer, c.xff, got, c.want)
		}
	}
	def := mk()
	if key(def, "127.0.0.1:5", "198.51.100.7") != "198.51.100.7" || key(def, "[::1]:5", "198.51.100.7") != "198.51.100.7" {
		t.Fatal("loopback must be trusted by default")
	}
	if key(def, "10.0.0.1:5", "198.51.100.7") != "10.0.0.1" {
		t.Fatal("only loopback is trusted by default")
	}
	for _, bad := range []string{"10.0.0.0/33", "nonsense", "fe80::1%en0", ""} {
		if _, err := New(Config{NodeID: "n1", Raft: newFakeNode(sm), FSM: sm, TrustedProxyHeader: "X-Forwarded-For", TrustedProxies: []string{bad}}); err == nil {
			t.Errorf("accepted trusted proxy %q", bad)
		}
	}
	// End to end: with a non-loopback proxy list the test client (127.0.0.1)
	// is not trusted, so a forged header does not buy fresh budgets.
	e := newEnv(t, func(c *Config) { c.TrustedProxyHeader = "X-Forwarded-For"; c.TrustedProxies = []string{"10.0.0.0/8"} })
	e.initCluster()
	for i := 0; i < registerPerIP; i++ {
		e.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 403, api.CodeInvalidInvite, withHeader("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1)))
	}
	e.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 429, api.CodeRateLimited, withHeader("X-Forwarded-For", "198.51.100.200"))
}

func TestUnauthenticatedBodyLimits(t *testing.T) {
	e := newEnv(t)
	e.initCluster()
	pad := strings.Repeat(" ", 5<<10)
	e.callErr("POST", "/v1/login", `{"username":"alice"`+pad+`}`, 413, api.CodeTooLarge)
	e.callErr("POST", "/v1/prelogin", `{"username":"alice"`+pad+`}`, 413, api.CodeTooLarge)
	reg := newAccount("alice").registerReq(testBootstrapToken)
	reg.WrappedAccountKey = box(fsm.MaxAccountBlobBytes)
	reg.EncPrivateKey = box(fsm.MaxAccountBlobBytes)
	reg.PersonalVault.EncMeta = box(fsm.MaxEncMetaBytes)
	// A personal vault's roster lists one member (~160 bytes); 1 KiB is a
	// generous realistic maximum. (A 16 KiB roster is accepted elsewhere but
	// would not fit a registration body.)
	reg.PersonalVault.EncRoster = box(1 << 10)
	reg.KDF.Salt = randBytes(fsm.KDFMaxSaltBytes)
	b, _ := json.Marshal(reg)
	if len(b) > maxRegisterBody {
		t.Fatalf("a maximal legitimate registration (%d bytes) exceeds the limit", len(b))
	}
	e.call("POST", "/v1/register", b, 200, nil)
	big := strings.Replace(string(b), `{"invite_code"`, `{"invite_code"`+strings.Repeat(" ", maxRegisterBody), 1)
	e.callErr("POST", "/v1/register", big, 413, api.CodeTooLarge)
}

func TestStaleReadWindow(t *testing.T) {
	longTokens := func(c *Config) { c.TokenTTL = 10 * 24 * time.Hour }
	e := newEnv(t, longTokens)
	alice, bob := e.household()
	e.node.setBarrierErr(fmt.Errorf("partitioned"))
	e.node.setLeader("")
	e.call("GET", "/v1/sync?consistency=stale", nil, 200, nil, withToken(alice.token)) // leader seen at setup
	e.clock.Advance(DefaultStaleReadWindow - time.Second)
	e.call("GET", "/v1/sync?consistency=stale", nil, 200, nil, withToken(alice.token))
	e.clock.Advance(2 * time.Second)
	d := e.callErr("GET", "/v1/sync?consistency=stale", nil, 503, api.CodeUnavailable, withToken(alice.token))
	if !strings.Contains(d.Message, "stale read window") {
		t.Fatalf("message: %q", d.Message)
	}
	e.callErr("POST", "/v1/prelogin?consistency=stale", api.PreloginRequest{Username: "bob"}, 503, api.CodeUnavailable)
	e.callErr("POST", "/v1/login?consistency=stale", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey}, 503, api.CodeUnavailable)
	// Knowing a leader again re-opens the window (sampled in the background
	// and on every stale request).
	e.node.setLeader("n2")
	e.srv.sampleLeader()
	if got := e.srv.lastLeader.Load(); got != e.clock.Now().UnixNano() {
		t.Fatal("sampleLeader did not record the leader")
	}
	e.call("GET", "/v1/sync?consistency=stale", nil, 200, nil, withToken(alice.token))

	// Negative window: no stale reads at all; linearizable reads unaffected.
	e2 := newEnv(t, func(c *Config) { c.StaleReadWindow = -1 })
	a2, _ := e2.household()
	e2.callErr("GET", "/v1/sync?consistency=stale", nil, 503, api.CodeUnavailable, withToken(a2.token))
	e2.call("GET", "/v1/sync", nil, 200, nil, withToken(a2.token))

	// A node that never sees a leader after start: the window counts from
	// the server's start time.
	e3 := newEnv(t, longTokens)
	e3.node.setLeader("")
	_, b3 := e3.household()
	e3.clock.Advance(DefaultStaleReadWindow + time.Second)
	e3.callErr("POST", "/v1/login?consistency=stale", api.LoginRequest{Username: "bob", LoginKey: b3.loginKey}, 503, api.CodeUnavailable)
}
