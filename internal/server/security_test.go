package server

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
)

const wantCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self' https://n1.vault.test:8443 https://n2.vault.test http://192.168.1.20:8080; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"

func TestLoginRateLimitPerUsername(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	for i := 0; i < loginFailuresPerUser; i++ {
		e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: randBytes(32)}, 401, api.CodeUnauthorized)
	}
	// Now even the right key is refused, without running Argon2.
	r := e.do("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey})
	d := r.errBody(t)
	if r.status != 429 || d.Code != api.CodeRateLimited || d.RetryAfterMs <= 0 || r.header.Get("Retry-After") == "" {
		t.Fatalf("expected 429: %d %s", r.status, r.body)
	}
	// Other usernames are unaffected; successes never consume the budget.
	for i := 0; i < loginFailuresPerUser+2; i++ {
		e.login(alice)
	}
	// The bucket refills over time (10 per 5 minutes).
	e.clock.Advance(31 * time.Second)
	e.login(bob)
	// Password-change guesses share the per-user budget.
	e.clock.Advance(rateWindow)
	for i := 0; i < loginFailuresPerUser; i++ {
		e.callErr("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: randBytes(32), NewKDF: clientKDF(), NewLoginKey: randBytes(32), NewWrappedAccountKey: box(73)},
			401, api.CodeUnauthorized, withToken(bob.token))
	}
	e.callErr("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: randBytes(32), NewWrappedAccountKey: box(73)},
		429, api.CodeRateLimited, withToken(bob.token))
}

func TestLoginRateLimitPerIP(t *testing.T) {
	e := newEnv(t)
	e.initCluster()
	for i := 0; i < loginFailuresPerIP; i++ {
		// Unknown usernames count too, or the limit would reveal which exist.
		e.callErr("POST", "/v1/login", api.LoginRequest{Username: "nobody" + strings.Repeat("x", i%5) + string(rune('a'+i%26)), LoginKey: randBytes(32)}, 401, api.CodeUnauthorized)
	}
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "fresh", LoginKey: randBytes(32)}, 429, api.CodeRateLimited)
}

func TestTrustedProxyHeader(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxyHeader = "X-Forwarded-For" })
	e.initCluster()
	for i := 0; i < registerPerIP; i++ {
		e.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 403, api.CodeInvalidInvite, withHeader("X-Forwarded-For", "203.0.113.9, 10.0.0.1"))
	}
	e.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 429, api.CodeRateLimited, withHeader("X-Forwarded-For", "198.51.100.1, 10.0.0.1"))
	// A different right-most (proxy-appended) address is a different client.
	e.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 403, api.CodeInvalidInvite, withHeader("X-Forwarded-For", "10.0.0.2"))

	// Without the option the header is ignored (a client cannot pick its key).
	e2 := newEnv(t)
	e2.initCluster()
	for i := 0; i < registerPerIP; i++ {
		e2.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 403, api.CodeInvalidInvite, withHeader("X-Forwarded-For", "10.9.9."+string(rune('0'+i))))
	}
	e2.callErr("POST", "/v1/register", newAccount("x").registerReq("bad"), 429, api.CodeRateLimited, withHeader("X-Forwarded-For", "10.8.8.8"))
}

func TestClientIPKeys(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/", nil)
	for addr, want := range map[string]string{
		"192.0.2.1:5555":                    "192.0.2.1",
		"[2001:db8:1:2:3:4:5:6]:443":        "2001:db8:1:2::/64",
		"[::ffff:192.0.2.7]:80":             "192.0.2.7",
		"[fe80::1%en0]:80":                  "fe80::/64",
		"not-an-address":                    "not-an-address",
		"[2001:db8:1:2:ffff:ffff:ffff:1]:1": "2001:db8:1:2::/64",
	} {
		r.RemoteAddr = addr
		if got := s.clientIP(r); got != want {
			t.Errorf("clientIP(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestLimiterBoundedKeys(t *testing.T) {
	l := newLimiter(2, time.Minute, 3)
	now := time.Unix(1000, 0)
	for _, k := range []string{"a", "b", "c"} {
		if ok, _ := l.take(k, now); !ok {
			t.Fatal("take failed")
		}
	}
	if ok, wait := l.take("d", now); ok || wait <= 0 {
		t.Fatal("a full table must fail closed for new keys")
	}
	// Once buckets refill they are collectable and new keys fit again.
	later := now.Add(time.Minute)
	if ok, _ := l.take("d", later); !ok || l.size() != 1 {
		t.Fatalf("after refill: size %d", l.size())
	}
	l.gc(later.Add(time.Minute))
	if l.size() != 0 {
		t.Fatal("gc kept full buckets")
	}
}

func TestBodyLimitsAndStrictJSON(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	auth := withToken(alice.token)
	big := `{"vault_id":"` + randID() + `","enc_meta":"` + base64.StdEncoding.EncodeToString(make([]byte, maxBody)) + `"}`
	e.callErr("POST", "/v1/vaults", big, 413, api.CodeTooLarge, auth)

	// Rekey bodies may be larger than 1 MiB (here: rejected later, not for size).
	var items []string
	blob := base64.StdEncoding.EncodeToString(box(60 << 10))
	for i := 0; i < 30; i++ {
		items = append(items, `{"id":"`+randID()+`","blob":"`+blob+`"}`)
	}
	rekey := `{"base_rev":1,"new_key_epoch":2,"enc_meta":"` + base64.StdEncoding.EncodeToString(box(64)) + `","enc_roster":"` + base64.StdEncoding.EncodeToString(box(64)) + `","wrapped_keys":{},"items":[` + strings.Join(items, ",") + `]}`
	if len(rekey) <= maxBody {
		t.Fatal("test body too small")
	}
	e.callErr("POST", "/v1/vaults/"+alice.personal+"/rekey", rekey, 409, api.CodeVersionConflict, auth)
	hugeRekey := `{"items":[{"id":"` + randID() + `","blob":"` + base64.StdEncoding.EncodeToString(make([]byte, maxRekeyBody)) + `"}]}`
	e.callErr("POST", "/v1/vaults/"+alice.personal+"/rekey", hugeRekey, 413, api.CodeTooLarge, auth)

	ok := `{"vault_id":"` + randID() + `","enc_meta":"` + base64.StdEncoding.EncodeToString(box(64)) + `","enc_roster":"` + base64.StdEncoding.EncodeToString(box(64)) +
		`","wrapped_key":{"sender_id":"` + alice.id + `","blob":"` + base64.StdEncoding.EncodeToString(box(105)) + `"}}`
	e.callErr("POST", "/v1/vaults", ok+` {}`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", ok+`x`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", strings.Replace(ok, `{"vault_id"`, `{"extra":1,"vault_id"`, 1), 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", `{"vault_id":`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", "", 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", `{"enc_meta":"!!"}`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/vaults", ok, 400, api.CodeBadRequest, auth, withHeader("Content-Type", "text/plain"))
	e.call("POST", "/v1/vaults", ok, 200, nil, auth, withHeader("Content-Type", "application/json; charset=utf-8"))

	// Item blobs above 64 KiB fit in the body limit but exceed the item limit.
	e.callErr("PUT", "/v1/vaults/"+alice.personal+"/items/"+randID(), api.PutItemRequest{Blob: box(64<<10 + 1), KeyEpoch: 1}, 413, api.CodeTooLarge, auth)
	e.callErr("PUT", "/v1/vaults/"+alice.personal+"/items/"+randID(), api.PutItemRequest{Blob: box(40), KeyEpoch: 1}, 400, api.CodeBadRequest, auth)
	e.callErr("PUT", "/v1/vaults/NOTHEX/items/"+randID(), api.PutItemRequest{Blob: box(100), KeyEpoch: 1}, 400, api.CodeBadRequest, auth)

	// Body-less endpoints accept nothing or {} only.
	e.callErr("POST", "/v1/account/revoke-sessions", `{"x":1}`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/account/revoke-sessions", `[]`, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "alice", LoginKey: randBytes(31)}, 400, api.CodeBadRequest)
}

func TestAPIRouting(t *testing.T) {
	e := newEnv(t)
	e.callErr("GET", "/v1/nope", nil, 404, api.CodeNotFound)
	e.callErr("GET", "/v1", nil, 404, api.CodeNotFound)
	e.callErr("GET", "/v1/health/", nil, 404, api.CodeNotFound)
	r := e.do("DELETE", "/v1/health", nil)
	if r.status != 405 || r.header.Get("Allow") != "GET" {
		t.Fatalf("405: %d %v", r.status, r.header)
	}
	r.errBody(t)
	r = e.do("GET", "/v1/vaults/"+randID(), nil)
	if r.status != 405 || r.header.Get("Allow") != "DELETE" {
		t.Fatalf("405 for vault: %d %v", r.status, r.header.Get("Allow"))
	}
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/v1/health", "/", "/some/page", "/v1/nope"} {
		r := e.do("GET", p, nil)
		h := r.header
		if h.Get("Content-Security-Policy") != wantCSP {
			t.Fatalf("%s CSP = %q", p, h.Get("Content-Security-Policy"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" ||
			h.Get("Cross-Origin-Opener-Policy") != "same-origin" || !strings.Contains(h.Get("Permissions-Policy"), "camera=()") ||
			h.Get("X-Frame-Options") != "DENY" || h.Get("X-Request-Id") == "" {
			t.Fatalf("%s headers: %v", p, h)
		}
		if h.Get("Strict-Transport-Security") != "" {
			t.Fatal("HSTS over plain HTTP")
		}
		if strings.HasPrefix(p, "/v1/") && (h.Get("Cache-Control") != "no-store" || !strings.Contains(strings.Join(h.Values("Vary"), ","), "Origin")) {
			t.Fatalf("%s API caching headers: %v", p, h)
		}
	}

	// Allowed origin (normalized from the configured URL).
	r := e.do("GET", "/v1/health", nil, withHeader("Origin", "https://n2.vault.test"))
	if r.header.Get("Access-Control-Allow-Origin") != "https://n2.vault.test" || r.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("CORS for a peer: %v", r.header)
	}
	r = e.do("GET", "/v1/health", nil, withHeader("Origin", "https://evil.test"))
	if r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS allowed a foreign origin")
	}
	r = e.do("GET", "/v1/health", nil, withHeader("Origin", "https://n1.vault.test:8443.evil.test"))
	if r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS matched by prefix")
	}

	// Preflight.
	r = e.do("OPTIONS", "/v1/vaults/"+randID()+"/items/"+randID(), nil,
		withHeader("Origin", "http://192.168.1.20:8080"), withHeader("Access-Control-Request-Method", "PUT"),
		withHeader("Access-Control-Request-Headers", "authorization, content-type, idempotency-key"))
	if r.status != 204 || r.header.Get("Access-Control-Allow-Origin") != "http://192.168.1.20:8080" ||
		r.header.Get("Access-Control-Allow-Methods") != "GET, POST, PUT, DELETE, OPTIONS" ||
		r.header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, Idempotency-Key" ||
		r.header.Get("Access-Control-Max-Age") == "" {
		t.Fatalf("preflight: %d %v", r.status, r.header)
	}
	r = e.do("OPTIONS", "/v1/login", nil, withHeader("Origin", "https://evil.test"), withHeader("Access-Control-Request-Method", "POST"))
	if r.status != 403 || r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign preflight: %d %v", r.status, r.header)
	}
	r.errBody(t)

	// HSTS over TLS.
	ts := httptest.NewTLSServer(e.srv.Handler())
	defer ts.Close()
	res, err := ts.Client().Get(ts.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Strict-Transport-Security") == "" || res.TLS == nil || res.TLS.Version < tls.VersionTLS12 {
		t.Fatal("no HSTS over TLS")
	}
}

func TestStaticUI(t *testing.T) {
	web := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>app</title>")},
		"sw.js":         {Data: []byte("self.addEventListener('fetch',()=>{})")},
		"assets/app.js": {Data: []byte("console.log(1)")},
		"app.wasm":      {Data: []byte("\x00asm")},
	}
	e := newEnv(t, func(c *Config) { c.WebFS = web })
	check := func(path, wantBody, wantType, wantCache string) {
		t.Helper()
		r := e.do("GET", path, nil)
		if r.status != 200 || string(r.body) != wantBody || r.header.Get("Content-Type") != wantType || r.header.Get("Cache-Control") != wantCache {
			t.Fatalf("%s: %d %q %q %q", path, r.status, r.body, r.header.Get("Content-Type"), r.header.Get("Cache-Control"))
		}
	}
	index := string(web["index.html"].Data)
	check("/", index, "text/html; charset=utf-8", "no-cache")
	check("/index.html", index, "text/html; charset=utf-8", "no-cache")
	check("/sw.js", string(web["sw.js"].Data), "text/javascript; charset=utf-8", "no-cache")
	check("/assets/app.js", "console.log(1)", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable")
	check("/app.wasm", "\x00asm", "application/wasm", "public, max-age=3600")
	check("/vaults/123/items", index, "text/html; charset=utf-8", "no-cache") // SPA fallback
	check("/assets", index, "text/html; charset=utf-8", "no-cache")
	check("/../../etc/passwd", index, "text/html; charset=utf-8", "no-cache")
	if r := e.do("POST", "/", "x"); r.status != 405 {
		t.Fatalf("POST /: %d", r.status)
	}

	e2 := newEnv(t)
	r := e2.do("GET", "/anything", nil)
	if r.status != 200 || !strings.Contains(string(r.body), "Family Vault") || r.header.Get("Content-Security-Policy") != wantCSP {
		t.Fatalf("placeholder: %d %s", r.status, r.body)
	}
}

// TestStaticCompressionAndRevalidation: files are served gzip-encoded to
// clients that accept it (identical bytes once decoded, which the service
// worker's integrity check relies on), every response carries an entity
// tag and the security headers, and a revalidation is a bodiless 304.
func TestStaticCompressionAndRevalidation(t *testing.T) {
	js := strings.Repeat("export const f = (a, b) => a.map(x => x * b);\n", 400)
	web := fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>app</title>" + strings.Repeat("<p>shell</p>", 50))},
		"assets/app-ABCD.js":   {Data: []byte(js)},
		"assets/logo-1234.png": {Data: randBytes(2000)}, // incompressible
	}
	e := newEnv(t, func(c *Config) { c.WebFS = web })
	get := func(path string, hdr ...reqOpt) resp {
		t.Helper()
		r := e.do("GET", path, nil, append([]reqOpt{withHeader("Accept-Encoding", "identity")}, hdr...)...)
		if r.header.Get("Content-Security-Policy") != wantCSP || r.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: security headers missing: %v", path, r.header)
		}
		return r
	}
	for path, name := range map[string]string{"/": "index.html", "/assets/app-ABCD.js": "assets/app-ABCD.js"} {
		plain := get(path)
		gz := get(path, withHeader("Accept-Encoding", "br, gzip;q=0.8"))
		if plain.status != 200 || gz.status != 200 || gz.header.Get("Content-Encoding") != "gzip" || plain.header.Get("Content-Encoding") != "" {
			t.Fatalf("%s: %d %d %q", path, plain.status, gz.status, gz.header.Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz.body))
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := io.ReadAll(zr)
		if !bytes.Equal(decoded, web[name].Data) || !bytes.Equal(plain.body, web[name].Data) || len(gz.body) >= len(plain.body)/2 {
			t.Fatalf("%s: encodings differ or did not compress (%d vs %d bytes)", path, len(gz.body), len(plain.body))
		}
		if gz.header.Get("Content-Length") != strconv.Itoa(len(gz.body)) || gz.header.Get("Vary") != "Accept-Encoding" || plain.header.Get("Vary") != "Accept-Encoding" {
			t.Fatalf("%s: headers %v", path, gz.header)
		}
		pt, gt := plain.header.Get("ETag"), gz.header.Get("ETag")
		if pt == "" || gt == "" || pt == gt {
			t.Fatalf("%s: entity tags %q %q", path, pt, gt)
		}
		for _, c := range []struct{ tag, enc string }{{pt, "identity"}, {gt, "gzip"}} {
			r := get(path, withHeader("Accept-Encoding", c.enc), withHeader("If-None-Match", c.tag))
			if r.status != 304 || len(r.body) != 0 || r.header.Get("ETag") != c.tag {
				t.Fatalf("%s %s: revalidation %d (%d bytes)", path, c.enc, r.status, len(r.body))
			}
		}
		// A tag of the other encoding does not match.
		if r := get(path, withHeader("Accept-Encoding", "gzip"), withHeader("If-None-Match", pt)); r.status != 200 {
			t.Fatalf("%s: identity tag matched the gzip encoding", path)
		}
	}
	if r := get("/assets/app-ABCD.js", withHeader("Accept-Encoding", "gzip;q=0")); r.header.Get("Content-Encoding") != "" {
		t.Fatal("gzip;q=0 was served gzip")
	}
	png := get("/assets/logo-1234.png", withHeader("Accept-Encoding", "gzip"))
	if png.header.Get("Content-Encoding") != "" || png.header.Get("Vary") != "" || !bytes.Equal(png.body, web["assets/logo-1234.png"].Data) {
		t.Fatal("incompressible file was gzip-encoded")
	}
	if r := e.do("HEAD", "/assets/app-ABCD.js", nil, withHeader("Accept-Encoding", "gzip")); r.status != 200 || len(r.body) != 0 || r.header.Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d %d %q", r.status, len(r.body), r.header.Get("Content-Length"))
	}
	// API responses are never compressed.
	if r := e.do("GET", "/v1/health", nil, withHeader("Accept-Encoding", "gzip")); r.header.Get("Content-Encoding") != "" {
		t.Fatal("API response was compressed")
	}
}

func TestNoSecretsInLogs(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ProposeTimeout = 100 * time.Millisecond })
	alice, bob := e.household()
	inv := e.invite(alice)
	carol := newAccount("carol")
	e.register(carol, inv.Code, withKey(randID()))
	e.login(bob)
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: alice.loginKey}, 401, api.CodeUnauthorized)
	newKey := randBytes(32)
	var lr api.LoginResponse
	e.call("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: newKey, NewWrappedAccountKey: box(73)}, 200, &lr, withToken(bob.token))
	e.sync(alice)
	e.node.setFallback(step{kind: stepUnknown})
	e.callErr("POST", "/v1/account/revoke-sessions", nil, 503, api.CodeOutcomeUnknown, withToken(lr.Token))
	e.node.setFallback(step{kind: stepOK})
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(alice.token+"x"))

	logs := e.logs.String()
	var secrets []string
	for _, k := range [][]byte{alice.loginKey, bob.loginKey, carol.loginKey, newKey} {
		secrets = append(secrets, base64.StdEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(k), hex.EncodeToString(k))
	}
	canonical, _ := canonicalInviteCode(inv.Code)
	secrets = append(secrets, alice.token, bob.token, carol.token, lr.Token, inv.Code, canonical, testBootstrapToken)
	for _, tok := range []string{alice.token, lr.Token} {
		secrets = append(secrets, strings.Split(tok, ".")[1], strings.Split(tok, ".")[2])
	}
	for _, sec := range secrets {
		if strings.Contains(logs, sec) {
			t.Fatalf("secret %q found in logs", sec)
		}
	}
	for _, want := range []string{`"pattern":"POST /v1/login"`, `"pattern":"GET /v1/sync"`, `"status":401`, `"node":"n1"`, `"req_id":"`, `"duration_ms":`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log lines lack %s:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, alice.id) || strings.Contains(logs, alice.personal) {
		t.Fatal("raw paths/ids were logged instead of route patterns")
	}
}

func TestFakePrelogin(t *testing.T) {
	e := newEnv(t)
	e.callErr("POST", "/v1/prelogin", api.PreloginRequest{Username: "nobody"}, 503, api.CodeUnavailable)
	alice, _ := e.household()
	get := func(name string) api.KDFParams {
		var pl api.PreloginResponse
		e.call("POST", "/v1/prelogin", api.PreloginRequest{Username: name}, 200, &pl)
		return pl.KDF
	}
	a, b := get("nobody"), get(" NoBody")
	m := hmac.New(sha256.New, e.sm.ClusterKey())
	m.Write([]byte("fpv/v1/fake-salt|nobody"))
	want := m.Sum(nil)[:16]
	if !bytes.Equal(a.Salt, want) || !bytes.Equal(a.Salt, b.Salt) || a.Alg != "argon2id" || a.Time != 3 || a.MemoryKiB != 65536 || a.Parallelism != 4 {
		t.Fatalf("fake prelogin: %+v", a)
	}
	if bytes.Equal(get("nobody2").Salt, a.Salt) {
		t.Fatal("fake salts must differ per username")
	}
	if real := get("alice"); !bytes.Equal(real.Salt, alice.kdf.Salt) {
		t.Fatal("known user must get the real salt")
	}
	e.callErr("POST", "/v1/prelogin", api.PreloginRequest{Username: "-bad"}, 400, api.CodeBadRequest)
	e.callErr("POST", "/v1/prelogin", api.PreloginRequest{Username: "ünï"}, 400, api.CodeBadRequest)
}

func TestLoginFailuresIndistinguishable(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	e.call("PUT", "/v1/admin/users/"+bob.id, api.AdminUpdateUserRequest{Disabled: ptr(true)}, 200, nil, withToken(alice.token))
	bodies := map[string]bool{}
	for _, req := range []api.LoginRequest{
		{Username: "nosuchuser", LoginKey: randBytes(32)},
		{Username: "alice", LoginKey: randBytes(32)},
		{Username: "bob", LoginKey: bob.loginKey}, // disabled, correct key
	} {
		r := e.do("POST", "/v1/login", req)
		if r.status != 401 {
			t.Fatalf("%s: %d", req.Username, r.status)
		}
		bodies[string(r.body)] = true
	}
	if len(bodies) != 1 {
		t.Fatalf("login failures are distinguishable: %v", bodies)
	}
}

func TestArgonSaturation(t *testing.T) {
	e := newEnv(t)
	_, bob := e.household()
	e.srv.argonWait = 50 * time.Millisecond
	for i := 0; i < argonSlots; i++ {
		e.srv.argonSem <- struct{}{}
	}
	r := e.do("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey})
	if r.status != 503 || r.errBody(t).Code != api.CodeUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("saturated: %d %s", r.status, r.body)
	}
	for i := 0; i < argonSlots; i++ {
		<-e.srv.argonSem
	}
	// A turned-away attempt does not count as a failure.
	for i := 0; i < loginFailuresPerUser; i++ {
		e.login(bob)
	}
}

func TestConfigValidation(t *testing.T) {
	sm := fsm.New()
	n := newFakeNode(sm)
	base := Config{NodeID: "n1", Raft: n, FSM: sm, Peers: testPeers}
	for name, mut := range map[string]func(*Config){
		"no node id":      func(c *Config) { c.NodeID = "" },
		"no raft":         func(c *Config) { c.Raft = nil },
		"no fsm":          func(c *Config) { c.FSM = nil },
		"weak bootstrap":  func(c *Config) { c.BootstrapToken = "short" },
		"relative peer":   func(c *Config) { c.Peers = []api.ClusterNode{{ID: "x", PublicURL: "/foo"}} },
		"bad scheme peer": func(c *Config) { c.Peers = []api.ClusterNode{{ID: "x", PublicURL: "ftp://x"}} },
		"userinfo peer":   func(c *Config) { c.Peers = []api.ClusterNode{{ID: "x", PublicURL: "https://u:p@x"}} },
	} {
		cfg := base
		mut(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted an invalid config", name)
		}
	}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapDisabledNode(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.BootstrapToken = "" })
	e.initCluster()
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(testBootstrapToken), 403, api.CodeInvalidInvite)
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(""), 403, api.CodeInvalidInvite)
}

func TestInviteCodeFormat(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, 20)
	code := formatInviteCode(raw)
	if len(code) != 39 || strings.Count(code, "-") != 7 {
		t.Fatalf("code %q", code)
	}
	canon, ok := canonicalInviteCode(code)
	if !ok || len(canon) != 32 || strings.Contains(canon, "-") {
		t.Fatalf("canonical %q", canon)
	}
	for _, in := range []string{strings.ToLower(code), strings.ReplaceAll(code, "-", ""), "  " + code + "\n", strings.ToLower(strings.ReplaceAll(code, "-", ""))} {
		if c, ok := canonicalInviteCode(in); !ok || c != canon {
			t.Errorf("%q did not canonicalize", in)
		}
	}
	for _, in := range []string{"", code[:38], code + "A", "1" + code[1:], "8" + code[1:], code[:1] + "ä" + code[2:], strings.Replace(code, "-", " ", 1), code + "-" + code} {
		if _, ok := canonicalInviteCode(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestHealthNeverBlocks(t *testing.T) {
	e := newEnv(t)
	e.node.setBarrierErr(io.ErrUnexpectedEOF)
	e.node.setFallback(step{kind: stepOK, delay: 10 * time.Second})
	start := time.Now()
	e.call("GET", "/v1/health", nil, 200, nil)
	e.call("GET", "/v1/cluster", nil, 200, nil)
	if time.Since(start) > time.Second {
		t.Fatal("health/cluster blocked on consensus")
	}
}
