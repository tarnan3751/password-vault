package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/tarnan3751/password-vault/internal/fsm"
)

// ---------------------------------------------------------------------------
// Tokens (api.md §3.2)
// ---------------------------------------------------------------------------

const (
	tokenPrefix   = "v1."
	tokenMACLabel = "fpv/v1/token|"
	maxTokenLen   = 512
)

// Strict decoding rejects non-canonical base64, so a token has exactly one
// valid spelling.
var b64url = base64.RawURLEncoding.Strict()

type tokenClaims struct {
	UID string `json:"uid"`
	Ep  uint64 `json:"ep"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	// At is when the login key was last proven (login, register, password
	// change). Refreshing a session through revoke-sessions keeps it, so a
	// stolen token cannot be kept alive forever.
	At int64 `json:"at"`
}

func tokenMAC(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(tokenMACLabel))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func mintToken(key []byte, c tokenClaims) string {
	j, _ := json.Marshal(c) // cannot fail for this struct
	payload := b64url.EncodeToString(j)
	return tokenPrefix + payload + "." + b64url.EncodeToString(tokenMAC(key, payload))
}

var errBadToken = errors.New("invalid token")

// parseToken verifies the MAC (constant time) before looking at the payload,
// then checks expiry and the absolute session age. Session state (epoch,
// disabled) is checked separately against the replicated state.
func parseToken(key []byte, tok string, now time.Time, maxAge time.Duration) (tokenClaims, error) {
	var c tokenClaims
	if len(tok) > maxTokenLen {
		return c, errBadToken
	}
	rest, ok := strings.CutPrefix(tok, tokenPrefix)
	if !ok {
		return c, errBadToken
	}
	payload, sig, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(sig, ".") {
		return c, errBadToken
	}
	mac, err := b64url.DecodeString(sig)
	if err != nil || !hmac.Equal(mac, tokenMAC(key, payload)) {
		return c, errBadToken
	}
	raw, err := b64url.DecodeString(payload)
	if err != nil {
		return c, errBadToken
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, errBadToken
	}
	if !fsm.ValidID(c.UID) || c.Ep == 0 || c.Exp <= now.Unix() || c.At <= 0 || now.Unix()-c.At > int64(maxAge/time.Second) {
		return c, errBadToken
	}
	return c, nil
}

// principal is the caller identified by a MAC-verified, unexpired token.
type principal struct {
	uid string
	ep  uint64
	at  int64 // auth time claim of the presented token
}

// ---------------------------------------------------------------------------
// Password verifier (api.md §3.1)
// ---------------------------------------------------------------------------

const (
	// argonSlots bounds concurrent Argon2 computations: each needs ~19 MiB,
	// so a login flood cannot exhaust the memory of a Raspberry Pi.
	argonSlots = 4
	// argonQueueWait is how long a request may wait for a slot before it is
	// turned away with 503.
	argonQueueWait = 3 * time.Second
)

var errArgonBusy = errors.New("password hashing capacity exhausted")

// argon computes Argon2id under the concurrency limit. It only ever runs
// with the fixed verifier parameters: stored verifiers are validated by the
// state machine, and checking again here means no input can choose the
// memory cost.
func (s *Server) argon(ctx context.Context, secret []byte, v fsm.Verifier) ([]byte, error) {
	if v.Time != fsm.VerifierTime || v.MemoryKiB != fsm.VerifierMemoryKiB || v.Parallelism != fsm.VerifierParallelism ||
		len(v.Salt) != fsm.VerifierSaltBytes {
		return nil, errors.New("unexpected verifier parameters")
	}
	t := time.NewTimer(s.argonWait)
	defer t.Stop()
	select {
	case s.argonSem <- struct{}{}:
	case <-t.C:
		return nil, errArgonBusy
	case <-ctx.Done():
		return nil, errArgonBusy
	}
	defer func() { <-s.argonSem }()
	return argon2.IDKey(secret, v.Salt, v.Time, v.MemoryKiB, v.Parallelism, fsm.VerifierHashBytes), nil
}

// checkVerifier reports whether loginKey matches v, comparing in constant
// time.
func (s *Server) checkVerifier(ctx context.Context, loginKey []byte, v fsm.Verifier) (bool, error) {
	h, err := s.argon(ctx, loginKey, v)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(h, v.Hash) == 1, nil
}

func verifierParams(salt []byte) fsm.Verifier {
	return fsm.Verifier{Salt: salt, Time: fsm.VerifierTime, MemoryKiB: fsm.VerifierMemoryKiB, Parallelism: fsm.VerifierParallelism}
}

// newVerifier hashes loginKey with a fresh random salt.
func (s *Server) newVerifier(ctx context.Context, loginKey []byte) (fsm.Verifier, error) {
	salt, err := s.randomBytes(fsm.VerifierSaltBytes)
	if err != nil {
		return fsm.Verifier{}, err
	}
	v := verifierParams(salt)
	h, err := s.argon(ctx, loginKey, v)
	if err != nil {
		return fsm.Verifier{}, err
	}
	v.Hash = h
	return v, nil
}

// placeholderVerifier has the right shape so that a command can be
// validated (and dry-run) before the expensive real verifier is computed.
func placeholderVerifier() fsm.Verifier {
	v := verifierParams(make([]byte, fsm.VerifierSaltBytes))
	v.Hash = make([]byte, fsm.VerifierHashBytes)
	return v
}

func (s *Server) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rand, b); err != nil {
		return nil, err
	}
	return b, nil
}

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// ---------------------------------------------------------------------------
// Invite codes (api.md §4)
// ---------------------------------------------------------------------------

const inviteCodeBytes = 20

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// formatInviteCode renders 20 bytes as 32 base32 characters in groups of 4.
func formatInviteCode(raw []byte) string {
	s := b32.EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// canonicalInviteCode accepts a code case-insensitively, with or without
// dashes, and returns its canonical form: 32 upper-case base32 characters
// without dashes. Non-ASCII input is rejected outright rather than
// case-folded, so look-alike characters cannot produce a match.
func canonicalInviteCode(in string) (string, bool) {
	in = strings.TrimSpace(in)
	b := make([]byte, 0, 32)
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '-':
			continue
		case 'a' <= c && c <= 'z':
			c -= 'a' - 'A'
		case 'A' <= c && c <= 'Z', '2' <= c && c <= '7':
		default:
			return "", false
		}
		if len(b) == 32 {
			return "", false
		}
		b = append(b, c)
	}
	if len(b) != 32 {
		return "", false
	}
	return string(b), true
}

// inviteHashOf is what the state stores for a canonical code.
func inviteHashOf(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write([]byte(p))
	}
	return m.Sum(nil)
}

// ---------------------------------------------------------------------------
// Rate limiting (api.md §3.4)
// ---------------------------------------------------------------------------

// limiter is a set of token buckets keyed by string. Memory is bounded: full
// buckets are indistinguishable from fresh ones and are garbage-collected,
// and once maxKeys keys are tracked new keys are refused (fail closed) rather
// than silently exempted from limiting.
type limiter struct {
	mu       sync.Mutex
	capacity float64
	perSec   float64
	maxKeys  int
	buckets  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(n int, per time.Duration, maxKeys int) *limiter {
	return &limiter{capacity: float64(n), perSec: float64(n) / per.Seconds(), maxKeys: maxKeys, buckets: map[string]*bucket{}}
}

func (l *limiter) refill(b *bucket, now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.capacity, b.tokens+el*l.perSec)
		b.last = now
	}
}

// take consumes one token. If none is available it returns the time until
// one will be.
func (l *limiter) take(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			l.gcLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false, time.Duration(float64(time.Second) / l.perSec)
			}
		}
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// refund returns a token taken for an attempt that turned out not to count
// (a successful login, or one that could not be evaluated).
func (l *limiter) refund(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[key]; b != nil {
		l.refill(b, now)
		b.tokens = math.Min(l.capacity, b.tokens+1)
	}
}

func (l *limiter) gc(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked(now)
}

func (l *limiter) gcLocked(now time.Time) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.capacity {
			delete(l.buckets, k)
		}
	}
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// reserveLogin takes a token from both the per-IP and the per-username
// failure buckets BEFORE the expensive check, so that parallel attempts
// cannot all slip through before the first failure is counted. The
// returned refund must be called if the attempt did not fail.
func (s *Server) reserveLogin(ip, username string) (func(), *apiError) {
	now := s.now()
	if ok, wait := s.limLoginIP.take(ip, now); !ok {
		return nil, errRateLimited(wait.Milliseconds())
	}
	if ok, wait := s.limLoginUser.take(username, now); !ok {
		s.limLoginIP.refund(ip, now)
		return nil, errRateLimited(wait.Milliseconds())
	}
	return func() {
		n := s.now()
		s.limLoginIP.refund(ip, n)
		s.limLoginUser.refund(username, n)
	}, nil
}

// clientIP returns the rate-limiting key for the client address.
//
// The proxy header is believed only when the socket peer itself is a
// trusted proxy; anyone else could put any address in it. Within the
// header, entries are walked from the right (each proxy appends the address
// it received the request from) past the trusted proxies, and the first
// untrusted address is the client: everything further left was written by
// the client and is ignored. IPv6 clients are keyed by /64, since a single
// host usually controls a whole /64.
func (s *Server) clientIP(r *http.Request) string {
	peer, ok := parseAddr(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if h := s.cfg.TrustedProxyHeader; h != "" && s.trusted(peer) {
		vals := strings.Split(strings.Join(r.Header.Values(h), ","), ",")
		var leftmost netip.Addr
		for i := len(vals) - 1; i >= 0; i-- {
			v := strings.TrimSpace(vals[i])
			if v == "" {
				continue
			}
			a, ok := parseAddr(v)
			if !ok {
				// A malformed hop: nothing to its left can be trusted, and
				// the request came through trusted proxies only, so key on
				// the last trusted hop.
				break
			}
			if !s.trusted(a) {
				return addrKey(a)
			}
			leftmost = a
		}
		if leftmost.IsValid() {
			// Every hop is a trusted proxy (e.g. a client on the proxy host).
			return addrKey(leftmost)
		}
	}
	return addrKey(peer)
}

// parsePrefix accepts a CIDR or a single address.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			return netip.Prefix{}, errors.New("use plain IPv4 notation")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, errors.New("not a CIDR or IP address")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (s *Server) trusted(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range s.trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return a, err == nil
}

func addrKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}
