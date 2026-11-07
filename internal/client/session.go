package client

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// MaxItemBlob is the server's limit on an encrypted item (api.md §1).
const MaxItemBlob = 64 * 1024

// Mode says how fresh the data a Session shows is.
type Mode int

const (
	// ModeOnline: a linearizable read was served (a majority is reachable).
	ModeOnline Mode = iota
	// ModeStale: only a stale read from some node was possible; writes are refused.
	ModeStale
	// ModeOffline: no server answered; the local cache is shown; writes are refused.
	ModeOffline
	// ModeOlder: the servers show older data than this device has seen (a
	// restored backup, or an attack). The cache is shown; writes are refused;
	// only an explicit recovery moves on (crypto.md §6.4).
	ModeOlder
)

func (m Mode) String() string {
	switch m {
	case ModeOnline:
		return "online"
	case ModeStale:
		return "stale"
	case ModeOlder:
		return "older"
	default:
		return "offline"
	}
}

// Deps are a Session's collaborators.
type Deps struct {
	// API may be nil for purely offline use.
	API *API
	// Store may be nil (nothing is persisted).
	Store *Store
	// CacheToken keeps the bearer token in token.json (config no_token_cache inverted).
	CacheToken bool
	// Now is the clock (default time.Now).
	Now func() time.Time
	// KDF returns the parameters for a new account / password change
	// (default vaultcrypto.DefaultKDFParams: t=3, m=64 MiB, p=4). The
	// acceptance bounds of crypto.md §2 are enforced regardless.
	KDF func() api.KDFParams
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deps) kdf() api.KDFParams {
	if d.KDF != nil {
		return d.KDF()
	}
	return vaultcrypto.DefaultKDFParams()
}

// LockReason says why a vault's contents are unavailable.
type LockReason string

const (
	NotLocked LockReason = ""
	// LockPending: shared by someone whose fingerprint this device has not
	// verified (or whose key replaced an accepted one): nothing is decrypted
	// until the user accepts it (AcceptVault).
	LockPending LockReason = "pending"
	// LockUndecryptable: the vault key could not be opened.
	LockUndecryptable LockReason = "undecryptable"
	// LockKeyMismatch: the sender's key contradicts the trust store.
	LockKeyMismatch LockReason = "key_mismatch"
	// LockContinuity: offered at a lower epoch, or at the same epoch with a
	// different key, than this device accepted before (crypto.md §6.4 rule 4).
	LockContinuity LockReason = "continuity"
	// LockInvalid: structurally wrong (personal vault wrapped by someone else,
	// roster that does not list this user with their key).
	LockInvalid LockReason = "invalid"
)

// PendingInfo describes who offered a pending vault.
type PendingInfo struct {
	SenderID          string
	SenderName        string
	SenderFingerprint string
	SenderVerified    bool
	// Replaced: this device had accepted the vault before, and the new key came
	// from someone who was not an owner then.
	Replaced bool
}

// MemberView is a vault member (from the roster) joined with the directory.
type MemberView struct {
	UserID      string
	Username    string
	Role        string
	Fingerprint string
	Verified    bool
	Disabled    bool
	KeyMismatch bool
	InRoster    bool
	InServer    bool
	// Note explains a discrepancy between the roster and the server's list.
	Note string
}

// ItemView is one item of a vault.
type ItemView struct {
	ID        string
	Version   uint64
	UpdatedAt int64 // unix ms
	UpdatedBy string
	// Item is nil if the blob could not be opened or decoded (then Err is set).
	Item *vaultcrypto.Item
	Err  string
}

// VaultView is a decrypted view of one vault.
type VaultView struct {
	ID               string
	Name             string
	Personal         bool
	KeyEpoch         uint32
	Role             string // the server's view of the caller's role
	RekeyRecommended bool
	MetaVersion      uint64
	RosterVersion    uint64
	Rev              uint64
	Members          []MemberView
	Items            []ItemView
	Locked           LockReason
	LockDetail       string
	Pending          *PendingInfo
	// MetaErr: the vault name could not be read.
	MetaErr bool
	// RosterBroken: the roster did not open or parse; an owner can repair it.
	RosterBroken bool
	// Discrepancies lists differences between the server's member list and the roster.
	Discrepancies []string
}

// Readable reports whether the vault's contents are decrypted.
func (v *VaultView) Readable() bool { return v.Locked == NotLocked }

// UserInfo describes a household member (a contact).
type UserInfo struct {
	UserID      string
	Username    string
	PublicKey   vaultcrypto.PublicKey
	Fingerprint string
	Verified    bool
	Disabled    bool
	IsAdmin     bool
	KeyMismatch bool
	Self        bool
}

type vaultSecret struct {
	vk     *vaultcrypto.SymmetricKey
	epoch  uint32
	meta   *vaultcrypto.VaultMeta // nil if unreadable
	roster *vaultcrypto.Roster    // nil if broken
}

// Session is the crypto-aware client. It holds unlocked key material in
// memory only. A Session is not safe for concurrent use.
type Session struct {
	d Deps

	UserID   string
	Username string
	isAdmin  bool

	mode       Mode
	lastSynced time.Time
	locked     bool
	secrets    *vaultcrypto.AccountSecrets
	loginKey   vaultcrypto.SymmetricKey
	raw        *api.SyncResponse
	vaultKeys  map[string]vaultSecret
	directory  map[string]api.DirectoryUser
	trust      *TrustStore
	mismatch   map[string]*KeyMismatchError
	warnings   []string
	vaults     []*VaultView
	forced     map[string]bool // vaults the user explicitly accepted in this session
	prefetch   *prefetch       // Open only: the first Sync's answer, requested early
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

// RegisterParams are the inputs of Register.
type RegisterParams struct {
	Username string
	Password string
	// InviteCode is an invite code, or the bootstrap token for the first user.
	InviteCode string
	// KDF overrides Deps.KDF (still subject to the bounds).
	KDF *api.KDFParams
}

// newVaultRequest makes a vault that sec owns: a fresh key wrapped to its
// owner, the sealed name and the one-member roster. The returned trust record
// is stored BEFORE the request is sent (crypto.md §6.4).
func newVaultRequest(sec *vaultcrypto.AccountSecrets, name string) (api.CreateVaultRequest, *VaultTrust, error) {
	req := api.CreateVaultRequest{VaultID: vaultcrypto.NewID()}
	vk := vaultcrypto.NewVaultKey()
	defer vk.Zero()
	wk, err := vaultcrypto.WrapVaultKey(vk, vaultcrypto.WrapContext{VaultID: req.VaultID, KeyEpoch: 1, SenderID: sec.UserID, RecipientID: sec.UserID}, &sec.PrivateKey, &sec.PublicKey)
	if err != nil {
		return req, nil, err
	}
	req.WrappedKey = api.WrappedKey{SenderID: sec.UserID, Blob: wk}
	if req.EncMeta, err = vaultcrypto.EncryptVaultMeta(vk, req.VaultID, 1, &vaultcrypto.VaultMeta{Name: name}); err != nil {
		return req, nil, err
	}
	roster := &vaultcrypto.Roster{V: 1, Members: []vaultcrypto.RosterMember{{ID: sec.UserID, PublicKey: sec.PublicKey, Role: vaultcrypto.RoleOwner}}}
	if req.EncRoster, err = vaultcrypto.EncryptRoster(vk, req.VaultID, 1, roster); err != nil {
		return req, nil, err
	}
	return req, &VaultTrust{Epoch: 1, Commitment: vaultcrypto.VaultKeyCommitment(vk, req.VaultID, 1), Owners: []OwnerKey{{ID: sec.UserID, PublicKey: sec.PublicKey.Bytes()}}}, nil
}

// Register creates an account (and its personal vault) and returns an online
// session. The master password must satisfy the policy floor
// (vaultcrypto.CheckMasterPassword); a *vaultcrypto.PolicyError is returned
// otherwise, before anything is derived or sent.
func Register(ctx context.Context, d Deps, p RegisterParams) (*Session, error) {
	if d.API == nil {
		return nil, errors.New("register needs a server")
	}
	username, err := vaultcrypto.NormalizeUsername(p.Username)
	if err != nil {
		return nil, &UserError{Msg: "invalid username: " + err.Error()}
	}
	if err := vaultcrypto.CheckMasterPassword(p.Password, username); err != nil {
		return nil, err
	}
	kdf := d.kdf()
	if p.KDF != nil {
		kdf = *p.KDF
	}
	mk, err := vaultcrypto.DeriveMasterKeys(username, p.Password, kdf) // enforces the parameter bounds
	if err != nil {
		return nil, err
	}
	userID := vaultcrypto.NewID()
	secrets, up, err := vaultcrypto.NewAccount(userID, mk)
	if err != nil {
		return nil, err
	}
	loginKey := mk.LoginKey
	mk.EncKey.Zero()

	personal, vt, err := newVaultRequest(secrets, "Personal")
	if err != nil {
		return nil, err
	}

	s := &Session{d: d, UserID: userID, Username: username, secrets: secrets, loginKey: loginKey, mode: ModeOnline,
		mismatch: map[string]*KeyMismatchError{}, forced: map[string]bool{}}
	s.trust = loadTrust(d.Store, secrets, false)
	s.selfContact()
	// A key this device generated is recorded BEFORE it is sent (crypto.md §6.4).
	s.trust.setVault(personal.VaultID, vt)
	if err := s.trust.Save(); err != nil {
		return nil, err
	}
	req := &api.RegisterRequest{
		InviteCode:        strings.TrimSpace(p.InviteCode),
		UserID:            userID,
		Username:          username,
		KDF:               kdf,
		LoginKey:          loginKey[:],
		PublicKey:         up.PublicKey,
		WrappedAccountKey: up.WrappedAccountKey,
		EncPrivateKey:     up.EncPrivateKey,
		PersonalVault:     personal,
	}
	lr, err := d.API.Register(ctx, req)
	if err != nil {
		if !OutcomeUnknown(err) && d.Store != nil {
			// The account does not exist: leave no trust file for it behind.
			_ = d.Store.DeleteTrust(userID)
		}
		s.Lock()
		return nil, err
	}
	if lr.UserID != userID || lr.Username != username {
		s.Lock()
		return nil, &ProtocolError{Msg: "the registration response names a different account"}
	}
	s.isAdmin = lr.IsAdmin
	s.saveToken(lr)
	if err := s.Sync(ctx); err != nil {
		s.Lock()
		return nil, err
	}
	s.learnNodes(ctx)
	return s, nil
}

// cacheOf returns the offline cache if it belongs to username (nil if there is
// none, it is someone else's or it cannot be read).
func cacheOf(d Deps, username string) *Cache {
	if d.Store == nil {
		return nil
	}
	if c, _ := d.Store.LoadCache(); c != nil && c.Username == username {
		return c
	}
	return nil
}

// Login signs in online: prelogin, derive keys (the KDF bounds are enforced
// BEFORE deriving, and parameters weaker than the cached account's are
// refused), login, sync, unlock. It falls back to stale reads inside the API
// client when no quorum is available.
func Login(ctx context.Context, d Deps, username, password string) (*Session, error) {
	s, resp, err := loginRaw(ctx, d, username, password)
	if err != nil {
		return nil, err
	}
	if err := s.applySync(resp, true); err != nil {
		s.Lock()
		return nil, err
	}
	s.learnNodes(ctx)
	return s, nil
}

// UnlockOffline unlocks from the cached SyncResponse with no server at all.
// Opening the wrapped account key under the password IS the password check.
// The session is read-only.
func UnlockOffline(d Deps, username, password string) (*Session, error) {
	username, err := vaultcrypto.NormalizeUsername(username)
	if err != nil {
		return nil, &UserError{Msg: "invalid username: " + err.Error()}
	}
	if d.Store == nil {
		return nil, ErrNoCache
	}
	cache, err := d.Store.LoadCache()
	if err != nil {
		return nil, err
	}
	return unlockCached(d, cache, username, password)
}

func unlockCached(d Deps, cache *Cache, username, password string) (*Session, error) {
	if cache == nil || cache.Username != username || cache.Sync.Account == nil {
		return nil, ErrNoCache
	}
	mk, err := vaultcrypto.DeriveMasterKeys(username, password, cache.Sync.Account.KDF)
	if err != nil {
		return nil, err
	}
	defer mk.EncKey.Zero()
	s, err := newFromAccount(d, cache.Sync.Account, username, mk, true)
	if err != nil {
		return nil, err
	}
	s.lastSynced = time.UnixMilli(cache.SavedAt)
	if err := s.applySync(&cache.Sync, false); err != nil {
		s.Lock()
		return nil, err
	}
	s.mode = ModeOffline
	return s, nil
}

// Open is what a command-line invocation uses. With a local cache it unlocks
// from the cache (that is the password check, and it needs no prelogin), then
// tries to reach a server using the cached token or, failing that, a login
// with the derived login key. If no server can serve a fresh read the
// session stays stale/offline on the cached data; check Mode and Notice.
// Without a cache, or if the cache does not open with this password (the
// password may have been changed from another device), it does a full Login.
func Open(ctx context.Context, d Deps, username, password string) (*Session, error) {
	username, err := vaultcrypto.NormalizeUsername(username)
	if err != nil {
		return nil, &UserError{Msg: "invalid username: " + err.Error()}
	}
	var cache *Cache
	if d.Store != nil {
		if cache, err = d.Store.LoadCache(); err != nil {
			return nil, err
		}
	}
	if cache != nil && cache.Username == username && cache.Sync.Account != nil {
		pf := startPrefetch(ctx, d, username)
		defer pf.stop()
		s, err := unlockCached(d, cache, username, password)
		if err == nil {
			if d.API == nil {
				return s, nil
			}
			s.prefetch = pf
			if cerr := s.connect(ctx); cerr != nil {
				s.Lock()
				if errors.Is(cerr, errPasswordChangedElsewhere) {
					return Login(ctx, d, username, password)
				}
				return nil, cerr
			}
			return s, nil
		}
		if !errors.Is(err, ErrWrongPassword) && !errors.Is(err, vaultcrypto.ErrDecrypt) {
			return nil, err
		}
		if d.API == nil {
			return nil, ErrWrongPassword
		}
	}
	if d.API == nil {
		return nil, ErrNoCache
	}
	s, err := Login(ctx, d, username, password)
	if err != nil && IsUnavailable(err) && cache != nil && cache.Username == username {
		// The cached copy rejected the password and no server can say whether it
		// was changed elsewhere: report the wrong password, not the outage.
		return nil, fmt.Errorf("%w (and no server can be reached to check whether it was changed elsewhere)", ErrWrongPassword)
	}
	return s, err
}

// prefetch is the sync request of a command-line start, sent with the cached
// token while the (deliberately slow) key derivation runs, so the round trip
// to the servers is not added to it. Its answer is only looked at once the
// password has opened the cache; a wrong password just wastes the request.
type prefetch struct {
	cancel context.CancelFunc
	done   chan struct{}
	resp   *api.SyncResponse
	err    error
}

// startPrefetch returns nil when there is no usable cached token: the start
// then logs in after unlocking, as before.
func startPrefetch(ctx context.Context, d Deps, username string) *prefetch {
	if d.API == nil || d.Store == nil {
		return nil
	}
	t, _ := d.Store.LoadToken()
	if t == nil || t.Username != username {
		return nil
	}
	d.API.SetToken(t.Token)
	ctx, cancel := context.WithCancel(ctx)
	p := &prefetch{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		p.resp, p.err = d.API.Sync(ctx, 0)
	}()
	return p
}

func (p *prefetch) stop() {
	if p != nil {
		p.cancel()
	}
}

var errPasswordChangedElsewhere = errors.New("password changed elsewhere")

// connect brings an offline-unlocked session online if possible.
func (s *Session) connect(ctx context.Context) error {
	if s.d.Store != nil {
		if t, _ := s.d.Store.LoadToken(); t != nil && t.Username == s.Username {
			s.d.API.SetToken(t.Token)
		}
	}
	if s.d.API.Token() == "" {
		if err := s.doLogin(ctx); err != nil {
			return s.connectErr(err)
		}
	}
	if err := s.Sync(ctx); err != nil {
		return s.connectErr(err)
	}
	return nil
}

func (s *Session) connectErr(err error) error {
	switch {
	case IsUnavailable(err):
		s.setOfflineNotice(err)
		return nil
	case errors.Is(err, ErrSessionExpired):
		return errPasswordChangedElsewhere
	}
	return err
}

func (s *Session) setOfflineNotice(err error) {
	var ae *APIError
	if errors.As(err, &ae) {
		s.mode = ModeStale
	} else {
		s.mode = ModeOffline
	}
}

// newFromAccount unlocks the account block under mk. The identity it
// establishes (user ID from the block, the username the user typed, the public
// key derived from the unlocked private key) is what every later sync is
// checked against (crypto.md §4).
func newFromAccount(d Deps, acct *api.Account, username string, mk *vaultcrypto.MasterKeys, hadState bool) (*Session, error) {
	if acct.Username != username {
		return nil, &ProtocolError{Msg: fmt.Sprintf("the account block belongs to %q, not %q", acct.Username, username)}
	}
	if !vaultcrypto.ValidID(acct.UserID) {
		return nil, &ProtocolError{Msg: "malformed user ID in the account block"}
	}
	sec, err := vaultcrypto.UnlockAccount(acct.UserID, mk, acct.PublicKey, acct.WrappedAccountKey, acct.EncPrivateKey)
	if err != nil {
		if errors.Is(err, vaultcrypto.ErrDecrypt) {
			return nil, ErrWrongPassword
		}
		return nil, err
	}
	s := &Session{d: d, UserID: acct.UserID, Username: username, isAdmin: acct.IsAdmin, secrets: sec, loginKey: mk.LoginKey, mode: ModeOnline,
		mismatch: map[string]*KeyMismatchError{}, forced: map[string]bool{}}
	s.trust = loadTrust(d.Store, sec, hadState)
	s.selfContact()
	return s, nil
}

// selfContact records the user's own identity, from the unlocked key, as a
// verified contact.
func (s *Session) selfContact() {
	if c, ok := s.trust.contact(s.UserID); ok && bytes.Equal(c.PublicKey, s.secrets.PublicKey[:]) && c.Username == s.Username && c.Verified {
		return
	}
	s.trust.addContact(Contact{UserID: s.UserID, Username: s.Username, PublicKey: s.secrets.PublicKey.Bytes(), Verified: true, FirstSeen: s.d.now().UnixMilli()})
}

func (s *Session) learnNodes(ctx context.Context) {
	if s.d.API == nil {
		return
	}
	_, _ = s.d.API.RefreshCluster(ctx) // best effort; OnNodesChanged persists the list
}

// Lock zeroes every key in memory. The Session is unusable afterwards.
func (s *Session) Lock() {
	if s.locked {
		return
	}
	s.locked = true
	if s.secrets != nil {
		s.secrets.Zero()
	}
	s.loginKey.Zero()
	for _, v := range s.vaultKeys {
		v.vk.Zero()
	}
	s.vaultKeys = nil
	s.raw, s.vaults, s.directory = nil, nil, nil
	if s.trust != nil {
		s.trust.zero()
	}
	if s.d.API != nil {
		s.d.API.SetToken("")
	}
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

func (s *Session) Mode() Mode            { return s.mode }
func (s *Session) IsAdmin() bool         { return s.isAdmin }
func (s *Session) LastSynced() time.Time { return s.lastSynced }
func (s *Session) Rev() uint64 {
	if s.raw == nil {
		return 0
	}
	return s.raw.Rev
}

// Fingerprint is the fingerprint of the user's own identity.
func (s *Session) Fingerprint() string {
	return fingerprintOf(s.UserID, s.Username, s.secrets.PublicKey[:])
}

// KeyMismatches lists users whose presented key/name currently contradicts the trust store.
func (s *Session) KeyMismatches() []*KeyMismatchError {
	ids := make([]string, 0, len(s.mismatch))
	for id := range s.mismatch {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*KeyMismatchError, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.mismatch[id])
	}
	return out
}

// TrustReset reports that the trust store was missing or unreadable and
// started empty (every contact unverified again).
func (s *Session) TrustReset() bool { return s.trust.Reset }

// Warnings lists everything the user should see: current key mismatches,
// recorded mismatch events not yet dismissed, locked and pending vaults,
// roster discrepancies and a reset trust store.
func (s *Session) Warnings() []string {
	var w []string
	if s.trust.Reset {
		w = append(w, "the local trust store was missing or unreadable and has been reset: every contact is unverified again")
	}
	if o := s.trust.older(); o != nil {
		w = append(w, (&RestoredStateError{ServerRev: o.ServerRev, SeenRev: o.SeenRev, LowerEpochVaults: o.Vaults}).Error())
	}
	cur := map[string]bool{}
	for _, m := range s.KeyMismatches() {
		cur[m.UserID] = true
		w = append(w, m.Error())
	}
	for _, e := range s.trust.events() {
		if !e.Dismissed && !cur[e.UserID] {
			w = append(w, fmt.Sprintf("earlier warning: the %s of %q was presented differently by the server (trusted %s, offered %s); dismiss with `fvault contacts dismiss %s` once you understand why", e.Kind, e.Username, e.PinnedFingerprint, e.OfferedFingerprint, e.Username))
		}
	}
	for _, v := range s.vaults {
		id := short8(v.ID)
		switch v.Locked {
		case LockPending:
			w = append(w, fmt.Sprintf("vault %s is waiting for you to confirm the sender, %s: run `fvault vault accept %s`", id, v.Pending.SenderName, id))
		case NotLocked:
			for _, d := range v.Discrepancies {
				w = append(w, fmt.Sprintf("vault %q: %s", v.Name, d))
			}
		default:
			w = append(w, fmt.Sprintf("vault %s is LOCKED (%s): %s", id, v.Locked, v.LockDetail))
		}
	}
	return append(w, s.warnings...)
}

func short8(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// Vaults returns the decrypted vault views (read-only; replaced on every sync).
func (s *Session) Vaults() []*VaultView { return s.vaults }

// Vault returns one vault by exact ID.
func (s *Session) Vault(id string) *VaultView {
	for _, v := range s.vaults {
		if v.ID == id {
			return v
		}
	}
	return nil
}

// Notice describes, for a human, why the data may not be fresh ("" if online).
func (s *Session) Notice() string {
	age := ""
	if !s.lastSynced.IsZero() {
		age = fmt.Sprintf(", saved %s ago", HumanAge(s.d.now().Sub(s.lastSynced)))
	}
	switch s.mode {
	case ModeOlder:
		return (&RestoredStateError{ServerRev: s.olderInfo().ServerRev, SeenRev: s.olderInfo().SeenRev, LowerEpochVaults: s.olderInfo().Vaults}).Error()
	case ModeStale:
		return "a majority of the servers (2 of 3) cannot be reached, so you see the last copy one server has, which may be out of date; saving is disabled"
	case ModeOffline:
		return "no server can be reached; showing the offline copy on this device" + age + "; saving is disabled"
	}
	return ""
}

// HumanAge formats an age the way notices do.
func HumanAge(d time.Duration) string {
	switch {
	case d < 2*time.Second:
		return "a moment"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// ---------------------------------------------------------------------------
// Authenticated calls
// ---------------------------------------------------------------------------

func (s *Session) saveToken(lr *api.LoginResponse) {
	if s.d.Store == nil || !s.d.CacheToken || lr == nil {
		return
	}
	_ = s.d.Store.SaveToken(&TokenFile{Username: s.Username, Token: lr.Token, ExpiresAt: lr.ExpiresAt})
}

func (s *Session) doLogin(ctx context.Context) error {
	if s.locked {
		return ErrLocked
	}
	lr, err := s.d.API.Login(ctx, s.Username, s.loginKey[:])
	if err != nil {
		if IsCode(err, api.CodeUnauthorized) {
			if s.d.Store != nil {
				_ = s.d.Store.DeleteToken()
			}
			return ErrSessionExpired
		}
		return err
	}
	if lr.UserID != s.UserID || lr.Username != s.Username {
		s.d.API.SetToken("")
		return &ProtocolError{Msg: "the login response names a different account than the one this device unlocked"}
	}
	s.saveToken(lr)
	return nil
}

// call runs an authenticated API call; on a 401 (expired token) it logs in
// once more with the in-memory login key and retries.
func (s *Session) call(ctx context.Context, fn func() error) error {
	if s.locked {
		return ErrLocked
	}
	if s.d.API == nil {
		return &ReadOnlyError{Reason: ReasonOffline}
	}
	err := fn()
	if IsCode(err, api.CodeUnauthorized) {
		if lerr := s.doLogin(ctx); lerr != nil {
			return lerr
		}
		return fn()
	}
	return err
}

// result runs an API call that returns a value through s.call or s.write.
func result[T any](run func(context.Context, func() error) error, ctx context.Context, f func() (T, error)) (r T, err error) {
	err = run(ctx, func() (e error) { r, e = f(); return e })
	return r, err
}

// write refuses when read-only and maps connectivity failures to the right mode.
func (s *Session) write(ctx context.Context, fn func() error) error {
	if s.locked {
		return ErrLocked
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	err := s.call(ctx, fn)
	var ne *NetworkError
	switch {
	case errors.As(err, &ne) && !ne.OutcomeUnknown:
		s.mode = ModeOffline
	case IsCode(err, api.CodeUnavailable):
		s.mode = ModeStale
	}
	return err
}

// ---------------------------------------------------------------------------
// Sync and views
// ---------------------------------------------------------------------------

// Sync fetches the current state (linearizable, else stale) and rebuilds the
// views. On failure the existing views and the cache are left untouched.
func (s *Session) Sync(ctx context.Context) error {
	if s.locked {
		return ErrLocked
	}
	if s.d.API == nil {
		return &ReadOnlyError{Reason: ReasonOffline}
	}
	var since uint64
	if s.raw != nil && s.mode == ModeOnline {
		since = s.raw.Rev
	}
	resp, err := result(s.call, ctx, func() (*api.SyncResponse, error) {
		if p := s.prefetch; p != nil && since == 0 {
			s.prefetch = nil // only the first attempt; a retry after a 401 asks again
			<-p.done
			return p.resp, p.err
		}
		return s.d.API.Sync(ctx, since)
	})
	if err != nil {
		return err
	}
	return s.applySync(resp, true)
}

// Refresh re-syncs and converts connectivity failures into the session mode
// instead of an error. It returns the resulting mode.
func (s *Session) Refresh(ctx context.Context) (Mode, error) {
	if s.locked {
		return s.mode, ErrLocked
	}
	if s.d.API != nil && s.d.API.Token() == "" {
		if err := s.doLogin(ctx); err != nil {
			if IsUnavailable(err) {
				s.setOfflineNotice(err)
				return s.mode, nil
			}
			return s.mode, err
		}
	}
	if err := s.Sync(ctx); err != nil {
		if IsUnavailable(err) {
			s.setOfflineNotice(err)
			return s.mode, nil
		}
		return s.mode, err
	}
	return s.mode, nil
}

// validateSync checks a full sync response (crypto.md §4, §6.2). It rejects
// the whole response on the first problem; nothing is applied.
func (s *Session) validateSync(r *api.SyncResponse) error {
	bad := func(format string, a ...any) error { return &ProtocolError{Msg: fmt.Sprintf(format, a...)} }
	if r.Account == nil {
		return bad("no account block")
	}
	a := r.Account
	// Own identity: what we unlocked, never what the server says.
	if a.UserID != s.UserID {
		return bad("the account block has a different user ID than this device unlocked")
	}
	if a.Username != s.Username {
		return bad("the account block has a different username than this device unlocked")
	}
	if !bytes.Equal(a.PublicKey, s.secrets.PublicKey[:]) {
		return bad("the account public key differs from the unlocked key")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	sawSelf := false
	for _, d := range r.Directory {
		if !vaultcrypto.ValidID(d.UserID) {
			return bad("malformed user ID in the directory")
		}
		if n, err := vaultcrypto.NormalizeUsername(d.Username); err != nil || n != d.Username {
			return bad("malformed username in the directory")
		}
		if len(d.PublicKey) != 32 {
			return bad("a directory public key is not 32 bytes")
		}
		if ids[d.UserID] {
			return bad("duplicate user ID in the directory")
		}
		if names[d.Username] {
			return bad("duplicate username in the directory")
		}
		ids[d.UserID], names[d.Username] = true, true
		if d.UserID == s.UserID {
			sawSelf = true
			if d.Username != s.Username || !bytes.Equal(d.PublicKey, s.secrets.PublicKey[:]) {
				return bad("the directory entry for this account does not match the unlocked identity")
			}
		}
	}
	if !sawSelf {
		return bad("this account is missing from the directory")
	}
	vaultIDs := map[string]bool{}
	for _, v := range r.Vaults {
		if !vaultcrypto.ValidID(v.ID) {
			return bad("malformed vault ID")
		}
		if vaultIDs[v.ID] {
			return bad("duplicate vault ID")
		}
		vaultIDs[v.ID] = true
		if v.KeyEpoch < 1 {
			return bad("vault key epoch below 1")
		}
		itemIDs := map[string]bool{}
		for _, it := range v.Items {
			if !vaultcrypto.ValidID(it.ID) {
				return bad("malformed item ID")
			}
			if itemIDs[it.ID] {
				return bad("duplicate item ID in a vault")
			}
			itemIDs[it.ID] = true
		}
		memIDs := map[string]bool{}
		for _, m := range v.Members {
			if !vaultcrypto.ValidID(m.UserID) {
				return bad("malformed member ID")
			}
			if memIDs[m.UserID] {
				return bad("duplicate member in a vault")
			}
			memIDs[m.UserID] = true
		}
		if !vaultcrypto.ValidID(v.MyKey.SenderID) {
			return bad("malformed sender ID on a vault key")
		}
	}
	return nil
}

func (s *Session) applySync(resp *api.SyncResponse, persist bool) error {
	if resp.Unchanged && s.raw != nil {
		s.lastSynced = s.d.now()
		s.mode = modeOf(resp)
		return nil
	}
	if err := s.validateSync(resp); err != nil {
		return err
	}
	// Older data than this device has seen: a lower rev, or a vault at a lower
	// key epoch than recorded. Expected only after a restored backup; the
	// client cannot tell it from a rollback, so it stops using the answer.
	baseline := s.trust.maxRev()
	if s.raw != nil && s.raw.Rev > baseline {
		baseline = s.raw.Rev
	}
	lower := s.lowerEpochVaults(resp)
	if !resp.Stale && (resp.Rev < baseline || len(lower) > 0) {
		info := &OlderState{ServerRev: resp.Rev, SeenRev: baseline, Vaults: lower, At: s.d.now().UnixMilli()}
		if resp.Rev >= baseline {
			info.SeenRev = resp.Rev
		}
		s.trust.setOlder(info)
		_ = s.trust.Save()
		s.mode = ModeOlder
		if s.raw == nil {
			return &RestoredStateError{ServerRev: info.ServerRev, SeenRev: info.SeenRev, LowerEpochVaults: lower}
		}
		return nil
	}
	if resp.Rev < baseline {
		// A stale answer older than what we show: keep what we have.
		s.mode = ModeStale
		return nil
	}
	s.warnings = nil
	s.raw = resp
	s.isAdmin = resp.Account.IsAdmin
	s.directory = make(map[string]api.DirectoryUser, len(resp.Directory))
	for _, d := range resp.Directory {
		s.directory[d.UserID] = d
	}
	s.observeContacts()
	s.buildViews(resp)
	if persist {
		s.trust.noteRev(resp.Rev)
		if !resp.Stale {
			s.trust.setOlder(nil)
		}
	}
	if err := s.trust.Save(); err != nil {
		return fmt.Errorf("saving the trust store: %w", err)
	}
	if persist {
		s.lastSynced = s.d.now()
		if s.d.Store != nil {
			if _, err := s.d.Store.SaveCacheUnlessOlder(&Cache{Username: s.Username, SavedAt: s.lastSynced.UnixMilli(), Sync: *resp}); err != nil {
				return fmt.Errorf("saving offline cache: %w", err)
			}
		}
	}
	s.mode = modeOf(resp)
	return nil
}

// lowerEpochVaults lists vaults the response offers at a lower key epoch than
// this device recorded (not counting a rekey of ours whose outcome was unknown).
func (s *Session) lowerEpochVaults(r *api.SyncResponse) []string {
	var out []string
	for _, v := range r.Vaults {
		vt := s.trust.vault(v.ID)
		if vt == nil || v.KeyEpoch >= vt.Epoch {
			continue
		}
		if vt.Prior != nil && v.KeyEpoch == vt.Prior.Epoch {
			continue
		}
		out = append(out, v.ID)
	}
	sort.Strings(out)
	return out
}

func (s *Session) olderInfo() OlderState {
	if o := s.trust.older(); o != nil {
		return *o
	}
	return OlderState{}
}

// Recovery returns the recorded "servers show older data" state, if any.
func (s *Session) Recovery() *OlderState { return s.trust.older() }

func modeOf(r *api.SyncResponse) Mode {
	if r.Stale {
		return ModeStale
	}
	return ModeOnline
}

// observeContacts feeds the directory into the trust store: unseen users
// become unverified contacts; a known user ID with another key or username,
// or a known username under another user ID, is a permanent mismatch.
func (s *Session) observeContacts() {
	s.mismatch = map[string]*KeyMismatchError{}
	now := s.d.now().UnixMilli()
	ids := make([]string, 0, len(s.directory))
	for id := range s.directory {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := s.directory[id]
		c, known := s.trust.contact(id)
		if known {
			switch {
			case !bytes.Equal(c.PublicKey, d.PublicKey):
				s.flagMismatch(id, c.Username, MismatchKey, fingerprintOf(c.UserID, c.Username, c.PublicKey), fingerprintOf(d.UserID, d.Username, d.PublicKey))
			case c.Username != d.Username:
				s.flagMismatch(id, c.Username, MismatchUsername, fingerprintOf(c.UserID, c.Username, c.PublicKey), fingerprintOf(d.UserID, d.Username, d.PublicKey))
			}
			continue
		}
		if other, ok := s.trust.contactByName(d.Username); ok && other.UserID != id {
			// A known name under a new account: neither may be trusted.
			pf := fingerprintOf(other.UserID, other.Username, other.PublicKey)
			of := fingerprintOf(d.UserID, d.Username, d.PublicKey)
			s.flagMismatch(id, d.Username, MismatchUserID, pf, of)
			s.flagMismatch(other.UserID, other.Username, MismatchUserID, pf, of)
			continue
		}
		s.trust.addContact(Contact{UserID: id, Username: d.Username, PublicKey: append([]byte(nil), d.PublicKey...), FirstSeen: now})
	}
}

// flagMismatch records a permanent mismatch event and shows it as a current
// warning (the first one found for a user stays).
func (s *Session) flagMismatch(userID, username, kind, pinnedFP, offeredFP string) {
	s.trust.recordEvent(MismatchEvent{UserID: userID, Username: username, Kind: kind, PinnedFingerprint: pinnedFP, OfferedFingerprint: offeredFP})
	if _, ok := s.mismatch[userID]; !ok {
		s.mismatch[userID] = &KeyMismatchError{UserID: userID, Username: username, Kind: kind, PinnedFingerprint: pinnedFP, OfferedFingerprint: offeredFP}
	}
}

func lockView(v *VaultView, r LockReason, detail string) {
	v.Locked, v.LockDetail = r, detail
}

// buildViews decides, per vault, whether its key may be accepted (crypto.md
// §6.4), and decrypts only accepted vaults.
func (s *Session) buildViews(resp *api.SyncResponse) {
	// An entry whose version is unchanged (in the same vault at the same key
	// epoch) keeps its decrypted view instead of being decrypted again.
	type itemKey struct {
		vault, item string
		epoch       uint32
		version     uint64
	}
	prev := map[itemKey]ItemView{}
	for _, v := range s.vaults {
		for _, it := range v.Items {
			prev[itemKey{v.ID, it.ID, v.KeyEpoch, it.Version}] = it
		}
	}
	newKeys := map[string]vaultSecret{}
	views := make([]*VaultView, 0, len(resp.Vaults))
	for _, v := range resp.Vaults {
		view := &VaultView{
			ID: v.ID, Name: "(locked)", Personal: v.Personal, KeyEpoch: v.KeyEpoch, Role: v.MyRole,
			RekeyRecommended: v.RekeyRecommended, MetaVersion: v.MetaVersion, RosterVersion: v.RosterVersion, Rev: v.Rev,
		}
		views = append(views, view)
		sec, ok := s.acceptVault(&v, view)
		if !ok {
			continue
		}
		newKeys[v.ID] = sec
		if sec.meta != nil {
			view.Name = sec.meta.Name
		} else {
			view.Name, view.MetaErr = "(unreadable name)", true
		}
		view.RosterBroken = sec.roster == nil
		s.fillMembers(&v, view, sec)
		for _, it := range v.Items {
			if hit, ok := prev[itemKey{v.ID, it.ID, v.KeyEpoch, it.Version}]; ok {
				view.Items = append(view.Items, hit)
				continue
			}
			iv := ItemView{ID: it.ID, Version: it.Version, UpdatedAt: it.UpdatedAt, UpdatedBy: it.UpdatedBy}
			if dec, err := vaultcrypto.DecryptItem(sec.vk, v.ID, it.ID, v.KeyEpoch, it.Blob); err == nil {
				iv.Item = dec
			} else {
				iv.Err = "this entry is unreadable"
			}
			view.Items = append(view.Items, iv)
		}
	}
	for _, old := range s.vaultKeys {
		old.vk.Zero()
	}
	s.vaultKeys = newKeys
	s.vaults = views
}

// acceptVault implements crypto.md §6.4 for one vault. On success it returns
// the opened vault secrets; otherwise it marks the view locked/pending and
// returns ok=false having decrypted nothing.
func (s *Session) acceptVault(v *api.Vault, view *VaultView) (vaultSecret, bool) {
	sender := v.MyKey.SenderID
	// 1. A personal vault is wrapped by its owner, nobody else.
	if v.Personal && sender != s.UserID {
		lockView(view, LockInvalid, "a personal vault's key must come from yourself, but the server offers one from someone else")
		return vaultSecret{}, false
	}
	// 2./3. Whose key opens the wrap: our own unlocked key, or the trust store's.
	var senderPub vaultcrypto.PublicKey
	var contact Contact
	if sender == s.UserID {
		senderPub = s.secrets.PublicKey
	} else {
		c, ok := s.trust.contact(sender)
		if !ok {
			lockView(view, LockUndecryptable, "the key was sent by a user this device has no contact for")
			return vaultSecret{}, false
		}
		if m := s.mismatch[sender]; m != nil {
			lockView(view, LockKeyMismatch, fmt.Sprintf("the key of %s changed (trusted %s, offered %s)", c.Username, m.PinnedFingerprint, m.OfferedFingerprint))
			return vaultSecret{}, false
		}
		contact = c
		copy(senderPub[:], c.PublicKey)
	}
	vk, err := vaultcrypto.UnwrapVaultKey(v.MyKey.Blob, vaultcrypto.WrapContext{VaultID: v.ID, KeyEpoch: v.KeyEpoch, SenderID: sender, RecipientID: s.UserID},
		&s.secrets.PrivateKey, &senderPub)
	if err != nil {
		lockView(view, LockUndecryptable, "the vault key could not be opened")
		return vaultSecret{}, false
	}
	fail := func(r LockReason, d string) (vaultSecret, bool) {
		vk.Zero()
		lockView(view, r, d)
		return vaultSecret{}, false
	}
	commit := vaultcrypto.VaultKeyCommitment(vk, v.ID, v.KeyEpoch)
	vt := s.trust.vault(v.ID)
	// A rekey this device started whose outcome was unknown: see what happened.
	if vt != nil && vt.Prior != nil {
		switch {
		case v.KeyEpoch == vt.Epoch && commit == vt.Commitment:
			vt.Prior = nil
			s.trust.setVault(v.ID, vt)
		case v.KeyEpoch == vt.Prior.Epoch && commit == vt.Prior.Commitment:
			vt = vt.Prior
			s.trust.setVault(v.ID, vt)
		}
	}
	// 4. Continuity.
	if vt != nil {
		if v.KeyEpoch < vt.Epoch {
			return fail(LockContinuity, fmt.Sprintf("the server offers key epoch %d but this device already accepted epoch %d (a rollback)", v.KeyEpoch, vt.Epoch))
		}
		if v.KeyEpoch == vt.Epoch && commit != vt.Commitment {
			return fail(LockContinuity, fmt.Sprintf("the server offers a different key for epoch %d than the one this device accepted", v.KeyEpoch))
		}
	}
	accepted := false
	switch {
	case sender == s.UserID:
		accepted = true
	case vt != nil && vt.Epoch == v.KeyEpoch && vt.Commitment == commit:
		accepted = true
	case vt != nil && vt.Epoch < v.KeyEpoch:
		if pk, ok := vt.ownerKey(sender); ok && bytes.Equal(pk, contact.PublicKey) {
			accepted = true
		}
	case vt == nil && contact.Verified:
		accepted = true
	}
	if !accepted && s.forced[v.ID] && contact.Verified {
		accepted = true // the user explicitly accepted this vault after verifying the sender
	}
	if !accepted {
		vk.Zero()
		lockView(view, LockPending, "shared by "+contact.Username+"; compare their fingerprint with them in person or on a phone call to open it")
		view.Pending = &PendingInfo{SenderID: sender, SenderName: contact.Username,
			SenderFingerprint: fingerprintOf(contact.UserID, contact.Username, contact.PublicKey), SenderVerified: contact.Verified, Replaced: vt != nil}
		return vaultSecret{}, false
	}
	// 5. The roster.
	sec := vaultSecret{vk: vk, epoch: v.KeyEpoch}
	if r, err := vaultcrypto.DecryptRoster(vk, v.ID, v.KeyEpoch, v.EncRoster); err == nil {
		me, ok := r.Member(s.UserID)
		if !ok || me.PublicKey != s.secrets.PublicKey {
			return fail(LockInvalid, "the vault's member list does not list you with your own key")
		}
		sec.roster = r
		for _, m := range r.Members {
			if c, ok := s.trust.contact(m.ID); ok && !bytes.Equal(c.PublicKey, m.PublicKey[:]) {
				s.flagMismatch(m.ID, c.Username, MismatchRoster, fingerprintOf(c.UserID, c.Username, c.PublicKey), fingerprintOf(c.UserID, c.Username, m.PublicKey[:]))
			}
		}
	}
	if m, err := vaultcrypto.DecryptVaultMeta(vk, v.ID, v.KeyEpoch, v.EncMeta); err == nil {
		sec.meta = m
	}
	// Record what was accepted (§6.4 rule 5).
	nt := &VaultTrust{Epoch: v.KeyEpoch, Commitment: commit}
	if vt != nil && vt.Prior != nil && vt.Epoch == v.KeyEpoch {
		nt.Prior = vt.Prior
	}
	if sec.roster != nil {
		for _, o := range sec.roster.Owners() {
			nt.Owners = append(nt.Owners, OwnerKey{ID: o.ID, PublicKey: o.PublicKey.Bytes()})
		}
	}
	if vt == nil || vt.Epoch != nt.Epoch || vt.Commitment != nt.Commitment || !sameOwners(vt.Owners, nt.Owners) {
		s.trust.setVault(v.ID, nt)
	}
	return sec, true
}

func sameOwners(a, b []OwnerKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || !bytes.Equal(a[i].PublicKey, b[i].PublicKey) {
			return false
		}
	}
	return true
}

// fillMembers builds the member list from the roster and notes every
// difference from the server's list.
func (s *Session) fillMembers(v *api.Vault, view *VaultView, sec vaultSecret) {
	server := map[string]api.Member{}
	for _, m := range v.Members {
		server[m.UserID] = m
	}
	mk := func(id, role string, pk []byte) MemberView {
		mv := MemberView{UserID: id, Username: "(unknown user)", Role: role, Verified: s.trust.isVerified(id), KeyMismatch: s.mismatch[id] != nil}
		if c, ok := s.trust.contact(id); ok {
			mv.Username = c.Username
			mv.Fingerprint = fingerprintOf(c.UserID, c.Username, c.PublicKey)
		} else if pk != nil {
			mv.Fingerprint = fingerprintOf(id, mv.Username, pk)
		}
		if d, ok := s.directory[id]; ok {
			mv.Disabled = d.Disabled
		}
		return mv
	}
	if sec.roster == nil {
		for _, m := range v.Members {
			mv := mk(m.UserID, m.Role, nil)
			mv.InServer, mv.Note = true, "member list unreadable: not authenticated"
			view.Members = append(view.Members, mv)
		}
		view.Discrepancies = append(view.Discrepancies, "the vault's member list is unreadable (an owner can rebuild it with `fvault vault rekey --repair`); the list below comes from the server and is not authenticated")
		return
	}
	for _, m := range sec.roster.Members {
		mv := mk(m.ID, m.Role, m.PublicKey[:])
		mv.InRoster = true
		if sm, ok := server[m.ID]; ok {
			mv.InServer = true
			if sm.Role != m.Role {
				mv.Note = fmt.Sprintf("the server says %s, the member list says %s", sm.Role, m.Role)
			}
		} else {
			mv.Note = "left: will lose access when the vault key is next replaced"
		}
		if mv.Note != "" {
			view.Discrepancies = append(view.Discrepancies, mv.Username+": "+mv.Note)
		}
		view.Members = append(view.Members, mv)
	}
	var extra []string
	for id := range server {
		if _, ok := sec.roster.Member(id); !ok {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		mv := mk(id, server[id].Role, nil)
		mv.InServer, mv.Note = true, "listed by the server but not in the vault's member list: ignored"
		view.Discrepancies = append(view.Discrepancies, mv.Username+": "+mv.Note)
		view.Members = append(view.Members, mv)
	}
}

// VaultLockedError is returned by operations on a vault that is pending or locked.
type VaultLockedError struct {
	VaultID string
	Reason  LockReason
	Detail  string
}

func (e *VaultLockedError) Error() string {
	if e.Reason == LockPending {
		return fmt.Sprintf("vault %s is waiting for you to confirm the sender: %s (run `fvault vault accept %s`)", short8(e.VaultID), e.Detail, short8(e.VaultID))
	}
	return fmt.Sprintf("vault %s is locked (%s): %s", short8(e.VaultID), e.Reason, e.Detail)
}

func (s *Session) mustVault(id string) (*VaultView, vaultSecret, error) {
	v := s.Vault(id)
	if v == nil {
		return nil, vaultSecret{}, &UserError{Msg: "that vault is not available"}
	}
	sec, ok := s.vaultKeys[id]
	if !ok {
		return nil, vaultSecret{}, &VaultLockedError{VaultID: id, Reason: v.Locked, Detail: v.LockDetail}
	}
	return v, sec, nil
}

func requireRole(v *VaultView, roles ...string) error {
	for _, r := range roles {
		if v.Role == r {
			return nil
		}
	}
	if v.Role == api.RoleViewer {
		return &ReadOnlyError{Reason: ReasonViewer}
	}
	return &PermissionError{Msg: "only a vault owner can do that"}
}

// syncAfterWrite refreshes the views after a successful write. The write
// already happened, so a failure here must not be reported as a failed write.
func (s *Session) syncAfterWrite(ctx context.Context) {
	_ = s.Sync(ctx)
}

// AcceptVault accepts a pending vault after the user compared the sender's
// fingerprint (crypto.md §6.4): the sender must be a verified contact (call
// MarkVerified / VerifyWithFingerprint first). It records the epoch, key
// commitment and owners, then the vault opens. Continuity violations and other
// hard errors cannot be overridden.
func (s *Session) AcceptVault(vaultID string) error {
	if s.locked {
		return ErrLocked
	}
	v := s.Vault(vaultID)
	if v == nil {
		return &UserError{Msg: "that vault is not available"}
	}
	if v.Locked != LockPending {
		if v.Locked == NotLocked {
			return nil
		}
		return &VaultLockedError{VaultID: vaultID, Reason: v.Locked, Detail: v.LockDetail}
	}
	if !s.trust.isVerified(v.Pending.SenderID) {
		c, _ := s.trust.contact(v.Pending.SenderID)
		return &UnverifiedContactError{User: UnverifiedUser{UserID: c.UserID, Username: c.Username, Fingerprint: v.Pending.SenderFingerprint}}
	}
	s.forced[vaultID] = true
	s.buildViews(s.raw)
	if err := s.trust.Save(); err != nil {
		return err
	}
	if nv := s.Vault(vaultID); nv.Locked != NotLocked {
		delete(s.forced, vaultID)
		return &VaultLockedError{VaultID: vaultID, Reason: nv.Locked, Detail: nv.LockDetail}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

// Directory lists every household member (contact) with fingerprint and verification state.
func (s *Session) Directory() []UserInfo {
	out := make([]UserInfo, 0, len(s.directory))
	for _, d := range s.directory {
		out = append(out, s.userInfo(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (s *Session) userInfo(d api.DirectoryUser) UserInfo {
	ui := UserInfo{UserID: d.UserID, Username: d.Username, Disabled: d.Disabled, IsAdmin: d.IsAdmin, Self: d.UserID == s.UserID}
	pub := d.PublicKey
	// The fingerprint shown is that of the trusted triple, not of whatever the directory now says.
	if c, ok := s.trust.contact(d.UserID); ok {
		pub = c.PublicKey
		ui.Username = c.Username
		ui.Verified = c.Verified
	}
	copy(ui.PublicKey[:], pub)
	ui.Fingerprint = fingerprintOf(d.UserID, ui.Username, pub)
	ui.KeyMismatch = s.mismatch[d.UserID] != nil
	if ui.KeyMismatch {
		ui.Verified = false // a verification belongs to the trusted triple, not to what is offered now
	}
	return ui
}

// ResolveUser finds a household member by username (a mismatching user is
// returned flagged; use LookupUser where a mismatch must be fatal).
func (s *Session) ResolveUser(username string) (*UserInfo, error) {
	name, err := vaultcrypto.NormalizeUsername(username)
	if err != nil {
		return nil, &UserError{Msg: "invalid username: " + err.Error()}
	}
	var hit *api.DirectoryUser
	for _, d := range s.directory {
		d := d
		if d.Username == name {
			hit = &d
			break
		}
	}
	if hit == nil {
		for _, c := range s.trust.allContacts() {
			if c.Username == name {
				if d, ok := s.directory[c.UserID]; ok {
					hit = &d
				}
			}
		}
	}
	if hit == nil {
		return nil, &UserError{Msg: fmt.Sprintf("there is no user %q in this household", name)}
	}
	ui := s.userInfo(*hit)
	return &ui, nil
}

// userOrSync resolves a username, syncing once if it is unknown: the user may
// have registered after our last sync.
func (s *Session) userOrSync(ctx context.Context, username string) (*UserInfo, error) {
	ui, err := s.ResolveUser(username)
	var ue *UserError
	if errors.As(err, &ue) && s.d.API != nil && s.mode == ModeOnline {
		if serr := s.Sync(ctx); serr == nil {
			return s.ResolveUser(username)
		}
	}
	return ui, err
}

// LookupUser is ResolveUser for sharing: a user whose key or name contradicts
// the trust store is a hard error.
func (s *Session) LookupUser(username string) (*UserInfo, error) {
	ui, err := s.ResolveUser(username)
	if err != nil {
		return nil, err
	}
	if w := s.mismatch[ui.UserID]; w != nil {
		return nil, w
	}
	return ui, nil
}

// MarkVerified records that the user's fingerprint was compared out of band.
// The caller has shown the fingerprint and obtained the confirmation.
func (s *Session) MarkVerified(userID string) error {
	if w := s.mismatch[userID]; w != nil {
		return w
	}
	if !s.trust.setVerified(userID) {
		return &UserError{Msg: "unknown contact"}
	}
	if err := s.trust.Save(); err != nil {
		return err
	}
	s.refreshVerified()
	return nil
}

// VerifyWithFingerprint marks a user verified if fp (any case, dashes
// optional) equals their fingerprint on this device; for scripts that name the
// fingerprint explicitly.
func (s *Session) VerifyWithFingerprint(userID, fp string) error {
	c, ok := s.trust.contact(userID)
	if !ok {
		return &UserError{Msg: "unknown contact"}
	}
	want := fingerprintOf(c.UserID, c.Username, c.PublicKey)
	norm := func(x string) string { return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(x), "-", "")) }
	if subtle.ConstantTimeCompare([]byte(norm(fp)), []byte(norm(want))) != 1 {
		return &UserError{Msg: fmt.Sprintf("the fingerprint you gave does not match %s's fingerprint on this device (%s)", c.Username, want)}
	}
	return s.MarkVerified(userID)
}

// DismissWarnings acknowledges recorded mismatch events of a user. The user
// stays untrusted: the contact triple never changes.
func (s *Session) DismissWarnings(userID string) (int, error) {
	name := ""
	if c, ok := s.trust.contact(userID); ok {
		name = c.Username
	}
	n := s.trust.dismiss(userID, name)
	return n, s.trust.Save()
}

func (s *Session) refreshVerified() {
	for _, v := range s.vaults {
		for i := range v.Members {
			v.Members[i].Verified = s.trust.isVerified(v.Members[i].UserID)
		}
	}
	for _, v := range s.vaults {
		if v.Pending != nil {
			v.Pending.SenderVerified = s.trust.isVerified(v.Pending.SenderID)
		}
	}
}
