// Package fsm is the replicated state machine of the vault (DESIGN.md §4).
//
// It holds only what the servers need to enforce access control, plus opaque
// client ciphertext: the cluster key, users, invites, vaults with members and
// items, a global revision counter and a bounded idempotency table.
//
// Determinism is the overriding constraint. Apply's result and the resulting
// state depend only on the previous state and the command bytes: no clocks
// (commands carry the proposer's timestamp), no randomness, no map iteration
// order in anything observable, and snapshots are canonical (sorted) so equal
// states serialize to identical bytes. Apply never panics on bad input and
// never trusts it: every command is re-validated and every permission is
// re-checked against the state it executes on.
package fsm

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"

	"github.com/tarnan3751/password-vault/internal/api"
)

// FSM implements raft.StateMachine. HTTP handlers read it concurrently with
// Apply, so all access goes through mu; readers only ever receive copies.
type FSM struct {
	mu  sync.RWMutex
	s   *state
	lim limits
}

// limits are the count limits and storage quotas enforced on writes. In
// production they are always defaultLimits (they are replicated semantics:
// every replica must use the same values); tests construct FSMs with tiny
// limits to drive the quota paths.
type limits struct {
	users, vaultsPerCreator, itemsPerVault int
	vaultBytes, userBytes, clusterBytes    int64
}

var defaultLimits = limits{
	users: MaxUsers, vaultsPerCreator: MaxVaultsPerOwner, itemsPerVault: MaxItemsPerVault,
	vaultBytes: MaxVaultBytes, userBytes: MaxUserBytes, clusterBytes: MaxClusterBytes,
}

// New returns an empty, uninitialized state machine.
func New() *FSM { return newWithLimits(defaultLimits) }

func newWithLimits(l limits) *FSM {
	f := &FSM{lim: l}
	f.s = newState(&f.lim)
	return f
}

// Apply executes one committed command and returns its JSON result
// ({"ok": ...} or {"err": ...}). index is not used: the result must not
// depend on where in the log a command landed, because retried proposals
// land in several places and must all produce the same answer.
func (f *FSM) Apply(index uint64, cmd []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.s.apply(cmd)
}

// Rev returns the current global revision.
func (f *FSM) Rev() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.rev
}

// StateHash is the SHA-256 of the canonical snapshot. Replicas that applied
// the same commands have the same hash (used by convergence checks). The
// encoding is streamed into the hash, never held in memory as a whole.
func (f *FSM) StateHash() [32]byte {
	f.mu.RLock()
	d := f.s.doc(true)
	f.mu.RUnlock() // as in snapshot
	e := &snapEncoder{buf: make([]byte, 0, 64<<10), h: sha256.New()}
	d.fields(e)
	e.h.Write(e.buf)
	return [32]byte(e.h.Sum(nil))
}

// CachedResult returns the stored result of cmd if a command with the same
// (caller, req_id) and the same request binding has already been applied
// locally. Handlers use it to answer a retry whose session was revoked by
// the very request being retried (password change, revoke-sessions): the
// state machine would otherwise be unreachable for it. A local hit is always
// trustworthy, since only applied (committed) commands are recorded.
func (f *FSM) CachedResult(cmd []byte) ([]byte, bool) {
	p, perr := parseCommand(cmd)
	if perr != nil {
		return nil, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.s.idem[p.key]
	if !ok || e.Binding != p.binding {
		return nil, false
	}
	return cloneBytes(e.Result), true
}

// DryRun reports the error that applying cmd to the current local state
// would produce, without changing anything (nil if it would succeed or would
// be answered from the idempotency table). Handlers use it to reject doomed
// requests before spending an Argon2 computation and a log entry on them.
// The state machine still decides authoritatively at apply time.
func (f *FSM) DryRun(cmd []byte) *Error {
	p, perr := parseCommand(cmd)
	if perr != nil {
		return perr
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if e, ok := f.s.idem[p.key]; ok {
		if e.Binding == p.binding {
			return nil
		}
		return errKeyReuse()
	}
	if p.argErr != nil {
		return p.argErr
	}
	_, err := f.s.prepare(p)
	return err
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type user struct {
	ID                string        `json:"id"`
	Username          string        `json:"username"`
	KDF               api.KDFParams `json:"kdf"`
	Verifier          Verifier      `json:"verifier"`
	PublicKey         []byte        `json:"public_key"`
	WrappedAccountKey []byte        `json:"wrapped_account_key"`
	EncPrivateKey     []byte        `json:"enc_private_key"`
	IsAdmin           bool          `json:"is_admin"`
	Disabled          bool          `json:"disabled"`
	TokenEpoch        uint64        `json:"token_epoch"`
	CreatedAt         int64         `json:"created_at"`
}

type invite struct {
	ID        string `json:"id"`   // first 16 hex chars of Hash
	Hash      string `json:"hash"` // hex SHA-256 of the canonical code
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	UsedBy    string `json:"used_by,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
}

func (i *invite) pending(now int64) bool {
	return !i.Revoked && i.UsedBy == "" && now < i.ExpiresAt
}

// member and item carry their map key (UserID, ID) too: they are also the
// records of a snapshot.
type member struct {
	UserID     string         `json:"user_id"`
	Role       string         `json:"role"`
	WrappedKey api.WrappedKey `json:"wrapped_key"`
	AddedBy    string         `json:"added_by"`
}

type item struct {
	ID        string `json:"id"`
	Blob      []byte `json:"blob"`
	Version   uint64 `json:"version"`
	UpdatedAt int64  `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

type vault struct {
	ID               string
	Creator          string
	Personal         bool
	KeyEpoch         uint32
	EncMeta          []byte
	MetaVersion      uint64
	EncRoster        []byte
	RosterVersion    uint64
	Rev              uint64
	RekeyRecommended bool
	Members          map[string]*member
	Items            map[string]*item

	// bytes is the storage charged to this vault: len(EncMeta) +
	// len(EncRoster) plus itemCost of every item. It is derived data: never serialized, always
	// recomputed on restore, and kept up to date by every mutation.
	bytes int64
}

func itemCost(blobLen int) int64 { return int64(blobLen) + ItemOverheadBytes }

func (v *vault) recount() {
	b := int64(len(v.EncMeta)) + int64(len(v.EncRoster))
	for _, it := range v.Items {
		b += itemCost(len(it.Blob))
	}
	v.bytes = b
}

func (v *vault) owners() int {
	n := 0
	for _, m := range v.Members {
		if m.Role == api.RoleOwner {
			n++
		}
	}
	return n
}

// idemEntry stores a result as base64 (in snapshots) rather than embedded
// JSON so that a replay after restore returns byte-for-byte what the
// original Apply did (encoding/json would re-escape embedded JSON).
type idemEntry struct {
	Key     string `json:"key"`
	Binding string `json:"binding"`
	Result  []byte `json:"result"`
}

// state is the replicated state. Byte slices stored in it are never
// modified in place (every write stores a fresh copy of its input), so a
// snapshot document can share them and be encoded after the lock is
// released (see FSM.snapshot).
type state struct {
	lim        *limits
	clusterKey []byte
	rev        uint64
	users      map[string]*user
	byName     map[string]string
	invites    map[string]*invite // by invite id
	vaults     map[string]*vault
	idem       map[string]*idemEntry
	idemOrder  []string // FIFO, oldest first; evicted in apply order
}

func newState(lim *limits) *state {
	return &state{
		lim:     lim,
		users:   map[string]*user{},
		byName:  map[string]string{},
		invites: map[string]*invite{},
		vaults:  map[string]*vault{},
		idem:    map[string]*idemEntry{},
	}
}

func (s *state) bump() uint64 {
	s.rev++
	return s.rev
}

func (s *state) apply(cmd []byte) (res []byte) {
	// Last line of defence. A panic here would be deterministic (same state,
	// same command on every replica), so converting it into an error result
	// keeps replicas identical, whereas crashing would crash every replica
	// on the same poisoned entry, forever. The fuzz tests exist so that this
	// never runs.
	defer func() {
		if r := recover(); r != nil {
			res = encodeResult(nil, newErr(api.CodeInternal, "internal error while applying command"))
		}
	}()
	p, perr := parseCommand(cmd)
	if perr != nil {
		return encodeResult(nil, perr)
	}
	// Exactly-once: a command already applied under this (caller, req_id) is
	// answered from the table without re-executing. The binding check stops
	// a reused key from returning one request's result to a different
	// request (e.g. a registration result to another registrant).
	if e, ok := s.idem[p.key]; ok {
		if e.Binding == p.binding {
			return cloneBytes(e.Result)
		}
		return encodeResult(nil, errKeyReuse())
	}
	var r []byte
	if p.argErr != nil {
		r = encodeResult(nil, p.argErr)
	} else if commit, err := s.prepare(p); err != nil {
		r = encodeResult(nil, err)
	} else {
		r = encodeResult(commit(), nil)
	}
	// Failures are recorded too: a retry must get the same answer even if
	// the state has changed in a way that would now let it succeed.
	s.record(p.key, p.binding, r)
	return cloneBytes(r)
}

func (s *state) record(key, binding string, result []byte) {
	s.idem[key] = &idemEntry{Key: key, Binding: binding, Result: result}
	s.idemOrder = append(s.idemOrder, key)
	for len(s.idemOrder) > IdempotencyCapacity {
		delete(s.idem, s.idemOrder[0])
		s.idemOrder[0] = ""
		s.idemOrder = s.idemOrder[1:]
	}
}

type execCtx struct {
	now    int64
	caller *user
}

// prepare performs every check for a command against the current state and
// returns a commit function that applies it. prepare never mutates: a
// command either fails with no effect or commits completely, and DryRun can
// reuse the same code.
func (s *state) prepare(p *parsedCommand) (func() *Outcome, *Error) {
	c := &execCtx{now: p.env.Now}
	if a, ok := p.args.(*InitArgs); ok {
		return s.prepInit(a)
	}
	if s.clusterKey == nil {
		return nil, errNotInitialized()
	}
	if a, ok := p.args.(*RegisterArgs); ok {
		return s.prepRegister(c, a)
	}
	// Every other op acts on behalf of a session: the caller must exist, be
	// enabled and present the CURRENT token epoch, judged against the state
	// the command executes on rather than the proposing node's view.
	u := s.users[p.env.UID]
	if p.env.UID == "" || u == nil || u.Disabled || u.TokenEpoch != p.env.Ep {
		return nil, errSession()
	}
	c.caller = u
	if e := p.args.Validate(u.ID); e != nil {
		return nil, e
	}
	switch a := p.args.(type) {
	case *ChangePasswordArgs:
		return s.prepChangePassword(c, a)
	case *RevokeSessionsArgs:
		return s.prepRevokeSessions(c)
	case *CreateInviteArgs:
		return s.prepCreateInvite(c, a)
	case *RevokeInviteArgs:
		return s.prepRevokeInvite(c, a)
	case *AdminUpdateUserArgs:
		return s.prepAdminUpdateUser(c, a)
	case *CreateVaultArgs:
		return s.prepCreateVault(c, a)
	case *UpdateVaultMetaArgs:
		return s.prepUpdateVaultMeta(c, a)
	case *DeleteVaultArgs:
		return s.prepDeleteVault(c, a)
	case *PutMemberArgs:
		return s.prepPutMember(c, a)
	case *RemoveMemberArgs:
		return s.prepRemoveMember(c, a)
	case *RekeyArgs:
		return s.prepRekey(c, a)
	case *PutItemArgs:
		return s.prepPutItem(c, a)
	case *DeleteItemArgs:
		return s.prepDeleteItem(c, a)
	}
	return nil, badRequest("unknown op")
}

// usage is the storage charged to user uid (the sum over the vaults they
// created) and to the household. Map order is irrelevant (integer addition).
func (s *state) usage(uid string) (user, total int64) {
	for _, v := range s.vaults {
		total += v.bytes
		if v.Creator == uid {
			user += v.bytes
		}
	}
	return user, total
}

func sizeString(n int64) string {
	if n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

// checkGrowth enforces the storage quotas for a write that changes the
// usage of a vault (created by creator, currently using current bytes) by
// delta. Writes that do not grow usage are always allowed, even when a
// quota is already exceeded (e.g. after limits were lowered): deleting and
// shrinking must remain possible, and a same-size rekey must never be
// blocked.
func (s *state) checkGrowth(creator string, current, delta int64) *Error {
	if delta <= 0 {
		return nil
	}
	if current+delta > s.lim.vaultBytes {
		return limit("vault storage quota of " + sizeString(s.lim.vaultBytes) + " exceeded")
	}
	user, total := s.usage(creator)
	if user+delta > s.lim.userBytes {
		return limit("per-user storage quota of " + sizeString(s.lim.userBytes) + " exceeded (charged to the vault's creator)")
	}
	if total+delta > s.lim.clusterBytes {
		return limit("household storage quota of " + sizeString(s.lim.clusterBytes) + " exceeded")
	}
	return nil
}

func noChange(s *state) func() *Outcome {
	return func() *Outcome { return &Outcome{Rev: s.rev} }
}

// ---------------------------------------------------------------------------
// Ops
// ---------------------------------------------------------------------------

func (s *state) prepInit(a *InitArgs) (func() *Outcome, *Error) {
	if e := a.Validate(""); e != nil {
		return nil, e
	}
	if s.clusterKey != nil {
		return noChange(s), nil // first init wins
	}
	return func() *Outcome {
		s.clusterKey = cloneBytes(a.ClusterKey)
		return &Outcome{Rev: s.bump()}
	}, nil
}

func (s *state) prepRegister(c *execCtx, a *RegisterArgs) (func() *Outcome, *Error) {
	if e := a.Validate(""); e != nil {
		return nil, e
	}
	// The invite is checked before anything that reveals whether a username
	// or id is taken, so that only invite holders can probe for those.
	var inv *invite
	if a.Bootstrap {
		// Accepted only while the household is empty, so exactly one
		// bootstrap registration can ever win, whichever nodes raced.
		if len(s.users) != 0 {
			return nil, errInvalidInvite()
		}
	} else {
		inv = s.invites[a.InviteHash[:16]]
		// Expiry is judged against the command's timestamp, so every
		// replica decides identically.
		if inv == nil || inv.Hash != a.InviteHash || !inv.pending(c.now) {
			return nil, errInvalidInvite()
		}
	}
	if len(s.users) >= s.lim.users {
		return nil, limit("the household already has the maximum number of users")
	}
	if _, ok := s.users[a.UserID]; ok {
		return nil, exists("user id already exists")
	}
	if _, ok := s.byName[a.Username]; ok {
		return nil, exists("username is already taken")
	}
	if _, ok := s.vaults[a.PersonalVault.VaultID]; ok {
		return nil, exists("vault id already exists")
	}
	if e := s.checkGrowth(a.UserID, 0, int64(len(a.PersonalVault.EncMeta)+len(a.PersonalVault.EncRoster))); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		u := &user{
			ID:                a.UserID,
			Username:          a.Username,
			KDF:               cloneKDF(a.KDF),
			Verifier:          a.Verifier.clone(),
			PublicKey:         cloneBytes(a.PublicKey),
			WrappedAccountKey: cloneBytes(a.WrappedAccountKey),
			EncPrivateKey:     cloneBytes(a.EncPrivateKey),
			IsAdmin:           len(s.users) == 0, // the first user administers the household
			TokenEpoch:        1,
			CreatedAt:         c.now,
		}
		s.users[u.ID] = u
		s.byName[u.Username] = u.ID
		if inv != nil {
			inv.UsedBy = u.ID
		}
		pv := a.PersonalVault
		s.vaults[pv.VaultID] = newVault(pv, u.ID, true, rev)
		return accountOutcome(rev, u, true)
	}, nil
}

// newVault is a vault as created at rev, with its creator as sole owner.
func newVault(r api.CreateVaultRequest, creator string, personal bool, rev uint64) *vault {
	return &vault{
		ID: r.VaultID, Creator: creator, Personal: personal, KeyEpoch: 1,
		EncMeta: cloneBytes(r.EncMeta), MetaVersion: rev, EncRoster: cloneBytes(r.EncRoster), RosterVersion: rev, Rev: rev,
		Members: map[string]*member{creator: {UserID: creator, Role: api.RoleOwner, WrappedKey: cloneWrapped(r.WrappedKey), AddedBy: creator}},
		Items:   map[string]*item{},
		bytes:   int64(len(r.EncMeta) + len(r.EncRoster)),
	}
}

func (s *state) prepChangePassword(c *execCtx, a *ChangePasswordArgs) (func() *Outcome, *Error) {
	u := c.caller
	return func() *Outcome {
		u.KDF = cloneKDF(a.NewKDF)
		u.WrappedAccountKey = cloneBytes(a.NewWrappedAccountKey)
		u.Verifier = a.Verifier.clone()
		u.TokenEpoch++ // revokes every older token, including the caller's
		return accountOutcome(s.bump(), u, true)
	}, nil
}

// accountOutcome is the result of an op that changed u's session state;
// withVerifier adds the verifier now stored (see Outcome.Verifier).
func accountOutcome(rev uint64, u *user, withVerifier bool) *Outcome {
	out := &Outcome{Rev: rev, UserID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin, Epoch: u.TokenEpoch}
	if withVerifier {
		v := u.Verifier.clone()
		out.Verifier = &v
	}
	return out
}

func (s *state) prepRevokeSessions(c *execCtx) (func() *Outcome, *Error) {
	u := c.caller
	return func() *Outcome {
		u.TokenEpoch++
		return accountOutcome(s.bump(), u, false)
	}, nil
}

func (s *state) prepCreateInvite(c *execCtx, a *CreateInviteArgs) (func() *Outcome, *Error) {
	if !c.caller.IsAdmin {
		return nil, forbidden("only admins can create invites")
	}
	id := a.InviteHash[:16]
	// The id is a prefix of the hash; refusing prefix collisions keeps ids
	// unique (practically unreachable with 160-bit codes).
	if _, ok := s.invites[id]; ok {
		return nil, exists("invite already exists")
	}
	pending := 0
	var prune []string
	for _, inv := range s.invites {
		switch {
		case inv.pending(c.now):
			pending++
		case inv.UsedBy == "":
			prune = append(prune, inv.ID) // revoked or expired, never used
		}
	}
	if pending >= MaxPendingInvites {
		return nil, limit("too many pending invites; revoke some first")
	}
	return func() *Outcome {
		// Dead invites are garbage-collected here so the table stays bounded.
		// Used invites are kept: they record who joined through whom, and
		// there can be at most one per user.
		for _, id := range prune {
			delete(s.invites, id)
		}
		rev := s.bump()
		inv := &invite{
			ID:        id,
			Hash:      a.InviteHash,
			CreatedBy: c.caller.ID,
			CreatedAt: c.now,
			ExpiresAt: c.now + int64(a.TTLHours)*3_600_000,
		}
		s.invites[id] = inv
		return &Outcome{Rev: rev, InviteID: inv.ID, ExpiresAt: inv.ExpiresAt}
	}, nil
}

func (s *state) prepRevokeInvite(c *execCtx, a *RevokeInviteArgs) (func() *Outcome, *Error) {
	if !c.caller.IsAdmin {
		return nil, forbidden("only admins can revoke invites")
	}
	inv := s.invites[a.InviteID]
	if inv == nil || inv.Revoked {
		return nil, notFound("invite not found")
	}
	if inv.UsedBy != "" {
		return nil, newErr(api.CodeInvalidInvite, "invite was already used")
	}
	return func() *Outcome {
		inv.Revoked = true
		return &Outcome{Rev: s.bump()}
	}, nil
}

func (s *state) enabledAdmins() int {
	n := 0
	for _, u := range s.users {
		if u.IsAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

func (s *state) prepAdminUpdateUser(c *execCtx, a *AdminUpdateUserArgs) (func() *Outcome, *Error) {
	if !c.caller.IsAdmin {
		return nil, forbidden("only admins can change users")
	}
	t := s.users[a.UserID]
	if t == nil {
		return nil, notFound("user not found")
	}
	disabled, admin := t.Disabled, t.IsAdmin
	if a.Disabled != nil {
		disabled = *a.Disabled
	}
	if a.IsAdmin != nil {
		admin = *a.IsAdmin
	}
	if disabled == t.Disabled && admin == t.IsAdmin {
		return noChange(s), nil
	}
	// The household must always keep one enabled admin, or nobody could
	// ever create invites or re-enable anyone again.
	if t.IsAdmin && !t.Disabled && !(admin && !disabled) && s.enabledAdmins() == 1 {
		return nil, forbidden("the last enabled admin cannot be disabled or demoted")
	}
	return func() *Outcome {
		if disabled && !t.Disabled {
			t.TokenEpoch++ // disabling revokes all of the user's sessions at once
		}
		t.Disabled, t.IsAdmin = disabled, admin
		return &Outcome{Rev: s.bump()}
	}, nil
}

func (s *state) createdBy(uid string) int {
	n := 0
	for _, v := range s.vaults {
		if v.Creator == uid {
			n++
		}
	}
	return n
}

func (s *state) prepCreateVault(c *execCtx, a *CreateVaultArgs) (func() *Outcome, *Error) {
	if _, ok := s.vaults[a.VaultID]; ok {
		return nil, exists("vault id already exists")
	}
	if s.createdBy(c.caller.ID) >= s.lim.vaultsPerCreator {
		return nil, limit("vault limit reached")
	}
	if e := s.checkGrowth(c.caller.ID, 0, int64(len(a.EncMeta)+len(a.EncRoster))); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		s.vaults[a.VaultID] = newVault(api.CreateVaultRequest(*a), c.caller.ID, false, rev)
		return &Outcome{Rev: rev, Version: rev}
	}, nil
}

// memberVault returns the vault and the caller's membership. A vault the
// caller is not a member of is reported exactly like a missing one, so
// non-members cannot even learn that it exists.
func (s *state) memberVault(vaultID, uid string) (*vault, *member, *Error) {
	v := s.vaults[vaultID]
	if v == nil {
		return nil, nil, errVaultNotFound()
	}
	m := v.Members[uid]
	if m == nil {
		return nil, nil, errVaultNotFound()
	}
	return v, m, nil
}

// vaultAs is memberVault for an op that needs the caller to be an owner
// (role owner) or at least an editor (role editor); forbidden(msg) if not.
func (s *state) vaultAs(vaultID, uid, role, msg string) (*vault, *Error) {
	v, m, err := s.memberVault(vaultID, uid)
	if err == nil && (m.Role == api.RoleViewer || role == api.RoleOwner && m.Role != api.RoleOwner) {
		err = forbidden(msg)
	}
	return v, err
}

func (s *state) prepUpdateVaultMeta(c *execCtx, a *UpdateVaultMetaArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleOwner, "only owners can change vault metadata")
	if err != nil {
		return nil, err
	}
	if a.BaseMetaVersion != v.MetaVersion {
		return nil, conflict("meta_version does not match", v.MetaVersion)
	}
	delta := int64(len(a.EncMeta)) - int64(len(v.EncMeta))
	if e := s.checkGrowth(v.Creator, v.bytes, delta); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		v.bytes += delta
		v.EncMeta = cloneBytes(a.EncMeta)
		v.MetaVersion = rev
		v.Rev = rev
		return &Outcome{Rev: rev, Version: rev}
	}, nil
}

func (s *state) prepDeleteVault(c *execCtx, a *DeleteVaultArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleOwner, "only owners can delete a vault")
	if err != nil {
		return nil, err
	}
	if v.Personal {
		return nil, forbidden("personal vaults cannot be deleted")
	}
	return func() *Outcome {
		delete(s.vaults, v.ID)
		return &Outcome{Rev: s.bump()}
	}, nil
}

func (s *state) prepPutMember(c *execCtx, a *PutMemberArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleOwner, "only owners can manage members")
	if err != nil {
		return nil, err
	}
	if v.Personal {
		return nil, forbidden("a personal vault cannot have other members")
	}
	if s.users[a.UserID] == nil {
		return nil, notFound("user not found")
	}
	// The new roster is sealed under the current key, for both additions
	// and role changes, so the client must be working at the current epoch.
	if a.KeyEpoch != v.KeyEpoch {
		return nil, newErr(api.CodeKeyEpochMismatch, "key_epoch is not the vault's current key epoch")
	}
	target := v.Members[a.UserID]
	if target == nil {
		if a.WrappedKey == nil {
			return nil, badRequest("wrapped_key is required to add a member")
		}
	} else {
		if a.WrappedKey != nil {
			// Replacing another member's wrapped key is not an operation the
			// API offers (it would let an owner silently swap someone's key);
			// keys change only through a rekey.
			return nil, exists("user is already a member; omit wrapped_key to change the role")
		}
		if target.Role == api.RoleOwner && a.Role != api.RoleOwner && v.owners() == 1 {
			return nil, forbidden("the last owner cannot be demoted")
		}
	}
	// Compare-and-swap on the roster: two owners editing the membership
	// concurrently cannot silently overwrite each other's roster.
	if a.BaseRosterVersion != v.RosterVersion {
		return nil, conflict("base_roster_version does not match", v.RosterVersion)
	}
	delta := int64(len(a.EncRoster)) - int64(len(v.EncRoster))
	if e := s.checkGrowth(v.Creator, v.bytes, delta); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		if target == nil {
			v.Members[a.UserID] = &member{UserID: a.UserID, Role: a.Role, WrappedKey: cloneWrapped(*a.WrappedKey), AddedBy: c.caller.ID}
		} else {
			target.Role = a.Role
		}
		v.bytes += delta
		v.EncRoster = cloneBytes(a.EncRoster)
		v.RosterVersion = rev
		v.Rev = rev
		return &Outcome{Rev: rev, Version: rev}
	}, nil
}

func (s *state) prepRemoveMember(c *execCtx, a *RemoveMemberArgs) (func() *Outcome, *Error) {
	v, m, err := s.memberVault(a.VaultID, c.caller.ID)
	if err != nil {
		return nil, err
	}
	if a.UserID != c.caller.ID && m.Role != api.RoleOwner {
		return nil, forbidden("only owners can remove other members")
	}
	target := v.Members[a.UserID]
	if target == nil {
		return nil, notFound("user is not a member of this vault")
	}
	if target.Role == api.RoleOwner && v.owners() == 1 {
		return nil, forbidden("the last owner cannot be removed")
	}
	return func() *Outcome {
		rev := s.bump()
		delete(v.Members, a.UserID)
		// The removed member still holds the old vault key.
		v.RekeyRecommended = true
		v.Rev = rev
		return &Outcome{Rev: rev}
	}, nil
}

func (s *state) prepRekey(c *execCtx, a *RekeyArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleOwner, "only owners can rekey a vault")
	if err != nil {
		return nil, err
	}
	if a.BaseRev != v.Rev {
		return nil, conflict("base_rev does not match the vault's rev", v.Rev)
	}
	if v.KeyEpoch == ^uint32(0) || a.NewKeyEpoch != v.KeyEpoch+1 {
		return nil, conflict("new_key_epoch must be the current key epoch + 1", v.Rev)
	}
	// Members removed by this rekey (Validate: valid ids, unique, never the
	// caller). base_rev matched, so the client's member list is current and
	// a non-member here is a malformed request, not a race.
	removed := make(map[string]bool, len(a.Remove))
	for _, uid := range a.Remove {
		if v.Members[uid] == nil {
			return nil, badRequest("remove lists a user who is not a member")
		}
		removed[uid] = true
	}
	if v.Personal && len(a.Remove) > 0 {
		return nil, badRequest("a personal vault has no members to remove") // unreachable: its only member is the caller
	}
	// Exact cover: a rekey that missed a remaining member would lock them
	// out, one that wrapped for a removed member would defeat the removal,
	// and one that missed an item would leave it under the old key.
	remaining, owners := 0, 0
	for uid, mem := range v.Members {
		if removed[uid] {
			continue
		}
		remaining++
		if mem.Role == api.RoleOwner {
			owners++
		}
		if _, ok := a.WrappedKeys[uid]; !ok {
			return nil, conflict("wrapped_keys must cover exactly the remaining members", v.Rev)
		}
	}
	if len(a.WrappedKeys) != remaining {
		return nil, conflict("wrapped_keys must cover exactly the remaining members", v.Rev)
	}
	if owners == 0 {
		// Unreachable (the caller is an owner and cannot be removed), kept
		// as a guard: a vault must never be left without an owner.
		return nil, forbidden("the last owner cannot be removed")
	}
	if len(a.Items) != len(v.Items) {
		return nil, conflict("items must cover exactly the current items", v.Rev)
	}
	delta := int64(len(a.EncMeta)) - int64(len(v.EncMeta)) + int64(len(a.EncRoster)) - int64(len(v.EncRoster))
	for _, it := range a.Items { // ids are unique (Validate)
		cur, ok := v.Items[it.ID]
		if !ok {
			return nil, conflict("items must cover exactly the current items", v.Rev)
		}
		delta += int64(len(it.Blob)) - int64(len(cur.Blob))
	}
	if e := s.checkGrowth(v.Creator, v.bytes, delta); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		for uid := range removed {
			delete(v.Members, uid)
		}
		v.bytes += delta
		v.KeyEpoch++
		v.EncMeta = cloneBytes(a.EncMeta)
		v.MetaVersion = rev
		v.EncRoster = cloneBytes(a.EncRoster)
		v.RosterVersion = rev
		for uid, mem := range v.Members {
			mem.WrappedKey = cloneWrapped(a.WrappedKeys[uid])
		}
		for _, it := range a.Items {
			v.Items[it.ID] = &item{ID: it.ID, Blob: cloneBytes(it.Blob), Version: rev, UpdatedAt: c.now, UpdatedBy: c.caller.ID}
		}
		// The removed members never see the new key; the remaining ones are
		// all on it, so there is nothing left to recommend.
		v.RekeyRecommended = false
		v.Rev = rev
		return &Outcome{Rev: rev}
	}, nil
}

func (s *state) prepPutItem(c *execCtx, a *PutItemArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleEditor, "viewers cannot change items")
	if err != nil {
		return nil, err
	}
	if a.KeyEpoch != v.KeyEpoch {
		return nil, newErr(api.CodeKeyEpochMismatch, "key_epoch is not the vault's current key epoch")
	}
	cur := v.Items[a.ItemID]
	var delta int64
	if a.BaseVersion == 0 {
		if cur != nil {
			return nil, conflict("item already exists", cur.Version)
		}
		if len(v.Items) >= s.lim.itemsPerVault {
			return nil, limit("item limit reached for this vault")
		}
		delta = itemCost(len(a.Blob))
	} else {
		if cur == nil {
			return nil, conflict("item does not exist", 0)
		}
		if cur.Version != a.BaseVersion {
			return nil, conflict("base_version does not match", cur.Version)
		}
		delta = int64(len(a.Blob)) - int64(len(cur.Blob))
	}
	if e := s.checkGrowth(v.Creator, v.bytes, delta); e != nil {
		return nil, e
	}
	return func() *Outcome {
		rev := s.bump()
		v.bytes += delta
		// The new version is the new global rev, so versions are never
		// reused, even across delete and re-create.
		v.Items[a.ItemID] = &item{ID: a.ItemID, Blob: cloneBytes(a.Blob), Version: rev, UpdatedAt: c.now, UpdatedBy: c.caller.ID}
		v.Rev = rev
		return &Outcome{Rev: rev, Version: rev}
	}, nil
}

func (s *state) prepDeleteItem(c *execCtx, a *DeleteItemArgs) (func() *Outcome, *Error) {
	v, err := s.vaultAs(a.VaultID, c.caller.ID, api.RoleEditor, "viewers cannot change items")
	if err != nil {
		return nil, err
	}
	cur := v.Items[a.ItemID]
	if cur == nil {
		return nil, conflict("item does not exist", 0)
	}
	if cur.Version != a.BaseVersion {
		return nil, conflict("base_version does not match", cur.Version)
	}
	return func() *Outcome {
		rev := s.bump()
		v.bytes -= itemCost(len(cur.Blob))
		delete(v.Items, a.ItemID)
		v.Rev = rev
		return &Outcome{Rev: rev}
	}, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
