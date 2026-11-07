package fsm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// harness drives one FSM with well-formed commands.
type harness struct {
	t   testing.TB
	f   *FSM
	now int64
	seq int
}

type tuser struct {
	id, name, personal string
	ep                 uint64
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	h := &harness{t: t, f: New(), now: 1_700_000_000_000}
	h.mustOK(nil, &InitArgs{ClusterKey: bytes.Repeat([]byte{7}, 32)})
	return h
}

func hexID(prefix byte, n int) string { return fmt.Sprintf("%02x%030x", prefix, n) }
func userID(n int) string             { return hexID(0x10, n) }
func vaultID(n int) string            { return hexID(0x20, n) }
func itemID(n int) string             { return hexID(0x30, n) }

func box(n int) []byte {
	b := bytes.Repeat([]byte{0xab}, n)
	b[0] = 1
	return b
}

func wk(sender string) api.WrappedKey {
	return api.WrappedKey{SenderID: sender, Blob: box(WrappedKeyBytes)}
}
func wkp(sender string) *api.WrappedKey {
	w := wk(sender)
	return &w
}

func kdf() api.KDFParams {
	return api.KDFParams{Alg: "argon2id", Salt: bytes.Repeat([]byte{1}, 16), Time: 3, MemoryKiB: 65536, Parallelism: 4}
}

func verifier(seed byte) Verifier {
	return Verifier{
		Salt: bytes.Repeat([]byte{seed}, VerifierSaltBytes), Time: VerifierTime, MemoryKiB: VerifierMemoryKiB,
		Parallelism: VerifierParallelism, Hash: bytes.Repeat([]byte{seed + 1}, VerifierHashBytes),
	}
}

func regArgs(n int, name string) *RegisterArgs {
	uid := userID(n)
	return &RegisterArgs{
		UserID: uid, Username: name, KDF: kdf(), Verifier: verifier(byte(n)),
		PublicKey: bytes.Repeat([]byte{byte(n)}, 32), WrappedAccountKey: box(73), EncPrivateKey: box(73),
		PersonalVault: api.CreateVaultRequest{VaultID: vaultID(1000 + n), EncMeta: box(64), EncRoster: box(64), WrappedKey: wk(uid)},
	}
}

func (h *harness) reqID() string {
	h.seq++
	return fmt.Sprintf("%032x", h.seq)
}

func (h *harness) cmd(u *tuser, args Args) []byte {
	h.t.Helper()
	uid, ep := "", uint64(0)
	if u != nil {
		uid, ep = u.id, u.ep
	}
	b, err := EncodeCommand(h.reqID(), h.now, uid, ep, args)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *harness) applyRaw(b []byte) *Result {
	h.t.Helper()
	r, err := DecodeResult(h.f.Apply(1, b))
	if err != nil {
		h.t.Fatalf("Apply returned an undecodable result: %v", err)
	}
	return r
}

func (h *harness) do(u *tuser, args Args) *Result { h.t.Helper(); return h.applyRaw(h.cmd(u, args)) }

func (h *harness) mustOK(u *tuser, args Args) *Outcome {
	h.t.Helper()
	r := h.do(u, args)
	if r.Err != nil {
		h.t.Fatalf("%s: unexpected error %s: %s", args.Op(), r.Err.Code, r.Err.Message)
	}
	return r.OK
}

func (h *harness) mustErr(u *tuser, args Args, code string) *Error {
	h.t.Helper()
	rev := h.f.Rev()
	before := coreHash(h.f)
	r := h.do(u, args)
	if r.Err == nil {
		h.t.Fatalf("%s: expected %s, got success", args.Op(), code)
	}
	if r.Err.Code != code {
		h.t.Fatalf("%s: expected %s, got %s (%s)", args.Op(), code, r.Err.Code, r.Err.Message)
	}
	if h.f.Rev() != rev {
		h.t.Fatalf("%s: failed command bumped rev", args.Op())
	}
	if coreHash(h.f) != before {
		h.t.Fatalf("%s: failed command changed state", args.Op())
	}
	return r.Err
}

// coreHash hashes the state excluding the idempotency table (which every
// keyed command, failed or not, appends to).
func coreHash(f *FSM) [32]byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	c := *f.s
	c.idem = map[string]*idemEntry{}
	c.idemOrder = nil
	e := &snapEncoder{}
	c.doc(true).fields(e)
	return sha256.Sum256(e.buf)
}

func (h *harness) bootstrap(n int, name string) *tuser {
	h.t.Helper()
	a := regArgs(n, name)
	a.Bootstrap = true
	out := h.mustOK(nil, a)
	return &tuser{id: out.UserID, name: name, ep: out.Epoch, personal: a.PersonalVault.VaultID}
}

// inviteHash varies in its first 16 hex chars, which form the invite id.
func inviteHash(n int) string { return fmt.Sprintf("%016x%048x", 0xabc000+n, n) }

func (h *harness) invite(admin *tuser, n int) string {
	h.t.Helper()
	hash := inviteHash(n)
	h.mustOK(admin, &CreateInviteArgs{InviteHash: hash, TTLHours: 72})
	return hash
}

func (h *harness) addUser(admin *tuser, n int, name string) *tuser {
	h.t.Helper()
	a := regArgs(n, name)
	a.InviteHash = h.invite(admin, n)
	out := h.mustOK(nil, a)
	return &tuser{id: out.UserID, name: name, ep: out.Epoch, personal: a.PersonalVault.VaultID}
}

func (h *harness) createVault(u *tuser, n int) string {
	h.t.Helper()
	id := vaultID(n)
	h.mustOK(u, &CreateVaultArgs{VaultID: id, EncMeta: box(64), EncRoster: box(64), WrappedKey: wk(u.id)})
	return id
}

func (h *harness) addMember(owner *tuser, vid string, m *tuser, role string) {
	h.t.Helper()
	h.mustOK(owner, &PutMemberArgs{VaultID: vid, UserID: m.id, Role: role, WrappedKey: wkp(owner.id), KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: h.rv(vid)})
}

// rv and ep read a vault's current roster version and key epoch (0 if the
// vault does not exist), for building commands in tests.
func (h *harness) rv(vid string) uint64 {
	h.f.mu.RLock()
	defer h.f.mu.RUnlock()
	if v := h.f.s.vaults[vid]; v != nil {
		return v.RosterVersion
	}
	return 0
}

func (h *harness) ep(vid string) uint32 {
	h.f.mu.RLock()
	defer h.f.mu.RUnlock()
	if v := h.f.s.vaults[vid]; v != nil {
		return v.KeyEpoch
	}
	return 0
}

func (h *harness) vault(u *tuser, vid string) api.Vault {
	h.t.Helper()
	r, ok := h.f.SyncView(u.id, 0)
	if !ok {
		h.t.Fatalf("unknown user %s", u.id)
	}
	for _, v := range r.Vaults {
		if v.ID == vid {
			return v
		}
	}
	h.t.Fatalf("vault %s not visible to %s", vid, u.name)
	return api.Vault{}
}

func (h *harness) visible(u *tuser, vid string) bool {
	r, _ := h.f.SyncView(u.id, 0)
	for _, v := range r.Vaults {
		if v.ID == vid {
			return true
		}
	}
	return false
}

func (h *harness) item(u *tuser, vid, iid string) (api.Item, bool) {
	for _, it := range h.vault(u, vid).Items {
		if it.ID == iid {
			return it, true
		}
	}
	return api.Item{}, false
}

func ptr[T any](v T) *T { return &v }

// Read helpers for tests (each takes the read lock once).

// HasUsers reports whether at least one user is registered.
func (f *FSM) HasUsers() (ok bool) {
	f.View(func(v *View) { ok = v.HasUsers() })
	return
}

// LookupUserByName returns the auth view of a user by canonical username.
func (f *FSM) LookupUserByName(name string) (u UserAuth, ok bool) {
	f.View(func(v *View) { u, ok = v.UserByName(name) })
	return
}

// SyncView returns the sync response for uid (see View.Sync).
func (f *FSM) SyncView(uid string, since uint64) (r *api.SyncResponse, ok bool) {
	f.View(func(v *View) { r, ok = v.Sync(uid, since) })
	return
}

// ListInvites lists non-revoked invites, oldest first.
func (f *FSM) ListInvites() (out []api.Invite) {
	f.View(func(v *View) { out = v.Invites() })
	return
}

// Directory lists every user, sorted by id.
func (f *FSM) Directory() (out []api.DirectoryUser) {
	f.View(func(v *View) { out = v.Directory() })
	return
}
