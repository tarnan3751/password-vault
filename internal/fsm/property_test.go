package fsm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// cmdGen produces long random command sequences, valid and invalid mixed.
// It peeks at a reference replica so that a good share of commands is
// plausible (current epochs, current versions, exact rekeys), which drives
// the state deep instead of bouncing off validation.
type cmdGen struct {
	rng     *rand.Rand
	ref     *FSM
	now     int64
	reqIDs  []string
	invites []string
	n       int
	// window > 0 restricts re-delivered entries and reused request ids to
	// the most recent window commands. Re-delivery older than the
	// idempotency capacity would legitimately re-execute (a documented
	// bound, not a bug), so the long eviction test keeps duplicates recent.
	window int
	fresh  []int                        // indices (in history) of freshly generated commands
	views  map[string]*api.SyncResponse // per-step cache of ref.SyncView
}

func (g *cmdGen) sync(uid string) (*api.SyncResponse, bool) {
	if r, ok := g.views[uid]; ok {
		return r, r != nil
	}
	r, ok := g.ref.SyncView(uid, 0)
	if !ok {
		r = nil
	}
	g.views[uid] = r
	return r, ok
}

func (g *cmdGen) recent(n int) int {
	if g.window > 0 && n > g.window {
		return n - 1 - g.pick(g.window)
	}
	return g.pick(n)
}

const (
	genUsers  = 8
	genVaults = 10
	genItems  = 12
)

func (g *cmdGen) hex(n int) string {
	b := make([]byte, n/2)
	for i := range b {
		b[i] = byte(g.rng.IntN(256))
	}
	return fmt.Sprintf("%x", b)
}

func (g *cmdGen) pick(n int) int { return g.rng.IntN(n) }
func (g *cmdGen) chance(p float64) bool {
	return g.rng.Float64() < p
}

func (g *cmdGen) caller(wantAdmin bool) (string, uint64) {
	id := userID(g.pick(genUsers))
	var pool []string
	for _, d := range g.ref.Directory() {
		if !d.Disabled && (!wantAdmin || d.IsAdmin) {
			pool = append(pool, d.UserID)
		}
	}
	if len(pool) > 0 && g.chance(0.9) {
		id = pool[g.pick(len(pool))]
	}
	u, ok := g.ref.LookupUserByID(id)
	if !ok {
		return id, 1
	}
	switch {
	case g.chance(0.9):
		return id, u.TokenEpoch
	case g.chance(0.5):
		return id, u.TokenEpoch - 1
	default:
		return id, u.TokenEpoch + 1
	}
}

func (g *cmdGen) view(uid, vid string) (api.Vault, bool) {
	r, ok := g.sync(uid)
	if !ok {
		return api.Vault{}, false
	}
	for _, v := range r.Vaults {
		if v.ID == vid {
			return v, true
		}
	}
	return api.Vault{}, false
}

func (g *cmdGen) blob(max int) []byte {
	n := MinBoxBytes + g.pick(200)
	switch {
	case g.chance(0.03):
		n = g.pick(MinBoxBytes)
	case g.chance(0.02):
		n = max + 1
	}
	return box(max0(n))
}

func max0(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func (g *cmdGen) wrapped(sender string) api.WrappedKey {
	if g.chance(0.05) {
		sender = userID(g.pick(genUsers))
	}
	w := wk(sender)
	if g.chance(0.02) {
		w.Blob = box(104)
	}
	return w
}

func (g *cmdGen) next(history [][]byte) []byte {
	g.n++
	g.views = map[string]*api.SyncResponse{}
	g.now += g.rng.Int64N(3_600_000)
	if g.chance(0.03) {
		g.now -= g.rng.Int64N(600_000) // a proposer with a slightly slow clock
	}
	// Re-deliveries and key reuse only ever refer back to FRESH commands, so
	// they cannot chain back past the idempotency capacity in long runs
	// (a re-delivery of an evicted entry legitimately re-executes).
	if len(g.fresh) > 0 && g.chance(0.04) {
		return history[g.fresh[g.recent(len(g.fresh))]] // a duplicated log entry
	}
	if g.chance(0.02) {
		return g.garbage(history)
	}
	g.fresh = append(g.fresh, len(history))
	reqID := g.hex(32)
	if len(g.reqIDs) > 0 && g.chance(0.03) {
		reqID = g.reqIDs[g.recent(len(g.reqIDs))] // key reuse (mostly a mismatch)
	} else {
		g.reqIDs = append(g.reqIDs, reqID)
	}

	op := 1 + g.pick(15)
	switch {
	case !g.ref.Initialized() && g.chance(0.8), g.chance(0.01):
		op = 0
	case len(g.ref.Directory()) < genUsers && g.chance(0.25):
		op = 1 // registrations are needed to get anywhere
	}
	uid, ep := g.caller(op >= 3 && op <= 5 && g.chance(0.8))
	var args Args
	switch op {
	case 0:
		args = &InitArgs{ClusterKey: bytes.Repeat([]byte{byte(g.n)}, 32)}
		uid, ep = "", 0
	case 1, 2:
		args = g.register()
		uid, ep = "", 0
	case 3:
		h := g.hex(64)
		g.invites = append(g.invites, h)
		ttl := 1 + g.pick(100)
		if g.chance(0.05) {
			ttl = 721
		}
		args = &CreateInviteArgs{InviteHash: h, TTLHours: ttl}
	case 4:
		id := g.hex(16)
		if len(g.invites) > 0 && g.chance(0.8) {
			id = g.invites[g.pick(len(g.invites))][:16]
		}
		args = &RevokeInviteArgs{InviteID: id}
	case 5:
		a := &AdminUpdateUserArgs{UserID: userID(g.pick(genUsers))}
		if g.chance(0.6) {
			a.Disabled = ptr(g.chance(0.4))
		}
		if g.chance(0.6) {
			a.IsAdmin = ptr(g.chance(0.5))
		}
		args = a
	case 6:
		k := kdf()
		if g.chance(0.05) {
			k.Time = 1
		}
		args = &ChangePasswordArgs{NewKDF: k, NewWrappedAccountKey: g.blob(MaxAccountBlobBytes), Verifier: verifier(byte(g.n))}
	case 7:
		args = &RevokeSessionsArgs{}
	case 8:
		args = &CreateVaultArgs{VaultID: vaultID(g.pick(genVaults)), EncMeta: g.blob(MaxEncMetaBytes), EncRoster: g.blob(MaxRosterBytes), WrappedKey: g.wrapped(uid)}
	case 9:
		vid := g.vaultFor(uid)
		base := uint64(g.pick(5))
		if v, ok := g.view(uid, vid); ok && g.chance(0.8) {
			base = v.MetaVersion
		}
		args = &UpdateVaultMetaArgs{VaultID: vid, EncMeta: g.blob(MaxEncMetaBytes), BaseMetaVersion: base}
	case 10:
		args = &DeleteVaultArgs{VaultID: g.vaultFor(uid)}
	case 11:
		vid := g.vaultPick(uid, true)
		a := &PutMemberArgs{VaultID: vid, UserID: userID(g.pick(genUsers)), Role: []string{api.RoleOwner, api.RoleEditor, api.RoleViewer}[g.pick(3)]}
		if g.chance(0.03) {
			a.Role = "guest"
		}
		a.EncRoster = g.blob(MaxRosterBytes)
		a.BaseRosterVersion = uint64(g.pick(4))
		if v, ok := g.view(uid, vid); ok {
			if g.chance(0.9) {
				a.KeyEpoch = v.KeyEpoch
			}
			if g.chance(0.85) { // otherwise a stale roster version: a CAS conflict
				a.BaseRosterVersion = v.RosterVersion
			}
		}
		if g.chance(0.7) {
			w := g.wrapped(uid)
			a.WrappedKey = &w
		}
		args = a
	case 12:
		vid := g.vaultPick(uid, true)
		target := userID(g.pick(genUsers))
		if v, ok := g.view(uid, vid); ok && g.chance(0.7) {
			target = v.Members[g.pick(len(v.Members))].UserID
		} else if g.chance(0.3) {
			target = uid
		}
		args = &RemoveMemberArgs{VaultID: vid, UserID: target}
	case 13:
		args = g.rekey(uid, g.vaultFor(uid))
	case 14:
		vid, iid := g.vaultFor(uid), itemID(g.pick(genItems))
		a := &PutItemArgs{VaultID: vid, ItemID: iid, Blob: g.blob(MaxItemBlobBytes), BaseVersion: uint64(g.pick(3))}
		if v, ok := g.view(uid, vid); ok {
			if g.chance(0.9) {
				a.KeyEpoch = v.KeyEpoch
			}
			if g.chance(0.8) {
				a.BaseVersion = 0
				for _, it := range v.Items {
					if it.ID == iid {
						a.BaseVersion = it.Version
					}
				}
			}
		}
		args = a
	case 15:
		vid, iid := g.vaultFor(uid), itemID(g.pick(genItems))
		a := &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: uint64(1 + g.pick(3))}
		if v, ok := g.view(uid, vid); ok && g.chance(0.8) {
			for _, it := range v.Items {
				if it.ID == iid {
					a.BaseVersion = it.Version
				}
			}
		}
		args = a
	}
	b, err := EncodeCommand(reqID, g.now, uid, ep, args)
	if err != nil {
		panic(err)
	}
	return b
}

// vaultFor mostly picks a vault the caller can see, so that vault ops get
// past the membership check and exercise the interesting rules.
func (g *cmdGen) vaultFor(uid string) string { return g.vaultPick(uid, false) }

func (g *cmdGen) vaultPick(uid string, shared bool) string {
	if r, ok := g.sync(uid); ok && len(r.Vaults) > 0 && g.chance(0.8) {
		var pool []string
		for _, v := range r.Vaults {
			if !shared || !v.Personal || g.chance(0.1) {
				pool = append(pool, v.ID)
			}
		}
		if len(pool) > 0 {
			return pool[g.pick(len(pool))]
		}
	}
	if g.chance(0.3) {
		return vaultID(500 + g.pick(genUsers)) // personal vaults
	}
	return vaultID(g.pick(genVaults))
}

func (g *cmdGen) register() *RegisterArgs {
	i := g.pick(genUsers)
	if g.chance(0.85) {
		for _, j := range g.rng.Perm(genUsers) {
			if _, taken := g.ref.LookupUserByID(userID(j)); !taken {
				i = j
				break
			}
		}
	}
	uid := userID(i)
	a := &RegisterArgs{
		UserID: uid, Username: fmt.Sprintf("user%d", i), KDF: kdf(), Verifier: verifier(byte(g.n)),
		PublicKey: bytes.Repeat([]byte{byte(i)}, 32), WrappedAccountKey: g.blob(MaxAccountBlobBytes), EncPrivateKey: box(73),
		PersonalVault: api.CreateVaultRequest{VaultID: vaultID(500 + i), EncMeta: g.blob(MaxEncMetaBytes), EncRoster: g.blob(MaxRosterBytes), WrappedKey: g.wrapped(uid)},
	}
	switch {
	case g.chance(0.05):
		a.Username = fmt.Sprintf("user%d", g.pick(genUsers)) // possible collision
	case g.chance(0.05):
		a.PersonalVault.VaultID = vaultID(g.pick(genVaults))
	}
	switch {
	case !g.ref.HasUsers() && g.chance(0.7), g.chance(0.05):
		a.Bootstrap = true
	case g.chance(0.85):
		open := map[string]bool{}
		for _, inv := range g.ref.ListInvites() {
			if inv.UsedBy == "" && g.now < inv.ExpiresAt {
				open[inv.InviteID] = true
			}
		}
		var pending []string
		for _, h := range g.invites {
			if open[h[:16]] {
				pending = append(pending, h)
			}
		}
		if len(pending) == 0 && len(g.invites) > 0 {
			pending = g.invites
		}
		if len(pending) == 0 {
			pending = []string{g.hex(64)}
		}
		a.InviteHash = pending[g.pick(len(pending))]
	default:
		a.InviteHash = g.hex(64)
	}
	return a
}

func (g *cmdGen) rekey(uid, vid string) *RekeyArgs {
	v, ok := g.view(uid, vid)
	if !ok {
		return &RekeyArgs{VaultID: vid, NewKeyEpoch: 2, EncMeta: box(64), EncRoster: box(64)}
	}
	a := rekeyArgs(v, uid)
	a.EncRoster = g.blob(MaxRosterBytes)
	// Remove some other members in the same rekey (the normal way to remove
	// someone): drop them from the wrapped keys too.
	if g.chance(0.7) {
		for _, m := range v.Members {
			if m.UserID != uid && g.chance(0.5) {
				a.Remove = append(a.Remove, m.UserID)
				delete(a.WrappedKeys, m.UserID)
			}
		}
	}
	switch {
	case g.chance(0.04) && len(a.Remove) > 0:
		a.WrappedKeys[a.Remove[0]] = wk(uid) // still wrapping for a removed member
	case g.chance(0.04):
		a.Remove = append(a.Remove, userID(g.pick(genUsers))) // maybe not a member, maybe the caller
	case g.chance(0.02) && len(a.Remove) > 0:
		a.Remove = append(a.Remove, a.Remove[0])
	case g.chance(0.05):
		a.BaseRev++
	case g.chance(0.05):
		a.NewKeyEpoch++
	case g.chance(0.05) && len(a.Items) > 0:
		a.Items = a.Items[1:]
	case g.chance(0.05):
		a.WrappedKeys[userID(g.pick(genUsers))] = wk(uid)
	}
	return a
}

func (g *cmdGen) garbage(history [][]byte) []byte {
	switch g.pick(3) {
	case 0:
		b := make([]byte, g.pick(64))
		for i := range b {
			b[i] = byte(g.rng.IntN(256))
		}
		return b
	case 1:
		if len(history) > 0 {
			h := history[g.pick(len(history))]
			return h[:g.pick(len(h))]
		}
	}
	var env Command
	if len(history) > 0 && json.Unmarshal(history[g.pick(len(history))], &env) == nil {
		env.Args = json.RawMessage(`{"vault_id":5}`)
		b, _ := json.Marshal(env)
		return b
	}
	return []byte(`{"op":"put_item"}`)
}

func runDeterminism(t *testing.T, seed uint64, n, dupWindow int, lim limits) map[string]int {
	t.Helper()
	a := newWithLimits(lim)
	g := &cmdGen{rng: rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15)), ref: a, now: 1_700_000_000_000}
	if n > IdempotencyCapacity {
		g.window = dupWindow
	}
	cmds := make([][]byte, 0, n)
	results := make([][]byte, 0, n)
	oks := 0
	limitHits := map[string]int{}
	for i := 0; i < n; i++ {
		c := g.next(cmds)
		cmds = append(cmds, c)
		r := a.Apply(uint64(i+1), c)
		results = append(results, r)
		if bytes.HasPrefix(r, []byte(`{"ok"`)) {
			oks++
			var env Command
			var rk RekeyArgs
			if json.Unmarshal(c, &env) == nil && env.Op == OpRekey && json.Unmarshal(env.Args, &rk) == nil && len(rk.Remove) > 0 {
				limitHits["ok: rekey with remove"]++
			}
		} else if res, err := DecodeResult(r); err == nil {
			limitHits[res.Err.Message]++
		}
	}
	if oks < n/5 {
		t.Fatalf("seed %d: only %d/%d commands succeeded; generator too weak", seed, oks, n)
	}

	rng := rand.New(rand.NewPCG(seed+1, 7))
	b := newWithLimits(lim)
	restores, dups := 0, 0
	for i, c := range cmds {
		if rng.IntN(25) == 0 {
			snap, err := b.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			fresh := newWithLimits(lim)
			if err := fresh.Restore(snap); err != nil {
				t.Fatalf("seed %d step %d: restore: %v", seed, i, err)
			}
			b = fresh
			restores++
			checkCounters(t, b)
		}
		if got := b.Apply(uint64(1_000_000+i), c); !bytes.Equal(got, results[i]) {
			t.Fatalf("seed %d step %d: result diverged\nA: %s\nB: %s\ncmd: %.300s", seed, i, results[i], got, c)
		}
		if i > 0 && rng.IntN(8) == 0 {
			j := i - rng.IntN(min(i, dupWindow))
			// The final hash comparison with A (which never sees these
			// extra deliveries) proves duplicates changed nothing; checking
			// rev here just localizes a failure cheaply.
			before := b.Rev()
			if got := b.Apply(uint64(2_000_000+i), cmds[j]); !bytes.Equal(got, results[j]) {
				t.Fatalf("seed %d: duplicate of step %d at %d returned a different result\nwant: %s\ngot:  %s", seed, j, i, results[j], got)
			}
			if b.Rev() != before {
				t.Fatalf("seed %d: duplicate of step %d at %d changed the state", seed, j, i)
			}
			dups++
		}
	}
	if a.StateHash() != b.StateHash() {
		t.Fatalf("seed %d: replicas diverged", seed)
	}
	sa, _ := a.Snapshot()
	sb, _ := b.Snapshot()
	if !bytes.Equal(sa, sb) {
		t.Fatalf("seed %d: snapshots differ", seed)
	}
	checkEncoder(t, a)
	c := newWithLimits(lim)
	if err := c.Restore(sa); err != nil || c.StateHash() != a.StateHash() {
		t.Fatalf("seed %d: restore of final snapshot: %v", seed, err)
	}
	// The usage counters are not part of the snapshot; they must agree too.
	checkCounters(t, a)
	checkCounters(t, b)
	for id, v := range a.s.vaults {
		if b.s.vaults[id].bytes != v.bytes || c.s.vaults[id].bytes != v.bytes {
			t.Fatalf("seed %d: usage of vault %s differs between replicas", seed, id)
		}
	}
	t.Logf("seed %d: %d commands, %d ok, rev %d, %d restores, %d duplicates, limit hits %v", seed, n, oks, a.Rev(), restores, dups, limitHits)
	return limitHits
}

// TestDeterminismWithQuotas runs the property test with tiny limits so that
// every count limit and storage quota is hit often, alongside shrinking
// writes and deletes of over-full vaults.
func TestDeterminismWithQuotas(t *testing.T) {
	tiny := limits{users: 5, vaultsPerCreator: 3, itemsPerVault: 4, vaultBytes: 2000, userBytes: 3000, clusterBytes: 11000}
	seeds := 8
	if testing.Short() || raceEnabled {
		seeds = 2
	}
	seen := map[string]int{}
	for s := 1; s <= seeds; s++ {
		for msg, n := range runDeterminism(t, uint64(100+s), 1500, 1000, tiny) {
			seen[msg] += n
		}
	}
	for _, want := range []string{"vault storage quota", "per-user storage quota", "household storage quota",
		"maximum number of users", "vault limit reached", "item limit reached"} {
		if testing.Short() || raceEnabled {
			break // too few seeds to hit every limit; the full run checks
		}
		hit := false
		for msg := range seen {
			if strings.Contains(msg, want) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("the generator never hit %q (seen: %v)", want, seen)
		}
	}
}

func TestDeterminismProperty(t *testing.T) {
	seeds := 12
	if testing.Short() || raceEnabled {
		seeds = 2
	}
	seen := map[string]int{}
	for s := 1; s <= seeds; s++ {
		for msg, n := range runDeterminism(t, uint64(s), 1500, 1000, defaultLimits) {
			seen[msg] += n
		}
	}
	// The roster and rekey-with-remove paths must actually be exercised
	// (checked on the full run; the reduced -short/-race run has too few
	// seeds to hit every rare path).
	for _, want := range []string{"ok: rekey with remove", "base_roster_version does not match",
		"remove lists a user who is not a member", "wrapped_keys must cover exactly the remaining members",
		"the caller cannot remove themself"} {
		if seen[want] == 0 && !testing.Short() && !raceEnabled {
			found := false
			for msg := range seen {
				found = found || strings.HasPrefix(msg, want)
			}
			if !found {
				t.Errorf("the generator never produced %q", want)
			}
		}
	}
	t.Logf("rekeys with remove: %d, roster CAS conflicts: %d", seen["ok: rekey with remove"], seen["base_roster_version does not match"])
}

// TestDeterminismWithEviction runs past the idempotency capacity, so
// eviction order is exercised (duplicates stay within a recent window,
// which is what Raft re-delivery looks like in practice).
func TestDeterminismWithEviction(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("long single-goroutine sequence; runs without -race/-short")
	}
	runDeterminism(t, 99, IdempotencyCapacity+2500, 300, defaultLimits)
}
