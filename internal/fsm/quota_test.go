package fsm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// usage returns the cached byte counter of a vault.
func usage(f *FSM, vid string) int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.vaults[vid].bytes
}

// checkCounters verifies every cached counter against a recomputation.
func checkCounters(t testing.TB, f *FSM) {
	t.Helper()
	f.mu.RLock()
	defer f.mu.RUnlock()
	for id, v := range f.s.vaults {
		for k, m := range v.Members {
			if m.UserID != k {
				t.Fatalf("vault %s: member %s stored under %s", id, m.UserID, k)
			}
		}
		for k, it := range v.Items {
			if it.ID != k {
				t.Fatalf("vault %s: item %s stored under %s", id, it.ID, k)
			}
		}
		cached := v.bytes
		v.recount()
		if v.bytes != cached {
			t.Fatalf("vault %s: cached usage %d, actual %d", id, cached, v.bytes)
		}
	}
}

// fill adds items to vault vid until its usage is exactly target.
func (h *harness) fill(u *tuser, vid string, target int64, next *int) {
	h.t.Helper()
	add := func(n int) {
		h.f.mu.RLock()
		epoch := h.f.s.vaults[vid].KeyEpoch
		h.f.mu.RUnlock()
		h.mustOK(u, &PutItemArgs{VaultID: vid, ItemID: itemID(*next), Blob: box(n), KeyEpoch: epoch})
		*next++
	}
	maxCost, minCost := itemCost(MaxItemBlobBytes), itemCost(MinBoxBytes)
	for {
		rem := target - usage(h.f, vid)
		switch {
		case rem == 0:
			return
		case rem > maxCost+minCost:
			add(MaxItemBlobBytes)
		case rem > maxCost:
			add(int(rem - minCost - ItemOverheadBytes))
		case rem >= minCost:
			add(int(rem - ItemOverheadBytes))
		default:
			h.t.Fatalf("cannot fill vault to exactly %d (remaining %d)", target, rem)
		}
	}
}

func quotaErr(t *testing.T, e *Error, which string) {
	t.Helper()
	if !strings.Contains(e.Message, which) {
		t.Fatalf("limit_exceeded message %q does not name the %s quota", e.Message, which)
	}
}

func TestVaultByteQuotaBoundary(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	vid := h.createVault(alice, 1)
	n := 0
	h.fill(alice, vid, MaxVaultBytes, &n)
	if got := usage(h.f, vid); got != MaxVaultBytes {
		t.Fatalf("usage %d", got)
	}
	// One byte over: a new item, a larger overwrite, larger metadata.
	quotaErr(t, h.mustErr(alice, &PutItemArgs{VaultID: vid, ItemID: itemID(9999), Blob: box(MinBoxBytes), KeyEpoch: 1}, api.CodeLimitExceeded), "vault")
	last, _ := h.item(alice, vid, itemID(n-1))
	quotaErr(t, h.mustErr(alice, &PutItemArgs{VaultID: vid, ItemID: last.ID, Blob: box(len(last.Blob) + 1), BaseVersion: last.Version, KeyEpoch: 1}, api.CodeLimitExceeded), "vault")
	v := h.vault(alice, vid)
	quotaErr(t, h.mustErr(alice, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(len(v.EncMeta) + 1), BaseMetaVersion: v.MetaVersion}, api.CodeLimitExceeded), "vault")
	big := rekeyArgs(v, alice.id)
	smallest := 0
	for i := range big.Items {
		big.Items[i].Blob = box(len(v.Items[i].Blob))
		if len(v.Items[i].Blob) < len(v.Items[smallest].Blob) {
			smallest = i
		}
	}
	big.EncMeta = box(len(v.EncMeta))
	big.Items[smallest].Blob = append(big.Items[smallest].Blob, 0)
	quotaErr(t, h.mustErr(alice, big, api.CodeLimitExceeded), "vault")
	// Equal-size and shrinking writes are always allowed.
	out := h.mustOK(alice, &PutItemArgs{VaultID: vid, ItemID: last.ID, Blob: box(len(last.Blob) - 1), BaseVersion: last.Version, KeyEpoch: 1})
	if usage(h.f, vid) != MaxVaultBytes-1 {
		t.Fatal("shrink not accounted")
	}
	h.mustOK(alice, &PutItemArgs{VaultID: vid, ItemID: last.ID, Blob: box(len(last.Blob)), BaseVersion: out.Version, KeyEpoch: 1})
	if usage(h.f, vid) != MaxVaultBytes {
		t.Fatal("back to exactly the cap")
	}
	v = h.vault(alice, vid)
	same := rekeyArgs(v, alice.id)
	for i := range same.Items {
		same.Items[i].Blob = box(len(v.Items[i].Blob))
	}
	same.EncMeta = box(len(v.EncMeta))
	h.mustOK(alice, same)
	if usage(h.f, vid) != MaxVaultBytes {
		t.Fatal("same-size rekey changed usage")
	}
	checkCounters(t, h.f)
	snapshotRoundTrip(t, h.f)
}

func TestUserAndClusterByteQuotas(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 48 MiB")
	}
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	n := 0
	// fullUser gives u vaults of 8 MiB, 4 MiB and 4 MiB minus the personal
	// vault's usage (metadata + roster): exactly the 16 MiB user quota, with
	// the middle vault well below the vault quota.
	fullUser := func(u *tuser, base int) (mid string) {
		v1, v2, v3 := h.createVault(u, base), h.createVault(u, base+1), h.createVault(u, base+2)
		h.fill(u, v1, MaxVaultBytes, &n)
		h.fill(u, v2, MaxVaultBytes/2, &n)
		h.fill(u, v3, MaxVaultBytes/2-usage(h.f, u.personal), &n)
		if got := creatorBytes(h.f.s, u.id); got != MaxUserBytes {
			t.Fatalf("%s usage %d", u.name, got)
		}
		return v2
	}
	a2 := fullUser(alice, 1)
	// a2 is below the vault cap, but alice is at her user cap.
	quotaErr(t, h.mustErr(alice, &PutItemArgs{VaultID: a2, ItemID: itemID(99999), Blob: box(MinBoxBytes), KeyEpoch: 1}, api.CodeLimitExceeded), "per-user")
	quotaErr(t, h.mustErr(alice, &CreateVaultArgs{VaultID: vaultID(9), EncRoster: box(64), EncMeta: box(MinBoxBytes), WrappedKey: wk(alice.id)}, api.CodeLimitExceeded), "per-user")
	// Writes by another member are charged to the creator.
	h.addMember(alice, a2, bob, api.RoleEditor)
	quotaErr(t, h.mustErr(bob, &PutItemArgs{VaultID: a2, ItemID: itemID(99999), Blob: box(MinBoxBytes), KeyEpoch: 1}, api.CodeLimitExceeded), "per-user")
	// bob has his own budget.
	fullUser(bob, 10)
	carol := h.addUser(alice, 3, "carol")
	c1, c2 := h.createVault(carol, 20), h.createVault(carol, 21)
	h.fill(carol, c1, MaxVaultBytes, &n)
	// The household is now short of its cap by exactly what carol may still add.
	rest := MaxClusterBytes - totalBytes(h.f.s)
	h.fill(carol, c2, rest+usage(h.f, c2), &n)
	if got := totalBytes(h.f.s); got != MaxClusterBytes {
		t.Fatalf("cluster usage %d", got)
	}
	// At the cluster cap even a registration (its personal vault metadata)
	// is refused, and so is any growth by anyone.
	hash := h.invite(alice, 4)
	dave := regArgs(4, "dave")
	dave.InviteHash = hash
	quotaErr(t, h.mustErr(nil, dave, api.CodeLimitExceeded), "household")
	pv := h.vault(carol, carol.personal)
	quotaErr(t, h.mustErr(carol, &UpdateVaultMetaArgs{VaultID: carol.personal, EncMeta: box(len(pv.EncMeta) + 1), BaseMetaVersion: pv.MetaVersion}, api.CodeLimitExceeded), "")
	// Freeing space anywhere makes room.
	it, _ := h.item(carol, c2, itemID(n-1))
	h.mustOK(carol, &DeleteItemArgs{VaultID: c2, ItemID: it.ID, BaseVersion: it.Version})
	h.mustOK(nil, dave)
	checkCounters(t, h.f)

	snap := snapshotRoundTrip(t, h.f)
	t.Logf("snapshot of a %d MiB household: %d bytes (%.1f MiB)", MaxClusterBytes>>20, len(snap), float64(len(snap))/(1<<20))
}

func TestQuotaDeltaAccounting(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleEditor)
	want := int64(64 + 64) // metadata + roster
	expect := func(what string) {
		t.Helper()
		if got := usage(h.f, vid); got != want {
			t.Fatalf("%s: usage %d, want %d", what, got, want)
		}
		checkCounters(t, h.f)
	}
	expect("create")
	o1 := h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(1000), KeyEpoch: 1})
	want += 1000 + ItemOverheadBytes
	expect("put")
	o1 = h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(300), BaseVersion: o1.Version, KeyEpoch: 1})
	want -= 700
	expect("shrinking overwrite")
	h.mustOK(alice, &PutItemArgs{VaultID: vid, ItemID: itemID(2), Blob: box(500), KeyEpoch: 1})
	want += 500 + ItemOverheadBytes
	expect("second item")
	v := h.vault(alice, vid)
	h.mustOK(alice, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(100), BaseMetaVersion: v.MetaVersion})
	want += 36
	expect("meta")
	v = h.vault(alice, vid)
	rk := rekeyArgs(v, alice.id) // rekeyArgs uses 500-byte blobs and 70 bytes of metadata
	h.mustOK(alice, rk)
	want = 70 + 64 + 2*(500+ItemOverheadBytes)
	expect("rekey")
	v = h.vault(alice, vid)
	h.mustOK(bob, &DeleteItemArgs{VaultID: vid, ItemID: itemID(1), BaseVersion: v.Items[0].Version})
	want -= 500 + ItemOverheadBytes
	expect("delete")
	before := totalBytes(h.f.s)
	h.mustOK(alice, &DeleteVaultArgs{VaultID: vid})
	if totalBytes(h.f.s) != before-want {
		t.Fatal("vault deletion not reflected in the cluster total")
	}
	// Counters after restore are recomputed and equal.
	other := h.createVault(alice, 2)
	h.mustOK(alice, &PutItemArgs{VaultID: other, ItemID: itemID(5), Blob: box(777), KeyEpoch: 1})
	snap, _ := h.f.Snapshot()
	g := New()
	if err := g.Restore(snap); err != nil {
		t.Fatal(err)
	}
	h.f.mu.RLock()
	for id, v := range h.f.s.vaults {
		if g.s.vaults[id].bytes != v.bytes {
			t.Fatalf("vault %s: %d after restore, %d before", id, g.s.vaults[id].bytes, v.bytes)
		}
	}
	h.f.mu.RUnlock()
	if bytes.Contains(snap, []byte(`"bytes"`)) {
		t.Fatal("derived counters must not be serialized")
	}
}

func TestRestoreAcceptsOverQuotaState(t *testing.T) {
	// Build a state under generous limits, then restore it into an FSM with
	// the real ones: it must load, refuse growth and allow shrinking.
	roomy := defaultLimits
	roomy.users, roomy.vaultsPerCreator, roomy.vaultBytes, roomy.userBytes = 40, 40, MaxVaultBytes+(1<<20), 64<<20
	h := &harness{t: t, f: newWithLimits(roomy), now: 1_700_000_000_000}
	h.mustOK(nil, &InitArgs{ClusterKey: bytes.Repeat([]byte{7}, 32)})
	alice := h.bootstrap(0, "u0")
	for i := 1; i < 40; i++ {
		h.addUser(alice, i, fmt.Sprintf("u%d", i))
	}
	for i := 1; i < 40; i++ {
		h.createVault(alice, i)
	}
	big := vaultID(1)
	n := 0
	h.fill(alice, big, MaxVaultBytes+(1<<20), &n)
	snap, _ := h.f.Snapshot()
	if err := ValidateSnapshot(snap); err != nil {
		t.Fatalf("over-quota state rejected: %v", err)
	}
	f := New()
	if err := f.Restore(snap); err != nil {
		t.Fatalf("over-quota state rejected: %v", err)
	}
	h.f = f
	h.mustErr(alice, &CreateVaultArgs{VaultID: vaultID(500), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)}, api.CodeLimitExceeded)
	inv := regArgs(77, "late")
	inv.InviteHash = h.invite(alice, 77)
	h.mustErr(nil, inv, api.CodeLimitExceeded)
	it, _ := h.item(alice, big, itemID(n-1)) // the small remainder item
	h.mustErr(alice, &PutItemArgs{VaultID: big, ItemID: it.ID, Blob: box(len(it.Blob) + 1), BaseVersion: it.Version, KeyEpoch: 1}, api.CodeLimitExceeded)
	out := h.mustOK(alice, &PutItemArgs{VaultID: big, ItemID: it.ID, Blob: box(len(it.Blob) - 10), BaseVersion: it.Version, KeyEpoch: 1})
	h.mustOK(alice, &DeleteItemArgs{VaultID: big, ItemID: it.ID, BaseVersion: out.Version})
	v := h.vault(alice, big)
	same := rekeyArgs(v, alice.id)
	for i := range same.Items {
		same.Items[i].Blob = box(len(v.Items[i].Blob))
	}
	same.EncMeta = box(len(v.EncMeta))
	h.mustOK(alice, same) // a same-size rekey is never blocked
	h.mustOK(alice, &DeleteVaultArgs{VaultID: vaultID(2)})
	checkCounters(t, h.f)
}

// TestSnapshotSizeAtClusterCap builds the largest state the limits allow
// (32 users, 32 vaults each, every shared vault with all 32 members, a full
// invite table and idempotency table, and ciphertext up to the household
// quota) and checks that its snapshot stays far below the peer transport's
// 128 MiB message limit. Two fillings are measured: maximum-size items
// (worst base64 expansion) and minimum-size items (worst metadata count).
func TestSnapshotSizeAtClusterCap(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("builds two ~70 MiB states")
	}
	for _, blobSize := range []int{MaxItemBlobBytes, MinBoxBytes} {
		h := newHarness(t)
		users := []*tuser{h.bootstrap(0, "u0")}
		for i := 1; i < MaxUsers; i++ {
			users = append(users, h.addUser(users[0], i, fmt.Sprintf("u%02d", i)))
		}
		var vaults []string
		owner := map[string]*tuser{}
		for ui, u := range users {
			for j := 1; j < MaxVaultsPerOwner; j++ {
				vid := vaultID(100000 + ui*100 + j)
				owner[vid] = u
				h.mustOK(u, &CreateVaultArgs{VaultID: vid, EncRoster: box(64), EncMeta: box(MaxEncMetaBytes), WrappedKey: wk(u.id)})
				for _, m := range users {
					if m != u {
						h.mustOK(u, &PutMemberArgs{VaultID: vid, UserID: m.id, Role: api.RoleEditor, WrappedKey: wkp(u.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)})
					}
				}
				vaults = append(vaults, vid)
			}
		}
		for i := 0; i < MaxPendingInvites; i++ {
			h.mustOK(users[0], &CreateInviteArgs{InviteHash: inviteHash(5000 + i), TTLHours: 720})
		}
		// Fill with items until the household quota is reached, respecting
		// the per-vault, per-user and per-vault item limits.
		next := 0
		cost := itemCost(blobSize)
		for _, vid := range vaults {
			o := owner[vid]
			v := h.f.s.vaults[vid]
			userUsed, total := creatorBytes(h.f.s, o.id), totalBytes(h.f.s)
			for len(v.Items) < MaxItemsPerVault && v.bytes+cost <= MaxVaultBytes &&
				userUsed+cost <= MaxUserBytes && total+cost <= MaxClusterBytes {
				h.mustOK(o, &PutItemArgs{VaultID: vid, ItemID: itemID(next), Blob: box(blobSize), KeyEpoch: 1})
				next++
				userUsed += cost
				total += cost
			}
			if totalBytes(h.f.s)+cost > MaxClusterBytes {
				break
			}
		}
		total := totalBytes(h.f.s)
		if MaxClusterBytes-total >= cost {
			t.Fatalf("did not reach the cluster cap: %d of %d", total, MaxClusterBytes)
		}
		snap, err := h.f.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("blob size %d: %d items, %d vaults, usage %d bytes; snapshot %d bytes (%.1f MiB)",
			blobSize, next, len(h.f.s.vaults), total, len(snap), float64(len(snap))/(1<<20))
		if len(snap) >= 100<<20 {
			t.Fatalf("snapshot at the cluster cap is %d bytes, want < 100 MiB", len(snap))
		}
		if err := ValidateSnapshot(snap); err != nil {
			t.Fatal(err)
		}
	}
}

func creatorBytes(s *state, uid string) int64 { u, _ := s.usage(uid); return u }
func totalBytes(s *state) int64               { _, t := s.usage(""); return t }
