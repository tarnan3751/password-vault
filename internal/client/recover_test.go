package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// TestRecoveryDrill is the real end-to-end drill: back up the servers, change
// things (including a rekey), restore the OLD backup into fresh storage the way
// `vaultd restore` does, and watch the devices refuse, then recover on request.
func TestRecoveryDrill(t *testing.T) {
	h := newHousehold(t)
	cl := h.cl
	dc, carol := h.newUser("carol", pwCarol)
	must(t, h.alice.Sync(bg))

	// Before the backup: a vault shared with bob (both sides verified), and a
	// vault carol shares with alice, whom alice never verified.
	early := mv(h.alice.CreateVault(bg, "Early"))
	mv(h.alice.CreateItem(bg, early, loginItem("early item")))
	shareVerified(t, h.alice, h.bob, early, api.RoleEditor)
	fromCarol := mv(carol.CreateVault(bg, "From carol"))
	must(t, carol.Sync(bg))
	carol.verifyUser(t, "alice")
	must(t, carol.AddMember(bg, fromCarol, "alice", api.RoleViewer))
	must(t, h.alice.Sync(bg))
	if h.alice.Vault(fromCarol).Locked != LockPending {
		t.Fatal("setup: carol's vault should be pending for alice")
	}
	backup := mv(h.alice.ServerBackup(bg))

	// After the backup: more changes, a rekey and a new vault.
	mv(h.alice.CreateItem(bg, early, loginItem("late item")))
	must(t, h.alice.RekeyVault(bg, early, RekeyOptions{}))
	late := mv(h.alice.CreateVault(bg, "Late"))
	shareVerified(t, h.alice, h.bob, late, api.RoleEditor)
	must(t, h.bob.Sync(bg))
	if h.alice.Vault(early).KeyEpoch != 2 || h.bob.Vault(early).KeyEpoch != 2 {
		t.Fatal("setup: expected epoch 2")
	}
	revBefore := h.alice.Rev()

	// Disaster: restore the older backup.
	cl.RestoreFrom(backup)
	_ = dc

	// 1. A fresh login is blocked with the right error (and the exit-4 class).
	_, err := Login(bg, h.da.fresh(cl).deps, "alice", pwAlice) // no cache on that device: it cannot tell...
	if err != nil {
		t.Fatalf("a device that never saw the newer state has nothing to compare: %v", err)
	}
	_, err = Login(bg, h.da.deps, "alice", pwAlice)
	var rs *RestoredStateError
	if !errors.As(err, &rs) || !IsUnavailable(err) || rs.ServerRev >= rs.SeenRev {
		t.Fatalf("login against restored servers: %v", err)
	}
	if rs.ServerRev >= revBefore {
		t.Fatalf("restored rev %d not below %d", rs.ServerRev, revBefore)
	}
	// 2. Open(): the offline cache stays readable, writes are refused, state recorded.
	op := mv(Open(bg, h.da.deps, "alice", pwAlice))
	if op.Mode() != ModeOlder || op.Recovery() == nil {
		t.Fatalf("Open mode %v", op.Mode())
	}
	if op.Vault(late) == nil || op.Vault(early).KeyEpoch != 2 {
		t.Fatal("the offline cache is not readable")
	}
	var ro *ReadOnlyError
	if _, err := op.CreateItem(bg, personalVault(t, op).ID, loginItem("x")); !errors.As(err, &ro) || ro.Reason != ReasonOlder {
		t.Fatalf("write in the older state: %v", err)
	}
	if err := op.Sync(bg); err != nil || op.Mode() != ModeOlder {
		t.Fatalf("sync: %v mode %v", err, op.Mode())
	}
	if !strings_contains(op.Warnings(), "OLDER data") {
		t.Fatalf("warnings: %v", op.Warnings())
	}
	// 3. Recovery: contacts and verifications survive; records are re-evaluated.
	rec := mv(BeginRecovery(bg, h.da.deps, "alice", pwAlice))
	if rec.Info.ServerRev >= rec.Info.SeenRev || len(rec.Info.LowerEpochVaults) != 1 || rec.Info.LowerEpochVaults[0] != early {
		t.Fatalf("recovery info: %+v", rec.Info)
	}
	// Nothing changed before Accept.
	if again := mv(UnlockOffline(Deps{Store: h.da.store}, "alice", pwAlice)); again.Rev() != revBefore {
		t.Fatalf("cache changed before accepting: rev %d", again.Rev())
	}
	s := mv(rec.Accept())
	if s.Mode() != ModeOnline || s.Recovery() != nil {
		t.Fatalf("after accept: mode %v", s.Mode())
	}
	if s.Vault(late) != nil {
		t.Fatal("a vault that does not exist in the backup is still listed")
	}
	ev := s.Vault(early)
	if ev == nil || ev.Locked != NotLocked || ev.KeyEpoch != 1 || len(ev.Items) != 1 {
		t.Fatalf("early vault after recovery: %+v", ev)
	}
	if v := s.Vault(fromCarol); v.Locked != LockPending {
		t.Fatalf("a vault from an unverified sender must stay pending, got %q", v.Locked)
	}
	if u := mv(s.ResolveUser("bob")); !u.Verified {
		t.Fatal("recovery cleared a verified contact")
	}
	if u := mv(s.ResolveUser("carol")); u.Verified {
		t.Fatal("recovery verified an unverified contact")
	}
	if c := mv(h.da.store.LoadCache()); c.Sync.Rev != s.Rev() || c.Sync.Rev >= revBefore {
		t.Fatalf("cache not replaced: rev %d", c.Sync.Rev)
	}
	if _, err := s.CreateItem(bg, early, loginItem("after recovery")); err != nil {
		t.Fatalf("writes after recovery: %v", err)
	}
	// A normal later session is quiet.
	if q := mv(Open(bg, h.da.deps, "alice", pwAlice)); q.Mode() != ModeOnline || q.Recovery() != nil {
		t.Fatalf("later session: %v", q.Mode())
	}
	// Recovery with nothing to recover is refused.
	if _, err := BeginRecovery(bg, h.da.deps, "alice", pwAlice); !errors.Is(err, ErrNothingToRecover) {
		t.Fatalf("second recovery: %v", err)
	}

	// Bob's device: blocked, then recovers; alice (whom he verified) is still accepted without a prompt.
	if _, err := Login(bg, h.db.deps, "bob", pwBob); !errors.As(err, &rs) {
		t.Fatalf("bob: %v", err)
	}
	brec := mv(BeginRecovery(bg, h.db.deps, "bob", pwBob))
	bs := mv(brec.Accept())
	if v := bs.Vault(early); v == nil || v.Locked != NotLocked || v.KeyEpoch != 1 {
		t.Fatalf("bob's vault after recovery: %+v", v)
	}
}

func strings_contains(ws []string, sub string) bool {
	for _, w := range ws {
		if len(w) >= len(sub) {
			for i := 0; i+len(sub) <= len(w); i++ {
				if w[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// TestRecoveryRefusals: recovery is never offered when there is nothing to
// recover, for a key mismatch, or for a different key at a recorded epoch, and a
// refused attempt changes nothing on disk.
func TestRecoveryRefusals(t *testing.T) {
	l := newLiar(t)
	vid := mv(l.alice.CreateVault(bg, "V"))
	shareVerified(t, l.alice, l.bob, vid, api.RoleEditor)
	mv(l.alice.CreateItem(bg, vid, loginItem("x")))
	must(t, l.alice.Sync(bg))
	rev := l.alice.Rev()

	// Nothing to recover from an honest server.
	if _, err := BeginRecovery(bg, l.da.deps, "alice", pwAlice); !errors.Is(err, ErrNothingToRecover) {
		t.Fatalf("honest server: %v", err)
	}

	older := func(r *api.SyncResponse) { r.Rev = rev - 1 }
	bobID := l.bob.UserID
	altVK := vaultcrypto.NewVaultKey()
	altWrap := mv(vaultcrypto.WrapVaultKey(altVK, vaultcrypto.WrapContext{VaultID: vid, KeyEpoch: 1, SenderID: l.alice.UserID, RecipientID: l.alice.UserID}, &l.alice.secrets.PrivateKey, &l.alice.secrets.PublicKey))
	altMeta := mv(vaultcrypto.EncryptVaultMeta(altVK, vid, 1, &vaultcrypto.VaultMeta{Name: "Evil"}))
	cases := map[string]func(*api.SyncResponse){
		"older rev with a key mismatch": func(r *api.SyncResponse) {
			older(r)
			forUser(r, bobID, func(d *api.DirectoryUser) { d.PublicKey = randKey() })
		},
		"older rev with a different key at the recorded epoch": func(r *api.SyncResponse) {
			older(r)
			v := findVault(r, vid)
			v.MyKey.Blob, v.EncMeta = altWrap, altMeta
		},
	}
	for name, mut := range cases {
		before := l.snap(l.alice)
		l.h.set(mut)
		_, err := BeginRecovery(bg, l.da.deps, "alice", pwAlice)
		l.h.set(nil)
		var rr *RecoveryRefusedError
		if !errors.As(err, &rr) {
			t.Fatalf("%s: want RecoveryRefusedError, got %v", name, err)
		}
		after := l.snap(l.alice)
		if string(before.cache) != string(after.cache) || string(before.trust) != string(after.trust) {
			t.Fatalf("%s: a refused recovery changed local state", name)
		}
		if _, err := os.Stat(filepath.Join(l.da.store.Dir, "cache.json")); err != nil {
			t.Fatal(err)
		}
	}
	// A mismatch also blocks accepting the restored state in a session that already saw one.
	l.h.set(func(r *api.SyncResponse) {
		older(r)
		forUser(r, bobID, func(d *api.DirectoryUser) { d.PublicKey = randKey() })
	})
	if _, err := BeginRecovery(bg, l.da.deps, "alice", pwAlice); err == nil {
		t.Fatal("recovery offered during a key mismatch")
	}
}
