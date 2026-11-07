package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// Regression tests that the client refuses invalid or inconsistent server
// responses. A "lying server" is the real server behind a RoundTripper that
// rewrites sync responses. Every test asserts the specific error AND that
// nothing was written: no state-changing request, an unchanged offline cache
// and an unchanged trust store.

type liar struct {
	t      *testing.T
	cl     *clienttest.Cluster
	h      *hostile
	da, db *device
	alice  *Session
	bob    *Session
}

func newLiar(t *testing.T) *liar {
	t.Helper()
	cl := clienttest.New(t, 1)
	l := &liar{t: t, cl: cl, h: newHostile()}
	l.da = newDevice(t, cl, withTransport(l.h))
	l.alice = l.da.register("alice", pwAlice, clienttest.BootstrapToken)
	inv := mv(l.alice.CreateInvite(bg, 1))
	l.db = newDevice(t, cl)
	l.bob = l.db.register("bob", pwBob, inv.Code)
	must(t, l.alice.Sync(bg))
	return l
}

func randKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

func randID() string { return vaultcrypto.NewID() }

// snapshot captures everything a rejected response must not have touched.
type snapshot struct {
	cache, trust []byte
	writes       int64
	rev          uint64
	vaults       []*VaultView
}

func (l *liar) snap(s *Session) snapshot {
	c, _ := os.ReadFile(filepath.Join(l.da.store.Dir, "cache.json"))
	tr, _ := os.ReadFile(filepath.Join(l.da.store.Dir, TrustFileName(s.UserID)))
	return snapshot{cache: c, trust: tr, writes: l.h.writes.Load(), rev: s.Rev(), vaults: s.Vaults()}
}

func (l *liar) assertUntouched(s *Session, before snapshot) {
	l.t.Helper()
	after := l.snap(s)
	if !bytes.Equal(before.cache, after.cache) {
		l.t.Fatal("the offline cache changed")
	}
	if !bytes.Equal(before.trust, after.trust) {
		l.t.Fatal("the trust store changed")
	}
	if before.writes != after.writes {
		l.t.Fatalf("%d state-changing request(s) were sent", after.writes-before.writes)
	}
	if before.rev != after.rev || len(before.vaults) != len(after.vaults) {
		l.t.Fatal("the session's view changed")
	}
}

// syncFull makes the next Sync ask for the full state (a since= answer is
// "unchanged" and would carry nothing to tamper with).
func syncFull(s *Session) error {
	s.mode = ModeStale
	err := s.Sync(bg)
	if s.mode == ModeStale && err != nil {
		s.mode = ModeOnline
	}
	return err
}

func TestRefuseIdentityMismatch(t *testing.T) {
	l := newLiar(t)
	cases := map[string]func(*api.SyncResponse){
		"account user_id":    func(r *api.SyncResponse) { r.Account.UserID = randID() },
		"account username":   func(r *api.SyncResponse) { r.Account.Username = "mallory" },
		"account public key": func(r *api.SyncResponse) { r.Account.PublicKey = randKey() },
		"own directory key": func(r *api.SyncResponse) {
			forUser(r, l.alice.UserID, func(d *api.DirectoryUser) { d.PublicKey = randKey() })
		},
		"own directory name": func(r *api.SyncResponse) {
			forUser(r, l.alice.UserID, func(d *api.DirectoryUser) { d.Username = "alicia" })
		},
		"own directory id": func(r *api.SyncResponse) {
			forUser(r, l.alice.UserID, func(d *api.DirectoryUser) { d.UserID = randID() })
		},
		"own entry missing": func(r *api.SyncResponse) { dropUser(r, l.alice.UserID) },
	}
	for name, mut := range cases {
		before := l.snap(l.alice)
		l.h.set(mut)
		err := syncFull(l.alice)
		l.h.set(nil)
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Fatalf("%s: want ProtocolError, got %v", name, err)
		}
		l.assertUntouched(l.alice, before)
	}
	// A login response naming another account is refused too.
	rt := newHostile()
	rt.rewrite = func(r *http.Request, resp *http.Response) (*http.Response, error) {
		if r.URL.Path != "/v1/login" {
			return resp, nil
		}
		var lr api.LoginResponse
		b := readBody(resp)
		_ = json.Unmarshal(b, &lr)
		lr.UserID = randID()
		nb, _ := json.Marshal(lr)
		return replaceBody(resp, nb), nil
	}
	d := newDevice(t, l.cl, withTransport(rt))
	if _, err := Login(bg, d.deps, "alice", pwAlice); err == nil || !strings.Contains(err.Error(), "not the one that logged in") {
		t.Fatalf("login response with another user id: %v", err)
	}
}

func readBody(resp *http.Response) []byte {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return buf.Bytes()
}

func forUser(r *api.SyncResponse, id string, f func(*api.DirectoryUser)) {
	for i := range r.Directory {
		if r.Directory[i].UserID == id {
			f(&r.Directory[i])
		}
	}
}

func dropUser(r *api.SyncResponse, id string) {
	var out []api.DirectoryUser
	for _, d := range r.Directory {
		if d.UserID != id {
			out = append(out, d)
		}
	}
	r.Directory = out
}

func TestRefuseMalformedOrDuplicateDirectory(t *testing.T) {
	l := newLiar(t)
	vid := mv(l.alice.CreateVault(bg, "V"))
	mv(l.alice.CreateItem(bg, vid, loginItem("a")))
	mv(l.alice.CreateItem(bg, vid, loginItem("b")))
	extra := func(r *api.SyncResponse, f func(*api.DirectoryUser)) {
		d := api.DirectoryUser{UserID: randID(), Username: "zed", PublicKey: randKey()}
		f(&d)
		r.Directory = append(r.Directory, d)
	}
	bobID := l.bob.UserID
	cases := map[string]func(*api.SyncResponse){
		"duplicate user id":  func(r *api.SyncResponse) { extra(r, func(d *api.DirectoryUser) { d.UserID = bobID }) },
		"duplicate username": func(r *api.SyncResponse) { extra(r, func(d *api.DirectoryUser) { d.Username = "bob" }) },
		"malformed user id": func(r *api.SyncResponse) {
			extra(r, func(d *api.DirectoryUser) { d.UserID = strings.ToUpper(d.UserID) })
		},
		"short user id":       func(r *api.SyncResponse) { extra(r, func(d *api.DirectoryUser) { d.UserID = "abc" }) },
		"bad username":        func(r *api.SyncResponse) { extra(r, func(d *api.DirectoryUser) { d.Username = "Bad Name" }) },
		"31-byte public key":  func(r *api.SyncResponse) { extra(r, func(d *api.DirectoryUser) { d.PublicKey = randKey()[:31] }) },
		"duplicate vault id":  func(r *api.SyncResponse) { r.Vaults = append(r.Vaults, r.Vaults[0]) },
		"malformed vault id":  func(r *api.SyncResponse) { r.Vaults[0].ID = "nothex" },
		"duplicate item id":   func(r *api.SyncResponse) { v := findVault(r, vid); v.Items = append(v.Items, v.Items[0]) },
		"malformed item id":   func(r *api.SyncResponse) { v := findVault(r, vid); v.Items[0].ID = "xyz" },
		"duplicate member id": func(r *api.SyncResponse) { v := findVault(r, vid); v.Members = append(v.Members, v.Members[0]) },
	}
	for name, mut := range cases {
		before := l.snap(l.alice)
		l.h.set(mut)
		err := syncFull(l.alice)
		l.h.set(nil)
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Fatalf("%s: want ProtocolError, got %v", name, err)
		}
		l.assertUntouched(l.alice, before)
	}
}

// TestContactChangesRefused: a contact's key or username changing, or a known
// username appearing under another user ID, is a permanent key-mismatch: it is
// recorded, nothing is wrapped for or accepted from that user, and the
// warning outlives the lie until dismissed.
func TestContactChangesRefused(t *testing.T) {
	l := newLiar(t)
	shared := mv(l.alice.CreateVault(bg, "Shared"))
	other := mv(l.alice.CreateVault(bg, "Other"))
	shareVerified(t, l.alice, l.bob, shared, api.RoleOwner)
	// bob shares a vault with alice; she accepts it.
	bobsVault := mv(l.bob.CreateVault(bg, "Bob's"))
	shareVerified(t, l.bob, l.alice, bobsVault, api.RoleEditor)
	bobID := l.bob.UserID

	attacks := map[string]struct {
		mut  func(*api.SyncResponse)
		kind string
	}{
		"key":      {func(r *api.SyncResponse) { forUser(r, bobID, func(d *api.DirectoryUser) { d.PublicKey = randKey() }) }, MismatchKey},
		"username": {func(r *api.SyncResponse) { forUser(r, bobID, func(d *api.DirectoryUser) { d.Username = "bobby" }) }, MismatchUsername},
		"name under another id": {func(r *api.SyncResponse) {
			nid := randID()
			forUser(r, bobID, func(d *api.DirectoryUser) { d.UserID, d.PublicKey = nid, randKey() })
		}, MismatchUserID},
	}
	for name, at := range attacks {
		mm := func() { mv(l.alice.CreateItem(bg, other, loginItem("bump-"+name))) } // any change, so the next sync is not "unchanged"
		mm()
		l.h.set(at.mut)
		must(t, syncFull(l.alice))
		ms := l.alice.KeyMismatches()
		found := false
		for _, m := range ms {
			if m.Kind == at.kind && m.PinnedFingerprint != m.OfferedFingerprint {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: no %s mismatch reported: %v", name, at.kind, ms)
		}
		// Nothing is wrapped for the changed identity: sharing, rekey, role change all refuse and send nothing.
		w0 := l.h.writes.Load()
		var km *KeyMismatchError
		if err := l.alice.AddMember(bg, other, "bob", api.RoleViewer); !errors.As(err, &km) {
			t.Fatalf("%s: AddMember: %v", name, err)
		}
		if err := l.alice.RekeyVault(bg, shared, RekeyOptions{}); !errors.As(err, &km) {
			t.Fatalf("%s: RekeyVault must not wrap for a changed key: %v", name, err)
		}
		if err := l.alice.MarkVerified(bobID); !errors.As(err, &km) {
			t.Fatalf("%s: MarkVerified of a mismatching contact: %v", name, err)
		}
		if l.h.writes.Load() != w0 {
			t.Fatalf("%s: a request was sent", name)
		}
		// A key accepted from that user earlier is no longer accepted: the vault bob shared is locked.
		if v := l.alice.Vault(bobsVault); v.Locked != LockKeyMismatch {
			t.Fatalf("%s: vault from the changed user is %q, want key_mismatch", name, v.Locked)
		}
		if !strings.Contains(strings.Join(l.alice.Warnings(), "\n"), "WARNING") {
			t.Fatalf("%s: no prominent warning", name)
		}
		// The trusted triple never changes.
		u := mv(l.alice.ResolveUser("bob"))
		if u.Fingerprint != l.bob.Fingerprint() && !u.KeyMismatch {
			t.Fatalf("%s: the trusted triple changed without being flagged", name)
		}
		if u.Verified && u.KeyMismatch {
			t.Fatalf("%s: a mismatching identity is shown as verified", name)
		}
		l.h.set(nil)
		must(t, syncFull(l.alice))
	}
	// The server is honest again, but the events stay until dismissed knowingly.
	if len(l.alice.KeyMismatches()) != 0 {
		t.Fatal("mismatch persists although the server is honest again")
	}
	if !strings.Contains(strings.Join(l.alice.Warnings(), "\n"), "earlier warning") {
		t.Fatal("recorded events vanished without being dismissed")
	}
	if l.alice.Vault(bobsVault).Locked != NotLocked {
		t.Fatal("vault stays locked after the lie stopped")
	}
	n, err := l.alice.DismissWarnings(bobID)
	must(t, err)
	if n < 3 {
		t.Fatalf("dismissed %d", n)
	}
	for _, w := range l.alice.Warnings() {
		if strings.Contains(w, "earlier warning") {
			t.Fatalf("dismissed warning still shown: %s", w)
		}
	}
	// And the events are in the sealed store for the next process.
	again := mv(UnlockOffline(Deps{Store: l.da.store}, "alice", pwAlice))
	_ = again
}

// TestPersistentMismatchSurvivesRestart: a mismatch recorded by one process is known to the next.
func TestPersistentMismatchSurvivesRestart(t *testing.T) {
	l := newLiar(t)
	other := mv(l.alice.CreateVault(bg, "Other"))
	l.h.set(func(r *api.SyncResponse) {
		forUser(r, l.bob.UserID, func(d *api.DirectoryUser) { d.PublicKey = randKey() })
	})
	mv(l.alice.CreateItem(bg, other, loginItem("bump")))
	if len(l.alice.KeyMismatches()) != 1 {
		t.Fatal("mismatch not detected")
	}
	l.h.set(nil)
	must(t, syncFull(l.alice)) // the honest answer is what gets cached
	s := mv(UnlockOffline(Deps{Store: l.da.store}, "alice", pwAlice))
	if !strings.Contains(strings.Join(s.Warnings(), "\n"), "earlier warning") {
		t.Fatalf("a second process does not know the recorded mismatch: %v", s.Warnings())
	}
}

// TestContinuityRefused: a vault offered at a lower epoch, or at the same
// epoch with a different key, is locked, never silently accepted.
func TestContinuityRefused(t *testing.T) {
	l := newLiar(t)
	// ---- sender is someone else (bob's device) ----
	vid := mv(l.alice.CreateVault(bg, "Shared"))
	shareVerified(t, l.alice, l.bob, vid, api.RoleEditor)
	oldBobView := *findVault(l.bob.raw, vid)
	oldAlice := *findVault(l.alice.raw, vid)
	bobHost := newHostile()
	l.db.api.hc.Transport = bobHost

	// Lower epoch: alice rekeys, bob follows (known owner), then the server offers epoch 1 again.
	must(t, l.alice.RekeyVault(bg, vid, RekeyOptions{}))
	must(t, l.bob.Sync(bg))
	if l.bob.Vault(vid).Locked != NotLocked || l.bob.Vault(vid).KeyEpoch != 2 {
		t.Fatalf("bob did not follow the rekey by a known owner: %+v", l.bob.Vault(vid))
	}
	w0 := bobHost.writes.Load()
	bobHost.set(func(r *api.SyncResponse) { *findVault(r, vid) = oldBobView })
	mv(l.alice.CreateItem(bg, vid, loginItem("bump"))) // so bob's next sync is a full one
	// A lower epoch is the "servers show older data" state, not a silent accept:
	// the view stays as it was, writes are refused, the state is recorded.
	must(t, l.bob.Sync(bg))
	if l.bob.Mode() != ModeOlder || l.bob.Vault(vid).KeyEpoch != 2 || l.bob.Vault(vid).Locked != NotLocked || l.bob.Recovery() == nil {
		t.Fatalf("lower epoch offered: mode=%v vault=%+v", l.bob.Mode(), l.bob.Vault(vid))
	}
	var ro *ReadOnlyError
	if _, err := l.bob.CreateItem(bg, vid, loginItem("x")); !errors.As(err, &ro) || ro.Reason != ReasonOlder || bobHost.writes.Load() != w0 {
		t.Fatalf("write while the servers show older data: %v", err)
	}
	// Same epoch, different key (from the same sender, who has the key pair to make it).
	altVK := vaultcrypto.NewVaultKey()
	altWrap := mv(vaultcrypto.WrapVaultKey(altVK, vaultcrypto.WrapContext{VaultID: vid, KeyEpoch: 2, SenderID: l.alice.UserID, RecipientID: l.bob.UserID}, &l.alice.secrets.PrivateKey, &l.bob.secrets.PublicKey))
	altMeta := mv(vaultcrypto.EncryptVaultMeta(altVK, vid, 2, &vaultcrypto.VaultMeta{Name: "Evil"}))
	bobHost.set(func(r *api.SyncResponse) {
		v := findVault(r, vid)
		v.MyKey.Blob, v.EncMeta = altWrap, altMeta
	})
	mv(l.alice.CreateItem(bg, vid, loginItem("bump2")))
	must(t, l.bob.Sync(bg))
	if v := l.bob.Vault(vid); v.Locked != LockContinuity || v.Name == "Evil" {
		t.Fatalf("same epoch, different key: %+v", v)
	}
	bobHost.set(nil)
	must(t, syncFull(l.bob))
	if l.bob.Vault(vid).Locked != NotLocked {
		t.Fatal("honest server does not restore access")
	}

	// ---- sender is the user (alice's device) ----
	l.h.set(func(r *api.SyncResponse) { *findVault(r, vid) = oldAlice })
	mv(l.bob.CreateItem(bg, vid, loginItem("bump3")))
	must(t, l.alice.Sync(bg))
	if l.alice.Mode() != ModeOlder || l.alice.Vault(vid).KeyEpoch != 2 {
		t.Fatalf("own vault at a lower epoch: mode=%v %+v", l.alice.Mode(), l.alice.Vault(vid))
	}
	l.h.set(nil)
	must(t, syncFull(l.alice))
	if l.alice.Mode() != ModeOnline || l.alice.Recovery() != nil {
		t.Fatal("an honest answer does not clear the older state")
	}

	// A vault this device created comes back with a different key: the key
	// was recorded BEFORE sending, so the server cannot swap it.
	created := mv(l.alice.CreateVault(bg, "Mine"))
	altVK2 := vaultcrypto.NewVaultKey()
	altWrap2 := mv(vaultcrypto.WrapVaultKey(altVK2, vaultcrypto.WrapContext{VaultID: created, KeyEpoch: 1, SenderID: l.alice.UserID, RecipientID: l.alice.UserID}, &l.alice.secrets.PrivateKey, &l.alice.secrets.PublicKey))
	altMeta2 := mv(vaultcrypto.EncryptVaultMeta(altVK2, created, 1, &vaultcrypto.VaultMeta{Name: "Swapped"}))
	l.h.set(func(r *api.SyncResponse) {
		v := findVault(r, created)
		v.MyKey.Blob, v.EncMeta = altWrap2, altMeta2
	})
	mv(l.bob.CreateVault(bg, "bump4"))
	must(t, l.alice.Sync(bg))
	if v := l.alice.Vault(created); v.Locked != LockContinuity || v.Name == "Swapped" {
		t.Fatalf("created vault with a swapped key: %+v", v)
	}
}

// TestPersonalVaultSenderMustBeSelf: §6.4 rule 1.
func TestPersonalVaultSenderMustBeSelf(t *testing.T) {
	l := newLiar(t)
	pv := personalVault(t, l.alice)
	vk := vaultcrypto.NewVaultKey()
	wrap := mv(vaultcrypto.WrapVaultKey(vk, vaultcrypto.WrapContext{VaultID: pv.ID, KeyEpoch: 1, SenderID: l.bob.UserID, RecipientID: l.alice.UserID}, &l.bob.secrets.PrivateKey, &l.alice.secrets.PublicKey))
	l.h.set(func(r *api.SyncResponse) {
		v := findVault(r, pv.ID)
		v.MyKey = api.WrappedKey{SenderID: l.bob.UserID, Blob: wrap}
	})
	mv(l.alice.CreateVault(bg, "bump"))
	must(t, l.alice.Sync(bg))
	if v := l.alice.Vault(pv.ID); v.Locked != LockInvalid || len(v.Items) != 0 {
		t.Fatalf("personal vault wrapped by someone else: %+v", v)
	}
}

// TestRekeyStopsWhenServerListsUnrosteredMember: a server-listed member who
// is not in the authenticated roster stops a rekey; nothing is sent.
func TestRekeyStopsWhenServerListsUnrosteredMember(t *testing.T) {
	l := newLiar(t)
	dd := newDevice(t, l.cl)
	inv := mv(l.alice.CreateInvite(bg, 1))
	carol := dd.register("carol", pwCarol, inv.Code)
	must(t, l.alice.Sync(bg))
	vid := mv(l.alice.CreateVault(bg, "V"))
	shareVerified(t, l.alice, l.bob, vid, api.RoleEditor)
	l.h.set(func(r *api.SyncResponse) {
		v := findVault(r, vid)
		v.Members = append(v.Members, api.Member{UserID: carol.UserID, Role: api.RoleEditor, AddedBy: l.alice.UserID})
	})
	mv(l.alice.CreateItem(bg, vid, loginItem("bump")))
	v := l.alice.Vault(vid)
	noted := false
	for _, m := range v.Members {
		if m.UserID == carol.UserID && !m.InRoster && strings.Contains(m.Note, "not in the vault's member list") {
			noted = true
		}
	}
	if !noted || len(v.Discrepancies) == 0 {
		t.Fatalf("discrepancy not reported: %+v", v.Members)
	}
	w0 := l.h.writes.Load()
	var rm *RosterMismatchError
	if err := l.alice.RekeyVault(bg, vid, RekeyOptions{}); !errors.As(err, &rm) {
		t.Fatalf("rekey: %v", err)
	}
	if _, err := l.alice.PlanRekey(vid, RekeyOptions{Remove: []string{l.bob.UserID}}); !errors.As(err, &rm) {
		t.Fatalf("plan: %v", err)
	}
	if l.h.writes.Load() != w0 {
		t.Fatal("a rekey request was sent")
	}
	// Sharing with the unrostered member is refused as well.
	l.alice.verifyUser(t, "carol")
	if err := l.alice.AddMember(bg, vid, "carol", api.RoleViewer); !errors.As(err, &rm) {
		t.Fatalf("AddMember of a server-listed non-roster member: %v", err)
	}
	if l.h.writes.Load() != w0 {
		t.Fatal("a request was sent")
	}
}

// TestUnverifiedRosterMemberNotWrapped: an owner who is about to be outvoted
// cannot smuggle in a recipient: a rekey needs every recipient verified on
// the rekeying device, and a roster key that contradicts the contact is a mismatch.
func TestUnverifiedRosterMemberNotWrapped(t *testing.T) {
	l := newLiar(t)
	dd := newDevice(t, l.cl)
	inv := mv(l.alice.CreateInvite(bg, 1))
	carol := dd.register("carol", pwCarol, inv.Code)
	must(t, l.alice.Sync(bg))
	vid := mv(l.alice.CreateVault(bg, "V"))
	shareVerified(t, l.alice, l.bob, vid, api.RoleOwner)
	// bob (an owner) adds carol; alice never compared carol's fingerprint.
	must(t, l.bob.Sync(bg))
	shareVerified(t, l.bob, carol, vid, api.RoleEditor)
	must(t, l.alice.Sync(bg))

	w0 := l.h.writes.Load()
	var ur *UnverifiedRecipientsError
	err := l.alice.RekeyVault(bg, vid, RekeyOptions{})
	if !errors.As(err, &ur) || len(ur.Users) != 1 || ur.Users[0].Username != "carol" {
		t.Fatalf("rekey with an unverified roster member: %v", err)
	}
	if l.h.writes.Load() != w0 {
		t.Fatal("a rekey was sent although a recipient is unverified")
	}
	plan := mv(l.alice.PlanRekey(vid, RekeyOptions{}))
	if len(plan.Unverified()) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	l.alice.verifyUser(t, "carol")
	must(t, l.alice.RekeyVault(bg, vid, RekeyOptions{}))
	if l.alice.Vault(vid).KeyEpoch != 2 || len(l.alice.Vault(vid).Members) != 3 {
		t.Fatalf("after verification: %+v", l.alice.Vault(vid))
	}

	// A roster whose key for carol differs from alice's contact triple is a mismatch.
	v := l.bob.Vault(vid)
	must(t, l.bob.Sync(bg))
	v = l.bob.Vault(vid)
	sec := l.bob.vaultKeys[vid]
	forged, _ := sec.roster.Without(carol.UserID)
	var evil vaultcrypto.PublicKey
	copy(evil[:], randKey())
	forged, err = forged.WithMember(vaultcrypto.RosterMember{ID: carol.UserID, PublicKey: evil, Role: api.RoleEditor})
	must(t, err)
	enc := mv(vaultcrypto.EncryptRoster(sec.vk, vid, sec.epoch, forged))
	must(t, l.db.api.PutMember(bg, vid, carol.UserID, &api.PutMemberRequest{Role: api.RoleEditor, KeyEpoch: sec.epoch, EncRoster: enc, BaseRosterVersion: v.RosterVersion}))
	w0 = l.h.writes.Load()
	must(t, l.alice.Sync(bg))
	var km *KeyMismatchError
	if err := l.alice.RekeyVault(bg, vid, RekeyOptions{}); !errors.As(err, &km) || km.Username != "carol" {
		t.Fatalf("rekey with a roster key that contradicts the contact: %v", err)
	}
	if l.h.writes.Load() != w0 {
		t.Fatal("a request was sent")
	}
}

// TestRosterMustListCaller: §6.3.
func TestRosterMustListCaller(t *testing.T) {
	l := newLiar(t)
	vid := mv(l.alice.CreateVault(bg, "V"))
	shareVerified(t, l.alice, l.bob, vid, api.RoleOwner)
	sec := l.alice.vaultKeys[vid]
	bobOnly := &vaultcrypto.Roster{V: 1, Members: []vaultcrypto.RosterMember{{ID: l.bob.UserID, PublicKey: l.bob.secrets.PublicKey, Role: api.RoleOwner}}}
	enc := mv(vaultcrypto.EncryptRoster(sec.vk, vid, sec.epoch, bobOnly))
	wrongKey := &vaultcrypto.Roster{V: 1, Members: []vaultcrypto.RosterMember{{ID: l.alice.UserID, PublicKey: vaultcrypto.PublicKey(randKey()), Role: api.RoleOwner}}}
	enc2 := mv(vaultcrypto.EncryptRoster(sec.vk, vid, sec.epoch, wrongKey))
	for name, blob := range map[string][]byte{"caller absent": enc, "caller with another key": enc2} {
		l.h.set(func(r *api.SyncResponse) { findVault(r, vid).EncRoster = blob })
		mv(l.bob.CreateItem(bg, vid, loginItem("bump-"+name)))
		w0 := l.h.writes.Load()
		must(t, l.alice.Sync(bg))
		if v := l.alice.Vault(vid); v.Locked != LockInvalid || len(v.Items) != 0 {
			t.Fatalf("%s: %+v", name, v)
		}
		if _, err := l.alice.CreateItem(bg, vid, loginItem("x")); err == nil || l.h.writes.Load() != w0 {
			t.Fatalf("%s: wrote into an invalid vault: %v", name, err)
		}
	}
}

// TestKDFParametersRefused: out-of-bounds parameters, and parameters weaker
// than the cached account's, are refused before any login key is derived or sent.
func TestKDFParametersRefused(t *testing.T) {
	cl := clienttest.New(t, 1)
	rt := newHostile()
	d := newDevice(t, cl, withTransport(rt))
	strong := fastKDF()
	strong.MemoryKiB = 2 * vaultcrypto.MinMemoryKiB
	strong.Time = 4
	d.deps.KDF = func() api.KDFParams { return strong }
	d.register("alice", pwAlice, clienttest.BootstrapToken)
	if c := cacheOf(d.deps, "alice"); c == nil || c.Sync.Account.KDF.MemoryKiB != 2*vaultcrypto.MinMemoryKiB {
		t.Fatal("cached account block missing")
	}
	d2 := newDevice(t, cl, withTransport(rt))
	for name, p := range map[string]func(*api.PreloginResponse){
		"memory below the floor": func(r *api.PreloginResponse) { r.KDF.MemoryKiB = 19456 },
		"time below the floor":   func(r *api.PreloginResponse) { r.KDF.Time = 2 },
		"memory above the cap":   func(r *api.PreloginResponse) { r.KDF.MemoryKiB = 1 << 20 },
		"short salt":             func(r *api.PreloginResponse) { r.KDF.Salt = r.KDF.Salt[:8] },
	} {
		rt.setPre(p)
		l0 := rt.logins.Load()
		_, err := Login(bg, d2.deps, "alice", pwAlice)
		if !errors.Is(err, vaultcrypto.ErrKDFParams) {
			t.Fatalf("%s: %v", name, err)
		}
		if rt.logins.Load() != l0 {
			t.Fatalf("%s: a login key was sent", name)
		}
	}
	// Valid, but weaker than what this device has cached.
	rt.setPre(func(r *api.PreloginResponse) {
		r.KDF.MemoryKiB, r.KDF.Time = vaultcrypto.MinMemoryKiB, vaultcrypto.MinTime
	})
	l0 := rt.logins.Load()
	_, err := Login(bg, d.deps, "alice", pwAlice)
	if err == nil || !strings.Contains(err.Error(), "weaker") {
		t.Fatalf("weaker than cached: %v", err)
	}
	if rt.logins.Load() != l0 {
		t.Fatal("a login key was sent")
	}
	// Open() falls back to a full login when the cache does not open; the check applies there too.
	if _, err := Open(bg, d.deps, "alice", "some other long password 7"); err == nil || !strings.Contains(err.Error(), "weaker") {
		t.Fatalf("Open with weaker parameters: %v", err)
	}
}

// TestLowerRevNotApplied: a sync older than what the device has seen does
// not replace the view, the cache or the trust store.
func TestLowerRevNotApplied(t *testing.T) {
	l := newLiar(t)
	vid := mv(l.alice.CreateVault(bg, "Newer"))
	mv(l.bob.CreateVault(bg, "bump"))
	must(t, l.alice.Sync(bg))
	rev := l.alice.Rev()
	before := l.snap(l.alice)
	l.h.set(func(r *api.SyncResponse) {
		r.Rev = rev - 1
		r.Vaults = nil
	})
	must(t, syncFull(l.alice))
	if l.alice.Vault(vid) == nil || l.alice.Mode() == ModeOnline || l.alice.Rev() != rev {
		t.Fatal("an older response replaced the view")
	}
	after := l.snap(l.alice)
	if !bytes.Equal(before.cache, after.cache) {
		t.Fatal("an older response touched the cache")
	}
	if l.alice.Recovery() == nil {
		t.Fatal("the older state was not recorded")
	}
	if !strings.Contains(strings.Join(l.alice.Warnings(), "\n"), "OLDER data") {
		t.Fatalf("no warning: %v", l.alice.Warnings())
	}
	// A fresh login against an older server state is refused outright.
	l.h.set(func(r *api.SyncResponse) { r.Rev = 1 })
	var rb *RestoredStateError
	if _, err := Login(bg, l.da.deps, "alice", pwAlice); !errors.As(err, &rb) {
		t.Fatalf("login against a rolled-back server: %v", err)
	}
}

// TestChangePasswordVerifiesAccountBlock: if the stored account block does
// not open with the new key, the client does not cache it.
func TestChangePasswordVerifiesAccountBlock(t *testing.T) {
	l := newLiar(t)
	before := l.snap(l.alice)
	l.h.set(func(r *api.SyncResponse) { r.Account.WrappedAccountKey = bytes.Repeat([]byte{5}, 73) })
	err := l.alice.ChangePassword(bg, pwAlice, "brand new purple monkey 3")
	l.h.set(nil)
	if err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("want an account-block verification failure, got %v", err)
	}
	after := l.snap(l.alice)
	if !bytes.Equal(before.cache, after.cache) {
		t.Fatal("the unverified account block was cached")
	}
}

// TestLearnedNodeURLsFiltered: URLs learned from /v1/cluster must be https
// (unless the user configured http), bare origins, never a downgrade, at most 16.
func TestLearnedNodeURLsFiltered(t *testing.T) {
	var nodes []api.ClusterNode
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(api.ClusterResponse{Nodes: nodes})
	}))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()
	nodes = []api.ClusterNode{
		{ID: "a", PublicURL: ts.URL},
		{ID: "b", PublicURL: "http://evil.example:80"},
		{ID: "c", PublicURL: "https://user:pw@creds.example"},
		{ID: "d", PublicURL: "https://path.example/api"},
		{ID: "e", PublicURL: "ftp://x.example"},
		{ID: "f", PublicURL: "not a url"},
		{ID: "g", PublicURL: "https://good.example:8443"},
	}
	a, err := New(Options{Nodes: []string{ts.URL}, HTTPClient: ts.Client()})
	must(t, err)
	_, err = a.RefreshCluster(bg)
	must(t, err)
	got := strings.Join(a.Nodes(), " ")
	if strings.Contains(got, "evil") || strings.Contains(got, "creds") || strings.Contains(got, "path.example") || strings.Contains(got, "ftp") {
		t.Fatalf("hostile URLs accepted: %s", got)
	}
	if !strings.Contains(got, "good.example:8443") || len(a.Nodes()) != 2 {
		t.Fatalf("nodes: %s", got)
	}
	// An http server the user configured may learn http siblings, but https stays https-only.
	nodes = nil
	for i := 0; i < 30; i++ {
		nodes = append(nodes, api.ClusterNode{ID: "n", PublicURL: "https://n" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"})
	}
	a2, _ := New(Options{Nodes: []string{ts.URL}, HTTPClient: ts.Client()})
	_, err = a2.RefreshCluster(bg)
	must(t, err)
	if len(a2.Nodes()) > 16 {
		t.Fatalf("node list grew to %d", len(a2.Nodes()))
	}
	if _, ok := a2.acceptLearned("http://127.0.0.1:1", "http://127.0.0.1:2"); ok {
		t.Fatal("http accepted without AllowInsecure")
	}
	a3, _ := New(Options{Nodes: []string{"http://127.0.0.1:2"}, AllowInsecure: true})
	if _, ok := a3.acceptLearned("http://127.0.0.1:1", "http://127.0.0.1:2"); !ok {
		t.Fatal("http sibling of a configured http server refused")
	}
	if _, ok := a3.acceptLearned("http://127.0.0.1:1", "https://x.example"); ok {
		t.Fatal("scheme downgrade accepted")
	}
}
