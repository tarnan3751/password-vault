package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/backup"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

var bg = context.Background()

const (
	pwAlice = "correct horse ünïcode 1"
	pwBob   = "staple battery purple 2"
	pwCarol = "orange monkey window 33"
	pwDave  = "silver falcon garden 44"
)

// household bootstraps a 1-node cluster with alice (admin) and bob.
type household struct {
	cl          *clienttest.Cluster
	da, db      *device
	alice, bob  *Session
	lastSession *Session
}

func newHousehold(t *testing.T) *household {
	t.Helper()
	cl := clienttest.New(t, 1)
	h := &household{cl: cl}
	h.da = newDevice(t, cl)
	h.alice = h.da.register("alice", pwAlice, clienttest.BootstrapToken)
	if !h.alice.IsAdmin() {
		t.Fatal("first user must be admin")
	}
	h.db = h.invited("bob", pwBob)
	h.bob = h.lastSession
	must(t, h.alice.Sync(bg))
	return h
}

// invited registers another user via an invite and returns their device.
func (h *household) invited(name, pw string) *device {
	inv := mv(h.alice.CreateInvite(bg, 1))
	d := newDevice(curT, h.cl)
	h.lastSession = d.register(name, pw, inv.Code)
	return d
}

func (h *household) newUser(name, pw string) (*device, *Session) {
	d := h.invited(name, pw)
	must(curT, h.alice.Sync(bg))
	return d, h.lastSession
}

// shareVerified is what a careful owner does: verify the contact, add them,
// and the member verifies the owner and accepts.
func shareVerified(t *testing.T, owner *Session, member *Session, vaultID, role string) {
	t.Helper()
	must(t, owner.Sync(bg))
	must(t, member.Sync(bg))
	owner.verifyUser(t, member.Username)
	must(t, owner.AddMember(bg, vaultID, member.Username, role))
	must(t, member.Sync(bg))
	member.verifyUser(t, owner.Username)
	must(t, member.AcceptVault(vaultID))
	if member.Vault(vaultID).Locked != NotLocked {
		t.Fatalf("vault still %s after accept", member.Vault(vaultID).Locked)
	}
}

func TestRegisterLoginUnlock(t *testing.T) {
	h := newHousehold(t)
	if h.alice.Mode() != ModeOnline {
		t.Fatalf("mode %v", h.alice.Mode())
	}
	pv := personalVault(t, h.alice)
	if pv.Name != "Personal" || pv.Role != api.RoleOwner || pv.Locked != NotLocked || len(pv.Members) != 1 || pv.RosterBroken {
		t.Fatalf("personal vault: %+v", pv)
	}

	// Login from a second device.
	d2 := h.da.fresh(h.cl)
	if _, err := Login(bg, d2.deps, "alice", "wrong password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	s2 := d2.login("Alice ", pwAlice) // normalised
	if s2.Fingerprint() != h.alice.Fingerprint() {
		t.Fatal("fingerprint differs between devices")
	}
	if got := personalVault(t, s2).Name; got != "Personal" {
		t.Fatal(got)
	}

	// Offline unlock from the cache written by login: the AEAD open is the password check.
	off := mv(UnlockOffline(Deps{Store: d2.store}, "alice", pwAlice))
	if off.Mode() != ModeOffline || personalVault(t, off).Name != "Personal" {
		t.Fatal("offline view wrong")
	}
	if _, err := UnlockOffline(Deps{Store: d2.store}, "alice", "nope"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("offline wrong password: %v", err)
	}
	if _, err := UnlockOffline(Deps{Store: d2.store}, "bob", pwBob); !errors.Is(err, ErrNoCache) {
		t.Fatalf("other user: %v", err)
	}
	if _, err := off.CreateItem(bg, personalVault(t, off).ID, loginItem("x")); !IsUnavailable(err) {
		t.Fatalf("offline write: %v", err)
	}
	op := mv(Open(bg, d2.deps, "alice", pwAlice))
	if op.Mode() != ModeOnline {
		t.Fatalf("Open mode %v", op.Mode())
	}
	// With a cache and a cached token, Open is one request (the sync, sent
	// while the key is derived) and no login; a wrong password still fails.
	rt := &faultRT{}
	d2.api.hc.Transport = rt
	if op := mv(Open(bg, d2.deps, "alice", pwAlice)); op.Mode() != ModeOnline || rt.calls.Load() != 1 || rt.logins.Load() != 0 {
		t.Fatalf("cached Open: mode %v, %d requests, %d logins", op.Mode(), rt.calls.Load(), rt.logins.Load())
	}
	if _, err := Open(bg, d2.deps, "alice", "nope nope nope nope"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Open with a wrong password: %v", err)
	}
	// Registration needs a valid invite; usernames are validated.
	if _, err := Register(bg, d2.deps, RegisterParams{Username: "mallory", Password: "a perfectly fine pass 9", InviteCode: "AAAA-BBBB"}); !IsCode(err, api.CodeInvalidInvite) {
		t.Fatalf("bad invite: %v", err)
	}
	if _, err := Register(bg, d2.deps, RegisterParams{Username: "Bad Name!", Password: "a perfectly fine pass 9", InviteCode: "x"}); err == nil {
		t.Fatal("invalid username accepted")
	}
}

func TestPasswordPolicyEnforced(t *testing.T) {
	cl := clienttest.New(t, 1)
	rt := &faultRT{}
	d := newDevice(t, cl, withTransport(rt))
	for _, c := range []struct{ user, pw, code string }{
		{"alice", "short 1", vaultcrypto.PolicyTooShort},
		{"alice", "xx alice xx alice", vaultcrypto.PolicyContainsUsername},
		{"alice", "aaaaaaaaaaaaaaaa", vaultcrypto.PolicyRepeated},
		{"alice", "abcdefghijklmnop", vaultcrypto.PolicySequence},
		{"alice", "password1234", vaultcrypto.PolicyCommon},
	} {
		_, err := Register(bg, d.deps, RegisterParams{Username: c.user, Password: c.pw, InviteCode: clienttest.BootstrapToken})
		var pe *vaultcrypto.PolicyError
		if !errors.As(err, &pe) || pe.Code != c.code {
			t.Fatalf("%q: want policy %s, got %v", c.pw, c.code, err)
		}
	}
	if rt.calls.Load() != 0 {
		t.Fatalf("a rejected password still reached the network (%d requests)", rt.calls.Load())
	}
	s := d.register("alice", pwAlice, clienttest.BootstrapToken)
	if err := s.ChangePassword(bg, pwAlice, "short"); err == nil {
		t.Fatal("weak new password accepted")
	}
}

func TestDefaultKDF(t *testing.T) {
	cl := clienttest.New(t, 1)
	d := newDevice(t, cl)
	d.deps.KDF = nil // production default
	s := d.register("dora", "long garden passphrase 55", clienttest.BootstrapToken)
	acct := s.raw.Account.KDF
	if acct.MemoryKiB != 65536 || acct.Time != 3 || acct.Parallelism != 4 {
		t.Fatalf("default KDF not used: %+v", acct)
	}
}

func TestItemCRUDAndConflict(t *testing.T) {
	h := newHousehold(t)
	pv := personalVault(t, h.alice)

	it := loginItem("Bank ü 銀行")
	it.Username, it.Password, it.URLs, it.Notes = "alice@example.com", "pw-1", []string{"https://bank.example"}, "notes ✓"
	it.Extra = []vaultcrypto.ExtraMember{{RawKey: []byte(`"x_future"`), RawValue: []byte(`{"a":[1,  2]}`)}}
	id := mv(h.alice.CreateItem(bg, pv.ID, it))
	got := h.alice.item(t, pv.ID, id)
	if got.Name != it.Name || got.Password != "pw-1" || got.Notes != it.Notes || len(got.Extra) != 1 || string(got.Extra[0].RawValue) != `{"a":[1,  2]}` {
		t.Fatalf("round trip: %+v", got)
	}

	// Update keeps unknown members byte for byte and records history.
	must(t, h.alice.UpdateItem(bg, pv.ID, id, func(i *vaultcrypto.Item) { i.Password = "pw-2" }))
	got = h.alice.item(t, pv.ID, id)
	if got.Password != "pw-2" || len(got.PasswordHistory) != 1 || got.PasswordHistory[0].Password != "pw-1" || string(got.Extra[0].RawValue) != `{"a":[1,  2]}` {
		t.Fatalf("after update: %+v", got)
	}

	// Conflict: a second session edits the same item first.
	s2 := h.da.fresh(h.cl).login("alice", pwAlice)
	must(t, s2.UpdateItem(bg, pv.ID, id, func(i *vaultcrypto.Item) { i.Notes = "edited elsewhere" }))
	err := h.alice.UpdateItem(bg, pv.ID, id, func(i *vaultcrypto.Item) { i.Username = "mine" })
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConflictError, got %v", err)
	}
	if ce.Theirs == nil || ce.Theirs.Item.Notes != "edited elsewhere" || ce.Mine == nil || ce.Mine.Item.Username != "mine" || ce.Kind != "update" {
		t.Fatalf("conflict contents: %+v", ce)
	}
	if h.alice.item(t, pv.ID, id).Notes != "edited elsewhere" || h.alice.item(t, pv.ID, id).Username != "alice@example.com" {
		t.Fatal("conflicting write overwrote data")
	}

	must(t, s2.Sync(bg))
	must(t, s2.UpdateItem(bg, pv.ID, id, func(i *vaultcrypto.Item) { i.Notes = "again" }))
	if err := h.alice.DeleteItem(bg, pv.ID, id); !errors.As(err, &ce) || ce.Kind != "delete" {
		t.Fatalf("delete conflict: %v", err)
	}
	must(t, h.alice.DeleteItem(bg, pv.ID, id))
	for _, i := range h.alice.Vault(pv.ID).Items {
		if i.ID == id {
			t.Fatal("item still present")
		}
	}
	if err := s2.DeleteItem(bg, pv.ID, id); err == nil {
		t.Fatal("deleting a deleted item succeeded")
	}
}

// TestShareVerifyAcceptAndRoleCAS covers the normal sharing path: sharing
// needs a verified contact, the vault is pending on the other side until the
// sender is verified and the vault accepted, and two owners editing the
// roster concurrently cannot overwrite each other.
func TestShareVerifyAcceptAndRoleCAS(t *testing.T) {
	h := newHousehold(t)
	vid := mv(h.alice.CreateVault(bg, "Family"))
	itemID := mv(h.alice.CreateItem(bg, vid, func() *vaultcrypto.Item { i := loginItem("Wifi"); i.Password = "hunter2"; return i }()))

	// 1. Sharing with an unverified contact is refused, and nothing is sent.
	rt := &faultRT{}
	h.da.api.hc.Transport = rt
	err := h.alice.AddMember(bg, vid, "bob", api.RoleEditor)
	var uc *UnverifiedContactError
	if !errors.As(err, &uc) || uc.User.Fingerprint == "" {
		t.Fatalf("share with unverified contact: %v", err)
	}
	if rt.writes.Load() != 0 {
		t.Fatalf("a refused share still wrote %d request(s)", rt.writes.Load())
	}
	// A wrong fingerprint does not verify; the right one does.
	bobID := h.bob.UserID
	if err := h.alice.VerifyWithFingerprint(bobID, "0000-0000-0000-0000-0000-0000-0000-0000"); err == nil {
		t.Fatal("wrong fingerprint verified")
	}
	bobInfo := mv(h.alice.ResolveUser("bob"))
	if bobInfo.Fingerprint != h.bob.Fingerprint() || len(bobInfo.Fingerprint) != 39 {
		t.Fatalf("fingerprint %q vs bob's own %q", bobInfo.Fingerprint, h.bob.Fingerprint())
	}
	must(t, h.alice.VerifyWithFingerprint(bobID, strings.ToUpper(strings.ReplaceAll(bobInfo.Fingerprint, "-", ""))))
	must(t, h.alice.AddMember(bg, vid, "bob", api.RoleViewer))

	// 2. On bob's device the vault is PENDING: nothing decrypted, nothing writable.
	must(t, h.bob.Sync(bg))
	bv := h.bob.Vault(vid)
	if bv.Locked != LockPending || bv.Pending == nil || bv.Pending.SenderName != "alice" || bv.Name == "Family" || len(bv.Items) != 0 {
		t.Fatalf("expected a pending vault, got %+v", bv)
	}
	if bv.Pending.SenderFingerprint != h.alice.Fingerprint() {
		t.Fatal("pending info shows the wrong fingerprint")
	}
	var vl *VaultLockedError
	if _, err := h.bob.CreateItem(bg, vid, loginItem("nope")); !errors.As(err, &vl) || vl.Reason != LockPending {
		t.Fatalf("write to a pending vault: %v", err)
	}
	if err := h.bob.AcceptVault(vid); !errors.As(err, &uc) {
		t.Fatalf("accept without verification: %v", err)
	}
	// 3. Verify the sender, accept: now it opens, and the roster is shown.
	h.bob.verifyUser(t, "alice")
	must(t, h.bob.AcceptVault(vid))
	bv = h.bob.Vault(vid)
	if bv.Locked != NotLocked || bv.Name != "Family" || h.bob.item(t, vid, itemID).Password != "hunter2" || bv.Role != api.RoleViewer {
		t.Fatalf("after accept: %+v", bv)
	}
	if len(bv.Members) != 2 || len(bv.Discrepancies) != 0 {
		t.Fatalf("members: %+v / %v", bv.Members, bv.Discrepancies)
	}
	if _, err := h.bob.CreateItem(bg, vid, loginItem("nope")); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("viewer write: %v", err)
	}
	// A later session on the same device opens it without asking again (trust store).
	again := mv(UnlockOffline(Deps{Store: h.db.store}, "bob", pwBob))
	if again.Vault(vid).Locked != NotLocked {
		t.Fatalf("accepted vault is pending again after a restart: %s", again.Vault(vid).Locked)
	}

	// 4. Roster CAS between two owners: alice makes bob an owner, adds dave and
	// carol; bob (stale) changes carol's role and has to retry on the fresh roster.
	_, carol := h.newUser("carol", pwCarol)
	_, dave := h.newUser("dave", pwDave)
	must(t, h.alice.SetMemberRole(bg, vid, bobID, api.RoleOwner))
	shareVerified(t, h.alice, carol, vid, api.RoleEditor)
	must(t, h.bob.Sync(bg))
	bobRT := &faultRT{}
	h.db.api.hc.Transport = bobRT
	// alice adds dave while bob's view is stale
	shareVerified(t, h.alice, dave, vid, api.RoleViewer)
	puts := func() int64 { return bobRT.writes.Load() }
	before := puts()
	must(t, h.bob.SetMemberRole(bg, vid, carol.UserID, api.RoleViewer))
	if puts()-before != 2 {
		t.Fatalf("expected a CAS conflict and one retry (2 writes), got %d", puts()-before)
	}
	must(t, h.alice.Sync(bg))
	r := h.alice.vaultKeys[vid].roster
	if m, ok := r.Member(carol.UserID); !ok || m.Role != api.RoleViewer {
		t.Fatalf("carol's role change lost: %+v", r)
	}
	if _, ok := r.Member(dave.UserID); !ok {
		t.Fatal("alice's concurrent addition of dave was overwritten")
	}
	if len(r.Members) != 4 {
		t.Fatalf("roster has %d members", len(r.Members))
	}
}

// TestRemoveRekeyAtomic: removal IS the rekey: one request drops the member,
// installs the new key and roster; the removed user gets not-found; everyone
// else still reads everything, an unreadable entry is carried over and can be
// deleted; a member who left is dropped by the next rekey; and a broken roster
// can be rebuilt by an owner who has verified everyone.
func TestRemoveRekeyAtomic(t *testing.T) {
	h := newHousehold(t)
	_, carol := h.newUser("carol", pwCarol)
	vid := mv(h.alice.CreateVault(bg, "Shared"))
	mv(h.alice.CreateItem(bg, vid, func() *vaultcrypto.Item { i := loginItem("Wifi"); i.Password = "hunter2"; return i }()))
	shareVerified(t, h.alice, h.bob, vid, api.RoleEditor)
	shareVerified(t, h.alice, carol, vid, api.RoleEditor)
	bobItem := mv(h.bob.CreateItem(bg, vid, loginItem("Bob's")))
	// A box that does not open (someone wrote garbage): must survive the rekey untouched.
	junk := vaultcrypto.NewID()
	must(t, h.da.api.PutItem(bg, vid, junk, &api.PutItemRequest{Blob: bytes.Repeat([]byte{7}, 100), KeyEpoch: 1}))
	must(t, h.alice.Sync(bg))
	if iv := itemView(h.alice.Vault(vid), junk); iv == nil || iv.Item != nil || iv.Err == "" {
		t.Fatalf("unreadable entry not marked: %+v", iv)
	}
	// Export of everything else is not blocked by it.
	_, st, err := h.alice.ExportBackup("a separate backup passphrase")
	must(t, err)
	if st.Skipped != 1 {
		t.Fatalf("skipped %d", st.Skipped)
	}

	// The plan shows exactly who gets the new key.
	plan := mv(h.alice.PlanRekey(vid, RekeyOptions{Remove: []string{h.bob.UserID}}))
	var names []string
	for _, r := range plan.Receives {
		names = append(names, r.Username)
	}
	if strings.Join(names, ",") != "alice,carol" && strings.Join(names, ",") != "carol,alice" {
		t.Fatalf("recipients: %v", names)
	}
	if len(plan.Removed) != 1 || plan.Removed[0].Username != "bob" {
		t.Fatalf("removed: %+v", plan.Removed)
	}

	oldVK := h.bob.vaultKeys[vid].vk
	rt := &faultRT{}
	h.da.api.hc.Transport = rt
	must(t, h.alice.RekeyVault(bg, vid, RekeyOptions{Remove: []string{h.bob.UserID}}))
	if rt.writes.Load() != 1 {
		t.Fatalf("removal took %d write requests, want exactly 1 (atomic)", rt.writes.Load())
	}
	v := h.alice.Vault(vid)
	if v.KeyEpoch != 2 || v.RekeyRecommended || len(v.Members) != 2 || v.RosterBroken {
		t.Fatalf("after rekey: epoch=%d rec=%v members=%d", v.KeyEpoch, v.RekeyRecommended, len(v.Members))
	}
	if h.alice.item(t, vid, bobItem).Name != "Bob's" {
		t.Fatal("alice lost an item")
	}
	if iv := itemView(v, junk); iv == nil || iv.Item != nil {
		t.Fatal("the unreadable entry vanished or became readable")
	}
	// Bob: not found on every route; sync no longer lists the vault.
	must(t, h.bob.Sync(bg))
	if h.bob.Vault(vid) != nil {
		t.Fatal("removed bob still sees the vault")
	}
	if err := h.db.api.PutItem(bg, vid, vaultcrypto.NewID(), &api.PutItemRequest{Blob: bytes.Repeat([]byte{1}, 100), KeyEpoch: 2}); !IsCode(err, api.CodeNotFound) {
		t.Fatalf("removed member's write: %v", err)
	}
	for _, rv := range h.alice.raw.Vaults {
		if rv.ID == vid {
			for _, it := range rv.Items {
				if _, err := vaultcrypto.DecryptItem(oldVK, vid, it.ID, 2, it.Blob); err == nil {
					t.Fatal("old vault key opens new ciphertext")
				}
			}
		}
	}
	// Carol keeps working with no prompt: the new key came from a known owner (§6.4).
	must(t, carol.Sync(bg))
	cv := carol.Vault(vid)
	if cv.Locked != NotLocked || cv.KeyEpoch != 2 || len(cv.Items) != 3 {
		t.Fatalf("carol after rekey: %+v", cv)
	}
	_ = carol.item(t, vid, bobItem)
	// ...and can delete the unreadable entry.
	must(t, carol.DeleteItem(bg, vid, junk))
	if itemView(carol.Vault(vid), junk) != nil {
		t.Fatal("unreadable entry not deleted")
	}
	if err := carol.UpdateItem(bg, vid, bobItem, func(i *vaultcrypto.Item) { i.Notes = "carol was here" }); err != nil {
		t.Fatal(err)
	}

	// Carol leaves: DELETE member, roster untouched, rekey recommended; the next rekey drops her.
	must(t, carol.LeaveVault(bg, vid))
	must(t, h.alice.Sync(bg))
	v = h.alice.Vault(vid)
	if !v.RekeyRecommended {
		t.Fatal("rekey_recommended not set after a leave")
	}
	noted := false
	for _, m := range v.Members {
		if m.Username == "carol" && strings.Contains(m.Note, "left") && m.InRoster && !m.InServer {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("leave not reported in the member list: %+v", v.Members)
	}
	plan = mv(h.alice.PlanRekey(vid, RekeyOptions{}))
	if len(plan.Left) != 1 || len(plan.Receives) != 1 {
		t.Fatalf("plan after leave: %+v", plan)
	}
	must(t, h.alice.RekeyVault(bg, vid, RekeyOptions{}))
	v = h.alice.Vault(vid)
	if v.KeyEpoch != 3 || v.RekeyRecommended || len(v.Members) != 1 {
		t.Fatalf("after second rekey: %+v", v)
	}

	// A personal vault is never rekeyed for a "member".
	pv := personalVault(t, h.alice)
	if _, err := h.alice.PlanRekey(pv.ID, RekeyOptions{Remove: []string{h.bob.UserID}}); err == nil {
		t.Fatal("personal vault removal planned")
	}
	must(t, h.alice.RekeyVault(bg, pv.ID, RekeyOptions{}))
}

func itemView(v *VaultView, id string) *ItemView {
	for i := range v.Items {
		if v.Items[i].ID == id {
			return &v.Items[i]
		}
	}
	return nil
}

func TestRosterRepair(t *testing.T) {
	h := newHousehold(t)
	vid := mv(h.alice.CreateVault(bg, "Repair me"))
	mv(h.alice.CreateItem(bg, vid, loginItem("keep")))
	shareVerified(t, h.alice, h.bob, vid, api.RoleEditor)
	v := h.alice.Vault(vid)
	// Someone (a buggy client) overwrites the roster with garbage.
	must(t, h.da.api.PutMember(bg, vid, h.bob.UserID, &api.PutMemberRequest{Role: api.RoleEditor, KeyEpoch: v.KeyEpoch,
		EncRoster: bytes.Repeat([]byte{9}, 100), BaseRosterVersion: v.RosterVersion}))
	must(t, h.alice.Sync(bg))
	v = h.alice.Vault(vid)
	if !v.RosterBroken || v.Locked != NotLocked || len(v.Items) != 1 {
		t.Fatalf("broken roster should leave the vault readable: %+v", v)
	}
	if err := h.alice.AddMember(bg, vid, "bob", api.RoleViewer); !errors.Is(err, ErrRosterBroken) {
		t.Fatalf("share with a broken roster: %v", err)
	}
	if err := h.alice.RekeyVault(bg, vid, RekeyOptions{}); !errors.Is(err, ErrRosterBroken) {
		t.Fatalf("plain rekey with a broken roster: %v", err)
	}
	// Repair needs every server-listed member to be a verified contact: unverify bob by using a fresh device.
	d2 := h.da.fresh(h.cl)
	a2 := d2.login("alice", pwAlice)
	var ur *UnverifiedRecipientsError
	if err := a2.RekeyVault(bg, vid, RekeyOptions{Repair: true}); !errors.As(err, &ur) {
		t.Fatalf("repair with unverified members: %v", err)
	}
	must(t, h.alice.RekeyVault(bg, vid, RekeyOptions{Repair: true}))
	v = h.alice.Vault(vid)
	if v.RosterBroken || v.KeyEpoch != 2 || len(v.Members) != 2 || v.Members[0].Note != "" {
		t.Fatalf("after repair: %+v", v)
	}
	must(t, h.bob.Sync(bg))
	if h.bob.Vault(vid).Locked != NotLocked {
		t.Fatalf("bob after repair: %s", h.bob.Vault(vid).Locked)
	}
}

func TestPasswordChange(t *testing.T) {
	h := newHousehold(t)
	dc, carol := h.newUser("carol", "old purple monkey 11")
	other := dc.fresh(h.cl)
	carol2 := other.login("carol", "old purple monkey 11") // a second session that will die

	oldToken := dc.api.Token()
	vid := mv(carol.CreateVault(bg, "Mine"))
	if err := carol.ChangePassword(bg, "wrong current", "new purple monkey 22"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current password: %v", err)
	}
	must(t, carol.ChangePassword(bg, "old purple monkey 11", "new purple monkey 22"))

	raw, _ := New(Options{Nodes: h.cl.URLs()[:1], AllowInsecure: true})
	raw.SetToken(oldToken)
	if _, err := raw.Sync(bg, 0); !IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("old token alive: %v", err)
	}
	if _, err := Login(bg, other.deps, "carol", "old purple monkey 11"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old password: %v", err)
	}
	if err := carol2.Sync(bg); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("stale session: %v", err)
	}
	dc.login("carol", "new purple monkey 22")
	// The cached account block was replaced: the new password opens it offline, the old one no longer does.
	if _, err := UnlockOffline(Deps{Store: dc.store}, "carol", "new purple monkey 22"); err != nil {
		t.Fatalf("offline new password: %v", err)
	}
	if _, err := UnlockOffline(Deps{Store: dc.store}, "carol", "old purple monkey 11"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("offline old password: %v", err)
	}
	if mv(UnlockOffline(Deps{Store: dc.store}, "carol", "new purple monkey 22")).Vault(vid) == nil {
		t.Fatal("vault lost")
	}
	// A device whose cache predates the change falls back to a full login.
	op := mv(Open(bg, other.deps, "carol", "new purple monkey 22"))
	if op.Mode() != ModeOnline {
		t.Fatalf("mode %v", op.Mode())
	}
}

func TestRevokeSessions(t *testing.T) {
	h := newHousehold(t)
	oldTok := h.da.api.Token()
	must(t, h.alice.RevokeSessions(bg))
	raw, _ := New(Options{Nodes: h.cl.URLs()[:1], AllowInsecure: true})
	raw.SetToken(oldTok)
	if _, err := raw.Sync(bg, 0); !IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("revoked token alive: %v", err)
	}
	must(t, h.alice.Sync(bg))
	h.da.api.SetToken(oldTok)
	must(t, h.alice.Sync(bg))
}

func TestInvitesAndAdmin(t *testing.T) {
	h := newHousehold(t)
	a := h.alice
	i1 := mv(a.CreateInvite(bg, 2))
	i2 := mv(a.CreateInvite(bg, 0))
	list := mv(a.ListInvites(bg))
	seen := map[string]bool{}
	for _, i := range list {
		seen[i.InviteID] = true
	}
	if !seen[i1.InviteID] || !seen[i2.InviteID] {
		t.Fatalf("invites missing from list: %+v", list)
	}
	must(t, a.RevokeInvite(bg, i2.InviteID))
	dd := newDevice(t, h.cl)
	if _, err := Register(bg, dd.deps, RegisterParams{Username: "dave", Password: pwDave, InviteCode: i2.Code}); !IsCode(err, api.CodeInvalidInvite) {
		t.Fatalf("revoked invite: %v", err)
	}
	dave := dd.register("dave", pwDave, i1.Code)
	if _, err := Register(bg, dd.deps, RegisterParams{Username: "dave2", Password: pwDave, InviteCode: i1.Code}); !IsCode(err, api.CodeInvalidInvite) {
		t.Fatalf("reused invite: %v", err)
	}
	if err := a.RevokeInvite(bg, i1.InviteID); !IsCode(err, api.CodeInvalidInvite) {
		t.Fatalf("revoking a used invite: %v", err)
	}
	if _, err := dave.CreateInvite(bg, 1); err == nil {
		t.Fatal("non-admin created an invite")
	}

	must(t, a.SetUserDisabled(bg, "dave", true))
	if _, err := Login(bg, dd.fresh(h.cl).deps, "dave", pwDave); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("disabled user login: %v", err)
	}
	if err := dave.Sync(bg); err == nil {
		t.Fatal("disabled user's session still works")
	}
	if u := mv(a.ResolveUser("dave")); !u.Disabled {
		t.Fatal("directory does not show disabled")
	}
	a.verifyUser(t, "dave")
	if err := a.AddMember(bg, mv(a.CreateVault(bg, "V")), "dave", api.RoleViewer); err == nil {
		t.Fatal("shared with a disabled user")
	}
	must(t, a.SetUserDisabled(bg, "dave", false))
	_ = dd.fresh(h.cl).login("dave", pwDave)
	must(t, a.SetUserAdmin(bg, "dave", true))
	if err := h.bob.SetUserAdmin(bg, "alice", true); err == nil {
		t.Fatal("non-admin set admin")
	}
	if ac := mv(a.AdminCluster(bg)); ac.NodeID == "" {
		t.Fatal("empty admin cluster response")
	}
	must(t, a.SetUserAdmin(bg, "alice", false))
	if a.IsAdmin() {
		t.Fatal("alice should have lost admin")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	h := newHousehold(t)
	a := h.alice
	vid := mv(a.CreateVault(bg, "Trip ✈"))
	it := loginItem("Hotel")
	it.Password, it.Notes = "pässwörd", "ünï"
	it.Extra = []vaultcrypto.ExtraMember{{RawKey: []byte(`"x_k"`), RawValue: []byte(`"v"`)}}
	mv(a.CreateItem(bg, vid, it))
	mv(a.CreateItem(bg, personalVault(t, a).ID, loginItem("Private")))

	data, st, err := a.ExportBackup("separate passphrase 1")
	must(t, err)
	if st.Vaults != 2 || st.Items != 2 || st.Skipped != 0 {
		t.Fatalf("stats %+v", st)
	}
	if bytes.Contains(data, []byte("Hotel")) || bytes.Contains(data, []byte("pässwörd")) {
		t.Fatal("plaintext in export")
	}
	if _, err := InspectBackup(data, "wrong"); !errors.Is(err, backup.ErrDecrypt) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	p := mv(InspectBackup(data, "separate passphrase 1"))
	before := len(a.Vaults())
	is := mv(a.ImportBackup(bg, p, nil))
	if is.Vaults != 2 || is.Items != 2 || is.Failed != 0 {
		t.Fatalf("import stats %+v", is)
	}
	if len(a.Vaults()) != before+2 {
		t.Fatalf("vaults %d -> %d", before, len(a.Vaults()))
	}
	var restored *VaultView
	for _, v := range a.Vaults() {
		if v.Name == "Trip ✈ (restored)" {
			restored = v
		}
	}
	if restored == nil || len(restored.Items) != 1 || restored.ID == vid || restored.Locked != NotLocked {
		t.Fatalf("restored vault: %+v", restored)
	}
	got := restored.Items[0].Item
	if got.Name != "Hotel" || got.Password != "pässwörd" || len(got.Extra) != 1 || string(got.Extra[0].RawValue) != `"v"` {
		t.Fatalf("restored item: %+v", got)
	}
	if len(a.Vault(vid).Items) != 1 {
		t.Fatal("original changed")
	}
}

// TestIdempotentRetry drops the first response of a write after the server has
// applied it. The automatic retry carries the same Idempotency-Key, so there is
// exactly one effect.
func TestIdempotentRetry(t *testing.T) {
	cl := clienttest.New(t, 1)
	var drops int
	var puts []string
	rt := &faultRT{}
	rt.dropResponse = func(r *http.Request) bool {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/items/") {
			puts = append(puts, r.Header.Get("Idempotency-Key"))
			if drops == 0 {
				drops++
				return true
			}
		}
		return false
	}
	d := newDevice(t, cl, withTransport(rt))
	s := d.register("alice", pwAlice, clienttest.BootstrapToken)
	pv := personalVault(t, s)
	rev0 := s.Rev()
	mv(s.CreateItem(bg, pv.ID, loginItem("once")))
	if drops != 1 || len(puts) != 2 || puts[0] == "" || puts[0] != puts[1] || len(puts[0]) != 32 {
		t.Fatalf("drops=%d keys=%v", drops, puts)
	}
	if n := len(s.Vault(pv.ID).Items); n != 1 {
		t.Fatalf("%d items", n)
	}
	if s.Rev() != rev0+1 {
		t.Fatalf("rev advanced by %d, want exactly 1", s.Rev()-rev0)
	}
	d2 := newDevice(t, cl, withTransport(&faultRT{dropResponse: func(r *http.Request) bool {
		return r.Method == http.MethodPost && r.URL.Path == "/v1/vaults"
	}}))
	d2.api.opts.MutationRetries = 1
	s2 := d2.login("alice", pwAlice)
	if _, err := s2.CreateVault(bg, "ambiguous"); !OutcomeUnknown(err) {
		t.Fatalf("want outcome-unknown error, got %v", err)
	}
	// The unknown-outcome vault landed; the trust store recorded its key beforehand, so a sync accepts it.
	must(t, s2.Sync(bg))
	found := false
	for _, v := range s2.Vaults() {
		if v.Name == "ambiguous" && v.Locked == NotLocked {
			found = true
		}
	}
	if !found {
		t.Fatal("vault whose creation response was lost is not usable")
	}
}

func TestLocalStateFiles(t *testing.T) {
	h := newHousehold(t)
	must(t, h.da.store.SaveConfig(&Config{Servers: h.cl.URLs(), Username: "alice", AllowInsecure: true}))
	vid := mv(h.alice.CreateVault(bg, "Secret vault"))
	mv(h.alice.CreateItem(bg, vid, func() *vaultcrypto.Item {
		i := loginItem("Secret item")
		i.Password = "SUPER-SECRET-PASSWORD-123"
		return i
	}()))
	must(t, h.alice.Sync(bg))

	dir := h.da.store.Dir
	trustFile := TrustFileName(h.alice.UserID)
	if runtime.GOOS != "windows" {
		fi := mv(os.Stat(dir))
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", fi.Mode().Perm())
		}
		for _, f := range []string{"config.json", "cache.json", trustFile, "token.json"} {
			fi, err := os.Stat(filepath.Join(dir, f))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode %v", f, fi.Mode().Perm())
			}
		}
	}
	for _, e := range mv(os.ReadDir(dir)) {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pins.json")); !os.IsNotExist(err) {
		t.Fatal("the old pins.json must not exist")
	}
	// No password, key or token in the plain files; the trust store is sealed.
	mk := mv(vaultcrypto.DeriveMasterKeys("alice", pwAlice, h.alice.raw.Account.KDF))
	forbidden := []string{pwAlice, "SUPER-SECRET-PASSWORD-123", h.da.api.Token()}
	for _, k := range [][]byte{mk.LoginKey[:], mk.EncKey[:], h.alice.secrets.AccountKey[:], h.alice.secrets.PrivateKey[:]} {
		forbidden = append(forbidden, base64.StdEncoding.EncodeToString(k), base64.RawStdEncoding.EncodeToString(k), hexs(k))
	}
	for _, vk := range h.alice.vaultKeys {
		k := vk.vk[:]
		forbidden = append(forbidden, base64.StdEncoding.EncodeToString(k), hexs(k))
	}
	for _, f := range []string{"config.json", "cache.json", trustFile} {
		if bad := contains(readAll(t, filepath.Join(dir, f)), forbidden...); bad != "" {
			t.Fatalf("%s contains a secret (%.6s...)", f, bad)
		}
	}
	blob := mv(os.ReadFile(filepath.Join(dir, trustFile)))
	if blob[0] != 0x01 || bytes.Contains(blob, []byte("contacts")) || bytes.Contains(blob, []byte("alice")) {
		t.Fatal("the trust store is not sealed")
	}
	tok := readAll(t, filepath.Join(dir, "token.json"))
	if !strings.Contains(tok, h.da.api.Token()) || contains(tok, pwAlice, base64.StdEncoding.EncodeToString(mk.LoginKey[:])) != "" {
		t.Fatal("token.json content wrong")
	}
	d := h.da.fresh(h.cl)
	d.deps.CacheToken = false
	d.login("alice", pwAlice)
	if _, err := os.Stat(filepath.Join(d.store.Dir, "token.json")); !os.IsNotExist(err) {
		t.Fatal("token cached although disabled")
	}
	loose := filepath.Join(t.TempDir(), "loose")
	must(t, os.Mkdir(loose, 0o755))
	st := mv(OpenStore(loose))
	if fi, _ := os.Stat(st.Dir); fi.Mode().Perm() != 0o700 {
		t.Fatal("dir not tightened")
	}
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(d[x>>4])
		sb.WriteByte(d[x&15])
	}
	return sb.String()
}

// TestTrustStoreReset: a missing or unopenable trust store starts empty and
// says so; everything becomes unverified again (vaults shared by others are
// pending again), which is the safe direction.
func TestTrustStoreReset(t *testing.T) {
	h := newHousehold(t)
	vid := mv(h.alice.CreateVault(bg, "Shared"))
	shareVerified(t, h.alice, h.bob, vid, api.RoleEditor)
	if h.bob.TrustReset() {
		t.Fatal("fresh trust store reported as reset")
	}
	trustPath := filepath.Join(h.db.store.Dir, TrustFileName(h.bob.UserID))
	for name, damage := range map[string]func(){
		"missing": func() { must(t, os.Remove(trustPath)) },
		"garbage": func() { must(t, os.WriteFile(trustPath, bytes.Repeat([]byte{0x42}, 120), 0o600)) },
	} {
		damage()
		s := mv(UnlockOffline(Deps{Store: h.db.store}, "bob", pwBob))
		if !s.TrustReset() {
			t.Fatalf("%s: reset not reported", name)
		}
		ws := strings.Join(s.Warnings(), "\n")
		if !strings.Contains(ws, "trust store") || !strings.Contains(ws, "waiting for you to confirm the sender") {
			t.Fatalf("%s: warnings: %s", name, ws)
		}
		if s.Vault(vid).Locked != LockPending {
			t.Fatalf("%s: vault is %q, want pending", name, s.Vault(vid).Locked)
		}
		if u := mv(s.ResolveUser("alice")); u.Verified {
			t.Fatalf("%s: contact still verified", name)
		}
		must(t, s.trust.Save())
		if mv(UnlockOffline(Deps{Store: h.db.store}, "bob", pwBob)).TrustReset() {
			t.Fatalf("%s: the notice repeats after the store was rewritten", name)
		}
	}
}

// TestQuotaSurfaces: the server's byte quota arrives as a typed 422 with a
// message naming the limit.
func TestQuotaSurfaces(t *testing.T) {
	h := newHousehold(t)
	vid := mv(h.alice.CreateVault(bg, "Big"))
	big := loginItem("big")
	big.Notes = strings.Repeat("x", 60000)
	var err error
	for i := 0; i < 200 && err == nil; i++ {
		_, err = h.alice.CreateItem(bg, vid, big)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != api.CodeLimitExceeded || !strings.Contains(strings.ToLower(ae.Message), "quota") && !strings.Contains(strings.ToLower(ae.Message), "limit") {
		t.Fatalf("want a limit_exceeded error naming the limit, got %v", err)
	}
}

func TestResolve(t *testing.T) {
	h := newHousehold(t)
	a := h.alice
	v1 := mv(a.CreateVault(bg, "Home"))
	v2 := mv(a.CreateVault(bg, "Work"))
	i1 := mv(a.CreateItem(bg, v1, loginItem("GitHub")))
	i2 := mv(a.CreateItem(bg, v2, loginItem("github")))
	mv(a.CreateItem(bg, v2, loginItem("Router")))
	if r := mv(a.ResolveItem("", "router")); r.Vault.ID != v2 {
		t.Fatal("router")
	}
	var amb *AmbiguousError
	if _, err := a.ResolveItem("", "GITHUB"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("ambiguity: %v", err)
	}
	if r := mv(a.ResolveItem("home", "github")); r.Item.ID != i1 {
		t.Fatal("scoped")
	}
	if r := mv(a.ResolveItem("", i2[:8])); r.Item.ID != i2 {
		t.Fatal("prefix")
	}
	var nf *NotFoundError
	if _, err := a.ResolveItem("", "zzz"); !errors.As(err, &nf) {
		t.Fatal("not found")
	}
	if r := mv(a.ResolveVault(v1[:6])); r.ID != v1 {
		t.Fatal("vault prefix")
	}
}

func TestStaleNeverOverwritesNewerCache(t *testing.T) {
	curT = t
	st := mv(OpenStore(filepath.Join(t.TempDir(), "h")))
	mk := func(rev uint64, stale bool) *Cache {
		return &Cache{Username: "u", SavedAt: int64(rev), Sync: api.SyncResponse{Rev: rev, Stale: stale}}
	}
	for _, c := range []struct {
		c    *Cache
		want bool
	}{
		{mk(10, false), true}, {mk(7, true), false}, {mk(10, true), true}, {mk(12, true), true}, {mk(9, true), false}, {mk(5, false), false}, {mk(12, false), true},
	} {
		wrote := mv(st.SaveCacheUnlessOlder(c.c))
		if wrote != c.want {
			t.Fatalf("rev=%d stale=%v wrote=%v want %v", c.c.Sync.Rev, c.c.Sync.Stale, wrote, c.want)
		}
	}
	if got := mv(st.LoadCache()); got.Sync.Rev != 12 {
		t.Fatalf("final rev %d", got.Sync.Rev)
	}
}
