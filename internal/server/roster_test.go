package server

import (
	"bytes"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// TestRosterAndRekeyWithRemove walks the revised sharing protocol through
// the HTTP API: create with a roster, add members with the roster CAS, a
// concurrent owner losing the race, an atomic rekey that removes a member,
// and what the removed and remaining members see afterwards.
func TestRosterAndRekeyWithRemove(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	carol := newAccount("carol")
	e.register(carol, e.invite(alice).Code)
	vid := randID()
	path := "/v1/vaults/" + vid

	// Creating a vault requires a roster.
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), WrappedKey: wrapped(alice.id)}, 400, api.CodeBadRequest, withToken(alice.token))
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), EncRoster: box(16<<10 + 1), WrappedKey: wrapped(alice.id)}, 413, api.CodeTooLarge, withToken(alice.token))
	var mr api.MutationResponse
	roster0 := box(120)
	e.call("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), EncRoster: roster0, WrappedKey: wrapped(alice.id)}, 200, &mr, withToken(alice.token))
	v, _ := vaultOf(e.sync(alice), vid)
	if !bytes.Equal(v.EncRoster, roster0) || v.RosterVersion != mr.Rev {
		t.Fatalf("new vault roster: %d bytes, version %d (rev %d)", len(v.EncRoster), v.RosterVersion, mr.Rev)
	}
	// Even a non-member learns that a taken vault id exists (documented).
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(carol.id)}, 409, api.CodeAlreadyExists, withToken(carol.token))

	// Add bob as owner, with the roster CAS.
	put := func(target *account) string { return "/v1/vaults/" + vid + "/members/" + target.id }
	addBob := api.PutMemberRequest{Role: api.RoleOwner, WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 1, EncRoster: box(200), BaseRosterVersion: v.RosterVersion}
	e.callErr("PUT", put(bob), api.PutMemberRequest{Role: api.RoleOwner, WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 1, BaseRosterVersion: v.RosterVersion}, 400, api.CodeBadRequest, withToken(alice.token))
	e.call("PUT", put(bob), addBob, 200, &mr, withToken(alice.token))
	if mr.Version != mr.Rev {
		t.Fatalf("put_member must return the new roster_version: %+v", mr)
	}
	rvAfterBob := mr.Version

	// Two owners add carol concurrently from the same base: one wins, the
	// other gets 409 with the current roster_version and changes nothing.
	byAlice := api.PutMemberRequest{Role: api.RoleViewer, WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 1, EncRoster: box(300), BaseRosterVersion: rvAfterBob}
	byBob := api.PutMemberRequest{Role: api.RoleEditor, WrappedKey: ptr(wrapped(bob.id)), KeyEpoch: 1, EncRoster: box(301), BaseRosterVersion: rvAfterBob}
	e.call("PUT", put(carol), byAlice, 200, &mr, withToken(alice.token))
	// carol is a member now, so bob's request (with a wrapped key) is an
	// "add" of an existing member...
	e.callErr("PUT", put(carol), byBob, 409, api.CodeAlreadyExists, withToken(bob.token))
	// ...and as a role change it loses on the roster CAS.
	byBob.WrappedKey = nil
	d := e.callErr("PUT", put(carol), byBob, 409, api.CodeVersionConflict, withToken(bob.token))
	if d.CurrentVersion == nil || *d.CurrentVersion != mr.Version {
		t.Fatalf("roster conflict detail: %+v", d)
	}
	v, _ = vaultOf(e.sync(bob), vid)
	if len(v.EncRoster) != 300 || v.RosterVersion != mr.Version {
		t.Fatal("the losing owner's roster was stored")
	}
	for _, m := range v.Members {
		if m.UserID == carol.id && m.Role != api.RoleViewer {
			t.Fatal("the losing owner's role change was applied")
		}
	}
	// Retrying on the fresh roster version works; key_epoch is checked too.
	byBob.BaseRosterVersion = v.RosterVersion
	byBob.KeyEpoch = 2
	e.callErr("PUT", put(carol), byBob, 409, api.CodeKeyEpochMismatch, withToken(bob.token))
	byBob.KeyEpoch = 1
	e.call("PUT", put(carol), byBob, 200, nil, withToken(bob.token))
	iid := randID()
	e.call("PUT", path+"/items/"+iid, api.PutItemRequest{Blob: box(400), KeyEpoch: 1}, 200, nil, withToken(carol.token))

	// Rekey that removes carol, atomically.
	v, _ = vaultOf(e.sync(alice), vid)
	rk := api.RekeyRequest{
		BaseRev: v.Rev, NewKeyEpoch: 2, Remove: []string{carol.id}, EncMeta: box(64), EncRoster: box(250),
		WrappedKeys: map[string]api.WrappedKey{alice.id: wrapped(alice.id), bob.id: wrapped(alice.id)},
		Items:       []api.RekeyItem{{ID: iid, Blob: box(400)}},
	}
	bad := rk
	bad.Remove = []string{alice.id}
	e.callErr("POST", path+"/rekey", bad, 400, api.CodeBadRequest, withToken(alice.token))
	bad = rk
	bad.Remove = []string{carol.id, carol.id}
	e.callErr("POST", path+"/rekey", bad, 400, api.CodeBadRequest, withToken(alice.token))
	bad = rk
	bad.Remove = []string{randID()}
	e.callErr("POST", path+"/rekey", bad, 400, api.CodeBadRequest, withToken(alice.token))
	bad = rk
	bad.WrappedKeys = map[string]api.WrappedKey{alice.id: wrapped(alice.id), bob.id: wrapped(alice.id), carol.id: wrapped(alice.id)}
	e.callErr("POST", path+"/rekey", bad, 409, api.CodeVersionConflict, withToken(alice.token))
	bad = rk
	bad.EncRoster = nil
	e.callErr("POST", path+"/rekey", bad, 400, api.CodeBadRequest, withToken(alice.token))
	byCarol := rk
	byCarol.Remove = []string{bob.id}
	byCarol.WrappedKeys = map[string]api.WrappedKey{alice.id: wrapped(carol.id), carol.id: wrapped(carol.id)}
	e.callErr("POST", path+"/rekey", byCarol, 403, api.CodeForbidden, withToken(carol.token)) // editors cannot rekey
	e.call("POST", path+"/rekey", rk, 200, &mr, withToken(alice.token))

	// The removed member: gone from sync, 404 on the vault.
	if _, ok := vaultOf(e.sync(carol), vid); ok {
		t.Fatal("carol still sees the vault")
	}
	e.callErr("PUT", path+"/items/"+iid, api.PutItemRequest{Blob: box(400), BaseVersion: mr.Rev, KeyEpoch: 2}, 404, api.CodeNotFound, withToken(carol.token))
	e.callErr("DELETE", path+"/members/"+carol.id, nil, 404, api.CodeNotFound, withToken(carol.token))
	// The remaining members: new epoch, roster and keys; nothing to recommend.
	for _, u := range []*account{alice, bob} {
		v, _ := vaultOf(e.sync(u), vid)
		if v.KeyEpoch != 2 || len(v.EncRoster) != 250 || v.RosterVersion != mr.Rev || v.RekeyRecommended ||
			len(v.Members) != 2 || v.MyKey.SenderID != alice.id || v.Items[0].Version != mr.Rev {
			t.Fatalf("%s after rekey: %+v", u.name, v)
		}
	}

	// Leaving (DELETE member) keeps the roster and recommends a rekey.
	e.call("DELETE", path+"/members/"+bob.id, nil, 200, nil, withToken(bob.token))
	v, _ = vaultOf(e.sync(alice), vid)
	if !v.RekeyRecommended || v.RosterVersion != mr.Rev || len(v.EncRoster) != 250 {
		t.Fatalf("after leaving: %+v", v)
	}

	// Personal vaults: rekey with only the owner's key and no removals.
	pv, _ := vaultOf(e.sync(alice), alice.personal)
	prk := api.RekeyRequest{BaseRev: pv.Rev, NewKeyEpoch: pv.KeyEpoch + 1, EncMeta: box(64), EncRoster: box(64),
		WrappedKeys: map[string]api.WrappedKey{alice.id: wrapped(alice.id)}}
	withRemove := prk
	withRemove.Remove = []string{bob.id}
	e.callErr("POST", "/v1/vaults/"+alice.personal+"/rekey", withRemove, 400, api.CodeBadRequest, withToken(alice.token))
	e.call("POST", "/v1/vaults/"+alice.personal+"/rekey", prk, 200, nil, withToken(alice.token))
}
