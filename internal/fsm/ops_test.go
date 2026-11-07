package fsm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

func TestInitFirstWins(t *testing.T) {
	f := New()
	h := &harness{t: t, f: f, now: 1_700_000_000_000}
	if f.Initialized() {
		t.Fatal("new FSM claims to be initialized")
	}
	// Nothing but init works before the cluster key exists.
	a := regArgs(1, "alice")
	a.Bootstrap = true
	h.mustErr(nil, a, api.CodeUnavailable)

	k1 := bytes.Repeat([]byte{1}, 32)
	out := h.mustOK(nil, &InitArgs{ClusterKey: k1})
	if out.Rev != 1 || !f.Initialized() || !bytes.Equal(f.ClusterKey(), k1) {
		t.Fatalf("init: rev=%d initialized=%v", out.Rev, f.Initialized())
	}
	out = h.mustOK(nil, &InitArgs{ClusterKey: bytes.Repeat([]byte{2}, 32)})
	if out.Rev != 1 || !bytes.Equal(f.ClusterKey(), k1) {
		t.Fatal("second init must be a no-op that does not bump rev")
	}
	h.mustErr(nil, &InitArgs{ClusterKey: []byte{1, 2, 3}}, api.CodeBadRequest)

	// ClusterKey returns a copy.
	k := f.ClusterKey()
	k[0] ^= 0xff
	if !bytes.Equal(f.ClusterKey(), k1) {
		t.Fatal("ClusterKey exposed internal memory")
	}
}

func TestRegisterBootstrap(t *testing.T) {
	h := newHarness(t)
	if h.f.HasUsers() {
		t.Fatal("HasUsers on empty state")
	}
	alice := h.bootstrap(1, "alice")
	if alice.ep != 1 {
		t.Fatalf("first epoch = %d, want 1", alice.ep)
	}
	ua, ok := h.f.LookupUserByName("alice")
	if !ok || !ua.IsAdmin || ua.Disabled || ua.ID != alice.id {
		t.Fatalf("bootstrap user: %+v", ua)
	}
	pv := h.vault(alice, alice.personal)
	if !pv.Personal || pv.MyRole != api.RoleOwner || pv.KeyEpoch != 1 || len(pv.Members) != 1 {
		t.Fatalf("personal vault: %+v", pv)
	}
	// A second bootstrap fails whichever node proposes it.
	b := regArgs(2, "bob")
	b.Bootstrap = true
	h.mustErr(nil, b, api.CodeInvalidInvite)
}

func TestRegisterWithInvite(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	hash := h.invite(alice, 2)

	b := regArgs(2, "bob")
	b.InviteHash = hash
	out := h.mustOK(nil, b)
	if out.IsAdmin {
		t.Fatal("invited user must not be admin")
	}
	inv := h.f.ListInvites()
	if len(inv) != 1 || inv[0].UsedBy != b.UserID || inv[0].InviteID != hash[:16] || inv[0].CreatedBy != alice.id {
		t.Fatalf("invite after use: %+v", inv)
	}

	// Single use.
	c := regArgs(3, "carol")
	c.InviteHash = hash
	h.mustErr(nil, c, api.CodeInvalidInvite)

	// Unknown invite.
	c.InviteHash = strings.Repeat("e", 64)
	h.mustErr(nil, c, api.CodeInvalidInvite)

	// Taken username / ids, but only after the invite is valid.
	h3 := h.invite(alice, 3)
	dup := regArgs(3, "bob")
	dup.InviteHash = h3
	h.mustErr(nil, dup, api.CodeAlreadyExists)
	dup = regArgs(3, "carol")
	dup.UserID = b.UserID
	dup.PersonalVault.WrappedKey = wk(b.UserID)
	dup.InviteHash = h3
	h.mustErr(nil, dup, api.CodeAlreadyExists)
	dup = regArgs(3, "carol")
	dup.PersonalVault.VaultID = b.PersonalVault.VaultID
	dup.InviteHash = h3
	h.mustErr(nil, dup, api.CodeAlreadyExists)
	// A failed registration does not consume the invite.
	ok := regArgs(3, "carol")
	ok.InviteHash = h3
	h.mustOK(nil, ok)
}

func TestInviteExpiryUsesCommandTime(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	created := h.now
	hash := inviteHash(9)
	out := h.mustOK(alice, &CreateInviteArgs{InviteHash: hash, TTLHours: 1})
	if out.ExpiresAt != created+3_600_000 || out.InviteID != hash[:16] {
		t.Fatalf("create invite: %+v", out)
	}
	b := regArgs(2, "bob")
	b.InviteHash = hash
	h.now = out.ExpiresAt // expiry is exclusive
	h.mustErr(nil, b, api.CodeInvalidInvite)
	h.now = out.ExpiresAt - 1
	h.mustOK(nil, b)
}

func TestInviteLifecycle(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")

	h.mustErr(bob, &CreateInviteArgs{InviteHash: inviteHash(50), TTLHours: 72}, api.CodeForbidden)
	h.mustErr(alice, &CreateInviteArgs{InviteHash: inviteHash(50), TTLHours: 0}, api.CodeBadRequest)
	h.mustErr(alice, &CreateInviteArgs{InviteHash: inviteHash(50), TTLHours: 721}, api.CodeBadRequest)
	h.mustErr(alice, &CreateInviteArgs{InviteHash: "nothex", TTLHours: 1}, api.CodeBadRequest)
	h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(50), TTLHours: 720})
	h.mustErr(alice, &CreateInviteArgs{InviteHash: inviteHash(50), TTLHours: 1}, api.CodeAlreadyExists)

	id := inviteHash(50)[:16]
	h.mustErr(bob, &RevokeInviteArgs{InviteID: id}, api.CodeForbidden)
	h.mustOK(alice, &RevokeInviteArgs{InviteID: id})
	h.mustErr(alice, &RevokeInviteArgs{InviteID: id}, api.CodeNotFound)
	h.mustErr(alice, &RevokeInviteArgs{InviteID: "0123456789abcdef"}, api.CodeNotFound)
	// Revoking a used invite is refused (it would rewrite history).
	h.mustErr(alice, &RevokeInviteArgs{InviteID: inviteHash(2)[:16]}, api.CodeInvalidInvite)
	for _, inv := range h.f.ListInvites() {
		if inv.InviteID == id {
			t.Fatal("revoked invite is still listed")
		}
	}
	// A revoked invite cannot be used.
	c := regArgs(3, "carol")
	c.InviteHash = inviteHash(50)
	h.mustErr(nil, c, api.CodeInvalidInvite)
}

func TestInvitePendingLimitAndPruning(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	for i := 0; i < MaxPendingInvites; i++ {
		h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(100 + i), TTLHours: 1})
	}
	h.mustErr(alice, &CreateInviteArgs{InviteHash: inviteHash(999), TTLHours: 1}, api.CodeLimitExceeded)
	if n := len(h.f.ListInvites()); n != MaxPendingInvites {
		t.Fatalf("listed %d invites", n)
	}
	// Once they have expired, creating a new one garbage-collects them.
	h.now += 2 * 3_600_000
	h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(999), TTLHours: 1})
	if n := len(h.f.ListInvites()); n != 1 {
		t.Fatalf("after pruning: %d invites", n)
	}
}

func TestRegisterValidation(t *testing.T) {
	cases := map[string]struct {
		mut  func(a *RegisterArgs)
		code string
	}{
		"bad user id":          {func(a *RegisterArgs) { a.UserID = "ABC" }, api.CodeBadRequest},
		"uppercase username":   {func(a *RegisterArgs) { a.Username = "Bob" }, api.CodeBadRequest},
		"username too long":    {func(a *RegisterArgs) { a.Username = strings.Repeat("b", 33) }, api.CodeBadRequest},
		"username leading .":   {func(a *RegisterArgs) { a.Username = ".bob" }, api.CodeBadRequest},
		"kdf alg":              {func(a *RegisterArgs) { a.KDF.Alg = "scrypt" }, api.CodeBadRequest},
		"kdf weak memory":      {func(a *RegisterArgs) { a.KDF.MemoryKiB = 1024 }, api.CodeBadRequest},
		"kdf weak time":        {func(a *RegisterArgs) { a.KDF.Time = 2 }, api.CodeBadRequest},
		"kdf old minimum mem":  {func(a *RegisterArgs) { a.KDF.MemoryKiB = 19456 }, api.CodeBadRequest},
		"kdf memory too high":  {func(a *RegisterArgs) { a.KDF.MemoryKiB = 262145 }, api.CodeBadRequest},
		"kdf time too high":    {func(a *RegisterArgs) { a.KDF.Time = 9 }, api.CodeBadRequest},
		"kdf parallelism 17":   {func(a *RegisterArgs) { a.KDF.Parallelism = 17 }, api.CodeBadRequest},
		"kdf salt too long":    {func(a *RegisterArgs) { a.KDF.Salt = make([]byte, 65) }, api.CodeBadRequest},
		"no roster":            {func(a *RegisterArgs) { a.PersonalVault.EncRoster = nil }, api.CodeBadRequest},
		"roster too large":     {func(a *RegisterArgs) { a.PersonalVault.EncRoster = box(MaxRosterBytes + 1) }, api.CodeTooLarge},
		"kdf short salt":       {func(a *RegisterArgs) { a.KDF.Salt = []byte{1, 2} }, api.CodeBadRequest},
		"kdf parallelism":      {func(a *RegisterArgs) { a.KDF.Parallelism = 0 }, api.CodeBadRequest},
		"verifier params":      {func(a *RegisterArgs) { a.Verifier.MemoryKiB = 1 << 20 }, api.CodeBadRequest},
		"verifier hash":        {func(a *RegisterArgs) { a.Verifier.Hash = nil }, api.CodeBadRequest},
		"public key size":      {func(a *RegisterArgs) { a.PublicKey = make([]byte, 31) }, api.CodeBadRequest},
		"account key short":    {func(a *RegisterArgs) { a.WrappedAccountKey = box(40) }, api.CodeBadRequest},
		"account key huge":     {func(a *RegisterArgs) { a.WrappedAccountKey = box(MaxAccountBlobBytes + 1) }, api.CodeTooLarge},
		"private key short":    {func(a *RegisterArgs) { a.EncPrivateKey = nil }, api.CodeBadRequest},
		"vault id":             {func(a *RegisterArgs) { a.PersonalVault.VaultID = "x" }, api.CodeBadRequest},
		"meta too large":       {func(a *RegisterArgs) { a.PersonalVault.EncMeta = box(MaxEncMetaBytes + 1) }, api.CodeTooLarge},
		"wrap sender":          {func(a *RegisterArgs) { a.PersonalVault.WrappedKey.SenderID = userID(99) }, api.CodeBadRequest},
		"wrap size":            {func(a *RegisterArgs) { a.PersonalVault.WrappedKey.Blob = box(104) }, api.CodeBadRequest},
		"wrap too large":       {func(a *RegisterArgs) { a.PersonalVault.WrappedKey.Blob = box(106) }, api.CodeTooLarge},
		"invite and bootstrap": {func(a *RegisterArgs) { a.InviteHash = inviteHash(1) }, api.CodeBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			a := regArgs(1, "bob")
			a.Bootstrap = true
			tc.mut(a)
			h.mustErr(nil, a, tc.code)
			if h.f.HasUsers() {
				t.Fatal("invalid registration created a user")
			}
		})
	}
}

func TestUserLimit(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(0, "u0")
	for i := 1; i < MaxUsers; i++ {
		h.addUser(alice, i, "u"+itoa(i))
	}
	hash := h.invite(alice, 500)
	a := regArgs(500, "toomany")
	a.InviteHash = hash
	h.mustErr(nil, a, api.CodeLimitExceeded)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestSessionChecksAtApply(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	args := func() Args {
		return &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(bob.id)}
	}

	h.mustErr(&tuser{id: bob.id, ep: bob.ep + 1}, args(), api.CodeUnauthorized)
	h.mustErr(&tuser{id: bob.id, ep: 0}, args(), api.CodeUnauthorized)
	h.mustErr(&tuser{id: userID(77), ep: 1}, args(), api.CodeUnauthorized)
	h.mustErr(nil, args(), api.CodeUnauthorized)

	h.mustOK(alice, &AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(true)})
	h.mustErr(bob, args(), api.CodeUnauthorized) // epoch was bumped
	bob.ep++
	h.mustErr(bob, args(), api.CodeUnauthorized) // still disabled
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(false)})
	h.mustOK(bob, args())
}

func TestChangePasswordAndRevokeSessions(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	newKDF := kdf()
	newKDF.Salt = bytes.Repeat([]byte{9}, 16)
	out := h.mustOK(alice, &ChangePasswordArgs{NewKDF: newKDF, NewWrappedAccountKey: box(80), Verifier: verifier(42)})
	if out.Epoch != 2 || out.Verifier == nil || !bytes.Equal(out.Verifier.Salt, verifier(42).Salt) || out.UserID != alice.id || !out.IsAdmin {
		t.Fatalf("change password outcome: %+v", out)
	}
	ua, _ := h.f.LookupUserByID(alice.id)
	if ua.TokenEpoch != 2 || !bytes.Equal(ua.KDF.Salt, newKDF.Salt) || !bytes.Equal(ua.Verifier.Hash, verifier(42).Hash) {
		t.Fatalf("user after change: %+v", ua)
	}
	// The old epoch is revoked (this is the compare-and-swap).
	h.mustErr(alice, &ChangePasswordArgs{NewKDF: newKDF, NewWrappedAccountKey: box(80), Verifier: verifier(43)}, api.CodeUnauthorized)
	alice.ep = out.Epoch
	h.mustErr(alice, &ChangePasswordArgs{NewKDF: api.KDFParams{}, NewWrappedAccountKey: box(80), Verifier: verifier(43)}, api.CodeBadRequest)

	out = h.mustOK(alice, &RevokeSessionsArgs{})
	if out.Epoch != 3 || out.Username != "alice" {
		t.Fatalf("revoke sessions: %+v", out)
	}
	h.mustErr(alice, &RevokeSessionsArgs{}, api.CodeUnauthorized)
}

func TestAdminUpdateUser(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")

	h.mustErr(bob, &AdminUpdateUserArgs{UserID: alice.id, Disabled: ptr(true)}, api.CodeForbidden)
	h.mustErr(alice, &AdminUpdateUserArgs{UserID: userID(99), Disabled: ptr(true)}, api.CodeNotFound)
	h.mustErr(alice, &AdminUpdateUserArgs{UserID: bob.id}, api.CodeBadRequest)

	// The last enabled admin can neither be disabled nor demoted.
	h.mustErr(alice, &AdminUpdateUserArgs{UserID: alice.id, Disabled: ptr(true)}, api.CodeForbidden)
	h.mustErr(alice, &AdminUpdateUserArgs{UserID: alice.id, IsAdmin: ptr(false)}, api.CodeForbidden)

	// No-op: does not bump rev.
	rev := h.f.Rev()
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: alice.id, IsAdmin: ptr(true), Disabled: ptr(false)})
	if h.f.Rev() != rev {
		t.Fatal("no-op admin update bumped rev")
	}

	h.mustOK(alice, &AdminUpdateUserArgs{UserID: bob.id, IsAdmin: ptr(true)})
	// A disabled admin does not count as an enabled admin.
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(true)})
	h.mustErr(alice, &AdminUpdateUserArgs{UserID: alice.id, IsAdmin: ptr(false)}, api.CodeForbidden)
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(false)})
	ub, _ := h.f.LookupUserByID(bob.id)
	bob.ep = ub.TokenEpoch
	if ub.TokenEpoch != 2 || !ub.IsAdmin || ub.Disabled {
		t.Fatalf("bob: %+v", ub)
	}
	// With two enabled admins, one may step down (even themself).
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: alice.id, IsAdmin: ptr(false)})
	h.mustErr(alice, &CreateInviteArgs{InviteHash: inviteHash(70), TTLHours: 1}, api.CodeForbidden)
	h.mustErr(bob, &AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(true)}, api.CodeForbidden)
}

func TestVaultLifecycle(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")

	h.mustErr(alice, &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(bob.id)}, api.CodeBadRequest)
	h.mustErr(alice, &CreateVaultArgs{VaultID: alice.personal, EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)}, api.CodeAlreadyExists)
	h.mustErr(alice, &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(40), WrappedKey: wk(alice.id)}, api.CodeBadRequest)
	out := h.mustOK(alice, &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)})
	if out.Version != out.Rev {
		t.Fatalf("create vault outcome %+v", out)
	}
	vid := vaultID(1)
	v := h.vault(alice, vid)
	if v.Personal || v.MetaVersion != out.Rev || v.Rev != out.Rev || v.KeyEpoch != 1 || v.MyRole != api.RoleOwner {
		t.Fatalf("vault: %+v", v)
	}
	h.addMember(alice, vid, bob, api.RoleEditor)
	h.addMember(alice, vid, carol, api.RoleViewer)

	// Metadata: owner only, CAS on meta_version.
	h.mustErr(bob, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(64), BaseMetaVersion: v.MetaVersion}, api.CodeForbidden)
	e := h.mustErr(alice, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(64), BaseMetaVersion: v.MetaVersion + 100}, api.CodeVersionConflict)
	if e.CurrentVersion == nil || *e.CurrentVersion != v.MetaVersion {
		t.Fatalf("meta conflict current_version = %v", e.CurrentVersion)
	}
	out = h.mustOK(alice, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(100), BaseMetaVersion: v.MetaVersion})
	if out.Version != out.Rev || h.vault(alice, vid).MetaVersion != out.Rev {
		t.Fatalf("meta update: %+v", out)
	}
	h.mustErr(alice, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(MaxEncMetaBytes + 1), BaseMetaVersion: out.Version}, api.CodeTooLarge)

	// Non-members cannot tell the vault exists.
	dave := h.addUser(alice, 4, "dave")
	h.mustErr(dave, &UpdateVaultMetaArgs{VaultID: vid, EncMeta: box(64), BaseMetaVersion: out.Version}, api.CodeNotFound)
	h.mustErr(dave, &DeleteVaultArgs{VaultID: vid}, api.CodeNotFound)
	h.mustErr(dave, &DeleteVaultArgs{VaultID: vaultID(404)}, api.CodeNotFound)

	// Delete: owner only, never the personal vault.
	h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(300), KeyEpoch: 1})
	h.mustErr(bob, &DeleteVaultArgs{VaultID: vid}, api.CodeForbidden)
	h.mustErr(alice, &DeleteVaultArgs{VaultID: alice.personal}, api.CodeForbidden)
	h.mustOK(alice, &DeleteVaultArgs{VaultID: vid})
	if h.visible(alice, vid) || h.visible(bob, vid) || h.visible(carol, vid) {
		t.Fatal("deleted vault still visible")
	}
	// The id can be reused and starts empty.
	h.createVault(bob, 1)
	if v := h.vault(bob, vid); len(v.Items) != 0 || len(v.Members) != 1 {
		t.Fatalf("re-created vault: %+v", v)
	}
}

func TestVaultLimitPerCreator(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	for i := 1; i < MaxVaultsPerOwner; i++ { // the personal vault counts
		h.createVault(alice, i)
	}
	h.mustErr(alice, &CreateVaultArgs{VaultID: vaultID(999), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)}, api.CodeLimitExceeded)
	h.mustOK(alice, &DeleteVaultArgs{VaultID: vaultID(1)})
	h.createVault(alice, 999)
}

func TestMembers(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	vid := h.createVault(alice, 1)

	// Adding needs a wrapped key from the caller for the current epoch.
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleEditor, KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeBadRequest)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleEditor, WrappedKey: wkp(bob.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeBadRequest)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleEditor, WrappedKey: wkp(alice.id), KeyEpoch: 2, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeKeyEpochMismatch)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: "admin", WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeBadRequest)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: userID(99), Role: api.RoleEditor, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeNotFound)
	h.mustErr(bob, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleOwner, WrappedKey: wkp(bob.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeNotFound)
	// Personal vaults are never shared.
	h.mustErr(alice, &PutMemberArgs{VaultID: alice.personal, UserID: bob.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(alice.personal)}, api.CodeForbidden)

	h.addMember(alice, vid, bob, api.RoleEditor)
	if v := h.vault(bob, vid); v.MyRole != api.RoleEditor || v.MyKey.SenderID != alice.id || len(v.Members) != 2 || v.Members[1].AddedBy != alice.id && v.Members[0].AddedBy != alice.id {
		t.Fatalf("bob's view: %+v", v)
	}
	// Editors cannot manage members.
	h.mustErr(bob, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleViewer, WrappedKey: wkp(bob.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeForbidden)
	h.mustErr(bob, &RemoveMemberArgs{VaultID: vid, UserID: alice.id}, api.CodeForbidden)
	// Re-adding with a key is refused; role changes omit the key.
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeAlreadyExists)
	// Setting the same role still uploads a roster: it is a write.
	rv := h.rv(vid)
	out := h.mustOK(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleEditor, KeyEpoch: h.ep(vid), EncRoster: box(80), BaseRosterVersion: rv})
	if h.rv(vid) != out.Rev || out.Version != out.Rev || len(h.vault(alice, vid).EncRoster) != 80 {
		t.Fatal("same-role put_member must replace the roster")
	}
	// The roster CAS: a stale base is refused and changes nothing.
	e := h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleViewer, KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: rv}, api.CodeVersionConflict)
	if e.CurrentVersion == nil || *e.CurrentVersion != out.Rev {
		t.Fatalf("roster conflict must report the current roster_version: %+v", e)
	}
	// Role changes are bound to the current key epoch too (the roster is
	// sealed under it).
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleViewer, KeyEpoch: 2, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeKeyEpochMismatch)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleViewer, KeyEpoch: 1, BaseRosterVersion: h.rv(vid)}, api.CodeBadRequest)
	// Last-owner rules.
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: alice.id, Role: api.RoleEditor, KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeForbidden)
	h.mustErr(alice, &RemoveMemberArgs{VaultID: vid, UserID: alice.id}, api.CodeForbidden)
	h.mustOK(alice, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleOwner, KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: h.rv(vid)})
	h.mustOK(bob, &PutMemberArgs{VaultID: vid, UserID: alice.id, Role: api.RoleViewer, KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: h.rv(vid)}) // more owners exist
	h.mustErr(bob, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleEditor, KeyEpoch: h.ep(vid), EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeForbidden)

	// Leaving and removing.
	h.mustOK(bob, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleViewer, WrappedKey: wkp(bob.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)})
	h.mustErr(carol, &RemoveMemberArgs{VaultID: vid, UserID: alice.id}, api.CodeForbidden)
	h.mustOK(carol, &RemoveMemberArgs{VaultID: vid, UserID: carol.id}) // leave
	if h.visible(carol, vid) {
		t.Fatal("carol still sees the vault after leaving")
	}
	if !h.vault(bob, vid).RekeyRecommended {
		t.Fatal("removal must set rekey_recommended")
	}
	h.mustErr(bob, &RemoveMemberArgs{VaultID: vid, UserID: carol.id}, api.CodeNotFound)
	h.mustOK(bob, &RemoveMemberArgs{VaultID: vid, UserID: alice.id})
	h.mustErr(bob, &RemoveMemberArgs{VaultID: vid, UserID: bob.id}, api.CodeForbidden) // last owner
	h.mustErr(alice, &RemoveMemberArgs{VaultID: alice.personal, UserID: alice.id}, api.CodeForbidden)
}

func TestItems(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleEditor)
	h.addMember(alice, vid, carol, api.RoleViewer)
	iid := itemID(1)

	h.mustErr(carol, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), KeyEpoch: 1}, api.CodeForbidden)
	h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), KeyEpoch: 2}, api.CodeKeyEpochMismatch)
	h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(MaxItemBlobBytes + 1), KeyEpoch: 1}, api.CodeTooLarge)
	h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(40), KeyEpoch: 1}, api.CodeBadRequest)
	e := h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), BaseVersion: 5, KeyEpoch: 1}, api.CodeVersionConflict)
	if e.CurrentVersion == nil || *e.CurrentVersion != 0 {
		t.Fatal("conflict on missing item must report current_version 0")
	}
	out := h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(MaxItemBlobBytes), KeyEpoch: 1})
	if out.Version != out.Rev {
		t.Fatalf("put item outcome %+v", out)
	}
	v1 := out.Version
	e = h.mustErr(alice, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), BaseVersion: 0, KeyEpoch: 1}, api.CodeVersionConflict)
	if *e.CurrentVersion != v1 {
		t.Fatalf("current_version %d, want %d", *e.CurrentVersion, v1)
	}
	out = h.mustOK(alice, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(301), BaseVersion: v1, KeyEpoch: 1})
	v2 := out.Version
	it, _ := h.item(carol, vid, iid)
	if it.Version != v2 || it.UpdatedBy != alice.id || it.UpdatedAt != h.now || len(it.Blob) != 301 {
		t.Fatalf("item: %+v", it)
	}
	if h.vault(carol, vid).Rev != v2 {
		t.Fatal("vault rev must follow item writes")
	}
	e = h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), BaseVersion: v1, KeyEpoch: 1}, api.CodeVersionConflict)
	if *e.CurrentVersion != v2 {
		t.Fatal("stale update must report the current version")
	}

	// Delete: CAS, viewers forbidden; versions never reused.
	h.mustErr(carol, &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: v2}, api.CodeForbidden)
	h.mustErr(bob, &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: v1}, api.CodeVersionConflict)
	h.mustErr(bob, &DeleteItemArgs{VaultID: vid, ItemID: iid}, api.CodeBadRequest)
	h.mustOK(bob, &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: v2})
	e = h.mustErr(bob, &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: v2}, api.CodeVersionConflict)
	if *e.CurrentVersion != 0 {
		t.Fatal("deleting a missing item must report current_version 0")
	}
	out = h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(300), KeyEpoch: 1})
	if out.Version <= v2 {
		t.Fatalf("re-created item reused version %d", out.Version)
	}
	// Viewers and outsiders cannot write; outsiders get 404.
	dave := h.addUser(alice, 4, "dave")
	h.mustErr(dave, &PutItemArgs{VaultID: vid, ItemID: itemID(2), Blob: box(300), KeyEpoch: 1}, api.CodeNotFound)
	h.mustErr(dave, &DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: out.Version}, api.CodeNotFound)
}

func TestItemLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("applies 10000 commands")
	}
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	for i := 0; i < MaxItemsPerVault; i++ {
		h.mustOK(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(i), Blob: box(41), KeyEpoch: 1})
	}
	h.mustErr(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(MaxItemsPerVault), Blob: box(41), KeyEpoch: 1}, api.CodeLimitExceeded)
	// Updates are still allowed at the limit.
	it, _ := h.item(alice, alice.personal, itemID(0))
	h.mustOK(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(0), Blob: box(42), BaseVersion: it.Version, KeyEpoch: 1})
	snapshotRoundTrip(t, h.f)
}

func rekeyArgs(v api.Vault, caller string) *RekeyArgs {
	a := &RekeyArgs{VaultID: v.ID, BaseRev: v.Rev, NewKeyEpoch: v.KeyEpoch + 1, EncMeta: box(70), EncRoster: box(64), WrappedKeys: map[string]api.WrappedKey{}}
	for _, m := range v.Members {
		a.WrappedKeys[m.UserID] = wk(caller)
	}
	for _, it := range v.Items {
		a.Items = append(a.Items, api.RekeyItem{ID: it.ID, Blob: box(500)})
	}
	return a
}

func TestRekey(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleEditor)
	h.addMember(alice, vid, carol, api.RoleViewer)
	for i := 0; i < 3; i++ {
		h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(i), Blob: box(300), KeyEpoch: 1})
	}
	h.mustOK(alice, &RemoveMemberArgs{VaultID: vid, UserID: carol.id})
	v := h.vault(alice, vid)
	if !v.RekeyRecommended {
		t.Fatal("expected rekey_recommended")
	}

	h.mustErr(bob, rekeyArgs(v, bob.id), api.CodeForbidden)
	h.mustErr(carol, rekeyArgs(v, carol.id), api.CodeNotFound)

	bad := rekeyArgs(v, alice.id)
	bad.BaseRev--
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	bad.NewKeyEpoch = 3
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	bad.WrappedKeys[carol.id] = wk(alice.id) // removed member
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	delete(bad.WrappedKeys, bob.id)
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	bad.Items = bad.Items[1:]
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	bad.Items[0].ID = itemID(99)
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = rekeyArgs(v, alice.id)
	bad.Items = append(bad.Items, bad.Items[0])
	h.mustErr(alice, bad, api.CodeBadRequest)
	bad = rekeyArgs(v, alice.id)
	bad.WrappedKeys[bob.id] = wk(bob.id) // must be wrapped by the caller
	h.mustErr(alice, bad, api.CodeBadRequest)
	bad = rekeyArgs(v, alice.id)
	bad.Items[1].Blob = box(MaxItemBlobBytes + 1)
	h.mustErr(alice, bad, api.CodeTooLarge)

	out := h.mustOK(alice, rekeyArgs(v, alice.id))
	nv := h.vault(bob, vid)
	if nv.KeyEpoch != 2 || nv.RekeyRecommended || nv.Rev != out.Rev || nv.MetaVersion != out.Rev || len(nv.EncMeta) != 70 {
		t.Fatalf("after rekey: %+v", nv)
	}
	for _, it := range nv.Items {
		if it.Version != out.Rev || len(it.Blob) != 500 || it.UpdatedBy != alice.id {
			t.Fatalf("item after rekey: %+v", it)
		}
	}
	// Writes with the old epoch are now refused.
	h.mustErr(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(0), Blob: box(300), BaseVersion: out.Rev, KeyEpoch: 1}, api.CodeKeyEpochMismatch)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeKeyEpochMismatch)
	h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(0), Blob: box(300), BaseVersion: out.Rev, KeyEpoch: 2})
	// A rekey based on the old rev fails.
	h.mustErr(alice, rekeyArgs(nv, alice.id), api.CodeVersionConflict)
	// Empty vault rekey works too.
	ev := h.createVault(alice, 2)
	h.mustOK(alice, rekeyArgs(h.vault(alice, ev), alice.id))
}

func TestSyncView(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	shared := h.createVault(alice, 5)
	h.createVault(alice, 3) // alice only
	h.addMember(alice, shared, bob, api.RoleViewer)
	h.mustOK(alice, &PutItemArgs{VaultID: shared, ItemID: itemID(9), Blob: box(100), KeyEpoch: 1})
	h.mustOK(alice, &PutItemArgs{VaultID: shared, ItemID: itemID(2), Blob: box(100), KeyEpoch: 1})

	r, ok := h.f.SyncView(bob.id, 0)
	if !ok {
		t.Fatal("bob unknown")
	}
	if r.Rev != h.f.Rev() || r.Account.UserID != bob.id || r.Account.IsAdmin || len(r.Directory) != 2 {
		t.Fatalf("sync: %+v", r)
	}
	if r.Directory[0].UserID > r.Directory[1].UserID {
		t.Fatal("directory not sorted")
	}
	if len(r.Vaults) != 2 || r.Vaults[0].ID > r.Vaults[1].ID {
		t.Fatalf("bob must see exactly his personal and the shared vault, sorted: %+v", r.Vaults)
	}
	var sv api.Vault
	for _, v := range r.Vaults {
		if v.ID == shared {
			sv = v
		}
	}
	if sv.MyRole != api.RoleViewer || len(sv.Items) != 2 || sv.Items[0].ID != itemID(2) || sv.Members[0].UserID > sv.Members[1].UserID {
		t.Fatalf("shared vault: %+v", sv)
	}
	// Results are copies.
	sv.Items[0].Blob[5] ^= 0xff
	r.Account.WrappedAccountKey[3] ^= 0xff
	r.Directory[0].PublicKey[0] ^= 0xff
	again, _ := h.f.SyncView(bob.id, 0)
	if !bytes.Equal(again.Account.WrappedAccountKey, box(73)) || again.Directory[0].PublicKey[0] == r.Directory[0].PublicKey[0] {
		t.Fatal("SyncView exposed internal memory")
	}
	for _, v := range again.Vaults {
		if v.ID == shared && v.Items[0].Blob[5] != 0xab {
			t.Fatal("SyncView exposed item memory")
		}
	}
	// Unchanged.
	u, _ := h.f.SyncView(bob.id, r.Rev)
	if !u.Unchanged || u.Rev != r.Rev || u.Account != nil || len(u.Vaults) != 0 {
		t.Fatalf("unchanged: %+v", u)
	}
	if _, ok := h.f.SyncView(userID(99), 0); ok {
		t.Fatal("unknown user must not sync")
	}
	// Empty item list encodes as [] for an empty vault.
	for _, v := range again.Vaults {
		if v.Items == nil || v.Members == nil {
			t.Fatal("nil slices in sync view")
		}
	}
}

func TestDryRunAndCachedResult(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	cmd := h.cmd(alice, &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)})
	if err := h.f.DryRun(cmd); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if h.f.visibleCount(alice.id) != 1 {
		t.Fatal("dry run changed state")
	}
	if _, ok := h.f.CachedResult(cmd); ok {
		t.Fatal("cached result before apply")
	}
	res := h.f.Apply(5, cmd)
	got, ok := h.f.CachedResult(cmd)
	if !ok || !bytes.Equal(got, res) {
		t.Fatal("cached result after apply")
	}
	if err := h.f.DryRun(cmd); err != nil {
		t.Fatal("dry run of an applied command should report success (replay)")
	}
	other := h.cmd(alice, &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(alice.id)})
	if err := h.f.DryRun(other); err == nil || err.Code != api.CodeAlreadyExists {
		t.Fatalf("dry run conflict: %v", err)
	}
	if err := h.f.DryRun([]byte("junk")); err == nil || err.Code != api.CodeBadRequest {
		t.Fatalf("dry run junk: %v", err)
	}
}

func (f *FSM) visibleCount(uid string) int {
	r, _ := f.SyncView(uid, 0)
	return len(r.Vaults)
}

func TestArgsValidate(t *testing.T) {
	caller := userID(1)
	good := wk(caller)
	cases := []struct {
		name string
		a    Args
		code string
	}{
		{"init short key", &InitArgs{ClusterKey: []byte{1}}, api.CodeBadRequest},
		{"invite bad ttl", &CreateInviteArgs{InviteHash: inviteHash(1), TTLHours: 0}, api.CodeBadRequest},
		{"revoke bad id", &RevokeInviteArgs{InviteID: "ABCDEF0123456789"}, api.CodeBadRequest},
		{"admin bad id", &AdminUpdateUserArgs{UserID: "x", Disabled: ptr(true)}, api.CodeBadRequest},
		{"vault bad id", &CreateVaultArgs{VaultID: "x", EncRoster: box(64), EncMeta: box(64), WrappedKey: good}, api.CodeBadRequest},
		{"vault sender", &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(userID(2))}, api.CodeBadRequest},
		{"vault bad sender id", &CreateVaultArgs{VaultID: vaultID(1), EncRoster: box(64), EncMeta: box(64), WrappedKey: api.WrappedKey{SenderID: "x", Blob: box(105)}}, api.CodeBadRequest},
		{"meta bad id", &UpdateVaultMetaArgs{VaultID: "x", EncMeta: box(64)}, api.CodeBadRequest},
		{"meta short", &UpdateVaultMetaArgs{VaultID: vaultID(1), EncMeta: box(3)}, api.CodeBadRequest},
		{"delete vault id", &DeleteVaultArgs{VaultID: ""}, api.CodeBadRequest},
		{"member vault", &PutMemberArgs{VaultID: "x", UserID: userID(2), Role: api.RoleViewer, EncRoster: box(64)}, api.CodeBadRequest},
		{"member user", &PutMemberArgs{VaultID: vaultID(1), UserID: "x", Role: api.RoleViewer, EncRoster: box(64)}, api.CodeBadRequest},
		{"member big key", &PutMemberArgs{VaultID: vaultID(1), UserID: userID(2), Role: api.RoleViewer, WrappedKey: &api.WrappedKey{SenderID: caller, Blob: box(200)}, EncRoster: box(64)}, api.CodeTooLarge},
		{"remove vault", &RemoveMemberArgs{VaultID: "x", UserID: userID(2)}, api.CodeBadRequest},
		{"remove user", &RemoveMemberArgs{VaultID: vaultID(1), UserID: "x"}, api.CodeBadRequest},
		{"rekey vault", &RekeyArgs{VaultID: "x", EncMeta: box(64)}, api.CodeBadRequest},
		{"rekey meta", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(MaxEncMetaBytes + 1)}, api.CodeTooLarge},
		{"rekey key id", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), WrappedKeys: map[string]api.WrappedKey{"x": good}}, api.CodeBadRequest},
		{"rekey item id", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), Items: []api.RekeyItem{{ID: "x", Blob: box(64)}}}, api.CodeBadRequest},
		{"item vault", &PutItemArgs{VaultID: "x", ItemID: itemID(1), Blob: box(64)}, api.CodeBadRequest},
		{"item id", &PutItemArgs{VaultID: vaultID(1), ItemID: "x", Blob: box(64)}, api.CodeBadRequest},
		{"del item vault", &DeleteItemArgs{VaultID: "x", ItemID: itemID(1), BaseVersion: 1}, api.CodeBadRequest},
		{"del item id", &DeleteItemArgs{VaultID: vaultID(1), ItemID: "x", BaseVersion: 1}, api.CodeBadRequest},
		{"password kdf", &ChangePasswordArgs{NewKDF: api.KDFParams{Alg: "argon2id"}, NewWrappedAccountKey: box(73), Verifier: verifier(1)}, api.CodeBadRequest},
		{"password verifier", &ChangePasswordArgs{NewKDF: kdf(), NewWrappedAccountKey: box(73)}, api.CodeBadRequest},
		{"vault no roster", &CreateVaultArgs{VaultID: vaultID(1), EncMeta: box(64), WrappedKey: good}, api.CodeBadRequest},
		{"vault big roster", &CreateVaultArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(MaxRosterBytes + 1), WrappedKey: good}, api.CodeTooLarge},
		{"member no roster", &PutMemberArgs{VaultID: vaultID(1), UserID: userID(2), Role: api.RoleViewer}, api.CodeBadRequest},
		{"member big roster", &PutMemberArgs{VaultID: vaultID(1), UserID: userID(2), Role: api.RoleViewer, EncRoster: box(MaxRosterBytes + 1)}, api.CodeTooLarge},
		{"rekey no roster", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64)}, api.CodeBadRequest},
		{"rekey big roster", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(MaxRosterBytes + 1)}, api.CodeTooLarge},
		{"rekey remove self", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(64), Remove: []string{caller}}, api.CodeBadRequest},
		{"rekey remove dup", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(64), Remove: []string{userID(2), userID(2)}}, api.CodeBadRequest},
		{"rekey remove bad id", &RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(64), Remove: []string{"bob"}}, api.CodeBadRequest},
	}
	for _, tc := range cases {
		e := tc.a.Validate(caller)
		if e == nil || e.Code != tc.code {
			t.Errorf("%s: got %v, want %s", tc.name, e, tc.code)
		}
		if e != nil && e.Error() == "" {
			t.Errorf("%s: empty error string", tc.name)
		}
	}
	// Canonicalization folds ASCII only.
	if CanonicalUsername("  BoB.x ") != "bob.x" || ValidUsername(CanonicalUsername("Kate")) {
		t.Fatal("username canonicalization")
	}
	for _, a := range []Args{
		&RevokeSessionsArgs{}, &InitArgs{ClusterKey: make([]byte, 32)},
		&RekeyArgs{VaultID: vaultID(1), EncMeta: box(64), EncRoster: box(64), Remove: []string{userID(2)}, WrappedKeys: map[string]api.WrappedKey{caller: good}, Items: []api.RekeyItem{{ID: itemID(1), Blob: box(64)}}},
	} {
		if e := a.Validate(caller); e != nil {
			t.Errorf("%s: unexpected %v", a.Op(), e)
		}
	}
}

func TestRekeyWithRemove(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	dave := h.addUser(alice, 4, "dave")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleOwner)
	h.addMember(alice, vid, carol, api.RoleViewer)
	h.addMember(alice, vid, dave, api.RoleEditor)
	h.mustOK(dave, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(300), KeyEpoch: 1})
	v := h.vault(alice, vid)
	if len(v.EncRoster) != 64 || v.RosterVersion == 0 || v.RosterVersion > v.Rev {
		t.Fatalf("roster in sync view: %d bytes, version %d", len(v.EncRoster), v.RosterVersion)
	}
	removing := func(ids ...string) *RekeyArgs {
		a := rekeyArgs(v, alice.id)
		a.Remove = ids
		for _, id := range ids {
			delete(a.WrappedKeys, id)
		}
		return a
	}

	h.mustErr(dave, &RekeyArgs{VaultID: vid, BaseRev: v.Rev, NewKeyEpoch: 2, EncMeta: box(64), EncRoster: box(64), Remove: []string{carol.id}}, api.CodeForbidden)
	h.mustErr(alice, removing(userID(99)), api.CodeBadRequest)         // not a member
	h.mustErr(alice, removing(alice.id), api.CodeBadRequest)           // the caller
	h.mustErr(alice, removing(carol.id, carol.id), api.CodeBadRequest) // duplicate
	bad := removing(carol.id)
	bad.WrappedKeys[carol.id] = wk(alice.id) // still wrapping for the removed member
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = removing(carol.id)
	delete(bad.WrappedKeys, dave.id) // a remaining member left out
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = removing(carol.id)
	bad.BaseRev--
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = removing(carol.id)
	bad.NewKeyEpoch++
	h.mustErr(alice, bad, api.CodeVersionConflict)
	bad = removing(carol.id)
	bad.EncRoster = nil
	h.mustErr(alice, bad, api.CodeBadRequest)

	// Remove carol and the other owner (bob) in one atomic rekey.
	good := removing(carol.id, bob.id)
	good.EncRoster = box(90)
	out := h.mustOK(alice, good)
	nv := h.vault(dave, vid)
	if nv.KeyEpoch != 2 || nv.RosterVersion != out.Rev || nv.MetaVersion != out.Rev || len(nv.EncRoster) != 90 ||
		nv.RekeyRecommended || len(nv.Members) != 2 || nv.Items[0].Version != out.Rev {
		t.Fatalf("after rekey with remove: %+v", nv)
	}
	if h.visible(carol, vid) || h.visible(bob, vid) {
		t.Fatal("removed members still see the vault")
	}
	h.mustErr(carol, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(300), BaseVersion: out.Rev, KeyEpoch: 2}, api.CodeNotFound)
	// Remaining members got their new wrapped keys.
	if nv.MyKey.SenderID != alice.id {
		t.Fatalf("dave's key: %+v", nv.MyKey)
	}

	// Leaving (DELETE member) leaves the roster alone and recommends a rekey.
	rv := nv.RosterVersion
	h.mustOK(dave, &RemoveMemberArgs{VaultID: vid, UserID: dave.id})
	if v := h.vault(alice, vid); v.RosterVersion != rv || !v.RekeyRecommended || len(v.EncRoster) != 90 {
		t.Fatalf("after leaving: %+v", v)
	}
	// A rekey whose remove list names someone who already left is refused;
	// the client must base it on the current member list.
	v = h.vault(alice, vid)
	h.mustErr(alice, removing(dave.id), api.CodeBadRequest)
	h.mustOK(alice, rekeyArgs(v, alice.id))

	// Personal vaults: rekey only with no removals and exactly the owner's key.
	pv := h.vault(alice, alice.personal)
	h.mustOK(alice, rekeyArgs(pv, alice.id))
	pv = h.vault(alice, alice.personal)
	pa := rekeyArgs(pv, alice.id)
	pa.Remove = []string{bob.id}
	h.mustErr(alice, pa, api.CodeBadRequest)
	pa = rekeyArgs(pv, alice.id)
	pa.WrappedKeys[bob.id] = wk(alice.id)
	h.mustErr(alice, pa, api.CodeVersionConflict)
	snapshotRoundTrip(t, h.f)
	checkCounters(t, h.f)
}

func TestPutMemberRosterRules(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleOwner)
	// Two owners race: both based on the same roster version.
	base := h.rv(vid)
	out := h.mustOK(alice, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(100), BaseRosterVersion: base})
	if out.Version != out.Rev || h.rv(vid) != out.Rev {
		t.Fatalf("put_member outcome %+v", out)
	}
	e := h.mustErr(bob, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleEditor, KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: base}, api.CodeVersionConflict)
	if *e.CurrentVersion != out.Rev {
		t.Fatalf("conflict current_version %d", *e.CurrentVersion)
	}
	v := h.vault(alice, vid)
	role := ""
	for _, m := range v.Members {
		if m.UserID == carol.id {
			role = m.Role
		}
	}
	if len(v.EncRoster) != 100 || role != api.RoleViewer {
		t.Fatal("the losing request changed something")
	}
	// The other existing checks still come first.
	h.mustErr(carol, &PutMemberArgs{VaultID: vid, UserID: bob.id, Role: api.RoleViewer, KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeForbidden)
	h.mustErr(alice, &PutMemberArgs{VaultID: alice.personal, UserID: bob.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(alice.personal)}, api.CodeForbidden)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: userID(99), Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeNotFound)
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleViewer, WrappedKey: wkp(alice.id), KeyEpoch: 1, EncRoster: box(64), BaseRosterVersion: h.rv(vid)}, api.CodeAlreadyExists)
	// A conflicting base is reported even when the epoch is right but the
	// roster moved; a wrong epoch is reported first.
	h.mustErr(alice, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleEditor, KeyEpoch: 9, EncRoster: box(64), BaseRosterVersion: base}, api.CodeKeyEpochMismatch)
	// Rosters count toward the storage quotas.
	before := usage(h.f, vid)
	h.mustOK(alice, &PutMemberArgs{VaultID: vid, UserID: carol.id, Role: api.RoleEditor, KeyEpoch: 1, EncRoster: box(MaxRosterBytes), BaseRosterVersion: h.rv(vid)})
	if usage(h.f, vid) != before-100+MaxRosterBytes {
		t.Fatalf("roster bytes not accounted: %d -> %d", before, usage(h.f, vid))
	}
	checkCounters(t, h.f)
}
