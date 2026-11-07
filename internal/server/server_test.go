package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
)

func ptr[T any](v T) *T { return &v }

func TestEndToEndHousehold(t *testing.T) {
	e := newEnv(t)
	e.initCluster()

	var h api.HealthResponse
	e.call("GET", "/v1/health", nil, 200, &h)
	if !h.Initialized || h.HasUsers || h.NodeID != "n1" || h.Role != "leader" || h.LeaderID != "n1" || h.Version != "test" {
		t.Fatalf("health: %+v", h)
	}
	var cl api.ClusterResponse
	e.call("GET", "/v1/cluster", nil, 200, &cl)
	if len(cl.Nodes) != 3 || cl.LeaderID != "n1" {
		t.Fatalf("cluster: %+v", cl)
	}

	// Bootstrap: only with the right token, only once.
	alice := newAccount("alice")
	e.callErr("POST", "/v1/register", alice.registerReq("definitely-not-the-token"), 403, api.CodeInvalidInvite)
	e.register(alice, testBootstrapToken)
	if !alice.isAdmin {
		t.Fatal("first user must be admin")
	}
	mallory := newAccount("mallory")
	e.callErr("POST", "/v1/register", mallory.registerReq(testBootstrapToken), 403, api.CodeInvalidInvite)

	// Invites: case-insensitive, dashes optional, single use.
	inv := e.invite(alice)
	if len(inv.Code) != 39 || strings.Count(inv.Code, "-") != 7 || inv.ExpiresAt != e.clock.Now().Add(72*time.Hour).UnixMilli() {
		t.Fatalf("invite: %+v", inv)
	}
	bob := newAccount("bob")
	e.register(bob, strings.ToLower(strings.ReplaceAll(inv.Code, "-", "")))
	if bob.isAdmin {
		t.Fatal("invited user must not be admin")
	}
	carol := newAccount("carol")
	e.callErr("POST", "/v1/register", carol.registerReq(inv.Code), 403, api.CodeInvalidInvite)
	inv2 := e.invite(alice)
	dup := newAccount("bob")
	e.callErr("POST", "/v1/register", dup.registerReq(inv2.Code), 409, api.CodeAlreadyExists)
	e.register(carol, inv2.Code)

	// Prelogin returns the stored parameters; login works with the key.
	var pl api.PreloginResponse
	e.call("POST", "/v1/prelogin", api.PreloginRequest{Username: "  BOB "}, 200, &pl)
	if pl.KDF.Alg != "argon2id" || !bytes.Equal(pl.KDF.Salt, bob.kdf.Salt) || pl.KDF.MemoryKiB != bob.kdf.MemoryKiB {
		t.Fatalf("prelogin: %+v", pl.KDF)
	}
	e.login(bob)
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: randBytes(32)}, 401, api.CodeUnauthorized)

	// Shared vault with an editor and a viewer.
	vid := randID()
	var mr api.MutationResponse
	e.call("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(alice.id)}, 200, &mr, withToken(alice.token))
	if mr.Rev == 0 || mr.Version != mr.Rev {
		t.Fatalf("create vault: %+v", mr)
	}
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: randID(), EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(bob.id)}, 400, api.CodeBadRequest, withToken(alice.token))
	member := func(u *account, role string) {
		rv, ep := e.rosterOf(alice, vid)
		e.call("PUT", "/v1/vaults/"+vid+"/members/"+u.id, api.PutMemberRequest{Role: role, WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: ep, EncRoster: box(64), BaseRosterVersion: rv}, 200, nil, withToken(alice.token))
	}
	member(bob, api.RoleEditor)
	member(carol, api.RoleViewer)
	e.callErr("PUT", "/v1/vaults/"+vid+"/members/"+carol.id, api.PutMemberRequest{Role: api.RoleOwner, EncRoster: box(64)}, 403, api.CodeForbidden, withToken(bob.token))

	iid := randID()
	itemPath := "/v1/vaults/" + vid + "/items/" + iid
	var ir api.MutationResponse
	e.call("PUT", itemPath, api.PutItemRequest{Blob: box(300), KeyEpoch: 1}, 200, &ir, withToken(bob.token))
	if ir.Version != ir.Rev {
		t.Fatalf("put item: %+v", ir)
	}
	e.callErr("PUT", itemPath, api.PutItemRequest{Blob: box(300), BaseVersion: ir.Version, KeyEpoch: 1}, 403, api.CodeForbidden, withToken(carol.token))
	d := e.callErr("PUT", itemPath, api.PutItemRequest{Blob: box(300), BaseVersion: ir.Version - 1, KeyEpoch: 1}, 409, api.CodeVersionConflict, withToken(bob.token))
	if d.CurrentVersion == nil || *d.CurrentVersion != ir.Version {
		t.Fatalf("conflict detail: %+v", d)
	}
	e.callErr("PUT", itemPath, api.PutItemRequest{Blob: box(300), BaseVersion: ir.Version, KeyEpoch: 2}, 409, api.CodeKeyEpochMismatch, withToken(bob.token))

	sr := e.sync(carol)
	v, ok := vaultOf(sr, vid)
	if !ok || v.MyRole != api.RoleViewer || len(v.Items) != 1 || v.Items[0].Version != ir.Version || sr.ServedBy != "n1" || sr.Stale {
		t.Fatalf("carol's sync: %+v", sr)
	}
	if len(sr.Directory) != 3 || sr.Account.UserID != carol.id {
		t.Fatalf("carol's directory/account: %+v", sr)
	}
	var un api.SyncResponse
	e.call("GET", "/v1/sync?since="+strconv.FormatUint(sr.Rev, 10), nil, 200, &un, withToken(carol.token))
	if !un.Unchanged || un.Rev != sr.Rev || un.Account != nil {
		t.Fatalf("unchanged sync: %+v", un)
	}
	e.callErr("GET", "/v1/sync?since=abc", nil, 400, api.CodeBadRequest, withToken(carol.token))

	// Metadata CAS.
	e.call("PUT", "/v1/vaults/"+vid+"/meta", api.UpdateVaultMetaRequest{EncMeta: box(80), BaseMetaVersion: v.MetaVersion}, 200, &mr, withToken(alice.token))
	if mr.Version != mr.Rev {
		t.Fatalf("meta: %+v", mr)
	}
	e.callErr("PUT", "/v1/vaults/"+vid+"/meta", api.UpdateVaultMetaRequest{EncMeta: box(80), BaseMetaVersion: v.MetaVersion}, 409, api.CodeVersionConflict, withToken(alice.token))

	// Remove carol, rekey.
	e.call("DELETE", "/v1/vaults/"+vid+"/members/"+carol.id, nil, 200, nil, withToken(alice.token))
	v, _ = vaultOf(e.sync(alice), vid)
	if !v.RekeyRecommended || len(v.Members) != 2 {
		t.Fatalf("after removal: %+v", v)
	}
	rk := api.RekeyRequest{
		BaseRev: v.Rev, NewKeyEpoch: 2, EncMeta: box(64), EncRoster: box(64),
		WrappedKeys: map[string]api.WrappedKey{alice.id: wrapped(alice.id), bob.id: wrapped(alice.id)},
		Items:       []api.RekeyItem{{ID: iid, Blob: box(310)}},
	}
	byBob := rk
	byBob.WrappedKeys = map[string]api.WrappedKey{alice.id: wrapped(bob.id), bob.id: wrapped(bob.id)}
	e.callErr("POST", "/v1/vaults/"+vid+"/rekey", byBob, 403, api.CodeForbidden, withToken(bob.token))
	e.callErr("POST", "/v1/vaults/"+vid+"/rekey", rk, 400, api.CodeBadRequest, withToken(bob.token))
	stale := rk
	stale.BaseRev--
	e.callErr("POST", "/v1/vaults/"+vid+"/rekey", stale, 409, api.CodeVersionConflict, withToken(alice.token))
	e.call("POST", "/v1/vaults/"+vid+"/rekey", rk, 200, &mr, withToken(alice.token))
	if _, visible := vaultOf(e.sync(carol), vid); visible {
		t.Fatal("removed member still sees the vault")
	}
	e.callErr("PUT", itemPath, api.PutItemRequest{Blob: box(300), KeyEpoch: 2}, 404, api.CodeNotFound, withToken(carol.token))

	// Delete item (CAS via query), then the vault; personal vaults stay.
	v, _ = vaultOf(e.sync(bob), vid)
	if v.KeyEpoch != 2 || v.RekeyRecommended || v.Items[0].Version != mr.Rev {
		t.Fatalf("after rekey: %+v", v)
	}
	e.callErr("DELETE", itemPath, nil, 400, api.CodeBadRequest, withToken(bob.token))
	e.callErr("DELETE", itemPath+"?base_version=1", nil, 409, api.CodeVersionConflict, withToken(bob.token))
	e.call("DELETE", itemPath+"?base_version="+strconv.FormatUint(v.Items[0].Version, 10), nil, 200, nil, withToken(bob.token))
	e.callErr("DELETE", "/v1/vaults/"+vid, nil, 403, api.CodeForbidden, withToken(bob.token))
	e.call("DELETE", "/v1/vaults/"+vid, nil, 200, nil, withToken(alice.token))
	e.callErr("DELETE", "/v1/vaults/"+alice.personal, nil, 403, api.CodeForbidden, withToken(alice.token))

	// Password change revokes every older token.
	old := bob.token
	newKey := randBytes(32)
	var lr api.LoginResponse
	e.callErr("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: randBytes(32), NewKDF: clientKDF(), NewLoginKey: newKey, NewWrappedAccountKey: box(73)}, 401, api.CodeUnauthorized, withToken(bob.token))
	e.call("POST", "/v1/account/password", api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: newKey, NewWrappedAccountKey: box(73)}, 200, &lr, withToken(bob.token))
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(old))
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: randID(), EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(bob.id)}, 401, api.CodeUnauthorized, withToken(old))
	bob.token = lr.Token
	e.sync(bob)
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey}, 401, api.CodeUnauthorized)
	bob.loginKey = newKey
	e.login(bob)

	// Revoke sessions.
	old = bob.token
	e.call("POST", "/v1/account/revoke-sessions", nil, 200, &lr, withToken(bob.token))
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(old))
	bob.token = lr.Token
	e.sync(bob)

	// Administration.
	var li api.ListInvitesResponse
	e.call("GET", "/v1/invites", nil, 200, &li, withToken(alice.token))
	used := map[string]bool{}
	for _, i := range li.Invites {
		used[i.UsedBy] = true
	}
	if len(li.Invites) != 2 || !used[bob.id] || !used[carol.id] || li.Invites[0].InviteID > li.Invites[1].InviteID {
		t.Fatalf("invites: %+v", li)
	}
	e.callErr("GET", "/v1/invites", nil, 403, api.CodeForbidden, withToken(bob.token))
	e.callErr("POST", "/v1/invites", api.CreateInviteRequest{}, 403, api.CodeForbidden, withToken(bob.token))
	e.callErr("POST", "/v1/invites", api.CreateInviteRequest{TTLHours: 721}, 400, api.CodeBadRequest, withToken(alice.token))
	inv3 := e.invite(alice)
	e.call("DELETE", "/v1/invites/"+inv3.InviteID, nil, 200, nil, withToken(alice.token))
	e.callErr("DELETE", "/v1/invites/"+inv3.InviteID, nil, 404, api.CodeNotFound, withToken(alice.token))
	e.callErr("DELETE", "/v1/invites/xyz", nil, 400, api.CodeBadRequest, withToken(alice.token))
	e.callErr("POST", "/v1/register", newAccount("dave").registerReq(inv3.Code), 403, api.CodeInvalidInvite)

	e.callErr("PUT", "/v1/admin/users/"+alice.id, api.AdminUpdateUserRequest{IsAdmin: ptr(false)}, 403, api.CodeForbidden, withToken(alice.token))
	e.callErr("PUT", "/v1/admin/users/"+carol.id, api.AdminUpdateUserRequest{Disabled: ptr(true)}, 403, api.CodeForbidden, withToken(bob.token))
	e.call("PUT", "/v1/admin/users/"+bob.id, api.AdminUpdateUserRequest{Disabled: ptr(true)}, 200, nil, withToken(alice.token))
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(bob.token))
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey}, 401, api.CodeUnauthorized)
	e.call("PUT", "/v1/admin/users/"+bob.id, api.AdminUpdateUserRequest{Disabled: ptr(false), IsAdmin: ptr(true)}, 200, nil, withToken(alice.token))
	e.login(bob)
	var me api.SyncResponse
	e.call("GET", "/v1/sync", nil, 200, &me, withToken(bob.token))
	if !me.Account.IsAdmin {
		t.Fatal("bob should be admin now")
	}

	var ac api.AdminClusterResponse
	e.call("GET", "/v1/admin/cluster", nil, 200, &ac, withToken(alice.token))
	if ac.NodeID != "n1" || ac.Rev != e.sm.Rev() || ac.Role != "leader" {
		t.Fatalf("admin cluster: %+v", ac)
	}
	e.callErr("GET", "/v1/admin/cluster", nil, 403, api.CodeForbidden, withToken(carol.token))
	var bk api.ServerBackup
	e.call("GET", "/v1/admin/backup", nil, 200, &bk, withToken(alice.token))
	if bk.Format != "fpv-server-backup" || bk.Version != 1 || bk.Rev != e.sm.Rev() || bk.NodeID != "n1" {
		t.Fatalf("backup header: %+v", bk)
	}
	if err := fsm.ValidateSnapshot(bk.State); err != nil {
		t.Fatalf("backup state: %v", err)
	}
	if bytes.Contains(bk.State, []byte(base64.StdEncoding.EncodeToString(e.sm.ClusterKey()))) {
		t.Fatal("backup contains the cluster key")
	}
	e.callErr("GET", "/v1/admin/backup", nil, 403, api.CodeForbidden, withToken(carol.token))

	e.call("GET", "/v1/health", nil, 200, &h)
	if !h.HasUsers {
		t.Fatal("health: has_users")
	}
}

func TestTokenValidation(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	good := alice.token
	e.call("GET", "/v1/sync", nil, 200, nil, withHeader("Authorization", "bearer "+good))

	parts := strings.Split(good, ".")
	var claims tokenClaims
	raw, _ := b64url.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &claims)
	claims.Ep++
	j, _ := json.Marshal(claims)
	tampered := parts[0] + "." + b64url.EncodeToString(j) + "." + parts[2]
	badMAC := parts[0] + "." + parts[1] + "." + b64url.EncodeToString(bytes.Repeat([]byte{1}, 32))
	foreign := mintToken(bytes.Repeat([]byte{9}, 32), tokenClaims{UID: alice.id, Ep: 1, Iat: 1, Exp: e.clock.Now().Add(time.Hour).Unix()})

	for name, h := range map[string]string{
		"missing":       "",
		"no token":      "Bearer ",
		"basic":         "Basic " + good,
		"tampered":      "Bearer " + tampered,
		"bad mac":       "Bearer " + badMAC,
		"foreign key":   "Bearer " + foreign,
		"wrong version": "Bearer v2." + parts[1] + "." + parts[2],
		"extra part":    "Bearer " + good + ".x",
		"huge":          "Bearer " + strings.Repeat("a", 4096),
		"garbage":       "Bearer !!!",
	} {
		opts := []reqOpt{}
		if h != "" {
			opts = append(opts, withHeader("Authorization", h))
		}
		r := e.do("GET", "/v1/sync", nil, opts...)
		if r.status != 401 || r.errBody(t).Code != api.CodeUnauthorized || r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: status %d %s", name, r.status, r.body)
		}
	}

	// Expiry.
	e.clock.Advance(12*time.Hour + time.Second)
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(good))
}

func TestRevokedTokenWriteIsRejectedWithoutProposing(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	old := alice.token
	var lr api.LoginResponse
	e.call("POST", "/v1/account/revoke-sessions", "{}", 200, &lr, withToken(old))
	before, _, _ := e.node.counts()
	e.callErr("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: randID(), EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(alice.id)}, 401, api.CodeUnauthorized, withToken(old))
	if after, _, _ := e.node.counts(); after != before {
		t.Fatal("a certainly-revoked token reached Propose")
	}
	e.call("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: randID(), EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(alice.id)}, 200, nil, withToken(lr.Token))
}

func TestStaleVersusLinearizableReads(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	e.node.setBarrierErr(errors.New("no quorum"))

	r := e.do("GET", "/v1/sync", nil, withToken(alice.token))
	if r.status != 503 || r.errBody(t).Code != api.CodeUnavailable || r.errBody(t).RetryAfterMs != 1000 || r.header.Get("Retry-After") != "1" {
		t.Fatalf("sync without quorum: %d %s %v", r.status, r.body, r.header)
	}
	var sr api.SyncResponse
	e.call("GET", "/v1/sync?consistency=stale", nil, 200, &sr, withToken(alice.token))
	if !sr.Stale || sr.Account == nil || sr.ServedBy != "n1" {
		t.Fatalf("stale sync: %+v", sr)
	}
	e.callErr("GET", "/v1/sync?consistency=eventual", nil, 400, api.CodeBadRequest, withToken(alice.token))

	e.callErr("POST", "/v1/prelogin", api.PreloginRequest{Username: "bob"}, 503, api.CodeUnavailable)
	e.call("POST", "/v1/prelogin?consistency=stale", api.PreloginRequest{Username: "bob"}, 200, nil)
	e.callErr("POST", "/v1/login", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey}, 503, api.CodeUnavailable)
	e.call("POST", "/v1/login?consistency=stale", api.LoginRequest{Username: "bob", LoginKey: bob.loginKey}, 200, nil)

	// Endpoints that must work without a quorum.
	e.call("GET", "/v1/health", nil, 200, nil)
	e.call("GET", "/v1/cluster", nil, 200, nil)
	e.call("GET", "/v1/admin/cluster", nil, 200, nil, withToken(alice.token))
	// Linearizable-only reads.
	e.callErr("GET", "/v1/invites", nil, 503, api.CodeUnavailable, withToken(alice.token))
	e.callErr("GET", "/v1/admin/backup", nil, 503, api.CodeUnavailable, withToken(alice.token))
	if _, err := e.srv.BuildBackup(context.Background()); err == nil {
		t.Fatal("BuildBackup must fail without a read barrier")
	}
	e.node.setBarrierErr(nil)
	if b, err := e.srv.BuildBackup(context.Background()); err != nil || b.Rev != e.sm.Rev() {
		t.Fatalf("BuildBackup: %v", err)
	}
	// Failed barriers do not count as login failures.
	for i := 0; i < 3; i++ {
		e.login(bob)
	}
}

func TestReadChecksSessionAfterBarrier(t *testing.T) {
	// The barrier is where the node catches up; a revocation applied while
	// waiting must be honoured by the read that follows.
	e := newEnv(t)
	alice, bob := e.household()
	e.node.setOnBarrier(func() {
		cmd, _ := fsm.EncodeCommand(randID(), e.clock.Now().UnixMilli(), alice.id, 1, &fsm.AdminUpdateUserArgs{UserID: bob.id, Disabled: ptr(true)})
		e.node.apply(cmd)
	})
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(bob.token))
}

func TestIdempotentRetry(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	key := randID()
	path := "/v1/vaults/" + alice.personal + "/items/" + randID()
	body := api.PutItemRequest{Blob: box(200), KeyEpoch: 1}
	r1 := e.call("PUT", path, body, 200, nil, withToken(alice.token), withKey(key))
	rev := e.sm.Rev()
	r2 := e.call("PUT", path, body, 200, nil, withToken(alice.token), withKey(strings.ToUpper(key)))
	if !bytes.Equal(r1.body, r2.body) || e.sm.Rev() != rev {
		t.Fatalf("retry was applied twice or answered differently:\n%s\n%s", r1.body, r2.body)
	}
	// Same key, different request.
	e.callErr("PUT", path, api.PutItemRequest{Blob: box(201), KeyEpoch: 1}, 400, api.CodeBadRequest, withToken(alice.token), withKey(key))
	// Without a key a blind retry is a new request.
	e.callErr("PUT", path, body, 409, api.CodeVersionConflict, withToken(alice.token))
	e.callErr("PUT", path, body, 400, api.CodeBadRequest, withToken(alice.token), withKey("not-hex"))

	// Create-invite retries show the same code and create one invite.
	ik := randID()
	var a, b api.CreateInviteResponse
	e.call("POST", "/v1/invites", api.CreateInviteRequest{TTLHours: 5}, 200, &a, withToken(alice.token), withKey(ik))
	e.clock.Advance(time.Minute)
	e.call("POST", "/v1/invites", api.CreateInviteRequest{TTLHours: 5}, 200, &b, withToken(alice.token), withKey(ik))
	if a != b {
		t.Fatalf("invite retry differs: %+v vs %+v", a, b)
	}
	var li api.ListInvitesResponse
	e.call("GET", "/v1/invites", nil, 200, &li, withToken(alice.token))
	if len(li.Invites) != 2 { // bob's (used) + this one
		t.Fatalf("invites after retry: %+v", li)
	}
	carol := newAccount("carol")
	e.register(carol, b.Code)
}

func TestRegisterRetry(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	inv := e.invite(alice)
	carol := newAccount("carol")
	req := carol.registerReq(inv.Code)
	key := randID()
	var r1, r2 api.LoginResponse
	e.call("POST", "/v1/register", req, 200, &r1, withKey(key))
	rev := e.sm.Rev()
	e.call("POST", "/v1/register", req, 200, &r2, withKey(key))
	if r2.UserID != carol.id || e.sm.Rev() != rev {
		t.Fatalf("register retry: %+v", r2)
	}
	e.call("GET", "/v1/sync", nil, 200, nil, withToken(r2.Token))
	// A replay never yields a session without the registered login key.
	bad := req
	bad.LoginKey = randBytes(32)
	e.callErr("POST", "/v1/register", bad, 401, api.CodeUnauthorized, withKey(key))
	// Nor can someone else's registration be answered with this key.
	other := newAccount("mallory").registerReq(inv.Code)
	e.callErr("POST", "/v1/register", other, 400, api.CodeBadRequest, withKey(key))
}

func TestProposeRetryPaths(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ProposeTimeout = 300 * time.Millisecond })
	alice, _ := e.household()
	create := func() api.CreateVaultRequest {
		return api.CreateVaultRequest{VaultID: randID(), EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(alice.id)}
	}
	count := func() (int, int) { p, a, _ := e.node.counts(); return p, a }

	// No leader twice, then success.
	p0, a0 := count()
	e.node.push(step{kind: stepNoLeader}, step{kind: stepNoLeader})
	e.call("POST", "/v1/vaults", create(), 200, nil, withToken(alice.token))
	if p, a := count(); p-p0 != 3 || a-a0 != 1 {
		t.Fatalf("no-leader retry: %d proposals, %d applies", p-p0, a-a0)
	}

	// Unknown outcome (not applied), then success.
	e.node.push(step{kind: stepUnknown})
	e.call("POST", "/v1/vaults", create(), 200, nil, withToken(alice.token))

	// Applied but reported unknown: the re-proposal of the same bytes is
	// de-duplicated, so the vault is created exactly once.
	rev := e.sm.Rev()
	e.node.push(step{kind: stepApplyUnknown})
	req := create()
	var mr api.MutationResponse
	e.call("POST", "/v1/vaults", req, 200, &mr, withToken(alice.token))
	if e.sm.Rev() != rev+1 || mr.Rev != rev+1 {
		t.Fatalf("apply-then-unknown: rev %d -> %d, response %+v", rev, e.sm.Rev(), mr)
	}

	// Permanently no leader: nothing changed, 503 unavailable.
	e.node.setFallback(step{kind: stepNoLeader})
	rev = e.sm.Rev()
	r := e.do("POST", "/v1/vaults", create(), withToken(alice.token))
	if r.status != 503 || r.errBody(t).Code != api.CodeUnavailable || r.header.Get("Retry-After") == "" || e.sm.Rev() != rev {
		t.Fatalf("permanent no leader: %d %s", r.status, r.body)
	}
	// Permanently unknown: outcome_unknown.
	e.node.setFallback(step{kind: stepUnknown})
	e.callErr("POST", "/v1/vaults", create(), 503, api.CodeOutcomeUnknown, withToken(alice.token))
	// Mixed: one attempt reached a leader, so the outcome is unknown.
	e.node.push(step{kind: stepUnknown})
	e.node.setFallback(step{kind: stepNoLeader})
	e.callErr("POST", "/v1/vaults", create(), 503, api.CodeOutcomeUnknown, withToken(alice.token))
	// A slow proposal that outlives the timeout.
	e.node.setFallback(step{kind: stepOK, delay: time.Second})
	e.callErr("POST", "/v1/vaults", create(), 503, api.CodeOutcomeUnknown, withToken(alice.token))
	// Stopped node, nothing in flight: certainly not applied.
	e.node.setFallback(step{kind: stepStopped})
	e.callErr("POST", "/v1/vaults", create(), 503, api.CodeUnavailable, withToken(alice.token))

	// The client-side story: the write applied but the client saw
	// outcome_unknown; a retry with the same key gets the original result.
	e.node.setFallback(step{kind: stepApplyUnknown})
	key := randID()
	req = create()
	rev = e.sm.Rev()
	e.callErr("POST", "/v1/vaults", req, 503, api.CodeOutcomeUnknown, withToken(alice.token), withKey(key))
	if e.sm.Rev() != rev+1 {
		t.Fatal("expected the write to have been applied once")
	}
	e.node.setFallback(step{kind: stepOK})
	e.call("POST", "/v1/vaults", req, 200, &mr, withToken(alice.token), withKey(key))
	if mr.Rev != rev+1 || e.sm.Rev() != rev+1 {
		t.Fatalf("client retry: %+v (state rev %d)", mr, e.sm.Rev())
	}
}

func TestAccountRetriesAfterUnknownOutcome(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ProposeTimeout = 200 * time.Millisecond })
	_, bob := e.household()

	// Password change applied, but the client only saw outcome_unknown. Its
	// old token is now revoked; the retry must still return the result.
	e.node.setFallback(step{kind: stepApplyUnknown})
	key := randID()
	newKey := randBytes(32)
	req := api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: newKey, NewWrappedAccountKey: box(73)}
	e.callErr("POST", "/v1/account/password", req, 503, api.CodeOutcomeUnknown, withToken(bob.token), withKey(key))
	e.node.setFallback(step{kind: stepOK})
	var lr api.LoginResponse
	e.call("POST", "/v1/account/password", req, 200, &lr, withToken(bob.token), withKey(key))
	e.call("GET", "/v1/sync", nil, 200, nil, withToken(lr.Token))
	// The replayed result is only handed to someone who knows the new key.
	bad := req
	bad.NewLoginKey = randBytes(32)
	e.callErr("POST", "/v1/account/password", bad, 401, api.CodeUnauthorized, withToken(bob.token), withKey(key))

	// Same for revoke-sessions.
	tok := lr.Token
	e.node.setFallback(step{kind: stepApplyUnknown})
	key = randID()
	e.callErr("POST", "/v1/account/revoke-sessions", nil, 503, api.CodeOutcomeUnknown, withToken(tok), withKey(key))
	e.node.setFallback(step{kind: stepOK})
	e.call("POST", "/v1/account/revoke-sessions", nil, 200, &lr, withToken(tok), withKey(key))
	e.call("GET", "/v1/sync", nil, 200, nil, withToken(lr.Token))
	e.callErr("GET", "/v1/sync", nil, 401, api.CodeUnauthorized, withToken(tok))
	// Without the key, the stale token gets nothing.
	e.callErr("POST", "/v1/account/revoke-sessions", nil, 401, api.CodeUnauthorized, withToken(tok))
}

func TestStartInitializesClusterKey(t *testing.T) {
	e := newEnv(t)
	other, err := New(Config{NodeID: "n2", Raft: e.node, FSM: e.sm, Peers: testPeers})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	e.node.push(step{kind: stepNoLeader}, step{kind: stepNoLeader}, step{kind: stepUnknown})
	e.callErr("POST", "/v1/prelogin", api.PreloginRequest{Username: "x"}, 503, api.CodeUnavailable)
	e.srv.Start()
	other.Start() // racing initializers are harmless
	deadline := time.Now().Add(10 * time.Second)
	for !e.sm.Initialized() {
		if time.Now().After(deadline) {
			t.Fatal("cluster key was never initialized")
		}
		time.Sleep(10 * time.Millisecond)
	}
	key := e.sm.ClusterKey()
	time.Sleep(50 * time.Millisecond)
	if !bytes.Equal(key, e.sm.ClusterKey()) {
		t.Fatal("cluster key changed after initialization")
	}
	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	e.call("POST", "/v1/prelogin", api.PreloginRequest{Username: "x"}, 200, nil)
}

func TestLaggingNodeAnswersUnavailable(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	lagging := newEnv(t) // never initialized
	r := lagging.do("GET", "/v1/sync?consistency=stale", nil, withToken(alice.token))
	if r.status != 503 || r.errBody(t).Code != api.CodeUnavailable {
		t.Fatalf("lagging node: %d %s", r.status, r.body)
	}
	lagging.callErr("POST", "/v1/login", api.LoginRequest{Username: "alice", LoginKey: alice.loginKey}, 503, api.CodeUnavailable)
	// A node that has the key but not yet the user lets the state machine
	// decide instead of rejecting a write early.
	if e.srv.revokedLocally(principal{uid: randID(), ep: 1}) {
		t.Fatal("unknown user treated as revoked")
	}
}

func TestAdminClusterPeers(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	e.node.mu.Lock()
	e.node.status.Peers = map[string]raft.PeerStatus{
		"n3": {MatchIndex: 7},
		"n2": {MatchIndex: 9, LastContact: time.Now().Add(-1500 * time.Millisecond)},
	}
	e.node.status.LastLogIndex, e.node.status.SnapshotIndex = 12, 4
	e.node.mu.Unlock()
	var ac api.AdminClusterResponse
	e.call("GET", "/v1/admin/cluster", nil, 200, &ac, withToken(alice.token))
	if len(ac.Peers) != 2 || ac.Peers[0].ID != "n2" || ac.Peers[1].ID != "n3" || ac.Peers[1].LastContactMs != -1 ||
		ac.Peers[0].LastContactMs < 1400 || ac.Peers[0].MatchIndex != 9 || ac.LastLogIndex != 12 || ac.SnapshotIndex != 4 {
		t.Fatalf("admin cluster: %+v", ac)
	}
}
