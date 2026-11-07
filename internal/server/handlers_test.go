package server

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
)

func TestRegisterErrors(t *testing.T) {
	e := newEnv(t)
	// Before the cluster key exists nothing can be registered.
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(testBootstrapToken), 503, api.CodeUnavailable)
	e.initCluster()

	bad := func(mut func(r *api.RegisterRequest), status int, code string) {
		t.Helper()
		e.clock.Advance(rateWindow / registerPerIP) // one registration token refills
		req := newAccount("alice").registerReq(testBootstrapToken)
		mut(&req)
		e.callErr("POST", "/v1/register", req, status, code)
	}
	bad(func(r *api.RegisterRequest) { r.LoginKey = r.LoginKey[:16] }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.UserID = "x" }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.Username = "a b" }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.KDF.MemoryKiB = 1024 }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.KDF.MemoryKiB = 19456 }, 400, api.CodeBadRequest) // the old minimum
	bad(func(r *api.RegisterRequest) { r.KDF.MemoryKiB = 262145 }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.PublicKey = nil }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.PersonalVault.EncMeta = box(5000) }, 413, api.CodeTooLarge)
	bad(func(r *api.RegisterRequest) { r.PersonalVault.WrappedKey.SenderID = randID() }, 400, api.CodeBadRequest)
	bad(func(r *api.RegisterRequest) { r.InviteCode = "AAAA-AAAA" }, 403, api.CodeInvalidInvite)
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(testBootstrapToken), 400, api.CodeBadRequest, withKey("zz"))

	e.clock.Advance(rateWindow) // every attempt above counted against the per-IP limit

	// No quorum: refused before anything is computed or proposed.
	e.node.setBarrierErr(errors.New("partitioned"))
	p0, _, _ := e.node.counts()
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(testBootstrapToken), 503, api.CodeUnavailable)
	if p, _, _ := e.node.counts(); p != p0 {
		t.Fatal("registration proposed without a confirmed state")
	}
	e.node.setBarrierErr(nil)

	// Usernames are canonicalized.
	alice := newAccount("alice")
	req := alice.registerReq(testBootstrapToken)
	req.Username = "  ALICE "
	var lr api.LoginResponse
	e.call("POST", "/v1/register", req, 200, &lr)
	if lr.Username != "alice" {
		t.Fatalf("username %q", lr.Username)
	}
	alice.token = lr.Token

	// A doomed registration is rejected by the dry run without consuming
	// the invite.
	inv := e.invite(alice)
	p0, _, _ = e.node.counts()
	e.callErr("POST", "/v1/register", newAccount("alice").registerReq(inv.Code), 409, api.CodeAlreadyExists, withKey(randID()))
	if p, _, _ := e.node.counts(); p != p0 {
		t.Fatal("doomed registration was proposed")
	}
	e.register(newAccount("bob"), inv.Code, withKey(randID()))

	// Propose failures surface as 503s.
	inv = e.invite(alice)
	e.node.setFallback(step{kind: stepNoLeader})
	e.callErr("POST", "/v1/register", newAccount("carol").registerReq(inv.Code), 503, api.CodeUnavailable)
	e.node.setFallback(step{kind: stepOK})
	// The same invite still works afterwards.
	e.register(newAccount("carol"), inv.Code)
}

func TestRegisterRetryOfRecordedFailure(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	inv := e.invite(alice)
	req := newAccount("carol").registerReq(inv.Code)
	key := randID()
	// The invite is revoked after the dry run but before the command is
	// applied, so the state machine records an invalid_invite result.
	e.node.setOnPropose(func() {
		cmd, _ := fsm.EncodeCommand(randID(), e.clock.Now().UnixMilli(), alice.id, 1, &fsm.RevokeInviteArgs{InviteID: inv.InviteID})
		e.node.apply(cmd)
	})
	first := e.call("POST", "/v1/register", req, 403, nil, withKey(key))
	p0, _, _ := e.node.counts()
	again := e.call("POST", "/v1/register", req, 403, nil, withKey(key))
	if string(first.body) != string(again.body) {
		t.Fatalf("retry answered differently: %s vs %s", first.body, again.body)
	}
	if p, _, _ := e.node.counts(); p != p0 {
		t.Fatal("retry of a recorded failure was proposed again")
	}
}

func TestChangePasswordErrors(t *testing.T) {
	e := newEnv(t)
	_, bob := e.household()
	ok := func() api.ChangePasswordRequest {
		return api.ChangePasswordRequest{CurrentLoginKey: bob.loginKey, NewKDF: clientKDF(), NewLoginKey: randBytes(32), NewWrappedAccountKey: box(73)}
	}
	auth := withToken(bob.token)
	r := ok()
	r.NewLoginKey = r.NewLoginKey[:31]
	e.callErr("POST", "/v1/account/password", r, 400, api.CodeBadRequest, auth)
	r = ok()
	r.NewKDF.Time = 9
	e.callErr("POST", "/v1/account/password", r, 400, api.CodeBadRequest, auth)
	r = ok()
	r.NewKDF.Alg = "pbkdf2"
	e.callErr("POST", "/v1/account/password", r, 400, api.CodeBadRequest, auth)
	r = ok()
	r.NewWrappedAccountKey = box(10)
	e.callErr("POST", "/v1/account/password", r, 400, api.CodeBadRequest, auth)
	e.callErr("POST", "/v1/account/password", ok(), 401, api.CodeUnauthorized)

	e.node.setBarrierErr(errors.New("partitioned"))
	e.callErr("POST", "/v1/account/password", ok(), 503, api.CodeUnavailable, auth)
	e.node.setBarrierErr(nil)

	// The epoch CAS: a session revocation that lands between the handler's
	// password check and the apply makes the state machine refuse the change.
	e.node.setOnPropose(func() {
		cmd, _ := fsm.EncodeCommand(randID(), e.clock.Now().UnixMilli(), bob.id, 1, &fsm.RevokeSessionsArgs{})
		e.node.apply(cmd)
	})
	e.callErr("POST", "/v1/account/password", ok(), 401, api.CodeUnauthorized, auth)
	u, _ := e.sm.LookupUserByID(bob.id)
	if u.TokenEpoch != 2 || bytes.Equal(u.KDF.Salt, bob.kdf.Salt) == false {
		t.Fatalf("password must be unchanged after the refused CAS: %+v", u)
	}
	// Plain old-token path (rejected before proposing).
	e.callErr("POST", "/v1/account/password", ok(), 401, api.CodeUnauthorized, auth)
	e.login(bob)
	e.call("POST", "/v1/account/password", ok(), 200, nil, withToken(bob.token))
}

func TestCreateInviteErrorsAndDefaults(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.household()
	auth := withToken(alice.token)
	e.callErr("POST", "/v1/invites", api.CreateInviteRequest{TTLHours: -1}, 400, api.CodeBadRequest, auth)
	var ir api.CreateInviteResponse
	e.call("POST", "/v1/invites", api.CreateInviteRequest{TTLHours: 720}, 200, &ir, auth)
	if ir.ExpiresAt != e.clock.Now().Add(720*time.Hour).UnixMilli() || len(ir.InviteID) != 16 {
		t.Fatalf("invite: %+v", ir)
	}
	canon, _ := canonicalInviteCode(ir.Code)
	if inviteHashOf(canon)[:16] != ir.InviteID {
		t.Fatal("invite_id is not the hash prefix of the canonical code")
	}
	// Different Idempotency-Keys yield different codes.
	var a, b api.CreateInviteResponse
	e.call("POST", "/v1/invites", api.CreateInviteRequest{}, 200, &a, auth, withKey(randID()))
	e.call("POST", "/v1/invites", api.CreateInviteRequest{}, 200, &b, auth, withKey(randID()))
	if a.Code == b.Code {
		t.Fatal("distinct keys produced the same code")
	}
	// Pending-invite limit.
	for i := 0; i < 61; i++ {
		e.invite(alice)
	}
	e.callErr("POST", "/v1/invites", api.CreateInviteRequest{}, 422, api.CodeLimitExceeded, auth)
}

func TestMiscValidation(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.household()
	auth := withToken(alice.token)
	vid := randID()
	e.call("POST", "/v1/vaults", api.CreateVaultRequest{VaultID: vid, EncMeta: box(64), EncRoster: box(64), WrappedKey: wrapped(alice.id)}, 200, nil, auth)
	e.callErr("PUT", "/v1/vaults/"+vid+"/members/xyz", api.PutMemberRequest{Role: "viewer", EncRoster: box(64)}, 400, api.CodeBadRequest, auth)
	e.callErr("PUT", "/v1/vaults/"+vid+"/members/"+bob.id, api.PutMemberRequest{Role: "root", WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 1, EncRoster: box(64)}, 400, api.CodeBadRequest, auth)
	e.callErr("PUT", "/v1/vaults/"+vid+"/members/"+bob.id, api.PutMemberRequest{Role: "viewer", WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 7, EncRoster: box(64)}, 409, api.CodeKeyEpochMismatch, auth)
	e.callErr("PUT", "/v1/vaults/"+vid+"/members/"+randID(), api.PutMemberRequest{Role: "viewer", WrappedKey: ptr(wrapped(alice.id)), KeyEpoch: 1, EncRoster: box(64)}, 404, api.CodeNotFound, auth)
	e.callErr("DELETE", "/v1/vaults/"+vid+"/members/"+bob.id, nil, 404, api.CodeNotFound, auth)
	e.callErr("DELETE", "/v1/vaults/"+vid+"/members/zz", nil, 400, api.CodeBadRequest, auth)
	e.callErr("PUT", "/v1/admin/users/"+bob.id, api.AdminUpdateUserRequest{}, 400, api.CodeBadRequest, auth)
	e.callErr("PUT", "/v1/admin/users/"+randID(), api.AdminUpdateUserRequest{IsAdmin: ptr(true)}, 404, api.CodeNotFound, auth)
	e.callErr("PUT", "/v1/vaults/"+vid+"/meta", api.UpdateVaultMetaRequest{EncMeta: box(64)}, 409, api.CodeVersionConflict, auth)
	e.callErr("POST", "/v1/account/revoke-sessions", `{}`, 400, api.CodeBadRequest, auth, withHeader("Content-Type", "text/plain"))
	e.callErr("DELETE", "/v1/vaults/"+vid+"/items/"+randID()+"?base_version=-1", nil, 400, api.CodeBadRequest, auth)
	r := e.do("GET", "/v1/sync", nil, auth, withKey(randID())) // ignored on reads
	if r.status != 200 {
		t.Fatalf("sync with an Idempotency-Key: %d", r.status)
	}
	if strings.Contains(string(r.body), `"verifier"`) {
		t.Fatal("sync leaks verifier material")
	}
}
