package server

import (
	"bytes"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
)

// Fake prelogin parameters for unknown usernames (api.md §3.3).
const (
	fakeSaltLabel     = "fpv/v1/fake-salt|"
	defaultKDFTime    = 3
	defaultKDFMemory  = 65536
	defaultKDFThreads = 4
	inviteCodeLabel   = "fpv/v1/invite-code|"
)

// consistency parses ?consistency= and, for stale reads, enforces the
// stale read window.
func (s *Server) consistency(r *http.Request) (stale bool, ae *apiError) {
	switch r.URL.Query().Get("consistency") {
	case "":
		return false, nil
	case "stale":
		if ae := s.staleAllowed(); ae != nil {
			return false, ae
		}
		return true, nil
	}
	return false, errBadRequest(`consistency must be "stale" or absent`)
}

// verifyLimited checks loginKey against v under the per-IP and per-username
// login failure budgets. Every password check outside /v1/login goes
// through here, so no path offers unmetered guesses (or unmetered use of
// the Argon2 slots).
func (s *Server) verifyLimited(r *http.Request, username string, loginKey []byte, v fsm.Verifier) *apiError {
	refund, ae := s.reserveLogin(s.clientIP(r), username)
	if ae != nil {
		return ae
	}
	ok, err := s.checkVerifier(r.Context(), loginKey, v)
	if err != nil {
		refund()
		return busyOrInternal(err)
	}
	if !ok {
		return errUnauthorized("invalid credentials")
	}
	refund()
	return nil
}

// sameUser is a defense-in-depth check before minting a token from an apply
// result: the result must be about the account the request is for. A
// mismatch can only be a bug (or a corrupted log), never a client error.
func (s *Server) sameUser(out *fsm.Outcome, want string) bool {
	if out.UserID == want && fsm.ValidID(want) && fsm.ValidUsername(out.Username) {
		return true
	}
	s.log.Error("SECURITY: refusing to mint a token: apply result is for a different account than the request",
		"result_user", out.UserID, "request_user", want)
	return false
}

func busyOrInternal(err error) *apiError {
	if errors.Is(err, errArgonBusy) {
		return errUnavailable("server is busy; try again shortly")
	}
	return errInternal()
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	st := s.cfg.Raft.Status() // never blocks on consensus
	resp := api.HealthResponse{
		NodeID: s.cfg.NodeID, Role: st.Role.String(), LeaderID: st.LeaderID, Term: st.Term,
		CommitIndex: st.CommitIndex, AppliedIndex: st.LastApplied, Version: s.cfg.Version,
	}
	s.cfg.FSM.View(func(v *fsm.View) {
		resp.Initialized = v.Initialized()
		resp.HasUsers = v.HasUsers()
	})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	nodes := append([]api.ClusterNode{}, s.cfg.Peers...)
	writeJSON(w, http.StatusOK, api.ClusterResponse{Nodes: nodes, LeaderID: s.cfg.Raft.Status().LeaderID})
}

func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	stale, ae := s.consistency(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var req api.PreloginRequest
	if ae := decodeBody(w, r, &req, maxSmallBody); ae != nil {
		s.fail(w, ae)
		return
	}
	name := fsm.CanonicalUsername(req.Username)
	if !fsm.ValidUsername(name) {
		s.fail(w, errBadRequest("invalid username"))
		return
	}
	if !stale {
		if ae := s.barrier(r.Context()); ae != nil {
			s.fail(w, ae)
			return
		}
	}
	var key []byte
	var u fsm.UserAuth
	var found bool
	s.cfg.FSM.View(func(v *fsm.View) {
		key = v.ClusterKey()
		u, found = v.UserByName(name)
	})
	if key == nil {
		s.fail(w, errUnavailable("cluster is not initialized yet"))
		return
	}
	// Computed for every request, so known and unknown usernames cost the same.
	fake := hmacSHA256(key, fakeSaltLabel, name)[:16]
	resp := api.PreloginResponse{KDF: api.KDFParams{
		Alg: "argon2id", Salt: fake, Time: defaultKDFTime, MemoryKiB: defaultKDFMemory, Parallelism: defaultKDFThreads,
	}}
	if found {
		resp.KDF = u.KDF
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	stale, ae := s.consistency(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var req api.LoginRequest
	if ae := decodeBody(w, r, &req, maxSmallBody); ae != nil {
		s.fail(w, ae)
		return
	}
	name := fsm.CanonicalUsername(req.Username)
	if !fsm.ValidUsername(name) {
		s.fail(w, errBadRequest("invalid username"))
		return
	}
	if len(req.LoginKey) != 32 {
		s.fail(w, errBadRequest("login_key must be 32 bytes"))
		return
	}
	refund, ae := s.reserveLogin(s.clientIP(r), name)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if !stale {
		if ae := s.barrier(r.Context()); ae != nil {
			refund() // not an attempt
			s.fail(w, ae)
			return
		}
	}
	var u fsm.UserAuth
	var found, initialized bool
	s.cfg.FSM.View(func(v *fsm.View) {
		initialized = v.Initialized()
		u, found = v.UserByName(name)
	})
	if !initialized {
		refund()
		s.fail(w, errUnavailable("cluster is not initialized yet"))
		return
	}
	// Unknown users are checked against a dummy verifier with the same cost,
	// so response time does not reveal whether a username exists.
	ver := s.dummy
	if found {
		ver = u.Verifier
	}
	match, err := s.checkVerifier(r.Context(), req.LoginKey, ver)
	if err != nil {
		refund()
		s.fail(w, busyOrInternal(err))
		return
	}
	if !found || !match || u.Disabled {
		// Unknown user, wrong key and disabled user are indistinguishable.
		s.fail(w, errUnauthorized("invalid username or password"))
		return
	}
	refund()
	resp, ae := s.issueToken(u.ID, u.Username, u.IsAdmin, u.TokenEpoch, s.now().Unix())
	if ae != nil {
		s.fail(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if ok, wait := s.limRegister.take(s.clientIP(r), s.now()); !ok {
		s.fail(w, errRateLimited(wait.Milliseconds()))
		return
	}
	var req api.RegisterRequest
	if ae := decodeBody(w, r, &req, maxRegisterBody); ae != nil {
		s.fail(w, ae)
		return
	}
	if len(req.LoginKey) != 32 {
		s.fail(w, errBadRequest("login_key must be 32 bytes"))
		return
	}
	reqID, explicit, ae := s.idempotencyKey(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	args := &fsm.RegisterArgs{
		UserID: req.UserID, Username: fsm.CanonicalUsername(req.Username), KDF: req.KDF,
		Verifier: placeholderVerifier(), PublicKey: req.PublicKey, WrappedAccountKey: req.WrappedAccountKey,
		EncPrivateKey: req.EncPrivateKey, PersonalVault: req.PersonalVault,
	}
	if s.isBootstrapToken(req.InviteCode) {
		args.Bootstrap = true
	} else {
		code, ok := canonicalInviteCode(req.InviteCode)
		if !ok {
			s.fail(w, errInvalidInvite())
			return
		}
		args.InviteHash = inviteHashOf(code)
	}
	if e := args.Validate(""); e != nil {
		s.fail(w, fromFSM(e))
		return
	}
	now := s.now().UnixMilli()
	skeleton, err := fsm.EncodeCommand(reqID, now, "", 0, args)
	if err != nil {
		s.fail(w, errInternal())
		return
	}
	// A retry of a registration that already went through is answered with
	// its recorded result.
	if s.barrierOrReplay(w, r, skeleton, explicit, req.LoginKey, req.UserID) {
		return
	}
	// Reject doomed registrations (bad invite, taken name, full household)
	// against the now-current state before paying for Argon2 and a log
	// entry. The state machine re-checks everything at apply time.
	if e := s.cfg.FSM.DryRun(skeleton); e != nil {
		s.fail(w, fromFSM(e))
		return
	}
	v, err := s.newVerifier(r.Context(), req.LoginKey)
	if err != nil {
		s.fail(w, busyOrInternal(err))
		return
	}
	args.Verifier = v
	cmd, err := fsm.EncodeCommand(reqID, now, "", 0, args)
	if err != nil {
		s.fail(w, errInternal())
		return
	}
	res, ae := s.propose(r.Context(), cmd)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	s.finishAccount(w, r, res, req.LoginKey, v.Salt, req.UserID)
}

// barrierOrReplay waits for the read barrier, unless cmd (a registration or
// password change, with its placeholder verifier) is the retry of one that
// was already applied: that is answered with the recorded result, through
// finishAccount. The table is checked before AND after the barrier (a local
// hit is trustworthy even without quorum, a miss only after it). It reports
// whether the request has been answered.
func (s *Server) barrierOrReplay(w http.ResponseWriter, r *http.Request, cmd []byte, explicit bool, loginKey []byte, uid string) bool {
	replayed := func() bool {
		if !explicit {
			return false
		}
		res, ok := s.cfg.FSM.CachedResult(cmd)
		if ok {
			s.finishAccount(w, r, res, loginKey, nil, uid)
		}
		return ok
	}
	if replayed() {
		return true
	}
	if ae := s.barrier(r.Context()); ae != nil {
		s.fail(w, ae)
		return true
	}
	return replayed()
}

// finishAccount turns the result of register/change_password into a
// LoginResponse. If the stored verifier is not the one this request just
// computed (mySalt), the result is a de-duplicated replay of an earlier
// attempt, and the caller must first prove knowledge of the login key that
// attempt registered: an Idempotency-Key alone never yields a session. That
// proof is a password check like any other and runs under the login
// failure limits.
func (s *Server) finishAccount(w http.ResponseWriter, r *http.Request, res []byte, loginKey, mySalt []byte, wantUID string) {
	out, ae := outcomeOf(res)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if !s.sameUser(out, wantUID) || out.Verifier == nil {
		s.fail(w, errInternal())
		return
	}
	if mySalt == nil || !bytes.Equal(out.Verifier.Salt, mySalt) {
		if ae := s.verifyLimited(r, out.Username, loginKey, *out.Verifier); ae != nil {
			s.fail(w, ae)
			return
		}
	}
	resp, ae := s.issueToken(out.UserID, out.Username, out.IsAdmin, out.Epoch, s.now().Unix())
	if ae != nil {
		s.fail(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Sync and account
// ---------------------------------------------------------------------------

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	stale, ae := s.consistency(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var since uint64
	if q := r.URL.Query().Get("since"); q != "" {
		n, err := strconv.ParseUint(q, 10, 64)
		if err != nil {
			s.fail(w, errBadRequest("since must be a non-negative integer"))
			return
		}
		since = n
	}
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if !stale {
		if ae := s.barrier(r.Context()); ae != nil {
			s.fail(w, ae)
			return
		}
	}
	var resp *api.SyncResponse
	// The session check and the data come from the same view, AFTER the
	// barrier, so a revoked token is rejected linearizably.
	s.cfg.FSM.View(func(v *fsm.View) {
		if _, ok := sessionOK(v, p); !ok {
			return
		}
		resp, _ = v.Sync(p.uid, since)
	})
	if resp == nil {
		s.fail(w, errUnauthorized("session is no longer valid"))
		return
	}
	resp.ServedBy = s.cfg.NodeID
	resp.Stale = stale
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var req api.ChangePasswordRequest
	if ae := decodeBody(w, r, &req, maxBody); ae != nil {
		s.fail(w, ae)
		return
	}
	if len(req.CurrentLoginKey) != 32 || len(req.NewLoginKey) != 32 {
		s.fail(w, errBadRequest("login keys must be 32 bytes"))
		return
	}
	reqID, explicit, ae := s.idempotencyKey(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	args := &fsm.ChangePasswordArgs{NewKDF: req.NewKDF, NewWrappedAccountKey: req.NewWrappedAccountKey, Verifier: placeholderVerifier()}
	if e := args.Validate(p.uid); e != nil {
		s.fail(w, fromFSM(e))
		return
	}
	now := s.now().UnixMilli()
	skeleton, err := fsm.EncodeCommand(reqID, now, p.uid, p.ep, args)
	if err != nil {
		s.fail(w, errInternal())
		return
	}
	// A retry after the change went through: the old token is now revoked,
	// but proving the NEW login key earns the new session. Otherwise the
	// current password must be checked against the current verifier, hence
	// the barrier.
	if s.barrierOrReplay(w, r, skeleton, explicit, req.NewLoginKey, p.uid) {
		return
	}
	var u fsm.UserAuth
	var ok bool
	s.cfg.FSM.View(func(v *fsm.View) { u, ok = sessionOK(v, p) })
	if !ok {
		s.fail(w, errUnauthorized("session is no longer valid"))
		return
	}
	// Guessing the current login key here is as good as guessing it at
	// login, so it shares the login failure limits.
	if ae := s.verifyLimited(r, u.Username, req.CurrentLoginKey, u.Verifier); ae != nil {
		s.fail(w, ae)
		return
	}
	v, err := s.newVerifier(r.Context(), req.NewLoginKey)
	if err != nil {
		s.fail(w, busyOrInternal(err))
		return
	}
	args.Verifier = v
	// The envelope's ep (the token's epoch) is the compare-and-swap that
	// makes the password check above authoritative: if anything changed the
	// verifier or revoked the session since, the epoch moved and the state
	// machine refuses the command.
	cmd, err := fsm.EncodeCommand(reqID, now, p.uid, p.ep, args)
	if err != nil {
		s.fail(w, errInternal())
		return
	}
	res, ae := s.propose(r.Context(), cmd)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	s.finishAccount(w, r, res, req.NewLoginKey, v.Salt, p.uid)
}

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if ae := decodeEmpty(w, r); ae != nil {
		s.fail(w, ae)
		return
	}
	out, ae := s.submit(r, &p, &fsm.RevokeSessionsArgs{})
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if !s.sameUser(out, p.uid) {
		s.fail(w, errInternal())
		return
	}
	// The login key is not re-proven here, so the session keeps its
	// original auth time: revoke-sessions cannot extend a session's life.
	resp, ae := s.issueToken(out.UserID, out.Username, out.IsAdmin, out.Epoch, p.at)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Vaults, members, items
// ---------------------------------------------------------------------------

// pathID returns a validated id path value.
func pathID(r *http.Request, name string) (string, *apiError) {
	v := r.PathValue(name)
	if !fsm.ValidID(v) {
		return "", errBadRequest(name + " id must be 32 lowercase hex characters")
	}
	return v, nil
}

// mutation runs the common shape of an authenticated write: authenticate,
// optionally decode a body, build args, submit, reply with MutationResponse.
func (s *Server) mutation(w http.ResponseWriter, r *http.Request, body any, limit int64, build func(p principal) (fsm.Args, *apiError)) {
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if body != nil {
		if ae := decodeBody(w, r, body, limit); ae != nil {
			s.fail(w, ae)
			return
		}
	}
	args, ae := build(p)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	out, ae := s.submit(r, &p, args)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, api.MutationResponse{Rev: out.Rev, Version: out.Version})
}

func (s *Server) handleCreateVault(w http.ResponseWriter, r *http.Request) {
	var req api.CreateVaultRequest
	s.mutation(w, r, &req, maxBody, func(principal) (fsm.Args, *apiError) {
		return &fsm.CreateVaultArgs{VaultID: req.VaultID, EncMeta: req.EncMeta, EncRoster: req.EncRoster, WrappedKey: req.WrappedKey}, nil
	})
}

func (s *Server) handleUpdateVaultMeta(w http.ResponseWriter, r *http.Request) {
	var req api.UpdateVaultMetaRequest
	s.mutation(w, r, &req, maxBody, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		return &fsm.UpdateVaultMetaArgs{VaultID: vid, EncMeta: req.EncMeta, BaseMetaVersion: req.BaseMetaVersion}, nil
	})
}

func (s *Server) handleDeleteVault(w http.ResponseWriter, r *http.Request) {
	s.mutation(w, r, nil, 0, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		return &fsm.DeleteVaultArgs{VaultID: vid}, nil
	})
}

func (s *Server) handlePutMember(w http.ResponseWriter, r *http.Request) {
	var req api.PutMemberRequest
	s.mutation(w, r, &req, maxBody, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		uid, ae := pathID(r, "user")
		if ae != nil {
			return nil, ae
		}
		return &fsm.PutMemberArgs{
			VaultID: vid, UserID: uid, Role: req.Role, WrappedKey: req.WrappedKey, KeyEpoch: req.KeyEpoch,
			EncRoster: req.EncRoster, BaseRosterVersion: req.BaseRosterVersion,
		}, nil
	})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	s.mutation(w, r, nil, 0, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		uid, ae := pathID(r, "user")
		if ae != nil {
			return nil, ae
		}
		return &fsm.RemoveMemberArgs{VaultID: vid, UserID: uid}, nil
	})
}

func (s *Server) handleRekey(w http.ResponseWriter, r *http.Request) {
	var req api.RekeyRequest
	s.mutation(w, r, &req, maxRekeyBody, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		return &fsm.RekeyArgs{
			VaultID: vid, BaseRev: req.BaseRev, NewKeyEpoch: req.NewKeyEpoch, Remove: req.Remove,
			EncMeta: req.EncMeta, EncRoster: req.EncRoster, WrappedKeys: req.WrappedKeys, Items: req.Items,
		}, nil
	})
}

func (s *Server) handlePutItem(w http.ResponseWriter, r *http.Request) {
	var req api.PutItemRequest
	s.mutation(w, r, &req, maxBody, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		iid, ae := pathID(r, "item")
		if ae != nil {
			return nil, ae
		}
		return &fsm.PutItemArgs{VaultID: vid, ItemID: iid, Blob: req.Blob, BaseVersion: req.BaseVersion, KeyEpoch: req.KeyEpoch}, nil
	})
}

func (s *Server) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	s.mutation(w, r, nil, 0, func(principal) (fsm.Args, *apiError) {
		vid, ae := pathID(r, "vault")
		if ae != nil {
			return nil, ae
		}
		iid, ae := pathID(r, "item")
		if ae != nil {
			return nil, ae
		}
		bv, err := strconv.ParseUint(r.URL.Query().Get("base_version"), 10, 64)
		if err != nil || bv == 0 {
			return nil, errBadRequest("base_version query parameter is required")
		}
		return &fsm.DeleteItemArgs{VaultID: vid, ItemID: iid, BaseVersion: bv}, nil
	})
}

// ---------------------------------------------------------------------------
// Invites and administration
// ---------------------------------------------------------------------------

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var req api.CreateInviteRequest
	if ae := decodeBody(w, r, &req, maxBody); ae != nil {
		s.fail(w, ae)
		return
	}
	ttl := req.TTLHours
	if ttl == 0 {
		ttl = fsm.DefaultInviteTTLHours
	}
	if ttl < 1 || ttl > fsm.MaxInviteTTLHours {
		s.fail(w, errBadRequest("ttl_hours must be between 1 and 720"))
		return
	}
	reqID, explicit, ae := s.idempotencyKey(r)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	var raw []byte
	if explicit {
		// The state keeps only the code's hash, so a retry could never show
		// the code again. Deriving it from (cluster key, caller, key) makes a
		// retry with the same Idempotency-Key reproduce the same code, and
		// thus the same hash, which the state machine de-duplicates.
		key := s.cfg.FSM.ClusterKey()
		if key == nil {
			s.fail(w, errUnavailable("cluster is not initialized yet"))
			return
		}
		raw = hmacSHA256(key, inviteCodeLabel, p.uid, "|", reqID)[:inviteCodeBytes]
	} else {
		b, err := s.randomBytes(inviteCodeBytes)
		if err != nil {
			s.fail(w, errInternal())
			return
		}
		raw = b
	}
	code := formatInviteCode(raw)
	canonical, _ := canonicalInviteCode(code)
	hash := inviteHashOf(canonical)
	out, ae := s.submitWithID(r, &p, &fsm.CreateInviteArgs{InviteHash: hash, TTLHours: ttl}, reqID, explicit)
	if ae != nil {
		s.fail(w, ae)
		return
	}
	if out.InviteID != hash[:16] {
		s.fail(w, errInternal())
		return
	}
	writeJSON(w, http.StatusOK, api.CreateInviteResponse{InviteID: out.InviteID, Code: code, ExpiresAt: out.ExpiresAt})
}

// adminView authenticates, waits for the barrier (if linearizable), checks
// session and admin rights in one consistent view, and runs fn in it.
func (s *Server) adminView(w http.ResponseWriter, r *http.Request, linearizable bool, fn func(v *fsm.View)) bool {
	p, ae := s.authenticate(r)
	if ae != nil {
		s.fail(w, ae)
		return false
	}
	if linearizable {
		if ae := s.barrier(r.Context()); ae != nil {
			s.fail(w, ae)
			return false
		}
	}
	s.cfg.FSM.View(func(v *fsm.View) {
		u, ok := sessionOK(v, p)
		switch {
		case !ok:
			ae = errUnauthorized("session is no longer valid")
		case !u.IsAdmin:
			ae = errForbidden("admin only")
		default:
			fn(v)
		}
	})
	if ae != nil {
		s.fail(w, ae)
		return false
	}
	return true
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	var inv []api.Invite
	if s.adminView(w, r, true, func(v *fsm.View) { inv = v.Invites() }) {
		writeJSON(w, http.StatusOK, api.ListInvitesResponse{Invites: inv})
	}
}

func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	s.mutation(w, r, nil, 0, func(principal) (fsm.Args, *apiError) {
		id := r.PathValue("invite_id")
		if !fsm.ValidInviteID(id) {
			return nil, errBadRequest("invite_id must be 16 lowercase hex characters")
		}
		return &fsm.RevokeInviteArgs{InviteID: id}, nil
	})
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req api.AdminUpdateUserRequest
	s.mutation(w, r, &req, maxBody, func(principal) (fsm.Args, *apiError) {
		uid, ae := pathID(r, "user")
		if ae != nil {
			return nil, ae
		}
		return &fsm.AdminUpdateUserArgs{UserID: uid, Disabled: req.Disabled, IsAdmin: req.IsAdmin}, nil
	})
}

// handleAdminCluster reports this node's Raft status. It must work exactly
// when the cluster is unhealthy, so it does not wait for a read barrier;
// admin rights are checked against the local state (the response contains
// only operational metadata).
func (s *Server) handleAdminCluster(w http.ResponseWriter, r *http.Request) {
	var rev uint64
	if !s.adminView(w, r, false, func(v *fsm.View) { rev = v.Rev() }) {
		return
	}
	st := s.cfg.Raft.Status()
	resp := api.AdminClusterResponse{
		NodeID: s.cfg.NodeID, Role: st.Role.String(), LeaderID: st.LeaderID, Term: st.Term,
		CommitIndex: st.CommitIndex, AppliedIndex: st.LastApplied, LastLogIndex: st.LastLogIndex,
		SnapshotIndex: st.SnapshotIndex, Rev: rev,
	}
	for id, ps := range st.Peers {
		ms := int64(-1)
		if !ps.LastContact.IsZero() {
			ms = time.Since(ps.LastContact).Milliseconds()
		}
		resp.Peers = append(resp.Peers, api.AdminPeerStatus{ID: id, MatchIndex: ps.MatchIndex, LastContactMs: ms})
	}
	sort.Slice(resp.Peers, func(i, j int) bool { return resp.Peers[i].ID < resp.Peers[j].ID })
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	if !s.adminView(w, r, true, func(*fsm.View) {}) {
		return
	}
	b, err := s.buildBackup()
	if err != nil {
		s.log.Error("backup failed", "err", err.Error())
		s.fail(w, errInternal())
		return
	}
	writeJSON(w, http.StatusOK, b)
}
