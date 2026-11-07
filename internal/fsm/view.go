package fsm

import (
	"sort"

	"github.com/tarnan3751/password-vault/internal/api"
)

// UserAuth is the authentication-relevant view of a user (a copy).
type UserAuth struct {
	ID         string
	Username   string
	IsAdmin    bool
	Disabled   bool
	TokenEpoch uint64
	KDF        api.KDFParams
	Verifier   Verifier
}

// View is a consistent read-only view of the state, valid only inside the
// callback passed to FSM.View. Every method returns copies.
type View struct{ s *state }

// View runs fn with the read lock held, so that several reads (for example
// a token check and the data it guards) observe the same state. fn must be
// quick, must not call other FSM methods (RWMutex read locks do not nest
// safely while a writer is waiting) and must not retain v.
func (f *FSM) View(fn func(v *View)) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v := &View{s: f.s}
	defer func() { v.s = nil }() // a retained View fails loudly instead of racing
	fn(v)
}

// Initialized reports whether the cluster key exists.
func (v *View) Initialized() bool { return v.s.clusterKey != nil }

// ClusterKey returns a copy of the cluster key, or nil if uninitialized.
func (v *View) ClusterKey() []byte { return cloneBytes(v.s.clusterKey) }

// HasUsers reports whether at least one user is registered.
func (v *View) HasUsers() bool { return len(v.s.users) > 0 }

// Rev returns the global revision.
func (v *View) Rev() uint64 { return v.s.rev }

func authView(u *user) UserAuth {
	return UserAuth{
		ID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin, Disabled: u.Disabled,
		TokenEpoch: u.TokenEpoch, KDF: cloneKDF(u.KDF), Verifier: u.Verifier.clone(),
	}
}

// UserByID looks a user up by id.
func (v *View) UserByID(id string) (UserAuth, bool) {
	u := v.s.users[id]
	if u == nil {
		return UserAuth{}, false
	}
	return authView(u), true
}

// UserByName looks a user up by canonical username.
func (v *View) UserByName(name string) (UserAuth, bool) {
	id, ok := v.s.byName[name]
	if !ok {
		return UserAuth{}, false
	}
	return authView(v.s.users[id]), true
}

// Directory lists every user, sorted by id.
func (v *View) Directory() []api.DirectoryUser {
	out := make([]api.DirectoryUser, 0, len(v.s.users))
	for _, id := range sortedKeys(v.s.users) {
		u := v.s.users[id]
		out = append(out, api.DirectoryUser{
			UserID: u.ID, Username: u.Username, PublicKey: cloneBytes(u.PublicKey),
			IsAdmin: u.IsAdmin, Disabled: u.Disabled,
		})
	}
	return out
}

// Invites lists the invites that have not been revoked, oldest first.
func (v *View) Invites() []api.Invite {
	out := make([]api.Invite, 0, len(v.s.invites))
	for _, inv := range v.s.invites {
		if inv.Revoked {
			continue
		}
		out = append(out, api.Invite{
			InviteID: inv.ID, CreatedBy: inv.CreatedBy, CreatedAt: inv.CreatedAt,
			ExpiresAt: inv.ExpiresAt, UsedBy: inv.UsedBy,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].InviteID < out[j].InviteID
	})
	return out
}

// Sync builds the complete view of the state visible to user uid
// (api.SyncResponse, sorted as documented there). If since equals the
// current rev (and is non-zero) only {rev, unchanged} is returned. ok is
// false if the user does not exist. ServedBy/Stale are left to the caller.
func (v *View) Sync(uid string, since uint64) (resp *api.SyncResponse, ok bool) {
	s := v.s
	u := s.users[uid]
	if u == nil {
		return nil, false
	}
	if since != 0 && since == s.rev {
		return &api.SyncResponse{Rev: s.rev, Unchanged: true}, true
	}
	resp = &api.SyncResponse{
		Rev: s.rev,
		Account: &api.Account{
			UserID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin, KDF: cloneKDF(u.KDF),
			PublicKey: cloneBytes(u.PublicKey), WrappedAccountKey: cloneBytes(u.WrappedAccountKey),
			EncPrivateKey: cloneBytes(u.EncPrivateKey), CreatedAt: u.CreatedAt,
		},
		Directory: v.Directory(),
	}
	for _, id := range sortedKeys(s.vaults) {
		vt := s.vaults[id]
		me := vt.Members[uid]
		if me == nil {
			continue // only vaults the caller belongs to are visible at all
		}
		out := api.Vault{
			ID: vt.ID, Personal: vt.Personal, KeyEpoch: vt.KeyEpoch, EncMeta: cloneBytes(vt.EncMeta),
			MetaVersion: vt.MetaVersion, EncRoster: cloneBytes(vt.EncRoster), RosterVersion: vt.RosterVersion,
			Rev: vt.Rev, RekeyRecommended: vt.RekeyRecommended,
			MyRole: me.Role, MyKey: cloneWrapped(me.WrappedKey),
			Members: make([]api.Member, 0, len(vt.Members)),
			Items:   make([]api.Item, 0, len(vt.Items)),
		}
		// Other members' wrapped keys are not exposed: each member only
		// needs their own.
		for _, mid := range sortedKeys(vt.Members) {
			m := vt.Members[mid]
			out.Members = append(out.Members, api.Member{UserID: mid, Role: m.Role, AddedBy: m.AddedBy})
		}
		for _, iid := range sortedKeys(vt.Items) {
			it := vt.Items[iid]
			out.Items = append(out.Items, api.Item{
				ID: iid, Version: it.Version, Blob: cloneBytes(it.Blob), UpdatedAt: it.UpdatedAt, UpdatedBy: it.UpdatedBy,
			})
		}
		resp.Vaults = append(resp.Vaults, out)
	}
	return resp, true
}

// ---------------------------------------------------------------------------
// Convenience wrappers (each takes the read lock once)
// ---------------------------------------------------------------------------

// Initialized reports whether the cluster key exists.
func (f *FSM) Initialized() (ok bool) {
	f.View(func(v *View) { ok = v.Initialized() })
	return
}

// ClusterKey returns a copy of the cluster key, or nil if uninitialized.
func (f *FSM) ClusterKey() (k []byte) {
	f.View(func(v *View) { k = v.ClusterKey() })
	return
}

// LookupUserByID returns the auth view of a user.
func (f *FSM) LookupUserByID(id string) (u UserAuth, ok bool) {
	f.View(func(v *View) { u, ok = v.UserByID(id) })
	return
}
