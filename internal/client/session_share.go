package client

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

func validRole(r string) bool {
	return r == api.RoleOwner || r == api.RoleEditor || r == api.RoleViewer
}

// WriteBlocked returns the reason writes are refused right now (offline, stale,
// or the servers show older data), or nil.
func (s *Session) WriteBlocked() error {
	switch s.mode {
	case ModeOlder:
		return &ReadOnlyError{Reason: ReasonOlder}
	case ModeStale:
		return &ReadOnlyError{Reason: ReasonStale}
	case ModeOffline:
		return &ReadOnlyError{Reason: ReasonOffline}
	}
	return nil
}

// verifiedContact returns the contact for a user if it is usable as a
// recipient: known, not mismatching, verified.
func (s *Session) verifiedContact(id string) (Contact, error) {
	c, ok := s.trust.contact(id)
	if !ok {
		return Contact{}, &UserError{Msg: "that user is not a known contact on this device"}
	}
	if m := s.mismatch[id]; m != nil {
		return Contact{}, m
	}
	if !c.Verified {
		return Contact{}, &UnverifiedContactError{User: UnverifiedUser{UserID: c.UserID, Username: c.Username, Fingerprint: fingerprintOf(c.UserID, c.Username, c.PublicKey)}}
	}
	return c, nil
}

// ownerContext returns the accepted vault, its secrets and an intact roster,
// for operations that only owners may do.
func (s *Session) ownerContext(vaultID string) (*VaultView, vaultSecret, error) {
	v, sec, err := s.mustVault(vaultID)
	if err != nil {
		return nil, sec, err
	}
	if err := requireRole(v, api.RoleOwner); err != nil {
		return nil, sec, err
	}
	if v.Personal {
		return nil, sec, &PermissionError{Msg: "a personal vault cannot be shared"}
	}
	if sec.roster == nil {
		return nil, sec, ErrRosterBroken
	}
	return v, sec, nil
}

// AddMember shares a vault with a user at the given role (owner only). The
// user must be a VERIFIED contact on this device (else *UnverifiedContactError:
// the caller shows the fingerprint, then MarkVerified). The vault key is
// wrapped to the trust store's key for the user, and the new roster is
// uploaded in the same request, compare-and-swap on the roster version (a
// conflict re-syncs and retries). crypto.md §6.5.
func (s *Session) AddMember(ctx context.Context, vaultID, username, role string) error {
	if !validRole(role) {
		return &UserError{Msg: "role must be owner, editor or viewer"}
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	target, err := s.userOrSync(ctx, username)
	if err != nil {
		return err
	}
	if w := s.mismatch[target.UserID]; w != nil {
		return w
	}
	if target.Disabled {
		return &UserError{Msg: "that user is disabled"}
	}
	return s.retryRoster(ctx, func() (bool, error) {
		v, sec, err := s.ownerContext(vaultID)
		if err != nil {
			return false, err
		}
		c, err := s.verifiedContact(target.UserID)
		if err != nil {
			return false, err
		}
		if _, ok := sec.roster.Member(c.UserID); ok {
			return false, s.SetMemberRole(ctx, vaultID, c.UserID, role)
		}
		for _, m := range v.Members {
			if m.UserID == c.UserID && !m.InRoster {
				return false, &RosterMismatchError{Details: []string{c.Username + " is listed by the server but not in the vault's member list"}}
			}
		}
		var pk vaultcrypto.PublicKey
		copy(pk[:], c.PublicKey)
		nr, err := sec.roster.WithMember(vaultcrypto.RosterMember{ID: c.UserID, PublicKey: pk, Role: role})
		if err != nil {
			return false, err
		}
		encRoster, err := vaultcrypto.EncryptRoster(sec.vk, vaultID, sec.epoch, nr)
		if err != nil {
			return false, err
		}
		wk, err := vaultcrypto.WrapVaultKey(sec.vk, vaultcrypto.WrapContext{VaultID: vaultID, KeyEpoch: sec.epoch, SenderID: s.UserID, RecipientID: c.UserID}, &s.secrets.PrivateKey, &pk)
		if err != nil {
			return false, err
		}
		return true, s.write(ctx, func() error {
			return s.d.API.PutMember(ctx, vaultID, c.UserID, &api.PutMemberRequest{Role: role, WrappedKey: &api.WrappedKey{SenderID: s.UserID, Blob: wk},
				KeyEpoch: sec.epoch, EncRoster: encRoster, BaseRosterVersion: v.RosterVersion})
		})
	})
}

// retryRoster runs one attempt at a roster change (build the request from the
// current state, send it) until it is accepted. A conflict with another owner
// (roster version or key epoch moved) re-syncs and tries again, up to 3 times.
// An attempt reports sent=false when it finished without writing.
func (s *Session) retryRoster(ctx context.Context, attempt func() (sent bool, err error)) error {
	for n := 0; ; n++ {
		sent, err := attempt()
		if (IsCode(err, api.CodeVersionConflict) || IsCode(err, api.CodeKeyEpochMismatch)) && n < 3 {
			if serr := s.Sync(ctx); serr != nil {
				return err
			}
			continue
		}
		if err == nil && sent {
			s.syncAfterWrite(ctx)
		}
		return err
	}
}

// SetMemberRole changes a roster member's role (owner only), uploading the new
// roster with compare-and-swap; a conflict with another owner re-syncs and retries.
func (s *Session) SetMemberRole(ctx context.Context, vaultID, userID, role string) error {
	if !validRole(role) {
		return &UserError{Msg: "role must be owner, editor or viewer"}
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	return s.retryRoster(ctx, func() (bool, error) {
		v, sec, err := s.ownerContext(vaultID)
		if err != nil {
			return false, err
		}
		if _, ok := sec.roster.Member(userID); !ok {
			return false, &UserError{Msg: "that user is not a member of the vault"}
		}
		nr, err := sec.roster.WithRole(userID, role)
		if err != nil {
			return false, &UserError{Msg: err.Error()}
		}
		encRoster, err := vaultcrypto.EncryptRoster(sec.vk, vaultID, sec.epoch, nr)
		if err != nil {
			return false, err
		}
		return true, s.write(ctx, func() error {
			return s.d.API.PutMember(ctx, vaultID, userID, &api.PutMemberRequest{Role: role, KeyEpoch: sec.epoch, EncRoster: encRoster, BaseRosterVersion: v.RosterVersion})
		})
	})
}

// LeaveVault removes the caller from a vault (DELETE member). The roster
// still lists them until an owner next rekeys.
func (s *Session) LeaveVault(ctx context.Context, vaultID string) error {
	v := s.Vault(vaultID)
	if v == nil {
		return &UserError{Msg: "that vault is not available"}
	}
	err := s.write(ctx, func() error { return s.d.API.DeleteMember(ctx, vaultID, s.UserID) })
	if err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}

// ---------------------------------------------------------------------------
// Rekey (crypto.md §6.6)
// ---------------------------------------------------------------------------

// RekeyOptions control a rekey.
type RekeyOptions struct {
	// Remove lists the members this rekey removes, atomically.
	Remove []string
	// Repair rebuilds an unreadable roster from the server's member list; every
	// listed member must be a verified contact.
	Repair bool
}

// RekeyRecipient is someone who will receive the new vault key.
type RekeyRecipient struct {
	UserID      string
	Username    string
	Role        string
	Fingerprint string
	Verified    bool
	Self        bool
}

// RekeyPlan is what a rekey would do, for the user to confirm.
type RekeyPlan struct {
	VaultID  string
	Name     string
	Epoch    uint32 // the epoch being created
	Repair   bool
	Removed  []RekeyRecipient // members removed by the request
	Left     []RekeyRecipient // roster members who are no longer on the server's list: dropped
	Receives []RekeyRecipient // recipients of the new key (including the caller)
}

// Unverified lists recipients (other than the caller) that are not verified contacts.
func (p *RekeyPlan) Unverified() []UnverifiedUser {
	var out []UnverifiedUser
	for _, r := range p.Receives {
		if !r.Self && !r.Verified {
			out = append(out, UnverifiedUser{UserID: r.UserID, Username: r.Username, Fingerprint: r.Fingerprint})
		}
	}
	return out
}

type rekeyMember struct {
	id   string
	role string
	pk   vaultcrypto.PublicKey
}

func (s *Session) recipientView(id, role string, self bool) RekeyRecipient {
	r := RekeyRecipient{UserID: id, Role: role, Self: self, Username: "(unknown user)"}
	if c, ok := s.trust.contact(id); ok {
		r.Username, r.Verified = c.Username, c.Verified
		r.Fingerprint = fingerprintOf(c.UserID, c.Username, c.PublicKey)
	}
	return r
}

// planRekey computes recipients locally from the authenticated roster (§6.6
// step 1) and checks every precondition except verification of recipients.
func (s *Session) planRekey(vaultID string, o RekeyOptions) (*RekeyPlan, []rekeyMember, []string, *VaultView, vaultSecret, error) {
	v, sec, err := s.mustVault(vaultID)
	if err != nil {
		return nil, nil, nil, nil, sec, err
	}
	if err := requireRole(v, api.RoleOwner); err != nil {
		return nil, nil, nil, nil, sec, err
	}
	srv := map[string]bool{}
	for _, m := range s.rawVault(vaultID).Members {
		srv[m.UserID] = true
	}
	removeSet := map[string]bool{}
	for _, id := range o.Remove {
		if id == s.UserID {
			return nil, nil, nil, nil, sec, &UserError{Msg: "you cannot remove yourself this way (use `fvault vault leave`)"}
		}
		removeSet[id] = true
	}
	plan := &RekeyPlan{VaultID: vaultID, Name: v.Name, Epoch: sec.epoch + 1, Repair: o.Repair}
	var rec []rekeyMember
	var removeOnServer []string

	if v.Personal {
		if len(removeSet) > 0 || len(srv) != 1 || !srv[s.UserID] {
			return nil, nil, nil, nil, sec, &PermissionError{Msg: "a personal vault is never shared, so its key is never replaced for other members"}
		}
		rec = []rekeyMember{{s.UserID, api.RoleOwner, s.secrets.PublicKey}}
		plan.Receives = append(plan.Receives, s.recipientView(s.UserID, api.RoleOwner, true))
		return plan, rec, nil, v, sec, nil
	}

	if sec.roster == nil {
		if !o.Repair {
			return nil, nil, nil, nil, sec, ErrRosterBroken
		}
		// Repair: recipients are the server-listed members, keys from the trust store.
		var ids []string
		roles := map[string]string{}
		for _, m := range s.rawVault(vaultID).Members {
			ids = append(ids, m.UserID)
			roles[m.UserID] = m.Role
		}
		sort.Strings(ids)
		for _, id := range ids {
			if removeSet[id] {
				plan.Removed = append(plan.Removed, s.recipientView(id, roles[id], false))
				removeOnServer = append(removeOnServer, id)
				continue
			}
			c, ok := s.trust.contact(id)
			if !ok {
				return nil, nil, nil, nil, sec, &UserError{Msg: "a member of this vault is not a known contact on this device"}
			}
			var pk vaultcrypto.PublicKey
			copy(pk[:], c.PublicKey)
			if id == s.UserID {
				pk = s.secrets.PublicKey
			}
			rec = append(rec, rekeyMember{id, roles[id], pk})
			plan.Receives = append(plan.Receives, s.recipientView(id, roles[id], id == s.UserID))
		}
	} else {
		// Stop if the server lists a member who is not in the roster.
		var details []string
		for id := range srv {
			if _, ok := sec.roster.Member(id); !ok {
				u := s.recipientView(id, "", false)
				details = append(details, fmt.Sprintf("%s is listed by the server but is not in the vault's member list", u.Username))
			}
		}
		if len(details) > 0 {
			sort.Strings(details)
			return nil, nil, nil, nil, sec, &RosterMismatchError{Details: details}
		}
		for id := range removeSet {
			if _, ok := sec.roster.Member(id); !ok && !srv[id] {
				return nil, nil, nil, nil, sec, &UserError{Msg: "that user is not a member of this vault"}
			}
		}
		for _, m := range sec.roster.Members {
			switch {
			case removeSet[m.ID] && srv[m.ID]:
				plan.Removed = append(plan.Removed, s.recipientView(m.ID, m.Role, false))
				removeOnServer = append(removeOnServer, m.ID)
			case removeSet[m.ID] || !srv[m.ID]:
				// Already gone from the server (left, or removed earlier): dropped from the roster.
				plan.Left = append(plan.Left, s.recipientView(m.ID, m.Role, false))
			default:
				rec = append(rec, rekeyMember{m.ID, m.Role, m.PublicKey})
				plan.Receives = append(plan.Receives, s.recipientView(m.ID, m.Role, m.ID == s.UserID))
			}
		}
	}
	// The caller must remain, as an owner.
	hasOwner := false
	for _, r := range rec {
		if r.id == s.UserID && r.role == api.RoleOwner {
			hasOwner = true
		}
	}
	if !hasOwner {
		return nil, nil, nil, nil, sec, &UserError{Msg: "this would leave the vault without you as an owner"}
	}
	sort.Strings(removeOnServer)
	return plan, rec, removeOnServer, v, sec, nil
}

func (s *Session) rawVault(id string) *api.Vault {
	for i := range s.raw.Vaults {
		if s.raw.Vaults[i].ID == id {
			return &s.raw.Vaults[i]
		}
	}
	return &api.Vault{}
}

// PlanRekey shows who would receive the new key and who would be removed,
// without changing anything.
func (s *Session) PlanRekey(vaultID string, o RekeyOptions) (*RekeyPlan, error) {
	p, _, _, _, _, err := s.planRekey(vaultID, o)
	return p, err
}

// RekeyVault replaces the vault key atomically (crypto.md §6.6): recipients
// are computed locally from the authenticated roster; every recipient other
// than the caller must be a verified contact (else *UnverifiedRecipientsError,
// nothing sent); every box that opens is re-encrypted from its raw plaintext,
// boxes that do not open are carried over unchanged; one request installs the
// new key, roster, metadata and items and removes o.Remove. The new key's
// epoch and commitment are recorded in the trust store before sending.
func (s *Session) RekeyVault(ctx context.Context, vaultID string, o RekeyOptions) error {
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			if err := s.Sync(ctx); err != nil {
				return err
			}
		}
		plan, rec, remove, v, sec, err := s.planRekey(vaultID, o)
		if err != nil {
			return err
		}
		if un := plan.Unverified(); len(un) > 0 {
			return &UnverifiedRecipientsError{Users: un}
		}
		// Every recipient's key is the trust store's; a roster that disagrees was flagged as a mismatch.
		for _, r := range rec {
			if r.id == s.UserID {
				continue
			}
			c, err := s.verifiedContact(r.id)
			if err != nil {
				return err
			}
			if !bytes.Equal(c.PublicKey, r.pk[:]) {
				return &KeyMismatchError{UserID: r.id, Username: c.Username, Kind: MismatchRoster,
					PinnedFingerprint: fingerprintOf(c.UserID, c.Username, c.PublicKey), OfferedFingerprint: fingerprintOf(c.UserID, c.Username, r.pk[:])}
			}
		}
		raw := s.rawVault(vaultID)
		newEpoch := sec.epoch + 1
		newVK := vaultcrypto.NewVaultKey()

		encMeta, opened, err := vaultcrypto.ReencryptMeta(sec.vk, newVK, vaultID, sec.epoch, newEpoch, raw.EncMeta)
		if err != nil {
			newVK.Zero()
			return err
		}
		if !opened {
			encMeta = raw.EncMeta // garbage stays garbage
		}
		items := make([]api.RekeyItem, 0, len(raw.Items))
		for _, it := range raw.Items {
			nb, opened, err := vaultcrypto.ReencryptItem(sec.vk, newVK, vaultID, it.ID, sec.epoch, newEpoch, it.Blob)
			if err != nil {
				newVK.Zero()
				return err
			}
			if !opened {
				nb = it.Blob
			}
			items = append(items, api.RekeyItem{ID: it.ID, Blob: nb})
		}
		roster := &vaultcrypto.Roster{V: 1}
		wrapped := make(map[string]api.WrappedKey, len(rec))
		for _, r := range rec {
			roster.Members = append(roster.Members, vaultcrypto.RosterMember{ID: r.id, PublicKey: r.pk, Role: r.role})
			pk := r.pk
			wk, err := vaultcrypto.WrapVaultKey(newVK, vaultcrypto.WrapContext{VaultID: vaultID, KeyEpoch: newEpoch, SenderID: s.UserID, RecipientID: r.id}, &s.secrets.PrivateKey, &pk)
			if err != nil {
				newVK.Zero()
				return err
			}
			wrapped[r.id] = api.WrappedKey{SenderID: s.UserID, Blob: wk}
		}
		sort.Slice(roster.Members, func(i, j int) bool { return roster.Members[i].ID < roster.Members[j].ID })
		encRoster, err := vaultcrypto.EncryptRoster(newVK, vaultID, newEpoch, roster)
		if err != nil {
			newVK.Zero()
			return err
		}
		// Record the new key before sending; remember the prior state in case the outcome is unknown.
		prior := s.trust.vault(vaultID)
		nt := &VaultTrust{Epoch: newEpoch, Commitment: vaultcrypto.VaultKeyCommitment(newVK, vaultID, newEpoch), Prior: prior}
		if nt.Prior != nil {
			nt.Prior.Prior = nil
		}
		for _, ow := range roster.Owners() {
			nt.Owners = append(nt.Owners, OwnerKey{ID: ow.ID, PublicKey: ow.PublicKey.Bytes()})
		}
		s.trust.setVault(vaultID, nt)
		if err := s.trust.Save(); err != nil {
			newVK.Zero()
			return err
		}
		newVK.Zero()
		err = s.write(ctx, func() error {
			return s.d.API.Rekey(ctx, vaultID, &api.RekeyRequest{BaseRev: v.Rev, NewKeyEpoch: newEpoch, Remove: remove,
				EncMeta: encMeta, EncRoster: encRoster, WrappedKeys: wrapped, Items: items})
		})
		if err == nil {
			s.syncAfterWrite(ctx)
			if cur := s.trust.vault(vaultID); cur != nil && cur.Prior != nil && cur.Epoch == newEpoch {
				cur.Prior = nil
				s.trust.setVault(vaultID, cur)
				_ = s.trust.Save()
			}
			return nil
		}
		if !OutcomeUnknown(err) {
			s.trust.setVault(vaultID, prior)
			_ = s.trust.Save()
		}
		if (IsCode(err, api.CodeVersionConflict) || IsCode(err, api.CodeKeyEpochMismatch)) && attempt < 3 {
			continue
		}
		return err
	}
	return ErrStaleState
}
