package client

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// ChangePassword changes the master password. accountKey and the key pair do
// not change, so nothing else is re-encrypted; the server revokes every older
// token and returns a fresh one. Before the new key is discarded the client
// syncs and verifies that the account block now opens with it, and only then
// replaces the cached account block, so the old password no longer unlocks
// this device offline (crypto.md §4). The new password must satisfy the
// policy floor.
func (s *Session) ChangePassword(ctx context.Context, current, next string) error {
	if s.locked {
		return ErrLocked
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	if err := vaultcrypto.CheckMasterPassword(next, s.Username); err != nil {
		return err
	}
	acct := s.raw.Account
	cur, err := vaultcrypto.DeriveMasterKeys(s.Username, current, acct.KDF)
	if err != nil {
		return err
	}
	ok := subtle.ConstantTimeCompare(cur.LoginKey[:], s.loginKey[:]) == 1
	cur.EncKey.Zero()
	cur.LoginKey.Zero()
	if !ok {
		return ErrWrongPassword
	}
	kdf := s.d.kdf()
	nk, err := vaultcrypto.DeriveMasterKeys(s.Username, next, kdf)
	if err != nil {
		return err
	}
	defer nk.EncKey.Zero()
	wrapped, err := vaultcrypto.RewrapAccountKey(s.UserID, &s.secrets.AccountKey, nk)
	if err != nil {
		return err
	}
	// One key for the whole logical call: automatic retries and ours dedupe.
	ctx = WithIdempotencyKey(ctx, NewIdempotencyKey())
	oldKey := s.loginKey
	lr, err := result(s.write, ctx, func() (*api.LoginResponse, error) {
		return s.d.API.ChangePassword(ctx, &api.ChangePasswordRequest{
			CurrentLoginKey: oldKey[:], NewKDF: kdf, NewLoginKey: nk.LoginKey[:], NewWrappedAccountKey: wrapped,
		})
	})
	if err != nil {
		return err
	}
	s.loginKey.Zero()
	s.loginKey = nk.LoginKey
	s.saveToken(lr)
	// Verify that what the server now stores opens with the new key before
	// anything is cached or the key is discarded.
	resp, err := result(s.call, ctx, func() (*api.SyncResponse, error) { return s.d.API.Sync(ctx, 0) })
	if err != nil {
		return fmt.Errorf("the password was changed, but the new account block could not be verified: %w", err)
	}
	if resp.Account == nil {
		return &ProtocolError{Msg: "no account block after the password change"}
	}
	chk, err := vaultcrypto.UnlockAccount(resp.Account.UserID, nk, resp.Account.PublicKey, resp.Account.WrappedAccountKey, resp.Account.EncPrivateKey)
	if err != nil {
		return fmt.Errorf("the password change was not applied as expected: the stored account block does not open with the new password (%w); keep using the old password and report this", err)
	}
	chk.Zero()
	s.raw = nil
	if err := s.applySync(resp, true); err != nil {
		return fmt.Errorf("the password was changed, but refreshing the offline copy failed: %w", err)
	}
	return nil
}

// RevokeSessions revokes every session of this account (including other
// devices); this session continues with a fresh token.
func (s *Session) RevokeSessions(ctx context.Context) error {
	lr, err := result(s.write, ctx, func() (*api.LoginResponse, error) { return s.d.API.RevokeSessions(ctx) })
	if err != nil {
		return err
	}
	s.saveToken(lr)
	return nil
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

func (s *Session) requireAdmin() error {
	if !s.isAdmin {
		return &PermissionError{Msg: "only an administrator can do that"}
	}
	return nil
}

// CreateInvite creates an invite code (shown once). ttlHours 0 = server default.
func (s *Session) CreateInvite(ctx context.Context, ttlHours int) (*api.CreateInviteResponse, error) {
	if err := s.requireAdmin(); err != nil {
		return nil, err
	}
	return result(s.write, ctx, func() (*api.CreateInviteResponse, error) { return s.d.API.CreateInvite(ctx, ttlHours) })
}

// ListInvites lists non-revoked invites.
func (s *Session) ListInvites(ctx context.Context) ([]api.Invite, error) {
	if err := s.requireAdmin(); err != nil {
		return nil, err
	}
	r, err := result(s.call, ctx, func() (*api.ListInvitesResponse, error) { return s.d.API.ListInvites(ctx) })
	if err != nil {
		return nil, err
	}
	return r.Invites, nil
}

// RevokeInvite revokes an unused invite by ID.
func (s *Session) RevokeInvite(ctx context.Context, id string) error {
	if err := s.requireAdmin(); err != nil {
		return err
	}
	return s.write(ctx, func() error { return s.d.API.DeleteInvite(ctx, id) })
}

// SetUserDisabled disables or enables a user (admin only).
func (s *Session) SetUserDisabled(ctx context.Context, username string, disabled bool) error {
	return s.adminUpdate(ctx, username, &api.AdminUpdateUserRequest{Disabled: &disabled})
}

// SetUserAdmin grants or revokes the admin flag (admin only).
func (s *Session) SetUserAdmin(ctx context.Context, username string, isAdmin bool) error {
	return s.adminUpdate(ctx, username, &api.AdminUpdateUserRequest{IsAdmin: &isAdmin})
}

func (s *Session) adminUpdate(ctx context.Context, username string, req *api.AdminUpdateUserRequest) error {
	if err := s.requireAdmin(); err != nil {
		return err
	}
	u, err := s.userOrSync(ctx, username)
	if err != nil {
		return err
	}
	if err := s.write(ctx, func() error { return s.d.API.AdminUpdateUser(ctx, u.UserID, req) }); err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}

// AdminCluster returns the raft view of the node serving the call (admin only).
func (s *Session) AdminCluster(ctx context.Context) (*api.AdminClusterResponse, error) {
	if err := s.requireAdmin(); err != nil {
		return nil, err
	}
	return result(s.call, ctx, func() (*api.AdminClusterResponse, error) { return s.d.API.AdminCluster(ctx) })
}

// ServerBackup downloads the server-state dump (ciphertext and password
// verifiers only; admin only).
func (s *Session) ServerBackup(ctx context.Context) (*api.ServerBackup, error) {
	if err := s.requireAdmin(); err != nil {
		return nil, err
	}
	return result(s.call, ctx, func() (*api.ServerBackup, error) { return s.d.API.AdminBackup(ctx) })
}
