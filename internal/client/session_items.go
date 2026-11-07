package client

import (
	"context"
	"errors"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

func (s *Session) encodeItem(sec vaultSecret, vaultID, itemID string, it *vaultcrypto.Item) ([]byte, error) {
	blob, err := vaultcrypto.EncryptItem(sec.vk, vaultID, itemID, sec.epoch, it)
	if err != nil {
		return nil, err
	}
	if len(blob) > MaxItemBlob {
		return nil, &UserError{Msg: "this entry is too large (64 KiB limit)"}
	}
	return blob, nil
}

// CreateItem adds a new item to a vault and returns its ID.
func (s *Session) CreateItem(ctx context.Context, vaultID string, it *vaultcrypto.Item) (string, error) {
	itemID := vaultcrypto.NewID()
	now := s.d.now().UnixMilli()
	it = it.Clone()
	if it.V == 0 {
		it.V = 1
	}
	if it.CreatedAt == 0 {
		it.CreatedAt = now
	}
	it.UpdatedAt = now
	if err := s.putItem(ctx, vaultID, itemID, it, 0, "create"); err != nil {
		return "", err
	}
	return itemID, nil
}

// UpdateItem applies edit to the current decrypted item (history and
// updated_at are maintained and unknown fields kept by vaultcrypto.EditItem)
// and saves it with optimistic concurrency. If the item changed on the server
// meanwhile it returns a *ConflictError and overwrites nothing. An unreadable
// item cannot be edited (it can be deleted).
func (s *Session) UpdateItem(ctx context.Context, vaultID, itemID string, edit func(*vaultcrypto.Item)) error {
	v, _, err := s.mustVault(vaultID)
	if err != nil {
		return err
	}
	var cur *ItemView
	for i := range v.Items {
		if v.Items[i].ID == itemID {
			cur = &v.Items[i]
		}
	}
	if cur == nil || cur.Item == nil {
		return &UserError{Msg: "that entry is not available or is unreadable (you can delete it)"}
	}
	curCopy := *cur
	next := vaultcrypto.EditItem(cur.Item, s.d.now().UnixMilli(), edit)
	err = s.putItem(ctx, vaultID, itemID, next, curCopy.Version, "update")
	var ce *ConflictError
	if errors.As(err, &ce) && ce.Kind == "update" && ce.Theirs != nil && ce.Theirs.Item != nil && sameItem(ce.Theirs.Item, curCopy.Item) {
		// A rekey (or a no-op write) bumps the version without changing the
		// content. If the server's copy is identical to what we started from,
		// nothing can be lost by rebasing; any real difference stays a conflict.
		return s.putItem(ctx, vaultID, itemID, next, ce.Theirs.Version, "update")
	}
	return err
}

func sameItem(a, b *vaultcrypto.Item) bool {
	ja, err1 := a.Encode()
	jb, err2 := b.Encode()
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}

// DeleteItem deletes an item (conflict-checked against the version we saw).
// It works on unreadable items too: any member with write access may delete them.
func (s *Session) DeleteItem(ctx context.Context, vaultID, itemID string) error {
	v, _, err := s.mustVault(vaultID)
	if err != nil {
		return err
	}
	if err := requireRole(v, api.RoleOwner, api.RoleEditor); err != nil {
		return err
	}
	var cur *ItemView
	for i := range v.Items {
		if v.Items[i].ID == itemID {
			c := v.Items[i]
			cur = &c
		}
	}
	if cur == nil {
		return &UserError{Msg: "that entry is not available"}
	}
	err = s.guardedItemWrite(ctx, vaultID, itemID, "delete", nil, func() error {
		return s.write(ctx, func() error { return s.d.API.DeleteItem(ctx, vaultID, itemID, cur.Version) })
	})
	if err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}

func (s *Session) putItem(ctx context.Context, vaultID, itemID string, it *vaultcrypto.Item, base uint64, kind string) error {
	v, _, err := s.mustVault(vaultID)
	if err != nil {
		return err
	}
	if err := requireRole(v, api.RoleOwner, api.RoleEditor); err != nil {
		return err
	}
	err = s.guardedItemWrite(ctx, vaultID, itemID, kind, it, func() error {
		// Re-read the key and epoch on each attempt: a key_epoch_mismatch retry runs after a sync.
		v2, sec, err := s.mustVault(vaultID)
		if err != nil {
			return err
		}
		blob, err := s.encodeItem(sec, vaultID, itemID, it)
		if err != nil {
			return err
		}
		return s.write(ctx, func() error {
			return s.d.API.PutItem(ctx, vaultID, itemID, &api.PutItemRequest{Blob: blob, BaseVersion: base, KeyEpoch: v2.KeyEpoch})
		})
	})
	if err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}

// guardedItemWrite handles the 409s: key_epoch_mismatch -> sync and retry once;
// version_conflict -> sync and surface a ConflictError (never overwrite).
func (s *Session) guardedItemWrite(ctx context.Context, vaultID, itemID, kind string, mine *vaultcrypto.Item, run func() error) error {
	for attempt := 0; ; attempt++ {
		err := run()
		if err == nil {
			return nil
		}
		if IsCode(err, api.CodeKeyEpochMismatch) && attempt == 0 {
			if serr := s.Sync(ctx); serr != nil {
				return err
			}
			continue
		}
		var ae *APIError
		if errors.As(err, &ae) && ae.Code == api.CodeVersionConflict {
			_ = s.Sync(ctx)
			ce := &ConflictError{VaultID: vaultID, ItemID: itemID, Kind: kind, CurrentVersion: ae.CurrentVersion}
			if mine != nil {
				ce.Mine = &ItemView{ID: itemID, Item: mine}
			}
			if v := s.Vault(vaultID); v != nil {
				for i := range v.Items {
					if v.Items[i].ID == itemID {
						c := v.Items[i]
						ce.Theirs = &c
						ce.CurrentVersion = c.Version
					}
				}
			}
			return ce
		}
		return err
	}
}

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

// CreateVault creates a vault owned by the caller and returns its ID. The key
// is generated here and its epoch and commitment are recorded in the trust
// store BEFORE the request is sent (crypto.md §6.4): a later sync that offers
// a different key for this vault fails the continuity rule.
func (s *Session) CreateVault(ctx context.Context, name string) (string, error) {
	req, vt, err := newVaultRequest(s.secrets, name)
	if err != nil {
		return "", err
	}
	vaultID := req.VaultID
	if err := s.WriteBlocked(); err != nil {
		return "", err
	}
	s.trust.setVault(vaultID, vt)
	if err := s.trust.Save(); err != nil {
		return "", err
	}
	err = s.write(ctx, func() error { return s.d.API.CreateVault(ctx, &req) })
	if err != nil {
		if !OutcomeUnknown(err) {
			s.trust.setVault(vaultID, nil)
			_ = s.trust.Save()
		}
		return "", err
	}
	s.syncAfterWrite(ctx)
	return vaultID, nil
}

// RenameVault renames a vault (owner only). Unknown metadata members are preserved.
func (s *Session) RenameVault(ctx context.Context, vaultID, name string) error {
	v, sec, err := s.mustVault(vaultID)
	if err != nil {
		return err
	}
	if err := requireRole(v, api.RoleOwner); err != nil {
		return err
	}
	m := &vaultcrypto.VaultMeta{V: 1, Name: name}
	if sec.meta != nil {
		c := *sec.meta
		c.Name = name
		m = &c
	}
	meta, err := vaultcrypto.EncryptVaultMeta(sec.vk, vaultID, sec.epoch, m)
	if err != nil {
		return err
	}
	err = s.write(ctx, func() error {
		return s.d.API.UpdateVaultMeta(ctx, vaultID, &api.UpdateVaultMetaRequest{EncMeta: meta, BaseMetaVersion: v.MetaVersion})
	})
	if IsCode(err, api.CodeVersionConflict) || IsCode(err, api.CodeKeyEpochMismatch) {
		_ = s.Sync(ctx)
		return ErrStaleState
	}
	if err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}

// DeleteVault deletes a vault and everything in it (owner only; not personal vaults).
func (s *Session) DeleteVault(ctx context.Context, vaultID string) error {
	v := s.Vault(vaultID)
	if v == nil {
		return &UserError{Msg: "that vault is not available"}
	}
	if err := requireRole(v, api.RoleOwner); err != nil {
		return err
	}
	if v.Personal {
		return &PermissionError{Msg: "a personal vault cannot be deleted"}
	}
	err := s.write(ctx, func() error { return s.d.API.DeleteVault(ctx, vaultID) })
	if err != nil {
		return err
	}
	s.syncAfterWrite(ctx)
	return nil
}
