package client

import (
	"context"
	"errors"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/backup"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// ExportStats describes an export.
type ExportStats struct {
	Vaults, Items int
	// Skipped counts vaults and entries that could not be decrypted and are
	// therefore NOT in the export.
	Skipped int
}

// ExportBackup builds the encrypted export file of everything this session can
// decrypt. It works offline too: it needs only what is already decrypted. The
// passphrase may be the master password or (better) a separate one.
func (s *Session) ExportBackup(passphrase string) ([]byte, ExportStats, error) {
	var st ExportStats
	if s.locked {
		return nil, st, ErrLocked
	}
	p := &backup.Payload{V: backup.PayloadVersion, ExportedAt: s.d.now().UnixMilli(), ExportedBy: s.Username}
	for _, v := range s.vaults {
		if v.Locked != NotLocked || v.MetaErr {
			st.Skipped++
			continue
		}
		bv := backup.Vault{ID: v.ID, Name: v.Name, Personal: v.Personal}
		for _, it := range v.Items {
			if it.Item == nil {
				st.Skipped++
				continue
			}
			bv.Items = append(bv.Items, backup.Entry{ID: it.ID, Item: it.Item})
			st.Items++
		}
		p.Vaults = append(p.Vaults, bv)
		st.Vaults++
	}
	data, err := backup.Encode(p, passphrase, s.d.kdf())
	return data, st, err
}

// InspectBackup decrypts a backup file (errors are those of package backup).
func InspectBackup(data []byte, passphrase string) (*backup.Payload, error) {
	return backup.Decode(data, passphrase)
}

// ImportStats describes an import.
type ImportStats struct {
	Vaults, Items, Failed int
}

// ImportBackup restores every vault of a backup into NEW vaults with new IDs
// (the AAD binds IDs, and the originals may still exist): nothing existing is
// overwritten. Names get a " (restored)" suffix, as in the web client.
func (s *Session) ImportBackup(ctx context.Context, p *backup.Payload, progress func(done, total int)) (ImportStats, error) {
	var st ImportStats
	total := 0
	for _, v := range p.Vaults {
		total += len(v.Items) + 1
	}
	done := 0
	for _, bv := range p.Vaults {
		id, err := s.CreateVault(ctx, bv.Name+" (restored)")
		if err != nil {
			return st, err
		}
		st.Vaults++
		done++
		if progress != nil {
			progress(done, total)
		}
		for _, e := range bv.Items {
			if e.Item == nil {
				st.Failed++
				continue
			}
			v, sec, err := s.mustVault(id)
			if err != nil {
				return st, err
			}
			itemID := vaultcrypto.NewID()
			blob, err := s.encodeItem(sec, id, itemID, e.Item)
			if err == nil {
				err = s.write(ctx, func() error {
					return s.d.API.PutItem(ctx, id, itemID, &api.PutItemRequest{Blob: blob, BaseVersion: 0, KeyEpoch: v.KeyEpoch})
				})
			}
			switch {
			case err == nil:
				st.Items++
			case IsUnavailable(err) || errors.Is(err, ErrLocked):
				return st, err
			default:
				st.Failed++
			}
			done++
			if progress != nil {
				progress(done, total)
			}
		}
	}
	_ = s.Sync(ctx)
	return st, nil
}
