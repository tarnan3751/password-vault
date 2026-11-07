// Package backup implements the encrypted export backup file of
// docs/spec/crypto.md §7: a self-contained JSON file, encrypted under a key
// derived from a passphrase with Argon2id, restorable with nothing else.
package backup

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// File format identifiers (crypto.md §7).
const (
	Format         = "fpv-backup"
	FileVersion    = 1
	PayloadVersion = 1
)

// AAD is the associated data of the backup blob (crypto.md §7).
var AAD = []byte("fpv/v1/backup")

// Errors returned by Decode. They distinguish a file that is not a (supported)
// backup from one that cannot be decrypted.
var (
	// ErrNotBackup means the input is not an fpv-backup JSON file.
	ErrNotBackup = errors.New("backup: not a Family Vault backup file")
	// ErrUnsupportedVersion means a recognised backup of an unknown version.
	ErrUnsupportedVersion = errors.New("backup: unsupported backup version")
	// ErrWeakKDF means the file's KDF parameters violate the minimum rule of
	// crypto.md §2 and are refused (the passphrase is never tried).
	ErrWeakKDF = errors.New("backup: key-derivation parameters below the accepted minimum")
	// ErrDecrypt means the passphrase is wrong or the file is corrupted; the
	// two cannot be told apart.
	ErrDecrypt = errors.New("backup: wrong passphrase or corrupted backup")
)

// Payload is the plaintext of a backup (crypto.md §7).
type Payload struct {
	V          int     `json:"v"`
	ExportedAt int64   `json:"exported_at"`
	ExportedBy string  `json:"exported_by"`
	Vaults     []Vault `json:"vaults"`
}

// Vault is one exported vault.
type Vault struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Personal bool    `json:"personal"`
	Items    []Entry `json:"items"`
}

// Entry is one exported item with its original ID. The item keeps unknown
// top-level fields (crypto.md §5.2).
type Entry struct {
	ID   string            `json:"id"`
	Item *vaultcrypto.Item `json:"item"`
}

// file is the on-disk JSON envelope (crypto.md §7).
type file struct {
	Format    string        `json:"format"`
	Version   int           `json:"version"`
	CreatedAt int64         `json:"created_at"`
	KDF       api.KDFParams `json:"kdf"`
	Blob      []byte        `json:"blob"`
}

func marshal(v any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// MarshalPayload returns the exact plaintext JSON that Encode encrypts
// (UTF-8, compact, not padded).
//
// Items are written with Item.Encode and spliced in as is: encoding/json would
// compact them and so destroy the byte-for-byte preservation of unknown
// members (crypto.md §5.2).
func MarshalPayload(p *Payload) ([]byte, error) {
	str := func(s string) []byte { b, _ := marshal(s, false); return b }
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"v":%d,"exported_at":%d,"exported_by":%s,"vaults":[`, p.V, p.ExportedAt, str(p.ExportedBy))
	for i, v := range p.Vaults {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%s,"name":%s,"personal":%t,"items":[`, str(v.ID), str(v.Name), v.Personal)
		for j, e := range v.Items {
			if j > 0 {
				b.WriteByte(',')
			}
			if e.Item == nil {
				return nil, errors.New("backup: entry without item")
			}
			it, err := e.Item.Encode()
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&b, `{"id":%s,"item":%s}`, str(e.ID), it)
		}
		b.WriteString("]}")
	}
	b.WriteString("]}")
	return b.Bytes(), nil
}

// Encode produces a backup file for payload, encrypted with passphrase under
// the given KDF parameters, which must satisfy vaultcrypto.ValidateKDFParams
// (use vaultcrypto.DefaultKDFParams for a fresh salt). created_at is the
// current time.
func Encode(payload *Payload, passphrase string, kdf api.KDFParams) ([]byte, error) {
	var nonce [24]byte
	_, _ = rand.Read(nonce[:])
	return EncodeDeterministic(payload, passphrase, kdf, time.Now().UnixMilli(), nonce[:])
}

// EncodeDeterministic is Encode with a caller-chosen created_at and AEAD
// nonce. For test vectors only.
func EncodeDeterministic(payload *Payload, passphrase string, kdf api.KDFParams, createdAtMs int64, nonce []byte) ([]byte, error) {
	if payload.V != PayloadVersion {
		return nil, fmt.Errorf("backup: payload version must be %d", PayloadVersion)
	}
	pj, err := MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Zero(pj)
	key, err := vaultcrypto.DeriveBackupKey(passphrase, kdf)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	blob, err := vaultcrypto.SealWithNonce(key, nonce, pj, AAD)
	if err != nil {
		return nil, err
	}
	return marshal(&file{Format: Format, Version: FileVersion, CreatedAt: createdAtMs, KDF: kdf, Blob: blob}, true)
}

// Decode parses and decrypts a backup file. Errors: ErrNotBackup (not an
// fpv-backup file), ErrUnsupportedVersion, ErrWeakKDF (parameters under the
// crypto.md §2 minimum; checked before any key derivation) and ErrDecrypt
// (wrong passphrase or corrupted data).
func Decode(data []byte, passphrase string) (*Payload, error) {
	var head struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Format != Format {
		return nil, ErrNotBackup
	}
	if head.Version != FileVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, head.Version)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w (malformed header: %v)", ErrDecrypt, err)
	}
	if err := vaultcrypto.ValidateKDFParams(f.KDF); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakKDF, err)
	}
	key, err := vaultcrypto.DeriveBackupKey(passphrase, f.KDF)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakKDF, err)
	}
	defer key.Zero()
	pj, err := vaultcrypto.Open(key, f.Blob, AAD)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer vaultcrypto.Zero(pj)
	var p Payload
	if err := json.Unmarshal(pj, &p); err != nil {
		return nil, fmt.Errorf("backup: authenticated payload is malformed: %w", err)
	}
	if p.V != PayloadVersion {
		return nil, fmt.Errorf("%w: payload version %d", ErrUnsupportedVersion, p.V)
	}
	for _, v := range p.Vaults {
		for _, e := range v.Items {
			if e.Item == nil {
				return nil, errors.New("backup: authenticated payload contains an entry without item")
			}
		}
	}
	return &p, nil
}
