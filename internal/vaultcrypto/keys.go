package vaultcrypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
)

// SymmetricKey is a 32-byte secret key (encKey, loginKey, accountKey, vault
// key, backup key; crypto.md §2-§6). It redacts itself when formatted.
type SymmetricKey [32]byte

// PrivateKey is an X25519 private scalar (crypto.md §4). It redacts itself
// when formatted.
type PrivateKey [32]byte

// PublicKey is an X25519 public key (crypto.md §4).
type PublicKey [32]byte

var errNoJSON = errors.New("vaultcrypto: refusing to serialise secret key material")

// Format implements fmt.Formatter and prints a fixed redaction for every verb.
func (SymmetricKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("SymmetricKey(redacted)")) }

// Format implements fmt.Formatter and prints a fixed redaction for every verb.
func (PrivateKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("PrivateKey(redacted)")) }

// MarshalJSON always fails: secret keys must never be serialised implicitly.
func (SymmetricKey) MarshalJSON() ([]byte, error) { return nil, errNoJSON }

// MarshalJSON always fails: secret keys must never be serialised implicitly.
func (PrivateKey) MarshalJSON() ([]byte, error) { return nil, errNoJSON }

// MarshalText always fails: secret keys must never be serialised implicitly.
func (SymmetricKey) MarshalText() ([]byte, error) { return nil, errNoJSON }

// MarshalText always fails: secret keys must never be serialised implicitly.
func (PrivateKey) MarshalText() ([]byte, error) { return nil, errNoJSON }

// Zero overwrites the key with zeros (best effort).
func (k *SymmetricKey) Zero() { Zero(k[:]) }

// Zero overwrites the key with zeros (best effort).
func (k *PrivateKey) Zero() { Zero(k[:]) }

// Bytes returns a copy of the key as a slice.
func (k PublicKey) Bytes() []byte { b := k; return b[:] }

// String returns the lowercase hex encoding of the public key.
func (k PublicKey) String() string { return hex.EncodeToString(k[:]) }

// Zero overwrites b with zeros. It is best effort: Go may have copied the
// data elsewhere (stack growth, GC), and callers should still minimise how
// long secrets live.
func Zero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

func symKeyFromSlice(b []byte) (*SymmetricKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("vaultcrypto: key must be 32 bytes, got %d", len(b))
	}
	var k SymmetricKey
	copy(k[:], b)
	return &k, nil
}
