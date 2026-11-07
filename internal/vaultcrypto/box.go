package vaultcrypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	boxVersion   = 0x01
	nonceSize    = chacha20poly1305.NonceSizeX // 24
	tagSize      = chacha20poly1305.Overhead   // 16
	minBoxLength = 1 + nonceSize + tagSize     // 41
)

// ErrDecrypt is the single, undifferentiated decryption failure (crypto.md §3):
// bad version byte, short input, wrong key, wrong AAD or tampered data.
var ErrDecrypt = errors.New("vaultcrypto: decryption failed")

// Seal encrypts plaintext under key with a fresh random nonce and returns
// 0x01 || nonce || ciphertext||tag (crypto.md §3).
func Seal(key *SymmetricKey, plaintext, aad []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	_, _ = rand.Read(nonce[:])
	return SealWithNonce(key, nonce[:], plaintext, aad)
}

// SealWithNonce is Seal with a caller-chosen 24-byte nonce. It exists ONLY to
// produce and check deterministic test vectors; reusing a nonce under one key
// is catastrophic (crypto.md §3).
func SealWithNonce(key *SymmetricKey, nonce, plaintext, aad []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("vaultcrypto: nil key")
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("vaultcrypto: nonce must be %d bytes, got %d", nonceSize, len(nonce))
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+nonceSize+len(plaintext)+tagSize)
	out = append(out, boxVersion)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Open verifies and decrypts a box produced by Seal (crypto.md §3). Every
// failure returns ErrDecrypt.
func Open(key *SymmetricKey, box, aad []byte) ([]byte, error) {
	if key == nil || len(box) < minBoxLength || box[0] != boxVersion {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, ErrDecrypt
	}
	nonce := box[1 : 1+nonceSize]
	pt, err := aead.Open(nil, nonce, box[1+nonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
