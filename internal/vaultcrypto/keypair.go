package vaultcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// ErrLowOrderPoint is returned when an X25519 operation yields the all-zero
// output, i.e. the peer's point has low order (crypto.md §6).
var ErrLowOrderPoint = errors.New("vaultcrypto: low-order X25519 point rejected")

// GenerateKeyPair returns a fresh X25519 key pair: 32 random bytes used as the
// scalar as-is, public = X25519(priv, basepoint) (crypto.md §4).
func GenerateKeyPair() (PrivateKey, PublicKey, error) {
	var priv PrivateKey
	_, _ = rand.Read(priv[:])
	pub, err := PublicFromPrivate(&priv)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	return priv, pub, nil
}

// PublicFromPrivate computes X25519(priv, basepoint) (crypto.md §4).
func PublicFromPrivate(priv *PrivateKey) (PublicKey, error) {
	var pub PublicKey
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, err
	}
	copy(pub[:], out)
	return pub, nil
}

// x25519 computes a Diffie-Hellman output and rejects the all-zero result.
func x25519(priv *PrivateKey, pub *PublicKey) ([]byte, error) {
	out, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, ErrLowOrderPoint
	}
	var acc byte
	for _, b := range out {
		acc |= b
	}
	if acc == 0 {
		return nil, ErrLowOrderPoint
	}
	return out, nil
}

// Fingerprint returns the identity-bound fingerprint of crypto.md §6.2: the
// first 16 bytes of SHA-256(utf8("fpv/v1/fingerprint|" + userID + "|" +
// username + "|") || publicKey) as 32 lowercase hex characters in eight
// groups of four separated by '-'. userID must be a well-formed ID and
// username a normalized username.
func Fingerprint(userID, username string, pub PublicKey) (string, error) {
	if err := checkIDs(userID); err != nil {
		return "", err
	}
	if err := checkNormalizedUsername(username); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("fpv/v1/fingerprint|" + userID + "|" + username + "|"))
	h.Write(pub[:])
	s := hex.EncodeToString(h.Sum(nil)[:16])
	out := make([]byte, 0, 39)
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, s[i:i+4]...)
	}
	return string(out), nil
}
