package vaultcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const infoLocalTrustKey = "fpv/v1/local-trust-key"

// VaultKeyCommitment returns lowercase hex of
// SHA-256(utf8("fpv/v1/vault-key-commit|" + vaultID + "|" + keyEpoch + "|") || VK)
// (crypto.md §6.2). The caller is responsible for passing a well-formed ID.
func VaultKeyCommitment(vk *SymmetricKey, vaultID string, epoch uint32) string {
	h := sha256.New()
	h.Write([]byte("fpv/v1/vault-key-commit|" + vaultID + "|" + epochStr(epoch) + "|"))
	h.Write(vk[:])
	return hex.EncodeToString(h.Sum(nil))
}

// LocalTrustKey derives the key that seals the local trust store:
// HKDF-SHA256(ikm = accountKey, salt = empty, info = "fpv/v1/local-trust-key",
// L = 32) (crypto.md §6.2).
func LocalTrustKey(accountKey *SymmetricKey) *SymmetricKey {
	k, err := deriveKey(accountKey[:], nil, infoLocalTrustKey)
	if err != nil {
		panic(err) // cannot happen: fixed, valid HKDF parameters
	}
	return k
}

// LocalTrustAAD returns "fpv/v1/local-trust|" + userID.
func LocalTrustAAD(userID string) []byte { return []byte("fpv/v1/local-trust|" + userID) }

// SealLocalTrust seals the trust-store plaintext (its JSON is the client's
// business) under LocalTrustKey(accountKey) (crypto.md §6.2).
func SealLocalTrust(accountKey *SymmetricKey, userID string, plaintext []byte) ([]byte, error) {
	var n [nonceSize]byte
	_, _ = rand.Read(n[:])
	return SealLocalTrustWithNonce(accountKey, userID, plaintext, n[:])
}

// SealLocalTrustWithNonce is SealLocalTrust with a fixed nonce. For test
// vectors only.
func SealLocalTrustWithNonce(accountKey *SymmetricKey, userID string, plaintext, nonce []byte) ([]byte, error) {
	if err := checkIDs(userID); err != nil {
		return nil, err
	}
	k := LocalTrustKey(accountKey)
	defer k.Zero()
	return SealWithNonce(k, nonce, plaintext, LocalTrustAAD(userID))
}

// OpenLocalTrust opens a sealed trust store; any failure is ErrDecrypt (the
// client then starts from an empty store).
func OpenLocalTrust(accountKey *SymmetricKey, userID string, blob []byte) ([]byte, error) {
	if err := checkIDs(userID); err != nil {
		return nil, err
	}
	k := LocalTrustKey(accountKey)
	defer k.Zero()
	return Open(k, blob, LocalTrustAAD(userID))
}
