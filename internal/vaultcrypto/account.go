package vaultcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ErrPublicKeyMismatch is returned by UnlockAccount when the decrypted private
// key does not correspond to the account's published public key (crypto.md §4).
var ErrPublicKeyMismatch = errors.New("vaultcrypto: private key does not match account public key")

// AccountSecrets holds the unlocked per-user secrets (crypto.md §4). It lives
// only in memory.
type AccountSecrets struct {
	UserID     string
	AccountKey SymmetricKey
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

// String redacts the secrets.
func (AccountSecrets) String() string { return "AccountSecrets(redacted)" }

// GoString redacts the secrets.
func (AccountSecrets) GoString() string { return "AccountSecrets(redacted)" }

// Zero overwrites the secret fields.
func (a *AccountSecrets) Zero() { a.AccountKey.Zero(); a.PrivateKey.Zero() }

// AccountUpload is what registration uploads besides the KDF parameters and
// login key (crypto.md §4).
type AccountUpload struct {
	PublicKey         []byte
	WrappedAccountKey []byte
	EncPrivateKey     []byte
}

// AccountKeyAAD returns "fpv/v1/account-key|" + userID (crypto.md §4).
func AccountKeyAAD(userID string) []byte { return []byte("fpv/v1/account-key|" + userID) }

// PrivateKeyAAD returns "fpv/v1/private-key|" + userID (crypto.md §4).
func PrivateKeyAAD(userID string) []byte { return []byte("fpv/v1/private-key|" + userID) }

// NewAccount creates the account secrets for userID with fresh randomness and
// the artifacts to upload (crypto.md §4).
func NewAccount(userID string, mk *MasterKeys) (*AccountSecrets, *AccountUpload, error) {
	var ak SymmetricKey
	var sk PrivateKey
	_, _ = rand.Read(ak[:])
	_, _ = rand.Read(sk[:])
	var n1, n2 [nonceSize]byte
	_, _ = rand.Read(n1[:])
	_, _ = rand.Read(n2[:])
	defer func() { ak.Zero(); sk.Zero() }()
	return NewAccountDeterministic(userID, mk, &ak, &sk, n1[:], n2[:])
}

// NewAccountDeterministic is NewAccount with caller-chosen accountKey, private
// key and the two box nonces (wrappedAccountKey, encPrivateKey). For test
// vectors only.
func NewAccountDeterministic(userID string, mk *MasterKeys, accountKey *SymmetricKey, priv *PrivateKey, nonceWrap, nonceEncPriv []byte) (*AccountSecrets, *AccountUpload, error) {
	if err := checkIDs(userID); err != nil {
		return nil, nil, err
	}
	pub, err := PublicFromPrivate(priv)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := SealWithNonce(&mk.EncKey, nonceWrap, accountKey[:], AccountKeyAAD(userID))
	if err != nil {
		return nil, nil, err
	}
	encPriv, err := SealWithNonce(accountKey, nonceEncPriv, priv[:], PrivateKeyAAD(userID))
	if err != nil {
		return nil, nil, err
	}
	return &AccountSecrets{UserID: userID, AccountKey: *accountKey, PrivateKey: *priv, PublicKey: pub},
		&AccountUpload{PublicKey: pub.Bytes(), WrappedAccountKey: wrapped, EncPrivateKey: encPriv}, nil
}

// UnlockAccount implements the unlock of crypto.md §4: open wrappedAccountKey
// with encKey (success is the offline password check), open encPrivateKey with
// the account key, and verify that the private key matches publicKey. A wrong
// password yields ErrDecrypt; an inconsistent key pair ErrPublicKeyMismatch.
func UnlockAccount(userID string, mk *MasterKeys, publicKey, wrappedAccountKey, encPrivateKey []byte) (*AccountSecrets, error) {
	if err := checkIDs(userID); err != nil {
		return nil, err
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("vaultcrypto: public key must be 32 bytes, got %d", len(publicKey))
	}
	akb, err := Open(&mk.EncKey, wrappedAccountKey, AccountKeyAAD(userID))
	if err != nil {
		return nil, err
	}
	defer Zero(akb)
	ak, err := symKeyFromSlice(akb)
	if err != nil {
		return nil, ErrDecrypt
	}
	skb, err := Open(ak, encPrivateKey, PrivateKeyAAD(userID))
	if err != nil {
		ak.Zero()
		return nil, err
	}
	defer Zero(skb)
	if len(skb) != 32 {
		ak.Zero()
		return nil, ErrDecrypt
	}
	var sk PrivateKey
	copy(sk[:], skb)
	pub, err := PublicFromPrivate(&sk)
	if err != nil {
		ak.Zero()
		sk.Zero()
		return nil, err
	}
	if subtle.ConstantTimeCompare(pub[:], publicKey) != 1 {
		ak.Zero()
		sk.Zero()
		return nil, ErrPublicKeyMismatch
	}
	out := &AccountSecrets{UserID: userID, AccountKey: *ak, PrivateKey: sk, PublicKey: pub}
	ak.Zero() // the heap copy; the caller owns the copy in the result
	sk.Zero()
	return out, nil
}

// RewrapAccountKey produces the new wrappedAccountKey for a password change
// (crypto.md §4): seal(encKey', accountKey, aad). The key pair is unchanged.
func RewrapAccountKey(userID string, accountKey *SymmetricKey, newMK *MasterKeys) ([]byte, error) {
	var n [nonceSize]byte
	_, _ = rand.Read(n[:])
	return RewrapAccountKeyWithNonce(userID, accountKey, newMK, n[:])
}

// RewrapAccountKeyWithNonce is RewrapAccountKey with a fixed nonce. For test
// vectors only.
func RewrapAccountKeyWithNonce(userID string, accountKey *SymmetricKey, newMK *MasterKeys, nonce []byte) ([]byte, error) {
	if err := checkIDs(userID); err != nil {
		return nil, err
	}
	return SealWithNonce(&newMK.EncKey, nonce, accountKey[:], AccountKeyAAD(userID))
}
