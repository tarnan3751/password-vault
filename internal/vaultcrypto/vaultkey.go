package vaultcrypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// WrapLen is the exact length of a wrapped vault key (crypto.md §6).
	WrapLen        = 1 + 32 + nonceSize + 32 + tagSize // 105
	infoVaultWrap  = "fpv/v1/vault-key-wrap"
	aadVaultKeyPfx = "fpv/v1/vault-key|"
)

// WrapContext identifies what a wrapped vault key is bound to (crypto.md §6
// AAD). All IDs must be well-formed (32 lowercase hex characters), which also
// rules out '|' ambiguity in the AAD; KeyEpoch must be >= 1.
type WrapContext struct {
	VaultID     string
	KeyEpoch    uint32
	SenderID    string
	RecipientID string
}

func (c WrapContext) aad() ([]byte, error) {
	if err := checkArgs(c.KeyEpoch, c.VaultID, c.SenderID, c.RecipientID); err != nil {
		return nil, err
	}
	return []byte(aadVaultKeyPfx + c.VaultID + "|" + epochStr(c.KeyEpoch) + "|" + c.SenderID + "|" + c.RecipientID), nil
}

// WrapAAD returns the AAD string of crypto.md §6 for ctx, or nil if ctx is
// invalid (malformed IDs, epoch 0).
func WrapAAD(ctx WrapContext) []byte {
	a, err := ctx.aad()
	if err != nil {
		return nil
	}
	return a
}

// NewVaultKey returns a fresh random 32-byte vault key.
func NewVaultKey() *SymmetricKey {
	var k SymmetricKey
	_, _ = rand.Read(k[:])
	return &k
}

// WrapVaultKey encrypts vk for the recipient with authenticated ECIES
// (crypto.md §6). senderPriv is the sender's static key; the result is exactly
// WrapLen (105) bytes.
func WrapVaultKey(vk *SymmetricKey, ctx WrapContext, senderPriv *PrivateKey, recipientPub *PublicKey) ([]byte, error) {
	var eph PrivateKey
	var nonce [nonceSize]byte
	_, _ = rand.Read(eph[:])
	_, _ = rand.Read(nonce[:])
	defer eph.Zero()
	return WrapVaultKeyDeterministic(vk, ctx, senderPriv, recipientPub, &eph, nonce[:])
}

// WrapVaultKeyDeterministic is WrapVaultKey with the ephemeral secret skE and
// the nonce supplied by the caller. For test vectors only: reusing skE or the
// nonce in production destroys the scheme's guarantees.
func WrapVaultKeyDeterministic(vk *SymmetricKey, ctx WrapContext, senderPriv *PrivateKey, recipientPub *PublicKey, ephPriv *PrivateKey, nonce []byte) ([]byte, error) {
	aad, err := ctx.aad()
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("vaultcrypto: nonce must be %d bytes, got %d", nonceSize, len(nonce))
	}
	pkE, err := PublicFromPrivate(ephPriv)
	if err != nil {
		return nil, err
	}
	pkS, err := PublicFromPrivate(senderPriv)
	if err != nil {
		return nil, err
	}
	dh1, err := x25519(ephPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer Zero(dh1)
	dh2, err := x25519(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer Zero(dh2)
	key, err := wrapKey(dh1, dh2, &pkE, &pkS, recipientPub)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, WrapLen)
	out = append(out, boxVersion)
	out = append(out, pkE[:]...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, vk[:], aad)
	if len(out) != WrapLen {
		return nil, errors.New("vaultcrypto: internal error: wrap has wrong length")
	}
	return out, nil
}

// UnwrapVaultKey opens a wrapped vault key as the recipient (crypto.md §6).
// recipientPriv is the recipient's static key; senderPub is the sender's
// public key as looked up (and pinned) by the caller. Any failure returns
// ErrDecrypt, or ErrLowOrderPoint for an all-zero DH output.
func UnwrapVaultKey(wrap []byte, ctx WrapContext, recipientPriv *PrivateKey, senderPub *PublicKey) (*SymmetricKey, error) {
	aad, err := ctx.aad()
	if err != nil {
		return nil, err
	}
	if len(wrap) != WrapLen || wrap[0] != boxVersion {
		return nil, ErrDecrypt
	}
	var pkE PublicKey
	copy(pkE[:], wrap[1:33])
	nonce := wrap[33 : 33+nonceSize]
	ct := wrap[33+nonceSize:]
	pkR, err := PublicFromPrivate(recipientPriv)
	if err != nil {
		return nil, err
	}
	dh1, err := x25519(recipientPriv, &pkE)
	if err != nil {
		return nil, err
	}
	defer Zero(dh1)
	dh2, err := x25519(recipientPriv, senderPub)
	if err != nil {
		return nil, err
	}
	defer Zero(dh2)
	key, err := wrapKey(dh1, dh2, &pkE, senderPub, &pkR)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil || len(pt) != 32 {
		return nil, ErrDecrypt
	}
	defer Zero(pt)
	return symKeyFromSlice(pt)
}

func wrapKey(dh1, dh2 []byte, pkE, pkS, pkR *PublicKey) (*SymmetricKey, error) {
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	defer Zero(ikm)
	salt := make([]byte, 0, 96)
	salt = append(salt, pkE[:]...)
	salt = append(salt, pkS[:]...)
	salt = append(salt, pkR[:]...)
	return deriveKey(ikm, salt, infoVaultWrap)
}
