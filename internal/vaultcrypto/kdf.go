package vaultcrypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/api"
	"golang.org/x/crypto/argon2"
)

// KDF parameter constants (crypto.md §2).
const (
	KDFAlgArgon2id     = "argon2id"
	SaltSize           = 16
	DefaultTime        = 3
	DefaultMemoryKiB   = 65536
	DefaultParallelism = 4

	MinSaltLen     = 16
	MaxSaltLen     = 64
	MinMemoryKiB   = 65536
	MaxMemoryKiB   = 262144
	MinTime        = 3
	MaxTime        = 8
	MinParallelism = 1
	MaxParallelism = 16
)

// HKDF info strings (crypto.md §2, §7).
const (
	infoEncKey    = "fpv/v1/enc-key"
	infoLoginKey  = "fpv/v1/login-key"
	infoBackupKey = "fpv/v1/backup-key"
)

// ErrKDFParams is wrapped by every KDF parameter rejection.
var ErrKDFParams = errors.New("vaultcrypto: unacceptable KDF parameters")

// MasterKeys are the two keys derived from the master password (crypto.md §2).
// EncKey never leaves the device; LoginKey is sent to the server.
type MasterKeys struct {
	EncKey   SymmetricKey
	LoginKey SymmetricKey
}

// String redacts the keys.
func (MasterKeys) String() string { return "MasterKeys(redacted)" }

// GoString redacts the keys.
func (MasterKeys) GoString() string { return "MasterKeys(redacted)" }

// Zero overwrites both keys.
func (m *MasterKeys) Zero() { m.EncKey.Zero(); m.LoginKey.Zero() }

// DefaultKDFParams returns the production parameters (t=3, m=64 MiB, p=4)
// with a fresh random 16-byte salt (crypto.md §2).
func DefaultKDFParams() api.KDFParams {
	salt := make([]byte, SaltSize)
	_, _ = rand.Read(salt)
	return api.KDFParams{
		Alg:         KDFAlgArgon2id,
		Salt:        salt,
		Time:        DefaultTime,
		MemoryKiB:   DefaultMemoryKiB,
		Parallelism: DefaultParallelism,
	}
}

// ValidateKDFParams enforces the acceptance rule of crypto.md §2:
// alg == "argon2id", 16 <= len(salt) <= 64, 65536 <= m <= 262144,
// 3 <= t <= 8, 1 <= p <= 16. A client must refuse to derive keys from
// anything else.
func ValidateKDFParams(p api.KDFParams) error {
	switch {
	case p.Alg != KDFAlgArgon2id:
		return fmt.Errorf("%w: algorithm %q", ErrKDFParams, p.Alg)
	case len(p.Salt) < MinSaltLen || len(p.Salt) > MaxSaltLen:
		return fmt.Errorf("%w: salt length outside [%d, %d] bytes", ErrKDFParams, MinSaltLen, MaxSaltLen)
	case p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB:
		return fmt.Errorf("%w: memory_kib %d outside [%d, %d]", ErrKDFParams, p.MemoryKiB, MinMemoryKiB, MaxMemoryKiB)
	case p.Time < MinTime || p.Time > MaxTime:
		return fmt.Errorf("%w: time %d outside [%d, %d]", ErrKDFParams, p.Time, MinTime, MaxTime)
	case p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism:
		return fmt.Errorf("%w: parallelism %d outside [%d, %d]", ErrKDFParams, p.Parallelism, MinParallelism, MaxParallelism)
	}
	return nil
}

// CheckKDFNotWeaker implements the rule of crypto.md §2 for a device that
// holds cached account data: the offered parameters must not have a smaller
// memory or time cost than the cached ones. Both are expected to have passed
// ValidateKDFParams already.
func CheckKDFNotWeaker(cached, offered api.KDFParams) error {
	if offered.MemoryKiB < cached.MemoryKiB || offered.Time < cached.Time {
		return fmt.Errorf("%w: offered parameters (m=%d, t=%d) are weaker than the cached ones (m=%d, t=%d)",
			ErrKDFParams, offered.MemoryKiB, offered.Time, cached.MemoryKiB, cached.Time)
	}
	return nil
}

// ArgonSalt returns SHA-256(utf8("fpv/v1/kdf-salt|" + username + "|") || salt),
// the actual Argon2 salt of crypto.md §2.
func ArgonSalt(username string, salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte("fpv/v1/kdf-salt|" + username + "|"))
	h.Write(salt)
	return h.Sum(nil)
}

func checkNormalizedUsername(username string) error {
	n, err := NormalizeUsername(username)
	if err != nil {
		return err
	}
	if n != username {
		return errors.New("vaultcrypto: username must be passed in normalized form")
	}
	return nil
}

// DeriveMasterKeys derives encKey and loginKey from the master password
// (crypto.md §2) after ValidateKDFParams. username must already be normalized
// (NormalizeUsername); it is mixed into the Argon2 salt.
func DeriveMasterKeys(username, password string, p api.KDFParams) (*MasterKeys, error) {
	if err := ValidateKDFParams(p); err != nil {
		return nil, err
	}
	if err := checkNormalizedUsername(username); err != nil {
		return nil, err
	}
	return deriveMasterKeys(username, password, p)
}

// DeriveMasterKeysUnsafeParams is DeriveMasterKeys WITHOUT the parameter
// bounds. It exists only so test vectors can use cheap parameters; production
// code must never call it. It still rejects parameters Argon2 cannot run with.
func DeriveMasterKeysUnsafeParams(username, password string, p api.KDFParams) (*MasterKeys, error) {
	if err := validateRunnable(p); err != nil {
		return nil, err
	}
	if err := checkNormalizedUsername(username); err != nil {
		return nil, err
	}
	return deriveMasterKeys(username, password, p)
}

func validateRunnable(p api.KDFParams) error {
	if p.Alg != KDFAlgArgon2id || p.Time < 1 || p.Parallelism < 1 || p.MemoryKiB < 8*uint32(p.Parallelism) {
		return fmt.Errorf("%w: cannot run argon2id with these parameters", ErrKDFParams)
	}
	return nil
}

func deriveMasterKeys(username, password string, p api.KDFParams) (*MasterKeys, error) {
	pw := NormalizePassword(password)
	mk := argon2.IDKey(pw, ArgonSalt(username, p.Salt), p.Time, p.MemoryKiB, p.Parallelism, 32)
	Zero(pw)
	defer Zero(mk)
	enc, err := deriveKey(mk, nil, infoEncKey)
	if err != nil {
		return nil, err
	}
	defer enc.Zero()
	login, err := deriveKey(mk, nil, infoLoginKey)
	if err != nil {
		return nil, err
	}
	defer login.Zero()
	return &MasterKeys{EncKey: *enc, LoginKey: *login}, nil
}

// DeriveBackupKey derives the backup encryption key from a passphrase and the
// backup's KDF parameters (crypto.md §7), enforcing ValidateKDFParams. The raw
// salt is used (no username).
func DeriveBackupKey(passphrase string, p api.KDFParams) (*SymmetricKey, error) {
	if err := ValidateKDFParams(p); err != nil {
		return nil, err
	}
	pw := NormalizePassword(passphrase)
	bk := argon2.IDKey(pw, p.Salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
	Zero(pw)
	defer Zero(bk)
	return deriveKey(bk, nil, infoBackupKey)
}

// deriveKey is HKDF-SHA256 (crypto.md §2) with a 32-byte output.
func deriveKey(ikm, salt []byte, info string) (*SymmetricKey, error) {
	k, err := hkdf.Key(sha256.New, ikm, salt, info, 32)
	if err != nil {
		return nil, err
	}
	defer Zero(k)
	return symKeyFromSlice(k)
}
