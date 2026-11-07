// Package vectorgen deterministically generates testvectors/crypto-v1.json
// (docs/spec/crypto.md §8). The types in this file ARE the schema of that
// file; they are exported so the Go tests of vaultcrypto and backup can load
// the checked-in vectors. The schema is documented field by field in
// testvectors/README.md.
//
// Conventions: every raw binary value is a lowercase hex string and the field
// name ends in "_hex". Text values (passwords, IDs, AAD strings, JSON
// documents) are ordinary JSON strings.
package vectorgen

import (
	"encoding/json"
	"os"
)

// File is the root of crypto-v1.json.
type File struct {
	Suite         string `json:"suite"`
	SchemaVersion int    `json:"schema_version"`
	Description   string `json:"description"`
	Encoding      string `json:"encoding"`

	PasswordPolicyCommon []string `json:"password_policy_common"`

	Argon2idPublished []Argon2idPublished `json:"argon2id_published"`
	HKDFPublished     []HKDFPublished     `json:"hkdf_sha256_published"`
	X25519Published   []X25519Published   `json:"x25519_published"`
	XChaChaPublished  []XChaChaPublished  `json:"xchacha20poly1305_published"`

	MasterKeys    []MasterKeyCase     `json:"master_keys"`
	KDFValidation []KDFValidationCase `json:"kdf_params_validation"`
	KDFNotWeaker  []KDFNotWeakerCase  `json:"kdf_not_weaker"`

	Box         []BoxCase     `json:"box"`
	BoxNegative []BoxNegative `json:"box_negative"`

	KeyPairs     []KeyPairCase     `json:"key_pairs"`
	Fingerprints []FingerprintCase `json:"fingerprints"`

	VaultKeyWrap         []WrapCase     `json:"vault_key_wrap"`
	VaultKeyWrapNegative []WrapNegative `json:"vault_key_wrap_negative"`

	Padding      []PaddingCase       `json:"padding"`
	VaultMeta    []VaultMetaCase     `json:"vault_meta"`
	VaultMetaNeg []VaultMetaNegative `json:"vault_meta_negative"`
	Items        []ItemCase          `json:"items"`
	ItemsNeg     []ItemNegative      `json:"items_negative"`
	Rosters      []RosterCase        `json:"rosters"`
	RostersNeg   []RosterNegative    `json:"rosters_negative"`

	DecodingAccept []DecodingAccept `json:"decoding_accept"`
	DecodingReject []DecodingReject `json:"decoding_reject"`
	EditPreserve   []EditPreserve   `json:"edit_preserve"`
	Reencrypt      []ReencryptCase  `json:"reencrypt"`

	Commitments    []CommitmentCase     `json:"vault_key_commitments"`
	LocalTrust     []LocalTrustCase     `json:"local_trust"`
	LocalTrustNeg  []LocalTrustNegative `json:"local_trust_negative"`
	PasswordPolicy []PasswordPolicyCase `json:"password_policy"`

	Accounts        []AccountCase     `json:"accounts"`
	AccountsNeg     []AccountNegative `json:"accounts_negative"`
	Backups         []BackupCase      `json:"backups"`
	BackupsNegative []BackupNegative  `json:"backups_negative"`
}

// Argon2idPublished is an Argon2id vector from the reference implementation.
type Argon2idPublished struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Source      string `json:"source"`
	PasswordHex string `json:"password_hex"`
	SaltHex     string `json:"salt_hex"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	OutLen      uint32 `json:"out_len"`
	ExpectedHex string `json:"expected_hex"`
}

// HKDFPublished is an RFC 5869 HKDF-SHA-256 vector.
type HKDFPublished struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Source      string `json:"source"`
	IKMHex      string `json:"ikm_hex"`
	SaltHex     string `json:"salt_hex"`
	InfoHex     string `json:"info_hex"`
	Length      int    `json:"length"`
	PRKHex      string `json:"prk_hex"`
	OKMHex      string `json:"okm_hex"`
}

// X25519Published is an RFC 7748 scalar multiplication vector.
type X25519Published struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Source      string `json:"source"`
	ScalarHex   string `json:"scalar_hex"`
	UHex        string `json:"u_hex"`
	ExpectedHex string `json:"expected_hex"`
}

// XChaChaPublished is the draft-irtf-cfrg-xchacha A.3.1 vector.
type XChaChaPublished struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Source        string `json:"source"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	AADHex        string `json:"aad_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
	TagHex        string `json:"tag_hex"`
}

// MasterKeyCase is crypto.md §2 (plus password normalisation, §1).
type MasterKeyCase struct {
	ID                    string `json:"id"`
	Description           string `json:"description"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PasswordHex           string `json:"password_hex"`
	NormalizedPasswordHex string `json:"normalized_password_hex"`
	SaltHex               string `json:"salt_hex"`
	ArgonSaltHex          string `json:"argon_salt_hex"`
	Time                  uint32 `json:"time"`
	MemoryKiB             uint32 `json:"memory_kib"`
	Parallelism           uint8  `json:"parallelism"`
	BelowProductionMin    bool   `json:"below_production_minimum"`
	MasterKeyHex          string `json:"master_key_hex"`
	EncKeyHex             string `json:"enc_key_hex"`
	LoginKeyHex           string `json:"login_key_hex"`
}

// KDFValidationCase checks the acceptance rule of crypto.md §2.
type KDFValidationCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Alg         string `json:"alg"`
	SaltHex     string `json:"salt_hex"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint32 `json:"parallelism"`
	Valid       bool   `json:"valid"`
}

// KDFNotWeakerCase checks the cached-parameters rule of crypto.md section 2.
type KDFNotWeakerCase struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	CachedTime       uint32 `json:"cached_time"`
	CachedMemoryKiB  uint32 `json:"cached_memory_kib"`
	OfferedTime      uint32 `json:"offered_time"`
	OfferedMemoryKiB uint32 `json:"offered_memory_kib"`
	Acceptable       bool   `json:"acceptable"`
}

// BoxCase is a positive crypto.md §3 vector.
type BoxCase struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	KeyHex       string `json:"key_hex"`
	NonceHex     string `json:"nonce_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	AADHex       string `json:"aad_hex"`
	BoxHex       string `json:"box_hex"`
}

// BoxNegative is an input that open() must reject.
type BoxNegative struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	KeyHex      string `json:"key_hex"`
	AADHex      string `json:"aad_hex"`
	BoxHex      string `json:"box_hex"`
}

// KeyPairCase is X25519 public-key derivation (crypto.md §4).
type KeyPairCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
}

// FingerprintCase is crypto.md §6.1.
type FingerprintCase struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	PublicKeyHex string `json:"public_key_hex"`
	Fingerprint  string `json:"fingerprint"`
}

// WrapCase is a positive crypto.md §6 vector.
type WrapCase struct {
	ID                  string `json:"id"`
	Description         string `json:"description"`
	SenderPrivateHex    string `json:"sender_private_hex"`
	SenderPublicHex     string `json:"sender_public_hex"`
	SenderID            string `json:"sender_id"`
	RecipientPrivateHex string `json:"recipient_private_hex"`
	RecipientPublicHex  string `json:"recipient_public_hex"`
	RecipientID         string `json:"recipient_id"`
	VaultID             string `json:"vault_id"`
	KeyEpoch            uint32 `json:"key_epoch"`
	VaultKeyHex         string `json:"vault_key_hex"`
	EphemeralPrivateHex string `json:"ephemeral_private_hex"`
	EphemeralPublicHex  string `json:"ephemeral_public_hex"`
	NonceHex            string `json:"nonce_hex"`
	AADString           string `json:"aad"`
	WrapHex             string `json:"wrap_hex"`
}

// WrapNegative is an unwrap call that must fail. Its inputs are exactly the
// arguments of unwrap; BaseCase names the positive case it was derived from.
type WrapNegative struct {
	ID                  string `json:"id"`
	Description         string `json:"description"`
	BaseCase            string `json:"base_case"`
	RecipientPrivateHex string `json:"recipient_private_hex"`
	SenderPublicHex     string `json:"sender_public_hex"`
	SenderID            string `json:"sender_id"`
	RecipientID         string `json:"recipient_id"`
	VaultID             string `json:"vault_id"`
	KeyEpoch            uint32 `json:"key_epoch"`
	WrapHex             string `json:"wrap_hex"`
}

// PaddingCase is pad() of crypto.md §5.
type PaddingCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	InputHex    string `json:"input_hex"`
	N           int    `json:"n"`
	PaddedHex   string `json:"padded_hex"`
}

// AccountKDF holds the Argon2id parameters of an account scenario.
type AccountKDF struct {
	SaltHex     string `json:"salt_hex"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

// PasswordChange is the §4 password-change part of an account scenario.
type PasswordChange struct {
	NewPassword             string     `json:"new_password"`
	NewKDF                  AccountKDF `json:"new_kdf"`
	NewNonceHex             string     `json:"new_nonce_hex"`
	NewEncKeyHex            string     `json:"new_enc_key_hex"`
	NewLoginKeyHex          string     `json:"new_login_key_hex"`
	NewWrappedAccountKeyHex string     `json:"new_wrapped_account_key_hex"`
}

// AccountCase is the full crypto.md §4 scenario.
type AccountCase struct {
	ID                   string         `json:"id"`
	Description          string         `json:"description"`
	UserID               string         `json:"user_id"`
	Username             string         `json:"username"`
	Password             string         `json:"password"`
	KDF                  AccountKDF     `json:"kdf"`
	AccountKeyHex        string         `json:"account_key_hex"`
	PrivateKeyHex        string         `json:"private_key_hex"`
	NonceWrapHex         string         `json:"nonce_wrapped_account_key_hex"`
	NonceEncPrivHex      string         `json:"nonce_enc_private_key_hex"`
	EncKeyHex            string         `json:"enc_key_hex"`
	LoginKeyHex          string         `json:"login_key_hex"`
	PublicKeyHex         string         `json:"public_key_hex"`
	WrappedAccountKeyHex string         `json:"wrapped_account_key_hex"`
	EncPrivateKeyHex     string         `json:"enc_private_key_hex"`
	PasswordChange       PasswordChange `json:"password_change"`
}

// Account negative error kinds.
const (
	ErrKindDecrypt           = "decrypt"
	ErrKindPublicKeyMismatch = "public_key_mismatch"
)

// AccountNegative is an unlock that must fail.
type AccountNegative struct {
	ID                   string     `json:"id"`
	Description          string     `json:"description"`
	UserID               string     `json:"user_id"`
	Username             string     `json:"username"`
	Password             string     `json:"password"`
	KDF                  AccountKDF `json:"kdf"`
	PublicKeyHex         string     `json:"public_key_hex"`
	WrappedAccountKeyHex string     `json:"wrapped_account_key_hex"`
	EncPrivateKeyHex     string     `json:"enc_private_key_hex"`
	ExpectError          string     `json:"expect_error"`
}

// BackupCase is a complete crypto.md §7 backup file.
type BackupCase struct {
	ID                  string          `json:"id"`
	Description         string          `json:"description"`
	Passphrase          string          `json:"passphrase"`
	AlternatePassphrase []string        `json:"alternate_passphrases"`
	KDF                 AccountKDF      `json:"kdf"`
	CreatedAt           int64           `json:"created_at"`
	NonceHex            string          `json:"nonce_hex"`
	BackupKeyHex        string          `json:"backup_key_hex"`
	PayloadJSON         string          `json:"payload_json"`
	Payload             json.RawMessage `json:"payload"`
	File                string          `json:"file"`
}

// Backup negative error kinds.
const (
	BackupErrNotBackup = "not_backup"
	BackupErrVersion   = "unsupported_version"
	BackupErrWeakKDF   = "weak_kdf"
	BackupErrDecrypt   = "decrypt"
)

// BackupNegative is a backup file that must be rejected.
type BackupNegative struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Passphrase  string `json:"passphrase"`
	File        string `json:"file"`
	ExpectError string `json:"expect_error"`
}

// Load reads and parses a vectors file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
