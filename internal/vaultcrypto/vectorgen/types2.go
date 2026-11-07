package vectorgen

// VaultMetaCase is encMeta of crypto.md section 5.
type VaultMetaCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	VaultID       string `json:"vault_id"`
	KeyEpoch      uint32 `json:"key_epoch"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextJSON string `json:"plaintext_json"`
	AADString     string `json:"aad"`
	PaddedLength  int    `json:"padded_length"`
	BlobHex       string `json:"blob_hex"`
}

// VaultMetaNegative is a decrypt that must fail.
type VaultMetaNegative struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	KeyHex      string `json:"key_hex"`
	VaultID     string `json:"vault_id"`
	KeyEpoch    uint32 `json:"key_epoch"`
	BlobHex     string `json:"blob_hex"`
}

// ItemCase is itemBlob of crypto.md section 5.
type ItemCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	VaultID       string `json:"vault_id"`
	ItemID        string `json:"item_id"`
	KeyEpoch      uint32 `json:"key_epoch"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextJSON string `json:"plaintext_json"`
	AADString     string `json:"aad"`
	PaddedLength  int    `json:"padded_length"`
	BlobHex       string `json:"blob_hex"`
}

// ItemNegative is a decrypt that must fail.
type ItemNegative struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	KeyHex      string `json:"key_hex"`
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	KeyEpoch    uint32 `json:"key_epoch"`
	BlobHex     string `json:"blob_hex"`
}

// RosterCase is encRoster of crypto.md sections 5 and 6.3.
type RosterCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	VaultID       string `json:"vault_id"`
	KeyEpoch      uint32 `json:"key_epoch"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextJSON string `json:"plaintext_json"`
	AADString     string `json:"aad"`
	BlobHex       string `json:"blob_hex"`
}

// RosterNegative is a roster decrypt that must fail; it has the fields of
// VaultMetaNegative.
type RosterNegative = VaultMetaNegative

// Decoding kinds.
const (
	KindItem   = "item"
	KindMeta   = "meta"
	KindRoster = "roster"
)

// DecodingAccept is a plaintext both clients must accept (crypto.md 5.3).
// CanonicalJSON is the exact text a decode followed by the canonical encode
// must produce.
type DecodingAccept struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Kind          string `json:"kind"`
	PlaintextHex  string `json:"plaintext_hex"`
	CanonicalJSON string `json:"canonical_json"`
}

// DecodingReject is a plaintext both clients must refuse (crypto.md 5.3).
type DecodingReject struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Kind         string `json:"kind"`
	PlaintextHex string `json:"plaintext_hex"`
}

// EditPreserve pins the re-encoding after changing only the name.
type EditPreserve struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Kind         string `json:"kind"`
	PlaintextHex string `json:"plaintext_hex"`
	NewName      string `json:"new_name"`
	ExpectedJSON string `json:"expected_json"`
}

// ReencryptCase is raw re-encryption for rekeying (crypto.md 5.3, 6.6).
type ReencryptCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Kind          string `json:"kind"`
	VaultID       string `json:"vault_id"`
	ItemID        string `json:"item_id"`
	OldKeyHex     string `json:"old_key_hex"`
	NewKeyHex     string `json:"new_key_hex"`
	OldEpoch      uint32 `json:"old_epoch"`
	NewEpoch      uint32 `json:"new_epoch"`
	NonceHex      string `json:"nonce_hex"`
	InputBlobHex  string `json:"input_blob_hex"`
	Opened        bool   `json:"opened"`
	OutputBlobHex string `json:"output_blob_hex"`
}

// CommitmentCase is the vault-key commitment of crypto.md 6.2.
type CommitmentCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	VaultKeyHex   string `json:"vault_key_hex"`
	VaultID       string `json:"vault_id"`
	KeyEpoch      uint32 `json:"key_epoch"`
	CommitmentHex string `json:"commitment_hex"`
}

// LocalTrustCase is the sealed local trust store of crypto.md 6.2.
type LocalTrustCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	AccountKeyHex string `json:"account_key_hex"`
	UserID        string `json:"user_id"`
	TrustKeyHex   string `json:"trust_key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	AADString     string `json:"aad"`
	BlobHex       string `json:"blob_hex"`
}

// LocalTrustNegative is an open that must fail.
type LocalTrustNegative struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	AccountKeyHex string `json:"account_key_hex"`
	UserID        string `json:"user_id"`
	BlobHex       string `json:"blob_hex"`
}

// PasswordPolicyCase is the master-password policy floor. Expect is "ok" or
// one of the rejection codes; Hint says whether the passphrase nudge shows.
type PasswordPolicyCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	Expect      string `json:"expect"`
	Hint        bool   `json:"hint"`
}
