package fsm

import (
	"strings"

	"github.com/tarnan3751/password-vault/internal/api"
)

// Limits (docs/spec/api.md §1). They are enforced when a command is APPLIED,
// so they are part of the replicated semantics: every replica must use the
// same values, and changing one is a protocol change.
const (
	MaxUsers          = 32
	MaxVaultsPerOwner = 32 // counted per vault creator, including the personal vault
	MaxItemsPerVault  = 10000

	// Storage quotas. Usage of a vault is len(enc_meta) + len(enc_roster)
	// plus, for every item, len(blob) + ItemOverheadBytes. The per-item charge covers the
	// item's metadata in the snapshot, so the snapshot size is bounded by the
	// cluster quota whatever the item sizes (otherwise millions of tiny items
	// would fit). Users are charged for the vaults they created; the cluster
	// quota keeps a full snapshot well below the peer transport's message
	// limit, so a lagging or replaced node can always catch up.
	MaxVaultBytes     = 8 << 20
	MaxUserBytes      = 16 << 20
	MaxClusterBytes   = 48 << 20
	ItemOverheadBytes = 128

	MaxItemBlobBytes    = 64 << 10
	MaxEncMetaBytes     = 4 << 10
	MaxRosterBytes      = 16 << 10 // enc_roster (crypto.md §6.3)
	MaxAccountBlobBytes = 4 << 10  // wrapped_account_key, enc_private_key
	MinBoxBytes         = 1 + 24 + 16
	WrappedKeyBytes     = 105
	PublicKeyBytes      = 32
	ClusterKeyBytes     = 32

	// MaxPendingInvites bounds the number of unused, unexpired, unrevoked
	// invites. Without it an admin token (or a bug) could grow the replicated
	// state without limit.
	MaxPendingInvites     = 64
	DefaultInviteTTLHours = 72
	MaxInviteTTLHours     = 720

	// IdempotencyCapacity is the number of most recent command results kept
	// for exactly-once de-duplication.
	IdempotencyCapacity = 4096

	// MaxCommandBytes bounds a single command (a 32 MiB rekey body plus
	// envelope overhead fits comfortably).
	MaxCommandBytes = 48 << 20
)

// Server-side password verifier parameters (api.md §3.1). The state machine
// accepts exactly these: the login path runs Argon2 with whatever parameters
// are stored, so accepting arbitrary values from the log would let a bad
// command turn every login into a memory-exhaustion attack on a small node.
const (
	VerifierTime        = 2
	VerifierMemoryKiB   = 19456
	VerifierParallelism = 1
	VerifierSaltBytes   = 16
	VerifierHashBytes   = 32
)

// Bounds on the client-side KDF parameters accepted at registration and
// password change. They mirror what clients accept (crypto.md §2): storing
// anything a client would refuse would lock the user out of their own
// account. They are policy for new writes only; restore checks stored
// parameters structurally (validateStoredKDF), so tightening the policy
// later never makes an existing state unrestorable.
const (
	KDFMinTime        = 3
	KDFMaxTime        = 8
	KDFMinMemoryKiB   = 65536
	KDFMaxMemoryKiB   = 262144
	KDFMinParallelism = 1
	KDFMaxParallelism = 16
	KDFMinSaltBytes   = 16
	KDFMaxSaltBytes   = 64
)

// maxNowMs rejects absurd timestamps (year > ~33000) so that expiry
// arithmetic can never overflow.
const maxNowMs = 1_000_000_000_000_000

// Error is a deterministic failure produced by the state machine (or by the
// shared stateless validators). Code is one of the api.Code* constants.
type Error struct {
	Code           string  `json:"code"`
	Message        string  `json:"message"`
	CurrentVersion *uint64 `json:"current_version,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(code, msg string) *Error { return &Error{Code: code, Message: msg} }

func badRequest(msg string) *Error { return newErr(api.CodeBadRequest, msg) }
func tooLarge(msg string) *Error   { return newErr(api.CodeTooLarge, msg) }
func forbidden(msg string) *Error  { return newErr(api.CodeForbidden, msg) }
func notFound(msg string) *Error   { return newErr(api.CodeNotFound, msg) }
func exists(msg string) *Error     { return newErr(api.CodeAlreadyExists, msg) }
func limit(msg string) *Error      { return newErr(api.CodeLimitExceeded, msg) }

func conflict(msg string, current uint64) *Error {
	c := current
	return &Error{Code: api.CodeVersionConflict, Message: msg, CurrentVersion: &c}
}

var (
	errSession        = func() *Error { return newErr(api.CodeUnauthorized, "session is no longer valid") }
	errInvalidInvite  = func() *Error { return newErr(api.CodeInvalidInvite, "invite is unknown, used, revoked or expired") }
	errNotInitialized = func() *Error { return newErr(api.CodeUnavailable, "cluster is not initialized yet") }
	errVaultNotFound  = func() *Error { return notFound("vault not found") }
	errKeyReuse       = func() *Error {
		return badRequest("Idempotency-Key was already used for a different request")
	}
)

// firstErr returns the first failed check. Checks are listed in the order
// in which they are reported (which error a malformed request gets is part
// of the API); they are pure, so evaluating all of them changes nothing.
func firstErr(errs ...*Error) *Error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// check is badRequest(msg) unless ok.
func check(ok bool, msg string) *Error {
	if ok {
		return nil
	}
	return badRequest(msg)
}

func checkID(field, id string) *Error {
	if ValidID(id) {
		return nil
	}
	return badRequest(field + " must be 32 lowercase hex characters")
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidID reports whether s is a client-generated ID: 32 lowercase hex chars.
func ValidID(s string) bool { return isLowerHex(s, 32) }

// ValidInviteID reports whether s has the shape of an invite id (16 lowercase
// hex chars, the prefix of the SHA-256 of the canonical code).
func ValidInviteID(s string) bool { return isLowerHex(s, 16) }

// ValidInviteHash reports whether s is a hex SHA-256 digest.
func ValidInviteHash(s string) bool { return isLowerHex(s, 64) }

// CanonicalUsername trims and lower-cases a username. Only ASCII letters are
// folded: Unicode case mapping would let e.g. U+212A KELVIN SIGN alias "k",
// and anything non-ASCII is rejected by ValidUsername anyway.
func CanonicalUsername(s string) string {
	b := []byte(strings.TrimSpace(s))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ValidUsername reports whether s matches ^[a-z0-9][a-z0-9._-]{0,31}$.
func ValidUsername(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// ValidRole reports whether r is one of the vault roles.
func ValidRole(r string) bool {
	return r == api.RoleOwner || r == api.RoleEditor || r == api.RoleViewer
}

// ValidateKDF checks client KDF parameters against crypto.md §2.
func ValidateKDF(k api.KDFParams) *Error {
	switch {
	case k.Alg != "argon2id":
		return badRequest("kdf.alg must be argon2id")
	case len(k.Salt) < KDFMinSaltBytes || len(k.Salt) > KDFMaxSaltBytes:
		return badRequest("kdf.salt must be 16 to 64 bytes")
	case k.Time < KDFMinTime || k.Time > KDFMaxTime:
		return badRequest("kdf.time is out of range")
	case k.MemoryKiB < KDFMinMemoryKiB || k.MemoryKiB > KDFMaxMemoryKiB:
		return badRequest("kdf.memory_kib is out of range")
	case k.Parallelism < KDFMinParallelism || k.Parallelism > KDFMaxParallelism:
		return badRequest("kdf.parallelism is out of range")
	}
	return nil
}

// validateStoredKDF is the structural check applied on restore.
func validateStoredKDF(k api.KDFParams) bool {
	return k.Alg == "argon2id" && len(k.Salt) >= KDFMinSaltBytes && len(k.Salt) <= KDFMaxSaltBytes &&
		k.Time >= 1 && k.Parallelism >= 1 && k.MemoryKiB >= 8*uint32(k.Parallelism)
}

// validateBox checks the length of an AEAD box (crypto.md §3). The server
// never looks inside: length is the only property it can and needs to check.
func validateBox(field string, b []byte, max int) *Error {
	if len(b) > max {
		return tooLarge(field + " is too large")
	}
	if len(b) < MinBoxBytes {
		return badRequest(field + " is too short to be a ciphertext")
	}
	return nil
}

// validateWrappedKey checks a wrapped vault key (crypto.md §6). If sender is
// non-empty the wrap must claim to come from that user: a member can only
// vouch for keys they wrapped themselves, otherwise one member could plant a
// key that appears to be authenticated by another.
func validateWrappedKey(field string, wk api.WrappedKey, sender string) *Error {
	if !ValidID(wk.SenderID) {
		return badRequest(field + ".sender_id is not a valid id")
	}
	if sender != "" && wk.SenderID != sender {
		return badRequest(field + ".sender_id must be the caller")
	}
	if len(wk.Blob) > WrappedKeyBytes {
		return tooLarge(field + ".blob must be exactly 105 bytes")
	}
	if len(wk.Blob) != WrappedKeyBytes {
		return badRequest(field + ".blob must be exactly 105 bytes")
	}
	return nil
}

// Verifier is the server-side password verifier (api.md §3.1):
// Hash = Argon2id(login_key, Salt, Time, MemoryKiB, Parallelism, 32).
type Verifier struct {
	Salt        []byte `json:"salt"`
	Time        uint32 `json:"t"`
	MemoryKiB   uint32 `json:"m"`
	Parallelism uint8  `json:"p"`
	Hash        []byte `json:"hash"`
}

func (v Verifier) validate() *Error {
	if len(v.Salt) != VerifierSaltBytes || len(v.Hash) != VerifierHashBytes ||
		v.Time != VerifierTime || v.MemoryKiB != VerifierMemoryKiB || v.Parallelism != VerifierParallelism {
		return badRequest("invalid password verifier")
	}
	return nil
}

func (v Verifier) clone() Verifier {
	v.Salt = cloneBytes(v.Salt)
	v.Hash = cloneBytes(v.Hash)
	return v
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneKDF(k api.KDFParams) api.KDFParams {
	k.Salt = cloneBytes(k.Salt)
	return k
}

func cloneWrapped(w api.WrappedKey) api.WrappedKey {
	w.Blob = cloneBytes(w.Blob)
	return w
}
