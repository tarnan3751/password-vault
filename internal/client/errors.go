package client

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// APIError is a non-2xx answer from a server (api.md). Its message is the
// server's own text; servers never see secrets, so it never contains any.
type APIError struct {
	Status  int
	Code    string // one of the api.Code* constants (or "" for a non-JSON error)
	Message string
	// CurrentVersion is set on version_conflict (item/meta version, or the
	// vault rev for a rekey); HasCurrentVersion tells 0 apart from "absent".
	CurrentVersion    uint64
	HasCurrentVersion bool
	// RetryAfter is set on rate_limited and unavailable when the server said so.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if e.Code == api.CodeRateLimited && e.RetryAfter > 0 {
		return fmt.Sprintf("%s (try again in %s)", msg, e.RetryAfter.Round(time.Second))
	}
	return msg
}

// NetworkError means no node gave a definite answer.
type NetworkError struct {
	Msg string
	// OutcomeUnknown is true for a mutation that may or may not have been
	// applied (a request went out but no definite answer came back, even after
	// the automatic retries with the same Idempotency-Key).
	OutcomeUnknown bool
	Err            error
}

func (e *NetworkError) Error() string {
	if e.Err != nil && e.Msg == "" {
		return e.Err.Error()
	}
	return e.Msg
}

func (e *NetworkError) Unwrap() error { return e.Err }

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// IsUnavailable reports whether err belongs to the "cannot reach a majority /
// any server" class: a NetworkError, or a 503 unavailable / outcome_unknown.
// The CLI maps this class to exit code 4.
func IsUnavailable(err error) bool {
	var ne *NetworkError
	if errors.As(err, &ne) {
		return true
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code == api.CodeUnavailable || ae.Code == api.CodeOutcomeUnknown
	}
	var ro *ReadOnlyError
	if errors.As(err, &ro) && (ro.Reason == ReasonOffline || ro.Reason == ReasonStale || ro.Reason == ReasonOlder) {
		return true
	}
	var rs *RestoredStateError
	return errors.As(err, &rs)
}

// OutcomeUnknown reports whether a mutation may have been applied.
func OutcomeUnknown(err error) bool {
	var ne *NetworkError
	if errors.As(err, &ne) {
		return ne.OutcomeUnknown
	}
	return IsCode(err, api.CodeOutcomeUnknown)
}

// Read-only reasons.
const (
	ReasonOffline = "offline"
	ReasonStale   = "stale"
	ReasonViewer  = "viewer"
	// ReasonOlder: the servers show older data than this device has seen.
	ReasonOlder = "older"
)

// ReadOnlyError is returned when a write is refused locally.
type ReadOnlyError struct{ Reason string }

func (e *ReadOnlyError) Error() string {
	switch e.Reason {
	case ReasonOffline:
		return "no server can be reached, so nothing can be saved (saving needs a majority of servers)"
	case ReasonOlder:
		return "the servers show older data than this device has already seen, so nothing can be saved; this is expected only if the administrator restored a backup (see `fvault recover`)"
	case ReasonStale:
		return "the servers cannot reach a majority right now, so this view may be out of date and nothing can be saved (saving needs a majority of servers)"
	case ReasonViewer:
		return "you have read-only (viewer) access to this vault"
	default:
		return "the session is locked"
	}
}

// ErrWrongPassword is returned when the master password does not open the account.
var ErrWrongPassword = errors.New("wrong username or password")

// ErrNoCache means there is no offline copy for the account on this device.
var ErrNoCache = errors.New("there is no offline copy of this account on this device; connect to a server and run `fvault login` first")

// ErrSessionExpired means the token was refused and a re-login failed
// (password changed elsewhere, sessions revoked, user disabled).
var ErrSessionExpired = errors.New("your session ended (it expired, was revoked, or the password was changed elsewhere); run `fvault login` again")

// ErrLocked is returned by every method of a Session after Lock.
var ErrLocked = errors.New("the session is locked")

// KeyMismatchError: what a server (or a roster) presents for a known user
// contradicts the (userID, username, publicKey) triple in the local trust
// store. Hard error (crypto.md §6.2): nothing is wrapped to, or accepted from,
// that user, and there is deliberately no "accept the new key" operation,
// since key pairs never change in v1.
type KeyMismatchError struct {
	UserID, Username   string
	Kind               string
	PinnedFingerprint  string
	OfferedFingerprint string
}

func (e *KeyMismatchError) Error() string {
	what := "the encryption key"
	switch e.Kind {
	case MismatchUsername:
		what = "the username"
	case MismatchUserID:
		what = "the account"
	}
	return fmt.Sprintf("WARNING: %s the server presents for %q is different from the one this device saw before "+
		"(trusted %s, offered %s). Someone may be trying to impersonate them or the server is compromised. "+
		"Nothing has been shared with, or accepted from, it. Contact them through another channel and do not proceed.",
		what, e.Username, e.PinnedFingerprint, e.OfferedFingerprint)
}

// ProtocolError: a server response is invalid or inconsistent with what this
// client unlocked or trusts (crypto.md §4, §6.2). The whole response was
// rejected; nothing was applied.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string {
	return "the server sent an invalid or inconsistent response: " + e.Msg
}

// RestoredStateError: the servers present older data than this device has
// seen (a lower rev, or a vault at a lower key epoch). That is expected ONLY
// if the administrator restored the servers from a backup; a client cannot tell
// it from a rollback attack, so it stops using the server's answers (the
// offline cache stays readable) until the user explicitly accepts the restored
// state (crypto.md §6.4, "Deliberate recovery").
type RestoredStateError struct {
	ServerRev, SeenRev uint64
	LowerEpochVaults   []string // IDs of vaults offered at a lower epoch than recorded
}

func (e *RestoredStateError) Error() string {
	d := ""
	if e.ServerRev < e.SeenRev {
		d = fmt.Sprintf("the servers are at revision %d but this device has already seen revision %d", e.ServerRev, e.SeenRev)
	}
	if len(e.LowerEpochVaults) > 0 {
		if d != "" {
			d += "; "
		}
		d += fmt.Sprintf("%d vault(s) are offered at an older key epoch than this device recorded", len(e.LowerEpochVaults))
	}
	return "the servers are showing OLDER data than this device has seen (" + d + "). This is expected only if the administrator restored the servers from a backup; " +
		"if they did not, do NOT accept it and tell the administrator. Your offline copy stays readable; nothing can be saved. " +
		"If a restore is expected, run `fvault recover --accept-restored-state`."
}

// ErrNothingToRecover means the servers do not show older data.
var ErrNothingToRecover = errors.New("the servers do not show older data than this device has seen; there is nothing to recover")

// RecoveryRefusedError: recovery is never available for key mismatches or for
// a different key at an epoch already recorded; a restore only moves rev and
// epochs backward.
type RecoveryRefusedError struct{ Reason string }

func (e *RecoveryRefusedError) Error() string {
	return "refusing to accept the restored state: " + e.Reason + ". A restored backup can only move the revision and key epochs backward; anything else is a hard error."
}

// UnverifiedUser names a contact whose fingerprint has not been compared.
type UnverifiedUser struct {
	UserID, Username, Fingerprint string
}

// UnverifiedContactError: an operation needs a verified contact.
type UnverifiedContactError struct{ User UnverifiedUser }

func (e *UnverifiedContactError) Error() string {
	return fmt.Sprintf("%s is not a verified contact on this device (fingerprint %s): compare it with them in person or on a phone call, not through this app, and verify it first", e.User.Username, e.User.Fingerprint)
}

// UnverifiedRecipientsError: a rekey would give the new key to people whose
// fingerprints were never compared on this device.
type UnverifiedRecipientsError struct{ Users []UnverifiedUser }

func (e *UnverifiedRecipientsError) Error() string {
	var n []string
	for _, u := range e.Users {
		n = append(n, u.Username)
	}
	return "the new vault key would go to contacts that are not verified on this device: " + strings.Join(n, ", ") + " (compare their fingerprints with them first)"
}

// RosterMismatchError: the server's member list and the authenticated roster
// disagree in a way that makes a rekey unsafe; nothing was changed.
type RosterMismatchError struct{ Details []string }

func (e *RosterMismatchError) Error() string {
	return "the server's member list does not match the vault's own signed member list: " + strings.Join(e.Details, "; ") + " (nothing was changed)"
}

// ErrRosterBroken means the vault's roster does not open or parse; an owner can rebuild it with a repair rekey.
var ErrRosterBroken = errors.New("this vault's member list is unreadable; an owner can rebuild it with `fvault vault rekey --repair`")

// ConflictError: an item changed on the server since the version we based the
// write on (409 version_conflict). The session has already re-synced; nothing
// was overwritten. It carries both versions so the caller can decide.
type ConflictError struct {
	VaultID, ItemID string
	Kind            string // "create" | "update" | "delete"
	// Mine is what we tried to save (nil for delete).
	Mine *ItemView
	// Theirs is the item as it is on the server now (nil if it no longer exists).
	Theirs         *ItemView
	CurrentVersion uint64
}

func (e *ConflictError) Error() string {
	switch {
	case e.Theirs == nil && e.Kind != "create":
		return "this item was deleted somewhere else while you were editing it"
	case e.Kind == "create":
		return "an item with this ID already exists"
	default:
		return "this item was changed somewhere else while you were editing it; nothing was overwritten"
	}
}

// StaleStateError: vault-level state (rename/rekey) raced with another writer;
// the session re-synced, retry.
var ErrStaleState = errors.New("the vault changed while you were working; it has been reloaded, please try again")

// PermissionError is a local permission refusal.
type PermissionError struct{ Msg string }

func (e *PermissionError) Error() string { return e.Msg }

// UserError is a precondition failure the user can fix (unknown user, bad name...).
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }
