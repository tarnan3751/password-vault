package fsm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/tarnan3751/password-vault/internal/api"
)

// Op names carried in Command.Op.
const (
	OpInit            = "init"
	OpRegister        = "register"
	OpChangePassword  = "change_password"
	OpRevokeSessions  = "revoke_sessions"
	OpCreateInvite    = "create_invite"
	OpRevokeInvite    = "revoke_invite"
	OpAdminUpdateUser = "admin_update_user"
	OpCreateVault     = "create_vault"
	OpUpdateVaultMeta = "update_vault_meta"
	OpDeleteVault     = "delete_vault"
	OpPutMember       = "put_member"
	OpRemoveMember    = "remove_member"
	OpRekey           = "rekey"
	OpPutItem         = "put_item"
	OpDeleteItem      = "delete_item"
)

// Command is the envelope of every entry in the Raft log.
//
//	{"op": "...", "req_id": "<32 hex>", "now": <unix ms>, "uid": "<caller or empty>", "ep": <token epoch>, "args": {...}}
//
// Now is chosen by the proposing node so that the state machine never reads
// a clock. UID/Ep identify the caller's session; they are re-checked against
// the state the command executes on (except for init and register, which
// have no caller).
type Command struct {
	Op    string          `json:"op"`
	ReqID string          `json:"req_id"`
	Now   int64           `json:"now"`
	UID   string          `json:"uid"`
	Ep    uint64          `json:"ep"`
	Args  json.RawMessage `json:"args"`
}

// Args is implemented by the argument struct of every op.
type Args interface {
	// Op is the op name these arguments belong to.
	Op() string
	// Validate performs the stateless checks for the op, given the caller's
	// user id ("" for init and register). The server calls it before
	// proposing, the state machine calls it again at apply time; sharing the
	// code guarantees both agree.
	Validate(caller string) *Error
}

// binder is implemented by the arguments of ops whose idempotency binding
// is not simply the arguments: bindingForm returns the value hashed into
// the binding, everything the client chose but not values the handling node
// randomizes per attempt (the verifier salt), so a client retry with the
// same Idempotency-Key matches while a different request does not. Binding
// more than needed only fails closed (a retry is refused as key reuse).
type binder interface{ bindingForm() any }

// EncodeCommand serializes a command for Propose.
func EncodeCommand(reqID string, now int64, uid string, ep uint64, args Args) ([]byte, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Command{Op: args.Op(), ReqID: reqID, Now: now, UID: uid, Ep: ep, Args: raw})
}

var newArgs = map[string]func() Args{
	OpInit:            func() Args { return &InitArgs{} },
	OpRegister:        func() Args { return &RegisterArgs{} },
	OpChangePassword:  func() Args { return &ChangePasswordArgs{} },
	OpRevokeSessions:  func() Args { return &RevokeSessionsArgs{} },
	OpCreateInvite:    func() Args { return &CreateInviteArgs{} },
	OpRevokeInvite:    func() Args { return &RevokeInviteArgs{} },
	OpAdminUpdateUser: func() Args { return &AdminUpdateUserArgs{} },
	OpCreateVault:     func() Args { return &CreateVaultArgs{} },
	OpUpdateVaultMeta: func() Args { return &UpdateVaultMetaArgs{} },
	OpDeleteVault:     func() Args { return &DeleteVaultArgs{} },
	OpPutMember:       func() Args { return &PutMemberArgs{} },
	OpRemoveMember:    func() Args { return &RemoveMemberArgs{} },
	OpRekey:           func() Args { return &RekeyArgs{} },
	OpPutItem:         func() Args { return &PutItemArgs{} },
	OpDeleteItem:      func() Args { return &DeleteItemArgs{} },
}

// ---------------------------------------------------------------------------
// Argument types
// ---------------------------------------------------------------------------

// InitArgs creates the cluster key. The first init applied wins; later ones
// are no-ops.
type InitArgs struct {
	ClusterKey []byte `json:"cluster_key"`
}

func (*InitArgs) Op() string { return OpInit }
func (a *InitArgs) Validate(string) *Error {
	if len(a.ClusterKey) != ClusterKeyBytes {
		return badRequest("cluster_key must be 32 bytes")
	}
	return nil
}

// The key itself is deliberately not part of the binding, so that no digest
// of it ends up in the idempotency table (and hence in backups, which omit
// the key).
func (a *InitArgs) bindingForm() any { return struct{}{} }

// RegisterArgs creates a user and their personal vault atomically.
// Exactly one of Bootstrap and InviteHash is set.
type RegisterArgs struct {
	Bootstrap         bool                   `json:"bootstrap,omitempty"`
	InviteHash        string                 `json:"invite_hash,omitempty"` // hex SHA-256 of the canonical invite code
	UserID            string                 `json:"user_id"`
	Username          string                 `json:"username"` // canonical
	KDF               api.KDFParams          `json:"kdf"`
	Verifier          Verifier               `json:"verifier"`
	PublicKey         []byte                 `json:"public_key"`
	WrappedAccountKey []byte                 `json:"wrapped_account_key"`
	EncPrivateKey     []byte                 `json:"enc_private_key"`
	PersonalVault     api.CreateVaultRequest `json:"personal_vault"`
}

func (*RegisterArgs) Op() string { return OpRegister }
func (a *RegisterArgs) Validate(string) *Error {
	if a.Bootstrap {
		if a.InviteHash != "" {
			return badRequest("a bootstrap registration must not carry an invite")
		}
	} else if !ValidInviteHash(a.InviteHash) {
		return newErr(api.CodeInvalidInvite, "invalid invite")
	}
	pv := a.PersonalVault
	return firstErr(
		checkID("user_id", a.UserID),
		check(ValidUsername(a.Username), "username must match ^[a-z0-9][a-z0-9._-]{0,31}$"),
		ValidateKDF(a.KDF),
		a.Verifier.validate(),
		check(len(a.PublicKey) == PublicKeyBytes, "public_key must be 32 bytes"),
		validateBox("wrapped_account_key", a.WrappedAccountKey, MaxAccountBlobBytes),
		validateBox("enc_private_key", a.EncPrivateKey, MaxAccountBlobBytes),
		checkID("personal_vault.vault_id", pv.VaultID),
		validateBox("personal_vault.enc_meta", pv.EncMeta, MaxEncMetaBytes),
		validateBox("personal_vault.enc_roster", pv.EncRoster, MaxRosterBytes),
		validateWrappedKey("personal_vault.wrapped_key", pv.WrappedKey, a.UserID),
	)
}
func (a *RegisterArgs) bindingForm() any {
	b := *a
	b.Verifier = Verifier{}
	return b
}

// ChangePasswordArgs replaces the caller's KDF parameters, wrapped account
// key and verifier, and bumps the token epoch. The envelope's ep acts as a
// compare-and-swap: every verifier change bumps the epoch, so ep matching
// proves the handler checked the current password against the verifier that
// is still current.
type ChangePasswordArgs struct {
	NewKDF               api.KDFParams `json:"new_kdf"`
	NewWrappedAccountKey []byte        `json:"new_wrapped_account_key"`
	Verifier             Verifier      `json:"verifier"`
}

func (*ChangePasswordArgs) Op() string { return OpChangePassword }
func (a *ChangePasswordArgs) Validate(string) *Error {
	return firstErr(ValidateKDF(a.NewKDF), a.Verifier.validate(),
		validateBox("new_wrapped_account_key", a.NewWrappedAccountKey, MaxAccountBlobBytes))
}
func (a *ChangePasswordArgs) bindingForm() any {
	b := *a
	b.Verifier = Verifier{}
	return b
}

// RevokeSessionsArgs bumps the caller's token epoch.
type RevokeSessionsArgs struct{}

func (*RevokeSessionsArgs) Op() string             { return OpRevokeSessions }
func (*RevokeSessionsArgs) Validate(string) *Error { return nil }

// CreateInviteArgs stores the hash of a new invite code (admin only).
type CreateInviteArgs struct {
	InviteHash string `json:"invite_hash"`
	TTLHours   int    `json:"ttl_hours"` // 1..720; the server maps 0 to the default
}

func (*CreateInviteArgs) Op() string { return OpCreateInvite }
func (a *CreateInviteArgs) Validate(string) *Error {
	return firstErr(check(ValidInviteHash(a.InviteHash), "invalid invite hash"),
		check(a.TTLHours >= 1 && a.TTLHours <= MaxInviteTTLHours, "ttl_hours must be between 1 and 720"))
}

// RevokeInviteArgs revokes an unused invite (admin only).
type RevokeInviteArgs struct {
	InviteID string `json:"invite_id"`
}

func (*RevokeInviteArgs) Op() string { return OpRevokeInvite }
func (a *RevokeInviteArgs) Validate(string) *Error {
	return check(ValidInviteID(a.InviteID), "invite_id must be 16 lowercase hex characters")
}

// AdminUpdateUserArgs disables/enables a user and grants/revokes admin.
type AdminUpdateUserArgs struct {
	UserID   string `json:"user_id"`
	Disabled *bool  `json:"disabled,omitempty"`
	IsAdmin  *bool  `json:"is_admin,omitempty"`
}

func (*AdminUpdateUserArgs) Op() string { return OpAdminUpdateUser }
func (a *AdminUpdateUserArgs) Validate(string) *Error {
	return firstErr(checkID("user id", a.UserID),
		check(a.Disabled != nil || a.IsAdmin != nil, "nothing to update: set disabled and/or is_admin"))
}

// CreateVaultArgs creates a shared vault owned by the caller.
type CreateVaultArgs struct {
	VaultID    string         `json:"vault_id"`
	EncMeta    []byte         `json:"enc_meta"`
	EncRoster  []byte         `json:"enc_roster"`
	WrappedKey api.WrappedKey `json:"wrapped_key"`
}

func (*CreateVaultArgs) Op() string { return OpCreateVault }
func (a *CreateVaultArgs) Validate(caller string) *Error {
	return firstErr(checkID("vault_id", a.VaultID), validateBox("enc_meta", a.EncMeta, MaxEncMetaBytes),
		validateBox("enc_roster", a.EncRoster, MaxRosterBytes), validateWrappedKey("wrapped_key", a.WrappedKey, caller))
}

// UpdateVaultMetaArgs replaces enc_meta with a compare-and-swap on meta_version.
type UpdateVaultMetaArgs struct {
	VaultID         string `json:"vault_id"`
	EncMeta         []byte `json:"enc_meta"`
	BaseMetaVersion uint64 `json:"base_meta_version"`
}

func (*UpdateVaultMetaArgs) Op() string { return OpUpdateVaultMeta }
func (a *UpdateVaultMetaArgs) Validate(string) *Error {
	return firstErr(checkID("vault id", a.VaultID), validateBox("enc_meta", a.EncMeta, MaxEncMetaBytes))
}

// DeleteVaultArgs deletes a shared vault with its items and memberships.
type DeleteVaultArgs struct {
	VaultID string `json:"vault_id"`
}

func (*DeleteVaultArgs) Op() string               { return OpDeleteVault }
func (a *DeleteVaultArgs) Validate(string) *Error { return checkID("vault id", a.VaultID) }

// PutMemberArgs adds a member (WrappedKey set) or changes a role (WrappedKey
// nil). Either way EncRoster replaces the vault's roster, with a
// compare-and-swap on BaseRosterVersion.
type PutMemberArgs struct {
	VaultID           string          `json:"vault_id"`
	UserID            string          `json:"user_id"`
	Role              string          `json:"role"`
	WrappedKey        *api.WrappedKey `json:"wrapped_key,omitempty"`
	KeyEpoch          uint32          `json:"key_epoch"`
	EncRoster         []byte          `json:"enc_roster"`
	BaseRosterVersion uint64          `json:"base_roster_version"`
}

func (*PutMemberArgs) Op() string { return OpPutMember }
func (a *PutMemberArgs) Validate(caller string) *Error {
	if e := firstErr(checkID("vault id", a.VaultID), checkID("user id", a.UserID),
		check(ValidRole(a.Role), "role must be owner, editor or viewer"),
		validateBox("enc_roster", a.EncRoster, MaxRosterBytes)); e != nil || a.WrappedKey == nil {
		return e
	}
	return validateWrappedKey("wrapped_key", *a.WrappedKey, caller)
}

// RemoveMemberArgs removes a member (or the caller leaves).
type RemoveMemberArgs struct {
	VaultID string `json:"vault_id"`
	UserID  string `json:"user_id"`
}

func (*RemoveMemberArgs) Op() string { return OpRemoveMember }
func (a *RemoveMemberArgs) Validate(string) *Error {
	return firstErr(checkID("vault id", a.VaultID), checkID("user id", a.UserID))
}

// RekeyArgs atomically removes the members in Remove and replaces the
// vault's key: metadata, roster, every remaining member's wrapped key and
// every item blob.
type RekeyArgs struct {
	VaultID     string                    `json:"vault_id"`
	BaseRev     uint64                    `json:"base_rev"`
	NewKeyEpoch uint32                    `json:"new_key_epoch"`
	Remove      []string                  `json:"remove,omitempty"`
	EncMeta     []byte                    `json:"enc_meta"`
	EncRoster   []byte                    `json:"enc_roster"`
	WrappedKeys map[string]api.WrappedKey `json:"wrapped_keys"`
	Items       []api.RekeyItem           `json:"items"`
}

func (*RekeyArgs) Op() string { return OpRekey }
func (a *RekeyArgs) Validate(caller string) *Error {
	if e := firstErr(checkID("vault id", a.VaultID), validateBox("enc_meta", a.EncMeta, MaxEncMetaBytes),
		validateBox("enc_roster", a.EncRoster, MaxRosterBytes)); e != nil {
		return e
	}
	removed := make(map[string]struct{}, len(a.Remove))
	for _, uid := range a.Remove {
		if !ValidID(uid) {
			return badRequest("remove must list user ids")
		}
		if uid == caller {
			return badRequest("the caller cannot remove themself by rekeying; leave the vault instead")
		}
		if _, dup := removed[uid]; dup {
			return badRequest("duplicate user id in remove")
		}
		removed[uid] = struct{}{}
	}
	// No count limits here: the exact-cover check at apply time bounds both
	// sets by the vault's real contents, and a vault restored from a state
	// created under higher limits must still be rekeyable.
	//
	// Iterate in sorted order: different entries can fail with different
	// codes (too_large vs bad_request), and map order would make the result
	// differ between replicas.
	for _, uid := range sortedKeys(a.WrappedKeys) {
		if !ValidID(uid) {
			return badRequest("wrapped_keys must be keyed by user id")
		}
		if e := validateWrappedKey("wrapped_keys[]", a.WrappedKeys[uid], caller); e != nil {
			return e
		}
	}
	seen := make(map[string]struct{}, len(a.Items))
	for _, it := range a.Items {
		if e := checkID("item id", it.ID); e != nil {
			return e
		}
		if _, dup := seen[it.ID]; dup {
			return badRequest("duplicate item id in rekey")
		}
		seen[it.ID] = struct{}{}
		if e := validateBox("items[].blob", it.Blob, MaxItemBlobBytes); e != nil {
			return e
		}
	}
	return nil
}

// PutItemArgs creates (BaseVersion 0) or updates an item.
type PutItemArgs struct {
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	Blob        []byte `json:"blob"`
	BaseVersion uint64 `json:"base_version"`
	KeyEpoch    uint32 `json:"key_epoch"`
}

func (*PutItemArgs) Op() string { return OpPutItem }
func (a *PutItemArgs) Validate(string) *Error {
	return firstErr(checkID("vault id", a.VaultID), checkID("item id", a.ItemID), validateBox("blob", a.Blob, MaxItemBlobBytes))
}

// DeleteItemArgs deletes an item with a compare-and-swap on its version.
type DeleteItemArgs struct {
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	BaseVersion uint64 `json:"base_version"`
}

func (*DeleteItemArgs) Op() string { return OpDeleteItem }
func (a *DeleteItemArgs) Validate(string) *Error {
	return firstErr(checkID("vault id", a.VaultID), checkID("item id", a.ItemID), check(a.BaseVersion != 0, "base_version is required"))
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// Outcome is the payload of a successful command. Which fields are set
// depends on the op.
type Outcome struct {
	Rev     uint64 `json:"rev"`
	Version uint64 `json:"version,omitempty"` // put_item: new item version; create_vault/update_vault_meta: meta_version

	// register, change_password, revoke_sessions.
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	IsAdmin  bool   `json:"is_admin,omitempty"`
	Epoch    uint64 `json:"ep,omitempty"`
	// register, change_password: the verifier now stored, so that a handler
	// receiving a de-duplicated (replayed) result can make the client prove
	// knowledge of the login key before minting a token. Never sent to clients.
	Verifier *Verifier `json:"verifier,omitempty"`

	// create_invite.
	InviteID  string `json:"invite_id,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// Result is the JSON returned by Apply: exactly one of OK and Err is set.
type Result struct {
	OK  *Outcome `json:"ok,omitempty"`
	Err *Error   `json:"err,omitempty"`
}

// DecodeResult parses the bytes returned by Apply (or relayed by Propose).
func DecodeResult(b []byte) (*Result, error) {
	var r Result
	if err := strictUnmarshal(b, &r); err != nil {
		return nil, err
	}
	if (r.OK == nil) == (r.Err == nil) {
		return nil, errors.New("fsm: result must have exactly one of ok and err")
	}
	if r.Err != nil && r.Err.Code == "" {
		return nil, errors.New("fsm: error result without code")
	}
	return &r, nil
}

func encodeResult(out *Outcome, e *Error) []byte {
	var r Result
	if e != nil {
		r.Err = e
	} else {
		r.OK = out
	}
	b, err := json.Marshal(r)
	if err != nil {
		// Unreachable: Result contains only plain strings, numbers and
		// []byte. Kept deterministic anyway.
		return []byte(`{"err":{"code":"internal","message":"cannot encode result"}}`)
	}
	return b
}

// strictUnmarshal decodes exactly one JSON value, rejecting unknown fields
// and trailing data. Apply never trusts its input, even though it was
// produced by our own server code.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Parsing and idempotency binding
// ---------------------------------------------------------------------------

type parsedCommand struct {
	env     Command
	args    Args   // nil if argErr != nil
	argErr  *Error // unknown op or undecodable args
	key     string // idempotency key: (uid or "anon") + ":" + req_id
	binding string // hex SHA-256 identifying the request
}

// parseCommand decodes the envelope. A nil *parsedCommand with an error
// means the command cannot even be keyed for idempotency; such commands are
// rejected without being recorded (they change nothing, so re-applying them
// is harmless and yields the same error).
func parseCommand(cmd []byte) (*parsedCommand, *Error) {
	if len(cmd) > MaxCommandBytes {
		return nil, tooLarge("command too large")
	}
	var env Command
	if err := strictUnmarshal(cmd, &env); err != nil {
		return nil, badRequest("malformed command")
	}
	if !ValidID(env.ReqID) {
		return nil, badRequest("invalid req_id")
	}
	if env.UID != "" && !ValidID(env.UID) {
		return nil, badRequest("invalid uid")
	}
	if env.Now <= 0 || env.Now > maxNowMs {
		return nil, badRequest("invalid timestamp")
	}
	owner := env.UID
	if owner == "" {
		owner = "anon"
	}
	p := &parsedCommand{env: env, key: owner + ":" + env.ReqID}
	mk := newArgs[env.Op]
	if mk == nil {
		p.argErr = badRequest("unknown op")
		p.binding = rawBinding(env.Op, env.Args)
		return p, nil
	}
	a := mk()
	if err := strictUnmarshal(env.Args, a); err != nil {
		p.argErr = badRequest("malformed arguments")
		p.binding = rawBinding(env.Op, env.Args)
		return p, nil
	}
	p.args = a
	p.binding = argsBinding(a)
	return p, nil
}

func argsBinding(a Args) string {
	var form any = a
	if b, ok := a.(binder); ok {
		form = b.bindingForm()
	}
	j, err := json.Marshal(form)
	if err != nil {
		return rawBinding(a.Op(), nil)
	}
	h := sha256.New()
	h.Write([]byte(a.Op()))
	h.Write([]byte{0})
	h.Write(j)
	return hex.EncodeToString(h.Sum(nil))
}

func rawBinding(op string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(op))
	h.Write([]byte{1})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func validIdemKey(k string) bool {
	if len(k) < 34 || k[len(k)-33] != ':' {
		return false
	}
	owner, req := k[:len(k)-33], k[len(k)-32:]
	return ValidID(req) && (owner == "anon" || ValidID(owner))
}
