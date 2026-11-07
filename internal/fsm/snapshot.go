package fsm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"strconv"

	"github.com/tarnan3751/password-vault/internal/api"
)

// Snapshot format identifiers.
const (
	SnapshotFormat  = "fpv-state"
	SnapshotVersion = 1
)

// snapshotDoc is the canonical serialized state. Every collection is a
// slice sorted by id (the idempotency table in FIFO order), so equal states
// always produce identical bytes.
type snapshotDoc struct {
	Format      string      `json:"format"`
	Version     int         `json:"version"`
	Rev         uint64      `json:"rev"`
	ClusterKey  []byte      `json:"cluster_key,omitempty"`
	Users       []user      `json:"users"`
	Invites     []invite    `json:"invites"`
	Vaults      []snapVault `json:"vaults"`
	Idempotency []idemEntry `json:"idempotency"`
}

type snapVault struct {
	ID               string   `json:"id"`
	Creator          string   `json:"creator"`
	Personal         bool     `json:"personal"`
	KeyEpoch         uint32   `json:"key_epoch"`
	EncMeta          []byte   `json:"enc_meta"`
	MetaVersion      uint64   `json:"meta_version"`
	EncRoster        []byte   `json:"enc_roster"`
	RosterVersion    uint64   `json:"roster_version"`
	Rev              uint64   `json:"rev"`
	RekeyRecommended bool     `json:"rekey_recommended"`
	Members          []member `json:"members"`
	Items            []item   `json:"items"`
}

// Snapshot serializes the complete state (raft.StateMachine).
func (f *FSM) Snapshot() ([]byte, error) {
	b, _ := f.snapshot(true)
	return b, nil
}

// BackupSnapshot returns a snapshot WITHOUT the cluster key, plus the rev it
// reflects. The cluster key signs every session token; leaving it out means
// a leaked backup file cannot be used to impersonate anyone. A cluster
// seeded from such a snapshot generates a new key (init), so all users
// simply log in again.
func (f *FSM) BackupSnapshot() ([]byte, uint64, error) {
	b, rev := f.snapshot(false)
	return b, rev, nil
}

// snapshot encodes the state and returns the rev it reflects. The lock is
// held only while the document is laid out: the document holds copies of
// every record and shares only byte slices, which the state never modifies,
// so the encoding (most of the time) can run without it. Otherwise a backup
// would make Apply, and with it the Raft event loop and every reader queued
// behind the pending writer, wait for the whole encoding.
func (f *FSM) snapshot(withKey bool) ([]byte, uint64) {
	f.mu.RLock()
	d, rev, hint := f.s.doc(withKey), f.s.rev, f.s.snapshotSizeHint()
	f.mu.RUnlock()
	e := &snapEncoder{buf: make([]byte, 0, hint)}
	d.fields(e)
	return e.buf, rev
}

// Restore replaces the complete state (raft.StateMachine). The snapshot is
// fully validated first; on error the current state is left untouched.
func (f *FSM) Restore(data []byte) error {
	s, err := decodeSnapshot(data, &f.lim)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.s = s
	f.mu.Unlock()
	return nil
}

// ValidateSnapshot checks that data is a well-formed snapshot that Restore
// would accept (used by `vaultd restore` before seeding a cluster).
func ValidateSnapshot(data []byte) error {
	_, err := decodeSnapshot(data, &defaultLimits)
	return err
}

// doc lays the state out as a snapshotDoc, sorted: copies of the records,
// sharing the state's byte slices (which are never modified in place).
func (s *state) doc(withKey bool) *snapshotDoc {
	d := &snapshotDoc{
		Format: SnapshotFormat, Version: SnapshotVersion, Rev: s.rev,
		Users: make([]user, 0, len(s.users)), Invites: make([]invite, 0, len(s.invites)),
		Vaults: make([]snapVault, 0, len(s.vaults)), Idempotency: make([]idemEntry, 0, len(s.idemOrder)),
	}
	if withKey {
		d.ClusterKey = s.clusterKey
	}
	for _, id := range sortedKeys(s.users) {
		d.Users = append(d.Users, *s.users[id])
	}
	for _, id := range sortedKeys(s.invites) {
		d.Invites = append(d.Invites, *s.invites[id])
	}
	for _, id := range sortedKeys(s.vaults) {
		v := s.vaults[id]
		sv := snapVault{
			ID: v.ID, Creator: v.Creator, Personal: v.Personal, KeyEpoch: v.KeyEpoch,
			EncMeta: v.EncMeta, MetaVersion: v.MetaVersion, EncRoster: v.EncRoster, RosterVersion: v.RosterVersion,
			Rev: v.Rev, RekeyRecommended: v.RekeyRecommended,
			Members: make([]member, 0, len(v.Members)),
			Items:   make([]item, 0, len(v.Items)),
		}
		for _, uid := range sortedKeys(v.Members) {
			sv.Members = append(sv.Members, *v.Members[uid])
		}
		for _, iid := range sortedKeys(v.Items) {
			sv.Items = append(sv.Items, *v.Items[iid])
		}
		d.Vaults = append(d.Vaults, sv)
	}
	for _, k := range s.idemOrder {
		d.Idempotency = append(d.Idempotency, *s.idem[k])
	}
	return d
}

// snapshotSizeHint slightly overestimates the encoded size, so that the
// encoder allocates its buffer once: base64 of every stored byte (vault
// usage already includes 128 bytes per item, more than an item's JSON
// framing) plus generous allowances for the other records.
func (s *state) snapshotSizeHint() int {
	n := 1024 + 1024*len(s.users) + 320*len(s.invites)
	for _, v := range s.vaults {
		n += int(v.bytes/3*4) + 400 + 320*len(v.Members)
	}
	for _, e := range s.idem {
		n += 180 + (len(e.Result)+2)/3*4
	}
	return n
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// fields is the canonical snapshot encoding, written once for both
// directions: snapEncoder produces exactly what json.Marshal produces for
// the document (TestSnapshotEncoderMatchesEncodingJSON holds the two
// together) and snapDecoder reads exactly that. Each call handles one value;
// its first argument is everything that precedes the value (punctuation and
// key).
//
// It is written by hand because snapshots are taken and restored on the
// Raft event loop, under the state lock, at up to 75 MiB: this needs no
// reflection, a single output buffer, one pass over the input, and lets
// StateHash stream the encoding into the hash. It also pins the bytes, and
// with them StateHash, in this package rather than in the JSON library.
func (d *snapshotDoc) fields(c codec) {
	c.str(`{"format":`, &d.Format)
	version := int64(d.Version)
	c.num(`,"version":`, &version)
	d.Version = int(version)
	c.num(`,"rev":`, &d.Rev)
	if c.has(`,"cluster_key":`, len(d.ClusterKey) > 0) { // omitempty
		c.bin(`,"cluster_key":`, &d.ClusterKey)
	}
	list(c, `,"users":[`, &d.Users, func(u *user) {
		c.str(`{"id":`, &u.ID)
		c.str(`,"username":`, &u.Username)
		c.str(`,"kdf":{"alg":`, &u.KDF.Alg)
		c.bin(`,"salt":`, &u.KDF.Salt)
		c.num(`,"time":`, &u.KDF.Time)
		c.num(`,"memory_kib":`, &u.KDF.MemoryKiB)
		c.num(`,"parallelism":`, &u.KDF.Parallelism)
		c.bin(`},"verifier":{"salt":`, &u.Verifier.Salt)
		c.num(`,"t":`, &u.Verifier.Time)
		c.num(`,"m":`, &u.Verifier.MemoryKiB)
		c.num(`,"p":`, &u.Verifier.Parallelism)
		c.bin(`,"hash":`, &u.Verifier.Hash)
		c.bin(`},"public_key":`, &u.PublicKey)
		c.bin(`,"wrapped_account_key":`, &u.WrappedAccountKey)
		c.bin(`,"enc_private_key":`, &u.EncPrivateKey)
		c.flag(`,"is_admin":`, &u.IsAdmin)
		c.flag(`,"disabled":`, &u.Disabled)
		c.num(`,"token_epoch":`, &u.TokenEpoch)
		c.num(`,"created_at":`, &u.CreatedAt)
		c.lit(`}`)
	})
	list(c, `],"invites":[`, &d.Invites, func(inv *invite) {
		c.str(`{"id":`, &inv.ID)
		c.str(`,"hash":`, &inv.Hash)
		c.str(`,"created_by":`, &inv.CreatedBy)
		c.num(`,"created_at":`, &inv.CreatedAt)
		c.num(`,"expires_at":`, &inv.ExpiresAt)
		if c.has(`,"used_by":`, inv.UsedBy != "") { // omitempty
			c.str(`,"used_by":`, &inv.UsedBy)
		}
		if c.has(`,"revoked":`, inv.Revoked) { // omitempty
			c.flag(`,"revoked":`, &inv.Revoked)
		}
		c.lit(`}`)
	})
	list(c, `],"vaults":[`, &d.Vaults, func(v *snapVault) {
		c.str(`{"id":`, &v.ID)
		c.str(`,"creator":`, &v.Creator)
		c.flag(`,"personal":`, &v.Personal)
		c.num(`,"key_epoch":`, &v.KeyEpoch)
		c.bin(`,"enc_meta":`, &v.EncMeta)
		c.num(`,"meta_version":`, &v.MetaVersion)
		c.bin(`,"enc_roster":`, &v.EncRoster)
		c.num(`,"roster_version":`, &v.RosterVersion)
		c.num(`,"rev":`, &v.Rev)
		c.flag(`,"rekey_recommended":`, &v.RekeyRecommended)
		list(c, `,"members":[`, &v.Members, func(m *member) {
			c.str(`{"user_id":`, &m.UserID)
			c.str(`,"role":`, &m.Role)
			c.str(`,"wrapped_key":{"sender_id":`, &m.WrappedKey.SenderID)
			c.bin(`,"blob":`, &m.WrappedKey.Blob)
			c.str(`},"added_by":`, &m.AddedBy)
			c.lit(`}`)
		})
		list(c, `],"items":[`, &v.Items, func(it *item) {
			c.str(`{"id":`, &it.ID)
			c.bin(`,"blob":`, &it.Blob)
			c.num(`,"version":`, &it.Version)
			c.num(`,"updated_at":`, &it.UpdatedAt)
			c.str(`,"updated_by":`, &it.UpdatedBy)
			c.lit(`}`)
		})
		c.lit(`]}`)
	})
	list(c, `],"idempotency":[`, &d.Idempotency, func(r *idemEntry) {
		c.str(`{"key":`, &r.Key)
		c.str(`,"binding":`, &r.Binding)
		c.bin(`,"result":`, &r.Result)
		c.lit(`}`)
	})
	c.lit(`]}`)
}

// codec is one direction of the snapshot encoding (see fields).
type codec interface {
	lit(s string)
	str(lit string, p *string)
	bin(lit string, p *[]byte)
	num(lit string, p any) // *uint64, *uint32, *uint8 or *int64
	flag(lit string, p *bool)
	// has reports whether an omitempty field is present: when encoding, if
	// nonEmpty; when decoding, if the input continues with lit.
	has(lit string, nonEmpty bool) bool
	// elems handles an array that starts with lit: n elements when
	// encoding, as many as there are when decoding.
	elems(lit string, n int, elem func(i int))
}

func list[T any](c codec, lit string, s *[]T, elem func(*T)) {
	if *s == nil {
		*s = []T{} // as encoding/json decodes []
	}
	c.elems(lit, len(*s), func(i int) {
		if i == len(*s) {
			*s = append(*s, *new(T))
		}
		elem(&(*s)[i])
	})
}

// snapEncoder appends JSON exactly as encoding/json encodes these field
// types. If h is set, the buffer is fed to h in chunks (the caller writes
// the rest); otherwise it accumulates the whole encoding.
type snapEncoder struct {
	buf []byte
	h   hash.Hash
}

func (e *snapEncoder) lit(s string) { e.buf = append(e.buf, s...) }

func (e *snapEncoder) has(_ string, nonEmpty bool) bool { return nonEmpty }

func (e *snapEncoder) flag(lit string, p *bool) {
	e.buf = strconv.AppendBool(append(e.buf, lit...), *p)
}

func (e *snapEncoder) num(lit string, p any) {
	e.buf = append(e.buf, lit...)
	switch n := p.(type) {
	case *uint64:
		e.buf = strconv.AppendUint(e.buf, *n, 10)
	case *uint32:
		e.buf = strconv.AppendUint(e.buf, uint64(*n), 10)
	case *uint8:
		e.buf = strconv.AppendUint(e.buf, uint64(*n), 10)
	case *int64:
		e.buf = strconv.AppendInt(e.buf, *n, 10)
	}
}

// bin encodes []byte as encoding/json does: standard base64 with padding,
// and null for a nil slice.
func (e *snapEncoder) bin(lit string, p *[]byte) {
	e.buf = append(e.buf, lit...)
	if *p == nil {
		e.buf = append(e.buf, "null"...)
		return
	}
	e.buf = append(base64.StdEncoding.AppendEncode(append(e.buf, '"'), *p), '"')
}

// str encodes a string. Everything the state stores is validated to be
// plain ASCII that needs no escaping; anything else (only reachable from a
// bug) is encoded by encoding/json itself, so the bytes always agree.
func (e *snapEncoder) str(lit string, p *string) {
	e.buf = append(e.buf, lit...)
	if !plainASCII(*p) {
		q, _ := json.Marshal(*p) // cannot fail for a string
		e.buf = append(e.buf, q...)
		return
	}
	e.buf = append(append(append(e.buf, '"'), *p...), '"')
}

func (e *snapEncoder) elems(lit string, n int, elem func(int)) {
	e.lit(lit)
	for i := range n {
		if i > 0 {
			e.buf = append(e.buf, ',')
		}
		elem(i)
		if e.h != nil && len(e.buf) >= 32<<10 {
			e.h.Write(e.buf)
			e.buf = e.buf[:0]
		}
	}
}

// plainASCII reports whether s is printable ASCII that encoding/json writes
// verbatim (it escapes '"', '\\' and, for HTML safety, '<', '>' and '&').
func plainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}

// snapDecoder reads the canonical encoding and nothing else. Any deviation
// (whitespace, escapes, other key order or case, null, a number out of
// range, trailing data...) only sets failed, and decodeSnapshot then decodes
// with encoding/json instead, so which snapshots are accepted, and what they
// mean, is decided exactly as before; this is only the fast path.
type snapDecoder struct {
	b      []byte
	failed bool
}

func (d *snapDecoder) fail() { d.failed, d.b = true, nil }

func (d *snapDecoder) has(lit string, _ bool) bool {
	return len(d.b) >= len(lit) && string(d.b[:len(lit)]) == lit
}

func (d *snapDecoder) lit(s string) {
	if !d.has(s, false) {
		d.fail()
		return
	}
	d.b = d.b[len(s):]
}

// quoted consumes a string and returns its contents, which must be plain
// ASCII (as plainASCII) if ascii is set. Without the check, the contents
// may hold anything but '"'; base64 decoding then refuses escapes.
func (d *snapDecoder) quoted(ascii bool) []byte {
	if len(d.b) == 0 || d.b[0] != '"' {
		d.fail()
		return nil
	}
	n := bytes.IndexByte(d.b[1:], '"')
	if n < 0 || ascii && !plainASCII(string(d.b[1:1+n])) {
		d.fail()
		return nil
	}
	s := d.b[1 : 1+n]
	d.b = d.b[2+n:]
	return s
}

func (d *snapDecoder) str(lit string, p *string) {
	d.lit(lit)
	if s := d.quoted(true); !d.failed {
		*p = string(s)
	}
}

func (d *snapDecoder) bin(lit string, p *[]byte) {
	d.lit(lit)
	if d.has("null", false) {
		d.b, *p = d.b[4:], nil
		return
	}
	s := d.quoted(false)
	if d.failed || len(s) == 0 {
		d.fail() // "" is left to encoding/json, which decodes it to a non-nil empty slice
		return
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(out, s)
	// Decode skips newlines; a canonical encoding has none.
	if err != nil || base64.StdEncoding.EncodedLen(n) != len(s) {
		d.fail()
		return
	}
	*p = out[:n]
}

func (d *snapDecoder) num(lit string, p any) {
	d.lit(lit)
	neg := len(d.b) > 0 && d.b[0] == '-'
	if neg {
		d.b = d.b[1:]
	}
	// At most 19 digits, so v cannot overflow; no leading zeros, no "-0".
	var v uint64
	n := 0
	for ; n < len(d.b) && n < 20 && '0' <= d.b[n] && d.b[n] <= '9'; n++ {
		v = v*10 + uint64(d.b[n]-'0')
	}
	ok := n > 0 && n < 20 && (n == 1 || d.b[0] != '0') && !(neg && v == 0)
	d.b = d.b[n:]
	switch q := p.(type) {
	case *uint64:
		*q, ok = v, ok && !neg
	case *uint32:
		*q, ok = uint32(v), ok && !neg && v <= math.MaxUint32
	case *uint8:
		*q, ok = uint8(v), ok && !neg && v <= math.MaxUint8
	case *int64:
		*q, ok = int64(v), ok && v <= math.MaxInt64 // the minimum is left to encoding/json
		if neg {
			*q = -*q
		}
	}
	if !ok {
		d.fail()
	}
}

func (d *snapDecoder) flag(lit string, p *bool) {
	d.lit(lit)
	switch {
	case d.has("true", false):
		d.b, *p = d.b[4:], true
	case d.has("false", false):
		d.b, *p = d.b[5:], false
	default:
		d.fail()
	}
}

func (d *snapDecoder) elems(lit string, _ int, elem func(int)) {
	d.lit(lit)
	if d.failed || len(d.b) > 0 && d.b[0] == ']' {
		return // the closing bracket belongs to the next literal
	}
	for i := 0; !d.failed; i++ {
		elem(i)
		if len(d.b) == 0 || d.b[0] != ',' {
			return
		}
		d.b = d.b[1:]
	}
}

func snapErr(format string, args ...any) error {
	return fmt.Errorf("fsm: invalid snapshot: "+format, args...)
}

// decodeSnapshot parses and validates a snapshot into a fresh state. It
// enforces every invariant the state machine maintains, so a restored state
// is indistinguishable from one built by applying commands, and garbage is
// rejected instead of producing a state that later commands mishandle.
func decodeSnapshot(data []byte, lim *limits) (*state, error) {
	doc, ok := decodeCanonical(data)
	if !ok {
		// Not exactly the canonical encoding: let encoding/json decide.
		doc = &snapshotDoc{}
		if err := strictUnmarshal(data, doc); err != nil {
			return nil, snapErr("%v", err)
		}
	}
	// From here on, the byte slices of doc are fresh copies owned by the new
	// state (neither decoder aliases data), so they are not copied again.
	if doc.Format != SnapshotFormat || doc.Version != SnapshotVersion {
		return nil, snapErr("unsupported format %q version %d", doc.Format, doc.Version)
	}
	s := newState(lim)
	s.rev = doc.Rev
	if len(doc.ClusterKey) != 0 {
		if len(doc.ClusterKey) != ClusterKeyBytes {
			return nil, snapErr("cluster key must be 32 bytes")
		}
		s.clusterKey = doc.ClusterKey
	}

	// Count limits and storage quotas are deliberately NOT enforced here:
	// they apply to writes only, so a state created under higher limits (or
	// by an older version) still restores after the limits are lowered.
	for i := range doc.Users {
		u := doc.Users[i]
		if i > 0 && doc.Users[i-1].ID >= u.ID {
			return nil, snapErr("users not sorted by id")
		}
		if err := validateSnapUser(&u); err != nil {
			return nil, err
		}
		if _, dup := s.byName[u.Username]; dup {
			return nil, snapErr("duplicate username")
		}
		s.users[u.ID] = &u
		s.byName[u.Username] = u.ID
	}
	userExists := func(id string) bool { return s.users[id] != nil }

	usedBy := map[string]bool{}
	for i := range doc.Invites {
		inv := doc.Invites[i]
		if i > 0 && doc.Invites[i-1].ID >= inv.ID {
			return nil, snapErr("invites not sorted by id")
		}
		if !ValidInviteHash(inv.Hash) || inv.ID != inv.Hash[:16] {
			return nil, snapErr("invalid invite id or hash")
		}
		if !userExists(inv.CreatedBy) || inv.CreatedAt <= 0 || inv.ExpiresAt <= inv.CreatedAt {
			return nil, snapErr("invalid invite %s", inv.ID)
		}
		if inv.UsedBy != "" {
			if !userExists(inv.UsedBy) || usedBy[inv.UsedBy] {
				return nil, snapErr("invalid invite user %s", inv.ID)
			}
			usedBy[inv.UsedBy] = true
		}
		s.invites[inv.ID] = &inv
	}

	personal := map[string]bool{}
	for i := range doc.Vaults {
		sv := &doc.Vaults[i]
		if i > 0 && doc.Vaults[i-1].ID >= sv.ID {
			return nil, snapErr("vaults not sorted by id")
		}
		v, err := restoreVault(sv, s.rev, userExists)
		if err != nil {
			return nil, err
		}
		if v.Personal {
			if personal[v.Creator] {
				return nil, snapErr("user has two personal vaults")
			}
			personal[v.Creator] = true
		}
		s.vaults[v.ID] = v
	}
	if len(personal) != len(s.users) {
		return nil, snapErr("every user must have exactly one personal vault")
	}

	if len(doc.Idempotency) > IdempotencyCapacity {
		return nil, snapErr("idempotency table too large")
	}
	for i, e := range doc.Idempotency {
		if !validIdemKey(e.Key) || !ValidInviteHash(e.Binding) {
			return nil, snapErr("invalid idempotency entry")
		}
		if _, dup := s.idem[e.Key]; dup {
			return nil, snapErr("duplicate idempotency key")
		}
		if _, err := DecodeResult(e.Result); err != nil {
			return nil, snapErr("invalid idempotency result: %v", err)
		}
		s.idem[e.Key] = &doc.Idempotency[i]
		s.idemOrder = append(s.idemOrder, e.Key)
	}
	return s, nil
}

// decodeCanonical decodes data if it is exactly the canonical encoding.
func decodeCanonical(data []byte) (*snapshotDoc, bool) {
	doc := &snapshotDoc{}
	d := &snapDecoder{b: data}
	doc.fields(d)
	return doc, !d.failed && len(d.b) == 0
}

func validateSnapUser(u *user) error {
	if !ValidID(u.ID) || !ValidUsername(u.Username) {
		return snapErr("invalid user id or username")
	}
	if !validateStoredKDF(u.KDF) || u.Verifier.validate() != nil || len(u.PublicKey) != PublicKeyBytes {
		return snapErr("invalid user %s", u.ID)
	}
	if validateBox("", u.WrappedAccountKey, MaxAccountBlobBytes) != nil || validateBox("", u.EncPrivateKey, MaxAccountBlobBytes) != nil {
		return snapErr("invalid key material for user %s", u.ID)
	}
	if u.TokenEpoch == 0 || u.CreatedAt <= 0 {
		return snapErr("invalid user %s", u.ID)
	}
	return nil
}

func restoreVault(sv *snapVault, rev uint64, userExists func(string) bool) (*vault, error) {
	if !ValidID(sv.ID) || !userExists(sv.Creator) {
		return nil, snapErr("invalid vault id or creator")
	}
	if sv.KeyEpoch == 0 || validateBox("", sv.EncMeta, MaxEncMetaBytes) != nil || validateBox("", sv.EncRoster, MaxRosterBytes) != nil {
		return nil, snapErr("invalid vault %s", sv.ID)
	}
	if sv.MetaVersion == 0 || sv.MetaVersion > sv.Rev || sv.RosterVersion == 0 || sv.RosterVersion > sv.Rev || sv.Rev > rev {
		return nil, snapErr("invalid revisions in vault %s", sv.ID)
	}
	v := &vault{
		ID: sv.ID, Creator: sv.Creator, Personal: sv.Personal, KeyEpoch: sv.KeyEpoch,
		EncMeta: sv.EncMeta, MetaVersion: sv.MetaVersion,
		EncRoster: sv.EncRoster, RosterVersion: sv.RosterVersion, Rev: sv.Rev,
		RekeyRecommended: sv.RekeyRecommended,
		Members:          make(map[string]*member, len(sv.Members)),
		Items:            make(map[string]*item, len(sv.Items)),
	}
	for i, m := range sv.Members {
		if i > 0 && sv.Members[i-1].UserID >= m.UserID {
			return nil, snapErr("members not sorted in vault %s", sv.ID)
		}
		if !userExists(m.UserID) || !ValidRole(m.Role) || !userExists(m.AddedBy) {
			return nil, snapErr("invalid member in vault %s", sv.ID)
		}
		if validateWrappedKey("", m.WrappedKey, "") != nil || !userExists(m.WrappedKey.SenderID) {
			return nil, snapErr("invalid wrapped key in vault %s", sv.ID)
		}
		v.Members[m.UserID] = &sv.Members[i]
	}
	if v.owners() == 0 {
		return nil, snapErr("vault %s has no owner", sv.ID)
	}
	if v.Personal {
		cm := v.Members[v.Creator]
		if len(v.Members) != 1 || cm == nil || cm.Role != api.RoleOwner {
			return nil, snapErr("personal vault %s must have exactly its creator as owner", sv.ID)
		}
	}
	for i, it := range sv.Items {
		if i > 0 && sv.Items[i-1].ID >= it.ID {
			return nil, snapErr("items not sorted in vault %s", sv.ID)
		}
		if !ValidID(it.ID) || validateBox("", it.Blob, MaxItemBlobBytes) != nil {
			return nil, snapErr("invalid item in vault %s", sv.ID)
		}
		if it.Version == 0 || it.Version > sv.Rev || it.UpdatedAt <= 0 || !userExists(it.UpdatedBy) {
			return nil, snapErr("invalid item metadata in vault %s", sv.ID)
		}
		v.Items[it.ID] = &sv.Items[i]
	}
	v.recount() // derived counters are recomputed, never trusted from input
	return v, nil
}
