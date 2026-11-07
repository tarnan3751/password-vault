package vaultcrypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
)

// Roles in a roster (crypto.md §6.3).
const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// RosterMember is one entry of a vault roster (crypto.md §6.3).
type RosterMember struct {
	ID        string
	PublicKey PublicKey
	Role      string
}

var (
	rosterKeys      = []string{"v", "members"}
	rosterEntryKeys = []string{"id", "pk", "role"}
)

// Roster is the authenticated member list of a vault (crypto.md §6.3).
// Members are sorted by ID (byte order), unique, with at least one owner.
type Roster struct {
	V       int
	Members []RosterMember
}

func validRole(r string) bool { return r == RoleOwner || r == RoleEditor || r == RoleViewer }

// Validate checks every roster invariant of crypto.md §6.3.
func (r *Roster) Validate() error {
	if r.V != 1 {
		return fmt.Errorf("vaultcrypto: unsupported roster version %d", r.V)
	}
	owners := 0
	for i, m := range r.Members {
		if !ValidID(m.ID) {
			return errors.New("vaultcrypto: roster member has a malformed ID")
		}
		if !validRole(m.Role) {
			return fmt.Errorf("vaultcrypto: roster role %q is not owner, editor or viewer", m.Role)
		}
		if i > 0 && r.Members[i-1].ID >= m.ID {
			return errors.New("vaultcrypto: roster members must be sorted by ID and unique")
		}
		if m.Role == RoleOwner {
			owners++
		}
	}
	if owners == 0 {
		return errors.New("vaultcrypto: roster has no owner")
	}
	return nil
}

// Encode validates the roster and returns its canonical JSON:
// {"v":1,"members":[{"id":...,"pk":<base64>,"role":...},...]} without
// whitespace.
func (r *Roster) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b := appendArray([]byte(`{"v":1,"members":`), r.Members, func(b []byte, m RosterMember) []byte {
		b = append(b, `{"id":`...)
		b = appendJSONString(b, m.ID)
		b = append(b, `,"pk":"`...)
		b = base64.StdEncoding.AppendEncode(b, m.PublicKey[:])
		b = append(b, `","role":`...)
		b = appendJSONString(b, m.Role)
		return append(b, '}')
	})
	return append(b, '}'), nil
}

// DecodeRoster decodes roster plaintext under §5.3 and validates the roster
// invariants. Unknown members (top level or inside entries) are ignored.
func DecodeRoster(pt []byte) (*Roster, error) {
	ms, err := parseObject(pt)
	if err != nil {
		return nil, err
	}
	as, _, err := splitMembers(ms, rosterKeys)
	if err != nil {
		return nil, err
	}
	if err := requireMembers(as, "v", "members"); err != nil {
		return nil, err
	}
	ents, err := decodeEntries(as["members"], rosterEntryKeys)
	if err != nil {
		return nil, err
	}
	r := &Roster{V: 1, Members: make([]RosterMember, 0, len(ents))}
	for _, e := range ents {
		var m RosterMember
		if err := requireMembers(e, "id", "pk", "role"); err != nil {
			return nil, err
		}
		if m.ID, err = asString(e["id"]); err != nil {
			return nil, err
		}
		if m.Role, err = asString(e["role"]); err != nil {
			return nil, err
		}
		pk, err := asString(e["pk"])
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(pk)
		if err != nil || len(raw) != 32 || bytes.ContainsAny([]byte(pk), "\r\n") {
			return nil, unreadable("pk must be 32 bytes of canonical padded base64")
		}
		copy(m.PublicKey[:], raw)
		r.Members = append(r.Members, m)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	return r, nil
}

// EncryptRoster returns seal(VK, rosterJSON, "fpv/v1/roster|"+vaultID+"|"+epoch)
// (crypto.md §5, §6.3). The roster is not padded.
func EncryptRoster(vk *SymmetricKey, vaultID string, epoch uint32, r *Roster) ([]byte, error) {
	if err := checkArgs(epoch, vaultID); err != nil {
		return nil, err
	}
	js, err := r.Encode()
	if err != nil {
		return nil, err
	}
	return Seal(vk, js, RosterAAD(vaultID, epoch))
}

// SealRosterWithNonce is EncryptRoster with a fixed nonce. For test vectors
// only.
func SealRosterWithNonce(vk *SymmetricKey, vaultID string, epoch uint32, r *Roster, nonce []byte) ([]byte, error) {
	js, err := r.Encode()
	if err != nil {
		return nil, err
	}
	return SealWithNonce(vk, nonce, js, RosterAAD(vaultID, epoch))
}

// DecryptRoster opens and decodes a roster blob (crypto.md §5, §5.3, §6.3).
func DecryptRoster(vk *SymmetricKey, vaultID string, epoch uint32, blob []byte) (*Roster, error) {
	if err := checkArgs(epoch, vaultID); err != nil {
		return nil, err
	}
	pt, err := Open(vk, blob, RosterAAD(vaultID, epoch))
	if err != nil {
		return nil, err
	}
	defer Zero(pt)
	return DecodeRoster(pt)
}

// Member returns the roster entry for id.
func (r *Roster) Member(id string) (RosterMember, bool) {
	i := sort.Search(len(r.Members), func(i int) bool { return r.Members[i].ID >= id })
	if i < len(r.Members) && r.Members[i].ID == id {
		return r.Members[i], true
	}
	return RosterMember{}, false
}

// Owners returns the owners of the roster.
func (r *Roster) Owners() []RosterMember {
	var out []RosterMember
	for _, m := range r.Members {
		if m.Role == RoleOwner {
			out = append(out, m)
		}
	}
	return out
}

func (r *Roster) clone() *Roster {
	return &Roster{V: r.V, Members: append([]RosterMember(nil), r.Members...)}
}

// WithMember returns a new roster with m added (an error if the ID is already
// present); the result is validated.
func (r *Roster) WithMember(m RosterMember) (*Roster, error) {
	if _, ok := r.Member(m.ID); ok {
		return nil, errors.New("vaultcrypto: member already in roster")
	}
	n := r.clone()
	n.Members = append(n.Members, m)
	sort.Slice(n.Members, func(i, j int) bool { return n.Members[i].ID < n.Members[j].ID })
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// WithRole returns a new roster in which id has the given role; an error if
// id is absent or the result would have no owner.
func (r *Roster) WithRole(id, role string) (*Roster, error) {
	n := r.clone()
	for i := range n.Members {
		if n.Members[i].ID == id {
			n.Members[i].Role = role
			if err := n.Validate(); err != nil {
				return nil, err
			}
			return n, nil
		}
	}
	return nil, errors.New("vaultcrypto: member not in roster")
}

// Without returns a new roster without id; an error if id is absent or the
// result would have no owner.
func (r *Roster) Without(id string) (*Roster, error) {
	n := &Roster{V: r.V}
	found := false
	for _, m := range r.Members {
		if m.ID == id {
			found = true
			continue
		}
		n.Members = append(n.Members, m)
	}
	if !found {
		return nil, errors.New("vaultcrypto: member not in roster")
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}
