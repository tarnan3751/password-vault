package vaultcrypto

import (
	"errors"
	"fmt"
	"strconv"
)

// Padding block sizes (crypto.md §5).
const (
	MetaPadBlock = 64
	ItemPadBlock = 256
	// MaxPasswordHistory is the maximum number of old passwords kept (§5.2).
	MaxPasswordHistory = 10
)

// Item types (crypto.md §5.2).
const (
	ItemTypeLogin = "login"
	ItemTypeNote  = "note"
)

func epochStr(epoch uint32) string { return strconv.FormatUint(uint64(epoch), 10) }

// VaultMetaAAD returns "fpv/v1/vault-meta|" + vaultID + "|" + keyEpoch
// (crypto.md §5).
func VaultMetaAAD(vaultID string, epoch uint32) []byte {
	return []byte("fpv/v1/vault-meta|" + vaultID + "|" + epochStr(epoch))
}

// ItemAAD returns "fpv/v1/item|" + vaultID + "|" + itemID + "|" + keyEpoch
// (crypto.md §5).
func ItemAAD(vaultID, itemID string, epoch uint32) []byte {
	return []byte("fpv/v1/item|" + vaultID + "|" + itemID + "|" + epochStr(epoch))
}

// RosterAAD returns "fpv/v1/roster|" + vaultID + "|" + keyEpoch (crypto.md §5).
func RosterAAD(vaultID string, epoch uint32) []byte {
	return []byte("fpv/v1/roster|" + vaultID + "|" + epochStr(epoch))
}

func checkEpoch(epoch uint32) error {
	if epoch < 1 {
		return errors.New("vaultcrypto: key epoch must be >= 1")
	}
	return nil
}

// checkArgs validates the IDs and the key epoch of an AAD-bound operation.
func checkArgs(epoch uint32, ids ...string) error {
	if err := checkIDs(ids...); err != nil {
		return err
	}
	return checkEpoch(epoch)
}

// VaultMeta is the vault metadata JSON of crypto.md §5.1. Unknown top-level
// members are kept in Extra and written back byte for byte.
type VaultMeta struct {
	V     int
	Name  string
	Extra []ExtraMember
}

// Encode returns the canonical JSON of m: {"v":1,"name":...}
// followed by Extra members in their original order.
func (m *VaultMeta) Encode() ([]byte, error) {
	if m.V != 1 {
		return nil, fmt.Errorf("vaultcrypto: unsupported vault meta version %d", m.V)
	}
	b := []byte{'{'}
	first := true
	b = appendMember(b, &first, "v", func(b []byte) []byte { return strconv.AppendInt(b, int64(m.V), 10) })
	b = appendMember(b, &first, "name", func(b []byte) []byte { return appendJSONString(b, m.Name) })
	return finishObject(b, &first, m.Extra)
}

func finishObject(b []byte, first *bool, extra []ExtraMember) ([]byte, error) {
	b, err := appendExtras(b, first, extra)
	if err != nil {
		return nil, err
	}
	return append(b, '}'), nil
}

// DecodeVaultMeta decodes vault metadata plaintext under the rules of
// crypto.md §5.3. Padding (trailing spaces) is accepted.
func DecodeVaultMeta(pt []byte) (*VaultMeta, error) {
	ms, err := parseObject(pt)
	if err != nil {
		return nil, err
	}
	as, extra, err := splitMembers(ms, vaultMetaKeys)
	if err != nil {
		return nil, err
	}
	if err := requireMembers(as, "v", "name"); err != nil {
		return nil, err
	}
	name, err := asString(as["name"])
	if err != nil {
		return nil, err
	}
	return &VaultMeta{V: 1, Name: name, Extra: extrasFrom(extra)}, nil
}

// EncryptVaultMeta returns seal(VK, pad(metaJSON, 64), aad) (crypto.md §5).
// m.V of 0 is treated as 1.
func EncryptVaultMeta(vk *SymmetricKey, vaultID string, epoch uint32, m *VaultMeta) ([]byte, error) {
	if err := checkArgs(epoch, vaultID); err != nil {
		return nil, err
	}
	mm := *m
	if mm.V == 0 {
		mm.V = 1
	}
	js, err := mm.Encode()
	if err != nil {
		return nil, err
	}
	pt := Pad(js, MetaPadBlock)
	defer Zero(pt)
	return Seal(vk, pt, VaultMetaAAD(vaultID, epoch))
}

// DecryptVaultMeta opens and decodes an encMeta blob (crypto.md §5, §5.3).
func DecryptVaultMeta(vk *SymmetricKey, vaultID string, epoch uint32, blob []byte) (*VaultMeta, error) {
	if err := checkArgs(epoch, vaultID); err != nil {
		return nil, err
	}
	pt, err := Open(vk, blob, VaultMetaAAD(vaultID, epoch))
	if err != nil {
		return nil, err
	}
	defer Zero(pt)
	return DecodeVaultMeta(pt)
}

// CustomField is an entry of Item.Fields (crypto.md §5.2). Unknown members of
// an entry are ignored when decoding and dropped on edit.
type CustomField struct {
	Name   string
	Value  string
	Hidden bool
}

// PasswordHistoryEntry is an entry of Item.PasswordHistory (crypto.md §5.2).
type PasswordHistoryEntry struct {
	Password  string
	ChangedAt int64
}

// Item is the decrypted item JSON of crypto.md §5.2. Unknown top-level members
// are kept verbatim, in order, in Extra and written back by Encode. Times are
// Unix milliseconds in 0..2^53-1.
type Item struct {
	V               int
	Type            string
	Name            string
	Username        string
	Password        string
	URLs            []string
	Notes           string
	TOTP            string
	Fields          []CustomField
	Tags            []string
	CreatedAt       int64
	UpdatedAt       int64
	PasswordHistory []PasswordHistoryEntry

	// Extra holds unknown top-level members, byte for byte.
	Extra []ExtraMember
}

// String redacts the item (it contains secrets).
func (Item) String() string { return "Item(redacted)" }

// GoString redacts the item (it contains secrets).
func (Item) GoString() string { return "Item(redacted)" }

var (
	vaultMetaKeys = []string{"v", "name"}
	knownItemKeys = []string{"v", "type", "name", "username", "password", "urls", "notes", "totp", "fields", "tags", "created_at", "updated_at", "password_history"}
	fieldKeys     = []string{"name", "value", "hidden"}
	historyKeys   = []string{"password", "changed_at"}
)

func (it *Item) validate() error {
	if it.V != 1 {
		return fmt.Errorf("vaultcrypto: unsupported item version %d", it.V)
	}
	if it.Type != ItemTypeLogin && it.Type != ItemTypeNote {
		return fmt.Errorf("vaultcrypto: unknown item type %q", it.Type)
	}
	for _, t := range []int64{it.CreatedAt, it.UpdatedAt} {
		if t < 0 || t > maxSafeInt {
			return errors.New("vaultcrypto: timestamp out of range")
		}
	}
	for _, h := range it.PasswordHistory {
		if h.ChangedAt < 0 || h.ChangedAt > maxSafeInt {
			return errors.New("vaultcrypto: timestamp out of range")
		}
	}
	return nil
}

// Encode returns the canonical JSON of the item. Member order: v, type, name,
// then username, password, urls, notes, totp, fields, tags (each omitted when
// empty), then created_at and updated_at (always present), then
// password_history (omitted when empty), then the Extra members in their
// original order. No whitespace. Strings use the escaping rule of
// appendJSONString. Within entries: fields -> name, value, hidden (only when
// true); password_history -> password, changed_at.
func (it *Item) Encode() ([]byte, error) {
	if err := it.validate(); err != nil {
		return nil, err
	}
	b := []byte{'{'}
	first := true
	str := func(key, v string, omitEmpty bool) {
		if omitEmpty && v == "" {
			return
		}
		b = appendMember(b, &first, key, func(b []byte) []byte { return appendJSONString(b, v) })
	}
	strs := func(key string, v []string) {
		if len(v) > 0 {
			b = appendMember(b, &first, key, func(b []byte) []byte { return appendArray(b, v, appendJSONString) })
		}
	}
	num := func(key string, v int64) {
		b = appendMember(b, &first, key, func(b []byte) []byte { return strconv.AppendInt(b, v, 10) })
	}
	num("v", int64(it.V))
	str("type", it.Type, false)
	str("name", it.Name, false)
	str("username", it.Username, true)
	str("password", it.Password, true)
	strs("urls", it.URLs)
	str("notes", it.Notes, true)
	str("totp", it.TOTP, true)
	if len(it.Fields) > 0 {
		b = appendMember(b, &first, "fields", func(b []byte) []byte {
			return appendArray(b, it.Fields, func(b []byte, f CustomField) []byte {
				b = append(b, `{"name":`...)
				b = appendJSONString(b, f.Name)
				b = append(b, `,"value":`...)
				b = appendJSONString(b, f.Value)
				if f.Hidden {
					b = append(b, `,"hidden":true`...)
				}
				return append(b, '}')
			})
		})
	}
	strs("tags", it.Tags)
	num("created_at", it.CreatedAt)
	num("updated_at", it.UpdatedAt)
	if len(it.PasswordHistory) > 0 {
		b = appendMember(b, &first, "password_history", func(b []byte) []byte {
			return appendArray(b, it.PasswordHistory, func(b []byte, h PasswordHistoryEntry) []byte {
				b = append(b, `{"password":`...)
				b = appendJSONString(b, h.Password)
				b = append(b, `,"changed_at":`...)
				b = strconv.AppendInt(b, h.ChangedAt, 10)
				return append(b, '}')
			})
		})
	}
	return finishObject(b, &first, it.Extra)
}

// MarshalJSON implements json.Marshaler using Encode.
func (it Item) MarshalJSON() ([]byte, error) { return it.Encode() }

// UnmarshalJSON implements json.Unmarshaler using DecodeItem.
func (it *Item) UnmarshalJSON(data []byte) error {
	d, err := DecodeItem(data)
	if err != nil {
		return err
	}
	*it = *d
	return nil
}

// DecodeItem decodes item plaintext under the rules of crypto.md §5.3.
// Padding (trailing spaces) is accepted.
func DecodeItem(pt []byte) (*Item, error) {
	ms, err := parseObject(pt)
	if err != nil {
		return nil, err
	}
	as, extra, err := splitMembers(ms, knownItemKeys)
	if err != nil {
		return nil, err
	}
	if err := requireMembers(as, "v", "type", "name"); err != nil {
		return nil, err
	}
	it := Item{V: 1}
	for k, raw := range as {
		switch k {
		case "type":
			it.Type, err = asString(raw)
		case "name":
			it.Name, err = asString(raw)
		case "username":
			it.Username, err = asString(raw)
		case "password":
			it.Password, err = asString(raw)
		case "notes":
			it.Notes, err = asString(raw)
		case "totp":
			it.TOTP, err = asString(raw)
		case "urls":
			it.URLs, err = asStringArray(raw)
		case "tags":
			it.Tags, err = asStringArray(raw)
		case "created_at":
			it.CreatedAt, err = asInt(raw)
		case "updated_at":
			it.UpdatedAt, err = asInt(raw)
		case "fields":
			it.Fields, err = decodeFields(raw)
		case "password_history":
			it.PasswordHistory, err = decodeHistory(raw)
		}
		if err != nil {
			return nil, err
		}
	}
	if it.Type != ItemTypeLogin && it.Type != ItemTypeNote {
		return nil, unreadable("unknown item type")
	}
	it.Extra = extrasFrom(extra)
	return &it, nil
}

func decodeEntries(raw []byte, known []string) ([]map[string][]byte, error) {
	els, err := parseArray(raw)
	if err != nil {
		return nil, err
	}
	var out []map[string][]byte
	for _, e := range els {
		ms, err := asObject(e)
		if err != nil {
			return nil, err
		}
		as, _, err := splitMembers(ms, known)
		if err != nil {
			return nil, err
		}
		out = append(out, as)
	}
	return out, nil
}

func decodeFields(raw []byte) ([]CustomField, error) {
	ents, err := decodeEntries(raw, fieldKeys)
	if err != nil {
		return nil, err
	}
	var out []CustomField
	for _, as := range ents {
		var f CustomField
		if v, ok := as["name"]; ok {
			if f.Name, err = asString(v); err != nil {
				return nil, err
			}
		}
		if v, ok := as["value"]; ok {
			if f.Value, err = asString(v); err != nil {
				return nil, err
			}
		}
		if v, ok := as["hidden"]; ok {
			if f.Hidden, err = asBool(v); err != nil {
				return nil, err
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func decodeHistory(raw []byte) ([]PasswordHistoryEntry, error) {
	ents, err := decodeEntries(raw, historyKeys)
	if err != nil {
		return nil, err
	}
	var out []PasswordHistoryEntry
	for _, as := range ents {
		var h PasswordHistoryEntry
		if v, ok := as["password"]; ok {
			if h.Password, err = asString(v); err != nil {
				return nil, err
			}
		}
		if v, ok := as["changed_at"]; ok {
			if h.ChangedAt, err = asInt(v); err != nil {
				return nil, err
			}
		}
		out = append(out, h)
	}
	return out, nil
}

// Clone returns a deep copy of the item.
func (it *Item) Clone() *Item {
	c := *it
	c.URLs = append([]string(nil), it.URLs...)
	c.Tags = append([]string(nil), it.Tags...)
	c.Fields = append([]CustomField(nil), it.Fields...)
	c.PasswordHistory = append([]PasswordHistoryEntry(nil), it.PasswordHistory...)
	c.Extra = cloneExtras(it.Extra)
	return &c
}

// EditItem applies edit to a copy of old and returns the result, maintaining
// the bookkeeping of crypto.md §5.2: updated_at is set to nowMs, and if the
// password changed (and the old one was non-empty) the old password is
// prepended to password_history with changed_at = nowMs, keeping at most
// MaxPasswordHistory entries. created_at, v and unknown members are preserved
// unless edit changes them itself. old is not modified.
func EditItem(old *Item, nowMs int64, edit func(*Item)) *Item {
	n := old.Clone()
	edit(n)
	n.UpdatedAt = nowMs
	if n.Password != old.Password && old.Password != "" {
		hist := make([]PasswordHistoryEntry, 0, len(n.PasswordHistory)+1)
		hist = append(hist, PasswordHistoryEntry{Password: old.Password, ChangedAt: nowMs})
		hist = append(hist, n.PasswordHistory...)
		if len(hist) > MaxPasswordHistory {
			hist = hist[:MaxPasswordHistory]
		}
		n.PasswordHistory = hist
	}
	return n
}

// EncryptItem returns seal(VK, pad(itemJSON, 256), aad) (crypto.md §5).
func EncryptItem(vk *SymmetricKey, vaultID, itemID string, epoch uint32, it *Item) ([]byte, error) {
	if err := checkArgs(epoch, vaultID, itemID); err != nil {
		return nil, err
	}
	js, err := it.Encode()
	if err != nil {
		return nil, err
	}
	pt := Pad(js, ItemPadBlock)
	defer Zero(pt)
	Zero(js)
	return Seal(vk, pt, ItemAAD(vaultID, itemID, epoch))
}

// DecryptItem opens and decodes an item blob (crypto.md §5, §5.3).
func DecryptItem(vk *SymmetricKey, vaultID, itemID string, epoch uint32, blob []byte) (*Item, error) {
	if err := checkArgs(epoch, vaultID, itemID); err != nil {
		return nil, err
	}
	pt, err := Open(vk, blob, ItemAAD(vaultID, itemID, epoch))
	if err != nil {
		return nil, err
	}
	defer Zero(pt)
	return DecodeItem(pt)
}
