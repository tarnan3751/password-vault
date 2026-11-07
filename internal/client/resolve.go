package client

import (
	"fmt"
	"strings"
)

// AmbiguousError: a name or ID prefix matched several things.
type AmbiguousError struct {
	Kind, Ref  string
	Candidates []string
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%s %q is ambiguous; it matches:\n  %s\nuse the ID (or a longer prefix) to pick one", e.Kind, e.Ref, strings.Join(e.Candidates, "\n  "))
}

// NotFoundError: nothing matched.
type NotFoundError struct{ Kind, Ref string }

func (e *NotFoundError) Error() string { return fmt.Sprintf("no %s matches %q", e.Kind, e.Ref) }

// minPrefix is the shortest ID prefix accepted.
const minPrefix = 4

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

// pick applies the shared rule: exact ID, then case-insensitive exact name
// (several = ambiguous), then a unique ID prefix of at least 4 hex digits.
func pick[T any](kind, ref string, all []T, id func(T) string, name func(T) string, describe func(T) string) (T, error) {
	var zero T
	for _, x := range all {
		if id(x) == ref {
			return x, nil
		}
	}
	var hits []T
	for _, x := range all {
		if strings.EqualFold(name(x), ref) {
			hits = append(hits, x)
		}
	}
	if len(hits) == 0 && len(ref) >= minPrefix && isHex(strings.ToLower(ref)) {
		for _, x := range all {
			if strings.HasPrefix(id(x), strings.ToLower(ref)) {
				hits = append(hits, x)
			}
		}
	}
	switch len(hits) {
	case 0:
		return zero, &NotFoundError{Kind: kind, Ref: ref}
	case 1:
		return hits[0], nil
	}
	c := make([]string, len(hits))
	for i, h := range hits {
		c[i] = describe(h)
	}
	return zero, &AmbiguousError{Kind: kind, Ref: ref, Candidates: c}
}

// ResolveVault finds a vault by ID, unique ID prefix or case-insensitive name.
func (s *Session) ResolveVault(ref string) (*VaultView, error) {
	return pick("vault", ref, s.vaults,
		func(v *VaultView) string { return v.ID },
		func(v *VaultView) string { return v.Name },
		func(v *VaultView) string { return fmt.Sprintf("%s  %s", v.ID[:8], v.Name) })
}

// ItemRef is an item together with its vault.
type ItemRef struct {
	Vault *VaultView
	Item  *ItemView
}

// ResolveItem finds an item by ID, unique ID prefix or case-insensitive name,
// in one vault (vaultRef != "") or in all readable vaults.
func (s *Session) ResolveItem(vaultRef, ref string) (*ItemRef, error) {
	vaults := s.vaults
	if vaultRef != "" {
		v, err := s.ResolveVault(vaultRef)
		if err != nil {
			return nil, err
		}
		vaults = []*VaultView{v}
	}
	var all []ItemRef
	for _, v := range vaults {
		for i := range v.Items {
			all = append(all, ItemRef{Vault: v, Item: &v.Items[i]})
		}
	}
	r, err := pick("item", ref, all,
		func(r ItemRef) string { return r.Item.ID },
		func(r ItemRef) string {
			if r.Item.Item == nil {
				return "\x00"
			}
			return r.Item.Item.Name
		},
		func(r ItemRef) string {
			n := "(unreadable)"
			if r.Item.Item != nil {
				n = r.Item.Item.Name
			}
			return fmt.Sprintf("%s  %s  [vault %s]", r.Item.ID[:8], n, r.Vault.Name)
		})
	if err != nil {
		return nil, err
	}
	return &r, nil
}
