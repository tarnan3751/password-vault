package vaultcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NewID returns a fresh random ID: 16 random bytes as 32 lowercase hex
// characters (crypto.md §1).
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ValidID reports whether s is a well-formed ID (32 lowercase hex characters).
func ValidID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func checkIDs(ids ...string) error {
	for _, id := range ids {
		if !ValidID(id) {
			return errors.New("vaultcrypto: malformed ID (want 32 lowercase hex characters)")
		}
	}
	return nil
}

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// NormalizeUsername trims and lower-cases a username and validates it against
// ^[a-z0-9][a-z0-9._-]{0,31}$ (crypto.md §1).
//
// Interpretation (see report): trimming removes only ASCII whitespace and any
// non-ASCII character is rejected BEFORE lower-casing, so that Go and
// JavaScript cannot disagree about Unicode case mapping (e.g. U+212A KELVIN
// SIGN or U+0130) or about which characters String.trim removes.
func NormalizeUsername(s string) (string, error) {
	s = strings.Trim(s, " \t\n\v\f\r")
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", fmt.Errorf("vaultcrypto: invalid username: only ASCII letters, digits, '.', '_' and '-' are allowed")
		}
	}
	s = strings.ToLower(s)
	if !usernameRE.MatchString(s) {
		return "", fmt.Errorf("vaultcrypto: invalid username: must match %s", usernameRE.String())
	}
	return s, nil
}

// NormalizePassword returns the UTF-8 bytes of the NFKC-normalised password
// (crypto.md §1). Invalid UTF-8 is replaced by U+FFFD first. No trimming is
// performed.
func NormalizePassword(password string) []byte { return []byte(normalizePassword(password)) }

func normalizePassword(password string) string {
	return norm.NFKC.String(strings.ToValidUTF8(password, "�"))
}
