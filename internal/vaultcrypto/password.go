package vaultcrypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
)

// CharClass is a selectable character class for GeneratePassword.
type CharClass int

// Character classes.
const (
	Lower CharClass = iota
	Upper
	Digits
	Symbols
)

const (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{};:,.?/~"
	ambiguous   = "O0oIl1|"

	// MaxGeneratedPasswordLength bounds GeneratePassword.
	MaxGeneratedPasswordLength = 1024
)

type passwordConfig struct {
	classes       []CharClass
	noAmbiguous   bool
	classesCalled bool
}

// PasswordOption configures GeneratePassword.
type PasswordOption func(*passwordConfig)

// WithClasses selects exactly the given character classes (default: all four).
func WithClasses(classes ...CharClass) PasswordOption {
	return func(c *passwordConfig) { c.classes = classes; c.classesCalled = true }
}

// ExcludeAmbiguous removes visually ambiguous characters (O 0 o I l 1 |).
func ExcludeAmbiguous() PasswordOption {
	return func(c *passwordConfig) { c.noAmbiguous = true }
}

func classChars(c CharClass, noAmb bool) (string, error) {
	var s string
	switch c {
	case Lower:
		s = lowerChars
	case Upper:
		s = upperChars
	case Digits:
		s = digitChars
	case Symbols:
		s = symbolChars
	default:
		return "", errors.New("vaultcrypto: unknown character class")
	}
	if noAmb {
		s = strings.Map(func(r rune) rune {
			if strings.ContainsRune(ambiguous, r) {
				return -1
			}
			return r
		}, s)
	}
	return s, nil
}

// randInt returns a uniform integer in [0, n) using rejection sampling (no
// modulo bias). n must be in [1, 2^32].
func randInt(n uint64) int {
	if n == 1 {
		return 0
	}
	const space = uint64(1) << 32
	limit := space - space%n
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		v := uint64(binary.BigEndian.Uint32(b[:]))
		if v < limit {
			return int(v % n)
		}
	}
}

// GeneratePassword returns a uniformly random password of the given length
// drawn from the selected character classes (default all four), containing at
// least one character of each selected class. Characters are chosen with
// rejection sampling from the OS CSPRNG; the required class characters are
// then shuffled into uniformly random positions (Fisher-Yates).
func GeneratePassword(length int, opts ...PasswordOption) (string, error) {
	cfg := passwordConfig{classes: []CharClass{Lower, Upper, Digits, Symbols}}
	for _, o := range opts {
		o(&cfg)
	}
	seen := map[CharClass]bool{}
	var sets []string
	var all []byte
	for _, c := range cfg.classes {
		if seen[c] {
			continue
		}
		seen[c] = true
		s, err := classChars(c, cfg.noAmbiguous)
		if err != nil {
			return "", err
		}
		sets = append(sets, s)
		all = append(all, s...)
	}
	if len(sets) == 0 {
		return "", errors.New("vaultcrypto: no character class selected")
	}
	if length < len(sets) || length > MaxGeneratedPasswordLength {
		return "", errors.New("vaultcrypto: password length out of range")
	}
	out := make([]byte, length)
	for i, s := range sets {
		out[i] = s[randInt(uint64(len(s)))]
	}
	for i := len(sets); i < length; i++ {
		out[i] = all[randInt(uint64(len(all)))]
	}
	for i := length - 1; i > 0; i-- {
		j := randInt(uint64(i + 1))
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}
