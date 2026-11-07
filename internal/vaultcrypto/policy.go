package vaultcrypto

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// Master-password policy. This is a FLOOR, not a strength meter: it rejects
// passwords that are trivially guessable and nudges toward a passphrase of
// several unrelated words; it says nothing about how strong an accepted
// password is. The same rules, in the same order, are implemented by the
// TypeScript client and pinned by the password_policy vectors.

// Policy rejection codes (PolicyError.Code).
const (
	PolicyTooShort         = "too_short"
	PolicyContainsUsername = "contains_username"
	PolicyRepeated         = "repeated"
	PolicySequence         = "sequence"
	PolicyCommon           = "common"
)

// MinPasswordLength is the minimum length in Unicode code points after NFKC.
const MinPasswordLength = 12

// HintText is returned by PasswordHint when it nudges.
const HintText = "Consider a passphrase of four or more unrelated words, for example four random words separated by spaces."

// PolicyError is returned by CheckMasterPassword.
type PolicyError struct {
	Code   string // one of the Policy* constants
	Reason string // human-readable
}

func (e *PolicyError) Error() string { return e.Reason }

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// CheckMasterPassword applies the policy floor, in this order, and returns a
// *PolicyError for the first rule broken:
//
//  1. too_short: fewer than 12 code points after NFKC.
//  2. contains_username: the ASCII-lower-cased password equals the
//     (ASCII-lower-cased) username, or, if the username has at least 3
//     characters, contains it.
//  3. repeated: one code point repeated, or a block of 1..4 code points
//     repeated to fill the whole password.
//  4. sequence: every consecutive pair of code points differs by +1
//     (ascending run) or every pair by -1 (descending run).
//  5. common: the ASCII-lower-cased password is in CommonPasswords().
func CheckMasterPassword(password, username string) error {
	pw := normalizePassword(password)
	rs := []rune(pw)
	if len(rs) < MinPasswordLength {
		return &PolicyError{PolicyTooShort, fmt.Sprintf("Use at least %d characters (this one has %d).", MinPasswordLength, len(rs))}
	}
	low := asciiLower(pw)
	if u := asciiLower(strings.Trim(username, " \t\n\v\f\r")); u != "" {
		if low == u || (len(u) >= 3 && strings.Contains(low, u)) {
			return &PolicyError{PolicyContainsUsername, "The password must not contain your username."}
		}
	}
	if isRepeated(rs) {
		return &PolicyError{PolicyRepeated, "The password must not be a short pattern repeated over and over."}
	}
	if isRun(rs) {
		return &PolicyError{PolicySequence, "The password must not be a simple ascending or descending run of characters."}
	}
	if commonSet()[low] {
		return &PolicyError{PolicyCommon, "This password is on the list of very common passwords."}
	}
	return nil
}

func isRepeated(rs []rune) bool {
	for p := 1; p <= 4 && p <= len(rs); p++ {
		if len(rs)%p != 0 {
			continue
		}
		ok := true
		for i := p; i < len(rs); i++ {
			if rs[i] != rs[i-p] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func isRun(rs []rune) bool {
	if len(rs) < 2 {
		return false
	}
	d := rs[1] - rs[0]
	if d != 1 && d != -1 {
		return false
	}
	for i := 2; i < len(rs); i++ {
		if rs[i]-rs[i-1] != d {
			return false
		}
	}
	return true
}

// PasswordHint returns HintText when the NFKC-normalised password has fewer
// than four non-empty words separated by U+0020, and "" otherwise. It is a
// nudge, not a judgement.
func PasswordHint(password string) string {
	words := 0
	for _, w := range strings.Split(normalizePassword(password), " ") {
		if w != "" {
			words++
		}
	}
	if words < 4 {
		return HintText
	}
	return ""
}

var (
	commonBases = []string{
		"password", "passw0rd", "p@ssw0rd", "p@ssword", "welcome", "letmein", "admin", "administrator",
		"qwerty", "qwertyuiop", "iloveyou", "monkey", "dragon", "football", "baseball", "master",
		"sunshine", "princess", "trustno1", "changeme", "secret", "login", "hello", "freedom",
		"whatever", "shadow", "superman", "batman", "starwars", "computer", "internet", "michael",
		"jessica", "charlie", "abc123", "summer", "winter", "spring", "autumn", "family", "mustang",
		"access", "google", "samsung", "windows", "pokemon", "liverpool", "arsenal", "chelsea",
		"mypassword", "newpassword", "default", "guest", "root", "test", "testing", "love", "fuckyou",
		"asdfghjkl", "zxcvbnm", "1q2w3e4r", "q1w2e3r4", "1qaz2wsx", "qazwsx",
	}
	commonSuffixes = []string{
		"", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
		"!", "1!", "123!", "!!", "!@#", "@123", "#1", "007", "69", "666", "777", "2019", "2020",
		"2021", "2022", "2023", "2024", "2025", "2026", "2027",
	}
	commonFixed = []string{
		"123456789012", "1234567890123", "12345678901234", "123456789012345", "1234567890123456",
		"098765432109", "111111111111", "000000000000", "999999999999", "121212121212", "123123123123",
		"qwertyuiopas", "qwertyuiop[]", "asdfghjklzxc", "zxcvbnmasdfg", "qwertzuiopas", "azertyuiopqs",
		"1q2w3e4r5t6y", "1q2w3e4r5t6y7u", "1qaz2wsx3edc", "zaq12wsxcde3", "qazwsxedcrfv", "1qazxsw23edc",
		"abcdefghijkl", "abcdefghijklm", "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqpo",
		"abcabcabcabc", "thequickbrownfox", "correcthorsebatterystaple", "letmeinletmein", "passwordpassword",
		"trustno1trustno1", "iloveyouiloveyou", "welcomewelcome", "adminadminadmin", "changemechangeme",
		"qwerty123456", "qwerty1234567", "password1234", "password12345", "password123456", "password!234",
		"letmein12345", "letmein123456", "iloveyou12345", "iloveyou123456", "welcome12345", "welcome123456",
		"administrator1", "administrator123", "masterpassword", "mymasterpassword", "vaultpassword", "familyvault",
		"familyvault123", "myfamilyvault", "securepassword", "supersecret123", "supersecretpassword",
		"opensesame123", "opensesameopen", "thisismypassword", "thisisapassword", "ihavenopassword",
	}
	commonOnce sync.Once
	commonMap  map[string]bool
	commonList []string
)

func buildCommon() {
	set := map[string]bool{}
	add := func(s string) {
		if utf8.RuneCountInString(s) >= MinPasswordLength {
			set[s] = true
		}
	}
	for _, b := range commonBases {
		for _, s := range commonSuffixes {
			add(b + s)
		}
	}
	for _, f := range commonFixed {
		add(f)
	}
	commonList = make([]string, 0, len(set))
	for s := range set {
		commonList = append(commonList, s)
	}
	sort.Strings(commonList)
	commonMap = set
}

func commonSet() map[string]bool {
	commonOnce.Do(buildCommon)
	return commonMap
}

// CommonPasswords returns the embedded list of very common passwords of at
// least 12 characters (shorter ones are already refused by length), sorted by
// byte order. It is generated from well-known base words, suffixes and
// keyboard patterns; the TypeScript client embeds exactly this list (it is
// published in the vectors file as password_policy_common).
func CommonPasswords() []string {
	commonSet()
	return append([]string(nil), commonList...)
}
