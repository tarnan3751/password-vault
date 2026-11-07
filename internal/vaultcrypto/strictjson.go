package vaultcrypto

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// This file implements the decoding rules of crypto.md §5.3 on top of a small
// strict JSON scanner (RFC 8259 grammar). encoding/json is deliberately not
// used for item, meta and roster plaintext: it matches member names
// case-insensitively, silently keeps the last of duplicate members, accepts
// null for anything, replaces invalid UTF-8 and lone surrogates, and rounds
// integers through float64 in some paths.
//
// Rules implemented here, identical in the TypeScript client:
//   - the plaintext must be valid UTF-8;
//   - exactly one JSON object, optionally surrounded by JSON whitespace
//     (space, TAB, LF, CR); anything else after it is invalid;
//   - lone surrogate \u escapes are invalid anywhere (keys and values);
//   - numbers follow the JSON grammar; known integer members must match
//     (0|[1-9][0-9]*) and be <= 2^53-1;
//   - nesting depth is unlimited (the scanner is iterative).

// ErrUnreadable is wrapped by every §5.3 decoding failure.
var ErrUnreadable = errors.New("vaultcrypto: unreadable plaintext")

func unreadable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnreadable, fmt.Sprintf(format, a...))
}

const maxSafeInt = 1<<53 - 1

type scanner struct {
	b []byte
	i int
}

func (s *scanner) skipWS() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

func (s *scanner) peek() int {
	if s.i >= len(s.b) {
		return -1
	}
	return int(s.b[s.i])
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func (s *scanner) hex4() (rune, error) {
	if s.i+4 > len(s.b) {
		return 0, errors.New("short \\u escape")
	}
	var r rune
	for k := 0; k < 4; k++ {
		v := hexVal(s.b[s.i+k])
		if v < 0 {
			return 0, errors.New("bad \\u escape")
		}
		r = r<<4 | rune(v)
	}
	s.i += 4
	return r, nil
}

func (s *scanner) str() (string, error) {
	b, err := s.strBytes()
	return string(b), err
}

// strBytes scans a JSON string starting at the opening quote and returns its
// decoded value. Without escapes the result aliases the input (no copy, so
// validating and skipping strings does not allocate); otherwise it is fresh.
func (s *scanner) strBytes() ([]byte, error) {
	if s.peek() != '"' {
		return nil, errors.New("expected string")
	}
	s.i++
	start := s.i
	for s.i < len(s.b) && s.b[s.i] != '"' && s.b[s.i] != '\\' && s.b[s.i] >= 0x20 {
		s.i++
	}
	if s.i < len(s.b) && s.b[s.i] == '"' {
		s.i++
		return s.b[start : s.i-1], nil
	}
	out := append([]byte(nil), s.b[start:s.i]...)
	for {
		if s.i >= len(s.b) {
			return nil, errors.New("unterminated string")
		}
		c := s.b[s.i]
		switch {
		case c == '"':
			s.i++
			return out, nil
		case c < 0x20:
			return nil, errors.New("control character in string")
		case c == '\\':
			s.i++
			if s.i >= len(s.b) {
				return nil, errors.New("unterminated escape")
			}
			e := s.b[s.i]
			s.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := s.hex4()
				if err != nil {
					return nil, err
				}
				if r >= 0xDC00 && r <= 0xDFFF {
					return nil, errors.New("lone low surrogate escape")
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if s.i+1 >= len(s.b) || s.b[s.i] != '\\' || s.b[s.i+1] != 'u' {
						return nil, errors.New("lone high surrogate escape")
					}
					s.i += 2
					lo, err := s.hex4()
					if err != nil {
						return nil, err
					}
					if lo < 0xDC00 || lo > 0xDFFF {
						return nil, errors.New("lone high surrogate escape")
					}
					r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
				}
				out = utf8.AppendRune(out, r)
			default:
				return nil, errors.New("invalid escape")
			}
		default:
			out = append(out, c)
			s.i++
		}
	}
}

func (s *scanner) number() error {
	if s.peek() == '-' {
		s.i++
	}
	switch c := s.peek(); {
	case c == '0':
		s.i++
	case c >= '1' && c <= '9':
		for s.peek() >= '0' && s.peek() <= '9' {
			s.i++
		}
	default:
		return errors.New("bad number")
	}
	if s.peek() == '.' {
		s.i++
		if !(s.peek() >= '0' && s.peek() <= '9') {
			return errors.New("bad number")
		}
		for s.peek() >= '0' && s.peek() <= '9' {
			s.i++
		}
	}
	if c := s.peek(); c == 'e' || c == 'E' {
		s.i++
		if c := s.peek(); c == '+' || c == '-' {
			s.i++
		}
		if !(s.peek() >= '0' && s.peek() <= '9') {
			return errors.New("bad number")
		}
		for s.peek() >= '0' && s.peek() <= '9' {
			s.i++
		}
	}
	return nil
}

func (s *scanner) literal(w string) error {
	if len(s.b)-s.i < len(w) || string(s.b[s.i:s.i+len(w)]) != w {
		return errors.New("bad literal")
	}
	s.i += len(w)
	return nil
}

// memberStart scans `"key" :` and leaves the scanner at the value. It returns
// the decoded key and the key text as written (with quotes).
func (s *scanner) memberStart() (key, rawKey []byte, err error) {
	start := s.i
	if key, err = s.strBytes(); err != nil {
		return nil, nil, err
	}
	rawKey = s.b[start:s.i]
	s.skipWS()
	if s.peek() != ':' {
		return nil, nil, errors.New("expected ':'")
	}
	s.i++
	return key, rawKey, nil
}

// skipValue validates and consumes one JSON value, iteratively.
func (s *scanner) skipValue() error {
	var stack []byte
	for {
		s.skipWS()
		c := s.peek()
		complete := true
		switch {
		case c == '{':
			s.i++
			s.skipWS()
			if s.peek() == '}' {
				s.i++
			} else {
				stack = append(stack, '{')
				if _, _, err := s.memberStart(); err != nil {
					return err
				}
				complete = false
			}
		case c == '[':
			s.i++
			s.skipWS()
			if s.peek() == ']' {
				s.i++
			} else {
				stack = append(stack, '[')
				complete = false
			}
		case c == '"':
			if _, err := s.strBytes(); err != nil {
				return err
			}
		case c == '-' || (c >= '0' && c <= '9'):
			if err := s.number(); err != nil {
				return err
			}
		case c == 't':
			if err := s.literal("true"); err != nil {
				return err
			}
		case c == 'f':
			if err := s.literal("false"); err != nil {
				return err
			}
		case c == 'n':
			if err := s.literal("null"); err != nil {
				return err
			}
		default:
			return errors.New("unexpected character")
		}
		if !complete {
			continue
		}
		// A value just ended: close containers / move to the next sibling.
		for {
			if len(stack) == 0 {
				return nil
			}
			s.skipWS()
			top := stack[len(stack)-1]
			c := s.peek()
			if c == ',' {
				s.i++
				s.skipWS()
				if top == '{' {
					if _, _, err := s.memberStart(); err != nil {
						return err
					}
				}
				break
			}
			if (top == '{' && c == '}') || (top == '[' && c == ']') {
				s.i++
				stack = stack[:len(stack)-1]
				continue
			}
			return errors.New("expected ',' or closing bracket")
		}
	}
}

// rawMember is one member of a parsed object: the decoded key, the key text as
// written (with quotes) and the value text as written (no surrounding
// whitespace). All three alias the parsed input, except a key with escapes.
type rawMember struct {
	key    []byte
	rawKey []byte
	value  []byte
}

// parseObject parses b as a single JSON object (§5.3).
func parseObject(b []byte) ([]rawMember, error) {
	if !utf8.Valid(b) {
		return nil, unreadable("not valid UTF-8")
	}
	s := &scanner{b: b}
	s.skipWS()
	if s.peek() != '{' {
		return nil, unreadable("not a JSON object")
	}
	s.i++
	members, err := s.members()
	if err != nil {
		return nil, unreadable("%v", err)
	}
	s.skipWS()
	if s.i != len(b) {
		return nil, unreadable("trailing data after the object")
	}
	return members, nil
}

// members parses the remainder of an object after '{'.
func (s *scanner) members() ([]rawMember, error) {
	var out []rawMember
	s.skipWS()
	if s.peek() == '}' {
		s.i++
		return out, nil
	}
	for {
		s.skipWS()
		key, rawKey, err := s.memberStart()
		if err != nil {
			return nil, err
		}
		s.skipWS()
		vs := s.i
		if err := s.skipValue(); err != nil {
			return nil, err
		}
		out = append(out, rawMember{key: key, rawKey: rawKey, value: s.b[vs:s.i]})
		s.skipWS()
		switch s.peek() {
		case ',':
			s.i++
		case '}':
			s.i++
			return out, nil
		default:
			return nil, errors.New("expected ',' or '}'")
		}
	}
}

// parseArray splits the JSON array text v into its element texts.
func parseArray(v []byte) ([][]byte, error) {
	s := &scanner{b: v}
	s.skipWS()
	if s.peek() != '[' {
		return nil, unreadable("expected an array")
	}
	s.i++
	s.skipWS()
	var out [][]byte
	if s.peek() == ']' {
		return out, nil
	}
	for {
		s.skipWS()
		st := s.i
		if err := s.skipValue(); err != nil {
			return nil, unreadable("%v", err)
		}
		out = append(out, v[st:s.i])
		s.skipWS()
		switch s.peek() {
		case ',':
			s.i++
		case ']':
			return out, nil
		default:
			return nil, unreadable("bad array")
		}
	}
}

func asObject(v []byte) ([]rawMember, error) {
	s := &scanner{b: v}
	if s.peek() != '{' {
		return nil, unreadable("expected an object")
	}
	s.i++
	m, err := s.members()
	if err != nil {
		return nil, unreadable("%v", err)
	}
	return m, nil
}

func asString(v []byte) (string, error) {
	s := &scanner{b: v}
	if s.peek() != '"' {
		return "", unreadable("expected a string")
	}
	str, err := s.str()
	if err != nil {
		return "", unreadable("%v", err)
	}
	return str, nil
}

func asBool(v []byte) (bool, error) {
	switch string(v) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, unreadable("expected a boolean")
}

func asInt(v []byte) (n int64, err error) {
	if len(v) == 0 || len(v) > 16 || (len(v) > 1 && v[0] == '0') {
		return 0, unreadable("expected an integer in 0..2^53-1")
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, unreadable("expected an integer in 0..2^53-1")
		}
		n = n*10 + int64(c-'0')
	}
	if n > maxSafeInt {
		return 0, unreadable("expected an integer in 0..2^53-1")
	}
	return n, nil
}

func asStringArray(v []byte) ([]string, error) {
	els, err := parseArray(v)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(els))
	for _, e := range els {
		s, err := asString(e)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// requireMembers fails unless every named member was assigned; when "v" is
// among them it must also be the integer 1.
func requireMembers(as map[string][]byte, names ...string) error {
	for _, name := range names {
		if _, ok := as[name]; !ok {
			return unreadable("missing required member %q", name)
		}
	}
	if raw, ok := as["v"]; ok {
		if n, err := asInt(raw); err != nil || n != 1 {
			return unreadable("v must be 1")
		}
	}
	return nil
}

// splitMembers separates the members named in known (keyed by their name, a
// duplicate being an error) from the unknown ones, which keep their order.
func splitMembers(ms []rawMember, known []string) (assigned map[string][]byte, extra []rawMember, err error) {
	assigned = make(map[string][]byte, len(ms))
	for _, m := range ms {
		name := ""
		for _, k := range known {
			if string(m.key) == k {
				name = k
				break
			}
		}
		switch _, dup := assigned[name]; {
		case name == "":
			extra = append(extra, m)
		case dup:
			return nil, nil, unreadable("duplicate member %q", name)
		default:
			assigned[name] = m.value
		}
	}
	return assigned, extra, nil
}

// ---------------------------------------------------------------------------
// Canonical encoding

// appendJSONString appends s as a JSON string using the canonical escaping
// rule shared by both clients: only '"', '\\' and U+0000..U+001F are escaped
// (\b \t \n \f \r short forms, others as \u00xx with lowercase hex); every
// other character, including U+007F, U+2028 and U+2029, is written as literal
// UTF-8.
func appendJSONString(b []byte, s string) []byte {
	const hexd = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&15])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// appendArray appends the JSON array of v, each element written by f.
func appendArray[T any](b []byte, v []T, f func([]byte, T) []byte) []byte {
	b = append(b, '[')
	for i, e := range v {
		if i > 0 {
			b = append(b, ',')
		}
		b = f(b, e)
	}
	return append(b, ']')
}

func appendMember(b []byte, first *bool, key string, appendVal func([]byte) []byte) []byte {
	if !*first {
		b = append(b, ',')
	}
	*first = false
	b = appendJSONString(b, key)
	b = append(b, ':')
	return appendVal(b)
}

func appendExtras(b []byte, first *bool, extra []ExtraMember) ([]byte, error) {
	for _, e := range extra {
		if err := e.validate(); err != nil {
			return nil, err
		}
		if !*first {
			b = append(b, ',')
		}
		*first = false
		b = append(b, e.RawKey...)
		b = append(b, ':')
		b = append(b, e.RawValue...)
	}
	return b, nil
}

// ExtraMember is an unknown top-level member kept verbatim (crypto.md §5.2):
// RawKey is the member name exactly as written including its quotes, RawValue
// the value text exactly as written (interior whitespace included, none
// around it).
type ExtraMember struct {
	RawKey   []byte
	RawValue []byte
}

func (e ExtraMember) validate() error {
	ks := &scanner{b: e.RawKey}
	if _, err := ks.str(); err != nil || ks.i != len(e.RawKey) {
		return errors.New("vaultcrypto: invalid extra member name")
	}
	vs := &scanner{b: e.RawValue}
	if err := vs.skipValue(); err != nil || vs.i != len(e.RawValue) || len(e.RawValue) == 0 || e.RawValue[0] == ' ' {
		return errors.New("vaultcrypto: invalid extra member value")
	}
	return nil
}

func cloneExtras(in []ExtraMember) []ExtraMember {
	if in == nil {
		return nil
	}
	out := make([]ExtraMember, len(in))
	for i, e := range in {
		out[i] = ExtraMember{RawKey: append([]byte(nil), e.RawKey...), RawValue: append([]byte(nil), e.RawValue...)}
	}
	return out
}

func extrasFrom(ms []rawMember) []ExtraMember {
	var out []ExtraMember
	for _, m := range ms {
		out = append(out, ExtraMember{RawKey: append([]byte(nil), m.rawKey...), RawValue: append([]byte(nil), m.value...)})
	}
	return out
}
