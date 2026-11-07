package vaultcrypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/tarnan3751/password-vault/internal/api"
	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

var cheapParams = api.KDFParams{Alg: "argon2id", Salt: bytes.Repeat([]byte{7}, 16), Time: 3, MemoryKiB: vc.MinMemoryKiB, Parallelism: 1}

func TestIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := vc.NewID()
		if !vc.ValidID(id) || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31) + "|"} {
		if vc.ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
}

func TestNormalizeUsername(t *testing.T) {
	ok := map[string]string{"Alice": "alice", "  bob \n": "bob", "a.b_c-d": "a.b_c-d", "0abc": "0abc", strings.Repeat("a", 32): strings.Repeat("a", 32)}
	for in, want := range ok {
		if got, err := vc.NormalizeUsername(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", " ", ".abc", "-abc", "_abc", "a b", strings.Repeat("a", 33), "alïce", "K", "İ", "a ", " a", "a/b", "a@b"} {
		if got, err := vc.NormalizeUsername(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestKDFParamValidationTable(t *testing.T) {
	good := vc.DefaultKDFParams()
	if err := vc.ValidateKDFParams(good); err != nil {
		t.Fatal(err)
	}
	if len(good.Salt) != 16 || good.Time != 3 || good.MemoryKiB != 65536 || good.Parallelism != 4 || good.Alg != "argon2id" {
		t.Fatalf("defaults %+v", good)
	}
	if bytes.Equal(good.Salt, vc.DefaultKDFParams().Salt) {
		t.Fatal("salt not random")
	}
	mut := func(f func(p *api.KDFParams)) api.KDFParams {
		p := good
		p.Salt = append([]byte(nil), good.Salt...)
		f(&p)
		return p
	}
	cases := []struct {
		name string
		p    api.KDFParams
		ok   bool
	}{
		{"alg", mut(func(p *api.KDFParams) { p.Alg = "argon2i" }), false},
		{"salt15", mut(func(p *api.KDFParams) { p.Salt = p.Salt[:15] }), false},
		{"salt nil", mut(func(p *api.KDFParams) { p.Salt = nil }), false},
		{"salt32", mut(func(p *api.KDFParams) { p.Salt = make([]byte, 32) }), true},
		{"salt64", mut(func(p *api.KDFParams) { p.Salt = make([]byte, 64) }), true},
		{"salt65", mut(func(p *api.KDFParams) { p.Salt = make([]byte, 65) }), false},
		{"m min", mut(func(p *api.KDFParams) { p.MemoryKiB = 65536 }), true},
		{"m min-1", mut(func(p *api.KDFParams) { p.MemoryKiB = 65535 }), false},
		{"m max", mut(func(p *api.KDFParams) { p.MemoryKiB = 262144 }), true},
		{"m max+1", mut(func(p *api.KDFParams) { p.MemoryKiB = 262145 }), false},
		{"t min", mut(func(p *api.KDFParams) { p.Time = 3 }), true},
		{"t min-1", mut(func(p *api.KDFParams) { p.Time = 2 }), false},
		{"t max", mut(func(p *api.KDFParams) { p.Time = 8 }), true},
		{"t max+1", mut(func(p *api.KDFParams) { p.Time = 9 }), false},
		{"p 0", mut(func(p *api.KDFParams) { p.Parallelism = 0 }), false},
		{"p 1", mut(func(p *api.KDFParams) { p.Parallelism = 1 }), true},
		{"p 16", mut(func(p *api.KDFParams) { p.Parallelism = 16 }), true},
		{"p 17", mut(func(p *api.KDFParams) { p.Parallelism = 17 }), false},
	}
	for _, c := range cases {
		err := vc.ValidateKDFParams(c.p)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
		if err != nil && !errors.Is(err, vc.ErrKDFParams) {
			t.Errorf("%s: error not ErrKDFParams", c.name)
		}
		if !c.ok {
			if _, e := vc.DeriveMasterKeys("alice", "x", c.p); e == nil {
				t.Errorf("%s: DeriveMasterKeys accepted", c.name)
			}
		}
	}
	// Unsafe variant must not panic on junk either.
	for _, p := range []api.KDFParams{{}, {Alg: "argon2id", Salt: make([]byte, 16), Time: 0, MemoryKiB: 64, Parallelism: 1}, {Alg: "argon2id", Salt: make([]byte, 16), Time: 1, MemoryKiB: 4, Parallelism: 1}} {
		if _, err := vc.DeriveMasterKeysUnsafeParams("alice", "x", p); err == nil {
			t.Errorf("unsafe accepted %+v", p)
		}
	}
}

func TestNFKCEquivalence(t *testing.T) {
	spellings := []string{"café ﬁx Ａ", "café fix A", "café fix A"}
	var first *vc.MasterKeys
	for _, s := range spellings {
		mk, err := vc.DeriveMasterKeys("alice", s, cheapParams)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = mk
		} else if mk.EncKey != first.EncKey || mk.LoginKey != first.LoginKey {
			t.Fatalf("spelling %q derives different keys", s)
		}
	}
	other, _ := vc.DeriveMasterKeys("alice", "cafe fix A", cheapParams)
	if other.EncKey == first.EncKey {
		t.Fatal("distinct passwords collide")
	}
	// no trimming
	sp, _ := vc.DeriveMasterKeys("alice", "pw ", cheapParams)
	nosp, _ := vc.DeriveMasterKeys("alice", "pw", cheapParams)
	if sp.EncKey == nosp.EncKey {
		t.Fatal("trailing space was trimmed")
	}
	if first.EncKey == first.LoginKey {
		t.Fatal("enc and login keys must differ")
	}
}

func TestBoxRoundTripAndProperties(t *testing.T) {
	for i := 0; i < 200; i++ {
		key := vc.NewVaultKey()
		pt := make([]byte, i*3)
		aad := make([]byte, i%17)
		rand.Read(pt)
		rand.Read(aad)
		box, err := vc.Seal(key, pt, aad)
		if err != nil || len(box) != 41+len(pt) {
			t.Fatal(err, len(box))
		}
		got, err := vc.Open(key, box, aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatal("round trip", err)
		}
		// flipping any single byte must break it
		j := i % len(box)
		bad := append([]byte(nil), box...)
		bad[j] ^= 0x40
		if _, err := vc.Open(key, bad, aad); !errors.Is(err, vc.ErrDecrypt) {
			t.Fatalf("byte %d flip accepted", j)
		}
	}
	k := vc.NewVaultKey()
	a, _ := vc.Seal(k, []byte("x"), nil)
	b, _ := vc.Seal(k, []byte("x"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("nonce reuse")
	}
	if _, err := vc.SealWithNonce(k, make([]byte, 23), nil, nil); err == nil {
		t.Fatal("short nonce accepted")
	}
	if _, err := vc.Open(nil, a, nil); !errors.Is(err, vc.ErrDecrypt) {
		t.Fatal("nil key")
	}
}

func TestWrapRoundTripAndNegatives(t *testing.T) {
	sSK, sPK, _ := vc.GenerateKeyPair()
	rSK, rPK, _ := vc.GenerateKeyPair()
	oSK, oPK, _ := vc.GenerateKeyPair()
	ctx := vc.WrapContext{VaultID: vc.NewID(), KeyEpoch: 3, SenderID: vc.NewID(), RecipientID: vc.NewID()}
	for i := 0; i < 20; i++ {
		vk := vc.NewVaultKey()
		w, err := vc.WrapVaultKey(vk, ctx, &sSK, &rPK)
		if err != nil || len(w) != vc.WrapLen || vc.WrapLen != 105 {
			t.Fatal(err, len(w))
		}
		got, err := vc.UnwrapVaultKey(w, ctx, &rSK, &sPK)
		if err != nil || *got != *vk {
			t.Fatal("unwrap", err)
		}
		if _, err := vc.UnwrapVaultKey(w, ctx, &oSK, &sPK); err == nil {
			t.Fatal("other recipient")
		}
		if _, err := vc.UnwrapVaultKey(w, ctx, &rSK, &oPK); err == nil {
			t.Fatal("wrong sender pk (sender not authenticated)")
		}
		c2 := ctx
		c2.KeyEpoch++
		if _, err := vc.UnwrapVaultKey(w, c2, &rSK, &sPK); err == nil {
			t.Fatal("epoch")
		}
		j := i * 5 % len(w)
		bad := append([]byte(nil), w...)
		bad[j] ^= 1
		if _, err := vc.UnwrapVaultKey(bad, ctx, &rSK, &sPK); err == nil {
			t.Fatalf("flip at %d accepted", j)
		}
		for _, n := range []int{0, 1, 104} {
			if _, err := vc.UnwrapVaultKey(w[:n], ctx, &rSK, &sPK); err == nil {
				t.Fatal("truncated accepted")
			}
		}
	}
	// invalid contexts
	vk := vc.NewVaultKey()
	for _, c := range []vc.WrapContext{{VaultID: "x", KeyEpoch: 1, SenderID: ctx.SenderID, RecipientID: ctx.RecipientID},
		{VaultID: ctx.VaultID, KeyEpoch: 0, SenderID: ctx.SenderID, RecipientID: ctx.RecipientID},
		{VaultID: ctx.VaultID, KeyEpoch: 1, SenderID: ctx.SenderID, RecipientID: "a|b"}} {
		if _, err := vc.WrapVaultKey(vk, c, &sSK, &rPK); err == nil {
			t.Errorf("invalid context accepted: %+v", c)
		}
	}
	// low-order recipient public key
	var zero vc.PublicKey
	if _, err := vc.WrapVaultKey(vk, ctx, &sSK, &zero); !errors.Is(err, vc.ErrLowOrderPoint) {
		t.Fatalf("zero recipient key: %v", err)
	}
	// self wrap
	w, err := vc.WrapVaultKey(vk, ctx, &sSK, &sPK)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := vc.UnwrapVaultKey(w, ctx, &sSK, &sPK); err != nil || *got != *vk {
		t.Fatal(err)
	}
}

func TestAccountLifecycle(t *testing.T) {
	uid := vc.NewID()
	mk, err := vc.DeriveMasterKeys("alice", "pw one", cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	sec, up, err := vc.NewAccount(uid, mk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := vc.UnlockAccount(uid, mk, up.PublicKey, up.WrappedAccountKey, up.EncPrivateKey)
	if err != nil || got.AccountKey != sec.AccountKey || got.PublicKey != sec.PublicKey {
		t.Fatal(err)
	}
	wrong, _ := vc.DeriveMasterKeys("alice", "pw two", cheapParams)
	if _, err := vc.UnlockAccount(uid, wrong, up.PublicKey, up.WrappedAccountKey, up.EncPrivateKey); !errors.Is(err, vc.ErrDecrypt) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := vc.UnlockAccount(uid, mk, up.PublicKey[:31], up.WrappedAccountKey, up.EncPrivateKey); err == nil {
		t.Fatal("short public key accepted")
	}
	// password change keeps key pair, nothing else re-encrypted
	p2 := cheapParams
	p2.Salt = bytes.Repeat([]byte{9}, 16)
	mk2, _ := vc.DeriveMasterKeys("alice", "pw two", p2)
	w2, err := vc.RewrapAccountKey(uid, &got.AccountKey, mk2)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := vc.UnlockAccount(uid, mk2, up.PublicKey, w2, up.EncPrivateKey)
	if err != nil || got2.PrivateKey != sec.PrivateKey {
		t.Fatal(err)
	}
	if _, err := vc.UnlockAccount(uid, mk, up.PublicKey, w2, up.EncPrivateKey); err == nil {
		t.Fatal("old password still works")
	}
	if _, _, err := vc.NewAccount("not-an-id", mk); err == nil {
		t.Fatal("bad user id accepted")
	}
}

func TestRedaction(t *testing.T) {
	k := vc.NewVaultKey()
	mk := &vc.MasterKeys{EncKey: *k}
	sec := &vc.AccountSecrets{AccountKey: *k, UserID: "u"}
	priv, _, _ := vc.GenerateKeyPair()
	hexs := fmt.Sprintf("%x", k[:])
	for _, v := range []any{k, *k, mk, *mk, sec, *sec, &priv, priv, struct{ K vc.SymmetricKey }{*k}, []vc.SymmetricKey{*k}} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
			if s := fmt.Sprintf(f, v); strings.Contains(s, hexs) || strings.Contains(s, fmt.Sprint([]byte(k[:]))) {
				t.Errorf("%s of %T leaks: %s", f, v, s)
			}
		}
	}
	if _, err := json.Marshal(k); err == nil {
		t.Error("SymmetricKey marshalled")
	}
	if _, err := json.Marshal(struct{ P vc.PrivateKey }{priv}); err == nil {
		t.Error("PrivateKey marshalled")
	}
	if s := fmt.Sprintf("%v", vc.Item{Password: "hunter2"}); strings.Contains(s, "hunter2") {
		t.Error("Item leaks")
	}
}

func TestPad(t *testing.T) {
	for n := 0; n < 700; n++ {
		in := bytes.Repeat([]byte{'x'}, n)
		out := vc.Pad(in, 256)
		if len(out) == 0 || len(out)%256 != 0 || len(out)-n >= 256 && n != 0 || !bytes.HasPrefix(out, in) || strings.Trim(string(out[n:]), " ") != "" {
			t.Fatalf("n=%d len=%d", n, len(out))
		}
		if n > 0 && n%256 == 0 && len(out) != n {
			t.Fatalf("multiple of n changed at %d", n)
		}
	}
	if got := vc.Pad(nil, 64); len(got) != 64 {
		t.Fatalf("empty input padded to %d", len(got))
	}
	in := []byte("abc")
	out := vc.Pad(in, 64)
	out[0] = 'z'
	if in[0] != 'a' {
		t.Fatal("aliasing")
	}
}

func ex(k, v string) vc.ExtraMember { return vc.ExtraMember{RawKey: []byte(k), RawValue: []byte(v)} }

func sampleItem() *vc.Item {
	return &vc.Item{V: 1, Type: "login", Name: "Bank", Username: "u", Password: "p0", URLs: []string{"https://x"}, Tags: []string{"a"},
		CreatedAt: 1, UpdatedAt: 1, Extra: []vc.ExtraMember{ex(`"zz_future"`, `{"a":[1,2]}`), ex(`"aa_other"`, `"s"`)}}
}

func TestItemCanonicalEncoding(t *testing.T) {
	got, err := (&vc.Item{V: 1, Type: "login", Name: "caf\u00e9\u2028\"\\\n\u0001\u007f<>&", Password: "p", Fields: []vc.CustomField{{Name: "a", Value: "b", Hidden: true}, {Name: "c"}},
		CreatedAt: 5, UpdatedAt: 6, PasswordHistory: []vc.PasswordHistoryEntry{{Password: "o", ChangedAt: 3}}, Extra: []vc.ExtraMember{ex(`"zz"`, `1.0`), ex(`"aa"`, `-0`)}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"v\":1,\"type\":\"login\",\"name\":\"caf\u00e9\u2028\\\"\\\\\\n\\u0001\u007f<>&\",\"password\":\"p\",\"fields\":[{\"name\":\"a\",\"value\":\"b\",\"hidden\":true},{\"name\":\"c\",\"value\":\"\"}],\"created_at\":5,\"updated_at\":6,\"password_history\":[{\"password\":\"o\",\"changed_at\":3}],\"zz\":1.0,\"aa\":-0}"
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestStrictDecodingRules(t *testing.T) {
	accept := map[string]string{
		`{"v":1,"type":"note","name":"n"}  `:                        `{"v":1,"type":"note","name":"n","created_at":0,"updated_at":0}`,
		`{"v":1,"type":"note","Name":"U","name":"l"}`:               `{"v":1,"type":"note","name":"l","created_at":0,"updated_at":0,"Name":"U"}`,
		`{"v":1,"type":"note","name":"a","x":12345678901234567890}`: `{"v":1,"type":"note","name":"a","created_at":0,"updated_at":0,"x":12345678901234567890}`,
		`{"v":1,"type":"note","name":"\ud83d\udd11"}`:               "{\"v\":1,\"type\":\"note\",\"name\":\"\U0001F511\",\"created_at\":0,\"updated_at\":0}",
	}
	for in, want := range accept {
		it, err := vc.DecodeItem([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		got, _ := it.Encode()
		if string(got) != want {
			t.Errorf("%s\n got %s\nwant %s", in, got, want)
		}
	}
	for _, in := range []string{
		`{"v":1,"type":"note","name":"a","name":"b"}`, `{"v":1,"type":"note","name":null}`, `{"v":1.0,"type":"note","name":"a"}`,
		`{"v":1,"type":"note","name":"a","created_at":9007199254740992}`, `{"v":1,"type":"note","name":"a"} x`,
		`{"v":1,"type":"note","name":"a","urls":[null]}`, "{\"v\":1,\"type\":\"note\",\"name\":\"\xff\"}",
		`{"v":1,"type":"note","name":"\ud800"}`, `{"v":1,"type":"note","Name":"a"}`,
	} {
		if _, err := vc.DecodeItem([]byte(in)); !errors.Is(err, vc.ErrUnreadable) {
			t.Errorf("%q accepted or wrong error: %v", in, err)
		}
	}
	// deep nesting in an unknown member must not blow the stack
	deep := `{"v":1,"type":"note","name":"a","x":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`
	if _, err := vc.DecodeItem([]byte(deep)); err != nil {
		t.Errorf("deep nesting: %v", err)
	}
	if _, err := vc.DecodeItem([]byte(`{"v":1,"type":"note","name":"a","x":` + strings.Repeat("[", 200000))); err == nil {
		t.Error("unterminated deep nesting accepted")
	}
}

func TestItemUnknownFieldsByteForByte(t *testing.T) {
	in := `{"v":1,"type":"note","name":"n","future_obj":{"x" : [1,{"y":null}]},"future_num":1.50,"Name":"case-variant","password":"pp","\u0078":0}`
	it, err := vc.DecodeItem([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if it.Name != "n" || it.Password != "pp" || len(it.Extra) != 4 {
		t.Fatalf("%d extras", len(it.Extra))
	}
	renamed := vc.EditItem(it, 9, func(i *vc.Item) { i.Name = "m" })
	out, err := renamed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{`"future_obj":{"x" : [1,{"y":null}]}`, `"future_num":1.50`, `"Name":"case-variant"`, `"\u0078":0`} {
		if !strings.Contains(string(out), frag) {
			t.Fatalf("lost %s in %s", frag, out)
		}
	}
	if i, j := strings.Index(string(out), "future_obj"), strings.Index(string(out), "future_num"); i > j {
		t.Fatal("extras reordered")
	}
}

func TestItemRoundTripRandom(t *testing.T) {
	vk := vc.NewVaultKey()
	vid, iid := vc.NewID(), vc.NewID()
	randStr := func() string {
		var b strings.Builder
		for i, n := 0, mathRand(40); i < n; i++ {
			switch mathRand(4) {
			case 0:
				b.WriteRune(rune('a' + mathRand(26)))
			case 1:
				b.WriteRune(rune(0x4e00 + mathRand(500)))
			case 2:
				b.WriteString([]string{"<", ">", "&", "\"", "\\", "\n", "\u2028", "\U0001F511", "\u0000", "\u007f"}[mathRand(10)])
			default:
				b.WriteRune(unicode.ReplacementChar)
			}
		}
		return b.String()
	}
	for i := 0; i < 200; i++ {
		it := &vc.Item{V: 1, Type: []string{"login", "note"}[mathRand(2)], Name: randStr(), Username: randStr(), Password: randStr(), Notes: randStr(),
			URLs: []string{randStr()}, CreatedAt: int64(mathRand(1 << 30)), UpdatedAt: int64(mathRand(1 << 30)),
			Fields:          []vc.CustomField{{Name: randStr(), Value: randStr(), Hidden: mathRand(2) == 0}},
			PasswordHistory: []vc.PasswordHistoryEntry{{Password: randStr(), ChangedAt: 5}},
			Extra:           []vc.ExtraMember{ex(jsonStr(fmt.Sprintf("x_%d", i)), fmt.Sprintf(`{"n":%d, "s":%s}`, i, jsonStr(randStr())))}}
		blob, err := vc.EncryptItem(vk, vid, iid, 2, it)
		if err != nil {
			t.Fatal(err)
		}
		got, err := vc.DecryptItem(vk, vid, iid, 2, blob)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := it.Encode()
		b, _ := got.Encode()
		if !bytes.Equal(a, b) {
			t.Fatalf("round trip differs:\n%s\n%s", a, b)
		}
		if len(blob)%256 != 41 {
			t.Fatalf("blob length %d not padded", len(blob))
		}
		if _, err := vc.DecryptItem(vk, vid, iid, 3, blob); !errors.Is(err, vc.ErrDecrypt) {
			t.Fatal("wrong epoch accepted")
		}
	}
	if _, err := vc.DecryptItem(vk, vid, vc.NewID(), 1, mustEnc(t, vk, vid, iid)); !errors.Is(err, vc.ErrDecrypt) {
		t.Fatal("item moved to another ID accepted")
	}
}

func mathRand(n int) int {
	var b [4]byte
	rand.Read(b[:])
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % n
}

func mustEnc(t *testing.T, vk *vc.SymmetricKey, vid, iid string) []byte {
	b, err := vc.EncryptItem(vk, vid, iid, 1, sampleItem())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestItemValidation(t *testing.T) {
	vk := vc.NewVaultKey()
	vid, iid := vc.NewID(), vc.NewID()
	bad := []*vc.Item{{V: 2, Type: "login"}, {V: 1, Type: "card"}, {V: 0, Type: "login"}, {V: 1, Type: "note", CreatedAt: -1}, {V: 1, Type: "note", UpdatedAt: 1 << 53}}
	for _, it := range bad {
		if _, err := vc.EncryptItem(vk, vid, iid, 1, it); err == nil {
			t.Errorf("%+v accepted", it.Type)
		}
	}
	if _, err := vc.EncryptItem(vk, "bad", iid, 1, sampleItem()); err == nil {
		t.Error("bad vault id accepted")
	}
	if _, err := vc.EncryptItem(vk, vid, iid, 0, sampleItem()); err == nil {
		t.Error("epoch 0 accepted")
	}
	if _, err := vc.DecryptItem(vk, vid, iid, 0, []byte{1}); err == nil {
		t.Error("epoch 0 accepted")
	}
	if _, err := vc.EncryptItem(vk, vid, iid, 1, &vc.Item{V: 1, Type: "note", Extra: []vc.ExtraMember{ex(`name`, `1`)}}); err == nil {
		t.Error("invalid extra key accepted")
	}
	if _, err := vc.EncryptItem(vk, vid, iid, 1, &vc.Item{V: 1, Type: "note", Extra: []vc.ExtraMember{ex(`"k"`, `[1,`)}}); err == nil {
		t.Error("invalid extra value accepted")
	}
	blob, _ := vc.Seal(vk, vc.Pad([]byte(`{"v":2,"type":"login","name":"n"}`), 256), vc.ItemAAD(vid, iid, 1))
	if _, err := vc.DecryptItem(vk, vid, iid, 1, blob); err == nil {
		t.Error("v2 accepted")
	}
}

func TestVaultMeta(t *testing.T) {
	vk := vc.NewVaultKey()
	vid := vc.NewID()
	blob, err := vc.EncryptVaultMeta(vk, vid, 7, &vc.VaultMeta{Name: "Family <3>", Extra: []vc.ExtraMember{ex(`"f"`, `[1,  2]`)}})
	if err != nil || (len(blob)-41)%64 != 0 {
		t.Fatal(err, len(blob))
	}
	m, err := vc.DecryptVaultMeta(vk, vid, 7, blob)
	if err != nil || m.Name != "Family <3>" || m.V != 1 || string(m.Extra[0].RawValue) != `[1,  2]` {
		t.Fatal(err, m)
	}
	m.Name = "Renamed"
	b2, _ := vc.EncryptVaultMeta(vk, vid, 7, m)
	m2, err := vc.DecryptVaultMeta(vk, vid, 7, b2)
	if err != nil || m2.Name != "Renamed" || string(m2.Extra[0].RawValue) != `[1,  2]` {
		t.Fatal("rename lost extras", err)
	}
	if _, err := vc.DecryptVaultMeta(vk, vc.NewID(), 7, blob); !errors.Is(err, vc.ErrDecrypt) {
		t.Fatal("wrong vault accepted")
	}
	if _, err := vc.DecryptVaultMeta(vk, vid, 8, blob); !errors.Is(err, vc.ErrDecrypt) {
		t.Fatal("wrong epoch accepted")
	}
	if _, err := vc.EncryptVaultMeta(vk, vid, 0, m); err == nil {
		t.Fatal("epoch 0")
	}
}

func TestEditItem(t *testing.T) {
	old := sampleItem()
	old.PasswordHistory = nil
	snapshot, _ := old.Encode()
	n := vc.EditItem(old, 100, func(it *vc.Item) { it.Name = "Renamed" })
	if n.UpdatedAt != 100 || n.CreatedAt != 1 || len(n.PasswordHistory) != 0 || n.Password != "p0" {
		t.Fatalf("%+v", n)
	}
	if string(n.Extra[0].RawValue) != `{"a":[1,2]}` {
		t.Fatal("extra lost")
	}
	cur := n
	for i := 1; i <= 15; i++ {
		cur = vc.EditItem(cur, int64(100+i), func(it *vc.Item) { it.Password = fmt.Sprintf("p%d", i) })
	}
	if len(cur.PasswordHistory) != vc.MaxPasswordHistory {
		t.Fatalf("history %d", len(cur.PasswordHistory))
	}
	if cur.PasswordHistory[0].Password != "p14" || cur.PasswordHistory[0].ChangedAt != 115 || cur.PasswordHistory[9].Password != "p5" {
		t.Fatalf("%+v", cur.PasswordHistory)
	}
	same := vc.EditItem(cur, 999, func(it *vc.Item) { it.Password = "p15"; it.Notes = "x" })
	if len(same.PasswordHistory) != 10 || same.PasswordHistory[0].Password != "p14" || same.UpdatedAt != 999 {
		t.Fatal("history changed without password change")
	}
	e := vc.EditItem(&vc.Item{V: 1, Type: "note", Name: "n"}, 5, func(it *vc.Item) { it.Password = "new" })
	if len(e.PasswordHistory) != 0 {
		t.Fatal("empty password recorded")
	}
	after, _ := old.Encode()
	if !bytes.Equal(snapshot, after) {
		t.Fatal("EditItem mutated its input")
	}
}

func sampleRoster(t testing.TB) (*vc.Roster, []vc.RosterMember) {
	var ms []vc.RosterMember
	for _, role := range []string{vc.RoleOwner, vc.RoleEditor, vc.RoleViewer} {
		_, pk, _ := vc.GenerateKeyPair()
		ms = append(ms, vc.RosterMember{ID: vc.NewID(), PublicKey: pk, Role: role})
	}
	var err error
	r := &vc.Roster{V: 1, Members: []vc.RosterMember{ms[0]}}
	for _, m := range ms[1:] {
		if r, err = r.WithMember(m); err != nil {
			t.Fatal(err)
		}
	}
	return r, ms
}

func TestRosterOperations(t *testing.T) {
	r, ms := sampleRoster(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(r.Members); i++ {
		if r.Members[i-1].ID >= r.Members[i].ID {
			t.Fatal("not sorted")
		}
	}
	for _, m := range ms {
		if got, ok := r.Member(m.ID); !ok || got != m {
			t.Fatal("lookup")
		}
	}
	if _, ok := r.Member(vc.NewID()); ok {
		t.Fatal("phantom member")
	}
	if _, err := r.WithMember(ms[1]); err == nil {
		t.Fatal("duplicate add accepted")
	}
	// the original roster is never mutated
	before, _ := r.Encode()
	r2, err := r.WithRole(ms[1].ID, vc.RoleOwner)
	if err != nil || len(r2.Owners()) != 2 {
		t.Fatal(err)
	}
	if _, err := r.WithRole(ms[0].ID, vc.RoleViewer); err == nil {
		t.Fatal("demoting the last owner accepted")
	}
	if _, err := r.WithRole(ms[1].ID, "admin"); err == nil {
		t.Fatal("bad role accepted")
	}
	if _, err := r.Without(ms[0].ID); err == nil {
		t.Fatal("removing the last owner accepted")
	}
	if _, err := r.Without(vc.NewID()); err == nil {
		t.Fatal("removing a stranger accepted")
	}
	r3, err := r.Without(ms[2].ID)
	if err != nil || len(r3.Members) != 2 {
		t.Fatal(err)
	}
	after, _ := r.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("roster mutated")
	}
	// encrypt/decrypt round trip
	vk, vid := vc.NewVaultKey(), vc.NewID()
	blob, err := vc.EncryptRoster(vk, vid, 3, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := vc.DecryptRoster(vk, vid, 3, blob)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := got.Encode()
	if !bytes.Equal(a, before) {
		t.Fatal("round trip differs")
	}
	if len(blob) != 41+len(before) {
		t.Fatal("roster must not be padded")
	}
	for _, bad := range []struct {
		vid string
		ep  uint32
	}{{vc.NewID(), 3}, {vid, 4}, {vid, 2}} {
		if _, err := vc.DecryptRoster(vk, bad.vid, bad.ep, blob); !errors.Is(err, vc.ErrDecrypt) {
			t.Fatalf("%v", err)
		}
	}
	// invalid rosters are not encodable
	inv := []*vc.Roster{
		{V: 2, Members: r.Members},
		{V: 1},
		{V: 1, Members: []vc.RosterMember{r.Members[1], r.Members[0]}},
		{V: 1, Members: []vc.RosterMember{{ID: "x", Role: vc.RoleOwner}}},
		{V: 1, Members: []vc.RosterMember{r.Members[0], r.Members[0]}},
	}
	for i, x := range inv {
		if _, err := vc.EncryptRoster(vk, vid, 1, x); err == nil {
			t.Errorf("invalid roster %d accepted", i)
		}
	}
}

func TestReencryptProperty(t *testing.T) {
	oldK, newK := vc.NewVaultKey(), vc.NewVaultKey()
	vid, iid := vc.NewID(), vc.NewID()
	for i := 0; i < 100; i++ {
		pt := make([]byte, mathRand(600))
		rand.Read(pt)
		blob, _ := vc.Seal(oldK, pt, vc.ItemAAD(vid, iid, 1))
		out, opened, err := vc.ReencryptItem(oldK, newK, vid, iid, 1, 2, blob)
		if err != nil || !opened {
			t.Fatal(err, opened)
		}
		got, err := vc.Open(newK, out, vc.ItemAAD(vid, iid, 2))
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatal("plaintext changed")
		}
		if _, err := vc.Open(newK, out, vc.ItemAAD(vid, iid, 1)); err == nil {
			t.Fatal("old epoch AAD still valid")
		}
		// wrong epoch / key: carried over unchanged
		out2, opened2, err := vc.ReencryptItem(oldK, newK, vid, iid, 5, 6, blob)
		if err != nil || opened2 || !bytes.Equal(out2, blob) {
			t.Fatal("carry-over failed")
		}
		mb, _ := vc.Seal(oldK, pt, vc.VaultMetaAAD(vid, 1))
		mo, mop, err := vc.ReencryptMeta(oldK, newK, vid, 1, 2, mb)
		if err != nil || !mop {
			t.Fatal(err)
		}
		if g, err := vc.Open(newK, mo, vc.VaultMetaAAD(vid, 2)); err != nil || !bytes.Equal(g, pt) {
			t.Fatal("meta plaintext changed")
		}
	}
	if _, _, err := vc.ReencryptItem(oldK, newK, vid, iid, 0, 1, nil); err == nil {
		t.Fatal("epoch 0 accepted")
	}
	if _, _, err := vc.ReencryptItem(oldK, newK, "bad", iid, 1, 2, nil); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestPolicyBasics(t *testing.T) {
	if err := vc.CheckMasterPassword("correct horse battery staple", "alice"); err != nil {
		t.Fatal(err)
	}
	var pe *vc.PolicyError
	if err := vc.CheckMasterPassword("short", "alice"); !errors.As(err, &pe) || pe.Code != vc.PolicyTooShort || pe.Reason == "" {
		t.Fatal(err)
	}
	if vc.PasswordHint("correct horse battery staple") != "" || vc.PasswordHint("hunter2hunter2") == "" {
		t.Fatal("hint")
	}
	l := vc.CommonPasswords()
	if len(l) < 200 || len(l) > 3000 || !sort.StringsAreSorted(l) {
		t.Fatalf("common list size %d", len(l))
	}
	for _, p := range l {
		if len([]rune(p)) < vc.MinPasswordLength {
			t.Fatalf("%q is shorter than the minimum, pointless entry", p)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	classes := map[vc.CharClass]string{vc.Lower: "abcdefghijklmnopqrstuvwxyz", vc.Upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", vc.Digits: "0123456789"}
	for i := 0; i < 500; i++ {
		pw, err := vc.GeneratePassword(4)
		if err != nil || len(pw) != 4 {
			t.Fatal(err, pw)
		}
		var l, u, d, s bool
		for _, r := range pw {
			switch {
			case strings.ContainsRune(classes[vc.Lower], r):
				l = true
			case strings.ContainsRune(classes[vc.Upper], r):
				u = true
			case strings.ContainsRune(classes[vc.Digits], r):
				d = true
			default:
				s = true
			}
		}
		if !(l && u && d && s) {
			t.Fatalf("missing class in %q", pw)
		}
	}
	pw, err := vc.GeneratePassword(30, vc.WithClasses(vc.Digits))
	if err != nil || strings.Trim(pw, "0123456789") != "" || len(pw) != 30 {
		t.Fatal(pw, err)
	}
	pw, _ = vc.GeneratePassword(200, vc.ExcludeAmbiguous())
	if strings.ContainsAny(pw, "O0oIl1|") {
		t.Fatalf("ambiguous char in %q", pw)
	}
	for _, bad := range []int{-1, 0, 3, 1025} {
		if _, err := vc.GeneratePassword(bad); err == nil {
			t.Errorf("length %d accepted", bad)
		}
	}
	if _, err := vc.GeneratePassword(10, vc.WithClasses()); err == nil {
		t.Error("no classes accepted")
	}
	if _, err := vc.GeneratePassword(10, vc.WithClasses(vc.CharClass(9))); err == nil {
		t.Error("unknown class accepted")
	}
	// distribution sanity: digits-only, 100000 samples, chi-square vs uniform
	counts := make([]int, 10)
	const total = 100000
	for i := 0; i < total/50; i++ {
		p, _ := vc.GeneratePassword(50, vc.WithClasses(vc.Digits))
		for _, r := range p {
			counts[r-'0']++
		}
	}
	exp := float64(total) / 10
	chi := 0.0
	for _, c := range counts {
		chi += (float64(c) - exp) * (float64(c) - exp) / exp
	}
	if chi > 40 { // 9 dof; p ~ 1e-5
		t.Fatalf("digits not uniform: chi2=%.1f counts=%v", chi, counts)
	}
	// position sanity: first char should not always come from the first class
	first := map[byte]bool{}
	for i := 0; i < 200; i++ {
		p, _ := vc.GeneratePassword(8)
		first[p[0]] = true
	}
	if len(first) < 20 {
		t.Fatalf("first-character diversity too low: %d", len(first))
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	vc.Zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal()
	}
	k := vc.NewVaultKey()
	k.Zero()
	if *k != (vc.SymmetricKey{}) {
		t.Fatal()
	}
}

func TestFingerprintFormat(t *testing.T) {
	_, pk, _ := vc.GenerateKeyPair()
	uid := vc.NewID()
	fp, err := vc.Fingerprint(uid, "alice", pk)
	if err != nil || len(fp) != 39 {
		t.Fatal(fp, err)
	}
	for i, c := range fp {
		if (i+1)%5 == 0 {
			if c != '-' {
				t.Fatal(fp)
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatal(fp)
		}
	}
	other, _ := vc.Fingerprint(uid, "alicf", pk)
	other2, _ := vc.Fingerprint(vc.NewID(), "alice", pk)
	if other == fp || other2 == fp {
		t.Fatal("fingerprint must depend on username and user ID")
	}
	for _, bad := range [][2]string{{"short", "alice"}, {uid, "Alice"}, {uid, ""}, {uid, "al ice"}} {
		if _, err := vc.Fingerprint(bad[0], bad[1], pk); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func FuzzOpen(f *testing.F) {
	key := vc.NewVaultKey()
	good, _ := vc.Seal(key, []byte("hello"), []byte("aad"))
	f.Add(good, []byte("aad"))
	f.Add([]byte{}, []byte{})
	f.Add(good[:40], []byte("aad"))
	f.Fuzz(func(t *testing.T, box, aad []byte) {
		pt, err := vc.Open(key, box, aad)
		if err == nil && !bytes.Equal(box, good) && len(pt) == 5 && string(pt) == "hello" && string(aad) == "aad" {
			// only the original may decrypt to this under this key/aad
			t.Fatal("forgery")
		}
	})
}

func FuzzUnwrapVaultKey(f *testing.F) {
	sSK, sPK, _ := vc.GenerateKeyPair()
	rSK, rPK, _ := vc.GenerateKeyPair()
	ctx := vc.WrapContext{VaultID: vc.NewID(), KeyEpoch: 1, SenderID: vc.NewID(), RecipientID: vc.NewID()}
	w, _ := vc.WrapVaultKey(vc.NewVaultKey(), ctx, &sSK, &rPK)
	f.Add(w, uint32(1))
	f.Add(w[:104], uint32(1))
	f.Add([]byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, wrap []byte, epoch uint32) {
		c := ctx
		c.KeyEpoch = epoch
		_, _ = vc.UnwrapVaultKey(wrap, c, &rSK, &sPK)
	})
}

func FuzzItemDecode(f *testing.F) {
	good, _ := sampleItem().Encode()
	f.Add(good)
	f.Add([]byte(`{"v":1,"type":"note","name":"x","a":{"b":[1]}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"v":1,"type":"login","name":"n","fields":[{"name":1}]}`))
	f.Add([]byte("{\"v\":1,\"type\":\"note\",\"name\":\"\xff\"}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		it, err := vc.DecodeItem(data)
		if err != nil {
			return
		}
		out, err := it.Encode()
		if err != nil {
			t.Fatalf("decoded item does not re-encode: %v", err)
		}
		it2, err := vc.DecodeItem(out)
		if err != nil {
			t.Fatalf("re-encoded item does not decode: %v", err)
		}
		out2, _ := it2.Encode()
		if !bytes.Equal(out, out2) {
			t.Fatal("encoding not a fixed point")
		}
	})
}

func FuzzMetaDecode(f *testing.F) {
	f.Add([]byte(`{"v":1,"name":"F","x":[1]}`))
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := vc.DecodeVaultMeta(data)
		if err != nil {
			return
		}
		out, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m2, err := vc.DecodeVaultMeta(out)
		if err != nil {
			t.Fatal(err)
		}
		if out2, _ := m2.Encode(); !bytes.Equal(out, out2) {
			t.Fatal("not a fixed point")
		}
	})
}

func FuzzDecryptRoster(f *testing.F) {
	vk, vid := vc.NewVaultKey(), vc.NewID()
	r, _ := sampleRoster(f)
	blob, _ := vc.EncryptRoster(vk, vid, 1, r)
	good, _ := r.Encode()
	f.Add(blob, good)
	f.Add([]byte{}, []byte(`{"v":1,"members":[]}`))
	f.Add(blob[:40], []byte("x"))
	f.Fuzz(func(t *testing.T, box, plaintext []byte) {
		_, _ = vc.DecryptRoster(vk, vid, 1, box)
		// also feed arbitrary plaintext through the decoder (an authentic but hostile roster)
		if r, err := vc.DecodeRoster(plaintext); err == nil {
			if r.Validate() != nil {
				t.Fatal("decoded roster violates its invariants")
			}
			out, err := r.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := vc.DecodeRoster(out); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }
