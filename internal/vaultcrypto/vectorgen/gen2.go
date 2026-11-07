package vectorgen

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/backup"
	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
	"golang.org/x/crypto/argon2"
)

func masterKeyCase(id, desc, username, password string, salt []byte, t, m uint32, p uint8, below bool) MasterKeyCase {
	params := api.KDFParams{Alg: "argon2id", Salt: salt, Time: t, MemoryKiB: m, Parallelism: p}
	norm := vc.NormalizePassword(password)
	as := sha256.Sum256(append([]byte("fpv/v1/kdf-salt|"+username+"|"), salt...))
	mkRaw := argon2.IDKey(norm, as[:], t, m, p, 32)
	mk := must(vc.DeriveMasterKeysUnsafeParams(username, password, params))
	return MasterKeyCase{
		ID: id, Description: desc, Username: username, Password: password, PasswordHex: hx([]byte(password)),
		NormalizedPasswordHex: hx(norm), SaltHex: hx(salt), ArgonSaltHex: hx(as[:]), Time: t, MemoryKiB: m, Parallelism: p,
		BelowProductionMin: below, MasterKeyHex: hx(mkRaw), EncKeyHex: hx(mk.EncKey[:]), LoginKeyHex: hx(mk.LoginKey[:]),
	}
}

func genKDF(f *File) {
	salt := det("kdf/salt", 16)
	const cheap = "Deliberately cheap Argon2id parameters, BELOW the accepted bounds of crypto.md section 2: a validating implementation must reject them in deriveMasterKeys and accept them only in the test-vector-only variant."
	f.MasterKeys = []MasterKeyCase{
		masterKeyCase("mk-ascii-cheap", cheap, "alice", "correct horse battery staple", salt, 1, 64, 1, true),
		masterKeyCase("mk-other-username-cheap", cheap+" Same password and salt as mk-ascii-cheap, different username: every key differs.", "bob", "correct horse battery staple", salt, 1, 64, 1, true),
		masterKeyCase("mk-empty-password-cheap", cheap+" Empty password.", "alice", "", salt, 1, 64, 1, true),
		masterKeyCase("mk-nfkc-ligature-fullwidth-cheap", cheap+" The password contains U+FB01 (fi ligature), full-width letters/digits and a combining sequence; NFKC changes it (to \"fifull123\" + precomposed U+00E9 + \" X\").",
			"alice", "\ufb01\uff46\uff55\uff4c\uff4c\uff11\uff12\uff13e\u0301 \uff38", salt, 2, 64, 1, true),
		masterKeyCase("mk-nfkc-already-normalized-cheap", cheap+" The NFKC-normalised spelling of mk-nfkc-ligature-fullwidth-cheap: must yield identical keys.",
			"alice", "fifull123\u00e9 X", salt, 2, 64, 1, true),
		masterKeyCase("mk-nonbmp-cheap", cheap+" Password with a non-BMP code point (U+1F511) and no normalisation change.", "alice.b-c_d", "k\U0001F511y", salt, 1, 64, 1, true),
		masterKeyCase("mk-long-salt-cheap", cheap+" 64-byte salt (the maximum).", "alice", "correct horse battery staple", det("kdf/salt64", 64), 1, 64, 1, true),
		masterKeyCase("mk-production-defaults", "Production default parameters t=3, m=65536 KiB, p=4 (RFC 9106 second recommended option). Within the accepted bounds: DeriveMasterKeys must accept.", "alice", "correct horse battery staple", salt, 3, 65536, 4, false),
		masterKeyCase("mk-production-max-bounds-p16", "t=3, m=65536, p=16: within bounds, high parallelism.", "alice", "correct horse battery staple", salt, 3, 65536, 16, false),
	}

	hexSalt := func(n int) string { return hx(det("kdf/validation-salt", n)) }
	v := func(id, desc, alg, saltHex string, t, m, p uint32, ok bool) {
		f.KDFValidation = append(f.KDFValidation, KDFValidationCase{ID: id, Description: desc, Alg: alg, SaltHex: saltHex, Time: t, MemoryKiB: m, Parallelism: p, Valid: ok})
	}
	v("kdfv-defaults", "production defaults", "argon2id", hexSalt(16), 3, 65536, 4, true)
	v("kdfv-minimums", "every parameter exactly at its lower bound", "argon2id", hexSalt(16), 3, 65536, 1, true)
	v("kdfv-maximums", "every upper bound exactly", "argon2id", hexSalt(64), 8, 262144, 16, true)
	v("kdfv-salt-32", "32-byte salt", "argon2id", hexSalt(32), 3, 65536, 4, true)
	v("kdfv-alg-argon2i", "wrong algorithm", "argon2i", hexSalt(16), 3, 65536, 4, false)
	v("kdfv-alg-empty", "empty algorithm", "", hexSalt(16), 3, 65536, 4, false)
	v("kdfv-alg-case", "algorithm is case sensitive", "Argon2id", hexSalt(16), 3, 65536, 4, false)
	v("kdfv-salt-15", "salt one byte too short", "argon2id", hexSalt(15), 3, 65536, 4, false)
	v("kdfv-salt-65", "salt one byte too long", "argon2id", hexSalt(65), 3, 65536, 4, false)
	v("kdfv-salt-empty", "empty salt", "argon2id", "", 3, 65536, 4, false)
	v("kdfv-mem-below", "memory one KiB below the lower bound", "argon2id", hexSalt(16), 3, 65535, 4, false)
	v("kdfv-mem-old-minimum", "the previous draft's minimum (19456) is now too weak", "argon2id", hexSalt(16), 3, 19456, 4, false)
	v("kdfv-mem-above", "memory one KiB above the upper bound", "argon2id", hexSalt(16), 3, 262145, 4, false)
	v("kdfv-mem-1gib", "1 GiB request", "argon2id", hexSalt(16), 3, 1048576, 4, false)
	v("kdfv-mem-zero", "zero memory", "argon2id", hexSalt(16), 3, 0, 4, false)
	v("kdfv-time-2", "time one below the lower bound", "argon2id", hexSalt(16), 2, 65536, 4, false)
	v("kdfv-time-0", "zero time", "argon2id", hexSalt(16), 0, 65536, 4, false)
	v("kdfv-time-9", "time one above the upper bound", "argon2id", hexSalt(16), 9, 65536, 4, false)
	v("kdfv-par-0", "zero parallelism", "argon2id", hexSalt(16), 3, 65536, 0, false)
	v("kdfv-par-17", "parallelism one above the maximum", "argon2id", hexSalt(16), 3, 65536, 17, false)

	nw := func(id, desc string, ct, cm, ot, om uint32, ok bool) {
		f.KDFNotWeaker = append(f.KDFNotWeaker, KDFNotWeakerCase{ID: id, Description: desc, CachedTime: ct, CachedMemoryKiB: cm, OfferedTime: ot, OfferedMemoryKiB: om, Acceptable: ok})
	}
	nw("nw-equal", "identical parameters", 3, 65536, 3, 65536, true)
	nw("nw-more-memory", "offered memory larger", 3, 65536, 3, 131072, true)
	nw("nw-more-time", "offered time larger", 3, 65536, 4, 65536, true)
	nw("nw-both-more", "both larger", 3, 65536, 5, 262144, true)
	nw("nw-less-memory", "offered memory smaller than cached", 3, 131072, 3, 65536, false)
	nw("nw-less-time", "offered time smaller than cached", 4, 65536, 3, 65536, false)
	nw("nw-more-memory-less-time", "more memory but less time is still weaker", 4, 65536, 3, 131072, false)
	nw("nw-less-memory-more-time", "less memory but more time is still weaker", 3, 131072, 8, 65536, false)
}

func genKeys(f *File) {
	add := func(id, desc string, p *vc.PrivateKey) {
		f.KeyPairs = append(f.KeyPairs, KeyPairCase{ID: id, Description: desc, PrivateKeyHex: hx(p[:]), PublicKeyHex: pubOf(p).String()})
	}
	var rfcA, rfcB vc.PrivateKey
	copy(rfcA[:], unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	copy(rfcB[:], unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	add("kp-rfc7748-alice", "RFC 7748 section 6.1 Alice (private key used as-is; clamping is X25519's job)", &rfcA)
	add("kp-rfc7748-bob", "RFC 7748 section 6.1 Bob", &rfcB)
	add("kp-random-1", "deterministic stand-in for a random scalar", privKey("kp1"))
	add("kp-random-2", "deterministic stand-in for a random scalar", privKey("kp2"))
	var zero vc.PrivateKey
	add("kp-zero-scalar", "all-zero scalar (clamping makes it valid; not a real key)", &zero)

	fp := func(id, desc, uid, uname string, pk vc.PublicKey) {
		f.Fingerprints = append(f.Fingerprints, FingerprintCase{ID: id, Description: desc, UserID: uid, Username: uname, PublicKeyHex: pk.String(), Fingerprint: must(vc.Fingerprint(uid, uname, pk))})
	}
	k1, k2 := pubOf(&rfcA), pubOf(privKey("kp1"))
	fp("fp-alice", "alice with RFC 7748 Alice key", detID("alice"), "alice", k1)
	fp("fp-same-key-other-username", "same user ID and key as fp-alice, different username: different fingerprint", detID("alice"), "alice2", k1)
	fp("fp-same-key-other-id", "same username and key as fp-alice, different user ID: different fingerprint", detID("mallory"), "alice", k1)
	fp("fp-same-identity-other-key", "same user ID and username as fp-alice, different key", detID("alice"), "alice", k2)
	fp("fp-bob", "another user", detID("bob"), "bob", k2)
	fp("fp-username-punctuation", "username with all allowed punctuation", detID("carol"), "c.a_r-0l", pubOf(privKey("kp2")))
	fp("fp-zero-key", "all-zero public key (not a real key; vector only)", detID("alice"), "alice", vc.PublicKey{})
}

// ---------------------------------------------------------------------------

func sealRaw(vk *vc.SymmetricKey, aad, nonce []byte, text string) []byte {
	return must(vc.SealWithNonce(vk, nonce, []byte(text), aad))
}

func genItems(f *File) {
	for _, n := range []int{0, 1, 255, 256, 257, 512} {
		in := bytes.Repeat([]byte{'a'}, n)
		desc := fmt.Sprintf("%d-byte input (0x61 repeated), n=256", n)
		if n == 0 {
			desc = "empty input, n=256: the result is a NON-ZERO multiple of n, i.e. 256 spaces (crypto.md section 5)"
		}
		if n == 256 || n == 512 {
			desc += ": already a multiple of n, unchanged"
		}
		f.Padding = append(f.Padding, PaddingCase{ID: fmt.Sprintf("pad-256-%d", n), Description: desc, InputHex: hx(in), N: 256, PaddedHex: hx(vc.Pad(in, 256))})
	}
	for _, n := range []int{0, 1, 63, 64, 65} {
		in := bytes.Repeat([]byte{'b'}, n)
		f.Padding = append(f.Padding, PaddingCase{ID: fmt.Sprintf("pad-64-%d", n), Description: fmt.Sprintf("%d-byte input (0x62 repeated), n=64", n), InputHex: hx(in), N: 64, PaddedHex: hx(vc.Pad(in, 64))})
	}

	vaultID := detID("vault1")
	vk := symKey("items/vk")
	const epoch = 3
	for i, name := range []string{"Family", "R\u00e9sum\u00e9 & <Notes> \U0001F512"} {
		meta := &vc.VaultMeta{V: 1, Name: name}
		if i == 1 {
			meta.Extra = []vc.ExtraMember{{RawKey: []byte(`"x_future"`), RawValue: []byte(`{"a" : [1, 2]}`)}}
		}
		js := must(meta.Encode())
		nonce := det(fmt.Sprintf("items/meta-nonce/%d", i), 24)
		padded := vc.Pad(js, 64)
		blob := must(vc.SealWithNonce(vk, nonce, padded, vc.VaultMetaAAD(vaultID, epoch)))
		f.VaultMeta = append(f.VaultMeta, VaultMetaCase{ID: fmt.Sprintf("meta-%d", i+1), Description: "vault metadata " + fmt.Sprintf("%q", name),
			VaultID: vaultID, KeyEpoch: epoch, KeyHex: hx(vk[:]), NonceHex: hx(nonce), PlaintextJSON: string(js),
			AADString: fmt.Sprintf("fpv/v1/vault-meta|%s|%d", vaultID, epoch), PaddedLength: len(padded), BlobHex: hx(blob)})
	}
	m1 := f.VaultMeta[0]
	mneg := func(id, desc, key, vid string, ep uint32) {
		f.VaultMetaNeg = append(f.VaultMetaNeg, VaultMetaNegative{ID: id, Description: desc, KeyHex: key, VaultID: vid, KeyEpoch: ep, BlobHex: m1.BlobHex})
	}
	mneg("metaneg-wrong-epoch", "right key, epoch 4 instead of 3", m1.KeyHex, vaultID, epoch+1)
	mneg("metaneg-older-epoch", "right key, epoch 2 instead of 3", m1.KeyHex, vaultID, epoch-1)
	mneg("metaneg-wrong-vault", "right key and epoch, other vault ID", m1.KeyHex, detID("vault2"), epoch)
	mneg("metaneg-wrong-key", "right vault and epoch, other key", hx(symKey("items/other")[:]), vaultID, epoch)

	items := []struct {
		id, desc string
		it       vc.Item
	}{
		{"item-login-full", "login item with every field, a hidden custom field, history, and an unknown top-level member x_future (with interior whitespace in its raw value)", vc.Item{
			V: 1, Type: "login", Name: "Example Bank", Username: "alice@example.com", Password: "correct horse battery staple",
			URLs: []string{"https://bank.example.com/login"}, Notes: "free text\nsecond line", TOTP: "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&issuer=Bank",
			Fields: []vc.CustomField{{Name: "PIN", Value: "1234", Hidden: true}, {Name: "Branch", Value: "Main"}},
			Tags:   []string{"finance"}, CreatedAt: 1767225600000, UpdatedAt: 1767225600000,
			PasswordHistory: []vc.PasswordHistoryEntry{{Password: "old one", ChangedAt: 1767000000000}},
			Extra:           []vc.ExtraMember{{RawKey: []byte(`"x_future"`), RawValue: []byte(`{"a":[1, 2,3],"b":null}`)}}}},
		{"item-note-minimal", "minimal secure note", vc.Item{V: 1, Type: "note", Name: "Wi-Fi", Notes: "guest / hunter2", CreatedAt: 1767225600000, UpdatedAt: 1767225600000}},
		{"item-unicode-escapes", "non-ASCII, HTML-significant characters, U+2028 and control characters: written literally except quote, backslash and C0 controls (canonical string rule)", vc.Item{
			V: 1, Type: "login", Name: "caf\u00e9 <b>&</b> \U0001F510", Username: "j\u00fcrgen", Password: "p\u00e4ss</script>\u2028\u007f\"\\\b\f\n\r\t\u0001\u001f", CreatedAt: 1767225600000, UpdatedAt: 1767225600001}},
		{"item-long-spans-blocks", "item whose JSON exceeds 256 bytes, padded to 512", vc.Item{
			V: 1, Type: "note", Name: "Long", Notes: strings.Repeat("0123456789", 30), CreatedAt: 1, UpdatedAt: 2}},
		{"item-max-int-empty-name", "empty name and the largest allowed integer, 2^53-1", vc.Item{V: 1, Type: "note", Name: "", CreatedAt: 9007199254740991, UpdatedAt: 0}},
	}
	for i, c := range items {
		itemID := detID(fmt.Sprintf("item%d", i+1))
		js := must(c.it.Encode())
		nonce := det(fmt.Sprintf("items/nonce/%d", i), 24)
		padded := vc.Pad(js, 256)
		blob := must(vc.SealWithNonce(vk, nonce, padded, vc.ItemAAD(vaultID, itemID, epoch)))
		f.Items = append(f.Items, ItemCase{ID: c.id, Description: c.desc, VaultID: vaultID, ItemID: itemID, KeyEpoch: epoch, KeyHex: hx(vk[:]), NonceHex: hx(nonce),
			PlaintextJSON: string(js), AADString: fmt.Sprintf("fpv/v1/item|%s|%s|%d", vaultID, itemID, epoch), PaddedLength: len(padded), BlobHex: hx(blob)})
	}
	first := f.Items[0]
	neg := func(id, desc, key, vid, iid string, ep uint32) {
		f.ItemsNeg = append(f.ItemsNeg, ItemNegative{ID: id, Description: desc, KeyHex: key, VaultID: vid, ItemID: iid, KeyEpoch: ep, BlobHex: first.BlobHex})
	}
	neg("itemneg-wrong-item-id", "blob of item-login-full opened as a different item of the same vault", first.KeyHex, first.VaultID, detID("other-item"), epoch)
	neg("itemneg-wrong-vault-id", "blob opened with the same item ID in a different vault", first.KeyHex, detID("other-vault"), first.ItemID, epoch)
	neg("itemneg-swapped-ids", "vault ID and item ID swapped", first.KeyHex, first.ItemID, first.VaultID, epoch)
	neg("itemneg-wrong-key", "blob opened with another vault key", hx(symKey("items/other")[:]), first.VaultID, first.ItemID, epoch)
	neg("itemneg-wrong-epoch", "right key, vault and item; epoch 4 instead of 3", first.KeyHex, first.VaultID, first.ItemID, epoch+1)
	neg("itemneg-epoch-1", "right key, vault and item; epoch 1 instead of 3", first.KeyHex, first.VaultID, first.ItemID, 1)
}

// ---------------------------------------------------------------------------

func genRosters(f *File) {
	vaultID := detID("vault1")
	vk := symKey("roster/vk")
	mk := func(label, role string) vc.RosterMember {
		return vc.RosterMember{ID: detID(label), PublicKey: pubOf(privKey("roster/" + label)), Role: role}
	}
	r := &vc.Roster{V: 1, Members: []vc.RosterMember{mk("alice", vc.RoleOwner)}}
	r1 := r
	r = must(r.WithMember(mk("bob", vc.RoleEditor)))
	r = must(r.WithMember(mk("carol", vc.RoleViewer)))
	r = must(r.WithMember(mk("dave", vc.RoleOwner)))
	r3 := r
	r2 := must(r3.Without(detID("bob")))
	r2 = must(r2.WithRole(detID("carol"), vc.RoleEditor))

	add := func(id, desc string, ep uint32, ro *vc.Roster, nonceLabel string) RosterCase {
		nonce := det("roster/nonce/"+nonceLabel, 24)
		js := must(ro.Encode())
		blob := must(vc.SealRosterWithNonce(vk, vaultID, ep, ro, nonce))
		return RosterCase{ID: id, Description: desc, VaultID: vaultID, KeyEpoch: ep, KeyHex: hx(vk[:]), NonceHex: hx(nonce),
			PlaintextJSON: string(js), AADString: fmt.Sprintf("fpv/v1/roster|%s|%d", vaultID, ep), BlobHex: hx(blob)}
	}
	f.Rosters = []RosterCase{
		add("roster-creator", "first roster of a vault: the creator as sole owner, epoch 1", 1, r1, "a"),
		add("roster-four-members", "four members, three roles, sorted by id (the order is the byte order of the lowercase hex id; it is NOT the order of the names)", 1, r3, "b"),
		add("roster-after-rekey", "epoch 2 roster after removing one member and promoting another role change", 2, r2, "c"),
	}
	base := f.Rosters[1]
	neg := func(id, desc, vid string, ep uint32, blob string) {
		f.RostersNeg = append(f.RostersNeg, RosterNegative{ID: id, Description: desc, KeyHex: base.KeyHex, VaultID: vid, KeyEpoch: ep, BlobHex: blob})
	}
	neg("rosterneg-wrong-vault", "valid blob, other vault ID", detID("vault2"), 1, base.BlobHex)
	neg("rosterneg-wrong-epoch", "valid blob, epoch 2 instead of 1", vaultID, 2, base.BlobHex)
	neg("rosterneg-wrong-key", "valid blob, other key", vaultID, 1, base.BlobHex)
	f.RostersNeg[2].KeyHex = hx(symKey("roster/other")[:])

	aad := vc.RosterAAD(vaultID, 1)
	n := func(i int) []byte { return det(fmt.Sprintf("roster/neg-nonce/%d", i), 24) }
	pk := func(label string) string {
		p := pubOf(privKey("roster/" + label))
		return base64.StdEncoding.EncodeToString(p[:])
	}
	ent := func(label, role string) string {
		return fmt.Sprintf(`{"id":"%s","pk":"%s","role":"%s"}`, detID(label), pk(label), role)
	}
	// Entries in sorted order for reference.
	labels := []string{"alice", "bob", "carol", "dave"}
	sort.Slice(labels, func(i, j int) bool { return detID(labels[i]) < detID(labels[j]) })
	a, b := labels[0], labels[1]
	doc := func(members ...string) string { return `{"v":1,"members":[` + strings.Join(members, ",") + `]}` }
	bad := func(i int, id, desc, text string) {
		neg(id, desc, vaultID, 1, hx(sealRaw(vk, aad, n(i), text)))
	}
	bad(1, "rosterneg-unsorted", "members not sorted by id", doc(ent(b, "owner"), ent(a, "viewer")))
	bad(2, "rosterneg-duplicate-id", "same id twice", doc(ent(a, "owner"), ent(a, "viewer")))
	bad(3, "rosterneg-no-owner", "no owner", doc(ent(a, "editor"), ent(b, "viewer")))
	bad(4, "rosterneg-empty-members", "empty member list (so no owner)", doc())
	bad(5, "rosterneg-bad-role", "role \"admin\"", doc(ent(a, "admin"), ent(b, "owner")))
	bad(6, "rosterneg-role-case", "role \"Owner\" (case sensitive)", doc(ent(a, "Owner")))
	bad(7, "rosterneg-short-key", "31-byte public key", doc(fmt.Sprintf(`{"id":"%s","pk":"%s","role":"owner"}`, detID(a), base64.StdEncoding.EncodeToString(det("x", 31)))))
	bad(8, "rosterneg-long-key", "33-byte public key", doc(fmt.Sprintf(`{"id":"%s","pk":"%s","role":"owner"}`, detID(a), base64.StdEncoding.EncodeToString(det("x", 33)))))
	bad(9, "rosterneg-unpadded-base64", "public key base64 without padding", doc(fmt.Sprintf(`{"id":"%s","pk":"%s","role":"owner"}`, detID(a), strings.TrimRight(pk(a), "="))))
	bad(10, "rosterneg-version-2", "v = 2", `{"v":2,"members":[`+ent(a, "owner")+`]}`)
	bad(11, "rosterneg-version-float", "v = 1.0", `{"v":1.0,"members":[`+ent(a, "owner")+`]}`)
	bad(12, "rosterneg-bad-id", "member id with upper-case hex", doc(strings.Replace(ent(a, "owner"), detID(a), strings.ToUpper(detID(a)), 1)))
	bad(13, "rosterneg-short-id", "member id of 31 characters", doc(strings.Replace(ent(a, "owner"), detID(a), detID(a)[:31], 1)))
	bad(14, "rosterneg-missing-role", "member without role", doc(fmt.Sprintf(`{"id":"%s","pk":"%s"}`, detID(a), pk(a))))
	bad(15, "rosterneg-duplicate-members-key", "\"members\" appears twice", `{"v":1,"members":[`+ent(a, "owner")+`],"members":[`+ent(a, "owner")+`]}`)
	bad(16, "rosterneg-null-member", "null as a member entry", `{"v":1,"members":[null,`+ent(a, "owner")+`]}`)
	bad(17, "rosterneg-trailing-garbage", "garbage after the object", doc(ent(a, "owner"))+"x")
	bad(18, "rosterneg-not-json", "not JSON", "owner")
	f.RostersNeg = append(f.RostersNeg, RosterNegative{ID: "rosterneg-invalid-utf8", Description: "invalid UTF-8 inside a string", KeyHex: base.KeyHex, VaultID: vaultID, KeyEpoch: 1,
		BlobHex: hx(must(vc.SealWithNonce(vk, n(19), append([]byte(`{"v":1,"members":[{"id":"`+detID(a)+`","pk":"`+pk(a)+`","role":"owner","x":"`), 0xff, '"', '}', ']', '}'), aad)))})
}

// ---------------------------------------------------------------------------

func genDecoding(f *File) {
	canon := func(kind string, pt []byte) string {
		switch kind {
		case KindItem:
			return string(must(must(vc.DecodeItem(pt)).Encode()))
		case KindMeta:
			return string(must(must(vc.DecodeVaultMeta(pt)).Encode()))
		default:
			return string(must(must(vc.DecodeRoster(pt)).Encode()))
		}
	}
	acc := func(id, desc, kind string, pt []byte) {
		f.DecodingAccept = append(f.DecodingAccept, DecodingAccept{ID: id, Description: desc, Kind: kind, PlaintextHex: hx(pt), CanonicalJSON: canon(kind, pt)})
	}
	rej := func(id, desc, kind string, pt []byte) {
		ok := func() (ok bool) {
			defer func() { recover() }()
			switch kind {
			case KindItem:
				_, err := vc.DecodeItem(pt)
				return err == nil
			case KindMeta:
				_, err := vc.DecodeVaultMeta(pt)
				return err == nil
			default:
				_, err := vc.DecodeRoster(pt)
				return err == nil
			}
		}()
		if ok {
			panic("decoding_reject case accepted by the Go decoder: " + id)
		}
		f.DecodingReject = append(f.DecodingReject, DecodingReject{ID: id, Description: desc, Kind: kind, PlaintextHex: hx(pt)})
	}
	I, M := KindItem, KindMeta
	s := func(x string) []byte { return []byte(x) }
	const base = `"v":1,"type":"login","name":"n"`

	acc("dec-item-minimal", "only the required members", I, s(`{"v":1,"type":"note","name":"n"}`))
	acc("dec-item-trailing-spaces", "trailing spaces (the padding) and JSON whitespace after the object", I, s("{\"v\":1,\"type\":\"note\",\"name\":\"n\"}   \t\r\n  "))
	acc("dec-item-leading-whitespace", "JSON whitespace before the object", I, s(" \n{\"v\":1,\"type\":\"note\",\"name\":\"n\"}"))
	acc("dec-item-whitespace-everywhere", "arbitrary JSON whitespace between tokens", I, s("{ \"v\" : 1 ,\n\"type\"\t:\"login\", \"name\" : \"n\" , \"urls\" : [ \"a\" , \"b\" ] }"))
	acc("dec-item-wrong-case-top", "\"Name\" is an unknown member, not name: name stays \"lower\" and Name is preserved verbatim after the known members", I, s(`{"v":1,"type":"note","Name":"UPPER","name":"lower"}`))
	acc("dec-item-wrong-case-only", "only \"NAME\" present would be missing name; here name is also present and TYPE/V are unknown extras", I, s(`{"V":1,"v":1,"TYPE":"x","type":"note","name":"n"}`))
	acc("dec-item-wrong-case-in-field", "\"VALUE\" inside a fields[] entry is an unknown member and is ignored and dropped; value is \"y\"", I, s(`{`+base+`,"fields":[{"name":"PIN","VALUE":"x","value":"y","hidden":true}]}`))
	acc("dec-item-wrong-case-only-in-field", "only \"VALUE\" present: value is empty", I, s(`{`+base+`,"fields":[{"name":"a","VALUE":"b"}]}`))
	acc("dec-item-unknown-in-history-entry", "unknown member inside a password_history[] entry is dropped", I, s(`{`+base+`,"password_history":[{"password":"old","changed_at":5,"why":"rotated"}]}`))
	acc("dec-item-hidden-false", "hidden false is accepted and omitted on re-encode", I, s(`{`+base+`,"fields":[{"name":"a","value":"b","hidden":false}]}`))
	acc("dec-item-escapes", "string escapes decode to characters; canonical output writes them literally (surrogate pair -> U+1F511, \\u00e9 -> e acute, \\/ -> /)", I, s(`{"v":1,"type":"note","name":"caf\u00e9 \ud83d\udd11 a\/b \u0041\n"}`))
	acc("dec-item-escaped-known-key", "\"n\\u0061me\" spells the known member name", I, s(`{"v":1,"type":"note","n\u0061me":"escaped key"}`))
	acc("dec-item-max-int", "created_at = 2^53-1", I, s(`{`+base+`,"created_at":9007199254740991,"updated_at":0}`))
	acc("dec-item-empty-name", "name may be empty", I, s(`{"v":1,"type":"note","name":""}`))
	acc("dec-item-empty-arrays", "empty arrays are accepted and omitted on re-encode", I, s(`{`+base+`,"urls":[],"tags":[],"fields":[],"password_history":[]}`))
	acc("dec-item-unknown-awkward", "unknown members with awkward raw values survive byte for byte, in original order, duplicates included", I,
		s(`{`+base+`,"x1":12345678901234567890,"x2":1.0,"x3":-0,"x4":{"a" : [1, 2e5, null], "b":{ }},"x5":null,"x1":2,"\u0078\u0036":"escaped key text kept as written"}`))
	acc("dec-item-all-members", "every known member", I, s(`{"v":1,"type":"login","name":"N","username":"u","password":"p","urls":["https://x"],"notes":"n","totp":"t","fields":[{"name":"a","value":"b"}],"tags":["t1","t2"],"created_at":1,"updated_at":2,"password_history":[{"password":"o","changed_at":3}]}`))
	acc("dec-item-nbsp-not-trimmed", "a non-ASCII space inside a value is data", I, s("{\"v\":1,\"type\":\"note\",\"name\":\"\u00a0x\u00a0\"}"))

	rej("dec-item-hidden-null", "\"hidden\": null (null is never accepted)", I, s(`{`+base+`,"fields":[{"name":"a","value":"b","hidden":null}]}`))
	rej("dec-item-hidden-string", "\"hidden\": \"true\" (wrong type)", I, s(`{`+base+`,"fields":[{"name":"a","value":"b","hidden":"true"}]}`))
	rej("dec-item-v-float", "\"v\": 1.0", I, s(`{"v":1.0,"type":"note","name":"n"}`))
	rej("dec-item-v-exponent", "\"v\": 1e0", I, s(`{"v":1e0,"type":"note","name":"n"}`))
	rej("dec-item-v-2", "\"v\": 2", I, s(`{"v":2,"type":"note","name":"n"}`))
	rej("dec-item-v-0", "\"v\": 0", I, s(`{"v":0,"type":"note","name":"n"}`))
	rej("dec-item-v-string", "\"v\": \"1\"", I, s(`{"v":"1","type":"note","name":"n"}`))
	rej("dec-item-v-missing", "no v", I, s(`{"type":"note","name":"n"}`))
	rej("dec-item-created-fraction", "\"created_at\": 1.5", I, s(`{`+base+`,"created_at":1.5}`))
	rej("dec-item-created-exponent", "\"created_at\": 1e3", I, s(`{`+base+`,"created_at":1e3}`))
	rej("dec-item-created-negative", "\"created_at\": -1", I, s(`{`+base+`,"created_at":-1}`))
	rej("dec-item-created-negative-zero", "\"created_at\": -0", I, s(`{`+base+`,"created_at":-0}`))
	rej("dec-item-created-leading-zero", "\"created_at\": 01 (not even JSON)", I, s(`{`+base+`,"created_at":01}`))
	rej("dec-item-created-too-big", "\"created_at\": 9007199254740992 (2^53)", I, s(`{`+base+`,"created_at":9007199254740992}`))
	rej("dec-item-created-huge", "\"updated_at\": 12345678901234567890", I, s(`{`+base+`,"updated_at":12345678901234567890}`))
	rej("dec-item-changed-at-fraction", "\"changed_at\": 2.0 inside password_history", I, s(`{`+base+`,"password_history":[{"password":"p","changed_at":2.0}]}`))
	rej("dec-item-created-string", "\"created_at\": \"5\"", I, s(`{`+base+`,"created_at":"5"}`))
	rej("dec-item-duplicate-top", "known member name twice at top level", I, s(`{"v":1,"type":"note","name":"a","name":"b"}`))
	rej("dec-item-duplicate-via-escape", "name and n\\u0061me are the same member", I, s(`{"v":1,"type":"note","name":"a","n\u0061me":"b"}`))
	rej("dec-item-duplicate-in-field", "\"value\" twice inside a fields[] entry", I, s(`{`+base+`,"fields":[{"name":"a","value":"x","value":"y"}]}`))
	rej("dec-item-duplicate-in-history", "\"password\" twice inside a password_history[] entry", I, s(`{`+base+`,"password_history":[{"password":"x","password":"y","changed_at":1}]}`))
	rej("dec-item-null-array-element", "null as an element of urls", I, s(`{`+base+`,"urls":["a",null]}`))
	rej("dec-item-null-field-entry", "null as an element of fields", I, s(`{`+base+`,"fields":[null]}`))
	rej("dec-item-null-member", "\"username\": null", I, s(`{`+base+`,"username":null}`))
	rej("dec-item-null-name", "\"name\": null", I, s(`{"v":1,"type":"note","name":null}`))
	rej("dec-item-urls-not-array", "\"urls\": \"x\"", I, s(`{`+base+`,"urls":"x"}`))
	rej("dec-item-urls-number-element", "number inside urls", I, s(`{`+base+`,"urls":[1]}`))
	rej("dec-item-fields-entry-not-object", "a fields[] entry that is a string", I, s(`{`+base+`,"fields":["x"]}`))
	rej("dec-item-field-name-number", "\"name\": 5 inside a fields[] entry", I, s(`{`+base+`,"fields":[{"name":5,"value":"b"}]}`))
	rej("dec-item-invalid-utf8", "byte 0xff inside a string", I, append(append([]byte(`{"v":1,"type":"note","name":"a`), 0xff), []byte(`"}`)...))
	rej("dec-item-overlong-utf8", "overlong encoding C0 80 inside a string", I, append(append([]byte(`{"v":1,"type":"note","name":"a`), 0xc0, 0x80), []byte(`"}`)...))
	rej("dec-item-encoded-surrogate", "UTF-8 encoded surrogate ED A0 80", I, append(append([]byte(`{"v":1,"type":"note","name":"a`), 0xed, 0xa0, 0x80), []byte(`"}`)...))
	rej("dec-item-lone-surrogate-escape", "\\ud800 without a low surrogate", I, s(`{"v":1,"type":"note","name":"\ud800"}`))
	rej("dec-item-lone-low-surrogate-escape", "\\udc00 on its own", I, s(`{"v":1,"type":"note","name":"\udc00"}`))
	rej("dec-item-lone-surrogate-in-unknown", "lone surrogate escape inside an unknown member's value", I, s(`{`+base+`,"x":"\ud800"}`))
	rej("dec-item-trailing-garbage", "garbage after the object", I, s(`{"v":1,"type":"note","name":"n"}x`))
	rej("dec-item-two-objects", "two objects", I, s(`{"v":1,"type":"note","name":"n"}{}`))
	rej("dec-item-trailing-nul", "NUL after the object is not whitespace", I, append([]byte(`{"v":1,"type":"note","name":"n"}`), 0))
	rej("dec-item-trailing-formfeed", "form feed after the object is not JSON whitespace", I, append([]byte(`{"v":1,"type":"note","name":"n"}`), 0x0c))
	rej("dec-item-trailing-comma", "trailing comma", I, s(`{"v":1,"type":"note","name":"n",}`))
	rej("dec-item-missing-name", "no name", I, s(`{"v":1,"type":"note"}`))
	rej("dec-item-only-wrong-case-name", "only \"Name\" present: name is missing", I, s(`{"v":1,"type":"note","Name":"n"}`))
	rej("dec-item-missing-type", "no type", I, s(`{"v":1,"name":"n"}`))
	rej("dec-item-type-card", "unknown type", I, s(`{"v":1,"type":"card","name":"n"}`))
	rej("dec-item-type-case", "type \"Login\" (case sensitive)", I, s(`{"v":1,"type":"Login","name":"n"}`))
	rej("dec-item-empty", "empty input", I, nil)
	rej("dec-item-whitespace-only", "only padding", I, s("      "))
	rej("dec-item-array", "top-level array", I, s(`[]`))
	rej("dec-item-string", "top-level string", I, s(`"x"`))
	rej("dec-item-null", "top-level null", I, s(`null`))
	rej("dec-item-comment", "a comment", I, s(`{"v":1,"type":"note","name":"n"}/*x*/`))
	rej("dec-item-single-quotes", "single-quoted strings", I, s(`{'v':1,'type':'note','name':'n'}`))
	rej("dec-item-bad-escape", "invalid escape \\x", I, s(`{"v":1,"type":"note","name":"a\x"}`))
	rej("dec-item-raw-control", "raw TAB inside a string", I, s("{\"v\":1,\"type\":\"note\",\"name\":\"a\tb\"}"))
	rej("dec-item-nan", "NaN as an unknown member's value", I, s(`{`+base+`,"x":NaN}`))
	rej("dec-item-unterminated", "truncated document", I, s(`{"v":1,"type":"note","name":"n"`))
	rej("dec-item-bad-nesting", "mismatched brackets inside an unknown member", I, s(`{`+base+`,"x":[1,2}`))

	acc("dec-meta-simple", "plain metadata, padded to 64", M, vc.Pad(s(`{"v":1,"name":"Family"}`), 64))
	acc("dec-meta-unknown-preserved", "unknown members are kept verbatim after name", M, s(`{"v":1,"future":{"k" : [1,  2]},"name":"F","Name":"wrong case","big":12345678901234567890}`))
	acc("dec-meta-empty-name", "empty name", M, s(`{"v":1,"name":""}`))
	rej("dec-meta-missing-name", "metadata without name", M, s(`{"v":1}`))
	rej("dec-meta-only-wrong-case-name", "only \"Name\"", M, s(`{"v":1,"Name":"x"}`))
	rej("dec-meta-null-name", "name null", M, s(`{"v":1,"name":null}`))
	rej("dec-meta-name-number", "name 5", M, s(`{"v":1,"name":5}`))
	rej("dec-meta-v-missing", "no v", M, s(`{"name":"x"}`))
	rej("dec-meta-v-float", "v 1.0", M, s(`{"v":1.0,"name":"x"}`))
	rej("dec-meta-v-2", "v 2", M, s(`{"v":2,"name":"x"}`))
	rej("dec-meta-duplicate-name", "name twice", M, s(`{"v":1,"name":"a","name":"b"}`))
	rej("dec-meta-duplicate-v", "v twice", M, s(`{"v":1,"v":1,"name":"a"}`))
	rej("dec-meta-invalid-utf8", "invalid UTF-8", M, append([]byte(`{"v":1,"name":"`), 0xfe, '"', '}'))
	rej("dec-meta-trailing-garbage", "trailing garbage", M, s(`{"v":1,"name":"a"} x`))
	rej("dec-meta-array", "top-level array", M, s(`[1]`))

	R := KindRoster
	pkb := func(l string) string {
		p := pubOf(privKey("roster/" + l))
		return base64.StdEncoding.EncodeToString(p[:])
	}
	e1 := fmt.Sprintf(`{"id":"%s","pk":"%s","role":"owner"}`, detID("alice"), pkb("alice"))
	acc("dec-roster-simple", "one owner", R, s(`{"v":1,"members":[`+e1+`]}`))
	acc("dec-roster-unknown-ignored", "unknown members at top level and inside an entry are ignored (and dropped on re-encode); whitespace and trailing spaces allowed", R,
		s(" {\"v\":1, \"extra\":{\"a\":1}, \"members\":[ {\"id\":\""+detID("alice")+"\",\"pk\":\""+pkb("alice")+"\",\"role\":\"owner\",\"note\":null} ] }   "))
	rej("dec-roster-duplicate-v", "v twice", R, s(`{"v":1,"v":1,"members":[`+e1+`]}`))
	rej("dec-roster-invalid-utf8", "invalid UTF-8 in an ignored member", R, append([]byte(`{"v":1,"x":"`), 0xff, '"', ',', '"', 'm', 'e', 'm', 'b', 'e', 'r', 's', '"', ':', '['))
	rej("dec-roster-wrong-case-members", "\"Members\" does not satisfy members", R, s(`{"v":1,"Members":[`+e1+`]}`))
	rej("dec-roster-wrong-case-role", "\"Role\" does not satisfy role", R, s(fmt.Sprintf(`{"v":1,"members":[{"id":"%s","pk":"%s","Role":"owner"}]}`, detID("alice"), pkb("alice"))))
	rej("dec-roster-trailing-garbage", "garbage after the object", R, s(`{"v":1,"members":[`+e1+`]}!`))

	// edit-and-preserve: change only the name, everything else byte for byte.
	ed := func(id, desc, kind string, pt []byte, newName string) {
		var out string
		if kind == KindItem {
			it := must(vc.DecodeItem(pt))
			it.Name = newName
			out = string(must(it.Encode()))
		} else {
			m := must(vc.DecodeVaultMeta(pt))
			m.Name = newName
			out = string(must(m.Encode()))
		}
		f.EditPreserve = append(f.EditPreserve, EditPreserve{ID: id, Description: desc, Kind: kind, PlaintextHex: hx(pt), NewName: newName, ExpectedJSON: out})
	}
	ed("edit-item-unknown-awkward", "rename an item that carries awkward unknown members, wrong-case twins and an escaped key: the unknown members' raw text (12345678901234567890, 1.0, -0, interior whitespace, duplicates, escaped key) is carried over unchanged and in original order; known members are re-emitted first in canonical order", KindItem,
		s(`{"x_big":12345678901234567890,"v":1,"type":"login","name":"Old","x_float":1.0,"password":"pw","x_negzero":-0,"x_nested":{"a" : [1,  2e5, null],"b":{ }},"Name":"wrongcase","x\u0041":true,"x_dup":1,"x_dup":2,"urls":["https://e.example"]}   `),
		"New \u00e9 \"q\" <&>\u2028")
	ed("edit-meta-unknown-awkward", "rename vault metadata with awkward unknown members", KindMeta,
		s(`{"name":"Old","v":1,"x_big":12345678901234567890,"x_float":1.0,"x_negzero":-0,"x_nested": {"a" :[ 1 ]},"NAME":"nope"}`+strings.Repeat(" ", 20)), "Renamed")
	ed("edit-item-no-unknown", "rename an item without unknown members (created_at/updated_at are re-emitted as 0 when absent)", KindItem, s(`{"v":1,"type":"note","name":"a"}`), "b")
}

// ---------------------------------------------------------------------------

func genReencrypt(f *File) {
	vaultID, itemID := detID("vault1"), detID("item1")
	oldVK, newVK, otherVK := symKey("reenc/old"), symKey("reenc/new"), symKey("reenc/other")
	const oe, ne = 4, 5
	nonce := det("reenc/nonce", 24)
	add := func(id, desc, kind string, in []byte, epochOld uint32) {
		var out []byte
		var opened bool
		var err error
		iid := itemID
		if kind == KindMeta {
			iid = ""
			out, opened, err = vc.ReencryptMetaWithNonce(oldVK, newVK, vaultID, epochOld, ne, in, nonce)
		} else {
			out, opened, err = vc.ReencryptItemWithNonce(oldVK, newVK, vaultID, itemID, epochOld, ne, in, nonce)
		}
		if err != nil {
			panic(err)
		}
		f.Reencrypt = append(f.Reencrypt, ReencryptCase{ID: id, Description: desc, Kind: kind, VaultID: vaultID, ItemID: iid,
			OldKeyHex: hx(oldVK[:]), NewKeyHex: hx(newVK[:]), OldEpoch: oe, NewEpoch: ne, NonceHex: hx(nonce),
			InputBlobHex: hx(in), Opened: opened, OutputBlobHex: hx(out)})
	}
	n := func(i int) []byte { return det(fmt.Sprintf("reenc/in-nonce/%d", i), 24) }
	itemPT := vc.Pad(must((&vc.Item{V: 1, Type: "login", Name: "Bank", Password: "pw", CreatedAt: 1, UpdatedAt: 2,
		Extra: []vc.ExtraMember{{RawKey: []byte(`"x"`), RawValue: []byte(`12345678901234567890`)}}}).Encode()), 256)
	add("reenc-item", "an item that opens: the output is seal(newKey, nonce, SAME plaintext bytes, aad with the new epoch)", KindItem,
		must(vc.SealWithNonce(oldVK, n(1), itemPT, vc.ItemAAD(vaultID, itemID, oe))), oe)
	add("reenc-item-garbage-plaintext", "authentic but unparseable plaintext is re-encrypted as-is: nothing is parsed", KindItem,
		must(vc.SealWithNonce(oldVK, n(2), vc.Pad([]byte("this is not json \xff"), 256), vc.ItemAAD(vaultID, itemID, oe))), oe)
	add("reenc-item-empty-plaintext", "empty plaintext", KindItem, must(vc.SealWithNonce(oldVK, n(3), nil, vc.ItemAAD(vaultID, itemID, oe))), oe)
	add("reenc-item-wrong-key", "does not open under the old key: carried over unchanged (output == input)", KindItem,
		must(vc.SealWithNonce(otherVK, n(4), itemPT, vc.ItemAAD(vaultID, itemID, oe))), oe)
	add("reenc-item-wrong-epoch", "sealed with epoch 3 AAD but old_epoch is 4: does not open, carried over unchanged", KindItem,
		must(vc.SealWithNonce(oldVK, n(5), itemPT, vc.ItemAAD(vaultID, itemID, 3))), oe)
	add("reenc-item-not-a-box", "input shorter than a box: carried over unchanged", KindItem, []byte{1, 2, 3}, oe)
	metaPT := vc.Pad(must((&vc.VaultMeta{V: 1, Name: "Family", Extra: []vc.ExtraMember{{RawKey: []byte(`"y"`), RawValue: []byte(`[1,  2]`)}}}).Encode()), 64)
	add("reenc-meta", "vault metadata that opens", KindMeta, must(vc.SealWithNonce(oldVK, n(6), metaPT, vc.VaultMetaAAD(vaultID, oe))), oe)
	add("reenc-meta-wrong-key", "metadata that does not open: carried over unchanged", KindMeta, must(vc.SealWithNonce(otherVK, n(7), metaPT, vc.VaultMetaAAD(vaultID, oe))), oe)
}

// ---------------------------------------------------------------------------

func genTrust(f *File) {
	userID := detID("alice")
	ak := symKey("trust/ak")
	tk := vc.LocalTrustKey(ak)
	// independent check of the derivation: RFC 5869 by hand with HMAC-SHA256
	if !bytes.Equal(hmacHKDF(ak[:], nil, "fpv/v1/local-trust-key", 32), tk[:]) {
		panic("local trust key mismatch")
	}
	for i, pt := range [][]byte{
		[]byte(`{"contacts":[],"vaults":{},"rev":0}`),
		nil,
		det("trust/big", 300),
	} {
		nonce := det(fmt.Sprintf("trust/nonce/%d", i), 24)
		blob := must(vc.SealLocalTrustWithNonce(ak, userID, pt, nonce))
		f.LocalTrust = append(f.LocalTrust, LocalTrustCase{ID: fmt.Sprintf("trust-%d", i+1), Description: []string{"small JSON document", "empty plaintext", "300 arbitrary bytes (the JSON inside is the client's business)"}[i],
			AccountKeyHex: hx(ak[:]), UserID: userID, TrustKeyHex: hx(tk[:]), NonceHex: hx(nonce), PlaintextHex: hx(pt),
			AADString: "fpv/v1/local-trust|" + userID, BlobHex: hx(blob)})
	}
	first := f.LocalTrust[0]
	neg := func(id, desc, ak2, uid string, blob []byte) {
		f.LocalTrustNeg = append(f.LocalTrustNeg, LocalTrustNegative{ID: id, Description: desc, AccountKeyHex: ak2, UserID: uid, BlobHex: hx(blob)})
	}
	b := unhex(first.BlobHex)
	neg("trustneg-wrong-user", "opened as another user ID", first.AccountKeyHex, detID("bob"), b)
	neg("trustneg-wrong-account-key", "opened with another account key", hx(symKey("trust/other")[:]), userID, b)
	neg("trustneg-flipped-bit", "one ciphertext bit flipped", first.AccountKeyHex, userID, flip(b, 30, 1))
	neg("trustneg-truncated", "truncated by one byte", first.AccountKeyHex, userID, b[:len(b)-1])
	neg("trustneg-empty", "empty blob (a missing store is simply empty)", first.AccountKeyHex, userID, nil)
	// sealed directly under the account key instead of the derived trust key
	neg("trustneg-sealed-under-account-key", "sealed with the account key itself, not the derived trust key", first.AccountKeyHex, userID,
		must(vc.SealWithNonce(ak, det("trust/nonce/x", 24), []byte("x"), vc.LocalTrustAAD(userID))))

	vk := symKey("commit/vk")
	for i, c := range []struct {
		vault string
		ep    uint32
		vk    *vc.SymmetricKey
		d     string
	}{
		{detID("vault1"), 1, vk, "epoch 1"},
		{detID("vault1"), 2, vk, "same key, epoch 2: different commitment"},
		{detID("vault2"), 1, vk, "same key and epoch, other vault: different commitment"},
		{detID("vault1"), 1, symKey("commit/vk2"), "other key"},
		{detID("vault1"), 4294967295, vk, "largest epoch"},
	} {
		f.Commitments = append(f.Commitments, CommitmentCase{ID: fmt.Sprintf("commit-%d", i+1), Description: c.d, VaultKeyHex: hx(c.vk[:]), VaultID: c.vault, KeyEpoch: c.ep,
			CommitmentHex: vc.VaultKeyCommitment(c.vk, c.vault, c.ep)})
	}
}

// ---------------------------------------------------------------------------

func genPolicy(f *File) {
	f.PasswordPolicyCommon = vc.CommonPasswords()
	add := func(id, desc, pw, user string) {
		expect := "ok"
		if err := vc.CheckMasterPassword(pw, user); err != nil {
			expect = err.(*vc.PolicyError).Code
		}
		f.PasswordPolicy = append(f.PasswordPolicy, PasswordPolicyCase{ID: id, Description: desc, Password: pw, Username: user, Expect: expect, Hint: vc.PasswordHint(pw) != ""})
	}
	add("pp-passphrase", "four unrelated words", "correct horse battery staple", "alice")
	add("pp-passphrase-unicode", "non-Latin passphrase", "\u043f\u0430\u0440\u043e\u043b\u044c \u043b\u043e\u0448\u0430\u0434\u044c \u0431\u0430\u0442\u0430\u0440\u0435\u044f \u0441\u043a\u0440\u0435\u043f\u043a\u0430", "alice")
	add("pp-mixed-12", "exactly 12 characters, accepted", "Tr0ub4dor&3x", "alice")
	add("pp-mixed-hint", "long single token: accepted but the passphrase hint shows", "q7#Lm2$Zp9!xV4", "alice")
	add("pp-short-11", "11 characters", "Tr0ub4dor&3", "alice")
	add("pp-empty", "empty", "", "alice")
	add("pp-nfkc-expands-to-11", "10 code points raw, 11 after NFKC (ligature): too short", "\ufb01reballs12", "alice")
	add("pp-nfkc-expands-to-12", "11 code points raw, 12 after NFKC: accepted", "\ufb01reballs123", "alice")
	add("pp-emoji-12-codepoints", "12 code points that are not UTF-16 units: counts code points, accepted", "\U0001F511\U0001F512\U0001F513\U0001F510\U0001F50F\U0001F514\U0001F515\U0001F516\U0001F517\U0001F518\U0001F519\U0001F51A", "alice")
	add("pp-emoji-11-codepoints", "11 emoji code points: too short", "\U0001F511\U0001F512\U0001F513\U0001F510\U0001F50F\U0001F514\U0001F515\U0001F516\U0001F517\U0001F518\U0001F519", "alice")
	add("pp-username-equal", "equals the username", "alicealicealice", "alicealicealice")
	add("pp-username-contained", "contains the username", "my-alice-is-secret-9!", "alice")
	add("pp-username-case", "contains the username in other case", "My-ALICE-is-Secret-9!", "alice")
	add("pp-username-short-contained-ok", "usernames shorter than 3 characters only count when equal", "xal horse battery staple", "al")
	add("pp-username-empty", "no username given", "alice is a secret 99", "")
	add("pp-repeated-char", "one character repeated", "aaaaaaaaaaaa", "bob")
	add("pp-repeated-pair", "two-character block repeated", "abababababab", "bob")
	add("pp-repeated-block4", "four-character block repeated", "xY7!xY7!xY7!", "bob")
	add("pp-repeated-block5-ok", "five-character block repeated is not caught", "xY7!qxY7!qxY7!q", "bob")
	add("pp-repeated-unicode", "repeated non-ASCII character", "\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9", "bob")
	add("pp-run-ascending", "ascending letters", "abcdefghijkl", "bob")
	add("pp-run-descending", "descending letters", "mlkjihgfedcb", "bob")
	add("pp-run-digits", "ascending digits (wrap-around is not a run, but this one is in the common list)", "123456789012", "bob")
	add("pp-run-digits-desc", "descending digits: the wrap from 0 to 9 breaks the run, so this is accepted", "987654321098", "bob")
	add("pp-run-digits-only-asc", "ascending digits 0-9 plus more: not a run past the 9", "0123456789ab", "bob")
	add("pp-common-password1234", "common password", "password1234", "bob")
	add("pp-common-case", "common password, different case", "PassWord1234", "bob")
	add("pp-common-keyboard", "keyboard walk", "qwertyuiopas", "bob")
	add("pp-common-fullwidth", "common password written with full-width characters (NFKC)", "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44\uff11\uff12\uff13\uff14", "bob")
	add("pp-common-suffix-year", "base word plus year", "iloveyou2024", "bob")
	add("pp-uncommon-near", "close to a common password but not on the list", "password1234x", "bob")
}

// ---------------------------------------------------------------------------

func accKDF(label string) AccountKDF {
	// The smallest parameters the validating DeriveMasterKeys accepts, with
	// p = 1 to keep the scenario cheap: t=3, m=64 MiB, p=1.
	return AccountKDF{SaltHex: hx(det("account/salt/"+label, 16)), Time: 3, MemoryKiB: 65536, Parallelism: 1}
}

func genAccounts(f *File) {
	userID := detID("alice")
	username := "alice"
	password := "Tr0ub4dor&3 \uff21\u0301" // contains a full-width letter and a combining mark (NFKC changes it)
	kdf := accKDF("1")
	mk := must(vc.DeriveMasterKeys(username, password, kdfOf(kdf)))
	ak, sk := symKey("account/ak"), privKey("account/sk")
	n1, n2 := det("account/nonce1", 24), det("account/nonce2", 24)
	_, up := must2(vc.NewAccountDeterministic(userID, mk, ak, sk, n1, n2))

	newPassword := "a brand new passphrase"
	newKDF := accKDF("2")
	newMK := must(vc.DeriveMasterKeys(username, newPassword, kdfOf(newKDF)))
	nn := det("account/nonce-new", 24)
	rewrapped := must(vc.RewrapAccountKeyWithNonce(userID, ak, newMK, nn))
	f.Accounts = []AccountCase{{
		ID: "account-1", Description: "registration artifacts from username + password + salt + fixed randomness, then a password change", UserID: userID, Username: username, Password: password, KDF: kdf,
		AccountKeyHex: hx(ak[:]), PrivateKeyHex: hx(sk[:]), NonceWrapHex: hx(n1), NonceEncPrivHex: hx(n2),
		EncKeyHex: hx(mk.EncKey[:]), LoginKeyHex: hx(mk.LoginKey[:]),
		PublicKeyHex: hx(up.PublicKey), WrappedAccountKeyHex: hx(up.WrappedAccountKey), EncPrivateKeyHex: hx(up.EncPrivateKey),
		PasswordChange: PasswordChange{NewPassword: newPassword, NewKDF: newKDF, NewNonceHex: hx(nn),
			NewEncKeyHex: hx(newMK.EncKey[:]), NewLoginKeyHex: hx(newMK.LoginKey[:]), NewWrappedAccountKeyHex: hx(rewrapped)},
	}}

	otherSK := privKey("account/other-sk")
	otherPub := pubOf(otherSK)
	_, upBadPriv := must2(vc.NewAccountDeterministic(userID, mk, ak, otherSK, n1, n2))
	otherUser := detID("mallory")
	_, upOtherUser := must2(vc.NewAccountDeterministic(otherUser, mk, ak, sk, n1, n2))
	add := func(id, desc, uid, uname, pw string, pub, w, e []byte, expect string) {
		f.AccountsNeg = append(f.AccountsNeg, AccountNegative{ID: id, Description: desc, UserID: uid, Username: uname, Password: pw, KDF: kdf,
			PublicKeyHex: hx(pub), WrappedAccountKeyHex: hx(w), EncPrivateKeyHex: hx(e), ExpectError: expect})
	}
	add("accneg-wrong-password", "wrong master password", userID, username, password+"x", up.PublicKey, up.WrappedAccountKey, up.EncPrivateKey, ErrKindDecrypt)
	add("accneg-wrong-username", "right password, but the username is mixed into the Argon2 salt: another name derives other keys", userID, "alice2", password, up.PublicKey, up.WrappedAccountKey, up.EncPrivateKey, ErrKindDecrypt)
	add("accneg-wrong-user-id", "blobs bound to another user ID", otherUser, username, password, up.PublicKey, up.WrappedAccountKey, up.EncPrivateKey, ErrKindDecrypt)
	add("accneg-wrapped-key-for-other-user", "wrappedAccountKey was sealed for another user ID", userID, username, password, up.PublicKey, upOtherUser.WrappedAccountKey, up.EncPrivateKey, ErrKindDecrypt)
	add("accneg-enc-private-key-for-other-user", "encPrivateKey was sealed for another user ID", userID, username, password, up.PublicKey, up.WrappedAccountKey, upOtherUser.EncPrivateKey, ErrKindDecrypt)
	add("accneg-swapped-blobs", "wrappedAccountKey and encPrivateKey swapped", userID, username, password, up.PublicKey, up.EncPrivateKey, up.WrappedAccountKey, ErrKindDecrypt)
	add("accneg-public-key-mismatch", "everything decrypts, but the account's published public key belongs to another key pair", userID, username, password, otherPub.Bytes(), up.WrappedAccountKey, up.EncPrivateKey, ErrKindPublicKeyMismatch)
	add("accneg-private-key-mismatch", "everything decrypts, but encPrivateKey holds a different private key than the published public key", userID, username, password, up.PublicKey, up.WrappedAccountKey, upBadPriv.EncPrivateKey, ErrKindPublicKeyMismatch)
	add("accneg-truncated-wrapped-key", "wrappedAccountKey truncated by one byte", userID, username, password, up.PublicKey, up.WrappedAccountKey[:len(up.WrappedAccountKey)-1], up.EncPrivateKey, ErrKindDecrypt)
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

// ---------------------------------------------------------------------------

func genBackups(f *File) {
	const exportedAt = 1767225600000
	vaultA, vaultB := detID("vault1"), detID("vault2")
	payload := &backup.Payload{V: 1, ExportedAt: exportedAt, ExportedBy: "alice", Vaults: []backup.Vault{
		{ID: vaultA, Name: "Personal", Personal: true, Items: []backup.Entry{
			{ID: detID("item1"), Item: &vc.Item{V: 1, Type: "login", Name: "Example Bank", Username: "alice@example.com", Password: "p\u00e4ss <&> word",
				URLs: []string{"https://bank.example.com/login"}, CreatedAt: 1767225600000, UpdatedAt: 1767225600000,
				PasswordHistory: []vc.PasswordHistoryEntry{{Password: "old one", ChangedAt: 1767000000000}},
				Extra:           []vc.ExtraMember{{RawKey: []byte(`"x_future"`), RawValue: []byte(`{"k":[true, null]}`)}}}},
		}},
		{ID: vaultB, Name: "Family", Personal: false, Items: []backup.Entry{
			{ID: detID("item2"), Item: &vc.Item{V: 1, Type: "note", Name: "Wi-Fi", Notes: "guest / hunter2", CreatedAt: 1767225600000, UpdatedAt: 1767225600000}},
			{ID: detID("item3"), Item: &vc.Item{V: 1, Type: "login", Name: "\U0001F510 caf\u00e9", Password: "x", CreatedAt: 5, UpdatedAt: 6}},
		}},
		{ID: detID("vault3"), Name: "Empty", Personal: false, Items: []backup.Entry{}},
	}}
	pass := "\ufb01re \uff46ly \uff11"
	altPass := "fire fly 1"
	kdf := accKDF("backup")
	apiKDF := kdfOf(kdf)
	nonce := det("backup/nonce", 24)
	createdAt := int64(exportedAt + 1000)
	file := must(backup.EncodeDeterministic(payload, pass, apiKDF, createdAt, nonce))
	pj := must(backup.MarshalPayload(payload))
	key := must(vc.DeriveBackupKey(pass, apiKDF))
	f.Backups = []BackupCase{{
		ID: "backup-1", Description: "complete backup file: three vaults (one empty), unicode and HTML-significant characters, an unknown item member; raw salt (no username) in the KDF",
		Passphrase: pass, AlternatePassphrase: []string{altPass}, KDF: kdf, CreatedAt: createdAt, NonceHex: hx(nonce),
		BackupKeyHex: hx(key[:]), PayloadJSON: string(pj), Payload: json.RawMessage(pj), File: string(file),
	}}

	parse := func() map[string]any {
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(file))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			panic(err)
		}
		return m
	}
	render := func(m map[string]any) string {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			panic(err)
		}
		return buf.String()
	}
	add := func(id, desc, passphrase, file, expect string) {
		f.BackupsNegative = append(f.BackupsNegative, BackupNegative{ID: id, Description: desc, Passphrase: passphrase, File: file, ExpectError: expect})
	}
	edit := func(mut func(m map[string]any)) string {
		m := parse()
		mut(m)
		return render(m)
	}
	add("backupneg-wrong-passphrase", "correct file, wrong passphrase", "wrong passphrase", string(file), BackupErrDecrypt)
	add("backupneg-empty-passphrase", "correct file, empty passphrase", "", string(file), BackupErrDecrypt)
	add("backupneg-tampered-blob", "last blob byte changed", pass, edit(func(m map[string]any) {
		b := unb64(m["blob"].(string))
		b[len(b)-1] ^= 1
		m["blob"] = b64(b)
	}), BackupErrDecrypt)
	add("backupneg-truncated-blob", "blob truncated to 40 bytes", pass, edit(func(m map[string]any) {
		m["blob"] = b64(unb64(m["blob"].(string))[:40])
	}), BackupErrDecrypt)
	add("backupneg-wrong-salt", "kdf.salt altered (key differs)", pass, edit(func(m map[string]any) {
		m["kdf"].(map[string]any)["salt"] = b64(det("backup/other-salt", 16))
	}), BackupErrDecrypt)
	add("backupneg-wrong-aad", "valid ciphertext sealed with a different AAD than \"fpv/v1/backup\"", pass, edit(func(m map[string]any) {
		m["blob"] = b64(must(vc.SealWithNonce(key, nonce, pj, []byte("fpv/v1/other"))))
	}), BackupErrDecrypt)
	add("backupneg-wrong-format", "format is not \"fpv-backup\"", pass, edit(func(m map[string]any) { m["format"] = "other-backup" }), BackupErrNotBackup)
	add("backupneg-missing-format", "format member missing", pass, edit(func(m map[string]any) { delete(m, "format") }), BackupErrNotBackup)
	add("backupneg-not-json", "not JSON at all", pass, "this is not a backup", BackupErrNotBackup)
	add("backupneg-json-array", "valid JSON of the wrong shape", pass, "[1,2,3]", BackupErrNotBackup)
	add("backupneg-empty-file", "empty file", pass, "", BackupErrNotBackup)
	add("backupneg-version-2", "file version 2 is not supported", pass, edit(func(m map[string]any) { m["version"] = json.Number("2") }), BackupErrVersion)
	add("backupneg-version-0", "file version 0 is not supported", pass, edit(func(m map[string]any) { m["version"] = json.Number("0") }), BackupErrVersion)

	weak := func(id, desc string, mut func(k map[string]any)) {
		add(id, desc+" (must be refused before any key derivation)", pass, edit(func(m map[string]any) { mut(m["kdf"].(map[string]any)) }), BackupErrWeakKDF)
	}
	weak("backupneg-weak-time", "time = 2", func(k map[string]any) { k["time"] = json.Number("2") })
	weak("backupneg-weak-memory", "memory_kib = 65535", func(k map[string]any) { k["memory_kib"] = json.Number("65535") })
	weak("backupneg-huge-memory", "memory_kib = 262145 (one above the upper bound)", func(k map[string]any) { k["memory_kib"] = json.Number("262145") })
	weak("backupneg-2gib-memory", "memory_kib = 2097152", func(k map[string]any) { k["memory_kib"] = json.Number("2097152") })
	weak("backupneg-huge-time", "time = 9", func(k map[string]any) { k["time"] = json.Number("9") })
	weak("backupneg-zero-parallelism", "parallelism = 0", func(k map[string]any) { k["parallelism"] = json.Number("0") })
	weak("backupneg-short-salt", "salt of 15 bytes", func(k map[string]any) { k["salt"] = b64(det("backup/short", 15)) })
	weak("backupneg-long-salt", "salt of 65 bytes", func(k map[string]any) { k["salt"] = b64(det("backup/long", 65)) })
	weak("backupneg-wrong-alg", "alg = argon2i", func(k map[string]any) { k["alg"] = "argon2i" })

	p2 := strings.Replace(string(pj), `"v":1`, `"v":2`, 1)
	f.BackupsNegative = append(f.BackupsNegative, BackupNegative{ID: "backupneg-payload-version-2", Description: "authentic blob whose payload has \"v\": 2",
		Passphrase: pass, ExpectError: BackupErrVersion, File: edit(func(m map[string]any) {
			m["blob"] = b64(must(vc.SealWithNonce(key, nonce, []byte(p2), backup.AAD)))
		})})
}
