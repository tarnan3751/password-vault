package vaultcrypto_test

import (
	"bytes"
	"testing"

	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// Benchmarks for the operations a client runs per item or per unlock.
// DeriveMasterKeys (default Argon2id parameters) is the reference: it
// dominates login by design.

func benchItem() *vc.Item {
	return &vc.Item{
		V: 1, Type: "login", Name: "Example Bank", Username: "alice@example.com", Password: "correct horse battery staple",
		URLs: []string{"https://bank.example.com/login"}, Notes: "free text\nsecond line", TOTP: "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP",
		Fields: []vc.CustomField{{Name: "PIN", Value: "1234", Hidden: true}, {Name: "Branch", Value: "Main"}},
		Tags:   []string{"finance"}, CreatedAt: 1767225600000, UpdatedAt: 1767225600000,
		PasswordHistory: []vc.PasswordHistoryEntry{{Password: "old one", ChangedAt: 1767000000000}},
		Extra:           []vc.ExtraMember{{RawKey: []byte(`"x_future"`), RawValue: []byte(`{"a":[1, 2,3],"b":null}`)}},
	}
}

func BenchmarkDeriveMasterKeysDefault(b *testing.B) {
	p := vc.DefaultKDFParams()
	for i := 0; i < b.N; i++ {
		if _, err := vc.DeriveMasterKeys("alice", "correct horse battery staple", p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptItem(b *testing.B) {
	vk, vid, iid, it := vc.NewVaultKey(), vc.NewID(), vc.NewID(), benchItem()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := vc.EncryptItem(vk, vid, iid, 1, it); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptItem(b *testing.B) {
	vk, vid, iid := vc.NewVaultKey(), vc.NewID(), vc.NewID()
	blob, err := vc.EncryptItem(vk, vid, iid, 1, benchItem())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := vc.DecryptItem(vk, vid, iid, 1, blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptRoster(b *testing.B) {
	vk, vid := vc.NewVaultKey(), vc.NewID()
	var r *vc.Roster
	for i := 0; i < 8; i++ {
		_, pub, _ := vc.GenerateKeyPair()
		m := vc.RosterMember{ID: vc.NewID(), PublicKey: pub, Role: vc.RoleViewer}
		if r == nil {
			m.Role = vc.RoleOwner
			r = &vc.Roster{V: 1, Members: []vc.RosterMember{m}}
		} else if nr, err := r.WithMember(m); err == nil {
			r = nr
		} else {
			b.Fatal(err)
		}
	}
	blob, err := vc.EncryptRoster(vk, vid, 1, r)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := vc.DecryptRoster(vk, vid, 1, blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReencryptItem(b *testing.B) {
	oldVK, newVK, vid, iid := vc.NewVaultKey(), vc.NewVaultKey(), vc.NewID(), vc.NewID()
	blob, err := vc.EncryptItem(oldVK, vid, iid, 1, benchItem())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok, err := vc.ReencryptItem(oldVK, newVK, vid, iid, 1, 2, blob); err != nil || !ok {
			b.Fatal(err, ok)
		}
	}
}

func BenchmarkLocalTrust(b *testing.B) {
	ak, uid := vc.NewVaultKey(), vc.NewID()
	pt := bytes.Repeat([]byte("x"), 4096)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		blob, err := vc.SealLocalTrust(ak, uid, pt)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := vc.OpenLocalTrust(ak, uid, blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckMasterPassword(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := vc.CheckMasterPassword("a Fairly Unusual passphrase 4 you", "alice"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFingerprint(b *testing.B) {
	_, pub, _ := vc.GenerateKeyPair()
	uid := vc.NewID()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := vc.Fingerprint(uid, "alice", pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWrapUnwrapVaultKey(b *testing.B) {
	sPriv, sPub, _ := vc.GenerateKeyPair()
	rPriv, rPub, _ := vc.GenerateKeyPair()
	ctx := vc.WrapContext{VaultID: vc.NewID(), KeyEpoch: 1, SenderID: vc.NewID(), RecipientID: vc.NewID()}
	vk := vc.NewVaultKey()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w, err := vc.WrapVaultKey(vk, ctx, &sPriv, &rPub)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := vc.UnwrapVaultKey(w, ctx, &rPriv, &sPub); err != nil {
			b.Fatal(err)
		}
	}
}
