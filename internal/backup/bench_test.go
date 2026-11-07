package backup_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tarnan3751/password-vault/internal/backup"
	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

func bigPayload() *backup.Payload {
	v := backup.Vault{ID: vc.NewID(), Name: "Family", Personal: true}
	for i := 0; i < 1000; i++ {
		v.Items = append(v.Items, backup.Entry{ID: vc.NewID(), Item: &vc.Item{
			V: 1, Type: "login", Name: fmt.Sprintf("Site %d", i), Username: "alice@example.com", Password: "correct horse battery staple",
			URLs: []string{"https://example.com/login"}, Notes: "some notes", CreatedAt: 1767225600000, UpdatedAt: 1767225600000,
		}})
	}
	return &backup.Payload{V: 1, ExportedAt: 1767225600000, ExportedBy: "alice", Vaults: []backup.Vault{v}}
}

// Encode and Decode each run Argon2id once at the default parameters (the
// fixed cost); MarshalPayload and DecodePayload isolate the part this package
// controls.
func BenchmarkMarshalPayload1000(b *testing.B) {
	p := bigPayload()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := backup.MarshalPayload(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodePayload1000(b *testing.B) {
	pj, err := backup.MarshalPayload(bigPayload())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var p backup.Payload
		if err := json.Unmarshal(pj, &p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportImport1000(b *testing.B) {
	p := bigPayload()
	kdf := vc.DefaultKDFParams()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data, err := backup.Encode(p, "correct horse battery staple", kdf)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := backup.Decode(data, "correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}
