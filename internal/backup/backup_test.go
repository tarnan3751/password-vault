package backup_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/backup"
	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto/vectorgen"
)

func kdf(t testing.TB, k vectorgen.AccountKDF) api.KDFParams {
	s, err := hex.DecodeString(k.SaltHex)
	if err != nil {
		t.Fatal(err)
	}
	return api.KDFParams{Alg: "argon2id", Salt: s, Time: k.Time, MemoryKiB: k.MemoryKiB, Parallelism: k.Parallelism}
}

func TestVectors(t *testing.T) {
	f, err := vectorgen.Load("../../testvectors/crypto-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Backups) == 0 || len(f.BackupsNegative) == 0 {
		t.Fatal("no backup vectors")
	}
	for _, c := range f.Backups {
		t.Run(c.ID, func(t *testing.T) {
			p, err := backup.Decode([]byte(c.File), c.Passphrase)
			if err != nil {
				t.Fatal(err)
			}
			got, err := backup.MarshalPayload(p)
			if err != nil || string(got) != c.PayloadJSON {
				t.Fatalf("payload differs (%v):\n%s\n%s", err, got, c.PayloadJSON)
			}
			var a, b any
			if json.Unmarshal(got, &a) != nil || json.Unmarshal(c.Payload, &b) != nil {
				t.Fatal("bad json")
			}
			ga, _ := json.Marshal(a)
			gb, _ := json.Marshal(b)
			if !bytes.Equal(ga, gb) {
				t.Fatal("payload object differs from payload_json")
			}
			for _, alt := range c.AlternatePassphrase {
				if _, err := backup.Decode([]byte(c.File), alt); err != nil {
					t.Fatalf("alternate passphrase %q: %v", alt, err)
				}
			}
			nonce, _ := hex.DecodeString(c.NonceHex)
			again, err := backup.EncodeDeterministic(p, c.Passphrase, kdf(t, c.KDF), c.CreatedAt, nonce)
			if err != nil || string(again) != c.File {
				t.Fatalf("re-encode differs: %v", err)
			}
		})
	}
	for _, c := range f.BackupsNegative {
		t.Run(c.ID, func(t *testing.T) {
			_, err := backup.Decode([]byte(c.File), c.Passphrase)
			want := map[string]error{
				vectorgen.BackupErrNotBackup: backup.ErrNotBackup, vectorgen.BackupErrVersion: backup.ErrUnsupportedVersion,
				vectorgen.BackupErrWeakKDF: backup.ErrWeakKDF, vectorgen.BackupErrDecrypt: backup.ErrDecrypt,
			}[c.ExpectError]
			if want == nil || !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
		})
	}
}

func samplePayload() *backup.Payload {
	return &backup.Payload{V: 1, ExportedAt: 5, ExportedBy: "bob", Vaults: []backup.Vault{{ID: vc.NewID(), Name: "V", Items: []backup.Entry{
		{ID: vc.NewID(), Item: &vc.Item{V: 1, Type: "note", Name: "n", Extra: []vc.ExtraMember{{RawKey: []byte(`"future"`), RawValue: []byte(`[1, {"a":null}]`)}}}}}}}}
}

func TestRoundTrip(t *testing.T) {
	p := samplePayload()
	k := api.KDFParams{Alg: "argon2id", Salt: bytes.Repeat([]byte{1}, 16), Time: 3, MemoryKiB: 65536, Parallelism: 1}
	file, err := backup.Encode(p, "pass phrase", k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := backup.Decode(file, "pass phrase")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := backup.MarshalPayload(p)
	b, _ := backup.MarshalPayload(got)
	if !bytes.Equal(a, b) || string(got.Vaults[0].Items[0].Item.Extra[0].RawValue) != `[1, {"a":null}]` {
		t.Fatalf("round trip differs:\n%s\n%s", a, b)
	}
	// two encodes differ (fresh nonce) but both decode
	file2, _ := backup.Encode(p, "pass phrase", k)
	if bytes.Equal(file, file2) {
		t.Fatal("nonce reused")
	}
	if _, err := backup.Decode(file, "other"); !errors.Is(err, backup.ErrDecrypt) {
		t.Fatal(err)
	}
}

func TestEncodeRefusesWeakParamsAndBadPayload(t *testing.T) {
	weak := api.KDFParams{Alg: "argon2id", Salt: make([]byte, 16), Time: 1, MemoryKiB: 64, Parallelism: 1}
	if _, err := backup.Encode(samplePayload(), "x", weak); !errors.Is(err, vc.ErrKDFParams) {
		t.Fatalf("got %v", err)
	}
	ok := vc.DefaultKDFParams()
	ok.MemoryKiB = 65536
	ok.Time = 3
	p := samplePayload()
	p.V = 2
	if _, err := backup.Encode(p, "x", ok); err == nil {
		t.Fatal("payload v2 accepted")
	}
}

func FuzzDecode(f *testing.F) {
	v, err := vectorgen.Load("../../testvectors/crypto-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(v.Backups[0].File), v.Backups[0].Passphrase)
	for _, n := range v.BackupsNegative {
		f.Add([]byte(n.File), n.Passphrase)
	}
	f.Add([]byte(`{"format":"fpv-backup","version":1}`), "")
	f.Fuzz(func(t *testing.T, data []byte, pass string) {
		// Avoid spending seconds in Argon2 on mutated-but-valid parameters.
		var h struct {
			KDF api.KDFParams `json:"kdf"`
		}
		if json.Unmarshal(data, &h) == nil && (h.KDF.MemoryKiB >= 65536 || h.KDF.Time > 3 || h.KDF.Parallelism > 4) {
			return
		}
		_, _ = backup.Decode(data, pass)
	})
}
