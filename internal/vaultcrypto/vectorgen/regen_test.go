package vectorgen_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/tarnan3751/password-vault/internal/vaultcrypto/vectorgen"
)

// TestCheckedInFileMatchesGenerator guards against drift: the generator is
// re-run in memory and must reproduce testvectors/crypto-v1.json byte for byte
// (and be deterministic). Fix a failure with `go run ./cmd/gen-vectors`.
func TestCheckedInFileMatchesGenerator(t *testing.T) {
	a, err := vectorgen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := vectorgen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("generator is not deterministic")
	}
	disk, err := os.ReadFile("../../../testvectors/crypto-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, disk) {
		t.Fatal("testvectors/crypto-v1.json is out of date; run: go run ./cmd/gen-vectors")
	}
}

// TestLoadable checks that the checked-in file parses into the schema types.
func TestLoadable(t *testing.T) {
	f, err := vectorgen.Load("../../../testvectors/crypto-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if f.Suite != "fpv/v1" {
		t.Fatal("bad suite")
	}
}
