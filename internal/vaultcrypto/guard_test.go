package vaultcrypto_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoTestVectorFunctionsOutsideCrypto fails if any non-test Go file outside
// the crypto packages references a function that exists only for test vectors
// (SealWithNonce, *Deterministic, *WithNonce, *UnsafeParams,
// EncodeDeterministic): those would break the security of production code.
func TestNoTestVectorFunctionsOutsideCrypto(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	re := regexp.MustCompile(`\b\w*(WithNonce|Deterministic|UnsafeParams)\b`)
	allowed := []string{"internal/vaultcrypto", "internal/backup", "cmd/gen-vectors"}
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			for _, a := range allowed {
				if rel == a {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if m := re.Find(data); m != nil {
			offenders = append(offenders, rel+": "+string(m))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("test-vector-only functions referenced outside the crypto packages:\n%s", strings.Join(offenders, "\n"))
	}
}
