// Command gen-vectors writes testvectors/crypto-v1.json deterministically
// (docs/spec/crypto.md §8). Usage: gen-vectors [-o path] (default
// testvectors/crypto-v1.json relative to the working directory).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tarnan3751/password-vault/internal/vaultcrypto/vectorgen"
)

func main() {
	out := flag.String("o", "testvectors/crypto-v1.json", "output path")
	flag.Parse()
	data, err := vectorgen.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-vectors:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen-vectors:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(data))
}
