// Command vaultd is the Family Vault server. Three copies of it, on three
// machines, replicate the household's encrypted vault with Raft.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `vaultd: Family Vault server

Usage:
  vaultd run --config <config.json>          start a node
  vaultd init-cluster --out <dir> --node <id>=<host>[,<host>...] ...
                                             generate a CA, certificates, configs and a
                                             bootstrap token for a new cluster
  vaultd issue-cert --ca-dir <dir> --node <id>=<host>[,<host>...] --out <dir>
                                             issue or renew one node certificate
  vaultd restore --config <config.json> --from <backup.json>
                                             seed an EMPTY data directory from a server backup
  vaultd version

Run "vaultd <command> -h" for what a command does and its flags.
Setting up a household is described step by step in docs/OPERATIONS.md.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "run":
		err = cmdRun(args)
	case "init-cluster":
		err = cmdInitCluster(args)
	case "issue-cert":
		err = cmdIssueCert(args)
	case "restore":
		err = cmdRestore(args)
	case "version", "--version", "-v":
		fmt.Println("vaultd", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "vaultd: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "vaultd:", err)
		os.Exit(1)
	}
}

// newFlagSet returns a flag set whose -h output says in words what the
// command does and lists its flags the way the documentation writes them.
func newFlagSet(name, synopsis, about string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "Usage: vaultd %s %s\n\n%s\n\nFlags:\n", name, synopsis, about)
		fs.VisitAll(func(f *flag.Flag) {
			arg, text := flag.UnquoteUsage(f)
			if arg != "" {
				arg = " " + arg
			}
			fmt.Fprintf(w, "  --%s%s\n        %s", f.Name, arg, text)
			if d := f.DefValue; d != "" && d != "0" && d != "false" && d != "[]" {
				fmt.Fprintf(w, " (default %s)", d)
			}
			fmt.Fprintln(w)
		})
	}
	return fs
}

// parseFlags parses args, answers -h on standard output, and turns a mistake
// into a one-line error that says where the help is.
func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		fs.SetOutput(os.Stdout)
		fs.Usage()
	case err != nil:
		err = fmt.Errorf("%s: %w (run \"vaultd %s -h\" for help)", fs.Name(), err, fs.Name())
	}
	return err
}
