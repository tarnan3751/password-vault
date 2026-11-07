// Command fvault is the command-line client of Family Vault.
//
// It talks to the household's vaultd servers over HTTPS, does every bit of
// cryptography locally (internal/vaultcrypto) and never loads code or
// configuration from a server. See `fvault help`.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tarnan3751/password-vault/internal/client"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitConflict = 3
	exitOffline  = 4
)

type command struct {
	name    string
	summary string
	run     func(a *app, args []string) error
}

// commands is populated by init() functions of the cmd_*.go files so each file
// owns its commands.
var commands []command

func register(c ...command) { commands = append(commands, c...) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runApp(&app{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr}, args)
}

func runApp(a *app, args []string) int {
	stdout, stderr := a.stdout, a.stderr
	// Global flags that may precede the command name.
	for len(args) > 0 {
		switch {
		case args[0] == "--home" || args[0] == "-home":
			if len(args) < 2 {
				fmt.Fprintln(stderr, "fvault: --home needs a directory")
				return exitUsage
			}
			a.home, args = args[1], args[2:]
			continue
		case strings.HasPrefix(args[0], "--home="):
			a.home, args = strings.TrimPrefix(args[0], "--home="), args[1:]
			continue
		}
		break
	}
	if len(args) == 0 {
		return a.bare()
	}
	name, rest := args[0], args[1:]
	switch name {
	case "-h", "--help", "help":
		if len(rest) > 0 && name == "help" {
			// `fvault help CMD [SUB]` is `fvault CMD [SUB] -h`.
			c := findCommand(rest[0])
			if c == nil {
				fmt.Fprintf(stderr, "fvault: unknown command %q.%s\n", rest[0], didYouMean(rest[0], commandNames()))
				return exitUsage
			}
			return a.finish(c.run(a, append(append([]string(nil), rest[1:]...), "-h")))
		}
		a.printOverview(stdout)
		return exitOK
	case "-v", "--version":
		name = "version"
	}
	c := findCommand(name)
	if c == nil {
		fmt.Fprintf(stderr, "fvault: unknown command %q.%s Run `fvault help` to see all commands.\n", name, didYouMean(name, commandNames()))
		return exitUsage
	}
	return a.finish(c.run(a, rest))
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// errNotOnline makes `status` exit 4 without another message.
var errNotOnline = &client.NetworkError{Msg: "the servers are not fully reachable"}

// errHelp signals that usage was printed on request (exit 0).
var errHelp = errors.New("help requested")

// usageError is a command-line mistake (exit 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{fmt.Sprintf(format, args...)} }

// finish converts an error into messages and an exit code.
func (a *app) finish(err error) int {
	if err == nil || errors.Is(err, errHelp) {
		return exitOK
	}
	var ue *usageError
	var ce *client.ConflictError
	switch {
	case errors.As(err, &ue):
		a.say(a.stderr, "fvault: "+ue.msg)
		fmt.Fprintln(a.stderr, "run `fvault help` or add -h to a command for usage")
		return exitUsage
	case errors.As(err, &ce):
		a.reportConflict(ce)
		return exitConflict
	case err == errNotOnline: // `status` has said everything already
		return exitOffline
	case client.IsUnavailable(err):
		a.say(a.stderr, "fvault: "+err.Error())
		if client.OutcomeUnknown(err) {
			a.say(a.stderr, "fvault: the change may or may not have been saved; run `fvault sync`, look at the item again, and only then retry")
		} else if errors.As(err, new(*client.ReadOnlyError)) {
			a.say(a.stderr, "  reading still works from the offline copy on this device; `fvault status` shows which servers are reachable")
		} else {
			a.say(a.stderr, "  `fvault status` shows which servers are reachable")
		}
		return exitOffline
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(a.stderr, "fvault: interrupted")
		return exitError
	}
	a.say(a.stderr, "fvault: "+err.Error())
	if h := hint(err); h != "" {
		fmt.Fprintln(a.stderr, "  "+h)
	}
	return exitError
}

// helpGroups orders the overview; the one-line summaries come from the
// command registry.
var helpGroups = []struct {
	title string
	names []string
}{
	{"Set up and sign in", []string{"init", "register", "login", "logout", "passwd", "status", "sync"}},
	{"Saved items", []string{"ls", "get", "add", "edit", "rm", "history", "generate"}},
	{"Several commands in a row", []string{"shell"}},
	{"Sharing with the household", []string{"vault", "contacts", "fingerprint"}},
	{"Administrators", []string{"invite", "admin"}},
	{"Backups and recovery", []string{"export", "import", "recover"}},
	{"Other", []string{"version"}},
}

func (a *app) printOverview(w io.Writer) {
	fmt.Fprint(w, `fvault - the Family Vault command line (self-hosted password manager)

Usage: fvault [--home DIR] COMMAND [ARGS]
More about one command, with examples: fvault help COMMAND

`)
	a.printFirstSteps(w)
	for _, g := range helpGroups {
		fmt.Fprintf(w, "\n%s\n", g.title)
		for _, n := range g.names {
			fmt.Fprintf(w, "  %-12s%s\n", n, findCommand(n).summary)
		}
	}
	fmt.Fprint(w, `  help [CMD]  this text, or the usage of one command (same as CMD -h)

Master password: it is read from the terminal without echo and cannot be
recovered if you forget it. Scripts can use --password-stdin or the
FVAULT_PASSWORD environment variable (prefer stdin: environment variables can
leak to other processes of the same user). It is never accepted as an argument.

Fingerprints: a fingerprint is a short code that identifies a person's key.
You trust someone's key only after comparing their fingerprint with them in
person or on a phone call, not through this app (`+"`fvault contacts verify`"+`). A
vault shared with you stays closed, "waiting for you to confirm the sender",
until you do that and run `+"`fvault vault accept`"+`.

Exit codes: 0 ok, 1 error, 2 usage, 3 conflict, 4 servers unreachable or no
majority of them (2 of 3) available. Settings are kept in $FVAULT_HOME, or in
the user config dir + /fvault (--home DIR).
`)
}

func (a *app) printFirstSteps(w io.Writer) {
	fmt.Fprint(w, `First time here?
  1. fvault init --server https://vault.example:8443
       (the address of any of your servers; add --insecure for plain http://
       on a development cluster)
  2. fvault register --username NAME --bootstrap-token CODE
       The first person uses the bootstrap token: the one-time setup code
       created when the servers were set up (printed by `+"`vaultd init-cluster`"+`,
       stored in the server's `+"`bootstrap-token`"+` file). Everyone else uses
       --invite CODE, from an administrator (`+"`fvault invite create`"+`).
  3. fvault add --name "Example Bank" --username me@example.com --generate
  4. fvault ls       then       fvault get "Example Bank" --show
Looking up several things? `+"`fvault shell`"+` asks for your master password once.
`)
}

// bare handles `fvault` without arguments: on a terminal it guides the next
// step (and offers the shell once an account exists); otherwise it is a usage
// error that prints the overview.
func (a *app) bare() int {
	tty := isTerminal(a.stdout) && ttyFile() != nil
	if !tty {
		a.printOverview(a.stderr)
		return exitUsage
	}
	st, err := a.store()
	var cfg *client.Config
	if err == nil {
		cfg, err = st.LoadConfig()
	}
	switch {
	case err != nil || len(cfg.Servers) == 0:
		fmt.Fprint(a.stdout, "Welcome to fvault, the command line of your household's password vault.\n\n")
		a.printFirstSteps(a.stdout)
		fmt.Fprintln(a.stdout, "\nAll commands: fvault help")
	case cfg.Username == "":
		fmt.Fprintf(a.stdout, "Servers are set up (%s) but there is no account on this device yet.\n  new here:       fvault register --username NAME --invite CODE\n  have an account: fvault login --username NAME\nAll commands: fvault help\n", cfg.Servers[0])
	default:
		fmt.Fprintf(a.stdout, "fvault: signed in as %s on this device. All commands: fvault help\n", cfg.Username)
		ok, err := a.ask("Open the interactive shell (asks for your master password once, then runs several commands)?", true)
		if err == nil && ok {
			return a.finish(cmdShell(a, nil))
		}
	}
	return exitOK
}
