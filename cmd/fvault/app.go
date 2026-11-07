package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/tarnan3751/password-vault/internal/client"
)

// app carries the process-wide state of one invocation.
type app struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	home   string // --home before the command name

	br      *bufio.Reader // shared reader for --password-stdin
	pwStdin bool
	// masterPassword remembers the password typed for this invocation so that
	// an export may default to it. Never written anywhere.
	masterPassword string

	// sess is the unlocked session of `fvault shell`, shared by the commands
	// typed there instead of unlocking again. Memory only.
	sess *client.Session
	// Test seams: askSecret replaces the terminal prompt, shellTTY makes the
	// shell behave as on a terminal, cols is the table width (0: ask the terminal).
	askSecret func(prompt string) (string, error)
	shellTTY  bool
	// Shell only: what was last reported, so it is not repeated before every command.
	lastMode  client.Mode
	lastOther int
	cols      int
}

// ---------------------------------------------------------------------------
// Flag plumbing
// ---------------------------------------------------------------------------

// cmdFlags wraps a FlagSet with the options every command shares and with
// usage text that is generated, so `-h` is always accurate.
type cmdFlags struct {
	*flag.FlagSet
	a        *app
	name     string
	synopsis string
	desc     string
	home     string
	stdin    bool
	asJSON   bool
	yes      bool
}

func (a *app) flags(name, synopsis, desc string) *cmdFlags {
	f := &cmdFlags{FlagSet: flag.NewFlagSet(name, flag.ContinueOnError), a: a, name: name, synopsis: synopsis, desc: desc}
	f.SetOutput(io.Discard)
	f.StringVar(&f.home, "home", "", "state directory (default $FVAULT_HOME or the user config dir + /fvault)")
	return f
}

// auth registers --password-stdin (commands that unlock the account).
func (f *cmdFlags) auth() *cmdFlags {
	f.BoolVar(&f.stdin, "password-stdin", false, "read the master password from standard input (any further secrets, in the order asked, on the following lines)")
	return f
}

func (f *cmdFlags) json() *cmdFlags {
	f.BoolVar(&f.asJSON, "json", false, "machine-readable JSON output")
	return f
}

func (f *cmdFlags) confirm() *cmdFlags {
	f.BoolVar(&f.yes, "yes", false, "do not ask for confirmation (for scripts)")
	return f
}

func (f *cmdFlags) usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: fvault %s\n\n%s\n", f.synopsis, strings.TrimSpace(f.desc))
	var n int
	f.VisitAll(func(*flag.Flag) { n++ })
	if n == 0 {
		return
	}
	fmt.Fprintln(w, "\nFlags:")
	// The flags of this command come first, in the order the synopsis names
	// them; the flags every command has come last.
	var all []*flag.Flag
	f.VisitAll(func(fl *flag.Flag) { all = append(all, fl) })
	rank := func(fl *flag.Flag) int {
		if i := strings.Index(f.synopsis, "--"+fl.Name); i >= 0 {
			return i
		}
		for i, n := range []string{"password-stdin", "json", "yes", "home"} {
			if fl.Name == n {
				return 1000 + i
			}
		}
		return 500
	}
	sort.SliceStable(all, func(i, j int) bool { return rank(all[i]) < rank(all[j]) })
	for _, fl := range all {
		name, usage := flag.UnquoteUsage(fl)
		head := "  --" + fl.Name
		if name != "" {
			head += " " + name
		}
		fmt.Fprintf(w, "%s\n        %s", head, usage)
		if fl.DefValue != "" && fl.DefValue != "false" && fl.DefValue != "0" {
			fmt.Fprintf(w, " (default %s)", fl.DefValue)
		}
		fmt.Fprintln(w)
	}
}

// parse accepts flags and positional arguments in any order (`fvault get X --show`),
// and "--" to end flag parsing. It checks the number of positionals.
func (f *cmdFlags) parse(args []string, min, max int) ([]string, error) {
	var pos []string
	for {
		if err := f.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				f.usage(f.a.stdout)
				return nil, errHelp
			}
			msg := fmt.Sprintf("%s: %v", f.name, err)
			if bad, ok := strings.CutPrefix(err.Error(), "flag provided but not defined: -"); ok {
				msg += "." + didYouMean("--"+strings.TrimLeft(bad, "-"), prefixed(flagNames(f), "--"))
			}
			return nil, usagef("%s", msg)
		}
		rest := f.Args()
		if len(rest) == 0 {
			break
		}
		if idx := len(args) - len(rest) - 1; idx >= 0 && args[idx] == "--" {
			pos = append(pos, rest...)
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	if len(pos) < min || (max >= 0 && len(pos) > max) {
		if max == 0 {
			return nil, usagef("%s takes no arguments (got %q)\nusage: fvault %s", f.name, pos[0], f.synopsis)
		}
		return nil, usagef("%s: wrong number of arguments\nusage: fvault %s", f.name, f.synopsis)
	}
	if f.home != "" {
		f.a.home = f.home
	}
	f.a.pwStdin = f.stdin
	return pos, nil
}

// open is parse followed by unlocking the account: the start of every command
// that reads or changes items. The caller releases the session.
func (f *cmdFlags) open(args []string, min, max int) ([]string, *client.Session, error) {
	pos, err := f.parse(args, min, max)
	if err != nil {
		return nil, nil, err
	}
	s, err := f.a.openSession()
	return pos, s, err
}

// repeated is a repeatable string flag.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func (f *cmdFlags) wasSet(name string) bool {
	set := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == name {
			set = true
		}
	})
	return set
}

// groupNotes are the short recipes shown under a group's subcommand list.
var groupNotes = map[string]string{
	"vault": `
Sharing a vault with someone (alice shares "Family" with bob):
  alice:  fvault vault create Family
  both:   fvault fingerprint           compare codes in person or by phone
  alice:  fvault vault share Family bob --role editor
  bob:    fvault vault ls              the vault shows as PENDING
  bob:    fvault vault accept ID       confirms alice, then opens the vault

`,
	"invite": "\nA new person registers with the code: fvault register --username NAME --invite CODE\n\n",
}

// group dispatches `fvault GROUP SUB ...`.
func (a *app) group(name string, subs []command, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		w := a.stdout
		if len(args) == 0 {
			w = a.stderr
		}
		fmt.Fprintf(w, "Usage: fvault %s SUBCOMMAND [ARGS]\n\nSubcommands:\n", name)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, s := range subs {
			fmt.Fprintf(tw, "  %s\t%s\n", s.name, s.summary)
		}
		tw.Flush()
		fmt.Fprintf(w, "%sRun `fvault %s SUBCOMMAND -h` for its flags and examples.\n", cmp.Or(groupNotes[name], "\n"), name)
		if len(args) == 0 {
			return usagef("%s needs a subcommand", name)
		}
		return errHelp
	}
	for _, s := range subs {
		if s.name == args[0] {
			return s.run(a, args[1:])
		}
	}
	var names []string
	for _, s := range subs {
		names = append(names, s.name)
	}
	return usagef("unknown %s subcommand %q.%s Run `fvault %s -h` to see them", name, args[0], didYouMean(args[0], names), name)
}

// ---------------------------------------------------------------------------
// Local state and sessions
// ---------------------------------------------------------------------------

func (a *app) store() (*client.Store, error) {
	return client.OpenStore(a.home)
}

// loadAll opens the state dir and the config.
func (a *app) loadAll() (*client.Store, *client.Config, error) {
	st, err := a.store()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := st.LoadConfig()
	if err != nil {
		return nil, nil, err
	}
	if len(cfg.Servers) == 0 {
		return nil, nil, client.ErrNotConfigured
	}
	return st, cfg, nil
}

func (a *app) buildAPI(st *client.Store, cfg *client.Config) (*client.API, error) {
	hc, err := client.NewHTTPClient(client.HTTPOptions{CAFile: cfg.CAFile, WithSystemRoots: cfg.CAWithSystemRoots})
	if err != nil {
		return nil, err
	}
	return client.New(client.Options{
		Nodes: cfg.Servers, HTTPClient: hc, AllowInsecure: cfg.AllowInsecure,
		OnNodesChanged: func(n []string) {
			_ = st.UpdateConfig(func(c *client.Config) { c.Servers = n })
		},
	})
}

func (a *app) deps(st *client.Store, cfg *client.Config) (client.Deps, error) {
	ap, err := a.buildAPI(st, cfg)
	if err != nil {
		return client.Deps{}, err
	}
	return client.Deps{API: ap, Store: st, CacheToken: !cfg.NoTokenCache}, nil
}

const errNoAccount = "no account is set up on this device yet. If you already have one, run `fvault login --username NAME`; to create one, run `fvault register --username NAME --invite CODE` (the first user uses --bootstrap-token instead)"

// openSession unlocks the account (cache first, then server) and prints a
// one-line notice on stderr when the data may not be fresh. Inside
// `fvault shell` it hands out the session that is already unlocked.
func (a *app) openSession() (*client.Session, error) {
	if s := a.sess; s != nil {
		if _, err := s.Refresh(a.ctx); err != nil {
			return nil, err
		}
		a.afterOpen(s)
		return s, nil
	}
	st, cfg, err := a.loadAll()
	if err != nil {
		return nil, err
	}
	if cfg.Username == "" {
		return nil, errors.New(errNoAccount)
	}
	d, err := a.deps(st, cfg)
	if err != nil {
		return nil, err
	}
	pw, err := a.secret("Master password for "+cfg.Username+": ", "FVAULT_PASSWORD", false, nil)
	if err != nil {
		return nil, err
	}
	a.masterPassword = pw
	done := a.working("Unlocking")
	s, err := client.Open(a.ctx, d, cfg.Username, pw)
	done()
	if err != nil {
		return nil, err
	}
	a.afterOpen(s)
	return s, nil
}

// release locks a session when a command is done with it, except the shared
// session of the interactive shell.
func (a *app) release(s *client.Session) {
	if s != a.sess {
		s.Lock()
	}
}

// afterOpen prints what the user must see on every command: key mismatches in
// full (they are attacks until proven otherwise), a reset trust store, the
// freshness notice, and a one-line pointer to everything else.
func (a *app) afterOpen(s *client.Session) {
	for _, w := range s.KeyMismatches() {
		a.say(a.stderr, "fvault: "+w.Error())
	}
	if s.TrustReset() {
		a.say(a.stderr, "fvault: notice: the local trust store was missing or unreadable and has been reset: every contact is unverified again")
	}
	// In the shell the state is told once, then only when it changes.
	changed := a.sess == nil || s.Mode() != a.lastMode
	if n := s.Notice(); n != "" && changed {
		a.say(a.stderr, "fvault: notice: "+n)
	} else if n == "" && changed && a.sess != nil {
		a.say(a.stderr, "The servers are reachable again: saving works.")
	}
	a.lastMode = s.Mode()
	other := 0
	for _, v := range s.Vaults() {
		if v.Locked != client.NotLocked || len(v.Discrepancies) > 0 {
			other++
		}
	}
	if other > 0 && (a.sess == nil || other != a.lastOther) {
		a.say(a.stderr, fmt.Sprintf("fvault: warning: %d vault(s) need attention (waiting for you to confirm the sender, locked, or inconsistent); run `fvault vault ls` for details\n", other))
	}
	a.lastOther = other
}

// ---------------------------------------------------------------------------
// Secrets and confirmation
// ---------------------------------------------------------------------------

// ttyFile returns a terminal for interactive input: stdin if it is one, else
// the controlling terminal.
func ttyFile() *os.File {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin
	}
	if runtime.GOOS != "windows" {
		if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			if term.IsTerminal(int(f.Fd())) {
				return f
			}
			f.Close()
		}
	}
	return nil
}

func (a *app) readStdinLine() (string, error) {
	if a.br == nil {
		a.br = bufio.NewReader(a.stdin)
	}
	line, err := a.br.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("expected a secret on standard input but it ended")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// maxSecretTries bounds how often a terminal user is asked again.
const maxSecretTries = 3

// secret obtains a secret: from stdin when --password-stdin is set, else from
// the environment variable, else from the terminal without echo. A secret is
// never taken from a command-line argument (visible in `ps` and shell history).
// check (optional) is applied right after the first entry. On a terminal a
// rejected or mismatching entry is explained and asked again (a few times);
// from stdin or the environment it fails at once.
func (a *app) secret(prompt, envName string, confirm bool, check func(string) error) (string, error) {
	if v := os.Getenv(envName); a.pwStdin || v != "" {
		if a.pwStdin {
			var err error
			if v, err = a.readStdinLine(); err != nil {
				return "", err
			}
		}
		if check != nil {
			if err := check(v); err != nil {
				return "", err
			}
		}
		return v, nil
	}
	read := a.askSecret
	if read == nil {
		tty := ttyFile()
		if tty == nil {
			return "", fmt.Errorf("no terminal to ask for a secret; use --password-stdin or set %s", envName)
		}
		if tty != os.Stdin {
			defer tty.Close()
		}
		read = func(p string) (string, error) {
			fmt.Fprint(a.stderr, p)
			b, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(a.stderr)
			return string(b), err
		}
	}
	for try := 1; try <= maxSecretTries; try++ {
		v, err := read(prompt)
		if err != nil {
			return "", errors.New("cancelled")
		}
		if check != nil {
			if err := check(v); err != nil {
				a.say(a.stderr, fmt.Sprintf("%v Try again.", err))
				continue
			}
		}
		if confirm {
			v2, err := read("Repeat: ")
			if err != nil {
				return "", errors.New("cancelled")
			}
			if v != v2 {
				fmt.Fprintln(a.stderr, "The two entries do not match. Try again.")
				continue
			}
		}
		return v, nil
	}
	return "", errors.New("too many attempts; nothing was changed")
}

// canPrompt reports whether an interactive secret prompt is possible.
func (a *app) canPrompt() bool { return !a.pwStdin && (a.askSecret != nil || ttyFile() != nil) }

// askYes asks a yes/no question on the terminal (default no). Without --yes
// and without a terminal it fails instead of guessing.
func (a *app) askYes(yes bool, question string) (bool, error) {
	if yes {
		return true, nil
	}
	return a.ask(question, false)
}

// mustConfirm is askYes that turns a "no" into the error `declined`.
func (a *app) mustConfirm(yes bool, question, declined string) error {
	ok, err := a.askYes(yes, question)
	if err == nil && !ok {
		err = errors.New(declined)
	}
	return err
}

// ask asks a yes/no question; an empty answer means def.
func (a *app) ask(question string, def bool) (bool, error) {
	tty := ttyFile()
	if tty == nil {
		return false, errors.New("this needs confirmation but there is no terminal; re-run with --yes if you are sure")
	}
	if tty != os.Stdin {
		defer tty.Close()
	}
	opts := " [y/N] "
	if def {
		opts = " [Y/n] "
	}
	fmt.Fprint(a.stderr, question+opts)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch l := strings.ToLower(strings.TrimSpace(line)); l {
	case "":
		return def, nil
	default:
		return l == "y" || l == "yes", nil
	}
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func ts(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func shortTS(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).Local().Format("2006-01-02 15:04")
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// copyToClipboard uses the platform's clipboard tool, if one is installed.
func copyToClipboard(text string) error {
	type tool struct {
		bin  string
		args []string
	}
	var tools []tool
	switch runtime.GOOS {
	case "darwin":
		tools = []tool{{"pbcopy", nil}}
	case "windows":
		tools = []tool{{"clip.exe", nil}, {"clip", nil}}
	default:
		tools = []tool{{"wl-copy", nil}, {"xclip", []string{"-selection", "clipboard"}}, {"xsel", []string{"--clipboard", "--input"}}, {"clip.exe", nil}}
	}
	for _, t := range tools {
		path, err := exec.LookPath(t.bin)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, t.args...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s failed: %w", t.bin, err)
		}
		return nil
	}
	return errors.New("no clipboard tool found (install pbcopy, wl-copy, xclip, xsel or clip.exe), or use --field and pipe the output")
}

func prefixed(names []string, p string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = p + n
	}
	return out
}
