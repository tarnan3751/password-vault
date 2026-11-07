package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tarnan3751/password-vault/internal/client"
)

func init() {
	register(command{"shell", "unlock once, then run several commands (locks itself when idle)", cmdShell})
}

// notInShell are the commands that change which account this device uses or
// its password; they run on their own, outside the shell.
var notInShell = map[string]bool{"init": true, "register": true, "login": true, "logout": true, "passwd": true, "recover": true, "shell": true}

func cmdShell(a *app, args []string) error {
	f := a.flags("shell", "shell [--lock-after DURATION]", `
Ask for the master password once, then read commands at a prompt. The commands
and flags are the same as on the normal command line, with shell-style
quoting:

  fvault (alice)> ls bank
  fvault (alice)> get "Example Bank" --show
  fvault (alice)> add --name "Cinema" --generate
  fvault (alice)> exit

Your keys live only in the memory of this one process: no key is written to
disk, put in an environment variable or passed to another program, and no
background process is left behind. After a period without input the shell locks itself
and forgets the keys; press Enter to unlock again with the master password.
Type "help" for the commands, "lock" to lock now, "exit" (or Ctrl-D) to leave.
Commands that change your account (init, register, login, logout, passwd,
recover) are run outside the shell.

With --password-stdin or FVAULT_PASSWORD the shell also works on piped input:
the first line is the password (--password-stdin only), then one command per
line; it never locks itself then.`).auth()
	lockAfter := 5 * time.Minute
	f.DurationVar(&lockAfter, "lock-after", lockAfter, "lock after this long without input, e.g. 90s or 10m")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	interactive := a.shellTTY || (a.stdin == os.Stdin && isTerminal(os.Stdin))
	idleText := lockAfter.String()
	if lockAfter%time.Minute == 0 {
		idleText = fmt.Sprintf("%d min", lockAfter/time.Minute) // "5m0s" reads badly
	}
	if !interactive && !a.pwStdin && os.Getenv("FVAULT_PASSWORD") == "" {
		return errors.New("the shell needs a terminal; for piped input use --password-stdin or FVAULT_PASSWORD")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	a.sess = s
	a.ctx = context.Background() // Ctrl-C must stop a command, not the shell (see shellLine)
	a.pwStdin = false            // the password line is consumed; later secrets come from the terminal or the environment
	defer a.lock()
	user := s.Username
	state := "online"
	if s.Mode() != client.ModeOnline {
		state = "read-only for now"
	}
	a.say(a.stderr, fmt.Sprintf("Unlocked as %s (%s). Type a command such as `ls` or `get NAME`; `help` lists them, `exit` leaves.\n", user, state))
	if interactive {
		fmt.Fprintf(a.stderr, "It locks after %s without input.\n", idleText)
	}

	if a.br == nil {
		a.br = bufio.NewReader(a.stdin)
	}
	type lineResult struct {
		line string
		err  error
	}
	var pending chan lineResult
	next := func() <-chan lineResult { // at most one read of the terminal is ever outstanding
		if pending == nil {
			pending = make(chan lineResult, 1)
			go func(c chan lineResult) {
				l, err := a.br.ReadString('\n')
				c <- lineResult{strings.TrimRight(l, "\r\n"), err}
			}(pending)
		}
		return pending
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	defer signal.Stop(term)

	for {
		if a.sess != nil && interactive {
			tag := user
			if a.lastMode != client.ModeOnline {
				tag += ", read-only"
			}
			fmt.Fprintf(a.stderr, "fvault (%s)> ", tag)
		}
		var idle <-chan time.Time
		t := time.NewTimer(lockAfter)
		if interactive && a.sess != nil {
			idle = t.C
		}
		var r lineResult
		select {
		case r = <-next():
			t.Stop()
			pending = nil
		case <-idle:
			a.lock()
			fmt.Fprintf(a.stderr, "\nLocked after %s without input: the keys were wiped from memory. Press Enter to unlock again, or Ctrl-D to leave.\n", idleText)
			continue
		case <-term:
			return nil
		}
		if r.err != nil && r.line == "" {
			if interactive {
				fmt.Fprintln(a.stderr)
			}
			return nil
		}
		if a.sess == nil { // locked: any input asks for the password again
			if s, err = a.openSession(); err != nil {
				a.say(a.stderr, "fvault: "+err.Error())
				continue
			}
			a.sess = s
			fmt.Fprintln(a.stderr, "Unlocked.")
			continue
		}
		if !a.shellLine(r.line) {
			return nil
		}
	}
}

// lock wipes the shell's keys from memory.
func (a *app) lock() {
	if a.sess != nil {
		a.sess.Lock()
	}
	a.sess, a.masterPassword = nil, ""
}

// shellLine runs one command line and reports whether the shell goes on.
func (a *app) shellLine(line string) bool {
	args, err := splitArgs(line)
	if err != nil {
		a.say(a.stderr, "fvault: "+err.Error())
		return true
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "#") {
		return true
	}
	name, rest := args[0], args[1:]
	switch name {
	case "exit", "quit":
		return false
	case "lock":
		a.lock()
		fmt.Fprintln(a.stderr, "Locked. Press Enter to unlock again, or Ctrl-D to leave.")
		return true
	case "help", "?":
		if len(rest) == 0 {
			fmt.Fprintln(a.stdout, "Commands: "+strings.Join(shellCommandNames(), " ")+"\nType `help COMMAND` for its usage and examples, `lock` to lock now, `exit` to leave.")
			return true
		}
		name, rest = rest[0], append(rest[1:], "-h")
	}
	c := findCommand(name)
	switch {
	case c == nil:
		fmt.Fprintf(a.stderr, "fvault: unknown command %q.%s Type `help` for the list.\n", name, didYouMean(name, shellCommandNames()))
		return true
	case notInShell[name]:
		fmt.Fprintf(a.stderr, "fvault: `%s` cannot be run inside the shell; leave with `exit` and run `fvault %s`\n", name, name)
		return true
	}
	for _, x := range rest {
		if x == "--password-stdin" {
			fmt.Fprintln(a.stderr, "fvault: --password-stdin does not apply inside the shell (the password is already entered)")
			return true
		}
	}
	// Ctrl-C stops the running command, not the shell.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	a.ctx = ctx
	a.finish(c.run(a, rest))
	stop()
	a.ctx, a.pwStdin = context.Background(), false
	return true
}

func shellCommandNames() []string {
	var n []string
	for _, g := range helpGroups {
		for _, name := range g.names {
			if !notInShell[name] {
				n = append(n, name)
			}
		}
	}
	return append(n, "help", "lock", "exit")
}

// splitArgs splits a command line the way a shell would: whitespace separates
// words; single quotes keep everything literal; inside double quotes a
// backslash escapes " and \; outside quotes it escapes the next character.
func splitArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quote rune
	in := false // a word is being built (so "" yields an empty argument)
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case quote == '"' && c == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\'):
			i++
			cur.WriteRune(rs[i])
		case quote != 0 && c != quote:
			cur.WriteRune(c)
		case quote != 0:
			quote = 0
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == '\\' && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
			in = true
		case c == ' ' || c == '\t':
			if in {
				args, in = append(args, cur.String()), false
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
			in = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unbalanced quote in the command")
	}
	if in {
		args = append(args, cur.String())
	}
	return args, nil
}
