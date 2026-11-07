package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/client/clienttest"
)

// safeBuf is a buffer that the shell goroutine and the test may use at once.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// scripted answers the terminal prompts of a.secret from a list and records
// the prompts it was asked.
func scripted(answers ...string) (*app, *[]string, *bytes.Buffer) {
	var asked []string
	var errb bytes.Buffer
	a := &app{ctx: context.Background(), stdout: io.Discard, stderr: &errb}
	a.askSecret = func(p string) (string, error) {
		asked = append(asked, p)
		if len(answers) == 0 {
			return "", io.EOF
		}
		r := answers[0]
		answers = answers[1:]
		return r, nil
	}
	return a, &asked, &errb
}

func TestSecretPolicyBeforeConfirmAndReprompt(t *testing.T) {
	// Too short: rejected right after the first entry (no "Repeat:"), asked
	// again, then a mismatch on the repeat, then success.
	a, asked, errb := scripted("short", "correct horse battery", "correct horse batterx", "correct horse battery staple", "correct horse battery staple")
	t.Setenv("FVAULT_PASSWORD", "")
	pw, err := a.secret("Choose: ", "FVAULT_PASSWORD", true, a.passwordCheck("alice"))
	if err != nil || pw != "correct horse battery staple" {
		t.Fatalf("pw=%q err=%v", pw, err)
	}
	want := []string{"Choose: ", "Choose: ", "Repeat: ", "Choose: ", "Repeat: "}
	if strings.Join(*asked, "|") != strings.Join(want, "|") {
		t.Fatalf("prompts %q, want %q", *asked, want)
	}
	for _, w := range []string{"at least 12 characters (this one has 5)", "Try again", "do not match"} {
		if !strings.Contains(errb.String(), w) {
			t.Errorf("stderr lacks %q:\n%s", w, errb.String())
		}
	}
}

func TestSecretGivesUpAfterThreeTries(t *testing.T) {
	a, asked, _ := scripted("a", "b", "c", "d")
	t.Setenv("FVAULT_PASSWORD", "")
	if _, err := a.secret("Choose: ", "FVAULT_PASSWORD", true, a.passwordCheck("alice")); err == nil || !strings.Contains(err.Error(), "too many attempts") {
		t.Fatalf("err=%v", err)
	}
	if len(*asked) != maxSecretTries {
		t.Fatalf("asked %d times", len(*asked))
	}
}

func TestSecretNonInteractiveFailsAtOnce(t *testing.T) {
	// From stdin and from the environment a bad password is an error, not a prompt.
	a, asked, _ := scripted("never used")
	a.stdin, a.pwStdin = strings.NewReader("short\nlonger line\n"), true
	if _, err := a.secret("Choose: ", "FVAULT_PASSWORD", true, a.passwordCheck("alice")); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("stdin: %v", err)
	}
	a, asked2, _ := scripted("never used")
	t.Setenv("FVAULT_PASSWORD", "short")
	if _, err := a.secret("Choose: ", "FVAULT_PASSWORD", true, a.passwordCheck("alice")); err == nil {
		t.Fatal("env: accepted a short password")
	}
	if len(*asked)+len(*asked2) != 0 {
		t.Fatal("prompted although the secret came from stdin or the environment")
	}
	// A plain mismatch-free confirm prompt (item password, backup passphrase) re-asks too.
	t.Setenv("FVAULT_PASSWORD", "")
	a, asked3, _ := scripted("x", "y", "z", "z")
	if v, err := a.secret("P: ", "FVAULT_PASSWORD", true, nil); err != nil || v != "z" || len(*asked3) != 4 {
		t.Fatalf("v=%q err=%v asked=%v", v, err, *asked3)
	}
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		`ls`:                             {"ls"},
		`  get   "Example Bank" --show `: {"get", "Example Bank", "--show"},
		`add --name 'it''s' --notes ""`:  {"add", "--name", "its", "--notes", ""},
		`add --name "say \"hi\" \\ x"`:   {"add", "--name", `say "hi" \ x`},
		`get a\ b`:                       {"get", "a b"},
		``:                               nil,
	}
	for in, want := range cases {
		got, err := splitArgs(in)
		if err != nil || strings.Join(got, "\x00") != strings.Join(want, "\x00") || len(got) != len(want) {
			t.Errorf("%q: got %q err %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`get "open`, `get 'open`} {
		if _, err := splitArgs(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestSuggest(t *testing.T) {
	names := commandNames()
	for typo, want := range map[string]string{"lss": "ls", "regsiter": "register", "passwod": "passwd", "stauts": "status", "vualt": "vault", "xyzzy": ""} {
		if got := suggest(typo, names); got != want {
			t.Errorf("suggest(%q) = %q, want %q", typo, got, want)
		}
	}
}

func TestTableFitsNarrowTerminal(t *testing.T) {
	var out bytes.Buffer
	a := &app{stdout: &out, cols: 60}
	rows := [][]string{{"232efdce", "Personal", "A very long item name indeed, longer than any column", "alice@example.com", "https://example.com/a/very/long/path/that/goes/on"}}
	a.table([]string{"ID", "VAULT*", "NAME*", "USERNAME*", "URL*"}, rows)
	for _, l := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if n := len([]rune(l)); n > 60 {
			t.Errorf("line of %d columns: %q", n, l)
		}
	}
	if !strings.Contains(out.String(), "…") || !strings.Contains(out.String(), "232efdce") {
		t.Errorf("expected shortened cells and a whole ID:\n%s", out.String())
	}
	out.Reset()
	a.cols = 0 // piped: nothing is cut
	a.table([]string{"ID", "NAME*"}, [][]string{{"1", strings.Repeat("x", 200)}})
	if !strings.Contains(out.String(), strings.Repeat("x", 200)) {
		t.Error("a table written to a pipe was shortened")
	}
}

func TestShellLocksWhenIdle(t *testing.T) {
	cl := clienttest.New(t, 1)
	const pw = "correct horse ünïcode 1"
	u := newUser(t, "alice", pw)
	u.run(t, "", "init", "--server", cl.URLs()[0], "--insecure").ok(t)
	u.run(t, "", "register", "--username", "alice", "--bootstrap-token", clienttest.BootstrapToken).ok(t)
	u.run(t, "", "add", "--name", "GitHub", "--username", "octo", "--generate").ok(t)

	t.Setenv("FVAULT_HOME", "")
	t.Setenv("FVAULT_PASSWORD", pw)
	pr, pw2 := io.Pipe()
	var out, errb safeBuf
	a := &app{ctx: context.Background(), stdin: pr, stdout: &out, stderr: &errb, home: u.home, shellTTY: true}
	done := make(chan error, 1)
	go func() { done <- cmdShell(a, []string{"--lock-after", "1500ms"}) }()
	waitFor := func(b *safeBuf, s string, n int) {
		t.Helper()
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if strings.Count(b.String(), s) >= n {
				return
			}
		}
		t.Fatalf("timed out waiting for %d x %q\nstdout: %s\nstderr: %s", n, s, out.String(), errb.String())
	}
	send := func(s string) { t.Helper(); io.WriteString(pw2, s) }

	waitFor(&errb, "Unlocked as alice", 1)
	send("ls\n")
	waitFor(&out, "GitHub", 1)
	send("lss\n")
	waitFor(&errb, `Did you mean "ls"`, 1)
	send("passwd\n")
	waitFor(&errb, "cannot be run inside the shell", 1)
	// No input for longer than --lock-after: the keys are dropped.
	waitFor(&errb, "Locked after", 1)
	if a.sess != nil || a.masterPassword != "" {
		t.Fatal("session still held after the idle lock")
	}
	send("ls\n") // while locked, any line only asks to unlock again; it is not run
	waitFor(&errb, "Unlocked.\n", 1)
	time.Sleep(200 * time.Millisecond)
	if n := strings.Count(out.String(), "GitHub"); n != 1 {
		t.Fatalf("a command typed while locked was run (%d listings)", n)
	}
	send("ls\n")
	waitFor(&out, "GitHub", 2)
	send("exit\n")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shell did not exit")
	}
	if a.sess != nil {
		t.Fatal("session kept after exit")
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("aaa bbb ccc ddd\n  indented text goes on and on", 12)
	want := "aaa bbb ccc\nddd\n  indented\n  text goes\n  on and on"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if wrapText("a very long line stays whole", 0) != "a very long line stays whole" {
		t.Fatal("width 0 must not wrap")
	}
	var out bytes.Buffer
	(&app{cols: 20}).say(&out, "one two three four five six\n")
	if out.String() != "one two three four\nfive six\n" {
		t.Fatalf("say: %q", out.String())
	}
}
