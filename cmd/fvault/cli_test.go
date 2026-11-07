package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
)

var fvaultBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fvault-bin-")
	if err != nil {
		panic(err)
	}
	fvaultBin = filepath.Join(dir, "fvault")
	if runtime.GOOS == "windows" {
		fvaultBin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", fvaultBin, ".").CombinedOutput()
	if err != nil {
		os.Stderr.Write(out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// user is one fvault state directory plus its password.
type user struct {
	home, name, pw string
}

type result struct {
	out, err string
	code     int
}

// transcript collects everything the CLI printed so that the end of the test can
// assert that no secret appeared in output that was not explicitly asking for it.
var transcript []string

func (u *user) run(t *testing.T, stdin string, args ...string) result {
	return u.runEnv(t, stdin, nil, args...)
}

func (u *user) runEnv(t *testing.T, stdin string, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(fvaultBin, args...)
	cmd.Env = append(os.Environ(), "FVAULT_HOME="+u.home, "FVAULT_PASSWORD="+u.pw)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	detach(cmd)
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running fvault %v: %v", args, err)
	}
	r := result{so.String(), se.String(), code}
	if !secretCommand(args) {
		transcript = append(transcript, r.out, r.err)
	}
	return r
}

// secretCommand reports whether the command deliberately prints secrets.
func secretCommand(args []string) bool {
	for _, a := range args {
		if a == "--show" || a == "--field" || a == "generate" || a == "--copy" {
			return true
		}
	}
	return len(args) > 0 && args[0] == "generate"
}

func (r result) ok(t *testing.T) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.out, r.err)
	}
	return r
}

func (r result) fails(t *testing.T, code int, stderrHas string) result {
	t.Helper()
	if r.code != code || !strings.Contains(r.err, stderrHas) {
		t.Fatalf("want exit %d with %q in stderr, got exit %d\nstdout: %s\nstderr: %s", code, stderrHas, r.code, r.out, r.err)
	}
	return r
}

func (r result) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.out), v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
}

func newUser(t *testing.T, name, pw string) *user {
	return &user{home: filepath.Join(t.TempDir(), "fv"), name: name, pw: pw}
}

type lsRow struct {
	ID      string   `json:"id"`
	VaultID string   `json:"vault_id"`
	Vault   string   `json:"vault"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	User    string   `json:"username"`
	URLs    []string `json:"urls"`
}

func (u *user) ls(t *testing.T, args ...string) []lsRow {
	t.Helper()
	var rows []lsRow
	u.run(t, "", append([]string{"ls", "--json"}, args...)...).ok(t).json(t, &rows)
	return rows
}

func TestCLI(t *testing.T) {
	cl := clienttest.New(t, 1)
	url := cl.URLs()[0]
	const pwA, pwB = "correct horse ünïcode 1", "staple battery purple 2"
	alice, bob := newUser(t, "alice", pwA), newUser(t, "bob", pwB)
	var generated string

	t.Run("usage", func(t *testing.T) {
		alice.run(t, "", "version").ok(t)
		if r := alice.run(t, "", "version").ok(t); !strings.HasPrefix(r.out, "fvault ") {
			t.Fatal(r.out)
		}
		h := alice.run(t, "", "help").ok(t)
		for _, w := range []string{"init", "register", "vault", "invite", "admin", "export", "import", "fingerprint", "generate", "Exit codes"} {
			if !strings.Contains(h.out, w) {
				t.Fatalf("help lacks %q", w)
			}
		}
		g := alice.run(t, "", "get", "-h").ok(t)
		for _, w := range []string{"--field", "--show", "--copy", "--json", "--vault", "--password-stdin"} {
			if !strings.Contains(g.out, w) {
				t.Fatalf("get -h lacks %q:\n%s", w, g.out)
			}
		}
		alice.run(t, "", "help", "vault", "share").ok(t)
		alice.run(t, "", "bogus").fails(t, 2, "unknown command")
		alice.run(t, "", "get").fails(t, 2, "wrong number of arguments")
		alice.run(t, "", "ls", "--password", "hunter2").fails(t, 2, "not defined")
		alice.run(t, "", "init").fails(t, 2, "--server is required")
		alice.run(t, "", "ls").fails(t, 1, "not configured")
		if g := alice.run(t, "", "vault").code; g != 2 {
			t.Fatalf("vault without subcommand: %d", g)
		}
	})

	t.Run("generate", func(t *testing.T) {
		out := strings.TrimSpace(alice.run(t, "", "generate", "--length", "33", "--no-symbols").ok(t).out)
		if len(out) != 33 || !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(out) {
			t.Fatalf("generated %q", out)
		}
		lines := strings.Fields(alice.run(t, "", "generate", "--count", "3", "--length", "8", "--no-digits", "--no-upper").ok(t).out)
		if len(lines) != 3 {
			t.Fatal(lines)
		}
		alice.run(t, "", "generate", "--length", "2").fails(t, 2, "")
	})

	t.Run("init", func(t *testing.T) {
		alice.run(t, "", "init", "--server", url).fails(t, 1, "plain http")
		r := alice.run(t, "", "init", "--server", url, "--insecure").ok(t)
		if !strings.Contains(r.out, "no users yet") {
			t.Fatalf("hint missing: %s", r.out)
		}
		var cfg map[string]any
		b, _ := os.ReadFile(filepath.Join(alice.home, "config.json"))
		_ = json.Unmarshal(b, &cfg)
		if cfg["allow_insecure"] != true || len(cfg["servers"].([]any)) != 1 {
			t.Fatalf("config: %s", b)
		}
		bob.run(t, "", "init", "--server", url, "--insecure").ok(t)
		alice.run(t, "", "init", "--server", "http://127.0.0.1:1", "--insecure").fails(t, 4, "cannot reach")
	})

	t.Run("status", func(t *testing.T) {
		var st struct {
			Reads     string `json:"reads"`
			Reachable int    `json:"reachable"`
			Nodes     []struct {
				URL       string `json:"url"`
				Reachable bool   `json:"reachable"`
				Role      string `json:"role"`
			} `json:"nodes"`
			Cache struct {
				Present bool `json:"present"`
			} `json:"cache"`
		}
		alice.run(t, "", "status", "--json").ok(t).json(t, &st)
		if st.Reads != "online" || st.Reachable != 1 || len(st.Nodes) != 1 || st.Nodes[0].Role != "leader" || st.Cache.Present {
			t.Fatalf("status: %+v", st)
		}
		if r := alice.run(t, "", "status").ok(t); !strings.Contains(r.out, "reads: online") {
			t.Fatal(r.out)
		}
	})

	t.Run("register and login", func(t *testing.T) {
		weak := &user{home: alice.home, pw: "short1"}
		r := weak.run(t, "", "register", "--username", "alice", "--bootstrap-token", clienttest.BootstrapToken).fails(t, 1, "")
		if !strings.Contains(strings.ToLower(r.err), "12") {
			t.Fatalf("policy message missing: %s", r.err)
		}
		if _, err := os.Stat(filepath.Join(alice.home, "cache.json")); !os.IsNotExist(err) {
			t.Fatal("a rejected registration left state behind")
		}
		hint := (&user{home: alice.home, pw: "aaaaaaaaaaaaaaaa"}).run(t, "", "register", "--username", "alice", "--bootstrap-token", clienttest.BootstrapToken)
		if hint.code == 0 {
			t.Fatal("repeated-character password accepted")
		}
		alice.run(t, "", "register", "--username", "alice", "--bootstrap-token", "wrong-token-wrong-token").fails(t, 1, "")
		r = alice.run(t, "", "register", "--username", "alice", "--bootstrap-token", clienttest.BootstrapToken).ok(t)
		if !strings.Contains(r.out, "administrator") || !regexp.MustCompile(`[0-9a-f]{4}(-[0-9a-f]{4}){7}`).MatchString(r.out) {
			t.Fatalf("register output: %s", r.out)
		}
		if !strings.Contains(r.err, "cannot be recovered") {
			t.Fatalf("no unrecoverable-password warning: %s", r.err)
		}
		for _, f := range []string{"config.json", "cache.json", "token.json"} {
			if runtime.GOOS != "windows" {
				fi, err := os.Stat(filepath.Join(alice.home, f))
				if err != nil || fi.Mode().Perm() != 0o600 {
					t.Fatalf("%s: %v %v", f, fi, err)
				}
			}
		}
		// Wrong password, then right, via stdin and via env.
		wrong := &user{home: alice.home, pw: "nope"}
		wrong.run(t, "", "ls").fails(t, 1, "wrong username or password")
		alice.runEnv(t, pwA+"\n", []string{"FVAULT_PASSWORD="}, "login", "--password-stdin").ok(t)
		alice.run(t, "", "login", "--username", "alice").ok(t)
		alice.run(t, "", "ls").ok(t)
		// Without a terminal and without any source the CLI refuses instead of hanging.
		alice.runEnv(t, "", []string{"FVAULT_PASSWORD="}, "ls").fails(t, 1, "no terminal")
	})

	t.Run("items", func(t *testing.T) {
		alice.run(t, "", "add", "--name", "GitHub", "--username", "alice", "--url", "https://github.com", "--generate", "--length", "30",
			"--set", "Recovery email=a@example.com", "--set-hidden", "PIN=4321").ok(t)
		alice.run(t, "", "add", "--name", "Wifi note", "--type", "note", "--notes", "ssid: ü\npass").ok(t)
		alice.run(t, "", "add", "--name", "Visible").ok(t)
		alice.run(t, "", "add").fails(t, 2, "--name is required")
		alice.run(t, "", "add", "--name", "x", "--type", "bogus").fails(t, 2, "login or note")

		rows := alice.ls(t)
		if len(rows) != 3 {
			t.Fatalf("rows: %+v", rows)
		}
		if r := alice.ls(t, "github"); len(r) != 1 || r[0].Name != "GitHub" || r[0].User != "alice" || len(r[0].URLs) != 1 || r[0].Vault != "Personal" {
			t.Fatalf("filtered: %+v", r)
		}
		if len(alice.ls(t, "zzzz")) != 0 {
			t.Fatal("query matched nothing, expected empty list")
		}
		table := alice.run(t, "", "ls").ok(t).out
		if !strings.Contains(table, "GitHub") || !strings.Contains(table, "NAME") {
			t.Fatal(table)
		}

		// Default output hides the password; --field and --show reveal it.
		def := alice.run(t, "", "get", "github").ok(t).out
		if !strings.Contains(def, "********") || strings.Contains(def, "Recovery email:") == false || strings.Contains(def, "4321") {
			t.Fatalf("get output:\n%s", def)
		}
		generated = strings.TrimSpace(alice.run(t, "", "get", "GITHUB", "--field", "password").ok(t).out)
		if len(generated) != 30 {
			t.Fatalf("password %q", generated)
		}
		if strings.Contains(def, generated) {
			t.Fatal("default get printed the password")
		}
		if shown := alice.run(t, "", "get", "github", "--show").ok(t).out; !strings.Contains(shown, generated) || !strings.Contains(shown, "4321") {
			t.Fatalf("--show:\n%s", shown)
		}
		if u := strings.TrimSpace(alice.run(t, "", "get", "github", "--field", "username").ok(t).out); u != "alice" {
			t.Fatal(u)
		}
		alice.run(t, "", "get", "github", "--field", "nonexistent").fails(t, 1, "no field")
		alice.run(t, "", "get", "github", "--field", "totp").fails(t, 1, "empty")
		if v := strings.TrimSpace(alice.run(t, "", "get", "github", "--field", "Recovery Email").ok(t).out); v != "a@example.com" {
			t.Fatal(v)
		}
		if n := alice.run(t, "", "get", "wifi note", "--field", "notes").ok(t).out; n != "ssid: ü\npass\n" {
			t.Fatalf("notes %q", n)
		}

		// --json: stable shape, no secrets without --show.
		var j map[string]any
		jr := alice.run(t, "", "get", "github", "--json").ok(t)
		jr.json(t, &j)
		if strings.Contains(jr.out, generated) || strings.Contains(jr.out, "4321") {
			t.Fatal("json leaked a secret")
		}
		for _, k := range []string{"id", "vault_id", "vault", "name", "type", "username", "urls", "notes", "fields", "has_password", "created_at", "updated_at", "version"} {
			if _, ok := j[k]; !ok {
				t.Fatalf("json lacks %q: %v", k, j)
			}
		}
		if _, has := j["password"]; has || j["has_password"] != true {
			t.Fatalf("json: %v", j)
		}
		var js map[string]any
		alice.run(t, "", "get", "github", "--json", "--show").ok(t).json(t, &js)
		if js["password"] != generated {
			t.Fatal("--json --show lacks the password")
		}

		// ID and prefix resolution.
		id := alice.ls(t, "github")[0].ID
		for _, ref := range []string{id, id[:8], strings.ToUpper("github")} {
			if n := strings.TrimSpace(alice.run(t, "", "get", ref, "--field", "name").ok(t).out); n != "GitHub" {
				t.Fatalf("ref %q resolved to %q", ref, n)
			}
		}
		alice.run(t, "", "get", "no such item").fails(t, 1, "no item matches")

		// Edit: change fields, regenerate (history), URL list replacement.
		alice.run(t, "", "edit", "github", "--username", "alice2", "--url", "https://a.example", "--url", "https://b.example", "--unset", "pin").ok(t)
		alice.run(t, "", "edit", "github").fails(t, 2, "nothing to change")
		alice.run(t, "", "edit", "github", "--generate", "--length", "16").ok(t)
		newPw := strings.TrimSpace(alice.run(t, "", "get", "github", "--field", "password").ok(t).out)
		if len(newPw) != 16 || newPw == generated {
			t.Fatalf("edit --generate: %q", newPw)
		}
		var h struct {
			History []struct {
				ChangedAt string  `json:"changed_at"`
				Password  *string `json:"password"`
			} `json:"history"`
		}
		hr := alice.run(t, "", "history", "github", "--json").ok(t)
		hr.json(t, &h)
		if len(h.History) != 1 || h.History[0].Password != nil || strings.Contains(hr.out, generated) {
			t.Fatalf("history: %s", hr.out)
		}
		alice.run(t, "", "history", "github", "--json", "--show").ok(t).json(t, &h)
		if *h.History[0].Password != generated {
			t.Fatal("history --show lost the old password")
		}
		if o := alice.run(t, "", "get", "github").ok(t).out; strings.Contains(o, "PIN") || !strings.Contains(o, "https://b.example") || !strings.Contains(o, "alice2") {
			t.Fatalf("after edit:\n%s", o)
		}

		// Item password from the environment (documented, scripts only).
		alice.runEnv(t, "", []string{"FVAULT_ITEM_PASSWORD=env-item-pw"}, "add", "--name", "FromEnv").ok(t)
		if v := strings.TrimSpace(alice.run(t, "", "get", "fromenv", "--field", "password").ok(t).out); v != "env-item-pw" {
			t.Fatal(v)
		}

		// rm needs confirmation; --yes deletes.
		alice.run(t, "", "rm", "fromenv").fails(t, 1, "--yes")
		alice.run(t, "", "rm", "fromenv", "--yes").ok(t)
		alice.run(t, "", "get", "fromenv").fails(t, 1, "no item matches")
	})

	t.Run("guidance, typos and the shell", func(t *testing.T) {
		alice.run(t, "", "lss").fails(t, 2, `Did you mean "ls"`)
		alice.run(t, "", "vault", "lst").fails(t, 2, `Did you mean "ls"`)
		alice.run(t, "", "ls", "--vualt", "x").fails(t, 2, `Did you mean "--vault"`)
		alice.run(t, "").fails(t, 2, "First time here?")
		if r := alice.run(t, "", "ls", "zzzz").ok(t); r.out != "" || !strings.Contains(r.err, "No items match") {
			t.Fatalf("empty result: %+v", r)
		}
		// A too-short new password from stdin fails at once, with the rules stated first.
		r := alice.run(t, pwA+"\nshort\n", "passwd", "--password-stdin").fails(t, 1, "at least 12")
		if !strings.Contains(r.err, "Rules:") || strings.Contains(r.err, "Repeat") {
			t.Fatalf("passwd stderr: %s", r.err)
		}
		alice.run(t, "", "ls").ok(t)

		// One unlock, several commands, shell-style quoting; account commands are refused.
		in := pwA + "\nls\nget \"Wifi note\" --field notes\nget github --field username\nlss\nlogin\nexit\nls\n"
		r = alice.run(t, in, "shell", "--password-stdin").ok(t)
		if strings.Count(r.out, "GitHub") != 1 || !strings.Contains(r.out, "ssid: ü") || !strings.Contains(r.out, "alice2\n") {
			t.Fatalf("shell output: %s", r.out)
		}
		for _, w := range []string{"Unlocked as alice", `Did you mean "ls"`, "cannot be run inside the shell"} {
			if !strings.Contains(r.err, w) {
				t.Fatalf("shell stderr lacks %q: %s", w, r.err)
			}
		}
		alice.runEnv(t, "", []string{"FVAULT_PASSWORD="}, "shell").fails(t, 1, "needs a terminal")
	})

	t.Run("vaults and ambiguity", func(t *testing.T) {
		alice.run(t, "", "vault", "create", "Work").ok(t)
		alice.run(t, "", "add", "--vault", "work", "--name", "github", "--username", "work-account").ok(t)
		r := alice.run(t, "", "get", "github").fails(t, 1, "ambiguous")
		if !strings.Contains(r.err, "Work") || !strings.Contains(r.err, "Personal") {
			t.Fatalf("candidates not listed: %s", r.err)
		}
		if n := strings.TrimSpace(alice.run(t, "", "get", "github", "--vault", "Work", "--field", "username").ok(t).out); n != "work-account" {
			t.Fatal(n)
		}
		var vs []map[string]any
		alice.run(t, "", "vault", "ls", "--json").ok(t).json(t, &vs)
		if len(vs) != 2 {
			t.Fatalf("vaults: %v", vs)
		}
		alice.run(t, "", "vault", "rename", "work", "Job").ok(t)
		alice.run(t, "", "vault", "rename", "job", "Work").ok(t)
		alice.run(t, "", "vault", "delete", "personal", "--yes").fails(t, 1, "personal vault")
		alice.run(t, "", "vault", "create", "Temp").ok(t)
		alice.run(t, "", "vault", "delete", "temp").fails(t, 1, "--yes")
		alice.run(t, "", "vault", "delete", "temp", "--yes").ok(t)
		alice.run(t, "", "ls", "--vault", "nonexistent").fails(t, 1, "no vault matches")
	})

	var aliceFP, bobFP string
	t.Run("invite register share", func(t *testing.T) {
		code := strings.TrimSpace(alice.run(t, "", "invite", "create", "--ttl-hours", "1").ok(t).out)
		if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(code) {
			t.Fatalf("invite code %q", code)
		}
		spare := strings.TrimSpace(alice.run(t, "", "invite", "create").ok(t).out)
		_ = spare
		var inv []map[string]any
		alice.run(t, "", "invite", "ls", "--json").ok(t).json(t, &inv)
		if len(inv) != 2 || inv[0]["state"] != "pending" {
			t.Fatalf("invites: %v", inv)
		}
		// Register bob through env-provided invite code.
		bob.runEnv(t, "", []string{"FVAULT_INVITE=" + code}, "register", "--username", "bob").ok(t)
		bob.run(t, "", "ls").ok(t)
		// Invite is single use; stale code fails.
		carol := newUser(t, "carol", "carol pw")
		carol.run(t, "", "init", "--server", url, "--insecure").ok(t)
		carol.run(t, "", "register", "--username", "carol", "--invite", code).fails(t, 1, "")
		id := inv[1]["invite_id"].(string)
		alice.run(t, "", "invite", "revoke", id[:6]).ok(t)
		alice.run(t, "", "invite", "revoke", "zzzz").fails(t, 1, "no invite")
		bob.run(t, "", "invite", "create").fails(t, 1, "administrator")

		// Fingerprints.
		var fa, fb []struct {
			Username    string `json:"username"`
			Fingerprint string `json:"fingerprint"`
			Self        bool   `json:"self"`
			Verified    bool   `json:"verified"`
		}
		alice.run(t, "", "fingerprint", "--json").ok(t).json(t, &fa)
		bob.run(t, "", "fingerprint", "--json").ok(t).json(t, &fb)
		for _, x := range fa {
			if x.Self {
				aliceFP = x.Fingerprint
			} else if x.Username == "bob" {
				bobFP = x.Fingerprint
			}
		}
		for _, x := range fb {
			if x.Self && x.Fingerprint != bobFP {
				t.Fatalf("bob's own fingerprint %s != what alice sees %s", x.Fingerprint, bobFP)
			}
			if x.Username == "alice" && x.Fingerprint != aliceFP {
				t.Fatalf("alice's fingerprint differs between devices")
			}
		}

		// Sharing needs a verified contact: with no terminal and no --fingerprint it refuses and shows the fingerprint.
		r := alice.run(t, "", "vault", "share", "work", "bob", "--role", "editor").fails(t, 1, "terminal")
		if !strings.Contains(r.err, bobFP) {
			t.Fatalf("share did not show bob's fingerprint: %s", r.err)
		}
		alice.run(t, "", "vault", "share", "work", "bob", "--role", "editor", "--yes").fails(t, 2, "not defined")
		alice.run(t, "", "vault", "share", "work", "bob").fails(t, 2, "--role is required")
		alice.run(t, "", "vault", "share", "work", "bob", "--role", "boss").fails(t, 2, "owner, editor or viewer")
		alice.run(t, "", "vault", "share", "work", "nobody", "--role", "viewer").fails(t, 1, "no user")
		alice.run(t, "", "vault", "share", "work", "bob", "--role", "viewer", "--fingerprint", "0000-0000-0000-0000-0000-0000-0000-0000").fails(t, 1, "does not match")
		var cs []struct {
			Username string `json:"username"`
			Verified bool   `json:"verified"`
		}
		alice.run(t, "", "contacts", "--json").ok(t).json(t, &cs)
		for _, c := range cs {
			if c.Username == "bob" && c.Verified {
				t.Fatal("bob verified before any comparison")
			}
		}
		alice.run(t, "", "contacts", "verify", "bob").fails(t, 1, "terminal")
		alice.run(t, "", "vault", "share", "work", "bob", "--role", "viewer", "--fingerprint", bobFP).ok(t)
		alice.run(t, "", "contacts", "--json").ok(t).json(t, &cs)
		for _, c := range cs {
			if c.Username == "bob" && !c.Verified {
				t.Fatal("bob not verified after the fingerprint check")
			}
		}

		var mem []struct {
			Username string `json:"username"`
			Role     string `json:"role"`
			Note     string `json:"note"`
		}
		alice.run(t, "", "vault", "members", "work", "--json").ok(t).json(t, &mem)
		if len(mem) != 2 {
			t.Fatalf("members: %v", mem)
		}

		// Bob sees the vault as PENDING: shown distinctly, nothing readable, writes refused.
		var bvs []struct {
			Name   string `json:"name"`
			Locked string `json:"locked"`
			ID     string `json:"id"`
		}
		bob.run(t, "", "vault", "ls", "--json").ok(t).json(t, &bvs)
		pendingID := ""
		for _, v := range bvs {
			if v.Locked == "pending" {
				pendingID = v.ID
			}
		}
		if pendingID == "" {
			t.Fatalf("bob's vault list shows no pending vault: %v", bvs)
		}
		if tab := bob.run(t, "", "vault", "ls").ok(t).out; !strings.Contains(tab, "PENDING") {
			t.Fatalf("pending not shown distinctly:\n%s", tab)
		}
		bob.run(t, "", "get", "github", "--field", "username").fails(t, 1, "no item matches")
		bob.run(t, "", "add", "--vault", pendingID[:8], "--name", "nope").fails(t, 1, "waiting for you to confirm the sender")
		if w := bob.run(t, "", "status", "--json").ok(t); !strings.Contains(w.out, "waiting for you to confirm the sender") {
			t.Fatalf("status lacks the pending warning:\n%s", w.out)
		}
		// Accepting: --yes alone is refused; a wrong fingerprint is refused; the right one opens it.
		bob.run(t, "", "vault", "accept", pendingID[:8], "--yes").fails(t, 2, "--fingerprint")
		bob.run(t, "", "vault", "accept", pendingID[:8]).fails(t, 1, "terminal")
		bob.run(t, "", "vault", "accept", pendingID[:8], "--fingerprint", bobFP, "--yes").fails(t, 1, "does not match")
		bob.run(t, "", "vault", "accept", pendingID[:8], "--fingerprint", aliceFP, "--yes").ok(t)
		if n := strings.TrimSpace(bob.run(t, "", "get", "github", "--field", "username").ok(t).out); n != "work-account" {
			t.Fatalf("bob reads shared item: %q", n)
		}
		bob.run(t, "", "add", "--vault", "work", "--name", "nope").fails(t, 1, "read-only")
		alice.run(t, "", "vault", "role", "work", "bob", "editor").ok(t)
		bob.run(t, "", "add", "--vault", "work", "--name", "bobs").ok(t)
		alice.run(t, "", "vault", "role", "personal", "bob", "editor").fails(t, 1, "not a member")

		// Remove bob: ONE atomic request that also rekeys. The recipients are shown first.
		r = alice.run(t, "", "vault", "unshare", "work", "bob").fails(t, 1, "--yes")
		if !strings.Contains(r.err, "new key") || !strings.Contains(r.err, "will lose access: bob") {
			t.Fatalf("recipient list not shown before the rekey:\n%s", r.err)
		}
		r = alice.run(t, "", "vault", "unshare", "work", "bob", "--yes").ok(t)
		if !strings.Contains(r.out, "replaced the vault key") {
			t.Fatalf("unshare: %s", r.out)
		}
		bob.run(t, "", "get", "bobs", "--vault", "work").fails(t, 1, "no vault matches")
		if n := alice.ls(t, "bobs"); len(n) != 1 {
			t.Fatalf("alice lost bob's item: %v", n)
		}
		var vs []struct {
			Name  string `json:"name"`
			Epoch int    `json:"key_epoch"`
			Rec   bool   `json:"rekey_recommended"`
		}
		alice.run(t, "", "vault", "ls", "--json").ok(t).json(t, &vs)
		for _, v := range vs {
			if v.Name == "Work" && (v.Epoch != 2 || v.Rec) {
				t.Fatalf("work after unshare: %+v", v)
			}
		}
		alice.run(t, "", "vault", "rekey", "work", "--yes").ok(t)

		// Re-share, then bob leaves; the next rekey drops him from the roster.
		alice.run(t, "", "vault", "share", "work", "bob", "--role", "viewer").ok(t) // already verified
		bob.run(t, "", "vault", "leave", "work").fails(t, 1, "--yes")
		bob.run(t, "", "vault", "leave", "work", "--yes").ok(t)
		mm := alice.run(t, "", "vault", "members", "work", "--json").ok(t)
		if !strings.Contains(mm.out, "left: will lose access") {
			t.Fatalf("leave not reported in the roster view:\n%s", mm.out)
		}
		alice.run(t, "", "vault", "rekey", "work", "--yes").ok(t)
		alice.run(t, "", "vault", "unshare", "work", "bob", "--yes").fails(t, 1, "not a member")
	})

	t.Run("admin", func(t *testing.T) {
		var us []map[string]any
		alice.run(t, "", "admin", "users", "--json").ok(t).json(t, &us)
		if len(us) != 2 {
			t.Fatalf("users: %v", us)
		}
		alice.run(t, "", "admin", "disable", "bob").ok(t)
		bob.run(t, "", "login").fails(t, 1, "wrong username or password")
		alice.run(t, "", "admin", "enable", "bob").ok(t)
		bob.run(t, "", "login").ok(t)
		alice.run(t, "", "admin", "set-admin", "bob", "maybe").fails(t, 2, "true or false")
		alice.run(t, "", "admin", "cluster").ok(t)
		bob.run(t, "", "admin", "cluster").fails(t, 1, "administrator")
		out := filepath.Join(t.TempDir(), "server-backup.json")
		alice.run(t, "", "admin", "backup", "--out", out).ok(t)
		var sb api.ServerBackup
		b, _ := os.ReadFile(out)
		if err := json.Unmarshal(b, &sb); err != nil || sb.Format != "fpv-server-backup" || len(sb.State) == 0 {
			t.Fatalf("backup file: %v %s", err, b[:min(len(b), 200)])
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
				t.Fatalf("backup mode %v", fi.Mode().Perm())
			}
		}
		alice.run(t, "", "admin", "backup", "--out", out).fails(t, 1, "already exists")
	})

	t.Run("export import", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "x.fpvbackup.json")
		env := []string{"FVAULT_BACKUP_PASSPHRASE=separate backup passphrase"}
		alice.runEnv(t, "", env, "export", "--out", out).ok(t)
		b, _ := os.ReadFile(out)
		if bytes.Contains(b, []byte("GitHub")) || bytes.Contains(b, []byte(generated)) {
			t.Fatal("plaintext in export")
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
				t.Fatalf("export mode %v", fi.Mode().Perm())
			}
		}
		alice.runEnv(t, "", env, "export", "--out", out).fails(t, 1, "already exists")
		before := len(alice.ls(t))
		alice.runEnv(t, "", []string{"FVAULT_BACKUP_PASSPHRASE=wrong"}, "import", out).fails(t, 1, "wrong passphrase")
		alice.runEnv(t, "", env, "import", out).ok(t)
		rows := alice.ls(t)
		if len(rows) <= before {
			t.Fatalf("import added nothing: %d -> %d", before, len(rows))
		}
		restored := 0
		for _, r := range rows {
			if strings.HasSuffix(r.Vault, "(restored)") && r.Name == "GitHub" {
				restored++
			}
		}
		if restored != 1 {
			t.Fatalf("restored GitHub items: %d", restored)
		}
		// Stdin variant: master on line 1, passphrase on line 2.
		out2 := filepath.Join(t.TempDir(), "y.json")
		alice.runEnv(t, pwA+"\nsecond passphrase\n", []string{"FVAULT_PASSWORD="}, "export", "--out", out2, "--password-stdin").ok(t)
		alice.runEnv(t, pwA+"\nsecond passphrase\n", []string{"FVAULT_PASSWORD="}, "import", out2, "--password-stdin").ok(t)
	})

	t.Run("password change", func(t *testing.T) {
		const newPw = "brand new purple monkey 99"
		r := alice.runEnv(t, pwA+"\n"+newPw+"\n", []string{"FVAULT_PASSWORD="}, "passwd", "--password-stdin").ok(t)
		if !strings.Contains(r.err, "cannot be recovered") {
			t.Fatalf("no warning: %s", r.err)
		}
		(&user{home: alice.home, pw: pwA}).run(t, "", "ls").fails(t, 1, "wrong username or password")
		alice.pw = newPw
		alice.run(t, "", "ls").ok(t)
		if len(alice.ls(t, "github")) == 0 {
			t.Fatal("data lost after password change")
		}
		// Bob's device still has a cache of the old state, and keeps working.
		bob.run(t, "", "ls").ok(t)
	})

	t.Run("offline and recovery", func(t *testing.T) {
		alice.run(t, "", "sync").ok(t)
		cl.Stop(0)
		// Reads fall back to the offline copy with a one-line notice.
		r := alice.run(t, "", "ls").ok(t)
		if !strings.Contains(r.err, "offline") || strings.Count(strings.TrimSpace(r.err), "\n") != 0 || !strings.Contains(r.err, "ago") {
			t.Fatalf("offline notice: %q", r.err)
		}
		if !strings.Contains(r.out, "GitHub") {
			t.Fatal("offline ls shows nothing")
		}
		if pw := strings.TrimSpace(alice.run(t, "", "get", "github", "--vault", "personal", "--field", "password").ok(t).out); len(pw) != 16 {
			t.Fatalf("offline get: %q", pw)
		}
		// Writes are refused with a clear explanation and exit code 4.
		alice.run(t, "", "add", "--name", "offline-write").fails(t, 4, "majority")
		alice.run(t, "", "vault", "create", "x").fails(t, 4, "majority")
		alice.run(t, "", "rm", "github", "--vault", "personal", "--yes").fails(t, 4, "majority")
		alice.run(t, "", "sync").fails(t, 4, "")
		alice.run(t, "", "status").fails(t, 4, "")
		(&user{home: alice.home, pw: "wrong"}).run(t, "", "ls").fails(t, 1, "wrong")
		// A user without any cache cannot read offline.
		dave := newUser(t, "dave", "x")
		dave.run(t, "", "init", "--server", url, "--insecure").fails(t, 4, "cannot reach")

		cl.Start(0)
		cl.WaitReady()
		alice.run(t, "", "add", "--name", "after-recovery").ok(t)
		if r := alice.run(t, "", "ls").ok(t); r.err != "" {
			t.Fatalf("unexpected notice after recovery: %q", r.err)
		}
	})

	t.Run("logout", func(t *testing.T) {
		tok := filepath.Join(alice.home, "token.json")
		if _, err := os.Stat(tok); err != nil {
			t.Fatal("no token cached")
		}
		alice.run(t, "", "logout").ok(t)
		if _, err := os.Stat(tok); !os.IsNotExist(err) {
			t.Fatal("token still there")
		}
		alice.run(t, "", "ls").ok(t) // logs in again from the password
		alice.run(t, "", "logout", "--all").ok(t)
		alice.run(t, "", "logout", "--purge").ok(t)
		if _, err := os.Stat(filepath.Join(alice.home, "cache.json")); !os.IsNotExist(err) {
			t.Fatal("cache survived --purge")
		}
		if m, _ := filepath.Glob(filepath.Join(alice.home, "trust-*.bin")); len(m) != 1 {
			t.Fatalf("the trust store must survive logout --purge: %v", m)
		}
		alice.run(t, "", "ls").ok(t)
	})

	t.Run("trust store reset", func(t *testing.T) {
		m, _ := filepath.Glob(filepath.Join(bob.home, "trust-*.bin"))
		if len(m) != 1 {
			t.Fatalf("bob's trust store: %v", m)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(m[0]); fi.Mode().Perm() != 0o600 {
				t.Fatalf("trust store mode %v", fi.Mode().Perm())
			}
		}
		raw, _ := os.ReadFile(m[0])
		if bytes.Contains(raw, []byte("alice")) || bytes.Contains(raw, []byte("contacts")) {
			t.Fatal("trust store is not sealed")
		}
		must0(t, os.Remove(m[0]))
		r := bob.run(t, "", "ls").ok(t)
		if !strings.Contains(r.err, "trust store") {
			t.Fatalf("no reset notice: %q", r.err)
		}
		if r2 := bob.run(t, "", "ls").ok(t); strings.Contains(r2.err, "trust store") {
			t.Fatalf("notice repeats: %q", r2.err)
		}
		// --reset-trust deletes it explicitly.
		alice.run(t, "", "logout", "--reset-trust").ok(t)
		if m, _ := filepath.Glob(filepath.Join(alice.home, "trust-*.bin")); len(m) != 0 {
			t.Fatalf("trust store survived --reset-trust: %v", m)
		}
		alice.run(t, "", "ls").ok(t)
	})

	t.Run("restored servers: blocked, then recover", func(t *testing.T) {
		bk := filepath.Join(t.TempDir(), "server-backup.json")
		alice.run(t, "", "admin", "backup", "--out", bk).ok(t)
		alice.run(t, "", "vault", "create", "Created after the backup").ok(t)
		alice.run(t, "", "add", "--name", "after backup").ok(t)
		var sb api.ServerBackup
		raw, _ := os.ReadFile(bk)
		must0(t, json.Unmarshal(raw, &sb))
		cl.RestoreFrom(&sb)

		// Reads come from the offline copy with an explanation; writes are refused (exit 4).
		r := alice.run(t, "", "ls").ok(t)
		if !strings.Contains(r.err, "OLDER data") || !strings.Contains(r.err, "restored") || !strings.Contains(r.out, "after backup") {
			t.Fatalf("older-state notice/offline copy:\nstdout %s\nstderr %s", r.out, r.err)
		}
		alice.run(t, "", "add", "--name", "must fail").fails(t, 4, "older data")
		alice.run(t, "", "login").fails(t, 4, "OLDER data")
		var sj struct {
			Restored bool     `json:"restored_state"`
			Warnings []string `json:"warnings"`
		}
		alice.run(t, "", "status", "--json").json(t, &sj)
		if !sj.Restored || len(sj.Warnings) == 0 {
			t.Fatalf("status does not report the restored state: %+v", sj)
		}

		// Recovery is explicit and never implicit.
		alice.run(t, "", "recover").fails(t, 2, "--accept-restored-state")
		alice.run(t, "", "recover", "--accept-restored-state").fails(t, 1, "--i-understand")
		r = alice.run(t, "", "recover", "--accept-restored-state", "--i-understand").ok(t)
		if !strings.Contains(r.out, "accepted the restored state") {
			t.Fatalf("recover: %s", r.out)
		}
		if r := alice.run(t, "", "ls").ok(t); strings.Contains(r.err, "OLDER") || strings.Contains(r.out, "after backup") {
			t.Fatalf("after recovery:\nstdout %s\nstderr %s", r.out, r.err)
		}
		alice.run(t, "", "add", "--name", "after recovery").ok(t)
		alice.run(t, "", "recover", "--accept-restored-state", "--i-understand").fails(t, 1, "nothing to recover")
	})

	t.Run("no secrets in default output", func(t *testing.T) {
		all := strings.Join(transcript, "\n")
		for _, s := range []string{pwA, pwB, "brand new purple monkey 99", generated, "4321", "env-item-pw", "separate backup passphrase", clienttest.BootstrapToken} {
			if strings.Contains(all, s) {
				t.Fatalf("secret %q appeared in command output", s)
			}
		}
		// And not in the state files either.
		for _, u := range []*user{alice, bob} {
			for _, f := range []string{"config.json", "cache.json"} {
				b, _ := os.ReadFile(filepath.Join(u.home, f))
				for _, s := range []string{pwA, pwB, "brand new purple monkey 99", generated} {
					if bytes.Contains(b, []byte(s)) {
						t.Fatalf("%s holds a secret", f)
					}
				}
			}
		}
	})
}

func must0(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
