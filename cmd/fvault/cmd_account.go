package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

func init() {
	register(
		command{"init", "point fvault at your servers (the first step)", cmdInit},
		command{"register", "create your account (invite code; the first user: bootstrap token)", cmdRegister},
		command{"login", "sign in again on this device and refresh the offline copy", cmdLogin},
		command{"logout", "forget this device's saved sign-in (--all: on every device)", cmdLogout},
		command{"passwd", "change your master password", cmdPasswd},
		command{"status", "are the servers up? can I read and save? (no password needed)", cmdStatus},
		command{"sync", "refresh the offline copy now", cmdSync},
		command{"fingerprint", "show fingerprints: the short codes that identify people's keys", cmdFingerprint},
		command{"contacts", "household members; verify a fingerprint before sharing", cmdContacts},
		command{"generate", "print a random password (needs no account)", cmdGenerate},
		command{"version", "print the version", cmdVersion},
	)
}

func cmdVersion(a *app, args []string) error {
	f := a.flags("version", "version", "Print the version of fvault.")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "fvault "+version)
	return nil
}

func cmdInit(a *app, args []string) error {
	f := a.flags("init", "init --server URL [--ca FILE] [--insecure]", `
The first step on every device. Save the address of any one of your servers;
fvault asks it for the other servers of the household and switches between
them when one is down. Run it again with another --server to change the
address (your username is kept).

Use https:// servers. --ca names the household CA certificate (ca.pem); it
REPLACES the system roots unless --ca-with-system-roots is given. Plain
http:// is accepted only with --insecure and is meant for local development.

Examples:
  fvault init --server https://vault.example:8443 --ca ca.pem
  fvault init --server http://127.0.0.1:8001 --insecure`)
	var server, ca string
	var insecure, withSys, noTok bool
	f.StringVar(&server, "server", "", "address of any one of your servers, e.g. https://vault.example:8443 (required)")
	f.StringVar(&ca, "ca", "", "PEM file with the household CA certificate to trust")
	f.BoolVar(&withSys, "ca-with-system-roots", false, "trust the --ca certificate in addition to the system roots")
	f.BoolVar(&insecure, "insecure", false, "allow plain http:// (local development only)")
	f.BoolVar(&noTok, "no-token-cache", false, "do not keep the session token in token.json (every command then logs in again)")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if server == "" {
		return usagef("init: --server is required")
	}
	u, err := client.NormalizeNodeURL(server, insecure)
	if err != nil {
		return err
	}
	cfg := &client.Config{Servers: []string{u}, AllowInsecure: insecure, CAWithSystemRoots: withSys, NoTokenCache: noTok}
	if ca != "" {
		if cfg.CAFile, err = filepath.Abs(ca); err != nil {
			return err
		}
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	if old, err := st.LoadConfig(); err == nil {
		cfg.Username = old.Username
	}
	d, err := a.deps(st, cfg)
	if err != nil {
		return err
	}
	done := a.working("Contacting " + u)
	h, herr := d.API.Health(a.ctx)
	done()
	if herr != nil {
		return fmt.Errorf("cannot reach the server at %s (nothing was saved): %w. Check the address and that the server is running; http:// needs --insecure", u, herr)
	}
	if _, err := d.API.RefreshCluster(a.ctx); err != nil {
		fmt.Fprintf(a.stderr, "fvault: warning: could not ask the server for the others (%v); only %s is known\n", err, u)
	}
	cfg.Servers = d.API.Nodes()
	if err := st.SaveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "saved %s\nservers (%d): %s\n", filepath.Join(st.Dir, "config.json"), len(cfg.Servers), strings.Join(cfg.Servers, " "))
	switch {
	case !h.HasUsers:
		a.say(a.stdout, "\nThis household has no users yet. Next, create the first (administrator) account:\n  fvault register --username NAME --bootstrap-token CODE\nThe bootstrap token is the one-time setup code created when the servers were set up (printed by `vaultd init-cluster`, stored in the server's `bootstrap-token` file).")
	case cfg.Username != "":
		fmt.Fprintf(a.stdout, "\nNext: fvault status, or fvault login --username %s if you were signed out.\n", cfg.Username)
	default:
		fmt.Fprintln(a.stdout, "\nNext: sign in with `fvault login --username NAME`, or create your account with the invite code an administrator gave you:\n  fvault register --username NAME --invite CODE")
	}
	if strings.HasPrefix(u, "http://") {
		a.say(a.stderr, "fvault: warning: plain http:// - your login key and session token cross the network unencrypted")
	}
	return nil
}

func cmdRegister(a *app, args []string) error {
	f := a.flags("register", "register --username NAME (--invite CODE | --bootstrap-token CODE)", `
Create your account on this device (run `+"`fvault init`"+` first).

  Everyone else:    --invite CODE, created by an administrator with
                    `+"`fvault invite create`"+`.
  The first user:   --bootstrap-token CODE. The bootstrap token is the
                    one-time setup code created when the servers were set up
                    (printed by `+"`vaultd init-cluster`"+`, stored in the server's
                    `+"`bootstrap-token`"+` file). The first user becomes an
                    administrator.

You will be asked to choose a master password. It unlocks everything, never
leaves this machine and CANNOT be recovered: if you forget it, your data is
gone for good (an administrator cannot reset it). Write it down somewhere
safe, and make an encrypted export now and then (fvault export).

The code can also be given in FVAULT_INVITE / FVAULT_BOOTSTRAP_TOKEN, or typed
when asked, to keep it out of your shell history.

Examples:
  fvault register --username alice --bootstrap-token CODE
  fvault register --username bob --invite CODE`)
	f.auth()
	var user, invite, boot string
	f.StringVar(&user, "username", "", "account name: letters, digits, . _ - (required)")
	f.StringVar(&invite, "invite", "", "invite code from an administrator")
	f.StringVar(&boot, "bootstrap-token", "", "the servers' bootstrap token (first user only)")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if user == "" {
		return usagef("register: --username is required")
	}
	if _, err := vaultcrypto.NormalizeUsername(user); err != nil {
		return usagef("register: %q is not a valid username: use 1 to 32 letters, digits, '.', '_' or '-', starting with a letter or digit", user)
	}
	if invite != "" && boot != "" {
		return usagef("register: give --invite or --bootstrap-token, not both")
	}
	code := invite + boot
	if code == "" {
		code = firstEnv("FVAULT_INVITE", "FVAULT_BOOTSTRAP_TOKEN")
	}
	st, cfg, err := a.loadAll()
	if err != nil {
		return err
	}
	if code == "" {
		if !a.canPrompt() {
			return usagef("register: an invite code (--invite CODE) or, for the very first user, the bootstrap token (--bootstrap-token CODE) is required")
		}
		if code, err = a.secret("Invite code (or bootstrap token): ", "FVAULT_INVITE", false, nil); err != nil {
			return err
		}
	}
	a.say(a.stderr, "Your master password cannot be recovered. If you forget it, your data is lost.\n"+passwordRules)
	pw, err := a.secret("Choose a master password: ", "FVAULT_PASSWORD", true, a.passwordCheck(strings.ToLower(strings.TrimSpace(user))))
	if err != nil {
		return err
	}
	d, err := a.deps(st, cfg)
	if err != nil {
		return err
	}
	done := a.working("Creating your account (this takes a moment)")
	s, err := client.Register(a.ctx, d, client.RegisterParams{Username: user, Password: pw, InviteCode: code})
	done()
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := st.UpdateConfig(func(c *client.Config) { c.Username, c.UserID = s.Username, s.UserID }); err != nil {
		return err
	}
	role := "user"
	if s.IsAdmin() {
		role = "administrator"
	}
	a.say(a.stdout, fmt.Sprintf("registered %s (%s)\nyour fingerprint: %s\nA fingerprint is a short code that identifies your key. When you share vaults with someone, read it out to them in person or on a phone call (not through this app) so they can check it matches.\n", s.Username, role, s.Fingerprint()))
	fmt.Fprintln(a.stdout, "\nNext steps:\n  fvault add --name \"Example Bank\" --generate   save a first password\n  fvault ls                                      list what you saved\n  fvault shell                                   unlock once, run several commands")
	if s.IsAdmin() {
		fmt.Fprintln(a.stdout, "  fvault invite create                           invite the next person")
	}
	return nil
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func cmdLogin(a *app, args []string) error {
	f := a.flags("login", "login [--username NAME]", `
Sign in to the servers and refresh the offline copy of your data. The
username is remembered for later commands. You need this on a new device (after
`+"`fvault init`"+`) or after being signed out; the other commands sign in by
themselves when needed.

Example:
  fvault login --username alice`)
	f.auth()
	var user string
	f.StringVar(&user, "username", "", "account name (default: the one saved by an earlier login)")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	st, cfg, err := a.loadAll()
	if err != nil {
		return err
	}
	if user == "" {
		user = cfg.Username
	}
	if user == "" {
		return usagef("login: --username is required the first time")
	}
	pw, err := a.secret("Master password for "+user+": ", "FVAULT_PASSWORD", false, nil)
	if err != nil {
		return err
	}
	d, err := a.deps(st, cfg)
	if err != nil {
		return err
	}
	done := a.working("Signing in")
	s, err := client.Login(a.ctx, d, user, pw)
	done()
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := st.UpdateConfig(func(c *client.Config) { c.Username, c.UserID = s.Username, s.UserID }); err != nil {
		return err
	}
	a.afterOpen(s)
	fmt.Fprintf(a.stdout, "signed in as %s; %s\n", s.Username, modeSentence(s.Mode()))
	return nil
}

func cmdLogout(a *app, args []string) error {
	f := a.flags("logout", "logout [--all] [--purge] [--reset-trust] [--yes]", `
Forget the sign-in saved on this device (the session token). Your data stays
safe on the servers, and the master password is still needed to open it.

  --all          first sign out every device you use (needs your password).
  --purge        also delete the offline copy of your data on this device;
                 without a server you can then not read anything here.
  --reset-trust  also forget which household members you verified and which
                 shared vaults you accepted. Every member is then unverified
                 again and you must compare fingerprints once more.`).auth().confirm()
	var all, purge, resetTrust bool
	f.BoolVar(&all, "all", false, "revoke every session of the account, on every device")
	f.BoolVar(&purge, "purge", false, "also delete the offline copy of your data")
	f.BoolVar(&resetTrust, "reset-trust", false, "also delete the local trust store (all contacts become unverified)")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	if (purge || resetTrust) && !f.yes && ttyFile() != nil { // scripts without a terminal behave as before
		what := "the offline copy of your data on this device"
		if resetTrust {
			what = "your list of verified household members and accepted shared vaults (you would have to compare fingerprints again)"
		}
		if err := a.mustConfirm(false, "This deletes "+what+".\nContinue?", "nothing was changed"); err != nil {
			return err
		}
	}
	if all {
		s, err := a.openSession()
		if err != nil {
			return err
		}
		defer a.release(s)
		if err := s.RevokeSessions(a.ctx); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "every device of your account was signed out")
	}
	if err := st.DeleteToken(); err != nil {
		return err
	}
	if purge {
		if err := st.DeleteCache(); err != nil {
			return err
		}
	}
	if resetTrust {
		if cfg, err := st.LoadConfig(); err == nil && cfg.UserID != "" {
			if err := st.DeleteTrust(cfg.UserID); err != nil {
				return err
			}
		}
	}
	fmt.Fprintln(a.stdout, "logged out: the saved sign-in was removed from this device. Use `fvault login` to sign in again.")
	return nil
}

func cmdPasswd(a *app, args []string) error {
	f := a.flags("passwd", "passwd", `
Change your master password. You are asked for the current one, then the new
one twice. Your other devices are signed out and must sign in with the new
password (`+"`fvault login`"+`); the offline copy here is refreshed to match.

The new password cannot be recovered if you forget it. With --password-stdin
give the current password on the first line and the new one on the second;
otherwise FVAULT_PASSWORD / FVAULT_NEW_PASSWORD are used before prompting.`).auth()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	cur := a.masterPassword
	a.say(a.stderr, "Your new master password cannot be recovered. If you forget it, your data is lost.\n"+passwordRules)
	next, err := a.secret("New master password: ", "FVAULT_NEW_PASSWORD", true, a.passwordCheck(s.Username))
	if err != nil {
		return err
	}
	done := a.working("Changing the password (this takes a moment)")
	err = s.ChangePassword(a.ctx, cur, next)
	done()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "master password changed; your other devices were signed out and need the new password")
	return nil
}

func cmdSync(a *app, args []string) error {
	f := a.flags("sync", "sync [--json]", `
Refresh the offline copy on this device from the servers and report what is
there. Other commands do this by themselves; use sync before going somewhere
without a connection.`).auth().json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	items := 0
	for _, v := range s.Vaults() {
		items += len(v.Items)
	}
	if f.asJSON {
		if err := a.printJSON(map[string]any{"mode": s.Mode().String(), "rev": s.Rev(), "vaults": len(s.Vaults()), "items": items, "synced_at": s.LastSynced().UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.stdout, "%d vaults, %d items (revision %d); %s\n", len(s.Vaults()), items, s.Rev(), modeSentence(s.Mode()))
	}
	return s.WriteBlocked()
}

func cmdStatus(a *app, args []string) error {
	f := a.flags("status", "status [--json] [--warnings]", `
Show whether the servers are up and what you can do right now. No password is
needed. The summary line says one of:

  online   a majority of the servers (2 of 3) answers: reading gives current
           data and saving works.
  stale    fewer than a majority answer: you see the last copy a server has,
           which may be out of date, and saving is off.
  offline  no server answers: you see the copy saved on this device, and
           saving is off.

Exit code 0 if online, 4 otherwise. The table lists each server with its role
in the cluster (one leader, the others followers), its term and applied
position (how far it has caught up) and its response time.

The warnings section (changed keys, vaults waiting for you to confirm the
sender, locked vaults, a reset trust store) is kept sealed on this device, so
it needs the master password: it is shown with --warnings, or when the
password comes from FVAULT_PASSWORD / --password-stdin. No server is
contacted for it.`).json().auth()
	var wantWarn bool
	f.BoolVar(&wantWarn, "warnings", false, "unlock the offline copy (asks for the password) and list warnings")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	st, cfg, err := a.loadAll()
	if err != nil {
		return err
	}
	ap, err := a.buildAPI(st, cfg)
	if err != nil {
		return err
	}
	done := a.working("Asking the servers")
	probes := ap.ProbeNodes(a.ctx)
	reads := "online"
	reachable := 0
	for _, p := range probes {
		if p.OK {
			reachable++
		}
	}
	if perr := ap.PreloginLinearizable(a.ctx, "fvault-status-probe"); perr != nil {
		if client.IsCode(perr, api.CodeUnavailable) {
			reads = "stale"
		} else {
			reads = "offline"
		}
	}
	done()
	cache, _ := st.LoadCache()
	var warnings []string
	restoredState := false
	warnNote := ""
	if wantWarn || f.stdin || os.Getenv("FVAULT_PASSWORD") != "" {
		if cfg.Username == "" {
			warnNote = "no account set up yet"
		} else if pw, err := a.secret("Master password for "+cfg.Username+": ", "FVAULT_PASSWORD", false, nil); err != nil {
			return err
		} else if sess, err := client.UnlockOffline(client.Deps{Store: st}, cfg.Username, pw); err != nil {
			warnNote = "could not unlock the offline copy: " + err.Error()
		} else {
			warnings = sess.Warnings()
			restoredState = sess.Recovery() != nil
			sess.Lock()
		}
	} else {
		warnNote = "not checked (needs the password: run `fvault status --warnings`)"
	}
	type nodeJSON struct {
		URL       string `json:"url"`
		Reachable bool   `json:"reachable"`
		ID        string `json:"id,omitempty"`
		Role      string `json:"role,omitempty"`
		LeaderID  string `json:"leader_id,omitempty"`
		Term      uint64 `json:"term,omitempty"`
		Applied   uint64 `json:"applied_index,omitempty"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
		Version   string `json:"version,omitempty"`
		Error     string `json:"error,omitempty"`
	}
	var nodes []nodeJSON
	for _, p := range probes {
		n := nodeJSON{URL: p.URL, Reachable: p.OK, Error: p.Err}
		if p.Health != nil {
			n.ID, n.Role, n.LeaderID, n.Term, n.Applied, n.Version = p.Health.NodeID, p.Health.Role, p.Health.LeaderID, p.Health.Term, p.Health.AppliedIndex, p.Health.Version
			n.LatencyMs = p.Latency.Milliseconds()
		}
		nodes = append(nodes, n)
	}
	cacheInfo := map[string]any{"present": false}
	if cache != nil {
		cacheInfo = map[string]any{"present": true, "username": cache.Username, "rev": cache.Sync.Rev, "saved_at": ts(cache.SavedAt),
			"age_seconds": int64(time.Since(time.UnixMilli(cache.SavedAt)).Seconds())}
	}
	if f.asJSON {
		if err := a.printJSON(map[string]any{"reads": reads, "reachable": reachable, "nodes_total": len(nodes), "nodes": nodes, "cache": cacheInfo, "restored_state": restoredState, "warnings": append([]string{}, warnings...), "warnings_note": warnNote}); err != nil {
			return err
		}
	} else {
		rows := [][]string{}
		var down []string
		for _, n := range nodes {
			if !n.Reachable {
				rows = append(rows, []string{"-", n.URL, "DOWN"})
				down = append(down, fmt.Sprintf("  %s does not answer: %s", n.URL, n.Error))
				continue
			}
			rows = append(rows, []string{n.ID, n.URL, "up", n.Role, n.LeaderID, fmt.Sprint(n.Term), fmt.Sprint(n.Applied), fmt.Sprintf("%dms", n.LatencyMs)})
		}
		a.table([]string{"SERVER", "URL", "STATE", "ROLE", "LEADER", "TERM", "APPLIED", "TIME"}, rows)
		for _, d := range down {
			a.say(a.stdout, d)
		}
		summary := fmt.Sprintf("\n%d of %d servers reachable; reads: %s", reachable, len(nodes), reads)
		switch reads {
		case "online":
			summary += " (a majority answers: current data, saving works)"
		case "stale":
			summary += " (no majority of the servers, 2 of 3: you see the last copy one server has, which may be out of date; saving is off)"
		case "offline":
			summary += " (no server answers: only the offline copy on this device can be read; saving is off)"
		}
		a.say(a.stdout, summary)
		if cache != nil {
			fmt.Fprintf(a.stdout, "offline copy: %s, revision %d, saved %s ago\n", cache.Username, cache.Sync.Rev, client.HumanAge(time.Since(time.UnixMilli(cache.SavedAt))))
		} else {
			fmt.Fprintln(a.stdout, "offline copy: none yet (it is made when you sign in: `fvault login`)")
		}
	}
	if !f.asJSON {
		fmt.Fprintln(a.stdout, "\nwarnings:")
		switch {
		case warnNote != "":
			fmt.Fprintln(a.stdout, "  "+warnNote)
		case len(warnings) == 0:
			fmt.Fprintln(a.stdout, "  none")
		}
		for _, w := range warnings {
			fmt.Fprintln(a.stdout, "  - "+w)
		}
	}
	if reads != "online" {
		return errNotOnline
	}
	return nil
}

func cmdGenerate(a *app, args []string) error {
	f := a.flags("generate", "generate [--length N] [--no-symbols] [--no-digits] [--no-upper] [--no-lower] [--exclude-ambiguous] [--count N]", `
Print random passwords from the operating system's CSPRNG. Needs no account
and no server.`)
	var length, count int
	var noSym, noDig, noUp, noLow, noAmb bool
	f.IntVar(&length, "length", 20, "password length")
	f.IntVar(&count, "count", 1, "how many passwords to print")
	f.BoolVar(&noSym, "no-symbols", false, "leave out symbols")
	f.BoolVar(&noDig, "no-digits", false, "leave out digits")
	f.BoolVar(&noUp, "no-upper", false, "leave out upper-case letters")
	f.BoolVar(&noLow, "no-lower", false, "leave out lower-case letters")
	f.BoolVar(&noAmb, "exclude-ambiguous", false, "leave out look-alike characters (O 0 o I l 1 |)")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if count < 1 || count > 1000 {
		return usagef("generate: --count must be between 1 and 1000")
	}
	opts := generatorOptions(noSym, noDig, noUp, noLow, noAmb)
	for range count {
		p, err := vaultcrypto.GeneratePassword(length, opts...)
		if err != nil {
			return usagef("generate: %v", err)
		}
		fmt.Fprintln(a.stdout, p)
	}
	return nil
}

func generatorOptions(noSym, noDig, noUp, noLow, noAmb bool) []vaultcrypto.PasswordOption {
	var classes []vaultcrypto.CharClass
	if !noLow {
		classes = append(classes, vaultcrypto.Lower)
	}
	if !noUp {
		classes = append(classes, vaultcrypto.Upper)
	}
	if !noDig {
		classes = append(classes, vaultcrypto.Digits)
	}
	if !noSym {
		classes = append(classes, vaultcrypto.Symbols)
	}
	opts := []vaultcrypto.PasswordOption{vaultcrypto.WithClasses(classes...)}
	if noAmb {
		opts = append(opts, vaultcrypto.ExcludeAmbiguous())
	}
	return opts
}
