package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/backup"
	"github.com/tarnan3751/password-vault/internal/client"
)

func init() {
	register(
		command{"invite", "invite someone new: create ls revoke (administrators)", cmdInvite},
		command{"admin", "manage the household (administrators; `fvault admin -h`)", cmdAdmin},
		command{"export", "save an encrypted copy of everything you can read to a file", cmdExport},
		command{"import", "restore such a file into new vaults", cmdImport},
	)
}

func cmdInvite(a *app, args []string) error {
	return a.group("invite", []command{
		{"create", "create an invite code (admin)", inviteCreate},
		{"ls", "list invites (admin)", inviteLs},
		{"revoke", "revoke an unused invite (admin)", inviteRevoke},
	}, args)
}

func inviteCreate(a *app, args []string) error {
	f := a.flags("invite create", "invite create [--ttl-hours N] [--json]", `
Create a single-use invite code for a new household member (administrators
only). The code is printed on standard output and can never be shown again;
send it to them in a message or call you trust. They then run:

  fvault init --server URL
  fvault register --username NAME --invite CODE

Example:
  fvault invite create --ttl-hours 24`).auth().json()
	var ttl int
	f.IntVar(&ttl, "ttl-hours", 0, "validity in hours (default 72, max 720)")
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	r, err := s.CreateInvite(a.ctx, ttl)
	if err != nil {
		return err
	}
	if f.asJSON {
		return a.printJSON(map[string]any{"invite_id": r.InviteID, "code": r.Code, "expires_at": ts(r.ExpiresAt)})
	}
	fmt.Fprintln(a.stdout, r.Code)
	fmt.Fprintf(a.stderr, "invite %s, valid until %s, for one person; this code cannot be shown again.\nThey register with: fvault register --username NAME --invite CODE\n", r.InviteID, shortTS(r.ExpiresAt))
	return nil
}

func inviteLs(a *app, args []string) error {
	f := a.flags("invite ls", "invite ls [--json]", "List invites that are still open (\"pending\"), already used, or expired.").auth().json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	list, err := s.ListInvites(a.ctx)
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, u := range s.Directory() {
		names[u.UserID] = u.Username
	}
	state := func(usedBy string, exp int64) string {
		switch {
		case usedBy != "":
			return "used by " + names[usedBy]
		case time.Now().UnixMilli() >= exp:
			return "expired"
		}
		return "pending"
	}
	if f.asJSON {
		out := []map[string]any{}
		for _, i := range list {
			out = append(out, map[string]any{"invite_id": i.InviteID, "created_by": names[i.CreatedBy], "created_at": ts(i.CreatedAt),
				"expires_at": ts(i.ExpiresAt), "used_by": names[i.UsedBy], "state": state(i.UsedBy, i.ExpiresAt)})
		}
		return a.printJSON(out)
	}
	if len(list) == 0 {
		fmt.Fprintln(a.stderr, "No invites yet. Create one with: fvault invite create")
		return nil
	}
	rows := [][]string{}
	for _, i := range list {
		rows = append(rows, []string{i.InviteID, names[i.CreatedBy], shortTS(i.CreatedAt), shortTS(i.ExpiresAt), state(i.UsedBy, i.ExpiresAt)})
	}
	a.table([]string{"ID", "CREATED BY", "CREATED", "EXPIRES", "STATE"}, rows)
	return nil
}

func inviteRevoke(a *app, args []string) error {
	f := a.flags("invite revoke", "invite revoke ID", "Cancel an invite that nobody used yet, so its code stops working. ID is the invite ID (or its first letters) shown by `fvault invite ls`.").auth()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	list, err := s.ListInvites(a.ctx)
	if err != nil {
		return err
	}
	var hit []string
	for _, i := range list {
		if strings.HasPrefix(i.InviteID, strings.ToLower(pos[0])) {
			hit = append(hit, i.InviteID)
		}
	}
	switch len(hit) {
	case 0:
		return &client.NotFoundError{Kind: "invite", Ref: pos[0]}
	case 1:
	default:
		return &client.AmbiguousError{Kind: "invite", Ref: pos[0], Candidates: hit}
	}
	if err := s.RevokeInvite(a.ctx, hit[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "revoked invite %s; its code no longer works\n", hit[0])
	return nil
}

func cmdAdmin(a *app, args []string) error {
	return a.group("admin", []command{
		{"users", "list household members and who is an administrator", adminUsers},
		{"disable", "disable a user (admin)", func(a *app, args []string) error { return adminDisable(a, args, true) }},
		{"enable", "enable a user (admin)", func(a *app, args []string) error { return adminDisable(a, args, false) }},
		{"set-admin", "grant or revoke the admin flag (admin)", adminSetAdmin},
		{"cluster", "how the servers are keeping in step, as seen by one server (admin)", adminCluster},
		{"backup", "download a dump of the servers' data for disaster recovery (admin)", adminBackup},
	}, args)
}

func adminUsers(a *app, args []string) error {
	f := a.flags("admin users", "admin users [--json]", "List every household member.").auth().json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	dir := s.Directory()
	if f.asJSON {
		out := []map[string]any{}
		for _, u := range dir {
			out = append(out, map[string]any{"username": u.Username, "user_id": u.UserID, "admin": u.IsAdmin, "disabled": u.Disabled, "fingerprint": u.Fingerprint, "verified": u.Verified, "self": u.UserID == s.UserID})
		}
		return a.printJSON(out)
	}
	rows := [][]string{}
	for _, u := range dir {
		rows = append(rows, []string{u.Username, yesNo(u.IsAdmin), yesNo(u.Disabled), u.Fingerprint})
	}
	a.table([]string{"USER", "ADMIN", "DISABLED", "FINGERPRINT"}, rows)
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func adminDisable(a *app, args []string, disable bool) error {
	verb := map[bool]string{true: "disable", false: "enable"}[disable]
	f := a.flags("admin "+verb, "admin "+verb+" USER", strings.ToUpper(verb[:1])+verb[1:]+" a user (administrators only). A disabled user cannot sign in and is signed out at once; their data stays, and `fvault admin enable USER` lets them back in.").auth()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := s.SetUserDisabled(a.ctx, pos[0], disable); err != nil {
		return err
	}
	if disable {
		fmt.Fprintf(a.stdout, "disabled %s: they are signed out and cannot sign in; their data is kept (undo: fvault admin enable %s)\n", pos[0], pos[0])
	} else {
		fmt.Fprintf(a.stdout, "enabled %s: they can sign in again\n", pos[0])
	}
	return nil
}

func adminSetAdmin(a *app, args []string) error {
	f := a.flags("admin set-admin", "admin set-admin USER true|false", "Make USER an administrator (true) or remove that right (false). The last administrator cannot be demoted.\n\nExample:\n  fvault admin set-admin bob true").auth()
	pos, err := f.parse(args, 2, 2)
	if err != nil {
		return err
	}
	var v bool
	switch strings.ToLower(pos[1]) {
	case "true", "yes", "1":
		v = true
	case "false", "no", "0":
	default:
		return usagef("admin set-admin: the second argument must be true or false")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := s.SetUserAdmin(a.ctx, pos[0], v); err != nil {
		return err
	}
	if v {
		fmt.Fprintf(a.stdout, "%s is now an administrator\n", pos[0])
	} else {
		fmt.Fprintf(a.stdout, "%s is no longer an administrator\n", pos[0])
	}
	return nil
}

func adminCluster(a *app, args []string) error {
	f := a.flags("admin cluster", "admin cluster [--json]", `
How the servers keep in step, as seen by the one that answered: its role
(leader or follower), the current term (it goes up after each election of a new
leader), how far it has applied the shared log, and how far each other server
has caught up. After a server was down, "MATCH INDEX" growing back to the
leader's number means it has caught up again.`).auth().json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	c, err := s.AdminCluster(a.ctx)
	if err != nil {
		return err
	}
	if f.asJSON {
		return a.printJSON(c)
	}
	fmt.Fprintf(a.stdout, "node %s: %s, leader %s, term %d\ncommit %d, applied %d, last log %d, snapshot %d, rev %d\n",
		c.NodeID, c.Role, c.LeaderID, c.Term, c.CommitIndex, c.AppliedIndex, c.LastLogIndex, c.SnapshotIndex, c.Rev)
	if len(c.Peers) > 0 {
		rows := [][]string{}
		for _, p := range c.Peers {
			lc := "never"
			if p.LastContactMs >= 0 {
				lc = (time.Duration(p.LastContactMs) * time.Millisecond).String() + " ago"
			}
			rows = append(rows, []string{p.ID, fmt.Sprint(p.MatchIndex), lc})
		}
		a.table([]string{"PEER", "MATCH INDEX", "LAST CONTACT"}, rows)
	}
	return nil
}

// writeNewFile writes data to path with mode 0600 (atomically), refusing to replace an existing file unless force is set.
func writeNewFile(path string, data []byte, force bool) error {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to replace it)", path)
		}
	}
	return client.WriteFileAtomic(path, data)
}

func adminBackup(a *app, args []string) error {
	f := a.flags("admin backup", "admin backup --out FILE [--force]", `
Download a dump of everything the servers store (encrypted data and password
checks only: no readable passwords, no keys) for disaster recovery with
`+"`vaultd restore`"+`. This is the administrator's backup of the whole household;
`+"`fvault export`"+` is your own backup of your data. The file is written readable
by you only (mode 0600).

Example:
  fvault admin backup --out household-2026-11.json`).auth()
	var out string
	var force bool
	f.StringVar(&out, "out", "", "file to write (required)")
	f.BoolVar(&force, "force", false, "replace an existing file")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if out == "" {
		return usagef("admin backup: --out is required")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	b, err := s.ServerBackup(a.ctx)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFile(out, data, force); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "wrote %s (server data revision %d, from server %s)\nKeep it somewhere safe and private.\n", out, b.Rev, b.NodeID)
	return nil
}

func (a *app) backupPassphrase(confirm bool) (string, error) {
	if !a.pwStdin && os.Getenv("FVAULT_BACKUP_PASSPHRASE") == "" && !a.canPrompt() {
		return "", errors.New("no terminal to ask for the backup passphrase; use --password-stdin (second line) or FVAULT_BACKUP_PASSPHRASE")
	}
	prompt := "Passphrase of the export file (empty = your master password): "
	if confirm {
		a.say(a.stderr, "Choose a passphrase for the export file. Without it the file cannot be opened, and it cannot be recovered.\nLeave it empty to use your master password (a separate passphrase is safer).")
		prompt = "Export passphrase (empty = your master password): "
	}
	p, err := a.secret(prompt, "FVAULT_BACKUP_PASSPHRASE", confirm, nil)
	if err != nil {
		return "", err
	}
	if p == "" {
		p = a.masterPassword
	}
	return p, nil
}

func cmdExport(a *app, args []string) error {
	f := a.flags("export", "export --out FILE [--force]", `
Save an encrypted copy of everything you can read (all vaults and items,
including shared ones) to a file. This is your safety net if you lose access
or something is deleted by mistake: `+"`fvault import`"+` restores it, into this or
any other household. It also works offline.

The passphrase protecting the file is asked on the terminal (empty = your
master password; a separate one is safer), or taken from the second line of
--password-stdin, or from FVAULT_BACKUP_PASSPHRASE. Keep the file somewhere
safe: anyone with the file AND the passphrase can read your data.

Example:
  fvault export --out family-2026-11.fvault`).auth()
	var out string
	var force bool
	f.StringVar(&out, "out", "", "file to write (required)")
	f.BoolVar(&force, "force", false, "replace an existing file")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if out == "" {
		return usagef("export: --out is required")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	pass, err := a.backupPassphrase(true)
	if err != nil {
		return err
	}
	data, st, err := s.ExportBackup(pass)
	if err != nil {
		return err
	}
	if err := writeNewFile(out, data, force); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "exported %d vaults, %d items to %s\nThe file is encrypted with your passphrase; keep both safe, and remember the passphrase.\n", st.Vaults, st.Items, out)
	if st.Skipped > 0 {
		fmt.Fprintf(a.stderr, "fvault: warning: %d vault(s)/item(s) could not be decrypted and are NOT in the export\n", st.Skipped)
	}
	return nil
}

func cmdImport(a *app, args []string) error {
	f := a.flags("import", "import FILE", `
Restore a file made by `+"`fvault export`"+`. Every vault in it becomes a NEW vault named
"... (restored)"; nothing that exists now is changed or overwritten, so it is
safe to try. Afterwards move or delete what you need. The passphrase is asked
like for export.

Example:
  fvault import family-2026-11.fvault`).auth()
	pos, err := f.parse(args, 1, 1)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	pass, err := a.backupPassphrase(false)
	if err != nil {
		return err
	}
	p, err := client.InspectBackup(data, pass)
	if err != nil {
		if errors.Is(err, backup.ErrDecrypt) {
			return errors.New("wrong passphrase, or the file is damaged")
		}
		return err
	}
	st, err := s.ImportBackup(a.ctx, p, nil)
	if err != nil {
		return fmt.Errorf("import stopped part-way (%d vaults, %d items restored so far): %w", st.Vaults, st.Items, err)
	}
	fmt.Fprintf(a.stdout, "imported %d vaults, %d items as new vaults named \"... (restored)\"; your existing vaults were not changed. See them with `fvault vault ls`.", st.Vaults, st.Items)
	if st.Failed > 0 {
		fmt.Fprintf(a.stdout, " (%d items could not be imported)", st.Failed)
	}
	fmt.Fprintln(a.stdout)
	if st.Failed > 0 {
		return errors.New("some items could not be imported")
	}
	return nil
}
