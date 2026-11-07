package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client"
)

func init() {
	register(command{"vault", "vaults and sharing (`fvault vault -h` lists what it can do)", cmdVault})
}

func cmdVault(a *app, args []string) error {
	return a.group("vault", []command{
		{"ls", "list your vaults", vaultLs},
		{"create", "create a vault", vaultCreate},
		{"rename", "rename a vault (owner)", vaultRename},
		{"delete", "delete a vault and its items (owner)", vaultDelete},
		{"members", "who can open a vault: roles, fingerprints, problems", vaultMembers},
		{"share", "let a household member open a vault (owner)", vaultShare},
		{"accept", "open a vault someone shared with you (after checking their fingerprint)", vaultAccept},
		{"role", "change a member's role (owner)", vaultRole},
		{"unshare", "remove members and replace the vault's key (owner)", vaultUnshare},
		{"rekey", "replace the vault's key now (owner; --repair fixes a broken member list)", vaultRekey},
		{"leave", "stop using a vault someone else shared with you", vaultLeave},
	}, args)
}

func vaultFlags(a *app, name, syn, desc string) *cmdFlags {
	return a.flags("vault "+name, "vault "+syn, desc).auth()
}

func vaultLs(a *app, args []string) error {
	f := vaultFlags(a, "ls", "ls [--json]", `
List the vaults you can see: your personal vault, vaults you made, and vaults
shared with you. A vault shared with you stays closed ("PENDING") until you
confirm the sender; the NOTES column tells you the command to run.`).json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	type row struct {
		ID, Name, Role         string
		Members, Items, Epoch  int
		Personal, RekeyAdvised bool
		Locked                 string
	}
	var rows []row
	for _, v := range s.Vaults() {
		rows = append(rows, row{ID: v.ID, Name: v.Name, Role: v.Role, Members: len(v.Members), Items: len(v.Items), Epoch: int(v.KeyEpoch),
			Personal: v.Personal, RekeyAdvised: v.RekeyRecommended, Locked: string(v.Locked)})
	}
	if f.asJSON {
		out := []map[string]any{}
		for _, r := range rows {
			out = append(out, map[string]any{"id": r.ID, "name": r.Name, "role": r.Role, "members": r.Members, "items": r.Items,
				"key_epoch": r.Epoch, "personal": r.Personal, "rekey_recommended": r.RekeyAdvised, "locked": r.Locked})
		}
		return a.printJSON(out)
	}
	table := [][]string{}
	var next []string
	for _, r := range rows {
		var notes []string
		if r.Personal {
			notes = append(notes, "personal")
		}
		switch r.Locked {
		case "":
		case string(client.LockPending):
			notes = append(notes, "PENDING")
			next = append(next, fmt.Sprintf("%s is waiting for you to confirm the sender: run `fvault vault accept %s`", short(r.ID), short(r.ID)))
		default:
			notes = append(notes, "LOCKED")
			next = append(next, fmt.Sprintf("%s is locked (%s); `fvault status --warnings` explains why", short(r.ID), r.Locked))
		}
		if r.RekeyAdvised {
			notes = append(notes, "REPLACE KEY")
			next = append(next, fmt.Sprintf("%s: a member left and its key should be replaced: `fvault vault rekey %s`", short(r.ID), short(r.ID)))
		}
		table = append(table, []string{short(r.ID), r.Name, r.Role, fmt.Sprint(r.Members), fmt.Sprint(r.Items), strings.Join(notes, ", ")})
	}
	a.table([]string{"ID", "NAME*", "ROLE", "MEMBERS", "ITEMS", "NOTES"}, table)
	if len(next) > 0 {
		fmt.Fprintln(a.stderr, "\n"+strings.Join(next, "\n"))
	}
	return nil
}

func vaultCreate(a *app, args []string) error {
	f := vaultFlags(a, "create", "create NAME", `
Create a vault that you own, to keep a set of items together and share them
with other household members later (see `+"`fvault vault share`"+`). Items go in with
`+"`fvault add --vault NAME`"+`.

Example:
  fvault vault create Family`)
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	id, err := s.CreateVault(a.ctx, pos[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "created vault %q (%s)\nAdd items with `fvault add --vault %q --name ...`; share it with `fvault vault share %q USER --role editor`.\n", pos[0], short(id), pos[0], pos[0])
	return nil
}

func vaultRename(a *app, args []string) error {
	f := vaultFlags(a, "rename", "rename V NAME", "Rename a vault you own.")
	pos, s, err := f.open(args, 2, 2)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if err := s.RenameVault(a.ctx, v.ID, pos[1]); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "renamed to %q\n", pos[1])
	return nil
}

func vaultDelete(a *app, args []string) error {
	f := vaultFlags(a, "delete", "delete V [--yes]", `
Delete a vault you own, with every item in it, for every member of it. This
cannot be undone (the only way back is an export file you made earlier). You
are asked to confirm; --yes skips the question for scripts.`).confirm()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	if err := a.mustConfirm(f.yes, fmt.Sprintf("Delete vault %q with its %d item(s) for all %d member(s)? This cannot be undone.", v.Name, len(v.Items), len(v.Members)), "not deleted"); err != nil {
		return err
	}
	if err := s.DeleteVault(a.ctx, v.ID); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "deleted vault %q\n", v.Name)
	return nil
}

func vaultMembers(a *app, args []string) error {
	f := vaultFlags(a, "members", "members V [--json]", `
Show who can open the vault: the vault's own member list (sealed under the
vault key, so the server cannot change it unnoticed), with each member's role,
fingerprint, and whether you verified them (compared their fingerprint with
them in person or on a phone call). Where the server's own list differs, the
difference is shown in the NOTE column.

Roles: owner (can share, change roles and delete), editor (can change items),
viewer (can only read).`).json()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if !v.Readable() {
		return fmt.Errorf("vault %s is %s: %s", short(v.ID), v.Locked, v.LockDetail)
	}
	if f.asJSON {
		out := []map[string]any{}
		for _, m := range v.Members {
			out = append(out, map[string]any{"username": m.Username, "user_id": m.UserID, "role": m.Role, "fingerprint": m.Fingerprint,
				"verified": m.Verified, "disabled": m.Disabled, "key_changed": m.KeyMismatch, "self": m.UserID == s.UserID,
				"in_roster": m.InRoster, "on_server": m.InServer, "note": m.Note})
		}
		return a.printJSON(out)
	}
	table := [][]string{}
	unverified := false
	for _, m := range v.Members {
		ver := verifiedLabel(m.UserID == s.UserID, m.KeyMismatch, m.Verified)
		unverified = unverified || ver == "no"
		name := m.Username
		if m.Disabled {
			name += " (disabled)"
		}
		table = append(table, []string{name, m.Role, m.Fingerprint, ver, m.Note})
	}
	a.table([]string{"USER", "ROLE", "FINGERPRINT", "VERIFIED", "NOTE*"}, table)
	if unverified {
		fmt.Fprintln(a.stderr, "\nVERIFIED \"no\": you have not compared that person's fingerprint with them yet; run `fvault contacts verify USER`.")
	}
	if v.RekeyRecommended {
		fmt.Fprintln(a.stderr, "note: a member left or was cut off and the vault's key has not been replaced yet; an owner can run `fvault vault rekey`")
	}
	return nil
}

func validRoleArg(r string) error {
	switch r {
	case api.RoleOwner, api.RoleEditor, api.RoleViewer:
		return nil
	}
	return usagef("role must be owner, editor or viewer")
}

// askTTY asks a yes/no question that cannot be answered by a flag.
func (a *app) askTTY(question, scriptHint string) (bool, error) {
	if ttyFile() == nil {
		return false, errors.New("you have to compare the fingerprint yourself, and there is no terminal to ask you on; " + scriptHint)
	}
	return a.askYes(false, question)
}

// ensureVerified makes sure a contact is verified on this device: already
// verified, verified by an explicit matching --fingerprint, or confirmed by
// the person at the terminal after comparing the fingerprint with them in
// person or on a phone call.
func (a *app) ensureVerified(s *client.Session, u client.UserInfo, fp string, purpose string) error {
	if u.Self || u.Verified {
		return nil
	}
	if u.KeyMismatch {
		return fmt.Errorf("the key of %s changed; refusing", u.Username)
	}
	if fp != "" {
		return s.VerifyWithFingerprint(u.UserID, fp)
	}
	a.say(a.stderr, fmt.Sprintf("%s\n  %s's fingerprint: %s\n  your fingerprint:   %s\nA fingerprint is a short code that identifies a person's key. Ask %s to read theirs out to you in person or on a phone call (not through this app) and compare it with the one shown above.",
		purpose, u.Username, u.Fingerprint, s.Fingerprint(), u.Username))
	ok, err := a.askTTY(fmt.Sprintf("Did you compare it with %s, and does it match exactly?", u.Username),
		"in scripts pass --fingerprint with the value they gave you")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s was not verified", u.Username)
	}
	return s.MarkVerified(u.UserID)
}

func vaultAccept(a *app, args []string) error {
	f := vaultFlags(a, "accept", "accept V [--fingerprint FP [--yes]]", `
Open a vault that someone shared with you. Until you do, it is closed ("waiting
for you to confirm the sender"): nothing in it is decrypted, because a server
could pretend that someone shared a vault with you. Check who sent it:
this shows their fingerprint and asks whether you compared it with them in
person or on a phone call (not through this app). If you say yes, the sender
becomes a verified contact and the vault opens. Find the vault's ID with
`+"`fvault vault ls`"+`.

Example:
  fvault vault accept 3f9a1c20

For scripts: --fingerprint must equal the sender's fingerprint as shown on
this device; --yes is only accepted together with --fingerprint.`).confirm()
	var fp string
	f.StringVar(&fp, "fingerprint", "", "the sender's fingerprint, as they told you; must match")
	pos, err := f.parse(args, 1, 1)
	if err != nil {
		return err
	}
	if f.yes && fp == "" {
		return usagef("vault accept: --yes needs --fingerprint (a script cannot accept blindly)")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if v.Locked == client.NotLocked {
		fmt.Fprintf(a.stdout, "vault %q is already open\n", v.Name)
		return nil
	}
	if v.Locked != client.LockPending {
		return fmt.Errorf("vault %s is locked (%s) and cannot be accepted: %s", short(v.ID), v.Locked, v.LockDetail)
	}
	p := v.Pending
	if p.Replaced {
		fmt.Fprintf(a.stderr, "WARNING: the key of this vault was replaced by %s, who was not an owner when this device last saw the vault.\nAsk %s whether they really did that before you accept.\n", p.SenderName, p.SenderName)
	}
	sender, err := s.ResolveUser(p.SenderName)
	if err != nil {
		return err
	}
	if fp != "" {
		if err := s.VerifyWithFingerprint(sender.UserID, fp); err != nil {
			return err
		}
	} else if !sender.Verified {
		if err := a.ensureVerified(s, *sender, "", fmt.Sprintf("Vault %s was shared with you by %s.", short(v.ID), p.SenderName)); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.stderr, "Vault %s was shared with you by %s, whom you already verified (fingerprint %s).\n", short(v.ID), p.SenderName, p.SenderFingerprint)
		if err := a.mustConfirm(false, "Accept it?", "not accepted"); err != nil {
			return err
		}
	}
	if err := s.AcceptVault(v.ID); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "accepted vault %q from %s; it is open now (see its items with `fvault ls --vault %s`)\n", s.Vault(v.ID).Name, p.SenderName, short(v.ID))
	return nil
}

func vaultShare(a *app, args []string) error {
	f := vaultFlags(a, "share", "share V USER --role owner|editor|viewer [--fingerprint FP]", `
Let a household member open a vault you own. Roles: owner (can share and
delete), editor (can change items), viewer (can only read).

Only verified contacts can be added: if you have not yet compared USER's
fingerprint with them (in person or on a phone call, not through this app), it
is shown and you are asked to confirm. This is what stops a compromised server
from slipping in a stranger's key. The vault's key is then given to USER's
key, and the vault's member list is updated in the same request. USER sees the
vault as "waiting for you to confirm the sender" until they run
`+"`fvault vault accept`"+`.

Examples:
  fvault vault share Family bob --role editor
  fvault vault share Family bob --role viewer --fingerprint 1a2b-...

For scripts: --fingerprint must equal USER's fingerprint as shown on this device.`)
	var role, fp string
	f.StringVar(&role, "role", "", "owner, editor or viewer (required)")
	f.StringVar(&fp, "fingerprint", "", "USER's fingerprint, as they told you; verifies them if it matches")
	pos, err := f.parse(args, 2, 2)
	if err != nil {
		return err
	}
	if role == "" {
		return usagef("vault share: --role is required")
	}
	if err := validRoleArg(role); err != nil {
		return err
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	u, err := s.LookupUser(pos[1])
	if err != nil {
		return err
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	if err := a.ensureVerified(s, *u, fp, fmt.Sprintf("You are about to share %q with %s as %s.", v.Name, u.Username, role)); err != nil {
		return err
	}
	if err := s.AddMember(a.ctx, v.ID, u.Username, role); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%s can now open %q as %s.\nTell %s to run `fvault vault ls`, then `fvault vault accept %s`.\n", u.Username, v.Name, role, u.Username, short(v.ID))
	return nil
}

func vaultRole(a *app, args []string) error {
	f := vaultFlags(a, "role", "role V USER ROLE", `
Change the role of a vault member: owner (can share and delete), editor (can
change items) or viewer (can only read). If another owner changed the member
list at the same moment, this retries on the fresh list.

Example:
  fvault vault role Family bob viewer`)
	pos, err := f.parse(args, 3, 3)
	if err != nil {
		return err
	}
	if err := validRoleArg(pos[2]); err != nil {
		return err
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	u, err := s.ResolveUser(pos[1])
	if err != nil {
		return err
	}
	member := false
	for _, m := range v.Members {
		member = member || (m.UserID == u.UserID && m.InRoster)
	}
	if !member {
		return fmt.Errorf("%s is not a member of %q (use `vault share`)", u.Username, v.Name)
	}
	if err := s.SetMemberRole(a.ctx, v.ID, u.UserID, pos[2]); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%s is now %s of %q\n", u.Username, pos[2], v.Name)
	return nil
}

// rekeyFlags are shared by unshare and rekey.
type rekeyFlags struct {
	verify repeated
}

func (r *rekeyFlags) register(f *cmdFlags) {
	f.Var(&r.verify, "verify", "USER=FINGERPRINT: verify a recipient by an explicit fingerprint (repeatable; needed in scripts for recipients you have not verified)")
	f.confirm()
}

// runRekey shows who will receive the new key, verifies unverified
// recipients (by --verify or at the terminal), asks for confirmation, and
// performs the atomic rekey.
func (a *app) runRekey(s *client.Session, v *client.VaultView, o client.RekeyOptions, f *cmdFlags, rf *rekeyFlags) (*client.RekeyPlan, error) {
	plan, err := s.PlanRekey(v.ID, o)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(a.stderr, "Vault %q: the new key (number %d) will be given to:\n", plan.Name, plan.Epoch)
	for _, r := range plan.Receives {
		st := "verified"
		switch {
		case r.Self:
			st = "you"
		case !r.Verified:
			st = "NOT VERIFIED YET"
		}
		fmt.Fprintf(a.stderr, "  %-16s %-7s %s  [%s]\n", r.Username, r.Role, r.Fingerprint, st)
	}
	for _, r := range plan.Removed {
		fmt.Fprintf(a.stderr, "  will lose access: %s (%s)\n", r.Username, r.Role)
	}
	for _, r := range plan.Left {
		fmt.Fprintf(a.stderr, "  left earlier, now dropped: %s\n", r.Username)
	}
	explicit := map[string]string{}
	for _, kv := range rf.verify {
		k, val, err := splitKV(kv)
		if err != nil {
			return nil, err
		}
		explicit[strings.ToLower(k)] = val
	}
	for _, un := range plan.Unverified() {
		u, err := s.ResolveUser(un.Username)
		if err != nil {
			return nil, err
		}
		if err := a.ensureVerified(s, *u, explicit[u.Username], fmt.Sprintf("%s will receive the new key but you have not verified them on this device.", u.Username)); err != nil {
			return nil, err
		}
	}
	if err := a.mustConfirm(f.yes, "Replace the key now? (Everyone listed above keeps access; the old key stops working for new data.)", "cancelled"); err != nil {
		return nil, err
	}
	if err := s.RekeyVault(a.ctx, v.ID, o); err != nil {
		return nil, err
	}
	return plan, nil
}

func vaultUnshare(a *app, args []string) error {
	f := vaultFlags(a, "unshare", "unshare V USER... [--yes] [--verify USER=FP]", `
Remove members from a vault. In the same request the vault's key is replaced:
the removed members are dropped and everyone else gets a new key, so there is
no moment at which a removed member still has the current key. The people who
will get the new key are listed first; each must be a verified contact on this
device (you compared their fingerprint with them).

Passwords a removed member has already seen cannot be taken back: change the
passwords they could read.

Example:
  fvault vault unshare Family bob`)
	var rf rekeyFlags
	rf.register(f)
	pos, s, err := f.open(args, 2, -1)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	var ids []string
	for _, name := range pos[1:] {
		u, err := s.ResolveUser(name)
		if err != nil {
			return err
		}
		ids = append(ids, u.UserID)
	}
	if _, err := a.runRekey(s, v, client.RekeyOptions{Remove: ids}, f, &rf); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "removed %s from %q and replaced the vault key\n", strings.Join(pos[1:], ", "), v.Name)
	return nil
}

func vaultRekey(a *app, args []string) error {
	f := vaultFlags(a, "rekey", "rekey V [--repair] [--yes] [--verify USER=FP]", `
Replace the vault's key: everything in the vault is re-encrypted under a new
key, and the new key is given to the vault's members (minus anyone who has
left). Use it when `+"`fvault vault ls`"+` says the key should be replaced, for example
after a member left. The people who will get the new key are listed first and
must be verified contacts. It refuses to run if the server lists a member who
is not in the vault's own member list.

--repair rebuilds an unreadable member list from the server's list; every
member must then be a verified contact.`)
	var rf rekeyFlags
	rf.register(f)
	var repair bool
	f.BoolVar(&repair, "repair", false, "rebuild an unreadable member list from the server's list")
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if _, err := a.runRekey(s, v, client.RekeyOptions{Repair: repair}, f, &rf); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "replaced the key of %q (key number %d)\n", s.Vault(v.ID).Name, s.Vault(v.ID).KeyEpoch)
	return nil
}

func vaultLeave(a *app, args []string) error {
	f := vaultFlags(a, "leave", "leave V [--yes]", `
Stop using a vault someone else shared with you. You lose access to it and to
every item in it (the owner and the other members keep theirs). To get back
in, an owner has to share it with you again. An owner should afterwards
replace the vault's key (`+"`fvault vault rekey`"+`).`).confirm()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	v, err := s.ResolveVault(pos[0])
	if err != nil {
		return err
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	if err := a.mustConfirm(f.yes, fmt.Sprintf("Leave vault %q? You will lose access to its %d item(s) until an owner shares it with you again.", v.Name, len(v.Items)), "not left"); err != nil {
		return err
	}
	if err := s.LeaveVault(a.ctx, v.ID); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "left vault %q\n", v.Name)
	return nil
}
