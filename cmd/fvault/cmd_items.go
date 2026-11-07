package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/client"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

func init() {
	register(
		command{"ls", "list saved items, optionally only those matching a word", cmdLs},
		command{"get", "show an item (--show reveals secrets, --copy copies the password)", cmdGet},
		command{"add", "save a new item (a login or a note)", cmdAdd},
		command{"edit", "change an item", cmdEdit},
		command{"rm", "delete an item", cmdRm},
		command{"history", "show an item's earlier passwords", cmdHistory},
	)
}

const maskedSecret = "********"

func cmdLs(a *app, args []string) error {
	f := a.flags("ls", "ls [--vault V] [QUERY]", `
List the items of all vaults you can read (or just one). QUERY keeps only
items whose name, username, URL or notes contain it, ignoring capitals.
Passwords are never shown here; use `+"`fvault get`"+` for those.

Examples:
  fvault ls
  fvault ls bank
  fvault ls --vault Family`).auth().json()
	var vref string
	f.StringVar(&vref, "vault", "", "only this vault (name, ID or unique ID prefix)")
	pos, s, err := f.open(args, 0, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	vaults := s.Vaults()
	if vref != "" {
		v, err := s.ResolveVault(vref)
		if err != nil {
			return err
		}
		vaults = []*client.VaultView{v}
	}
	q := ""
	if len(pos) == 1 {
		q = strings.ToLower(pos[0])
	}
	type row struct {
		ID        string   `json:"id"`
		VaultID   string   `json:"vault_id"`
		Vault     string   `json:"vault"`
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Username  string   `json:"username"`
		URLs      []string `json:"urls"`
		Version   uint64   `json:"version"`
		UpdatedAt string   `json:"updated_at"`
		Error     string   `json:"error,omitempty"`
	}
	rows := []row{}
	for _, v := range vaults {
		for _, iv := range v.Items {
			r := row{ID: iv.ID, VaultID: v.ID, Vault: v.Name, Version: iv.Version, UpdatedAt: ts(iv.UpdatedAt), URLs: []string{}}
			if it := iv.Item; it != nil {
				if q != "" && !strings.Contains(strings.ToLower(it.Name+"\n"+it.Username+"\n"+strings.Join(it.URLs, "\n")+"\n"+it.Notes), q) {
					continue
				}
				r.Name, r.Type, r.Username = it.Name, it.Type, it.Username
				if it.URLs != nil {
					r.URLs = it.URLs
				}
			} else {
				if q != "" {
					continue
				}
				r.Name, r.Error = "(unreadable)", iv.Err
			}
			rows = append(rows, r)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Vault != rows[j].Vault {
			return strings.ToLower(rows[i].Vault) < strings.ToLower(rows[j].Vault)
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	if f.asJSON {
		return a.printJSON(rows)
	}
	if len(rows) == 0 {
		if q != "" {
			fmt.Fprintf(a.stderr, "No items match %q. Run `fvault ls` to list everything.\n", pos[0])
		} else {
			fmt.Fprintln(a.stderr, "No items yet. Save one with: fvault add --name \"Example Bank\" --username me@example.com --generate")
		}
		return nil
	}
	table := [][]string{}
	for _, r := range rows {
		table = append(table, []string{short(r.ID), r.Vault, r.Name, r.Username, firstOf(r.URLs), shortTSStr(r.UpdatedAt)})
	}
	a.table([]string{"ID", "VAULT*", "NAME*", "USERNAME*", "URL*", "UPDATED"}, table)
	return nil
}

func firstOf(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// shortTSStr shows an RFC 3339 time in the local time zone, like `get` does.
func shortTSStr(rfc string) string {
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	return t.Local().Format("2006-01-02 15:04")
}

// fieldValue returns the value of a named field of an item. Standard names are
// case-insensitive; anything else is looked up among the custom fields.
func fieldValue(it *vaultcrypto.Item, name string) (string, bool) {
	switch strings.ToLower(name) {
	case "password":
		return it.Password, true
	case "username", "user":
		return it.Username, true
	case "url", "urls":
		return strings.Join(it.URLs, "\n"), true
	case "notes", "note":
		return it.Notes, true
	case "totp":
		return it.TOTP, true
	case "name":
		return it.Name, true
	}
	for _, cf := range it.Fields {
		if strings.EqualFold(cf.Name, name) {
			return cf.Value, true
		}
	}
	return "", false
}

func cmdGet(a *app, args []string) error {
	f := a.flags("get", "get ITEM [--vault V] [--field password|username|url|notes|totp|NAME] [--show] [--copy] [--json]", `
Show an item. ITEM is its name (capitals do not matter), or the ID or ID
prefix (at least 4 characters) from `+"`fvault ls`"+`. Secrets (password, TOTP code
key, hidden custom fields) are masked unless you ask for them:

  --show    reveal them in the output
  --copy    put the password (or the --field you name) on the clipboard
            without printing it
  --field   print just that one field's raw value (for scripts)

Examples:
  fvault get "Example Bank" --show
  fvault get "Example Bank" --copy
  fvault get "Example Bank" --field username`).auth().json()
	var vref, field string
	var show, cp bool
	f.StringVar(&vref, "vault", "", "look only in this vault")
	f.StringVar(&field, "field", "", "print only this field's raw value: password, username, url, notes, totp, name, or a custom field name")
	f.BoolVar(&show, "show", false, "reveal secrets in the output")
	f.BoolVar(&cp, "copy", false, "copy the field (default: password) to the clipboard")
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	r, err := s.ResolveItem(vref, pos[0])
	if err != nil {
		return err
	}
	it := r.Item.Item
	if it == nil {
		return fmt.Errorf("item %s is unreadable (%s)", short(r.Item.ID), r.Item.Err)
	}
	if cp || field != "" {
		name := cmp.Or(field, "password")
		v, ok := fieldValue(it, name)
		if !ok {
			return fmt.Errorf("the item has no field %q", name)
		}
		if v == "" {
			return fmt.Errorf("the %s field is empty", name)
		}
		if !cp {
			fmt.Fprintln(a.stdout, v)
			return nil
		}
		if err := copyToClipboard(v); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "copied %s of %q to the clipboard\n", name, it.Name)
		return nil
	}
	if f.asJSON {
		type cf struct {
			Name   string  `json:"name"`
			Value  *string `json:"value"`
			Hidden bool    `json:"hidden"`
		}
		o := map[string]any{
			"id": r.Item.ID, "vault_id": r.Vault.ID, "vault": r.Vault.Name, "name": it.Name, "type": it.Type,
			"username": it.Username, "urls": nonNil(it.URLs), "notes": it.Notes, "tags": nonNil(it.Tags),
			"has_password": it.Password != "", "has_totp": it.TOTP != "",
			"created_at": ts(it.CreatedAt), "updated_at": ts(it.UpdatedAt), "version": r.Item.Version,
			"history_entries": len(it.PasswordHistory),
		}
		var fields []cf
		for _, c := range it.Fields {
			x := cf{Name: c.Name, Hidden: c.Hidden}
			if !c.Hidden || show {
				v := c.Value
				x.Value = &v
			}
			fields = append(fields, x)
		}
		if fields == nil {
			fields = []cf{}
		}
		o["fields"] = fields
		if show {
			o["password"], o["totp"] = it.Password, it.TOTP
		}
		return a.printJSON(o)
	}
	w := a.stdout
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-10s %s\n", k+":", v)
		}
	}
	secret := func(v string) string {
		switch {
		case v == "":
			return ""
		case show:
			return v
		}
		return maskedSecret + "  (--show reveals it, --copy copies it)"
	}
	line("Name", it.Name)
	line("Vault", r.Vault.Name)
	line("ID", r.Item.ID)
	line("Type", it.Type)
	line("Username", it.Username)
	line("Password", secret(it.Password))
	for i, u := range it.URLs {
		k := "URL"
		if i > 0 {
			k = ""
		}
		line(k, u)
	}
	line("TOTP", secret(it.TOTP))
	if it.Notes != "" {
		fmt.Fprintf(w, "%-10s %s\n", "Notes:", strings.ReplaceAll(it.Notes, "\n", "\n           "))
	}
	for _, c := range it.Fields {
		v := c.Value
		if c.Hidden && !show {
			v = maskedSecret
		}
		line(c.Name, v)
	}
	if len(it.Tags) > 0 {
		line("Tags", strings.Join(it.Tags, ", "))
	}
	line("Created", shortTS(it.CreatedAt))
	line("Updated", shortTS(r.Item.UpdatedAt))
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// itemFlags are the field flags shared by add and edit.
type itemFlags struct {
	vault, name, username, notes, typ string
	urls, set, setHidden, unset       repeated
	generate, showPw, promptPw        bool
	length                            int
	noSym, noDig, noUp, noLow, noAmb  bool
}

func (x *itemFlags) register(f *cmdFlags, forAdd bool) {
	f.StringVar(&x.name, "name", "", "item name"+map[bool]string{true: " (required)", false: " (rename)"}[forAdd])
	f.StringVar(&x.username, "username", "", "login username")
	f.Var(&x.urls, "url", "URL (repeatable; on edit, giving --url replaces the list; --url '' clears it)")
	f.StringVar(&x.notes, "notes", "", "free-text notes")
	f.Var(&x.set, "set", "custom field NAME=VALUE (repeatable)")
	f.Var(&x.setHidden, "set-hidden", "custom secret field NAME=VALUE (repeatable; masked in output)")
	f.Var(&x.unset, "unset", "remove the custom field NAME (repeatable)")
	f.BoolVar(&x.generate, "generate", false, "set the password to a freshly generated one")
	f.IntVar(&x.length, "length", 24, "length of a generated password")
	f.BoolVar(&x.noSym, "no-symbols", false, "generated password: leave out symbols")
	f.BoolVar(&x.noDig, "no-digits", false, "generated password: leave out digits")
	f.BoolVar(&x.noUp, "no-upper", false, "generated password: leave out upper-case letters")
	f.BoolVar(&x.noLow, "no-lower", false, "generated password: leave out lower-case letters")
	f.BoolVar(&x.noAmb, "exclude-ambiguous", false, "generated password: leave out look-alike characters")
	f.BoolVar(&x.showPw, "show", false, "print the generated password once")
	f.BoolVar(&x.promptPw, "password-prompt", false, "ask for the item password on the terminal (no echo)")
	f.StringVar(&x.vault, "vault", "", "vault (name, ID or unique ID prefix)")
}

func splitKV(kv string) (string, string, error) {
	i := strings.IndexByte(kv, '=')
	if i <= 0 {
		return "", "", usagef("expected NAME=VALUE, got %q", kv)
	}
	return kv[:i], kv[i+1:], nil
}

// itemPassword decides the new item password: generated, from
// FVAULT_ITEM_PASSWORD, or typed. ok=false means "leave unchanged / empty".
func (a *app) itemPassword(x *itemFlags, interactiveDefault bool) (pw string, ok bool, err error) {
	switch {
	case x.generate:
		pw, err = vaultcrypto.GeneratePassword(x.length, generatorOptions(x.noSym, x.noDig, x.noUp, x.noLow, x.noAmb)...)
		if err != nil {
			return "", false, usagef("%v", err)
		}
		return pw, true, nil
	case os.Getenv("FVAULT_ITEM_PASSWORD") != "" && !x.promptPw:
		return os.Getenv("FVAULT_ITEM_PASSWORD"), true, nil
	case x.promptPw || (interactiveDefault && a.canPrompt()):
		pw, err = a.secret("Item password (empty for none): ", "FVAULT_ITEM_PASSWORD", true, nil)
		if err != nil {
			return "", false, err
		}
		return pw, pw != "", nil
	}
	return "", false, nil
}

func applyFields(it *vaultcrypto.Item, x *itemFlags, f *cmdFlags) error {
	if f.wasSet("name") {
		it.Name = x.name
	}
	if f.wasSet("username") {
		it.Username = x.username
	}
	if f.wasSet("notes") {
		it.Notes = x.notes
	}
	if f.wasSet("url") {
		it.URLs = nil
		for _, u := range x.urls {
			if u != "" {
				it.URLs = append(it.URLs, u)
			}
		}
	}
	setField := func(list repeated, hidden bool) error {
		for _, kv := range list {
			k, v, err := splitKV(kv)
			if err != nil {
				return err
			}
			found := false
			for i := range it.Fields {
				if strings.EqualFold(it.Fields[i].Name, k) {
					it.Fields[i].Value, it.Fields[i].Hidden, found = v, hidden, true
				}
			}
			if !found {
				it.Fields = append(it.Fields, vaultcrypto.CustomField{Name: k, Value: v, Hidden: hidden})
			}
		}
		return nil
	}
	if err := setField(x.set, false); err != nil {
		return err
	}
	if err := setField(x.setHidden, true); err != nil {
		return err
	}
	for _, k := range x.unset {
		var keep []vaultcrypto.CustomField
		for _, c := range it.Fields {
			if !strings.EqualFold(c.Name, k) {
				keep = append(keep, c)
			}
		}
		it.Fields = keep
	}
	return nil
}

func cmdAdd(a *app, args []string) error {
	f := a.flags("add", "add --name NAME [--vault V] [--username U] [--url URL]... [--notes TEXT] [--generate [--length N]] [--type login|note]", `
Save a new item (default vault: your personal vault). The password comes from
--generate (a random one), from FVAULT_ITEM_PASSWORD, or is typed at a prompt
when you have a terminal; it is never taken from an argument, so it stays out
of your shell history. A generated password is not printed unless you pass
--show; read it later with `+"`fvault get NAME --show`"+`.

Examples:
  fvault add --name "Example Bank" --username me@example.com --generate
  fvault add --name "Wi-Fi" --url https://router.local     (asks for the password)
  fvault add --name "Safe code" --type note --notes "1234 under the stairs"
  fvault add --vault Family --name "Netflix" --generate --length 32`).auth()
	var x itemFlags
	x.register(f, true)
	f.StringVar(&x.typ, "type", "login", "item type: login or note")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if x.name == "" {
		return usagef("add: --name is required")
	}
	if x.typ != vaultcrypto.ItemTypeLogin && x.typ != vaultcrypto.ItemTypeNote {
		return usagef("add: --type must be login or note")
	}
	s, err := a.openSession()
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := s.WriteBlocked(); err != nil { // before asking for a password that could not be saved
		return err
	}
	vid, err := a.targetVault(s, x.vault)
	if err != nil {
		return err
	}
	it := &vaultcrypto.Item{V: 1, Type: x.typ}
	if err := applyFields(it, &x, f); err != nil {
		return err
	}
	if x.typ == vaultcrypto.ItemTypeLogin {
		pw, ok, err := a.itemPassword(&x, true)
		if err != nil {
			return err
		}
		if ok {
			it.Password = pw
			if x.generate && x.showPw {
				defer fmt.Fprintln(a.stdout, "generated password:", pw)
			}
		}
	}
	id, err := s.CreateItem(a.ctx, vid, it)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "added %q (%s) to %s\n", it.Name, short(id), s.Vault(vid).Name)
	if x.generate && !x.showPw {
		fmt.Fprintf(a.stdout, "A password was generated. To see it:  fvault get %q --show\n                           to copy it: fvault get %q --copy\n", it.Name, it.Name)
	}
	return nil
}

// targetVault picks the vault to write to: the named one, or the personal vault.
func (a *app) targetVault(s *client.Session, ref string) (string, error) {
	if ref != "" {
		v, err := s.ResolveVault(ref)
		if err != nil {
			return "", err
		}
		return v.ID, nil
	}
	for _, v := range s.Vaults() {
		if v.Personal {
			return v.ID, nil
		}
	}
	return "", errors.New("you have no personal vault; pass --vault")
}

func cmdEdit(a *app, args []string) error {
	f := a.flags("edit", "edit ITEM [--vault V] [--name N] [--username U] [--url URL]... [--notes TEXT] [--generate] [--set NAME=VALUE] [--unset NAME]", `
Change an item. Only the fields you pass are changed; unknown fields written
by other clients are kept, and an old password is moved to the history. If the
item was changed elsewhere in the meantime nothing is overwritten and the
exit code is 3. The new password comes from --generate, FVAULT_ITEM_PASSWORD
or --password-prompt.`).auth()
	var x itemFlags
	x.register(f, false)
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	r, err := s.ResolveItem(x.vault, pos[0])
	if err != nil {
		return err
	}
	pw, hasPw, err := a.itemPassword(&x, false)
	if err != nil {
		return err
	}
	var ferr error
	changed := hasPw
	for _, n := range []string{"name", "username", "notes", "url"} {
		changed = changed || f.wasSet(n)
	}
	changed = changed || len(x.set)+len(x.setHidden)+len(x.unset) > 0
	if !changed {
		return usagef("edit: nothing to change (give at least one field flag)")
	}
	err = s.UpdateItem(a.ctx, r.Vault.ID, r.Item.ID, func(it *vaultcrypto.Item) {
		ferr = applyFields(it, &x, f)
		if hasPw {
			it.Password = pw
		}
	})
	if ferr != nil {
		return ferr
	}
	if err != nil {
		return err
	}
	name := "item"
	if r.Item.Item != nil {
		name = r.Item.Item.Name
	}
	if f.wasSet("name") {
		name = x.name
	}
	fmt.Fprintf(a.stdout, "updated %q (%s)\n", name, short(r.Item.ID))
	if hasPw && x.generate && x.showPw {
		fmt.Fprintln(a.stdout, "generated password:", pw)
	}
	return nil
}

func cmdRm(a *app, args []string) error {
	f := a.flags("rm", "rm ITEM [--vault V] [--yes]", `
Delete an item, for everyone who can open its vault. This cannot be undone
(the only way back is an export file you made earlier, see `+"`fvault export`"+`).
You are asked to confirm; --yes skips the question for scripts.`).auth().confirm()
	var vref string
	f.StringVar(&vref, "vault", "", "look only in this vault")
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	r, err := s.ResolveItem(vref, pos[0])
	if err != nil {
		return err
	}
	name := "(unreadable)"
	if r.Item.Item != nil {
		name = r.Item.Item.Name
	}
	if err := s.WriteBlocked(); err != nil {
		return err
	}
	if err := a.mustConfirm(f.yes, fmt.Sprintf("Delete %q from vault %q for everyone who can open it? This cannot be undone.", name, r.Vault.Name), "not deleted"); err != nil {
		return err
	}
	if err := s.DeleteItem(a.ctx, r.Vault.ID, r.Item.ID); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "deleted %q\n", name)
	return nil
}

func cmdHistory(a *app, args []string) error {
	f := a.flags("history", "history ITEM [--vault V] [--show] [--json]", `
List the earlier passwords of an item, newest first, with the date each was
replaced. They are masked unless --show is given.`).auth().json()
	var vref string
	var show bool
	f.StringVar(&vref, "vault", "", "look only in this vault")
	f.BoolVar(&show, "show", false, "reveal the old passwords")
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	r, err := s.ResolveItem(vref, pos[0])
	if err != nil {
		return err
	}
	it := r.Item.Item
	if it == nil {
		return fmt.Errorf("item %s is unreadable", short(r.Item.ID))
	}
	type row struct {
		ChangedAt string  `json:"changed_at"`
		Password  *string `json:"password"`
	}
	rows := []row{}
	for _, h := range it.PasswordHistory {
		x := row{ChangedAt: ts(h.ChangedAt)}
		if show {
			p := h.Password
			x.Password = &p
		}
		rows = append(rows, x)
	}
	if f.asJSON {
		return a.printJSON(map[string]any{"id": r.Item.ID, "name": it.Name, "version": r.Item.Version, "updated_at": ts(r.Item.UpdatedAt), "history": rows})
	}
	fmt.Fprintf(a.stdout, "%s: updated %s, %d earlier password(s)\n", it.Name, shortTS(r.Item.UpdatedAt), len(rows))
	if len(rows) > 0 && !show {
		fmt.Fprintln(a.stdout, "(add --show to see them)")
	}
	for _, x := range rows {
		p := maskedSecret
		if x.Password != nil {
			p = *x.Password
		}
		fmt.Fprintf(a.stdout, "  replaced %s  %s\n", shortTSStr(x.ChangedAt), p)
	}
	return nil
}

// reportConflict explains a ConflictError without printing any secret value.
func (a *app) reportConflict(ce *client.ConflictError) {
	fmt.Fprintln(a.stderr, "fvault: conflict: "+ce.Error())
	if ce.Theirs != nil && ce.Theirs.Item != nil {
		fmt.Fprintf(a.stderr, "  the stored version is %d, updated %s by user %s\n", ce.Theirs.Version, shortTS(ce.Theirs.UpdatedAt), short(ce.Theirs.UpdatedBy))
		if ce.Mine != nil && ce.Mine.Item != nil {
			if d := differingFields(ce.Mine.Item, ce.Theirs.Item); len(d) > 0 {
				fmt.Fprintf(a.stderr, "  fields that differ from your attempt: %s\n", strings.Join(d, ", "))
			}
		}
	}
	fmt.Fprintln(a.stderr, "  nothing was overwritten; look at the item as it is now with `fvault get`, and repeat your change if it still applies")
}

func differingFields(mine, theirs *vaultcrypto.Item) []string {
	var d []string
	chk := func(name string, a, b string) {
		if a != b {
			d = append(d, name)
		}
	}
	chk("name", mine.Name, theirs.Name)
	chk("username", mine.Username, theirs.Username)
	chk("password", mine.Password, theirs.Password)
	chk("url", strings.Join(mine.URLs, "\n"), strings.Join(theirs.URLs, "\n"))
	chk("notes", mine.Notes, theirs.Notes)
	chk("totp", mine.TOTP, theirs.TOTP)
	if fmt.Sprint(mine.Fields) != fmt.Sprint(theirs.Fields) {
		d = append(d, "custom fields")
	}
	return d
}
