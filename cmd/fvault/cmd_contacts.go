package main

import (
	"errors"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/client"
)

func cmdFingerprint(a *app, args []string) error {
	f := a.flags("fingerprint", "fingerprint [USER]", `
Show fingerprints. A fingerprint is a short code that identifies a person's
key (32 hex characters in 8 groups; it also covers their user ID and
username). Without USER it lists yours and everyone else's.

Before you trust someone, compare their fingerprint with them in person or on
a phone call, not through this app (then run `+"`fvault contacts verify USER`"+`).
That check is what protects you if a server is ever tampered with. Read your
own fingerprint out to the people you share with.

Example:
  fvault fingerprint bob`).auth().json()
	pos, s, err := f.open(args, 0, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	dir := s.Directory()
	if len(pos) == 1 {
		u, err := s.ResolveUser(pos[0])
		if err != nil {
			return err
		}
		dir = []client.UserInfo{*u}
	}
	return a.printContacts(s, dir, f.asJSON)
}

func (a *app) printContacts(s *client.Session, dir []client.UserInfo, asJSON bool) error {
	if asJSON {
		type row struct {
			Username    string `json:"username"`
			UserID      string `json:"user_id"`
			Fingerprint string `json:"fingerprint"`
			Verified    bool   `json:"verified"`
			Self        bool   `json:"self,omitempty"`
			KeyChanged  bool   `json:"key_changed,omitempty"`
			Admin       bool   `json:"admin"`
			Disabled    bool   `json:"disabled"`
		}
		rows := []row{}
		for _, u := range dir {
			rows = append(rows, row{u.Username, u.UserID, u.Fingerprint, u.Verified || u.Self, u.Self, u.KeyMismatch, u.IsAdmin, u.Disabled})
		}
		return a.printJSON(rows)
	}
	rows := [][]string{}
	unverified := false
	for _, u := range dir {
		v := verifiedLabel(u.Self, u.KeyMismatch, u.Verified)
		unverified = unverified || v == "no"
		rows = append(rows, []string{u.Username, u.Fingerprint, v})
	}
	a.table([]string{"USER", "FINGERPRINT", "VERIFIED"}, rows)
	if unverified {
		a.say(a.stderr, "\n"+fingerprintExplained+"\nVERIFIED \"no\" means you have not done that yet; once you have, run `fvault contacts verify USER`.")
	}
	return nil
}

func cmdContacts(a *app, args []string) error {
	if len(args) > 0 && (args[0] == "verify" || args[0] == "dismiss") {
		return a.group("contacts", []command{
			{"verify", "mark a contact verified after comparing fingerprints", contactsVerify},
			{"dismiss", "acknowledge recorded key-mismatch warnings of a user", contactsDismiss},
		}, args)
	}
	f := a.flags("contacts", "contacts [--json]  |  contacts verify USER [--fingerprint FP]  |  contacts dismiss USER", `
List the household members with their fingerprints and whether you verified
them on this device. A fingerprint is a short code that identifies a person's
key; "verified" means you compared it with them in person or on a phone call.
You can only share vaults with verified people, and only their shares are
accepted without a question.

Examples:
  fvault contacts
  fvault contacts verify bob`).auth().json()
	_, s, err := f.open(args, 0, 0)
	if err != nil {
		return err
	}
	defer a.release(s)
	return a.printContacts(s, s.Directory(), f.asJSON)
}

func contactsVerify(a *app, args []string) error {
	f := a.flags("contacts verify", "contacts verify USER [--fingerprint FP]", `
Show USER's fingerprint and ask whether you compared it with them in person
or on a phone call (not through this app) and it matches. Answering yes marks
them verified on this device; you only have to do this once per person.

For scripts: --fingerprint FP must equal the fingerprint shown on this device.

Example:
  fvault contacts verify bob`).auth()
	var fp string
	f.StringVar(&fp, "fingerprint", "", "the fingerprint USER told you; verifies if it matches")
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	u, err := s.ResolveUser(pos[0])
	if err != nil {
		return err
	}
	if u.Self {
		return errors.New("that is you")
	}
	if u.Verified && fp == "" {
		fmt.Fprintf(a.stdout, "%s is already verified (%s)\n", u.Username, u.Fingerprint)
		return nil
	}
	u.Verified = false
	if err := a.ensureVerified(s, *u, fp, "Verifying a contact."); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%s is now a verified contact (%s); you can share vaults with them\n", u.Username, u.Fingerprint)
	return nil
}

func contactsDismiss(a *app, args []string) error {
	f := a.flags("contacts dismiss", "contacts dismiss USER", `
Hide the recorded warnings that USER's key looked different from before, so
they stop being shown. This does NOT trust the new key: the key this device
recorded for USER never changes, and nothing is shared with or accepted from
the different key.`).auth()
	pos, s, err := f.open(args, 1, 1)
	if err != nil {
		return err
	}
	defer a.release(s)
	u, err := s.ResolveUser(pos[0])
	if err != nil {
		return err
	}
	n, err := s.DismissWarnings(u.UserID)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "dismissed %d warning(s) about %s\n", n, u.Username)
	return nil
}
