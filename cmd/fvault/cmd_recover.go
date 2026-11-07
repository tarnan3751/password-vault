package main

import (
	"errors"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/client"
)

func init() {
	register(command{"recover", "accept the servers' older data after a backup restore", cmdRecover})
}

func cmdRecover(a *app, args []string) error {
	f := a.flags("recover", "recover --accept-restored-state [--i-understand]", `
Use this only after the administrator has restored the servers from a backup.
The servers then legitimately show OLDER data than this device has seen (an
earlier revision, perhaps older vault keys). fvault cannot tell that from an
attack, so it stops using the servers' answers: your offline copy stays
readable, nothing can be saved, and the message says to run this command.

Accepting makes this device forget the newest revision it had seen and the
key records of each vault, replaces the offline copy with what the servers
show, and checks every vault again as if seen for the first time: vaults whose
keys come from you or from contacts you verified open; the others are
"waiting for you to confirm the sender" again. Your contacts, the ones you
verified and the recorded key warnings are kept.

If the administrator did NOT restore a backup, do not accept: tell the
administrator, because the servers may have been tampered with. It is refused
outright when a contact's key changed, or when a vault shows a different key
than this device recorded for the same key number: a restore cannot cause
either.

You are asked to confirm. Without a terminal, --i-understand is required.

Example:
  fvault recover --accept-restored-state`).auth()
	var accept, understand bool
	f.BoolVar(&accept, "accept-restored-state", false, "required: accept the older state the servers show")
	f.BoolVar(&understand, "i-understand", false, "confirm without a terminal that the administrator restored a backup")
	if _, err := f.parse(args, 0, 0); err != nil {
		return err
	}
	if !accept {
		return usagef("recover: pass --accept-restored-state to confirm that you want to accept the servers' restored state")
	}
	st, cfg, err := a.loadAll()
	if err != nil {
		return err
	}
	if cfg.Username == "" {
		return errors.New(errNoAccount)
	}
	pw, err := a.secret("Master password for "+cfg.Username+": ", "FVAULT_PASSWORD", false, nil)
	if err != nil {
		return err
	}
	d, err := a.deps(st, cfg)
	if err != nil {
		return err
	}
	rec, err := client.BeginRecovery(a.ctx, d, cfg.Username, pw)
	if err != nil {
		return err
	}
	a.say(a.stderr, "fvault: "+rec.Info.Error())
	if ttyFile() != nil && !understand {
		if err := a.mustConfirm(false, "Did the administrator restore the servers from a backup, and do you accept the older state?", "not accepted"); err != nil {
			rec.Close()
			return err
		}
	} else if !understand {
		rec.Close()
		return errors.New("no terminal to ask for confirmation; re-run with --i-understand if the administrator restored a backup")
	}
	s, err := rec.Accept()
	if err != nil {
		return err
	}
	defer a.release(s)
	open, pending, locked := 0, 0, 0
	for _, v := range s.Vaults() {
		switch v.Locked {
		case client.NotLocked:
			open++
		case client.LockPending:
			pending++
		default:
			locked++
		}
	}
	a.afterOpen(s)
	fmt.Fprintf(a.stdout, "accepted the restored state (rev %d): %d vault(s) open, %d waiting for you to confirm the sender, %d locked\n", s.Rev(), open, pending, locked)
	return nil
}
