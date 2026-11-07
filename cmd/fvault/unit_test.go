package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/client"
)

func TestExitCodes(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, exitOK},
		{errHelp, exitOK},
		{usagef("bad"), exitUsage},
		{&client.ConflictError{Kind: "update"}, exitConflict},
		{fmt.Errorf("wrapped: %w", &client.ConflictError{Kind: "delete"}), exitConflict},
		{&client.NetworkError{Msg: "down"}, exitOffline},
		{&client.ReadOnlyError{Reason: client.ReasonOffline}, exitOffline},
		{&client.APIError{Status: 503, Code: "unavailable", Message: "no quorum"}, exitOffline},
		{&client.APIError{Status: 503, Code: "outcome_unknown", Message: "?"}, exitOffline},
		{&client.APIError{Status: 403, Code: "forbidden", Message: "no"}, exitError},
		{client.ErrWrongPassword, exitError},
		{errors.New("boom"), exitError},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		a := &app{ctx: context.Background(), stdout: &out, stderr: &errb}
		if got := a.finish(c.err); got != c.want {
			t.Errorf("%v: exit %d, want %d (stderr %q)", c.err, got, c.want, errb.String())
		}
	}
}

func TestParseInterspersed(t *testing.T) {
	a := &app{ctx: context.Background(), stdout: io.Discard, stderr: io.Discard}
	f := a.flags("t", "t X", "d")
	var show bool
	var field string
	f.BoolVar(&show, "show", false, "")
	f.StringVar(&field, "field", "", "")
	pos, err := f.parse([]string{"item", "--show", "--field", "password", "second"}, 1, 2)
	if err != nil || len(pos) != 2 || pos[0] != "item" || pos[1] != "second" || !show || field != "password" {
		t.Fatalf("pos=%v err=%v show=%v field=%q", pos, err, show, field)
	}
	f = a.flags("t", "t X", "d")
	f.BoolVar(&show, "show", false, "")
	pos, err = f.parse([]string{"--", "--show"}, 1, 1)
	if err != nil || len(pos) != 1 || pos[0] != "--show" {
		t.Fatalf("after --: pos=%v err=%v", pos, err)
	}
	f = a.flags("t", "t X", "d")
	if _, err = f.parse([]string{"--password", "hunter2"}, 0, 0); err == nil || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("a password flag must not exist: %v", err)
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("not a usage error: %T", err)
	}
	_ = flag.ErrHelp
}

func TestSplitKV(t *testing.T) {
	k, v, err := splitKV("PIN=12=34")
	if err != nil || k != "PIN" || v != "12=34" {
		t.Fatal(k, v, err)
	}
	if _, _, err := splitKV("novalue"); err == nil {
		t.Fatal("accepted")
	}
}
