package client

import (
	"errors"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
)

func TestFailoverAndOffline(t *testing.T) {
	cl := clienttest.New(t, 3)
	d := newDevice(t, cl)
	s := d.register("alice", pwAlice, clienttest.BootstrapToken)
	if got := len(d.api.Nodes()); got != 3 {
		t.Fatalf("learned %d nodes, want 3", got)
	}
	cfg := mv(d.store.LoadConfig())
	if len(cfg.Servers) != 3 {
		t.Fatalf("persisted nodes: %v", cfg.Servers)
	}
	pv := personalVault(t, s)
	mv(s.CreateItem(bg, pv.ID, loginItem("before")))

	cl.Stop(0)
	id2 := mv(s.CreateItem(bg, pv.ID, loginItem("one node down")))
	must(t, s.Sync(bg))
	if s.Mode() != ModeOnline {
		t.Fatalf("mode %v with 2/3 nodes", s.Mode())
	}
	_ = s.item(t, pv.ID, id2)
	if node, _ := d.api.LastServed(); node == cl.Nodes[0].URL {
		t.Fatal("served by the dead node?")
	}
	d2 := d.fresh(cl, withNodes(cl.URLs()...))
	d2.login("alice", pwAlice)

	cl.Stop(1)
	_, err := s.CreateItem(bg, pv.ID, loginItem("no quorum"))
	if err == nil || !IsUnavailable(err) {
		t.Fatalf("write without quorum: %v", err)
	}
	if !IsCode(err, api.CodeUnavailable) && !IsCode(err, api.CodeOutcomeUnknown) && !OutcomeUnknown(err) {
		t.Fatalf("want unavailable/outcome_unknown, got %T %v", err, err)
	}
	mode, err := s.Refresh(bg)
	must(t, err)
	if mode != ModeStale {
		t.Fatalf("mode %v, want stale", mode)
	}
	if _, stale := d.api.LastServed(); !stale {
		t.Fatal("LastServed does not report stale")
	}
	if len(s.Vault(pv.ID).Items) != 2 {
		t.Fatalf("stale view has %d items", len(s.Vault(pv.ID).Items))
	}
	var ro *ReadOnlyError
	if _, err := s.CreateItem(bg, pv.ID, loginItem("stale write")); !errors.As(err, &ro) || ro.Reason != ReasonStale {
		t.Fatalf("stale write: %v", err)
	}
	op := mv(Open(bg, d.deps, "alice", pwAlice))
	if op.Mode() != ModeStale || op.Notice() == "" {
		t.Fatalf("Open under no quorum: mode=%v notice=%q", op.Mode(), op.Notice())
	}

	cl.Stop(2)
	mode, err = s.Refresh(bg)
	must(t, err)
	if mode != ModeOffline {
		t.Fatalf("mode %v, want offline", mode)
	}
	off := mv(Open(bg, d.deps, "alice", pwAlice))
	if off.Mode() != ModeOffline || len(off.Vault(pv.ID).Items) != 2 || off.Notice() == "" {
		t.Fatalf("offline open: mode=%v", off.Mode())
	}
	if _, err := off.CreateItem(bg, pv.ID, loginItem("offline write")); !errors.As(err, &ro) || ro.Reason != ReasonOffline {
		t.Fatalf("offline write: %v", err)
	}
	if _, err := UnlockOffline(Deps{Store: d.store}, "alice", "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("offline wrong password: %v", err)
	}

	cl.Start(0)
	cl.Start(1)
	cl.WaitReady()
	mode, err = s.Refresh(bg)
	must(t, err)
	if mode != ModeOnline {
		t.Fatalf("mode after restart: %v", mode)
	}
	mv(s.CreateItem(bg, pv.ID, loginItem("recovered")))
	if len(s.Vault(pv.ID).Items) != 3 {
		t.Fatalf("items after recovery: %d", len(s.Vault(pv.ID).Items))
	}
}
