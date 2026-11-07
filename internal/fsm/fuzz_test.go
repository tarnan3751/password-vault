package fsm

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// FuzzApply feeds arbitrary bytes to Apply on a populated state. Apply must
// never panic (the recover in apply would turn a panic into an "internal"
// result, which the fuzzer treats as a failure too), must always return a
// well-formed result, must be deterministic, and must leave a state that
// passes full snapshot validation.
func FuzzApply(f *testing.F) {
	h := richState(f)
	base, err := h.f.Snapshot()
	if err != nil {
		f.Fatal(err)
	}
	g := &cmdGen{rng: rand.New(rand.NewPCG(5, 5)), ref: h.f, now: h.now}
	var hist [][]byte
	for i := 0; i < 64; i++ {
		c := g.next(hist)
		hist = append(hist, c)
		f.Add(c)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"op":"rekey","req_id":"00000000000000000000000000000001","now":1,"uid":"","ep":0,"args":{"wrapped_keys":{"x":{}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		m := New()
		if err := m.Restore(base); err != nil {
			t.Fatal(err)
		}
		res := m.Apply(1, data)
		r, err := DecodeResult(res)
		if err != nil {
			t.Fatalf("malformed result %q: %v", res, err)
		}
		if r.Err != nil && r.Err.Code == "internal" {
			t.Fatalf("Apply hit the panic guard for %q", data)
		}
		snap, err := m.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateSnapshot(snap); err != nil {
			t.Fatalf("Apply produced an invalid state: %v", err)
		}
		checkCounters(t, m)
		m2 := New()
		_ = m2.Restore(base)
		if res2 := m2.Apply(7, data); !bytes.Equal(res, res2) || m2.StateHash() != m.StateHash() {
			t.Fatal("Apply is not deterministic")
		}
	})
}

// FuzzRestore feeds arbitrary bytes to Restore: it must never panic, must
// leave the state untouched on error, and anything it accepts must
// round-trip canonically.
func FuzzRestore(f *testing.F) {
	h := richState(f)
	base, _ := h.f.Snapshot()
	empty, _ := New().Snapshot()
	backup, _, _ := h.f.BackupSnapshot()
	f.Add(base)
	f.Add(empty)
	f.Add(backup)
	f.Add([]byte(`{"format":"fpv-state","version":1,"rev":0,"users":null,"invites":[],"vaults":[],"idempotency":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		checkDecoder(t, data, false)
		m := New()
		if err := m.Restore(base); err != nil {
			t.Fatal(err)
		}
		before := m.StateHash()
		if err := m.Restore(data); err != nil {
			if m.StateHash() != before {
				t.Fatal("failed Restore changed the state")
			}
			return
		}
		s1, err := m.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		m2 := New()
		if err := m2.Restore(s1); err != nil {
			t.Fatalf("re-restore of an accepted snapshot failed: %v", err)
		}
		if s2, _ := m2.Snapshot(); !bytes.Equal(s1, s2) {
			t.Fatal("accepted snapshot does not round-trip canonically")
		}
		// The restored state must keep working.
		m.Apply(1, []byte(`{"op":"revoke_sessions","req_id":"0123456789abcdef0123456789abcdef","now":5,"uid":"","ep":0,"args":{}}`))
	})
}
