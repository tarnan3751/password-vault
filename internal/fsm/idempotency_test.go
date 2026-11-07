package fsm

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

func TestReplayReturnsIdenticalBytesWithoutReapplying(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	cmd := h.cmd(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(1), Blob: box(100), KeyEpoch: 1})
	first := h.f.Apply(10, cmd)
	rev := h.f.Rev()
	hash := h.f.StateHash()
	for i := 0; i < 3; i++ {
		again := h.f.Apply(uint64(11+i), cmd)
		if !bytes.Equal(first, again) {
			t.Fatalf("replay returned different bytes:\n%s\n%s", first, again)
		}
	}
	if h.f.Rev() != rev || h.f.StateHash() != hash {
		t.Fatal("replay changed state")
	}

	// A client retry re-built by a handler (new timestamp) is the same request.
	var env Command
	if err := json.Unmarshal(cmd, &env); err != nil {
		t.Fatal(err)
	}
	env.Now += 5000
	retry, _ := json.Marshal(env)
	if got := h.f.Apply(20, retry); !bytes.Equal(got, first) {
		t.Fatal("retry with a new timestamp must be de-duplicated")
	}

	// Same key, different request: refused, nothing applied, not recorded.
	env.Args, _ = json.Marshal(&PutItemArgs{VaultID: alice.personal, ItemID: itemID(2), Blob: box(100), KeyEpoch: 1})
	other, _ := json.Marshal(env)
	r, _ := DecodeResult(h.f.Apply(21, other))
	if r.Err == nil || r.Err.Code != api.CodeBadRequest || !strings.Contains(r.Err.Message, "Idempotency-Key") {
		t.Fatalf("key reuse: %+v", r)
	}
	if h.f.Rev() != rev {
		t.Fatal("key reuse applied the command")
	}
	if got := h.f.Apply(22, cmd); !bytes.Equal(got, first) {
		t.Fatal("original result lost after key reuse")
	}
}

func TestIdempotencyKeyIsPerCaller(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	req := strings.Repeat("ab", 16)
	mk := func(u *tuser, vid string) []byte {
		b, _ := EncodeCommand(req, h.now, u.id, u.ep, &CreateVaultArgs{VaultID: vid, EncRoster: box(64), EncMeta: box(64), WrappedKey: wk(u.id)})
		return b
	}
	if r, _ := DecodeResult(h.f.Apply(1, mk(alice, vaultID(1)))); r.Err != nil {
		t.Fatal(r.Err)
	}
	if r, _ := DecodeResult(h.f.Apply(2, mk(bob, vaultID(2)))); r.Err != nil {
		t.Fatalf("bob's request was confused with alice's: %v", r.Err)
	}
	if !h.visible(bob, vaultID(2)) {
		t.Fatal("bob's vault missing")
	}
}

func TestFailedCommandsAreRecorded(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	vid := h.createVault(alice, 1)
	// bob is not a member yet: not_found.
	cmd := h.cmd(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(1), Blob: box(100), KeyEpoch: 1})
	first := h.f.Apply(1, cmd)
	h.addMember(alice, vid, bob, api.RoleEditor)
	// Now it would succeed, but the retry must get the original answer.
	if again := h.f.Apply(2, cmd); !bytes.Equal(first, again) {
		t.Fatalf("retry of a failed command re-executed: %s vs %s", first, again)
	}
	if _, ok := h.item(bob, vid, itemID(1)); ok {
		t.Fatal("retry applied the command")
	}
}

func TestUnkeyableCommandsAreNotRecorded(t *testing.T) {
	h := newHarness(t)
	n := len(h.f.s.idemOrder)
	for _, c := range [][]byte{
		[]byte("not json"),
		[]byte(`{"op":"init","req_id":"short","now":1,"uid":"","ep":0,"args":{}}`),
	} {
		r, err := DecodeResult(h.f.Apply(1, c))
		if err != nil || r.Err == nil {
			t.Fatalf("expected an error result for %q", c)
		}
	}
	if len(h.f.s.idemOrder) != n {
		t.Fatal("unkeyable command was recorded")
	}
}

func TestIdempotencyEvictionFIFO(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	first := h.cmd(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(0), Blob: box(100), KeyEpoch: 1})
	firstRes := h.f.Apply(1, first)
	// Fill the table with cheap failing commands (failures are recorded).
	for i := 0; i < IdempotencyCapacity; i++ {
		h.do(alice, &DeleteVaultArgs{VaultID: alice.personal})
	}
	if len(h.f.s.idemOrder) != IdempotencyCapacity || len(h.f.s.idem) != IdempotencyCapacity {
		t.Fatalf("table size %d/%d", len(h.f.s.idemOrder), len(h.f.s.idem))
	}
	// The first command was evicted: its retry is executed again (and now
	// conflicts because the item exists).
	raw := h.f.Apply(2, first)
	again, _ := DecodeResult(raw)
	if bytes.Equal(raw, firstRes) || again.Err == nil || again.Err.Code != api.CodeVersionConflict {
		t.Fatalf("evicted command was answered from the table: %s", raw)
	}
	snapshotRoundTrip(t, h.f)
}

func TestIdempotencySurvivesSnapshot(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	cmd := h.cmd(alice, &PutItemArgs{VaultID: alice.personal, ItemID: itemID(1), Blob: box(100), KeyEpoch: 1})
	first := h.f.Apply(1, cmd)
	snap, _ := h.f.Snapshot()
	g := New()
	if err := g.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if again := g.Apply(2, cmd); !bytes.Equal(again, first) {
		t.Fatal("replay after restore differs")
	}
	if g.StateHash() != h.f.StateHash() {
		t.Fatal("replay after restore changed state")
	}
}

func TestMalformedEnvelopes(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	good := func(mut func(m map[string]any)) []byte {
		m := map[string]any{
			"op": OpRevokeSessions, "req_id": strings.Repeat("c", 32), "now": h.now,
			"uid": alice.id, "ep": alice.ep, "args": map[string]any{},
		}
		mut(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string][]byte{
		"empty":         nil,
		"array":         []byte(`[]`),
		"null":          []byte(`null`),
		"trailing":      append(good(func(map[string]any) {}), []byte(" {}")...),
		"unknown field": good(func(m map[string]any) { m["extra"] = 1 }),
		"bad req id":    good(func(m map[string]any) { m["req_id"] = "ZZ" }),
		"uppercase req": good(func(m map[string]any) { m["req_id"] = strings.Repeat("C", 32) }),
		"bad uid":       good(func(m map[string]any) { m["uid"] = "alice" }),
		"zero now":      good(func(m map[string]any) { m["now"] = 0 }),
		"negative now":  good(func(m map[string]any) { m["now"] = -5 }),
		"huge now":      good(func(m map[string]any) { m["now"] = int64(1) << 62 }),
		"float now":     good(func(m map[string]any) { m["now"] = 1.5 }),
		"unknown op":    good(func(m map[string]any) { m["op"] = "drop_tables"; m["req_id"] = strings.Repeat("d", 32) }),
		"args not obj":  good(func(m map[string]any) { m["args"] = 42; m["req_id"] = strings.Repeat("e", 32) }),
		"args extra":    good(func(m map[string]any) { m["args"] = map[string]any{"x": 1}; m["req_id"] = strings.Repeat("f", 32) }),
		"missing args":  good(func(m map[string]any) { delete(m, "args"); m["req_id"] = strings.Repeat("1", 32) }),
		"negative ep":   good(func(m map[string]any) { m["ep"] = -1 }),
		"string ep":     good(func(m map[string]any) { m["ep"] = "1" }),
		"nested garbage": good(func(m map[string]any) {
			m["op"] = OpPutItem
			m["args"] = map[string]any{"blob": "!!"}
			m["req_id"] = strings.Repeat("2", 32)
		}),
	}
	rev := h.f.Rev()
	for name, c := range cases {
		r, err := DecodeResult(h.f.Apply(1, c))
		if err != nil {
			t.Fatalf("%s: undecodable result: %v", name, err)
		}
		if r.Err == nil || r.Err.Code != api.CodeBadRequest {
			t.Fatalf("%s: expected bad_request, got %+v", name, r)
		}
	}
	if h.f.Rev() != rev {
		t.Fatal("malformed command changed state")
	}
	// A huge command is refused without parsing.
	r, _ := DecodeResult(h.f.Apply(1, make([]byte, MaxCommandBytes+1)))
	if r.Err == nil || r.Err.Code != api.CodeTooLarge {
		t.Fatalf("oversized command: %+v", r)
	}
}

func TestConcurrentReadersDuringApply(t *testing.T) {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleEditor)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				switch g % 6 {
				case 0:
					if r, ok := h.f.SyncView(bob.id, 0); ok {
						for _, v := range r.Vaults {
							for _, it := range v.Items {
								it.Blob[0] ^= 1 // must be a private copy
							}
						}
					}
				case 1:
					h.f.LookupUserByName("alice")
					h.f.LookupUserByID(bob.id)
				case 2:
					h.f.StateHash()
				case 3:
					h.f.ListInvites()
					h.f.Directory()
				case 4:
					if _, err := h.f.Snapshot(); err != nil {
						t.Error(err)
					}
				case 5:
					h.f.View(func(v *View) { v.Rev(); v.Sync(alice.id, 0); v.ClusterKey() })
				}
			}
		}(g)
	}
	for i := 0; i < 400; i++ {
		iid := itemID(i % 20)
		it, ok := h.item(bob, vid, iid)
		base := uint64(0)
		if ok {
			base = it.Version
		}
		h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: iid, Blob: box(64 + i), BaseVersion: base, KeyEpoch: 1})
		if i%50 == 0 {
			h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(1000 + i), TTLHours: 1})
		}
	}
	close(stop)
	wg.Wait()
	// Readers mutated their copies; the state must be intact.
	for i := 0; i < 20; i++ {
		it, _ := h.item(bob, vid, itemID(i))
		if it.Blob[0] != 1 {
			t.Fatalf("reader mutation leaked into state: %x", it.Blob[0])
		}
	}
}

func TestRegisterReplayBinding(t *testing.T) {
	// Anonymous registrations share the "anon" key space: a reused key with a
	// different registration must not hand out the first registrant's result.
	h := newHarness(t)
	req := strings.Repeat("9", 32)
	a := regArgs(1, "alice")
	a.Bootstrap = true
	c1, _ := EncodeCommand(req, h.now, "", 0, a)
	first := h.f.Apply(1, c1)
	// Same registration re-proposed by a handler with a fresh verifier salt
	// (client retry): de-duplicated.
	a2 := *a
	a2.Verifier = verifier(200)
	c2, _ := EncodeCommand(req, h.now+1, "", 0, &a2)
	if got := h.f.Apply(2, c2); !bytes.Equal(got, first) {
		t.Fatal("client retry of a registration was not de-duplicated")
	}
	// A different registrant with the same key is refused.
	b := regArgs(2, "mallory")
	b.Bootstrap = true
	c3, _ := EncodeCommand(req, h.now, "", 0, b)
	r, _ := DecodeResult(h.f.Apply(3, c3))
	if r.Err == nil || r.Err.Code != api.CodeBadRequest {
		t.Fatalf("key reuse by another registrant: %+v", r)
	}
}
