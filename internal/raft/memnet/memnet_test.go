package memnet

import (
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
)

type sink struct {
	mu  sync.Mutex
	got []raft.Message
}

func (s *sink) handle(m raft.Message) {
	s.mu.Lock()
	s.got = append(s.got, m)
	s.mu.Unlock()
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *sink) indexes() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []uint64
	for _, m := range s.got {
		out = append(out, m.Index)
	}
	return out
}

func setup(t *testing.T, ids ...string) (*Network, map[string]*Endpoint, map[string]*sink) {
	t.Helper()
	n := New(1)
	t.Cleanup(n.Close)
	eps, sinks := map[string]*Endpoint{}, map[string]*sink{}
	for _, id := range ids {
		eps[id] = n.Join(id)
		sinks[id] = &sink{}
		eps[id].SetHandler(sinks[id].handle)
	}
	return n, eps, sinks
}

func send(e *Endpoint, from, to string, idx uint64) {
	e.Send([]raft.Message{{Type: raft.MsgApp, From: from, To: to, Index: idx}})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func settle() { time.Sleep(30 * time.Millisecond) }

func TestDeliveryInOrderWithoutFaults(t *testing.T) {
	_, eps, sinks := setup(t, "a", "b")
	for i := uint64(1); i <= 100; i++ {
		send(eps["a"], "a", "b", i)
	}
	eventually(t, "delivery", func() bool { return sinks["b"].count() == 100 })
	for i, idx := range sinks["b"].indexes() {
		if idx != uint64(i+1) {
			t.Fatalf("reordered without faults: %v", sinks["b"].indexes())
		}
	}
}

func TestMessagesAreCopied(t *testing.T) {
	_, eps, sinks := setup(t, "a", "b")
	data := []byte("hello")
	ents := []raft.Entry{{Index: 1, Data: data}}
	eps["a"].Send([]raft.Message{{From: "a", To: "b", Entries: ents, Data: data}})
	data[0] = 'X'
	eventually(t, "delivery", func() bool { return sinks["b"].count() == 1 })
	m := sinks["b"].got[0]
	if string(m.Data) != "hello" || string(m.Entries[0].Data) != "hello" {
		t.Fatalf("message aliases sender memory: %q %q", m.Data, m.Entries[0].Data)
	}
}

func TestPartitionsCutsIsolationHeal(t *testing.T) {
	n, eps, sinks := setup(t, "a", "b", "c")
	n.Partition([]string{"a"}, []string{"b", "c"})
	send(eps["a"], "a", "b", 1)
	send(eps["b"], "b", "a", 2)
	send(eps["b"], "b", "c", 3)
	settle()
	if sinks["a"].count() != 0 || sinks["b"].count() != 0 || sinks["c"].count() != 1 {
		t.Fatalf("partition: a=%d b=%d c=%d", sinks["a"].count(), sinks["b"].count(), sinks["c"].count())
	}
	n.Heal()
	n.Cut("a", "c") // one way
	send(eps["a"], "a", "c", 4)
	send(eps["c"], "c", "a", 5)
	settle()
	if sinks["c"].count() != 1 || sinks["a"].count() != 1 {
		t.Fatalf("one-way cut: a=%d c=%d", sinks["a"].count(), sinks["c"].count())
	}
	n.Uncut("a", "c")
	n.Isolate("b")
	send(eps["a"], "a", "b", 6)
	send(eps["b"], "b", "c", 7)
	send(eps["a"], "a", "c", 8)
	settle()
	if sinks["b"].count() != 0 || sinks["c"].count() != 2 {
		t.Fatalf("isolate: b=%d c=%d", sinks["b"].count(), sinks["c"].count())
	}
	n.Heal()
	send(eps["a"], "a", "b", 9)
	eventually(t, "delivery after heal", func() bool { return sinks["b"].count() == 1 })
}

func TestPartitionEatsInFlightMessages(t *testing.T) {
	n, eps, sinks := setup(t, "a", "b")
	n.SetDelay(50*time.Millisecond, 50*time.Millisecond)
	send(eps["a"], "a", "b", 1)
	n.Isolate("b")
	time.Sleep(100 * time.Millisecond)
	if sinks["b"].count() != 0 {
		t.Fatal("message in flight crossed a partition created after it was sent")
	}
}

func TestDropDuplicateDelayReorder(t *testing.T) {
	n, eps, sinks := setup(t, "a", "b")
	n.SetDropRate(1)
	send(eps["a"], "a", "b", 1)
	settle()
	if sinks["b"].count() != 0 {
		t.Fatal("drop rate 1 delivered")
	}
	n.SetDropRate(0)
	n.SetDuplicateRate(1)
	send(eps["a"], "a", "b", 2)
	eventually(t, "duplicates", func() bool { return sinks["b"].count() == 2 })
	n.SetDuplicateRate(0)

	n.SetDelay(40*time.Millisecond, 40*time.Millisecond)
	t0 := time.Now()
	send(eps["a"], "a", "b", 3)
	eventually(t, "delayed delivery", func() bool { return sinks["b"].count() == 3 })
	if d := time.Since(t0); d < 35*time.Millisecond {
		t.Fatalf("delivered after %v, want >= 40ms", d)
	}
	n.SetDelay(0, 0)
	n.SetReorder(0.5, 30*time.Millisecond)
	for i := uint64(10); i < 60; i++ {
		send(eps["a"], "a", "b", i)
	}
	eventually(t, "reordered delivery", func() bool { return sinks["b"].count() == 53 })
	idx := sinks["b"].indexes()[3:]
	sorted := true
	for i := 1; i < len(idx); i++ {
		if idx[i] < idx[i-1] {
			sorted = false
		}
	}
	if sorted {
		t.Fatal("SetReorder did not reorder anything")
	}
}

func TestDisconnectReconnectAndRejoin(t *testing.T) {
	n, eps, sinks := setup(t, "a", "b")
	n.SetDelay(30*time.Millisecond, 30*time.Millisecond)
	send(eps["a"], "a", "b", 1)
	n.Disconnect("b") // purges the message queued for b
	n.Reconnect("b")
	time.Sleep(60 * time.Millisecond)
	if sinks["b"].count() != 0 {
		t.Fatal("message queued before Disconnect was delivered")
	}
	n.SetDelay(0, 0)
	n.Disconnect("a")
	send(eps["a"], "a", "b", 2)
	settle()
	if sinks["b"].count() != 0 {
		t.Fatal("disconnected node could send")
	}
	n.Reconnect("a")
	// Rejoining replaces the endpoint; the old one is closed.
	b2 := n.Join("b")
	s2 := &sink{}
	b2.SetHandler(s2.handle)
	send(eps["a"], "a", "b", 3)
	eventually(t, "delivery to the new endpoint", func() bool { return s2.count() == 1 })
	if sinks["b"].count() != 0 {
		t.Fatal("old endpoint still receives")
	}
	eps["b"].Send([]raft.Message{{From: "b", To: "a"}})
	settle()
	if sinks["a"].count() != 0 {
		t.Fatal("closed endpoint could send")
	}
}

func TestConcurrentUse(t *testing.T) {
	n, eps, sinks := setup(t, "a", "b", "c")
	n.SetDelay(0, time.Millisecond)
	var wg sync.WaitGroup
	for _, from := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func(from string) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				for _, to := range []string{"a", "b", "c"} {
					if to != from {
						send(eps[from], from, to, uint64(i))
					}
				}
			}
		}(from)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			n.Isolate("a")
			n.SetDropRate(0.1)
			n.Heal()
			n.SetDropRate(0)
		}
	}()
	wg.Wait()
	settle()
	if sinks["b"].count() == 0 {
		t.Fatal("nothing delivered")
	}
}
