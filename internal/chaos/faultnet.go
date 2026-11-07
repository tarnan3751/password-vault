package chaos

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// LinkFault describes what happens to traffic on one directed link
// (from -> to). The zero value is a healthy link.
type LinkFault struct {
	// Cut drops everything (in-process) or closes and refuses connections
	// (TCP forwarders).
	Cut bool `json:"cut,omitempty"`
	// Blackhole accepts traffic and stalls it (TCP forwarders); in-process
	// it behaves like Cut, since there is no connection to stall.
	Blackhole bool `json:"blackhole,omitempty"`
	// Drop is the probability that a message is lost (in-process), or that
	// a forwarded chunk resets its TCP connection (forwarders).
	Drop float64 `json:"drop,omitempty"`
	// Dup is the probability that a message is delivered twice
	// (in-process only).
	Dup float64 `json:"dup,omitempty"`
	// Each message (or forwarded chunk) is delayed by a uniformly random
	// duration in [DelayMin, DelayMax].
	DelayMin time.Duration `json:"delay_min,omitempty"`
	DelayMax time.Duration `json:"delay_max,omitempty"`
}

// Blocked reports whether no traffic passes at all.
func (f LinkFault) Blocked() bool { return f.Cut || f.Blackhole }

// delay draws one message's delay from rng (0 on a link without delay).
func (f LinkFault) delay(rng *rand.Rand) time.Duration {
	if f.DelayMax <= 0 {
		return 0
	}
	lo, hi := min(f.DelayMin, f.DelayMax), max(f.DelayMin, f.DelayMax)
	if hi == lo {
		return lo
	}
	return lo + time.Duration(rng.Int64N(int64(hi-lo)+1))
}

// IsZero reports a healthy link.
func (f LinkFault) IsZero() bool { return f == LinkFault{} }

type link struct{ from, to string }

// FaultNetStats counts what the decorators did, so tests (and the run
// summary) can see that the faults actually bit.
type FaultNetStats struct {
	Sent, CutOnSend, CutOnReceive, Dropped, Duplicated, Delayed, CutAfterDelay uint64
	// Snapshots counts MsgSnap messages handed to the real transport: a
	// follower that fell behind the leader's compacted log is caught up by
	// InstallSnapshot.
	Snapshots uint64
}

// FaultNet is the shared, directed fault table of an in-process cluster.
// Every node's transport is wrapped in a FaultTransport that consults it on
// the SEND side (when the raft core hands a message over) and again on the
// RECEIVE side (when the real HTTP transport delivers a batch). Checking
// both ends is what makes a partition cut traffic that is already in
// flight: a batch POSTed just before the cut is still discarded when it
// arrives, exactly as a real network partition would lose it.
type FaultNet struct {
	mu    sync.RWMutex
	links map[link]LinkFault

	rngMu sync.Mutex
	rng   *rand.Rand

	sent, cutSend, cutRecv, dropped, duplicated, delayed, cutAfterDelay, snaps atomic.Uint64
}

// NewFaultNet returns a table with every link healthy. All randomness
// (loss, duplication, delays) comes from seed.
func NewFaultNet(seed int64) *FaultNet {
	return &FaultNet{
		links: map[link]LinkFault{},
		rng:   rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x5eed5eed)),
	}
}

// Set installs f on from -> to (the zero value heals the link).
func (n *FaultNet) Set(from, to string, f LinkFault) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if f.IsZero() {
		delete(n.links, link{from, to})
		return
	}
	n.links[link{from, to}] = f
}

// Get returns the fault on from -> to.
func (n *FaultNet) Get(from, to string) LinkFault {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.links[link{from, to}]
}

// Heal removes every fault.
func (n *FaultNet) Heal() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.links = map[link]LinkFault{}
}

// Stats returns cumulative counters.
func (n *FaultNet) Stats() FaultNetStats {
	return FaultNetStats{
		Sent: n.sent.Load(), CutOnSend: n.cutSend.Load(), CutOnReceive: n.cutRecv.Load(),
		Dropped: n.dropped.Load(), Duplicated: n.duplicated.Load(), Delayed: n.delayed.Load(),
		CutAfterDelay: n.cutAfterDelay.Load(), Snapshots: n.snaps.Load(),
	}
}

func (n *FaultNet) chance(p float64) bool {
	if p <= 0 {
		return false
	}
	n.rngMu.Lock()
	defer n.rngMu.Unlock()
	return n.rng.Float64() < p
}

func (n *FaultNet) delay(f LinkFault) time.Duration {
	if f.DelayMax <= 0 {
		return 0 // the common case takes no lock
	}
	n.rngMu.Lock()
	defer n.rngMu.Unlock()
	return f.delay(n.rng)
}

// Wrap decorates the transport of node id.
func (n *FaultNet) Wrap(id string, inner raft.Transport) *FaultTransport {
	return &FaultTransport{id: id, inner: inner, net: n}
}

// FaultTransport is a raft.Transport decorator that applies the FaultNet's
// faults to everything node id sends and receives.
type FaultTransport struct {
	id     string
	inner  raft.Transport
	net    *FaultNet
	closed atomic.Bool
}

var _ raft.Transport = (*FaultTransport)(nil)

// Send implements raft.Transport. Loss, duplication and delay are applied
// here, once per message; cuts are applied here and again on receipt.
func (t *FaultTransport) Send(msgs []raft.Message) {
	if t.closed.Load() {
		return
	}
	now := make([]raft.Message, 0, len(msgs))
	for _, m := range msgs {
		f := t.net.Get(t.id, m.To)
		if f.Blocked() {
			t.net.cutSend.Add(1)
			continue
		}
		if t.net.chance(f.Drop) {
			t.net.dropped.Add(1)
			continue
		}
		copies := 1
		if t.net.chance(f.Dup) {
			copies = 2
			t.net.duplicated.Add(1)
		}
		for range copies {
			d := t.net.delay(f)
			if d <= 0 {
				if m.Type == raft.MsgSnap {
					t.net.snaps.Add(1)
				}
				now = append(now, m)
				continue
			}
			// The delayed copy is deep-copied: the core may legitimately
			// reuse buffers once Send has returned, and a real network
			// would have serialized the message by now anyway.
			mc := cloneMessage(m)
			t.net.delayed.Add(1)
			time.AfterFunc(d, func() {
				if t.closed.Load() {
					return
				}
				// A partition installed while the message was "on the
				// wire" still eats it.
				if t.net.Get(t.id, mc.To).Blocked() {
					t.net.cutAfterDelay.Add(1)
					return
				}
				t.net.sent.Add(1)
				if mc.Type == raft.MsgSnap {
					t.net.snaps.Add(1)
				}
				t.inner.Send([]raft.Message{mc})
			})
		}
	}
	if len(now) > 0 {
		t.net.sent.Add(uint64(len(now)))
		t.inner.Send(now)
	}
}

// SetHandler implements raft.Transport: inbound messages from a peer whose
// link to us is cut are discarded before the core sees them.
func (t *FaultTransport) SetHandler(h func(raft.Message)) {
	if h == nil {
		t.inner.SetHandler(nil)
		return
	}
	t.inner.SetHandler(func(m raft.Message) {
		if t.closed.Load() {
			return
		}
		if t.net.Get(m.From, t.id).Blocked() {
			t.net.cutRecv.Add(1)
			return
		}
		h(m)
	})
}

// Close implements raft.Transport.
func (t *FaultTransport) Close() error {
	t.closed.Store(true)
	return t.inner.Close()
}

func cloneMessage(m raft.Message) raft.Message {
	c := m
	if m.Entries != nil {
		c.Entries = make([]raft.Entry, len(m.Entries))
		for i, e := range m.Entries {
			e.Data = append([]byte(nil), e.Data...)
			c.Entries[i] = e
		}
	}
	if m.Snap != nil {
		s := *m.Snap
		s.Data = append([]byte(nil), s.Data...)
		c.Snap = &s
	}
	if m.Data != nil {
		c.Data = append([]byte(nil), m.Data...)
	}
	return c
}
