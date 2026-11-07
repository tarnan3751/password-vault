// Package memnet is an in-memory, fault-injecting raft.Transport network for
// tests.
//
//	net := memnet.New(seed)
//	t1 := net.Join("a") // a raft.Transport for node "a"
//
// Messages are deep-copied on send (as a real network would serialize them)
// and delivered to the destination's handler by one goroutine per endpoint,
// after a random delay. Faults can be changed at any time and apply both when
// a message is sent and when it is about to be delivered, so a partition also
// eats messages already in flight:
//
//   - Partition/Cut/Isolate/Heal: symmetric and one-way link cuts.
//   - SetDropRate, SetDuplicateRate, SetDelay, SetReorder.
//   - Disconnect/Reconnect: a node neither sends nor receives (crash
//     simulation); its pending inbound messages are discarded.
//
// All methods are safe for concurrent use.
package memnet

import (
	"bytes"
	"container/heap"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// Network connects endpoints.
type Network struct {
	mu        sync.Mutex
	rng       *rand.Rand
	endpoints map[string]*Endpoint
	cuts      map[link]bool
	isolated  map[string]bool
	down      map[string]bool

	dropRate     float64
	dupRate      float64
	reorderRate  float64
	reorderExtra time.Duration
	minDelay     time.Duration
	maxDelay     time.Duration

	closed bool
	wg     sync.WaitGroup
}

type link struct{ from, to string }

// New returns a network with no faults and no delay. All randomness (drops,
// delays, duplication) comes from seed.
func New(seed int64) *Network {
	return &Network{
		rng:       rand.New(rand.NewPCG(uint64(seed), 0x5eed)),
		endpoints: map[string]*Endpoint{},
		cuts:      map[link]bool{},
		isolated:  map[string]bool{},
		down:      map[string]bool{},
	}
}

// Join creates the endpoint for id, replacing (and closing) any previous one,
// which is how a test restarts a node with a fresh transport.
func (n *Network) Join(id string) *Endpoint {
	e := &Endpoint{net: n, id: id, wake: make(chan struct{}, 1), done: make(chan struct{})}
	n.mu.Lock()
	old := n.endpoints[id]
	n.endpoints[id] = e
	closed := n.closed
	if !closed {
		n.wg.Add(1)
	}
	n.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if closed {
		e.Close()
		return e
	}
	go e.loop()
	return e
}

// Partition cuts every link between nodes in different groups, in both
// directions. Links within a group and to unlisted nodes are left alone.
func (n *Network) Partition(groups ...[]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, g := range groups {
		for j, h := range groups {
			if i == j {
				continue
			}
			for _, a := range g {
				for _, b := range h {
					n.cuts[link{a, b}] = true
				}
			}
		}
	}
}

// Cut drops messages from -> to (one way).
func (n *Network) Cut(from, to string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cuts[link{from, to}] = true
}

// Uncut restores the link from -> to.
func (n *Network) Uncut(from, to string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.cuts, link{from, to})
}

// Isolate cuts id off from every other node in both directions.
func (n *Network) Isolate(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.isolated[id] = true
}

// Heal removes all cuts and isolations. It does not reconnect disconnected
// nodes or change drop/delay settings.
func (n *Network) Heal() {
	n.mu.Lock()
	defer n.mu.Unlock()
	clear(n.cuts)
	clear(n.isolated)
}

// Disconnect makes id unreachable and silent, and discards messages queued
// for it, as if the process had crashed.
func (n *Network) Disconnect(id string) {
	n.mu.Lock()
	n.down[id] = true
	e := n.endpoints[id]
	n.mu.Unlock()
	if e != nil {
		e.purge()
	}
}

// Reconnect undoes Disconnect.
func (n *Network) Reconnect(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.down, id)
}

// SetDropRate makes each message be dropped with probability p.
func (n *Network) SetDropRate(p float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dropRate = p
}

// SetDuplicateRate makes each message be delivered twice with probability p.
func (n *Network) SetDuplicateRate(p float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dupRate = p
}

// SetDelay delays each message by a uniformly random duration in [min, max].
// Different delays reorder messages.
func (n *Network) SetDelay(min, max time.Duration) {
	if max < min {
		max = min
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.minDelay, n.maxDelay = min, max
}

// SetReorder gives each message, with probability p, an additional random
// delay of up to extra, so that later messages overtake it.
func (n *Network) SetReorder(p float64, extra time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reorderRate, n.reorderExtra = p, extra
}

// Close shuts every endpoint down and waits for the delivery goroutines.
func (n *Network) Close() {
	n.mu.Lock()
	n.closed = true
	eps := make([]*Endpoint, 0, len(n.endpoints))
	for _, e := range n.endpoints {
		eps = append(eps, e)
	}
	n.mu.Unlock()
	for _, e := range eps {
		e.Close()
	}
	n.wg.Wait()
}

func (n *Network) blockedLocked(from, to string) bool {
	return n.down[from] || n.down[to] || n.isolated[from] || n.isolated[to] || n.cuts[link{from, to}]
}

// route decides the fate of one message: nil if dropped, else the delivery
// delays (two if duplicated).
func (n *Network) route(from, to string) (*Endpoint, []time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	dst := n.endpoints[to]
	if n.closed || dst == nil || n.blockedLocked(from, to) {
		return nil, nil
	}
	if n.dropRate > 0 && n.rng.Float64() < n.dropRate {
		return nil, nil
	}
	copies := 1
	if n.dupRate > 0 && n.rng.Float64() < n.dupRate {
		copies = 2
	}
	delays := make([]time.Duration, copies)
	for i := range delays {
		d := n.minDelay
		if n.maxDelay > n.minDelay {
			d += time.Duration(n.rng.Int64N(int64(n.maxDelay - n.minDelay + 1)))
		}
		if n.reorderRate > 0 && n.reorderExtra > 0 && n.rng.Float64() < n.reorderRate {
			d += time.Duration(n.rng.Int64N(int64(n.reorderExtra) + 1))
		}
		delays[i] = d
	}
	return dst, delays
}

func (n *Network) deliverable(from, to string, dst *Endpoint) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.closed && n.endpoints[to] == dst && !n.blockedLocked(from, to)
}

// Endpoint is one node's attachment to the network; it implements
// raft.Transport.
type Endpoint struct {
	net  *Network
	id   string
	wake chan struct{}
	done chan struct{}

	mu      sync.Mutex
	handler func(raft.Message)
	queue   msgQueue
	seq     uint64
	closed  bool
}

var _ raft.Transport = (*Endpoint)(nil)

// Send queues msgs for delivery; it never blocks.
func (e *Endpoint) Send(msgs []raft.Message) {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return
	}
	now := time.Now()
	for i := range msgs {
		m := msgs[i]
		dst, delays := e.net.route(e.id, m.To)
		for _, d := range delays {
			dst.enqueue(e.id, cloneMessage(m), now.Add(d))
		}
	}
}

// SetHandler installs the inbound message callback.
func (e *Endpoint) SetHandler(h func(raft.Message)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handler = h
}

// Close stops delivery to and from this endpoint. It does not wait for an
// in-progress handler call (it may be called from one).
func (e *Endpoint) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		e.queue = nil
		close(e.done)
	}
	return nil
}

func (e *Endpoint) enqueue(from string, m raft.Message, at time.Time) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.seq++
	heap.Push(&e.queue, &queued{at: at, seq: e.seq, from: from, msg: m})
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Endpoint) purge() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queue = nil
}

func (e *Endpoint) loop() {
	defer e.net.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return
		}
		now := time.Now()
		var due []*queued
		for len(e.queue) > 0 && !e.queue[0].at.After(now) {
			due = append(due, heap.Pop(&e.queue).(*queued))
		}
		wait := time.Duration(-1)
		if len(e.queue) > 0 {
			wait = e.queue[0].at.Sub(now)
		}
		h := e.handler
		e.mu.Unlock()

		for _, q := range due {
			if h != nil && e.net.deliverable(q.from, e.id, e) {
				h(q.msg)
			}
		}
		if len(due) > 0 {
			continue
		}
		if wait >= 0 {
			timer.Reset(wait)
		}
		select {
		case <-e.wake:
		case <-timer.C:
		case <-e.done:
			return
		}
		timer.Stop()
	}
}

type queued struct {
	at   time.Time
	seq  uint64
	from string
	msg  raft.Message
}

type msgQueue []*queued

func (q msgQueue) Len() int { return len(q) }
func (q msgQueue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	return q[i].seq < q[j].seq
}
func (q msgQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *msgQueue) Push(x any)   { *q = append(*q, x.(*queued)) }
func (q *msgQueue) Pop() any {
	old := *q
	it := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	return it
}

func cloneMessage(m raft.Message) raft.Message {
	if m.Entries != nil {
		ents := make([]raft.Entry, len(m.Entries))
		for i, en := range m.Entries {
			en.Data = bytes.Clone(en.Data)
			ents[i] = en
		}
		m.Entries = ents
	}
	if m.Snap != nil {
		s := *m.Snap
		s.Data = bytes.Clone(s.Data)
		m.Snap = &s
	}
	m.Data = bytes.Clone(m.Data)
	return m
}
