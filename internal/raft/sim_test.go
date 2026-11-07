package raft

// Deterministic simulation of whole clusters of cores.
//
// Everything runs on one goroutine in virtual time, and every random choice
// (scheduling, network faults, crashes, client behaviour, election timeouts)
// comes from one PRNG seeded per run, so any failure replays exactly from its
// seed:
//
//	RAFT_SIM_SEED=1234 go test -run TestSimulation ./internal/raft/   # replay one seed
//	RAFT_SIM_SEEDS=20000 go test -run TestSimulation ./internal/raft/ # more seeds
//	RAFT_SIM_FIRST_SEED=50000 ...                                     # start elsewhere
//	RAFT_SIM_VIZ=/tmp ...                  # write a Porcupine visualization on failure
//
// Nodes are cores driven by the production driver (driver.go) on top of a
// MemStorage that can "crash" inside any mutating call (doing all, none or a
// prefix of an Append), right after a leader sent the MsgApps that go out
// before its own entries are persisted, between persisting and sending, or
// between sending and advance, including right after a node sent a vote
// grant or an append acknowledgement. A crashed node keeps exactly what its storage methods had
// completed, and restarts from Load. The network delays, drops, duplicates
// and reorders messages and supports arbitrary directed cuts (symmetric,
// one-way and "bridge" partitions, flapping). Nodes can also be paused (a GC
// pause or a stopped VM), which produces stale leaders, and new leaders can
// be crashed or isolated right after their election. Each seed draws its
// own mix of these faults, cluster size (1, 3 or 5) and protocol parameters.
// Clients retry with the same request ID (the state machine deduplicates)
// and sometimes give up, leaving writes with unknown outcomes.
//
// Invariants are checked continuously: election safety, one vote per server
// per term (across restarts), (index, term) uniquely identifies an entry, log
// matching, leader completeness, state machine safety, per-incarnation commit
// monotonicity, strictly increasing Apply indices, and that every
// acknowledged write is a committed entry. At the end the network heals, the
// cluster must converge (one leader, every node applied the same commands to
// the same state, every acknowledged write applied everywhere), and the
// client history must be linearizable (Porcupine; see finalChecks).

import (
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
)

var errSimCrash = errors.New("simulated crash")

type simParams struct {
	nodes          int
	clients        int
	chaosMs        int64
	tickMs         int64
	electionTicks  int
	heartbeatTicks int
	snapThreshold  uint64
	snapTrailing   uint64
	maxAppendBytes int
	maxInflight    int
	clientTimeout  int64
	keys           []string

	// The adversary. Each seed draws its own mix so that different runs
	// stress different corners.
	crashRate     float64 // per storage call and per ready step
	promiseCrash  float64 // crash right after sending a vote grant or an append ack
	earlyCrash    float64 // crash after a leader's early MsgApps, before or while persisting
	installCrash  float64 // crash inside InstallSnapshot (a rare call, hence a high rate)
	leaderChurn   float64 // crash or isolate a node soon after it becomes leader
	fastRestart   float64 // fraction of crashes followed by an almost immediate restart
	nemesisMin    int64   // nemesis interval (ms)
	nemesisSpan   int64
	baseSlowRate  float64
	longDelayRate float64
}

func randomParams(rng *rand.Rand) simParams {
	pick := func(vals ...float64) float64 { return vals[rng.IntN(len(vals))] }
	p := simParams{
		nodes:          3,
		clients:        2 + rng.IntN(4),
		chaosMs:        3000 + rng.Int64N(4000),
		tickMs:         10,
		electionTicks:  10,
		heartbeatTicks: 1 + rng.IntN(2),
		snapThreshold:  uint64(8 + rng.IntN(60)),
		snapTrailing:   uint64(rng.IntN(12)),
		maxAppendBytes: 64 + rng.IntN(1024),
		maxInflight:    1 + rng.IntN(16),
		clientTimeout:  300 + rng.Int64N(1200),
		keys:           []string{"a", "b", "c"}[:1+rng.IntN(3)],
		crashRate:      pick(0, 0.0002, 0.0005, 0.001),
		promiseCrash:   pick(0, 0, 0.002, 0.01, 0.03),
		earlyCrash:     pick(0, 0, 0.002, 0.01, 0.03),
		installCrash:   pick(0, 0.1, 0.3),
		leaderChurn:    pick(0, 0, 0.2, 0.5),
		fastRestart:    pick(0, 0.3, 0.8),
		nemesisMin:     100,
		nemesisSpan:    700,
		baseSlowRate:   pick(0, 0, 0.05, 0.3),
		longDelayRate:  pick(0.001, 0.005, 0.02),
	}
	switch x := rng.IntN(10); {
	case x == 0:
		p.nodes = 1
	case x <= 3:
		p.nodes = 5
	}
	if rng.IntN(3) == 0 {
		p.maxAppendBytes = 1 // one entry per MsgApp
	}
	if rng.IntN(4) == 0 {
		// Short election timeouts relative to network delay: many split
		// votes and competing candidates.
		p.electionTicks = 3 + rng.IntN(4)
		p.heartbeatTicks = 1
	}
	if rng.IntN(3) == 0 {
		p.nemesisMin, p.nemesisSpan = 10, 120 // flapping faults
	}
	return p
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

type simEvent struct {
	at  int64
	seq uint64
	fn  func()
}

type simQueue []*simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	if q[i].at != q[j].at {
		return q[i].at < q[j].at
	}
	return q[i].seq < q[j].seq
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(*simEvent)) }
func (q *simQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	return e
}

// ---------------------------------------------------------------------------
// Simulated storage with crash points
// ---------------------------------------------------------------------------

type simStore struct {
	*MemStorage
	s     *sim
	armed bool // the next mutating call crashes (set after early sends)
}

func (st *simStore) crash() bool {
	if st.armed {
		st.armed = false
		return true
	}
	return st.s.crashNow()
}

// atomic runs op, or crashes during it with op taking effect or not.
func (st *simStore) atomic(op func() error) error {
	if !st.crash() {
		return op()
	}
	if st.s.rng.IntN(2) == 0 {
		if err := op(); err != nil {
			return err // a precondition violation, not a crash
		}
	}
	return errSimCrash
}

func (st *simStore) SaveHardState(hs HardState) error {
	return st.atomic(func() error { return st.MemStorage.SaveHardState(hs) })
}

func (st *simStore) Append(ents []Entry) error {
	if st.crash() {
		// A torn append keeps the old log or old prefix + a prefix of ents.
		if k := st.s.rng.IntN(len(ents) + 1); k > 0 {
			if err := st.MemStorage.Append(ents[:k]); err != nil {
				return err
			}
		}
		return errSimCrash
	}
	return st.MemStorage.Append(ents)
}

func (st *simStore) InstallSnapshot(snap Snapshot) error {
	if !st.crash() && !(st.s.chaos && st.s.chance(st.s.p.installCrash)) {
		return st.MemStorage.InstallSnapshot(snap)
	}
	old := st.ents
	if r := st.s.rng.IntN(3); r > 0 {
		if err := st.MemStorage.InstallSnapshot(snap); err != nil {
			return err // a precondition violation, not a crash
		}
		if r == 2 {
			// Crashed between the two steps: the snapshot is durable, the old
			// log not yet discarded. Load's recovery rule must sort it out.
			st.ents = old
		}
	}
	return errSimCrash
}

func (st *simStore) SaveSnapshot(snap Snapshot) error {
	return st.atomic(func() error { return st.MemStorage.SaveSnapshot(snap) })
}

func (st *simStore) Compact(through uint64) error {
	return st.atomic(func() error { return st.MemStorage.Compact(through) })
}

// ---------------------------------------------------------------------------
// Nodes, clients, records
// ---------------------------------------------------------------------------

type simNode struct {
	id          string
	store       *simStore
	up          bool
	pausedUntil int64
	inc         int
	core        *core
	drv         driver
	kv          *KVStore
	lastCommit  uint64
	nextID      uint64
	props       map[uint64]simAttempt
	reads       map[uint64]simAttempt
	readWaits   []simReadWait
}

type simAttempt struct {
	op  *simOp
	att int
}

type simReadWait struct {
	index uint64
	simAttempt
}

type opState uint8

const (
	opPending opState = iota
	opOK
	opUnknown
	opFailed
)

type simOp struct {
	client int
	reqID  uint64
	input  KVInput
	call   int64
	ret    int64
	out    KVOutput
	state  opState
	index  uint64 // acknowledged writes: entry index

	attempts    int
	maxAttempts int
	maybe       bool // some attempt may have been proposed
	retrying    bool
}

type simClient struct {
	id  int
	cur *simOp
}

type commitRec struct {
	term       uint64
	data       []byte
	commitTerm uint64 // term of the first node observed to have committed it
}

type voteKey struct {
	voter string
	term  uint64
}

type entryRec struct {
	term uint64
	data []byte
}

type sim struct {
	seed  int64
	p     simParams
	rng   *rand.Rand
	now   int64
	queue simQueue
	seq   uint64
	nodes []*simNode
	byID  map[string]*simNode

	cuts     map[[2]string]bool
	dropRate float64
	dupRate  float64
	slowRate float64
	chaos    bool

	clients   []*simClient
	ops       []*simOp
	nextReqID uint64
	nextValue int

	leaders      map[uint64]string
	committed    map[uint64]commitRec
	maxCommitted uint64
	applied      map[uint64]entryRec
	commitTime   map[uint64]int64 // index -> virtual time it was first observed committed
	entryData    map[[2]uint64][]byte
	votes        map[voteKey]string // (voter, term) -> candidate granted
	acked        []*simOp
	steps        int
	failure      error
	trace        uint64
	stats        simStats
}

type simStats struct {
	crashes, restarts, elections, snapshotsSent, events int
	acked, unknown                                      int
}

func newSim(seed int64) *sim {
	rng := rand.New(rand.NewPCG(uint64(seed), 0xdecafbad))
	s := &sim{
		seed:       seed,
		rng:        rng,
		p:          randomParams(rng),
		byID:       map[string]*simNode{},
		cuts:       map[[2]string]bool{},
		leaders:    map[uint64]string{},
		committed:  map[uint64]commitRec{},
		applied:    map[uint64]entryRec{},
		commitTime: map[uint64]int64{},
		entryData:  map[[2]uint64][]byte{},
		votes:      map[voteKey]string{},
		trace:      1469598103934665603,
	}
	for i := 0; i < s.p.nodes; i++ {
		n := &simNode{id: fmt.Sprintf("n%d", i+1)}
		n.store = &simStore{MemStorage: NewMemStorage(), s: s}
		s.nodes = append(s.nodes, n)
		s.byID[n.id] = n
	}
	for i := 0; i < s.p.clients; i++ {
		s.clients = append(s.clients, &simClient{id: i})
	}
	return s
}

func (s *sim) peerIDs() []string {
	ids := make([]string, len(s.nodes))
	for i, n := range s.nodes {
		ids[i] = n.id
	}
	return ids
}

func (s *sim) fail(format string, args ...any) {
	if s.failure == nil {
		s.failure = fmt.Errorf("t=%dms: "+format, append([]any{s.now}, args...)...)
	}
}

func (s *sim) mix(vals ...uint64) {
	for _, v := range vals {
		s.trace ^= v
		s.trace *= 1099511628211
	}
}

func (s *sim) chance(p float64) bool { return p > 0 && s.rng.Float64() < p }

func (s *sim) crashNow() bool { return s.chaos && s.chance(s.p.crashRate) }

func (s *sim) at(t int64, fn func()) {
	s.seq++
	heap.Push(&s.queue, &simEvent{at: t, seq: s.seq, fn: fn})
}

func (s *sim) after(d int64, fn func()) { s.at(s.now+d, fn) }

// ---------------------------------------------------------------------------
// Node lifecycle
// ---------------------------------------------------------------------------

func (s *sim) start(n *simNode) {
	n.kv = NewKVStore()
	c, drv, err := restart(coreConfig{
		id:             n.id,
		peers:          s.peerIDs(),
		electionTicks:  s.p.electionTicks,
		heartbeatTicks: s.p.heartbeatTicks,
		maxAppendBytes: s.p.maxAppendBytes,
		maxInflight:    s.p.maxInflight,
		rng:            s.rng,
	}, n.store, n.kv, s.p.snapThreshold, s.p.snapTrailing)
	if err != nil {
		s.fail("%s: start: %v", n.id, err)
		return
	}
	n.core, n.drv = c, drv
	n.up = true
	n.inc++
	n.lastCommit = c.commit
	n.props = map[uint64]simAttempt{}
	n.reads = map[uint64]simAttempt{}
	n.readWaits = nil
	n.nextID = s.rng.Uint64() >> 1
	inc := n.inc
	s.after(1+s.rng.Int64N(s.p.tickMs), func() { s.tick(n, inc) })
}

func (s *sim) tick(n *simNode, inc int) {
	if !n.up || n.inc != inc {
		return
	}
	s.after(s.p.tickMs, func() { s.tick(n, inc) })
	if n.pausedUntil > s.now {
		return // a paused process does not notice time passing
	}
	n.core.tick()
	s.drive(n)
}

func (s *sim) crash(n *simNode, why string) {
	if !n.up {
		return
	}
	s.stats.crashes++
	s.mix(0xc0, uint64(len(n.id)))
	n.up = false
	n.core = nil
	n.kv = nil
	// Iterate in id order: the retries scheduled here consume randomness.
	for _, id := range slices.Sorted(maps.Keys(n.props)) {
		a := n.props[id]
		s.attemptFailed(a.op, a.att, true)
	}
	for _, id := range slices.Sorted(maps.Keys(n.reads)) {
		a := n.reads[id]
		s.attemptFailed(a.op, a.att, false)
	}
	for _, w := range n.readWaits {
		s.attemptFailed(w.op, w.att, false)
	}
	n.props, n.reads, n.readWaits = nil, nil, nil
	if s.chaos {
		d := 10 + s.rng.Int64N(1500)
		if s.chance(s.p.fastRestart) {
			d = s.rng.Int64N(15)
		}
		s.after(d, func() { s.restart(n) })
	}
	_ = why
}

func (s *sim) restart(n *simNode) {
	if n.up {
		return
	}
	s.stats.restarts++
	n.pausedUntil = 0
	s.start(n)
}

// ---------------------------------------------------------------------------
// Driving a core
// ---------------------------------------------------------------------------

func (s *sim) drive(n *simNode) {
	for n.up && s.failure == nil && n.core.hasReady() {
		rd := n.core.ready()
		s.observe(n)
		for _, e := range rd.entries {
			k := [2]uint64{e.Index, e.Term}
			if d, ok := s.entryData[k]; !ok {
				s.entryData[k] = e.Data
			} else if !bytes.Equal(d, e.Data) {
				s.fail("two different entries at index %d term %d", e.Index, e.Term)
			}
		}
		if rd.snapshot != nil {
			s.stats.snapshotsSent++
		}
		out, err := n.drv.process(&rd, func(early []Message) {
			for _, m := range early {
				s.send(m)
			}
			// Crash before or while persisting what was just sent: a leader
			// whose followers hold entries it lost.
			n.store.armed = s.chaos && s.chance(s.p.earlyCrash)
		})
		if errors.Is(err, errSimCrash) {
			s.crash(n, "storage")
			return
		}
		if err != nil {
			s.fail("%s: driver: %v", n.id, err)
			return
		}
		if n.store.armed { // nothing was written after the early send
			n.store.armed = false
			s.crash(n, "after early send")
			return
		}
		s.checkApplied(n, rd.committed)
		if s.crashNow() {
			s.crash(n, "after persist, before send")
			return
		}
		promised := false
		for _, m := range out.msgs {
			s.send(m)
			promised = promised || (!m.Reject && (m.Type == MsgVoteResp || m.Type == MsgAppResp || m.Type == MsgSnapResp))
		}
		if s.crashNow() || (promised && s.chaos && s.chance(s.p.promiseCrash)) {
			s.crash(n, "after send, before advance")
			return
		}
		n.core.advance(rd)
		for _, r := range out.local {
			if a, ok := n.props[r.id]; ok {
				delete(n.props, r.id)
				s.finishWrite(n, a.op, r.index, r.data)
			}
		}
		for _, r := range rd.propResults {
			a, ok := n.props[r.id]
			if !ok {
				continue
			}
			delete(n.props, r.id)
			switch {
			case r.err == nil:
				s.finishWrite(n, a.op, r.index, r.data)
			case errors.Is(r.err, ErrNoLeader):
				s.attemptFailed(a.op, a.att, false)
			case errors.Is(r.err, ErrUnknownOutcome):
				s.attemptFailed(a.op, a.att, true)
			default:
				s.fail("%s: proposal error is neither ErrNoLeader nor ErrUnknownOutcome: %v", n.id, r.err)
			}
		}
		for _, r := range rd.readResults {
			a, ok := n.reads[r.id]
			if !ok {
				continue
			}
			delete(n.reads, r.id)
			if r.err != nil {
				s.attemptFailed(a.op, a.att, false)
				continue
			}
			n.readWaits = append(n.readWaits, simReadWait{index: r.index, simAttempt: a})
		}
		s.releaseReads(n)
		if err := n.drv.maybeSnapshot(n.core); err != nil {
			if errors.Is(err, errSimCrash) {
				s.crash(n, "snapshot")
				return
			}
			s.fail("%s: snapshot: %v", n.id, err)
			return
		}
	}
	if n.up {
		s.observe(n)
	}
}

func (s *sim) releaseReads(n *simNode) {
	kept := n.readWaits[:0]
	for _, w := range n.readWaits {
		if w.index <= n.drv.applied {
			s.finishRead(w.op, n.kv.Get(w.op.input.Key))
		} else {
			kept = append(kept, w)
		}
	}
	n.readWaits = kept
}

// entry returns log entry i (offset < i <= last); for the invariant checks.
func (l *raftLog) entry(i uint64) Entry {
	if i <= l.offset || i > l.lastIndex() {
		panic(fmt.Sprintf("raft: entry %d out of range (%d, %d]", i, l.offset, l.lastIndex()))
	}
	return l.entries[i-l.offset-1]
}

// observe checks invariants that depend on a node's in-memory state.
func (s *sim) observe(n *simNode) {
	c := n.core
	if c.role == Leader {
		if l, ok := s.leaders[c.term]; !ok {
			s.leaders[c.term] = n.id
			s.stats.elections++
			s.checkLeaderCompleteness(n)
			if s.chaos && s.chance(s.p.leaderChurn) {
				inc := n.inc
				isolate := s.rng.IntN(2) == 0
				s.after(s.rng.Int64N(3*s.p.tickMs), func() {
					if !s.chaos || !n.up || n.inc != inc {
						return
					}
					if isolate {
						for _, o := range s.nodes {
							if o != n {
								s.cutBoth(n.id, o.id)
							}
						}
					} else {
						s.crash(n, "leader churn")
					}
				})
			}
		} else if l != n.id {
			s.fail("election safety: %s and %s both leaders of term %d", l, n.id, c.term)
		}
	}
	if c.commit < n.lastCommit {
		s.fail("%s: commit index went backwards %d -> %d", n.id, n.lastCommit, c.commit)
	}
	if c.commit > c.log.lastIndex() {
		s.fail("%s: commit %d beyond last index %d", n.id, c.commit, c.log.lastIndex())
		return
	}
	for i := max(n.lastCommit, c.log.offset) + 1; i <= c.commit; i++ {
		e := c.log.entry(i)
		if rec, ok := s.committed[i]; ok {
			if rec.term != e.Term || !bytes.Equal(rec.data, e.Data) {
				s.fail("%s: committed entry %d is %d/%q, but %d/%q was committed before", n.id, i, e.Term, e.Data, rec.term, rec.data)
			}
		} else {
			s.committed[i] = commitRec{term: e.Term, data: e.Data, commitTerm: c.term}
			s.commitTime[i] = s.now
			s.maxCommitted = max(s.maxCommitted, i)
		}
	}
	n.lastCommit = c.commit
}

func (s *sim) checkLeaderCompleteness(n *simNode) {
	l := &n.core.log
	for i := l.offset + 1; i <= s.maxCommitted; i++ {
		rec, ok := s.committed[i]
		if !ok || rec.commitTerm >= n.core.term {
			continue
		}
		t, ok := l.term(i)
		if !ok || t != rec.term || !bytes.Equal(l.entry(i).Data, rec.data) {
			s.fail("leader completeness: %s became leader of term %d without committed entry %d (term %d)", n.id, n.core.term, i, rec.term)
			return
		}
	}
	if l.offset > 0 && n.core.snapshotIndex() < l.offset {
		s.fail("%s: log compacted to %d beyond snapshot %d", n.id, l.offset, n.core.snapshotIndex())
	}
}

func (s *sim) checkApplied(n *simNode, ents []Entry) {
	for _, e := range ents {
		if rec, ok := s.applied[e.Index]; ok {
			if rec.term != e.Term || !bytes.Equal(rec.data, e.Data) {
				s.fail("state machine safety: %s applied %d/%q at %d, another node applied %d/%q", n.id, e.Term, e.Data, e.Index, rec.term, rec.data)
			}
		} else {
			s.applied[e.Index] = entryRec{term: e.Term, data: e.Data}
		}
		if rec, ok := s.committed[e.Index]; !ok || rec.term != e.Term {
			s.fail("%s applied entry %d/%d that was not observed committed", n.id, e.Index, e.Term)
		}
	}
	if v := n.kv.Violation(); v != "" {
		s.fail("%s: state machine contract: %s", n.id, v)
	}
}

func (s *sim) checkLogMatching() {
	for i := 0; i < len(s.nodes); i++ {
		for j := i + 1; j < len(s.nodes); j++ {
			a, b := s.nodes[i], s.nodes[j]
			if !a.up || !b.up {
				continue
			}
			la, lb := &a.core.log, &b.core.log
			lo := max(la.offset, lb.offset) + 1
			hi := min(la.lastIndex(), lb.lastIndex())
			for k := hi; k >= lo && k > 0; k-- {
				ta, _ := la.term(k)
				tb, _ := lb.term(k)
				if ta != tb {
					continue
				}
				for x := lo; x <= k; x++ {
					ea, eb := la.entry(x), lb.entry(x)
					if ea.Term != eb.Term || !bytes.Equal(ea.Data, eb.Data) {
						s.fail("log matching: %s and %s agree on %d/%d but differ at %d", a.id, b.id, k, ta, x)
						return
					}
				}
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

func (s *sim) blocked(from, to string) bool { return s.cuts[[2]string{from, to}] }

func (s *sim) delay() int64 {
	d := 1 + s.rng.Int64N(4)
	if s.chance(s.slowRate) {
		d += s.rng.Int64N(80)
	}
	if s.chaos && s.chance(s.p.longDelayRate) {
		d += 50 + s.rng.Int64N(2000) // a very stale message
	}
	return d
}

func (s *sim) send(m Message) {
	if m.Type == MsgVoteResp && !m.Reject {
		// One vote per server per term, across restarts.
		k := voteKey{m.From, m.Term}
		if prev, ok := s.votes[k]; ok && prev != m.To {
			s.fail("vote safety: %s voted for %s and %s in term %d", m.From, prev, m.To, m.Term)
		}
		s.votes[k] = m.To
	}
	if s.blocked(m.From, m.To) || s.chance(s.dropRate) {
		return
	}
	copies := 1
	if s.chance(s.dupRate) {
		copies = 2
	}
	for i := 0; i < copies; i++ {
		s.after(s.delay(), func() { s.deliver(m) })
	}
}

func (s *sim) deliver(m Message) {
	n := s.byID[m.To]
	if !n.up || s.blocked(m.From, m.To) {
		return
	}
	if n.pausedUntil > s.now {
		s.at(n.pausedUntil+s.rng.Int64N(3), func() { s.deliver(m) })
		return
	}
	s.mix(uint64(m.Type), m.Term, m.LogIndex, uint64(len(m.Entries)))
	n.core.step(m)
	s.drive(n)
}

func (s *sim) heal() {
	clear(s.cuts)
}

func (s *sim) cutBoth(a, b string) {
	s.cuts[[2]string{a, b}] = true
	s.cuts[[2]string{b, a}] = true
}

func (s *sim) leader() *simNode {
	var best *simNode
	for _, n := range s.nodes {
		if n.up && n.core.role == Leader && (best == nil || n.core.term > best.core.term) {
			best = n
		}
	}
	return best
}

func (s *sim) randomNode() *simNode { return s.nodes[s.rng.IntN(len(s.nodes))] }

func (s *sim) nemesis() {
	if !s.chaos || s.failure != nil {
		return
	}
	defer s.after(s.p.nemesisMin+s.rng.Int64N(s.p.nemesisSpan), s.nemesis)
	ids := s.peerIDs()
	switch x := s.rng.IntN(100); {
	case x < 18:
		s.heal()
	case x < 32: // random symmetric split
		s.heal()
		perm := s.rng.Perm(len(ids))
		k := 1 + s.rng.IntN(max(1, len(ids)-1))
		for i := 0; i < k; i++ {
			for j := k; j < len(ids); j++ {
				s.cutBoth(ids[perm[i]], ids[perm[j]])
			}
		}
	case x < 40: // isolate one node, often the leader
		target := s.randomNode()
		if l := s.leader(); l != nil && s.rng.IntN(2) == 0 {
			target = l
		}
		for _, id := range ids {
			if id != target.id {
				s.cutBoth(target.id, id)
			}
		}
	case x < 48: // one-way cuts
		for i := 0; i < 1+s.rng.IntN(3); i++ {
			a, b := s.randomNode().id, s.randomNode().id
			if a != b {
				s.cuts[[2]string{a, b}] = true
			}
		}
	case x < 55: // bridge: two sides that only talk through one node
		if len(ids) >= 3 {
			s.heal()
			perm := s.rng.Perm(len(ids))
			bridge := ids[perm[0]]
			rest := perm[1:]
			half := len(rest) / 2
			for _, i := range rest[:half] {
				for _, j := range rest[half:] {
					s.cutBoth(ids[i], ids[j])
				}
			}
			_ = bridge
		}
	case x < 68: // crash a node
		s.crash(s.randomNode(), "nemesis")
	case x < 74: // crash the leader
		if l := s.leader(); l != nil {
			s.crash(l, "nemesis leader")
		}
	case x < 82: // pause a node (stale leader / slow process)
		target := s.randomNode()
		if l := s.leader(); l != nil && s.rng.IntN(2) == 0 {
			target = l
		}
		target.pausedUntil = s.now + 50 + s.rng.Int64N(1500)
	case x < 92:
		s.dropRate = []float64{0, 0, 0.01, 0.05, 0.2}[s.rng.IntN(5)]
		s.dupRate = []float64{0, 0, 0.02, 0.1}[s.rng.IntN(4)]
		s.slowRate = []float64{s.p.baseSlowRate, 0.05, 0.3}[s.rng.IntN(3)]
	default:
		for _, n := range s.nodes {
			if !n.up {
				s.restart(n)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

func (s *sim) clientStep(cl *simClient) {
	if !s.chaos || s.failure != nil {
		return
	}
	key := s.p.keys[s.rng.IntN(len(s.p.keys))]
	s.nextValue++
	val := "v" + strconv.Itoa(s.nextValue) + "."
	var in KVInput
	switch x := s.rng.IntN(100); {
	case x < 40:
		in = KVInput{Op: "get", Key: key}
	case x < 60:
		in = KVInput{Op: "put", Key: key, Value: val}
	case x < 85:
		in = KVInput{Op: "append", Key: key, Value: val}
	default:
		// cas against some node's current value (or "") so that it
		// succeeds now and then.
		old := ""
		if n := s.randomNode(); n.up && s.rng.IntN(2) == 0 {
			old = n.kv.Get(key)
		}
		in = KVInput{Op: "cas", Key: key, Old: old, Value: val}
	}
	s.nextReqID++
	op := &simOp{client: cl.id, reqID: s.nextReqID, input: in, call: s.now, maxAttempts: 1}
	if s.rng.IntN(5) != 0 {
		op.maxAttempts = 2 + s.rng.IntN(8)
	}
	cl.cur = op
	s.ops = append(s.ops, op)
	s.attempt(op)
}

// attempt sends op (again) to a random node. Retries reuse the request ID,
// so the state machine applies the command at most once, exactly like a real
// client retrying an idempotent request.
func (s *sim) attempt(op *simOp) {
	if op.state != opPending || s.failure != nil {
		return
	}
	op.attempts++
	att := op.attempts
	n := s.randomNode()
	s.after(s.p.clientTimeout, func() { s.attemptFailed(op, att, true) })
	s.submit(n, n.inc, op, att)
}

// attemptFailed records a failed attempt. maybe says whether the command
// might nevertheless have been proposed. During chaos a client gives up after
// maxAttempts (the outcome is then unknown if any attempt might have been
// proposed); while the cluster settles it keeps retrying.
func (s *sim) attemptFailed(op *simOp, att int, maybe bool) {
	if op.state != opPending {
		return
	}
	if maybe && op.input.Op != "get" {
		op.maybe = true
	}
	if att != op.attempts || op.retrying {
		return // an older attempt, or a retry is already scheduled
	}
	if !s.chaos || op.attempts < op.maxAttempts {
		op.retrying = true
		s.after(5+s.rng.Int64N(40), func() {
			op.retrying = false
			s.attempt(op)
		})
		return
	}
	if op.maybe {
		op.state, op.ret, op.out = opUnknown, math.MaxInt64, KVOutput{Unknown: true}
		s.stats.unknown++
	} else {
		op.state = opFailed
	}
	s.opDone(op)
}

// submit hands op to node n (as of incarnation inc), waiting out a pause.
func (s *sim) submit(n *simNode, inc int, op *simOp, att int) {
	if op.state != opPending {
		return
	}
	if !n.up || n.inc != inc {
		s.attemptFailed(op, att, false) // never reached the node
		return
	}
	if n.pausedUntil > s.now {
		s.at(n.pausedUntil+s.rng.Int64N(3), func() { s.submit(n, inc, op, att) })
		return
	}
	n.nextID++
	id := n.nextID
	if op.input.Op == "get" {
		n.reads[id] = simAttempt{op, att}
		n.core.readIndex(id)
	} else {
		in := op.input
		n.props[id] = simAttempt{op, att}
		n.core.propose(id, EncodeKV(KVCommand{ID: op.reqID, Op: in.Op, Key: in.Key, Value: in.Value, Old: in.Old}))
	}
	s.drive(n)
}

func (s *sim) opDone(op *simOp) {
	cl := s.clients[op.client]
	if cl.cur == op {
		cl.cur = nil
		s.after(s.rng.Int64N(30), func() { s.clientStep(cl) })
	}
}

func (s *sim) finishWrite(n *simNode, op *simOp, index uint64, data []byte) {
	if op.state != opPending {
		return
	}
	res, err := DecodeKVResult(data)
	if err != nil {
		s.fail("%s: undecodable result %q for op %d", n.id, data, op.reqID)
		return
	}
	rec, ok := s.committed[index]
	if !ok {
		s.fail("acknowledged write %d at index %d is not a committed entry", op.reqID, index)
		return
	}
	var cmd KVCommand
	if json.Unmarshal(rec.data, &cmd) != nil || cmd.ID != op.reqID {
		s.fail("acknowledged write %d at index %d, but the committed entry there is %q", op.reqID, index, rec.data)
		return
	}
	op.state, op.ret, op.index = opOK, s.now, index
	op.out = KVOutput{OK: res.OK}
	s.acked = append(s.acked, op)
	s.stats.acked++
	s.opDone(op)
}

func (s *sim) finishRead(op *simOp, v string) {
	if op.state != opPending {
		return
	}
	op.state, op.ret, op.out = opOK, s.now, KVOutput{Value: v}
	s.opDone(op)
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

func (s *sim) runUntil(t int64, stop func() bool) {
	for len(s.queue) > 0 && s.failure == nil {
		if s.queue[0].at > t {
			break
		}
		ev := heap.Pop(&s.queue).(*simEvent)
		s.now = ev.at
		ev.fn()
		s.steps++
		s.stats.events++
		if s.steps%97 == 0 {
			s.checkLogMatching()
		}
		if stop != nil && s.steps%16 == 0 && stop() {
			return
		}
	}
	if s.now < t && (stop == nil || !stop()) {
		s.now = t
	}
}

func (s *sim) converged() bool {
	l := s.leader()
	if l == nil || !l.core.committedInTerm() || l.core.commit != l.core.log.lastIndex() {
		return false
	}
	for _, n := range s.nodes {
		if !n.up || n.core.commit != l.core.commit || n.drv.applied != l.core.commit || n.core.log.lastIndex() != l.core.log.lastIndex() {
			return false
		}
	}
	for _, cl := range s.clients {
		if cl.cur != nil {
			return false
		}
	}
	return true
}

func (s *sim) run() error {
	for _, n := range s.nodes {
		s.start(n)
	}
	s.chaos = true
	s.slowRate = s.p.baseSlowRate
	s.after(200+s.rng.Int64N(500), s.nemesis)
	for _, cl := range s.clients {
		cl := cl
		s.after(s.rng.Int64N(300), func() { s.clientStep(cl) })
	}
	s.runUntil(s.p.chaosMs, nil)
	if s.failure != nil {
		return s.failure
	}

	// Heal everything and let the cluster settle.
	s.chaos = false
	s.heal()
	s.dropRate, s.dupRate, s.slowRate = 0, 0, 0
	for _, n := range s.nodes {
		n.pausedUntil = 0
		if !n.up {
			s.restart(n)
		}
	}
	deadline := s.now + 20000
	s.runUntil(deadline, s.converged)
	if s.failure != nil {
		return s.failure
	}
	if !s.converged() {
		return fmt.Errorf("did not converge within 20s of virtual time after healing: %s", s.describe())
	}
	return s.finalChecks()
}

func (s *sim) finalChecks() error {
	s.checkLogMatching()
	if s.failure != nil {
		return s.failure
	}
	l := s.leader()
	want := l.kv.Dump()
	for _, n := range s.nodes {
		if got := n.kv.Dump(); got != want {
			return fmt.Errorf("state machines diverged: %s has %s, leader %s has %s", n.id, got, l.id, want)
		}
		for _, op := range s.acked {
			if op.index > n.drv.applied {
				return fmt.Errorf("acknowledged write %d at index %d not applied on %s (applied %d)", op.reqID, op.index, n.id, n.drv.applied)
			}
		}
	}
	for _, op := range s.acked {
		if rec := s.committed[op.index]; !bytes.Contains(rec.data, []byte(fmt.Sprintf(`"id":%d,`, op.reqID))) {
			return fmt.Errorf("acknowledged write %d lost: index %d holds %q", op.reqID, op.index, rec.data)
		}
	}

	// Every index up to the final commit must have been observed committed.
	firstCommitted := map[uint64]uint64{} // request ID -> first index holding it
	for i := uint64(1); i <= l.core.commit; i++ {
		rec, ok := s.committed[i]
		if !ok {
			return fmt.Errorf("index %d <= final commit %d was never observed committed", i, l.core.commit)
		}
		var cmd KVCommand
		if len(rec.data) > 0 && json.Unmarshal(rec.data, &cmd) == nil {
			if _, seen := firstCommitted[cmd.ID]; !seen {
				firstCommitted[cmd.ID] = i
			}
		}
	}

	// The history, plus a final read of every key on every node, is checked
	// against the literal model: a write with an unknown outcome may have
	// taken effect at any time after its call (Return = MaxInt64).
	//
	// Porcupine is exponential in overlapping operations, so first search
	// for a witness in a refined history built from the simulator's
	// knowledge of the log. Every millisecond t is embedded as the integer
	// slot [t*slot, t*slot+slot-1], which preserves the real-time order of
	// all operations exactly. A write whose command committed becomes the
	// point (time its first entry was first observed committed)*slot +
	// index, which lies inside its literal interval and orders writes that
	// committed in the same millisecond by log position; an unknown write
	// whose command never committed is left out (it can be linearized last,
	// after the final reads). So every linearization of the refined history
	// is one of the literal history, and "refined OK" proves
	// linearizability. For a correct Raft the refined history is always
	// linearizable (commit times are monotone in the index, and a read
	// invoked after index i committed gets a read index >= i). If the
	// refined search does not succeed, the literal check decides.
	const slot = 1 << 20
	history := func(refined bool) []porcupine.Operation {
		lo := func(t int64) int64 { return t }
		hi := lo
		if refined {
			lo = func(t int64) int64 { return t * slot }
			hi = func(t int64) int64 {
				if t == math.MaxInt64 {
					return t
				}
				return t*slot + slot - 1
			}
		}
		var hist []porcupine.Operation
		for _, op := range s.ops {
			if op.state != opOK && op.state != opUnknown {
				continue
			}
			call, ret := lo(op.call), hi(op.ret)
			if refined && op.input.Op != "get" {
				idx, ok := firstCommitted[op.reqID]
				if !ok && op.state == opUnknown {
					continue
				}
				if t := s.commitTime[idx]; ok && idx < slot && op.call <= t && t <= op.ret {
					call = t*slot + int64(idx)
					ret = call
				}
			}
			hist = append(hist, porcupine.Operation{ClientId: op.client, Input: op.input, Call: call, Output: op.out, Return: ret})
		}
		for i, n := range s.nodes {
			for _, k := range s.p.keys {
				hist = append(hist, porcupine.Operation{
					ClientId: len(s.clients) + i,
					Input:    KVInput{Op: "get", Key: k},
					Call:     lo(s.now + 1), Return: hi(s.now + 1),
					Output: KVOutput{Value: n.kv.Get(k)},
				})
			}
		}
		return hist
	}
	if porcupine.CheckOperationsTimeout(KVModel, history(true), 20*time.Second) == porcupine.Ok {
		return nil
	}
	hist := history(false)
	res, info := porcupine.CheckOperationsVerbose(KVModel, hist, 20*time.Second)
	switch res {
	case porcupine.Ok:
		return nil
	case porcupine.Unknown:
		return fmt.Errorf("porcupine timed out on %d operations (and found no linearization of the refined history)", len(hist))
	default:
		path := ""
		if dir := os.Getenv("RAFT_SIM_VIZ"); dir != "" {
			path = fmt.Sprintf("%s/raft-sim-%d.html", dir, s.seed)
			if err := porcupine.VisualizePath(KVModel, info, path); err != nil {
				path = "visualization failed: " + err.Error()
			}
		}
		return fmt.Errorf("history of %d operations is not linearizable %s", len(hist), path)
	}
}

func (s *sim) describe() string {
	var b strings.Builder
	for _, n := range s.nodes {
		if !n.up {
			fmt.Fprintf(&b, "[%s down] ", n.id)
			continue
		}
		c := n.core
		fmt.Fprintf(&b, "[%s %s t=%d lead=%s commit=%d applied=%d last=%d/%d snap=%d] ",
			n.id, c.role, c.term, c.leader, c.commit, n.drv.applied, c.log.lastIndex(), c.log.lastTerm(), c.snapshotIndex())
	}
	return b.String()
}

func (s *sim) finalHash() uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%d|%d|%d|", s.trace, s.now, s.steps)
	for _, n := range s.nodes {
		if n.up {
			fmt.Fprintf(h, "%s:%d:%d:%s|", n.id, n.core.term, n.core.commit, n.kv.Dump())
		}
	}
	return h.Sum64()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func simSeeds(t *testing.T) (first int64, count int) {
	if v := os.Getenv("RAFT_SIM_SEED"); v != "" {
		seed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("RAFT_SIM_SEED: %v", err)
		}
		return seed, 1
	}
	count = 1000
	if testing.Short() {
		count = 100
	}
	if v := os.Getenv("RAFT_SIM_SEEDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("RAFT_SIM_SEEDS: %v", err)
		}
		count = n
	}
	first = 1
	if v := os.Getenv("RAFT_SIM_FIRST_SEED"); v != "" {
		f, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("RAFT_SIM_FIRST_SEED: %v", err)
		}
		first = f
	}
	return first, count
}

func runSimSeed(seed int64) (s *sim, err error) {
	s = newSim(seed)
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 16<<10)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("panic at t=%dms: %v\n%s", s.now, r, buf)
		}
	}()
	return s, s.run()
}

func TestSimulation(t *testing.T) {
	first, count := simSeeds(t)
	workers := min(runtime.GOMAXPROCS(0), 8)
	var (
		next     atomic.Int64
		mu       sync.Mutex
		failures []string
		total    simStats
		wg       sync.WaitGroup
	)
	next.Store(first)
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				seed := next.Add(1) - 1
				if seed >= first+int64(count) {
					return
				}
				s, err := runSimSeed(seed)
				mu.Lock()
				if err != nil {
					failures = append(failures, fmt.Sprintf("seed %d (nodes=%d): %v\n  rerun: RAFT_SIM_SEED=%d go test -run TestSimulation ./internal/raft/", seed, s.p.nodes, err, seed))
				}
				total.crashes += s.stats.crashes
				total.elections += s.stats.elections
				total.events += s.stats.events
				total.acked += s.stats.acked
				total.unknown += s.stats.unknown
				total.snapshotsSent += s.stats.snapshotsSent
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("%d seeds from %d in %v: %d events, %d leaders elected, %d crashes, %d snapshot installs, %d acked writes, %d unknown outcomes",
		count, first, time.Since(start).Round(time.Millisecond), total.events, total.elections, total.crashes, total.snapshotsSent, total.acked, total.unknown)
	slices.Sort(failures)
	for i, f := range failures {
		if i == 10 {
			t.Errorf("... and %d more failing seeds", len(failures)-10)
			break
		}
		t.Error(f)
	}
}

// TestSimulationDeterministic replays a few seeds and requires identical
// traces, so that a printed seed really reproduces a failure.
func TestSimulationDeterministic(t *testing.T) {
	for seed := int64(1); seed <= 5; seed++ {
		a, errA := runSimSeed(seed)
		b, errB := runSimSeed(seed)
		if (errA == nil) != (errB == nil) || a.finalHash() != b.finalHash() || a.steps != b.steps {
			t.Fatalf("seed %d is not deterministic: %v / %v, steps %d / %d", seed, errA, errB, a.steps, b.steps)
		}
	}
}
