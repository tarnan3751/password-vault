package raft

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// A tiny synchronous harness: cores over MemStorage with the real driver, a
// FIFO message queue and an optional drop filter.
// ---------------------------------------------------------------------------

type tnode struct {
	c     *core
	st    *MemStorage
	drv   driver
	kv    *KVStore
	props []propResult
	reads []readResult
	local []localResult
}

type tnet struct {
	t     *testing.T
	ids   []string
	nodes map[string]*tnode
	queue []Message
	drop  func(Message) bool
	seen  []Message // every message put on the wire
}

func testCoreConfig(id string, peers []string) coreConfig {
	return coreConfig{id: id, peers: peers, electionTicks: 10, heartbeatTicks: 1, rng: rand.New(rand.NewPCG(uint64(len(id)), 7))}
}

func newTNet(t *testing.T, n int) *tnet {
	tn := &tnet{t: t, nodes: map[string]*tnode{}}
	for i := 1; i <= n; i++ {
		tn.ids = append(tn.ids, fmt.Sprintf("n%d", i))
	}
	for _, id := range tn.ids {
		tn.start(id, NewMemStorage())
	}
	return tn
}

func (tn *tnet) start(id string, st *MemStorage) *tnode {
	tn.t.Helper()
	kv := NewKVStore()
	c, drv, err := restart(testCoreConfig(id, tn.ids), st, kv, 0, 0)
	if err != nil {
		tn.t.Fatal(err)
	}
	n := &tnode{c: c, st: st, kv: kv, drv: drv}
	tn.nodes[id] = n
	return n
}

// process runs every pending ready of id.
func (tn *tnet) process(id string) {
	tn.t.Helper()
	n := tn.nodes[id]
	for n.c.hasReady() {
		rd := n.c.ready()
		out, err := n.drv.process(&rd, tn.put)
		if err != nil {
			tn.t.Fatalf("%s: %v", id, err)
		}
		tn.put(out.msgs)
		n.c.advance(rd)
		n.props = append(n.props, rd.propResults...)
		n.reads = append(n.reads, rd.readResults...)
		n.local = append(n.local, out.local...)
		if err := n.drv.maybeSnapshot(n.c); err != nil {
			tn.t.Fatalf("%s: %v", id, err)
		}
	}
}

func (tn *tnet) put(msgs []Message) {
	for _, m := range msgs {
		tn.seen = append(tn.seen, m)
		if tn.drop == nil || !tn.drop(m) {
			tn.queue = append(tn.queue, m)
		}
	}
}

func (tn *tnet) processAll() {
	for _, id := range tn.ids {
		tn.process(id)
	}
}

// settle delivers messages until the network is quiet.
func (tn *tnet) settle() {
	tn.t.Helper()
	tn.processAll()
	for i := 0; len(tn.queue) > 0; i++ {
		if i > 100000 {
			tn.t.Fatal("network did not quiesce")
		}
		m := tn.queue[0]
		tn.queue = tn.queue[1:]
		tn.nodes[m.To].c.step(m)
		tn.process(m.To)
	}
}

func (tn *tnet) tick(id string, k int) {
	for i := 0; i < k; i++ {
		tn.nodes[id].c.tick()
		tn.settle()
	}
}

// elect ticks id until it is leader (other nodes are not ticked).
func (tn *tnet) elect(id string) {
	tn.t.Helper()
	for i := 0; i < 100 && tn.nodes[id].c.role != Leader; i++ {
		tn.tick(id, 1)
	}
	if tn.nodes[id].c.role != Leader {
		tn.t.Fatalf("%s did not become leader: %s", id, tn.nodes[id].c.role)
	}
}

func cmd(id uint64, v string) []byte {
	return EncodeKV(KVCommand{ID: id, Op: "append", Key: "k", Value: v})
}

func ents(terms ...uint64) []Entry {
	out := make([]Entry, len(terms))
	for i, t := range terms {
		out[i] = Entry{Index: uint64(i + 1), Term: t, Data: cmd(uint64(1000+i), fmt.Sprint(i+1))}
	}
	return out
}

// lone builds a core from explicit persistent state and returns it with the
// messages of its first ready discarded.
func lone(t *testing.T, id string, peers []string, hs HardState, snap *Snapshot, log []Entry) *core {
	t.Helper()
	c, err := newCore(testCoreConfig(id, peers), hs, snap, log)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func drain(c *core) ready {
	rd := c.ready()
	c.advance(rd)
	return rd
}

func findMsg(msgs []Message, typ MsgType, to string) (Message, bool) {
	for _, m := range msgs {
		if m.Type == typ && m.To == to {
			return m, true
		}
	}
	return Message{}, false
}

var peers3 = []string{"n1", "n2", "n3"}
var peers5 = []string{"n1", "n2", "n3", "n4", "n5"}

// ---------------------------------------------------------------------------
// Elections
// ---------------------------------------------------------------------------

func TestVoteUpToDateCheck(t *testing.T) {
	// Our log: (1,1) (2,2); term 2.
	cases := []struct {
		lastIndex, lastTerm uint64
		grant               bool
	}{
		{1, 3, true},  // higher last term wins even with a shorter log
		{5, 1, false}, // lower last term loses even with a longer log
		{1, 2, false}, // same last term, shorter
		{2, 2, true},  // identical
		{3, 2, true},  // same last term, longer
	}
	for _, tc := range cases {
		c := lone(t, "n1", peers3, HardState{Term: 2}, nil, ents(1, 2))
		c.step(Message{Type: MsgVote, From: "n2", To: "n1", Term: 3, LogIndex: tc.lastIndex, LogTerm: tc.lastTerm})
		rd := drain(c)
		m, ok := findMsg(rd.messages, MsgVoteResp, "n2")
		if !ok || m.Reject == tc.grant || m.Term != 3 {
			t.Fatalf("candidate (%d,%d): got %+v, want grant=%v", tc.lastIndex, tc.lastTerm, m, tc.grant)
		}
		if tc.grant && (rd.hardState == nil || rd.hardState.VotedFor != "n2" || rd.hardState.Term != 3) {
			t.Fatalf("grant must persist the vote in the same ready, got %+v", rd.hardState)
		}
	}
}

func TestOneVotePerTerm(t *testing.T) {
	c := lone(t, "n1", peers3, HardState{Term: 1}, nil, nil)
	c.step(Message{Type: MsgVote, From: "n2", To: "n1", Term: 2})
	c.step(Message{Type: MsgVote, From: "n3", To: "n1", Term: 2})
	c.step(Message{Type: MsgVote, From: "n2", To: "n1", Term: 2}) // retransmission
	rd := drain(c)
	var got []string
	for _, m := range rd.messages {
		got = append(got, fmt.Sprintf("%s:%v", m.To, !m.Reject))
	}
	if !slices.Equal(got, []string{"n2:true", "n3:false", "n2:true"}) {
		t.Fatalf("votes: %v", got)
	}
	// After a restart from storage the vote is remembered.
	c2 := lone(t, "n1", peers3, *rd.hardState, nil, nil)
	c2.step(Message{Type: MsgVote, From: "n3", To: "n1", Term: 2})
	if m, _ := findMsg(drain(c2).messages, MsgVoteResp, "n3"); !m.Reject {
		t.Fatal("restarted node voted twice in term 2")
	}
}

func TestVoteIgnoredWhileLeaderIsFresh(t *testing.T) {
	c := lone(t, "n1", peers3, HardState{Term: 1}, nil, ents(1))
	c.step(Message{Type: MsgApp, From: "n2", To: "n1", Term: 1, LogIndex: 1, LogTerm: 1, Commit: 1})
	drain(c)
	// A rejoining node with a higher term asks for votes: ignored entirely.
	c.step(Message{Type: MsgVote, From: "n3", To: "n1", Term: 5, LogIndex: 9, LogTerm: 1})
	c.step(Message{Type: MsgPreVote, From: "n3", To: "n1", Term: 5, LogIndex: 9, LogTerm: 1})
	rd := drain(c)
	if c.term != 1 || c.leader != "n2" {
		t.Fatalf("term %d leader %q: a fresh leader was deposed", c.term, c.leader)
	}
	if m, ok := findMsg(rd.messages, MsgVoteResp, "n3"); ok {
		t.Fatalf("answered vote while in lease: %+v", m)
	}
	if m, ok := findMsg(rd.messages, MsgPreVoteResp, "n3"); !ok || !m.Reject {
		t.Fatalf("pre-vote should be refused while in lease: %+v", m)
	}
	// Once the leader has been silent for an election timeout, it may vote.
	for i := 0; i < c.cfg.electionTicks; i++ {
		c.tick()
		if c.role != Follower {
			break
		}
	}
	drain(c)
	c2 := lone(t, "n1", peers3, HardState{Term: 1}, nil, ents(1))
	c2.step(Message{Type: MsgVote, From: "n3", To: "n1", Term: 5, LogIndex: 9, LogTerm: 1})
	if m, ok := findMsg(drain(c2).messages, MsgVoteResp, "n3"); !ok || m.Reject {
		t.Fatalf("no leader known: vote should be granted, got %+v ok=%v", m, ok)
	}
}

func TestPreVoteDoesNotInflateTerm(t *testing.T) {
	c := lone(t, "n1", peers3, HardState{Term: 3}, nil, ents(1, 3))
	drain(c)
	for i := 0; i < 200; i++ { // ~10 election timeouts, nobody answers
		c.tick()
		rd := drain(c)
		if rd.hardState != nil {
			t.Fatalf("isolated node persisted a new hard state %+v", rd.hardState)
		}
	}
	if c.term != 3 || c.role != PreCandidate {
		t.Fatalf("isolated node: term %d role %s, want term 3 pre-candidate", c.term, c.role)
	}
	// It resends pre-votes, all for term 4.
	c.tick()
	for _, m := range drain(c).messages {
		if m.Type != MsgPreVote || m.Term != 4 {
			t.Fatalf("unexpected %+v", m)
		}
	}
}

func TestElectionAndSingleNode(t *testing.T) {
	tn := newTNet(t, 1)
	tn.tick("n1", 1)
	n := tn.nodes["n1"]
	if n.c.role != Leader || n.c.term != 1 || n.c.commit != 1 {
		t.Fatalf("single node: role %s term %d commit %d", n.c.role, n.c.term, n.c.commit)
	}
	n.c.propose(7, cmd(1, "x"))
	tn.settle()
	if len(n.local) != 1 || n.local[0].id != 7 || n.kv.Get("k") != "x" {
		t.Fatalf("single node proposal: %+v %q", n.local, n.kv.Get("k"))
	}
	n.c.readIndex(8)
	tn.settle()
	if len(n.reads) != 1 || n.reads[0].err != nil || n.reads[0].index != 2 {
		t.Fatalf("single node read: %+v", n.reads)
	}
}

func TestCheckQuorumStepDown(t *testing.T) {
	tn := newTNet(t, 3)
	tn.elect("n1")
	tn.drop = func(m Message) bool { return m.From == "n1" || m.To == "n1" }
	n := tn.nodes["n1"]
	n.c.propose(1, cmd(1, "lost"))
	for i := 0; i < 2*n.c.cfg.electionTicks && n.c.role == Leader; i++ {
		tn.tick("n1", 1)
	}
	if n.c.role == Leader {
		t.Fatal("isolated leader did not step down")
	}
	if len(n.props) != 1 || !errors.Is(n.props[0].err, ErrUnknownOutcome) {
		t.Fatalf("pending proposal on deposed leader: %+v", n.props)
	}
}

// ---------------------------------------------------------------------------
// Commitment
// ---------------------------------------------------------------------------

// becomeLeaderAt makes a lone core with the given log win an election.
func becomeLeaderAt(t *testing.T, peers []string, hs HardState, log []Entry) *core {
	t.Helper()
	c := lone(t, "n1", peers, hs, nil, log)
	for c.role != PreCandidate {
		c.tick()
	}
	drain(c)
	for _, p := range peers[1:] {
		c.step(Message{Type: MsgPreVoteResp, From: p, To: "n1", Term: c.term + 1})
	}
	drain(c)
	for _, p := range peers[1:] {
		c.step(Message{Type: MsgVoteResp, From: p, To: "n1", Term: c.term})
	}
	if c.role != Leader {
		t.Fatalf("not leader: %s", c.role)
	}
	return c
}

func TestLeaderCountsOnlyDurableSelf(t *testing.T) {
	c := becomeLeaderAt(t, peers5, HardState{Term: 3}, ents(1, 2))
	// The no-op at 3 has not been handed to the driver yet, so it is not
	// durable locally: two follower acks plus our own in-memory copy must not
	// make a quorum of three.
	c.step(Message{Type: MsgAppResp, From: "n2", To: "n1", Term: 4, MatchIndex: 3})
	c.step(Message{Type: MsgAppResp, From: "n3", To: "n1", Term: 4, MatchIndex: 3})
	if c.commit != 0 {
		t.Fatalf("committed %d counting the leader's unpersisted entry", c.commit)
	}
	drain(c) // now it is durable
	if c.commit != 3 {
		t.Fatalf("commit %d after the leader persisted, want 3", c.commit)
	}
}

func TestFigure8NoCommitByCountingOldTermReplicas(t *testing.T) {
	// n1 holds (1,1) (2,2) and becomes leader of term 4 with a no-op at 3.
	c := becomeLeaderAt(t, peers5, HardState{Term: 3}, ents(1, 2))
	if c.term != 4 || c.log.lastIndex() != 3 {
		t.Fatalf("term %d last %d", c.term, c.log.lastIndex())
	}
	drain(c)
	// Entry 2 (term 2) is now durable on n1, n2, n3: a majority, but of an
	// older term. It could still be overwritten (Figure 8), so no commit.
	c.step(Message{Type: MsgAppResp, From: "n2", To: "n1", Term: 4, MatchIndex: 2})
	c.step(Message{Type: MsgAppResp, From: "n3", To: "n1", Term: 4, MatchIndex: 2})
	c.step(Message{Type: MsgAppResp, From: "n2", To: "n1", Term: 4, MatchIndex: 3})
	if c.commit != 0 {
		t.Fatalf("Figure 8: committed old-term entry by counting replicas (commit %d)", c.commit)
	}
	// Once the term-4 entry is on a majority, both commit.
	c.step(Message{Type: MsgAppResp, From: "n3", To: "n1", Term: 4, MatchIndex: 3})
	if c.commit != 3 {
		t.Fatalf("commit %d, want 3", c.commit)
	}
}

// ---------------------------------------------------------------------------
// Replication and backtracking
// ---------------------------------------------------------------------------

func TestConflictHints(t *testing.T) {
	// Follower log terms: 1 1 2 2 2 3, commit 1.
	mk := func() *core {
		c := lone(t, "n1", peers3, HardState{Term: 5}, nil, ents(1, 1, 2, 2, 2, 3))
		c.commit = 1
		return c
	}
	cases := []struct {
		prevIdx, prevTerm uint64
		ct, ci            uint64
	}{
		{6, 4, 3, 6}, // conflicting last entry: its term starts at 6
		{5, 3, 2, 3}, // term 2 run starts at 3
		{9, 5, 0, 7}, // follower too short
		{3, 1, 2, 3},
	}
	for _, tc := range cases {
		c := mk()
		c.step(Message{Type: MsgApp, From: "n2", To: "n1", Term: 5, LogIndex: tc.prevIdx, LogTerm: tc.prevTerm})
		m, _ := findMsg(drain(c).messages, MsgAppResp, "n2")
		if !m.Reject || m.ConflictTerm != tc.ct || m.ConflictIdx != tc.ci || m.LogIndex != tc.prevIdx {
			t.Fatalf("prev (%d,%d): got %+v, want term %d idx %d", tc.prevIdx, tc.prevTerm, m, tc.ct, tc.ci)
		}
	}
}

func TestFastBacktracking(t *testing.T) {
	// n1 will lead with a long log of term 3; n2 has a long divergent tail
	// of term 2. With conflict hints the leader needs a handful of
	// rejections, not one per entry.
	lead := ents(1)
	for i := 0; i < 200; i++ {
		lead = append(lead, Entry{Index: uint64(len(lead) + 1), Term: 3, Data: cmd(uint64(i), "L")})
	}
	div := ents(1)
	for i := 0; i < 300; i++ {
		div = append(div, Entry{Index: uint64(len(div) + 1), Term: 2, Data: cmd(uint64(5000+i), "D")})
	}
	tn := &tnet{t: t, nodes: map[string]*tnode{}, ids: peers3}
	for id, log := range map[string][]Entry{"n1": lead, "n2": div, "n3": lead} {
		st := NewMemStorage()
		st.SaveHardState(HardState{Term: 3})
		st.Append(log)
		tn.start(id, st)
	}
	tn.elect("n1")
	tn.tick("n1", 3)
	rejects := 0
	for _, m := range tn.seen {
		if m.Type == MsgAppResp && m.From == "n2" && m.Reject {
			rejects++
		}
	}
	if rejects > 3 {
		t.Fatalf("%d rejections to repair a divergent log", rejects)
	}
	a, b := tn.nodes["n1"].c.log, tn.nodes["n2"].c.log
	if a.lastIndex() != b.lastIndex() || tn.nodes["n2"].c.commit != a.lastIndex() {
		t.Fatalf("n2 did not converge: last %d vs %d, commit %d", b.lastIndex(), a.lastIndex(), tn.nodes["n2"].c.commit)
	}
	for i := uint64(1); i <= a.lastIndex(); i++ {
		if a.entry(i).Term != b.entry(i).Term {
			t.Fatalf("logs differ at %d", i)
		}
	}
}

func TestBatchesAreSizeBoundedButNonEmpty(t *testing.T) {
	tn := newTNet(t, 3)
	for _, n := range tn.nodes {
		n.c.cfg.maxAppendBytes = 100
	}
	tn.elect("n1")
	big := make([]byte, 1000)
	tn.nodes["n1"].c.propose(1, EncodeKV(KVCommand{ID: 1, Op: "put", Key: "k", Value: string(big)}))
	tn.nodes["n1"].c.propose(2, cmd(2, "a"))
	tn.nodes["n1"].c.propose(3, cmd(3, "b"))
	tn.settle()
	for _, m := range tn.seen {
		if m.Type != MsgApp || len(m.Entries) == 0 {
			continue
		}
		size := 0
		for _, e := range m.Entries {
			size += entrySize(e)
		}
		if len(m.Entries) > 1 && size > 100 {
			t.Fatalf("batch of %d entries, %d bytes, exceeds the cap", len(m.Entries), size)
		}
	}
	if got := tn.nodes["n3"].kv.Get("k"); len(got) != 1002 {
		t.Fatalf("follower state %d bytes", len(got))
	}
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

func TestSnapshotInstallEdgeCases(t *testing.T) {
	kv := NewKVStore()
	kv.Apply(1, cmd(1, "s"))
	data, _ := kv.Snapshot()
	snapAt := func(i, term uint64) *Snapshot { return &Snapshot{Meta: SnapshotMeta{Index: i, Term: term}, Data: data} }

	t.Run("matching last entry keeps the log", func(t *testing.T) {
		c := lone(t, "n1", peers3, HardState{Term: 3}, nil, ents(1, 1, 2, 2, 3))
		c.step(Message{Type: MsgSnap, From: "n2", To: "n1", Term: 3, Snap: snapAt(3, 2)})
		rd := drain(c)
		if rd.snapshot != nil || c.log.lastIndex() != 5 || c.commit != 3 {
			t.Fatalf("snapshot %v, last %d, commit %d", rd.snapshot, c.log.lastIndex(), c.commit)
		}
		if m, _ := findMsg(rd.messages, MsgSnapResp, "n2"); m.MatchIndex != 3 {
			t.Fatalf("resp %+v", m)
		}
	})
	t.Run("conflicting log is discarded", func(t *testing.T) {
		c := lone(t, "n1", peers3, HardState{Term: 3}, nil, ents(1, 1, 1, 1))
		c.step(Message{Type: MsgSnap, From: "n2", To: "n1", Term: 3, Snap: snapAt(3, 2)})
		rd := drain(c)
		if rd.snapshot == nil || c.log.lastIndex() != 3 || c.log.offset != 3 || c.commit != 3 || c.applying != 3 {
			t.Fatalf("snapshot %v, last %d, offset %d, commit %d", rd.snapshot, c.log.lastIndex(), c.log.offset, c.commit)
		}
	})
	t.Run("stale snapshot is ignored", func(t *testing.T) {
		c := lone(t, "n1", peers3, HardState{Term: 3}, snapAt(6, 2), nil)
		c.step(Message{Type: MsgSnap, From: "n2", To: "n1", Term: 3, Snap: snapAt(4, 2)})
		rd := drain(c)
		if rd.snapshot != nil || c.log.offset != 6 {
			t.Fatalf("installed a stale snapshot")
		}
		if m, _ := findMsg(rd.messages, MsgSnapResp, "n2"); m.MatchIndex != 6 {
			t.Fatalf("resp %+v", m)
		}
	})
	t.Run("leader sends snapshot once entries are compacted", func(t *testing.T) {
		tn := newTNet(t, 3)
		for _, n := range tn.nodes {
			n.drv.threshold, n.drv.trailing = 5, 1
		}
		tn.elect("n1")
		tn.drop = func(m Message) bool { return m.To == "n3" || m.From == "n3" }
		for i := uint64(1); i <= 20; i++ {
			tn.nodes["n1"].c.propose(i, cmd(i, "x"))
			tn.settle()
		}
		if tn.nodes["n1"].c.log.offset == 0 {
			t.Fatal("leader did not compact")
		}
		tn.drop = nil
		tn.tick("n1", 2)
		snaps := 0
		for _, m := range tn.seen {
			if m.Type == MsgSnap && m.To == "n3" {
				snaps++
			}
		}
		n3 := tn.nodes["n3"]
		if snaps != 1 || n3.drv.applied != tn.nodes["n1"].c.commit || n3.kv.Dump() != tn.nodes["n1"].kv.Dump() {
			t.Fatalf("snaps %d, n3 applied %d, leader commit %d", snaps, n3.drv.applied, tn.nodes["n1"].c.commit)
		}
	})
}

// Coordinator storage point 4: after a crash inside InstallSnapshot, Load may
// return the new snapshot with the old log when it continues the snapshot.
func TestLoadNewSnapshotWithOldLog(t *testing.T) {
	log := ents(1, 1, 2, 2, 2, 3, 3)
	snap := &Snapshot{Meta: SnapshotMeta{Index: 4, Term: 2}}
	c := lone(t, "n1", peers3, HardState{Term: 3}, snap, log)
	if c.log.offset != 1 || c.log.lastIndex() != 7 || c.commit != 4 || c.applying != 4 {
		t.Fatalf("offset %d last %d commit %d applying %d", c.log.offset, c.log.lastIndex(), c.commit, c.applying)
	}
	// MemStorage applies the recovery rule: a log that does not continue the
	// snapshot is discarded.
	st := NewMemStorage()
	st.SaveHardState(HardState{Term: 3})
	st.Append(ents(1, 1, 1, 1, 1))
	st.mu.Lock()
	st.snap = &Snapshot{Meta: SnapshotMeta{Index: 4, Term: 2}} // as if InstallSnapshot crashed half way
	st.mu.Unlock()
	_, s2, e2, err := st.Load()
	if err != nil || s2 == nil || len(e2) != 0 {
		t.Fatalf("recovery rule: snap %v, %d entries, err %v", s2, len(e2), err)
	}
}

// Coordinator storage point 5: entries at or below the snapshot index are
// kept for slow followers but never re-applied.
func TestTrailingEntriesNotReapplied(t *testing.T) {
	kv := NewKVStore()
	for i := uint64(1); i <= 10; i++ {
		kv.Apply(i, cmd(i, fmt.Sprint(i)))
	}
	data, _ := kv.Snapshot()
	st := NewMemStorage()
	st.SaveHardState(HardState{Term: 1})
	full := ents(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
	for i := range full {
		full[i].Data = cmd(uint64(i+1), fmt.Sprint(i+1))
	}
	st.Append(full)
	if err := st.SaveSnapshot(Snapshot{Meta: SnapshotMeta{Index: 10, Term: 1}, Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(4); err != nil {
		t.Fatal(err)
	}
	tn := &tnet{t: t, nodes: map[string]*tnode{}, ids: []string{"n1"}}
	n := tn.start("n1", st)
	if n.c.commit != 10 || n.c.applying != 10 || n.c.log.offset != 5 {
		t.Fatalf("commit %d applying %d offset %d", n.c.commit, n.c.applying, n.c.log.offset)
	}
	tn.tick("n1", 1) // single node: leader, no-op at 13 commits 11..13
	if got, want := n.kv.Get("k"), "12345678910"+"1112"; got != want {
		t.Fatalf("state %q, want %q (entries at or below the snapshot re-applied?)", got, want)
	}
	if v := n.kv.Violation(); v != "" {
		t.Fatal(v)
	}
}

// Coordinator storage points 1-3: MemStorage rejects what the on-disk store
// rejects, so the simulator would catch a node making such a call.
func TestMemStoragePreconditions(t *testing.T) {
	st := NewMemStorage()
	if err := st.Compact(1); err == nil {
		t.Error("Compact without a snapshot accepted")
	}
	if err := st.Append([]Entry{{Index: 0, Term: 1}}); err == nil {
		t.Error("Append at index 0 accepted")
	}
	if err := st.Append([]Entry{{Index: 2, Term: 1}}); err == nil {
		t.Error("Append with a gap accepted")
	}
	if err := st.Append([]Entry{{Index: 1, Term: 1}, {Index: 3, Term: 1}}); err == nil {
		t.Error("non-contiguous Append accepted")
	}
	st.Append(ents(1, 1, 2, 2, 2, 2))
	if err := st.SaveSnapshot(Snapshot{Meta: SnapshotMeta{Index: 3, Term: 1}}); err == nil {
		t.Error("SaveSnapshot with the wrong term accepted")
	}
	if err := st.SaveSnapshot(Snapshot{Meta: SnapshotMeta{Index: 9, Term: 2}}); err == nil {
		t.Error("SaveSnapshot beyond the log accepted")
	}
	if err := st.SaveSnapshot(Snapshot{Meta: SnapshotMeta{Index: 4, Term: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(5); err == nil {
		t.Error("Compact beyond the snapshot accepted")
	}
	if err := st.Compact(4); err != nil {
		t.Fatal(err)
	}
	if err := st.Append([]Entry{{Index: 4, Term: 9}}); err == nil {
		t.Error("Append rewriting the snapshot position accepted")
	}
	if err := st.InstallSnapshot(Snapshot{Meta: SnapshotMeta{Index: 3, Term: 1}}); err == nil {
		t.Error("InstallSnapshot older than the stored snapshot accepted")
	}
	st2 := NewMemStorage()
	st2.Append(ents(1, 1, 1, 1, 1, 1))
	st2.SaveSnapshot(Snapshot{Meta: SnapshotMeta{Index: 5, Term: 1}})
	st2.Compact(5)
	st2.mu.Lock()
	st2.snap = nil // a store that forgot its snapshot: log starts at 6
	st2.mu.Unlock()
	if err := st2.InstallSnapshot(Snapshot{Meta: SnapshotMeta{Index: 3, Term: 1}}); err == nil {
		t.Error("InstallSnapshot ending before the first log index accepted")
	}
}

// ---------------------------------------------------------------------------
// ReadIndex and forwarding
// ---------------------------------------------------------------------------

func TestReadIndexWaitsForCommitInTermAndQuorumRound(t *testing.T) {
	// n1 becomes leader of term 2 holding an entry from term 1.
	c := becomeLeaderAt(t, peers3, HardState{Term: 1}, ents(1))
	rd := drain(c) // persists the no-op
	_ = rd
	c.readIndex(42)
	if rd := drain(c); len(rd.readResults) != 0 {
		t.Fatalf("read answered before the leader committed in its term: %+v", rd.readResults)
	}
	// An acknowledgement echoing a ReadCtx from before the read must not
	// count; one for the no-op commits it.
	c.step(Message{Type: MsgAppResp, From: "n2", To: "n1", Term: 2, MatchIndex: 2, ReadCtx: c.readSeq})
	if c.commit != 2 {
		t.Fatalf("commit %d", c.commit)
	}
	rd = drain(c) // starts the heartbeat round for the deferred read
	if len(rd.readResults) != 0 {
		t.Fatalf("read answered without a quorum round: %+v", rd.readResults)
	}
	hb, ok := findMsg(rd.messages, MsgApp, "n3")
	if !ok || hb.ReadCtx == 0 {
		t.Fatalf("no read round heartbeat: %+v", rd.messages)
	}
	c.step(Message{Type: MsgAppResp, From: "n3", To: "n1", Term: 2, MatchIndex: 2, ReadCtx: hb.ReadCtx - 1})
	if rd := drain(c); len(rd.readResults) != 0 {
		t.Fatal("stale acknowledgement released a read")
	}
	c.step(Message{Type: MsgAppResp, From: "n3", To: "n1", Term: 2, MatchIndex: 2, ReadCtx: hb.ReadCtx})
	rd = drain(c)
	if len(rd.readResults) != 1 || rd.readResults[0].id != 42 || rd.readResults[0].index != 2 || rd.readResults[0].err != nil {
		t.Fatalf("read result %+v", rd.readResults)
	}
}

func TestForwardingAndDuplicateProposals(t *testing.T) {
	tn := newTNet(t, 3)
	tn.elect("n1")
	// Duplicate every MsgProp on the wire.
	orig := tn.drop
	tn.drop = func(m Message) bool {
		if m.Type == MsgProp {
			tn.queue = append(tn.queue, m)
		}
		return orig != nil && orig(m)
	}
	tn.nodes["n2"].c.propose(5, cmd(77, "fwd"))
	tn.nodes["n3"].c.readIndex(6)
	tn.settle()
	n2, n3 := tn.nodes["n2"], tn.nodes["n3"]
	if len(n2.props) != 1 || n2.props[0].err != nil || n2.props[0].id != 5 {
		t.Fatalf("forwarded proposal: %+v", n2.props)
	}
	if len(n3.reads) != 1 || n3.reads[0].err != nil || n3.reads[0].index == 0 {
		t.Fatalf("forwarded read: %+v", n3.reads)
	}
	if got := tn.nodes["n1"].kv.Get("k"); got != "fwd" {
		t.Fatalf("leader state %q", got)
	}
	appended := 0
	for _, e := range tn.nodes["n1"].c.log.entries {
		if e.Type == EntryNormal {
			appended++
		}
	}
	if appended != 1 {
		t.Fatalf("duplicate MsgProp appended %d entries", appended)
	}
	// No leader: ErrNoLeader, certainly not proposed.
	c := lone(t, "n1", peers3, HardState{Term: 1}, nil, nil)
	c.propose(9, cmd(9, "x"))
	if rd := drain(c); len(rd.propResults) != 1 || !errors.Is(rd.propResults[0].err, ErrNoLeader) || len(rd.messages) != 0 {
		t.Fatalf("%+v", rd)
	}
}

func TestStaleTermMessagesDroppedOnTermChange(t *testing.T) {
	c := lone(t, "n1", peers3, HardState{Term: 1}, nil, nil)
	// Grant a vote in term 2, then (same batch) learn of term 3: the term-2
	// grant was never persisted (the term-3 hard state replaces it) and
	// must not be sent.
	c.step(Message{Type: MsgVote, From: "n2", To: "n1", Term: 2})
	c.step(Message{Type: MsgApp, From: "n3", To: "n1", Term: 3})
	rd := drain(c)
	if _, ok := findMsg(rd.messages, MsgVoteResp, "n2"); ok {
		t.Fatal("sent a vote grant for a term whose vote is not being persisted")
	}
	if rd.hardState == nil || rd.hardState.Term != 3 {
		t.Fatalf("hard state %+v", rd.hardState)
	}
}
