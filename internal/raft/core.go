package raft

// The consensus core.
//
// core is a deterministic, single-threaded Raft state machine. It never
// blocks, reads a clock, starts a goroutine, performs I/O or draws randomness
// from anywhere but the *rand.Rand it is given. Its inputs are tick(),
// step(Message), propose(id, data) and readIndex(id); its output is a ready:
//
//	hardState   term/vote to persist (nil if unchanged)
//	snapshot    leader snapshot to install (InstallSnapshot + Restore)
//	entries     log entries to append (may overwrite a suffix)
//	committed   entries to apply (all already durable locally)
//	messages    to send, ONLY after everything above is durable (except
//	            those takeEarly allows)
//	results     outcomes of local proposals and read-index requests
//
// A driver (driver.go) executes a ready in this order: early messages, hard
// state, snapshot, apply committed, append entries, send the rest, then
// advance(). Between ready() and advance() nothing else may be called. Every
// other message in a ready may depend on state persisted by that same ready
// (a vote grant depends on the vote, an append acknowledgement on the
// entries); because those are sent only after the ready is durable, a crash
// can never make a node forget something it told another node. Messages
// tagged with a term that the node has since left are dropped when the term
// changes, so a ready never carries a promise about state that was
// overwritten before it could be persisted.
//
// Protocol notes (Ongaro's thesis, with etcd-style refinements):
//   - PreVote: a node whose election timer fires first asks for pre-votes
//     for term+1 without changing its term; only with a quorum of pre-votes
//     does it start a real election. A partitioned node therefore cannot
//     inflate terms and disrupt a healthy leader when it returns.
//   - Leader stickiness / CheckQuorum: a node that has heard from a leader
//     within the (non-randomized) election timeout ignores vote requests and
//     refuses pre-votes; a leader that has not heard from a quorum within an
//     election timeout steps down. A node that answers a stale-term MsgApp
//     tells the sender its term, so a node stranded in a higher term rejoins.
//   - Commitment: the leader only advances commit to an index N whose entry
//     is from its current term and that a quorum holds durably (Figure 8);
//     the leader's own vote counts only for entries it has persisted. A
//     no-op entry is appended on election so earlier entries commit promptly.
//   - Replication: per-follower progress (probe/replicate/snapshot) with
//     size-bounded batches, a bounded in-flight window, and ConflictTerm/
//     ConflictIdx hints for fast backtracking. A stalled pipeline is detected
//     at heartbeat time with a cheap empty MsgApp at next-1.
//   - Snapshots: followers whose next entry was compacted away get MsgSnap. A
//     follower that already holds the snapshot's last entry with the same
//     term keeps its log and just advances commit.
//   - ReadIndex: a read is answered with the commit index once (a) the
//     leader has committed an entry in its current term and (b) a quorum has
//     acknowledged a message the leader sent after the read arrived. (b) uses
//     a sequence number (ReadCtx) that only increases; every MsgApp carries
//     the current value and followers echo it. A read that arrives gets ctx =
//     readSeq+1 and readSeq is bumped (starting a heartbeat round) only
//     afterwards, so any acknowledgement echoing >= ctx answers a message
//     sent after the read arrived. No clocks are involved.
//   - Forwarding: a follower forwards proposals (MsgProp) and read-index
//     requests (MsgReadIndex) to the leader it knows, correlating responses
//     by RequestID. A forwarded request whose leader changes or that times
//     out completes with an "unknown outcome" (proposals) or a retryable
//     error (reads).
//   - Membership is static: peers is the full voter set including self.

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
)

type coreConfig struct {
	id    string
	peers []string // all voters, including id

	electionTicks  int
	heartbeatTicks int

	maxAppendBytes int // soft cap on the entries of one MsgApp
	maxInflight    int // MsgApps outstanding per replicating follower

	rng *rand.Rand
}

const (
	maxApplyBytes = 64 << 20 // soft cap on the committed entries of one ready

	// In election timeouts: a forwarded proposal fails after propForwardElections,
	// a forwarded read-index request after readForwardElections, and an
	// unanswered MsgSnap is resent after snapshotRetryElections.
	propForwardElections   = 10
	readForwardElections   = 2
	snapshotRetryElections = 5
)

func (cfg *coreConfig) fillDefaults() {
	if cfg.electionTicks == 0 {
		cfg.electionTicks = 10
	}
	if cfg.heartbeatTicks == 0 {
		cfg.heartbeatTicks = 1
	}
	if cfg.maxAppendBytes == 0 {
		cfg.maxAppendBytes = 1 << 20
	}
	if cfg.maxInflight == 0 {
		cfg.maxInflight = 64
	}
}

// waiter is someone waiting for the result of the entry at some index.
type waiter struct {
	term uint64 // term the entry was proposed in; the result is only theirs if the applied entry has this term
	from string // "" for a local proposal, else the follower that forwarded it
	id   uint64 // local request id, or the follower's RequestID
}

type entryWaiter struct {
	index uint64
	waiter
}

type remoteKey struct {
	from string
	id   uint64
}

// forward is a local request that was handed to the leader.
type forward struct {
	read  bool
	to    string
	ticks int
}

type readReq struct {
	from  string // "" for local
	id    uint64
	index uint64
	ctx   uint64
}

type propResult struct {
	id    uint64
	index uint64
	data  []byte
	err   error
}

type readResult struct {
	id    uint64
	index uint64
	err   error
}

// ready is a batch of effects the driver must carry out; see the top of
// this file for the required order.
type ready struct {
	hardState   *HardState
	snapshot    *Snapshot
	entries     []Entry
	stable      uint64 // highest log index that was durable before this ready
	committed   []Entry
	waiters     []entryWaiter // waiters of entries in committed, in index order
	messages    []Message
	propResults []propResult
	readResults []readResult
}

type core struct {
	cfg    coreConfig
	id     string
	others []string // sorted peers except id
	quorum int

	term     uint64
	votedFor string
	role     Role
	leader   string

	log      raftLog
	commit   uint64
	applying uint64    // highest index handed out for application (or covered by snapshot)
	snap     *Snapshot // latest snapshot, sent to followers that need it

	electionElapsed   int
	heartbeatElapsed  int
	randomizedTimeout int

	votes map[string]bool
	prs   map[string]*progress

	persisted   HardState
	pendingSnap *Snapshot
	msgs        []Message
	propResults []propResult
	readResults []readResult

	waiters     map[uint64]waiter // leader: proposal waiters by log index
	remoteProps map[remoteKey]struct{}
	forwards    map[uint64]*forward

	readSeq       uint64
	readRound     bool
	pendingReads  []readReq // ctx assigned, waiting for a quorum of acks
	deferredReads []readReq // waiting for the first commit of the term
	bcastPending  bool

	inReady bool
}

func newCore(cfg coreConfig, hs HardState, snap *Snapshot, ents []Entry) (*core, error) {
	cfg.fillDefaults()
	if cfg.rng == nil {
		return nil, fmt.Errorf("raft: core needs a random source")
	}
	if cfg.heartbeatTicks >= cfg.electionTicks {
		return nil, fmt.Errorf("raft: heartbeat ticks (%d) must be < election ticks (%d)", cfg.heartbeatTicks, cfg.electionTicks)
	}
	c := &core{
		cfg:         cfg,
		id:          cfg.id,
		waiters:     map[uint64]waiter{},
		remoteProps: map[remoteKey]struct{}{},
		forwards:    map[uint64]*forward{},
	}
	seen := map[string]bool{}
	for _, p := range cfg.peers {
		if p == "" || seen[p] {
			return nil, fmt.Errorf("raft: invalid or duplicate peer %q", p)
		}
		seen[p] = true
		if p != cfg.id {
			c.others = append(c.others, p)
		}
	}
	if !seen[cfg.id] {
		return nil, fmt.Errorf("raft: peers %v do not include self %q", cfg.peers, cfg.id)
	}
	slices.Sort(c.others)
	c.quorum = len(cfg.peers)/2 + 1

	for i := 1; i < len(ents); i++ {
		if ents[i].Index != ents[i-1].Index+1 {
			return nil, fmt.Errorf("raft: loaded log not contiguous at %d", ents[i].Index)
		}
	}
	switch {
	case snap == nil:
		if len(ents) > 0 && ents[0].Index != 1 {
			return nil, fmt.Errorf("raft: loaded log starts at %d without a snapshot", ents[0].Index)
		}
		c.log = newRaftLog(0, 0, ents)
	case len(ents) == 0 || ents[0].Index == snap.Meta.Index+1:
		c.log = newRaftLog(snap.Meta.Index, snap.Meta.Term, ents)
	case ents[0].Index <= snap.Meta.Index:
		k := snap.Meta.Index - ents[0].Index
		if k >= uint64(len(ents)) || ents[k].Term != snap.Meta.Term {
			return nil, fmt.Errorf("raft: loaded log does not contain snapshot position %d/%d", snap.Meta.Index, snap.Meta.Term)
		}
		c.log = newRaftLog(ents[0].Index, ents[0].Term, ents[1:])
	default:
		return nil, fmt.Errorf("raft: gap between snapshot %d and log start %d", snap.Meta.Index, ents[0].Index)
	}
	if snap != nil {
		c.snap = snap
		c.commit = snap.Meta.Index
		c.applying = snap.Meta.Index
	}
	if c.log.lastTerm() > hs.Term {
		return nil, fmt.Errorf("raft: hard state term %d is behind last log term %d", hs.Term, c.log.lastTerm())
	}
	c.term, c.votedFor, c.persisted = hs.Term, hs.VotedFor, hs
	c.becomeFollower(c.term, "")
	return c, nil
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

func (c *core) tick() {
	c.checkNotInReady()
	c.tickForwards()
	if c.role == Leader {
		c.tickLeader()
		return
	}
	c.electionElapsed++
	if c.quorum == 1 || c.electionElapsed >= c.randomizedTimeout {
		c.electionElapsed = 0
		c.becomePreCandidate()
		return
	}
	if (c.role == PreCandidate || c.role == Candidate) && c.electionElapsed%c.cfg.heartbeatTicks == 0 {
		// Reissue unanswered requests (§5.2): a lost request should not
		// cost a whole election timeout. Granting is idempotent.
		c.requestVotes()
	}
}

func (c *core) tickLeader() {
	c.heartbeatElapsed++
	c.electionElapsed++
	if c.electionElapsed >= c.cfg.electionTicks {
		c.electionElapsed = 0
		active := 1
		for _, p := range c.others {
			pr := c.prs[p]
			if pr.recentActive {
				active++
			}
			pr.recentActive = false
		}
		if active < c.quorum {
			// CheckQuorum: we may be on the minority side of a partition.
			c.becomeFollower(c.term, "")
			return
		}
	}
	for _, p := range c.others {
		pr := c.prs[p]
		if pr.state == stateSnapshot {
			pr.snapshotTicks++
			if pr.snapshotTicks >= snapshotRetryElections*c.cfg.electionTicks {
				pr.becomeProbe()
				c.sendAppend(p)
			}
		}
	}
	if c.heartbeatElapsed >= c.cfg.heartbeatTicks {
		c.heartbeatElapsed = 0
		for _, p := range c.others {
			c.heartbeat(p)
		}
	}
}

func (c *core) tickForwards() {
	if len(c.forwards) == 0 {
		return
	}
	var expired []uint64
	for id, f := range c.forwards {
		f.ticks++
		limit := propForwardElections
		if f.read {
			limit = readForwardElections
		}
		if f.ticks >= limit*c.cfg.electionTicks {
			expired = append(expired, id)
		}
	}
	slices.Sort(expired)
	for _, id := range expired {
		c.failForward(id, "forwarded request timed out")
	}
}

func (c *core) step(m Message) {
	c.checkNotInReady()
	if m.To != c.id || m.From == c.id || !c.isPeer(m.From) {
		return
	}
	switch m.Type {
	case MsgProp:
		c.handleForwardedProp(m)
		return
	case MsgPropResp:
		c.handlePropResp(m)
		return
	case MsgReadIndex:
		if c.role != Leader {
			c.send(Message{Type: MsgReadIndexResp, To: m.From, RequestID: m.RequestID, Error: "not leader"})
			return
		}
		c.leaderRead(readReq{from: m.From, id: m.RequestID})
		return
	case MsgReadIndexResp:
		c.handleReadIndexResp(m)
		return
	}

	switch {
	case m.Term > c.term:
		switch {
		case m.Type == MsgPreVote:
			// Pre-votes never change our term.
		case m.Type == MsgPreVoteResp && !m.Reject:
			// A granted pre-vote carries the term we would campaign in.
		case m.Type == MsgVote && c.inLease():
			// Leader stickiness: we heard from a leader recently, so this
			// candidate cannot have a quorum that lost the leader. Ignore it
			// entirely (do not even adopt its term).
			return
		default:
			leader := ""
			if m.Type == MsgApp || m.Type == MsgSnap {
				leader = m.From
			}
			c.becomeFollower(m.Term, leader)
		}
	case m.Term < c.term:
		switch m.Type {
		case MsgApp, MsgSnap:
			// The sender believes it leads an older term. Tell it our term:
			// with CheckQuorum and stickiness, a node stranded in a higher
			// term could otherwise never rejoin. LogIndex 0 makes this
			// reject harmless if the sender happens to reach our term.
			c.send(Message{Type: MsgAppResp, To: m.From, Term: c.term, Reject: true})
		case MsgPreVote:
			c.send(Message{Type: MsgPreVoteResp, To: m.From, Term: c.term, Reject: true})
		}
		return
	}

	switch m.Type {
	case MsgPreVote:
		c.handlePreVote(m)
		return
	case MsgVote:
		c.handleVote(m)
		return
	}

	switch c.role {
	case Follower:
		switch m.Type {
		case MsgApp:
			c.leader = m.From
			c.electionElapsed = 0
			c.handleAppend(m)
		case MsgSnap:
			c.leader = m.From
			c.electionElapsed = 0
			c.handleSnapshot(m)
		}
	case PreCandidate, Candidate:
		switch m.Type {
		case MsgApp:
			c.becomeFollower(m.Term, m.From)
			c.handleAppend(m)
		case MsgSnap:
			c.becomeFollower(m.Term, m.From)
			c.handleSnapshot(m)
		case MsgPreVoteResp:
			if c.role != PreCandidate {
				return
			}
			if !m.Reject && m.Term != c.term+1 {
				return // stale grant from an earlier round
			}
			won, lost := c.poll(m.From, !m.Reject)
			if won {
				c.becomeCandidate()
			} else if lost {
				c.becomeFollower(c.term, "")
			}
		case MsgVoteResp:
			if c.role != Candidate {
				return
			}
			won, lost := c.poll(m.From, !m.Reject)
			if won {
				c.becomeLeader()
			} else if lost {
				c.becomeFollower(c.term, "")
			}
		}
	case Leader:
		pr := c.prs[m.From]
		pr.recentActive = true
		switch m.Type {
		case MsgAppResp:
			c.handleAppResp(m, pr)
		case MsgSnapResp:
			c.handleSnapResp(m, pr)
		}
	}
}

// propose submits a local proposal. The outcome is reported through a ready:
// either as a committed-entry waiter (leader), or as a propResult.
func (c *core) propose(id uint64, data []byte) {
	c.checkNotInReady()
	switch {
	case c.role == Leader:
		idx := c.appendProposal(data)
		c.waiters[idx] = waiter{term: c.term, id: id}
	case c.leader != "":
		c.forwards[id] = &forward{to: c.leader}
		c.send(Message{Type: MsgProp, To: c.leader, RequestID: id, Data: data})
	default:
		// The command never left this node: safe to retry.
		c.propResults = append(c.propResults, propResult{id: id, err: ErrNoLeader})
	}
}

// readIndex requests a linearizable read index for a local caller; the
// answer arrives as a readResult.
func (c *core) readIndex(id uint64) {
	c.checkNotInReady()
	switch {
	case c.role == Leader:
		c.leaderRead(readReq{id: id})
	case c.leader != "":
		c.forwards[id] = &forward{read: true, to: c.leader}
		c.send(Message{Type: MsgReadIndex, To: c.leader, RequestID: id})
	default:
		c.readResults = append(c.readResults, readResult{id: id, err: ErrNoLeader})
	}
}

// compact records a snapshot the driver has made durable and drops log
// entries up to compactTo (which trails the snapshot so that slightly slow
// followers can still be served from the log).
func (c *core) compact(snap *Snapshot, compactTo uint64) {
	c.checkNotInReady()
	if c.snap != nil && snap.Meta.Index <= c.snap.Meta.Index {
		return
	}
	if !c.log.matchTerm(snap.Meta.Index, snap.Meta.Term) || snap.Meta.Index > c.applying {
		panic(fmt.Sprintf("raft: local snapshot %d/%d not in applied log", snap.Meta.Index, snap.Meta.Term))
	}
	c.snap = snap
	compactTo = min(compactTo, snap.Meta.Index, c.log.stableIndex())
	c.log.compact(compactTo)
}

// ---------------------------------------------------------------------------
// Ready / advance
// ---------------------------------------------------------------------------

func (c *core) hasReady() bool {
	if c.inReady {
		return false
	}
	return c.bcastPending || c.readRound ||
		c.hardState() != c.persisted || c.pendingSnap != nil ||
		c.log.unstable <= c.log.lastIndex() ||
		min(c.commit, c.log.stableIndex()) > c.applying ||
		len(c.msgs) > 0 || len(c.propResults) > 0 || len(c.readResults) > 0
}

func (c *core) ready() ready {
	c.checkNotInReady()
	c.flush()
	var rd ready
	if hs := c.hardState(); hs != c.persisted {
		rd.hardState = &hs
	}
	rd.snapshot = c.pendingSnap
	rd.entries = c.log.unstableEntries()
	rd.stable = c.log.stableIndex()
	// Only entries that were durable before this ready are applied, so the
	// driver may apply them before (or while) persisting the new ones, and a
	// local snapshot never covers an entry the local log might not have.
	if hi := min(c.commit, c.log.stableIndex()); hi > c.applying {
		rd.committed = c.log.slice(c.applying+1, hi+1, maxApplyBytes)
		for _, e := range rd.committed {
			w, ok := c.waiters[e.Index]
			if !ok {
				continue
			}
			delete(c.waiters, e.Index)
			if w.from != "" {
				delete(c.remoteProps, remoteKey{w.from, w.id})
			}
			if w.term == e.Term {
				rd.waiters = append(rd.waiters, entryWaiter{index: e.Index, waiter: w})
			} else {
				c.failWaiter(w, "entry was superseded")
			}
		}
		c.applying = rd.committed[len(rd.committed)-1].Index
	}
	rd.messages, c.msgs = c.msgs, nil
	rd.propResults, c.propResults = c.propResults, nil
	rd.readResults, c.readResults = c.readResults, nil
	c.inReady = true
	return rd
}

// takeEarly removes from rd and returns the messages that may be sent BEFORE
// rd is persisted, in a ready that changes neither hard state nor snapshot:
// the leader's MsgApps, and acknowledgements that claim only entries that
// were durable before this ready. The leader then writes its new entries
// while the followers write theirs (Raft thesis §10.2.1), so a commit waits
// for one disk flush instead of two in series, and a follower answers a
// heartbeat (a read-index round, CheckQuorum) without waiting for the write
// of entries that arrived with it. This is safe:
//   - A MsgApp promises nothing about the sender's durable state. Its entries
//     are for the follower to persist and acknowledge itself; its Commit is
//     at most c.commit, which maybeCommit derives only from durable copies
//     (the leader's own vote covers only stable entries, a follower's only
//     what it acknowledged after persisting); LogIndex/LogTerm only drive
//     the follower's consistency check against entries this leader created.
//   - If the leader crashes before its own write is durable, followers may
//     hold entries of its term that it lost. It restarts as a follower in
//     that same term (it became leader on grants answering vote requests
//     that were sent only after its hard state was durable, and a ready that
//     changes hard state sends nothing early), so it can never lead that
//     term again and no different entry can ever appear at the same (index,
//     term). Its lost copies were never counted towards commitment, so those
//     entries are committed only if a quorum of followers durably holds
//     them, which is exactly Raft's rule.
//   - An accepting MsgAppResp with MatchIndex <= rd.stable claims only
//     entries that were already durable (truncation lowers rd.stable, so
//     entries this ready overwrites are never claimed), in a term that is
//     already durable; its ReadCtx and Term say nothing this ready persists.
//   - Everything else waits: vote grants, acknowledgements of entries this
//     ready writes and snapshot acknowledgements promise durable state,
//     rejections carry hints about the unpersisted log, vote requests travel
//     with a hard state change, and read-index and proposal results stay
//     behind the state they report.
//
// The node loop takes no input until a ready has been carried out, so no
// acknowledgement of an early MsgApp is processed before the leader's own
// write has completed. The stable-only rule in maybeCommit is what would
// keep this safe if that ever changed.
func (rd *ready) takeEarly() (early []Message) {
	if rd.hardState != nil || rd.snapshot != nil {
		return nil
	}
	var late []Message
	for _, m := range rd.messages {
		if m.Type == MsgApp || (m.Type == MsgAppResp && !m.Reject && m.MatchIndex <= rd.stable) {
			early = append(early, m)
		} else {
			late = append(late, m)
		}
	}
	rd.messages = late
	return early
}

// advance tells the core that rd has been fully carried out.
func (c *core) advance(rd ready) {
	if !c.inReady {
		panic("raft: advance without ready")
	}
	c.inReady = false
	if rd.hardState != nil {
		c.persisted = *rd.hardState
	}
	if rd.snapshot != nil && c.pendingSnap == rd.snapshot {
		c.pendingSnap = nil
	}
	if n := len(rd.entries); n > 0 {
		c.log.stableTo(rd.entries[n-1].Index)
	}
	if c.role == Leader && c.maybeCommit() {
		c.bcastPending = true
	}
}

// flush sends what was batched while handling the last group of inputs: one
// append round for new proposals / commit changes, and one heartbeat round
// for read-index requests that arrived.
func (c *core) flush() {
	if c.role != Leader {
		c.bcastPending, c.readRound = false, false
		return
	}
	if c.readRound {
		c.readRound = false
		c.readSeq++
		for _, p := range c.others {
			c.heartbeat(p)
		}
	}
	if c.bcastPending {
		c.bcastPending = false
		for _, p := range c.others {
			c.sendAppend(p)
			c.maybeSendCommit(p)
		}
	}
}

func (c *core) hardState() HardState { return HardState{Term: c.term, VotedFor: c.votedFor} }

func (c *core) checkNotInReady() {
	if c.inReady {
		panic("raft: core used between ready() and advance()")
	}
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

// setTerm moves to a higher term. Messages queued under the old term are
// dropped: they may promise state (an acknowledged entry, a vote) that the
// term change has already overwritten in memory and that will therefore
// never be persisted. They are best-effort anyway.
func (c *core) setTerm(t uint64) {
	if t < c.term {
		panic(fmt.Sprintf("raft: term going backwards %d -> %d", c.term, t))
	}
	if t == c.term {
		return
	}
	c.term = t
	c.votedFor = ""
	kept := c.msgs[:0]
	for _, m := range c.msgs {
		if m.Term >= t || isRequestType(m.Type) {
			kept = append(kept, m)
		}
	}
	c.msgs = kept
	c.failAllForwards("leader changed")
}

func isRequestType(t MsgType) bool {
	return t == MsgProp || t == MsgPropResp || t == MsgReadIndex || t == MsgReadIndexResp
}

func (c *core) resetTimers() {
	c.electionElapsed = 0
	c.heartbeatElapsed = 0
	c.randomizedTimeout = c.cfg.electionTicks + c.cfg.rng.IntN(c.cfg.electionTicks)
}

func (c *core) becomeFollower(term uint64, leader string) {
	c.setTerm(term)
	if c.role == Leader {
		c.abandonLeadership()
	}
	c.role = Follower
	c.leader = leader
	c.votes = nil
	c.resetTimers()
}

func (c *core) becomePreCandidate() {
	c.role = PreCandidate
	c.leader = ""
	c.votes = map[string]bool{c.id: true}
	c.resetTimers()
	if len(c.votes) >= c.quorum {
		c.becomeCandidate()
		return
	}
	c.requestVotes()
}

// requestVotes sends a (pre-)vote request to every peer that has not answered.
func (c *core) requestVotes() {
	t, term := MsgVote, c.term
	if c.role == PreCandidate {
		t, term = MsgPreVote, c.term+1
	}
	for _, p := range c.others {
		if _, answered := c.votes[p]; !answered {
			c.send(Message{Type: t, To: p, Term: term, LogIndex: c.log.lastIndex(), LogTerm: c.log.lastTerm()})
		}
	}
}

func (c *core) becomeCandidate() {
	c.setTerm(c.term + 1)
	c.votedFor = c.id
	c.role = Candidate
	c.leader = ""
	c.votes = map[string]bool{c.id: true}
	c.resetTimers()
	if len(c.votes) >= c.quorum {
		c.becomeLeader()
		return
	}
	c.requestVotes()
}

func (c *core) becomeLeader() {
	c.role = Leader
	c.leader = c.id
	c.votes = nil
	c.resetTimers()
	c.prs = make(map[string]*progress, len(c.others))
	next := c.log.lastIndex() + 1
	for _, p := range c.others {
		c.prs[p] = &progress{next: next}
	}
	c.pendingReads, c.deferredReads = nil, nil
	c.readRound = false
	c.log.append(Entry{Index: next, Term: c.term, Type: EntryNoop})
	c.bcastPending = true
}

// abandonLeadership fails everything that was waiting on this node's
// leadership. Proposals may still commit under a later leader, so their
// outcome is unknown; reads simply failed and are safe to retry.
func (c *core) abandonLeadership() {
	for _, i := range slices.Sorted(maps.Keys(c.waiters)) {
		c.failWaiter(c.waiters[i], "leadership lost")
	}
	clear(c.waiters)
	clear(c.remoteProps)
	for _, r := range c.deferredReads {
		c.failRead(r, "leadership lost")
	}
	for _, r := range c.pendingReads {
		c.failRead(r, "leadership lost")
	}
	c.pendingReads, c.deferredReads = nil, nil
	c.prs = nil
	c.readRound, c.bcastPending = false, false
}

func (c *core) inLease() bool {
	return c.leader != "" && c.electionElapsed < c.cfg.electionTicks
}

func (c *core) poll(from string, granted bool) (won, lost bool) {
	c.votes[from] = granted
	g, r := 0, 0
	for _, v := range c.votes {
		if v {
			g++
		} else {
			r++
		}
	}
	n := len(c.others) + 1
	return g >= c.quorum, r > n-c.quorum
}

// upToDate reports whether a candidate's log is at least as up to date as
// ours (§5.4.1): compare last terms, then last indexes. Our last entry may
// not be durable yet, but any answer we send is.
func (c *core) upToDate(lastIndex, lastTerm uint64) bool {
	lt := c.log.lastTerm()
	return lastTerm > lt || (lastTerm == lt && lastIndex >= c.log.lastIndex())
}

func (c *core) handlePreVote(m Message) {
	// m.Term is the term the sender would campaign in.
	grant := m.Term > c.term && !c.inLease() && c.upToDate(m.LogIndex, m.LogTerm)
	if grant {
		c.send(Message{Type: MsgPreVoteResp, To: m.From, Term: m.Term})
	} else {
		c.send(Message{Type: MsgPreVoteResp, To: m.From, Term: c.term, Reject: true})
	}
}

func (c *core) handleVote(m Message) {
	// After the term preamble, m.Term == c.term.
	canVote := c.votedFor == m.From || (c.votedFor == "" && c.leader == "")
	if canVote && c.upToDate(m.LogIndex, m.LogTerm) {
		// The vote is persisted (hard state) before this grant is sent.
		c.votedFor = m.From
		c.electionElapsed = 0
		c.send(Message{Type: MsgVoteResp, To: m.From, Term: c.term})
		return
	}
	c.send(Message{Type: MsgVoteResp, To: m.From, Term: c.term, Reject: true})
}

// ---------------------------------------------------------------------------
// Follower: AppendEntries / InstallSnapshot
// ---------------------------------------------------------------------------

func (c *core) handleAppend(m Message) {
	resp := Message{Type: MsgAppResp, To: m.From, Term: c.term, LogIndex: m.LogIndex, ReadCtx: m.ReadCtx}
	for i, e := range m.Entries {
		if e.Index != m.LogIndex+1+uint64(i) || e.Term > m.Term {
			return // malformed; drop
		}
	}
	if m.LogIndex < c.commit {
		// Everything up to our commit index is committed and therefore
		// identical in the leader's log; tell the leader where we are.
		resp.MatchIndex = c.commit
		c.send(resp)
		return
	}
	if !c.log.matchTerm(m.LogIndex, m.LogTerm) {
		resp.Reject = true
		if m.LogIndex > c.log.lastIndex() {
			resp.ConflictIdx = c.log.lastIndex() + 1
		} else {
			// m.LogIndex > commit >= offset, so its term is known. Point the
			// leader at the first index of the conflicting term (entries at
			// or below commit cannot conflict).
			ct, _ := c.log.term(m.LogIndex)
			idx := m.LogIndex
			for idx-1 > c.commit {
				t, _ := c.log.term(idx - 1)
				if t != ct {
					break
				}
				idx--
			}
			resp.ConflictTerm, resp.ConflictIdx = ct, idx
		}
		c.send(resp)
		return
	}
	for i, e := range m.Entries {
		if c.log.matchTerm(e.Index, e.Term) {
			continue
		}
		if e.Index <= c.commit {
			panic(fmt.Sprintf("raft: %s: leader %s overwrites committed entry %d", c.id, m.From, e.Index))
		}
		c.log.truncateAndAppend(m.Entries[i:])
		break
	}
	lastNew := m.LogIndex + uint64(len(m.Entries))
	if nc := min(m.Commit, lastNew); nc > c.commit {
		c.commit = nc
	}
	resp.MatchIndex = lastNew
	c.send(resp)
}

func (c *core) handleSnapshot(m Message) {
	s := m.Snap
	if s == nil {
		return
	}
	resp := Message{Type: MsgSnapResp, To: m.From, Term: c.term}
	switch {
	case s.Meta.Index <= c.commit:
		resp.MatchIndex = c.commit
	case c.log.matchTerm(s.Meta.Index, s.Meta.Term):
		// We already hold the snapshot's last entry, so by Log Matching our
		// log agrees with the leader up to it, and it is committed. Keep the
		// log (and whatever follows) rather than discarding it.
		c.commit = s.Meta.Index
		resp.MatchIndex = s.Meta.Index
	default:
		c.log.restore(s.Meta.Index, s.Meta.Term)
		c.commit = s.Meta.Index
		c.applying = s.Meta.Index
		c.snap = s
		c.pendingSnap = s
		resp.MatchIndex = s.Meta.Index
	}
	c.send(resp)
}

// ---------------------------------------------------------------------------
// Leader: replication
// ---------------------------------------------------------------------------

func (c *core) appendProposal(data []byte) uint64 {
	idx := c.log.lastIndex() + 1
	c.log.append(Entry{Index: idx, Term: c.term, Type: EntryNormal, Data: data})
	c.bcastPending = true
	return idx
}

func (c *core) handleAppResp(m Message, pr *progress) {
	if m.ReadCtx > pr.ackedCtx {
		pr.ackedCtx = m.ReadCtx
		c.releaseReads()
	}
	if m.Reject {
		if pr.maybeDecrTo(m.LogIndex, c.hintNext(m)) {
			c.sendAppend(m.From)
		}
		return
	}
	if m.MatchIndex > c.log.lastIndex() {
		return // cannot be a response to anything we sent in this term
	}
	if pr.state == stateProbe {
		pr.probeSent = false
	}
	if pr.maybeUpdate(m.MatchIndex) {
		switch pr.state {
		case stateProbe:
			pr.becomeReplicate()
		case stateSnapshot:
			if pr.match >= c.log.offset {
				pr.becomeReplicate()
			}
		case stateReplicate:
			pr.freeInflight(pr.match)
		}
		if c.maybeCommit() {
			c.bcastPending = true
		}
	}
	c.sendAppend(m.From)
	c.maybeSendCommit(m.From)
}

func (c *core) handleSnapResp(m Message, pr *progress) {
	if m.MatchIndex > c.log.lastIndex() {
		return
	}
	pr.maybeUpdate(m.MatchIndex)
	if pr.state == stateSnapshot && pr.match >= c.log.offset {
		pr.becomeReplicate()
	} else if pr.state == stateSnapshot && pr.match >= pr.pendingSnapshot {
		pr.becomeProbe()
	}
	if c.maybeCommit() {
		c.bcastPending = true
	}
	c.sendAppend(m.From)
	c.maybeSendCommit(m.From)
}

// hintNext turns a follower's conflict hints into a guess for its next index.
func (c *core) hintNext(m Message) uint64 {
	if m.ConflictTerm == 0 {
		return m.ConflictIdx
	}
	// If we have entries of ConflictTerm, the follower's log matches ours up
	// to our last one of that term; otherwise skip the follower's whole run
	// of that term.
	for i := min(m.LogIndex, c.log.lastIndex()); i >= c.log.offset; i-- {
		t, _ := c.log.term(i)
		if t == m.ConflictTerm {
			return i + 1
		}
		if t < m.ConflictTerm || i == 0 {
			break
		}
	}
	return m.ConflictIdx
}

// sendAppend sends entries to a follower if it is not paused and there is
// something to send (or, in probe state, if the follower is not known to be
// caught up).
func (c *core) sendAppend(to string) {
	pr := c.prs[to]
	last := c.log.lastIndex()
	for !pr.paused(c.cfg.maxInflight) {
		if pr.state == stateReplicate && pr.next > last {
			return
		}
		if pr.state == stateProbe && pr.match >= last {
			return
		}
		prev := pr.next - 1
		prevTerm, ok := c.log.term(prev)
		if !ok {
			c.sendSnapshot(to, pr)
			return
		}
		var ents []Entry
		if pr.next <= last {
			ents = c.log.slice(pr.next, last+1, c.cfg.maxAppendBytes)
		}
		lastSent := prev + uint64(len(ents))
		c.send(Message{
			Type: MsgApp, To: to, Term: c.term,
			LogIndex: prev, LogTerm: prevTerm, Entries: ents,
			Commit: c.commit, ReadCtx: c.readSeq,
		})
		pr.commitSent = max(pr.commitSent, min(c.commit, lastSent))
		if pr.state == stateProbe {
			pr.probeSent = true
			return
		}
		pr.next = lastSent + 1
		pr.inflight = append(pr.inflight, lastSent)
	}
}

func (c *core) sendSnapshot(to string, pr *progress) {
	if c.snap == nil {
		panic(fmt.Sprintf("raft: %s: log compacted at %d but no snapshot", c.id, c.log.offset))
	}
	pr.becomeSnapshot(c.snap.Meta.Index)
	c.send(Message{Type: MsgSnap, To: to, Term: c.term, Snap: c.snap})
}

// heartbeat sends an empty MsgApp anchored at the follower's match index,
// which the follower always accepts; it carries commit (clamped by the
// follower to match) and the current ReadCtx. It also detects a stalled
// pipeline (lost MsgApps) and probes the end of it.
func (c *core) heartbeat(to string) {
	pr := c.prs[to]
	prev := pr.match
	prevTerm, ok := c.log.term(prev)
	if !ok {
		prev, prevTerm = 0, 0
	}
	c.send(Message{Type: MsgApp, To: to, Term: c.term, LogIndex: prev, LogTerm: prevTerm, Commit: c.commit, ReadCtx: c.readSeq})
	pr.commitSent = max(pr.commitSent, min(c.commit, prev))

	if pr.state == stateReplicate && pr.match < c.log.lastIndex() && pr.match == pr.hbMatch {
		// No progress for a whole heartbeat interval. Either the follower is
		// slow or something was lost; an empty MsgApp at next-1 is accepted
		// in the first case and rejected (sending us back to probing) in the
		// second.
		if len(pr.inflight) >= c.cfg.maxInflight {
			pr.inflight = pr.inflight[1:]
		}
		if t, ok := c.log.term(pr.next - 1); ok {
			c.send(Message{Type: MsgApp, To: to, Term: c.term, LogIndex: pr.next - 1, LogTerm: t, Commit: c.commit, ReadCtx: c.readSeq})
		} else {
			pr.becomeProbe()
			c.sendAppend(to)
		}
	}
	pr.hbMatch = pr.match
}

// maybeSendCommit makes sure a follower learns a commit index it can use.
func (c *core) maybeSendCommit(to string) {
	pr := c.prs[to]
	if min(c.commit, pr.match) > pr.commitSent {
		if t, ok := c.log.term(pr.match); ok {
			c.send(Message{Type: MsgApp, To: to, Term: c.term, LogIndex: pr.match, LogTerm: t, Commit: c.commit, ReadCtx: c.readSeq})
			pr.commitSent = min(c.commit, pr.match)
		}
	}
}

// maybeCommit advances commit to the highest index held durably by a quorum,
// but only if that entry is from the current term: an entry from an earlier
// term can be replicated on a majority and still be overwritten (Figure 8).
// It becomes committed indirectly, when an entry of the current term after it
// commits.
func (c *core) maybeCommit() bool {
	matches := make([]uint64, 0, len(c.others)+1)
	matches = append(matches, c.log.stableIndex()) // our own vote counts only for durable entries
	for _, p := range c.others {
		matches = append(matches, c.prs[p].match)
	}
	slices.Sort(matches)
	n := matches[len(matches)-c.quorum]
	if n <= c.commit {
		return false
	}
	if t, ok := c.log.term(n); !ok || t != c.term {
		return false
	}
	first := !c.committedInTerm()
	c.commit = n
	if first {
		deferred := c.deferredReads
		c.deferredReads = nil
		for _, r := range deferred {
			c.leaderRead(r)
		}
	}
	return true
}

func (c *core) committedInTerm() bool {
	t, ok := c.log.term(c.commit)
	return ok && t == c.term
}

// ---------------------------------------------------------------------------
// Read index
// ---------------------------------------------------------------------------

func (c *core) leaderRead(r readReq) {
	if !c.committedInTerm() {
		// Until an entry of this term commits, our commit index may be
		// behind entries committed by earlier leaders.
		c.deferredReads = append(c.deferredReads, r)
		return
	}
	r.index = c.commit
	if c.quorum == 1 {
		c.deliverRead(r)
		return
	}
	// Any acknowledgement echoing >= ctx answers a message sent after now.
	r.ctx = c.readSeq + 1
	c.pendingReads = append(c.pendingReads, r)
	c.readRound = true
}

func (c *core) releaseReads() {
	for len(c.pendingReads) > 0 {
		r := c.pendingReads[0]
		acks := 1
		for _, p := range c.others {
			if c.prs[p].ackedCtx >= r.ctx {
				acks++
			}
		}
		if acks < c.quorum {
			return
		}
		c.pendingReads = c.pendingReads[1:]
		c.deliverRead(r)
	}
}

func (c *core) deliverRead(r readReq) {
	if r.from == "" {
		c.readResults = append(c.readResults, readResult{id: r.id, index: r.index})
		return
	}
	c.send(Message{Type: MsgReadIndexResp, To: r.from, RequestID: r.id, Index: r.index})
}

func (c *core) failRead(r readReq, why string) {
	if r.from == "" {
		c.readResults = append(c.readResults, readResult{id: r.id, err: fmt.Errorf("%w: read index: %s", ErrNoLeader, why)})
		return
	}
	c.send(Message{Type: MsgReadIndexResp, To: r.from, RequestID: r.id, Error: why})
}

func (c *core) handleReadIndexResp(m Message) {
	f, ok := c.forwards[m.RequestID]
	if !ok || !f.read || f.to != m.From {
		return
	}
	delete(c.forwards, m.RequestID)
	if m.Error != "" {
		c.readResults = append(c.readResults, readResult{id: m.RequestID, err: fmt.Errorf("%w: read index: leader %s: %s", ErrNoLeader, m.From, m.Error)})
		return
	}
	c.readResults = append(c.readResults, readResult{id: m.RequestID, index: m.Index})
}

// ---------------------------------------------------------------------------
// Proposals and forwarding
// ---------------------------------------------------------------------------

func (c *core) handleForwardedProp(m Message) {
	if c.role != Leader {
		// Not "certainly not proposed" from the sender's point of view: this
		// MsgProp may be a duplicate of one we appended while leader.
		c.send(Message{Type: MsgPropResp, To: m.From, RequestID: m.RequestID, Error: "not leader"})
		return
	}
	key := remoteKey{m.From, m.RequestID}
	if _, dup := c.remoteProps[key]; dup {
		return // duplicate delivery of an in-flight proposal
	}
	idx := c.appendProposal(m.Data)
	c.waiters[idx] = waiter{term: c.term, from: m.From, id: m.RequestID}
	c.remoteProps[key] = struct{}{}
}

func (c *core) handlePropResp(m Message) {
	f, ok := c.forwards[m.RequestID]
	if !ok || f.read || f.to != m.From {
		return
	}
	delete(c.forwards, m.RequestID)
	if m.Error != "" {
		c.propResults = append(c.propResults, propResult{id: m.RequestID, err: fmt.Errorf("%w: leader %s: %s", ErrUnknownOutcome, m.From, m.Error)})
		return
	}
	c.propResults = append(c.propResults, propResult{id: m.RequestID, index: m.Index, data: m.Data})
}

func (c *core) failWaiter(w waiter, why string) {
	if w.from == "" {
		c.propResults = append(c.propResults, propResult{id: w.id, err: fmt.Errorf("%w: %s", ErrUnknownOutcome, why)})
		return
	}
	c.send(Message{Type: MsgPropResp, To: w.from, RequestID: w.id, Error: why})
}

func (c *core) failForward(id uint64, why string) {
	f := c.forwards[id]
	delete(c.forwards, id)
	if f.read {
		c.readResults = append(c.readResults, readResult{id: id, err: fmt.Errorf("%w: read index: %s", ErrNoLeader, why)})
	} else {
		c.propResults = append(c.propResults, propResult{id: id, err: fmt.Errorf("%w: %s", ErrUnknownOutcome, why)})
	}
}

func (c *core) failAllForwards(why string) {
	for _, id := range slices.Sorted(maps.Keys(c.forwards)) {
		c.failForward(id, why)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *core) send(m Message) {
	m.From = c.id
	if isRequestType(m.Type) {
		m.Term = c.term
	}
	c.msgs = append(c.msgs, m)
}

func (c *core) isPeer(id string) bool {
	_, ok := slices.BinarySearch(c.others, id)
	return ok
}

func (c *core) snapshotIndex() uint64 {
	if c.snap == nil {
		return 0
	}
	return c.snap.Meta.Index
}
