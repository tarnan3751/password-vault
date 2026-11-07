package raft

// progressState is how the leader is currently feeding one follower.
type progressState uint8

const (
	// stateProbe: the leader does not know where the follower's log diverges.
	// It sends one MsgApp at a time and waits for the answer (or for the next
	// heartbeat response) before sending another.
	stateProbe progressState = iota
	// stateReplicate: the follower's log is known to match up to match; the
	// leader streams entries optimistically, bounded by maxInflight.
	stateReplicate
	// stateSnapshot: the entries the follower needs were compacted away; a
	// MsgSnap is outstanding and nothing else is sent until it is answered or
	// the retry timer expires.
	stateSnapshot
)

// progress is the leader's view of one follower.
type progress struct {
	match uint64 // highest index known to be durably replicated on the follower
	next  uint64 // next index to send

	state           progressState
	probeSent       bool     // probe: a MsgApp is outstanding
	inflight        []uint64 // replicate: last index of each outstanding MsgApp
	pendingSnapshot uint64   // snapshot: index of the MsgSnap sent
	snapshotTicks   int      // snapshot: ticks since it was sent

	recentActive bool   // heard from since the last CheckQuorum round
	ackedCtx     uint64 // highest ReadCtx the follower has echoed in this term
	commitSent   uint64 // highest commit index the follower can have learned from us
	hbMatch      uint64 // match at the previous heartbeat, to detect a stalled pipeline
}

func (p *progress) becomeProbe() {
	p.state = stateProbe
	p.next = p.match + 1
	p.probeSent = false
	p.inflight = nil
	p.pendingSnapshot = 0
}

func (p *progress) becomeReplicate() {
	p.state = stateReplicate
	p.next = p.match + 1
	p.probeSent = false
	p.inflight = p.inflight[:0]
	p.pendingSnapshot = 0
}

func (p *progress) becomeSnapshot(index uint64) {
	p.state = stateSnapshot
	p.pendingSnapshot = index
	p.snapshotTicks = 0
	p.probeSent = false
	p.inflight = nil
}

// maybeUpdate records a successful acknowledgement of n.
func (p *progress) maybeUpdate(n uint64) bool {
	updated := false
	if n > p.match {
		p.match = n
		updated = true
	}
	if p.next < n+1 {
		p.next = n + 1
	}
	return updated
}

// maybeDecrTo handles a rejection of a MsgApp whose LogIndex was rejected.
// hintNext is the leader's best guess for the follower's next index, derived
// from the follower's conflict hints. Returns false for stale rejections.
func (p *progress) maybeDecrTo(rejected, hintNext uint64) bool {
	switch p.state {
	case stateReplicate:
		if rejected <= p.match {
			return false
		}
		p.becomeProbe()
	case stateProbe:
		if rejected != p.next-1 {
			return false
		}
		p.probeSent = false
	default:
		return false
	}
	// next must not exceed the rejected position (the follower does not have
	// it) and must stay above match (the follower certainly has that).
	n := min(rejected, hintNext)
	p.next = max(n, p.match+1)
	return true
}

func (p *progress) freeInflight(upTo uint64) {
	i := 0
	for i < len(p.inflight) && p.inflight[i] <= upTo {
		i++
	}
	p.inflight = p.inflight[i:]
}

func (p *progress) paused(maxInflight int) bool {
	switch p.state {
	case stateProbe:
		return p.probeSent
	case stateReplicate:
		return len(p.inflight) >= maxInflight
	default:
		return true
	}
}
