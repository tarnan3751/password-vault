// Package raft is a from-scratch implementation of the Raft consensus
// algorithm (Ongaro & Ousterhout), written for the family password vault.
//
// This file is the CONTRACT between the consensus core and everything around
// it (durable storage, network transports, the replicated state machine and
// the HTTP server). The exported names and the semantics documented here are
// relied on by other packages; extend them if needed, but do not rename or
// weaken them.
//
// Architecture (see docs/DESIGN.md §3):
//
//	core     a deterministic, single-threaded Raft state machine: no clocks,
//	         no goroutines, no I/O. Inputs: Tick, Step(Message), proposals.
//	         Outputs: state to persist, messages to send, entries to apply.
//	node     the runtime that drives a core with real time, a Storage, a
//	         Transport and a StateMachine, and implements the Node interface.
//	Storage  durable log + hard state + snapshot (internal/raft/filestore for
//	         production, an in-memory implementation for tests).
//	Transport best-effort message passing between nodes
//	         (internal/raft/httptransport for production, an in-memory
//	         fault-injecting network for tests).
package raft

import (
	"context"
	"errors"
	"time"
)

// ---------------------------------------------------------------------------
// Log and persistent state
// ---------------------------------------------------------------------------

// EntryType distinguishes application commands from internal entries.
type EntryType uint8

const (
	// EntryNormal carries an application command; it is passed to
	// StateMachine.Apply once committed.
	EntryNormal EntryType = iota
	// EntryNoop is appended by a newly elected leader at the start of its
	// term. It is never passed to the state machine.
	EntryNoop
)

// Entry is one slot of the replicated log. Index starts at 1.
type Entry struct {
	Index uint64
	Term  uint64
	Type  EntryType
	Data  []byte
}

// HardState is the state that must be durable before a node answers any
// message that depends on it.
type HardState struct {
	Term     uint64
	VotedFor string // "" means no vote cast in Term
}

// SnapshotMeta identifies the last log entry covered by a snapshot.
type SnapshotMeta struct {
	Index uint64
	Term  uint64
}

// Snapshot is a serialized state machine plus the log position it covers.
type Snapshot struct {
	Meta SnapshotMeta
	Data []byte
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// Storage is the durable store of a single node. It is used by exactly one
// node and is called from a single goroutine at a time.
//
// DURABILITY: every mutating method must have made its effect crash-durable
// (fsync, including the containing directory where a file is created or
// renamed) before it returns nil. Raft's safety depends on this: a node that
// acknowledges an entry or a vote and then forgets it can cause committed
// data to be lost.
//
// A method that returns a non-nil error leaves the store in a state that is
// still safe to Load (either the old or the new state, never a mix). The
// node treats any Storage error as fatal and stops.
type Storage interface {
	// Load returns everything that was persisted. It is called once at
	// startup, before any other method.
	//
	// Guarantees on the returned values:
	//   - snap is nil if no snapshot was ever saved.
	//   - entries are contiguous and ascending by Index.
	//   - If snap == nil, entries is empty or starts at Index 1.
	//   - If snap != nil, entries is empty or entries[0].Index <= snap.Meta.Index+1
	//     (trailing entries at or before the snapshot may be retained), and
	//     if an entry with Index == snap.Meta.Index is present its Term equals
	//     snap.Meta.Term.
	//
	// RECOVERY RULE (this is what makes InstallSnapshot crash-atomic): if a
	// snapshot exists and the on-disk log is not provably a continuation of
	// it, Load discards the log. Concretely, with s = snap.Meta and f the
	// first on-disk log index:
	//   - f == s.Index+1                       -> keep the log
	//   - f <= s.Index and the log contains s.Index with Term == s.Term -> keep
	//   - f <= s.Index otherwise (entry missing or term mismatch)       -> discard all entries
	//   - f >  s.Index+1                       -> return an error (corruption)
	//
	// A torn final record (crash in the middle of an append) is silently
	// dropped: it was never acknowledged. Corruption anywhere else is an error.
	//
	// Consequently the node must accept, at startup: the newest snapshot
	// together with the OLD log when a crash interrupted InstallSnapshot and
	// that log happens to continue the snapshot; and entries at or below
	// snap.Meta.Index (what Compact(through < snapshot index) leaves). Those
	// entries are never re-applied: commit and applied start at the
	// snapshot index.
	Load() (hs HardState, snap *Snapshot, entries []Entry, err error)

	// SaveHardState durably replaces the hard state.
	SaveHardState(hs HardState) error

	// Append durably appends entries, which must be contiguous and ascending.
	// If the store already holds an entry with Index >= entries[0].Index,
	// every stored entry from entries[0].Index onward is discarded first
	// (conflict truncation), atomically with respect to crashes: after a
	// crash the log is either the old log or old-prefix + new entries (a
	// prefix of the new entries is acceptable; a mix of old suffix and new
	// entries is not).
	// entries[0].Index must be <= lastIndex+1 (no gaps), and >= 1. Appending
	// an empty slice is a no-op. Entries must not disagree with the latest
	// snapshot at its index (the node never appends at or below its commit
	// index, which is >= the snapshot index). Stores reject violations.
	Append(entries []Entry) error

	// SaveSnapshot durably stores snap as the latest snapshot, leaving the
	// log untouched. Used for local compaction (the log already contains
	// snap.Meta.Index with a matching term). Older snapshots may be deleted
	// once the new one is durable.
	//
	// PRECONDITION (rejected with an error otherwise): snap is not older than
	// the stored snapshot, and the log provably continues it: it contains
	// snap.Meta.Index with Term == snap.Meta.Term, or starts exactly at
	// snap.Meta.Index+1. Anything else would make Load's recovery rule
	// discard acknowledged entries.
	SaveSnapshot(snap Snapshot) error

	// InstallSnapshot durably stores snap as the latest snapshot and then
	// discards the ENTIRE log. Used when a follower receives a snapshot from
	// the leader that is ahead of, or conflicts with, its log. Because of the
	// recovery rule in Load, a crash between the two steps is safe.
	//
	// PRECONDITION (rejected with an error otherwise): snap.Meta.Index+1 >=
	// the first index still in the log. A crash midway through installing a
	// snapshot that ends before the log starts would leave a log starting
	// after the snapshot, which Load must call corruption. The node only
	// installs snapshots above its commit index, which is >= its own
	// snapshot index and so >= every compacted index.
	InstallSnapshot(snap Snapshot) error

	// Compact discards log entries with Index <= through. It is only called
	// once a snapshot has been saved and with through <= latest snapshot
	// index (stores reject anything else). It need not be durable before
	// returning, but must be crash-atomic (after a crash, Load sees either
	// the uncompacted or the compacted log).
	Compact(through uint64) error

	// Close releases resources. The store is not used afterwards.
	Close() error
}

// ---------------------------------------------------------------------------
// Messages and transport
// ---------------------------------------------------------------------------

// MsgType enumerates the messages exchanged between nodes. All communication
// is asynchronous message passing: a "response" is simply another message
// travelling the other way, correlated by term/index (or by RequestID for
// forwarded proposals and read-index requests).
type MsgType uint8

const (
	MsgPreVote MsgType = iota + 1
	MsgPreVoteResp
	MsgVote
	MsgVoteResp
	MsgApp // AppendEntries; with no entries it doubles as a heartbeat
	MsgAppResp
	MsgSnap // InstallSnapshot (whole snapshot in one message)
	MsgSnapResp
	MsgProp // a follower forwarding a client proposal to the leader
	MsgPropResp
	MsgReadIndex // a follower asking the leader for a linearizable read index
	MsgReadIndexResp
)

// Message is the single wire type. Which fields are meaningful depends on
// Type. The consensus core owns this struct and may add fields; transports
// must treat it as opaque apart from From and To, and must serialize all
// exported fields (encoding/gob does this automatically).
type Message struct {
	Type MsgType
	From string
	To   string
	Term uint64

	// MsgPreVote/MsgVote: candidate's last log position.
	// MsgApp: position immediately preceding Entries.
	// MsgAppResp: echoes the LogIndex of the MsgApp it answers (used to
	// recognize stale rejections).
	LogIndex uint64
	LogTerm  uint64

	Entries []Entry   // MsgApp
	Commit  uint64    // MsgApp: leader's commit index
	Snap    *Snapshot // MsgSnap

	// Responses.
	Reject       bool
	MatchIndex   uint64 // MsgAppResp/MsgSnapResp success: highest index known replicated
	ConflictTerm uint64 // MsgAppResp reject: fast-backtracking hint
	ConflictIdx  uint64 // MsgAppResp reject: fast-backtracking hint

	// Correlation for MsgProp*/MsgReadIndex* and for matching heartbeat
	// acknowledgements to read-index rounds: every MsgApp carries the
	// leader's current read sequence number in ReadCtx and MsgAppResp
	// echoes it.
	RequestID uint64
	ReadCtx   uint64

	Data  []byte // MsgProp: command; MsgPropResp: apply result
	Index uint64 // MsgReadIndexResp: the read index; MsgPropResp: index of the applied entry
	Error string // MsgPropResp/MsgReadIndexResp: non-empty on failure
}

// Transport carries Messages between nodes. Delivery is BEST EFFORT:
// messages may be dropped, delayed, duplicated or reordered, and the core
// tolerates all of that. A transport never retries on its own behalf in a way
// that could deliver a message long after it was sent (stale messages are
// harmless but wasteful).
type Transport interface {
	// Send queues msgs for delivery to their respective To peers and returns
	// immediately. It never blocks on the network: when a peer's queue is
	// full or the peer is unreachable, messages are dropped.
	Send(msgs []Message)

	// SetHandler installs the function invoked for every inbound message.
	// It is called once, before the node starts. The handler does not block
	// on consensus progress, but may be called concurrently.
	SetHandler(h func(Message))

	// Close stops delivery in both directions.
	Close() error
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

// StateMachine is the replicated application. Apply, Snapshot and Restore
// are never called concurrently with each other.
//
// Apply MUST be deterministic: the result and the resulting state may depend
// only on the previous state and (index, cmd) -- never on wall-clock time,
// randomness, map iteration order or anything local to the node.
type StateMachine interface {
	// Apply executes a committed command and returns a result that is handed
	// back to the proposer. Indices are strictly increasing but not
	// necessarily consecutive (no-op entries are skipped). After a restart
	// the node restores the latest snapshot and re-applies later entries, so
	// Apply is invoked again for entries after the snapshot.
	Apply(index uint64, cmd []byte) []byte

	// Snapshot serializes the complete current state.
	Snapshot() ([]byte, error)

	// Restore replaces the complete state with a previously produced snapshot.
	Restore(data []byte) error
}

// ---------------------------------------------------------------------------
// Node: the API the rest of the program uses
// ---------------------------------------------------------------------------

// Role is a node's current role in the protocol.
type Role uint8

const (
	Follower Role = iota
	PreCandidate
	Candidate
	Leader
)

func (r Role) String() string {
	switch r {
	case Follower:
		return "follower"
	case PreCandidate:
		return "pre-candidate"
	case Candidate:
		return "candidate"
	case Leader:
		return "leader"
	}
	return "unknown"
}

// PeerStatus is the leader's view of one follower.
type PeerStatus struct {
	MatchIndex  uint64
	LastContact time.Time // last time a message from this peer was received
}

// Status is a point-in-time view of a node, for health endpoints and tests.
type Status struct {
	ID            string
	Role          Role
	Term          uint64
	LeaderID      string // "" if unknown
	CommitIndex   uint64
	LastApplied   uint64
	LastLogIndex  uint64
	SnapshotIndex uint64
	Peers         map[string]PeerStatus // populated on the leader only
}

var (
	// ErrNoLeader is returned by Propose and ReadBarrier when there is no
	// known leader to hand the request to. For Propose it guarantees the
	// command was NOT appended to any log: it is safe to retry.
	ErrNoLeader = errors.New("raft: no leader")

	// ErrUnknownOutcome is returned (possibly wrapped) by Propose when the
	// command was handed to a leader but its fate could not be determined
	// (leadership lost, timeout, shutdown, forwarded reply lost...). The
	// command may or may not be committed, now or later. Callers that need
	// exactly-once semantics must make their commands idempotent.
	ErrUnknownOutcome = errors.New("raft: proposal outcome unknown")

	// ErrStopped is returned once the node has been stopped. If a proposal
	// was already in flight the returned error also wraps ErrUnknownOutcome.
	ErrStopped = errors.New("raft: node stopped")
)

// Node is a running Raft participant.
type Node interface {
	// Propose replicates cmd and, once it is committed and applied, returns
	// the result of StateMachine.Apply for it. It may be called on any node:
	// a follower forwards the command to the leader and relays the result.
	//
	// Errors: ErrNoLeader means the command was certainly not proposed. Any
	// other error (including ctx expiry after hand-off) wraps
	// ErrUnknownOutcome.
	Propose(ctx context.Context, cmd []byte) ([]byte, error)

	// ReadBarrier blocks until the local state machine has applied every
	// command that was committed anywhere in the cluster at the moment
	// ReadBarrier was called. After it returns nil, a read of the local
	// state machine is linearizable. It may be called on any node
	// (implemented with the ReadIndex protocol: the leader confirms its
	// leadership with a quorum round; followers obtain the index from the
	// leader and wait until they have applied up to it). It never relies on
	// clocks/leases for safety.
	ReadBarrier(ctx context.Context) error

	// Status reports the node's current view. It is cheap and never blocks
	// on consensus.
	Status() Status

	// Stop shuts the node down and waits for its goroutines to exit. It does
	// not close the Storage or Transport passed in Config.
	Stop() error
}

// Lifecycle is implemented by nodes returned from StartNode.
type Lifecycle interface {
	// Done is closed when the node has stopped, whether through Stop or a fatal error.
	Done() <-chan struct{}
	// Err returns nil while running and after a clean Stop, and the fatal error otherwise.
	Err() error
}
