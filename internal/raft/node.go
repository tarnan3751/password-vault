package raft

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Config configures a Node.
type Config struct {
	ID                string
	Peers             []string // all voters incl. ID
	Storage           Storage
	Transport         Transport
	StateMachine      StateMachine
	TickInterval      time.Duration // default 100ms
	ElectionTicks     int           // default 10; timeout randomized in [ElectionTicks, 2*ElectionTicks)
	HeartbeatTicks    int           // default 1
	SnapshotThreshold uint64        // snapshot after this many applied entries since the last one; default 4096
	SnapshotTrailing  uint64        // entries kept behind a snapshot for slow followers; default 256
	MaxAppendBytes    int           // soft cap per MsgApp; default 1 MiB
	Logger            *slog.Logger  // nil => discard
	Seed              int64         // 0 => seeded from crypto/rand
}

func (cfg *Config) fillDefaults() {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 100 * time.Millisecond
	}
	if cfg.ElectionTicks <= 0 {
		cfg.ElectionTicks = 10
	}
	if cfg.HeartbeatTicks <= 0 {
		cfg.HeartbeatTicks = 1
	}
	if cfg.SnapshotThreshold == 0 {
		cfg.SnapshotThreshold = 4096
	}
	if cfg.SnapshotTrailing == 0 {
		cfg.SnapshotTrailing = 256
	}
	if cfg.MaxAppendBytes <= 0 {
		cfg.MaxAppendBytes = 1 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

const (
	recvBuffer    = 4096 // inbound messages queued for the run loop; excess is dropped
	maxInputBatch = 1024 // inputs folded into one ready (group commit)
)

type propCall struct {
	cmd  []byte
	done chan propOutcome
}

type propOutcome struct {
	data []byte
	err  error
}

type readCall struct {
	done chan error
}

type readWait struct {
	index uint64
	call  *readCall
}

type node struct {
	cfg       Config
	log       *slog.Logger
	transport Transport

	recvc    chan Message
	propc    chan *propCall
	readc    chan *readCall
	stopc    chan struct{}
	donec    chan struct{}
	stopOnce sync.Once

	// Owned by the run goroutine.
	core        *core
	drv         driver
	nextID      uint64
	props       map[uint64]*propCall
	reads       map[uint64]*readCall
	readWaits   []readWait
	lastContact map[string]time.Time

	mu     sync.Mutex
	status Status
	err    error // fatal error that stopped the node
}

// StartNode loads cfg.Storage, restores cfg.StateMachine from the latest
// snapshot (entries after it are re-applied as they are learned to be
// committed), installs the transport handler and starts the node.
func StartNode(cfg Config) (Node, error) {
	cfg.fillDefaults()
	if cfg.ID == "" {
		return nil, errors.New("raft: Config.ID is empty")
	}
	if cfg.Storage == nil || cfg.Transport == nil || cfg.StateMachine == nil {
		return nil, errors.New("raft: Config needs Storage, Transport and StateMachine")
	}
	if cfg.HeartbeatTicks >= cfg.ElectionTicks {
		return nil, fmt.Errorf("raft: HeartbeatTicks (%d) must be less than ElectionTicks (%d)", cfg.HeartbeatTicks, cfg.ElectionTicks)
	}
	seed := cfg.Seed
	if seed == 0 {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("raft: seeding: %w", err)
		}
		seed = int64(binary.LittleEndian.Uint64(b[:]))
	}
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))
	c, drv, err := restart(coreConfig{
		id:             cfg.ID,
		peers:          slices.Clone(cfg.Peers),
		electionTicks:  cfg.ElectionTicks,
		heartbeatTicks: cfg.HeartbeatTicks,
		maxAppendBytes: cfg.MaxAppendBytes,
		rng:            rng,
	}, cfg.Storage, cfg.StateMachine, cfg.SnapshotThreshold, cfg.SnapshotTrailing)
	if err != nil {
		return nil, err
	}
	n := &node{
		cfg:         cfg,
		log:         cfg.Logger.With("raft_id", cfg.ID),
		transport:   cfg.Transport,
		recvc:       make(chan Message, recvBuffer),
		propc:       make(chan *propCall),
		readc:       make(chan *readCall),
		stopc:       make(chan struct{}),
		donec:       make(chan struct{}),
		core:        c,
		nextID:      rng.Uint64() >> 1, // request IDs must not repeat across restarts
		props:       map[uint64]*propCall{},
		reads:       map[uint64]*readCall{},
		lastContact: map[string]time.Time{},
		drv:         drv,
	}
	n.publishStatus()
	cfg.Transport.SetHandler(n.handle)
	n.log.Info("raft node starting", "term", c.term, "snapshot", c.snapshotIndex(), "last_index", c.log.lastIndex(), "peers", cfg.Peers)
	go n.run()
	return n, nil
}

// handle is the transport callback. It must never block.
func (n *node) handle(m Message) {
	if m.To != n.cfg.ID {
		return
	}
	select {
	case n.recvc <- m:
	default:
	}
}

// notSubmittedError reports a proposal that never reached the run loop. It
// matches ErrNoLeader (the command was certainly not proposed, so a retry is
// safe) and wraps the cause.
type notSubmittedError struct{ cause error }

func (e notSubmittedError) Error() string        { return "raft: proposal not submitted: " + e.cause.Error() }
func (e notSubmittedError) Unwrap() error        { return e.cause }
func (e notSubmittedError) Is(target error) bool { return target == ErrNoLeader }

func (n *node) Propose(ctx context.Context, cmd []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, notSubmittedError{err}
	}
	call := &propCall{cmd: bytes.Clone(cmd), done: make(chan propOutcome, 1)}
	if call.cmd == nil {
		call.cmd = []byte{}
	}
	select {
	case n.propc <- call:
	case <-ctx.Done():
		return nil, notSubmittedError{ctx.Err()}
	case <-n.donec:
		return nil, n.stoppedErr()
	}
	select {
	case out := <-call.done:
		return out.data, out.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrUnknownOutcome, ctx.Err())
	}
}

func (n *node) ReadBarrier(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call := &readCall{done: make(chan error, 1)}
	select {
	case n.readc <- call:
	case <-ctx.Done():
		return ctx.Err()
	case <-n.donec:
		return n.stoppedErr()
	}
	select {
	case err := <-call.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.status
	s.Peers = maps.Clone(s.Peers)
	return s
}

func (n *node) Stop() error {
	n.stopOnce.Do(func() { close(n.stopc) })
	<-n.donec
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.err
}

var _ Lifecycle = (*node)(nil)

// Done is closed once the run loop has exited; n.err is final by then
// (shutdown records it before the loop returns and closes donec).
func (n *node) Done() <-chan struct{} { return n.donec }

// Err returns the fatal error that stopped the node, or nil.
func (n *node) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.err
}

func (n *node) stoppedErr() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return fmt.Errorf("%w: %v", ErrStopped, n.err)
	}
	return ErrStopped
}

func (n *node) run() {
	defer close(n.donec)
	ticker := time.NewTicker(n.cfg.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopc:
			n.shutdown(nil)
			return
		case <-ticker.C:
			n.core.tick()
		case m := <-n.recvc:
			n.onMessage(m)
		case p := <-n.propc:
			n.onPropose(p)
		case r := <-n.readc:
			n.onRead(r)
		}
		// Fold everything else that is already waiting into the same ready,
		// so concurrent proposals share one Storage.Append (group commit).
	batch:
		for i := 0; i < maxInputBatch; i++ {
			select {
			case m := <-n.recvc:
				n.onMessage(m)
			case p := <-n.propc:
				n.onPropose(p)
			case r := <-n.readc:
				n.onRead(r)
			default:
				break batch
			}
		}
		if err := n.processReadies(); err != nil {
			n.log.Error("raft: fatal error, stopping node", "err", err)
			n.shutdown(err)
			return
		}
		n.publishStatus()
	}
}

func (n *node) onMessage(m Message) {
	if n.core.isPeer(m.From) {
		n.lastContact[m.From] = time.Now()
	}
	n.core.step(m)
}

func (n *node) onPropose(p *propCall) {
	n.nextID++
	n.props[n.nextID] = p
	n.core.propose(n.nextID, p.cmd)
}

func (n *node) onRead(r *readCall) {
	n.nextID++
	n.reads[n.nextID] = r
	n.core.readIndex(n.nextID)
}

func (n *node) processReadies() error {
	for n.core.hasReady() {
		rd := n.core.ready()
		out, err := n.drv.process(&rd, n.transport.Send)
		if err != nil {
			return err
		}
		if len(out.msgs) > 0 {
			n.transport.Send(out.msgs)
		}
		n.core.advance(rd)

		for _, r := range out.local {
			n.finishProp(r.id, propOutcome{data: r.data})
		}
		for _, r := range rd.propResults {
			n.finishProp(r.id, propOutcome{data: r.data, err: r.err})
		}
		for _, r := range rd.readResults {
			call, ok := n.reads[r.id]
			if !ok {
				continue
			}
			delete(n.reads, r.id)
			if r.err != nil {
				call.done <- r.err
				continue
			}
			n.readWaits = append(n.readWaits, readWait{index: r.index, call: call})
		}
		n.releaseReads()
		if err := n.drv.maybeSnapshot(n.core); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) finishProp(id uint64, out propOutcome) {
	if call, ok := n.props[id]; ok {
		delete(n.props, id)
		call.done <- out
	}
}

// releaseReads completes ReadBarrier calls whose read index has been applied
// locally.
func (n *node) releaseReads() {
	kept := n.readWaits[:0]
	for _, w := range n.readWaits {
		if w.index <= n.drv.applied {
			w.call.done <- nil
		} else {
			kept = append(kept, w)
		}
	}
	clear(n.readWaits[len(kept):])
	n.readWaits = kept
}

func (n *node) shutdown(cause error) {
	stopErr := ErrStopped
	if cause != nil {
		stopErr = fmt.Errorf("%w: %v", ErrStopped, cause)
	}
	n.mu.Lock()
	n.err = cause
	n.mu.Unlock()
	for id, call := range n.props {
		call.done <- propOutcome{err: fmt.Errorf("%w (%w)", stopErr, ErrUnknownOutcome)}
		delete(n.props, id)
	}
	for id, call := range n.reads {
		call.done <- stopErr
		delete(n.reads, id)
	}
	for _, w := range n.readWaits {
		w.call.done <- stopErr
	}
	n.readWaits = nil
	n.publishStatus()
	n.log.Info("raft node stopped", "term", n.core.term, "applied", n.drv.applied)
}

func (n *node) publishStatus() {
	c := n.core
	s := Status{
		ID:            n.cfg.ID,
		Role:          c.role,
		Term:          c.term,
		LeaderID:      c.leader,
		CommitIndex:   c.commit,
		LastApplied:   n.drv.applied,
		LastLogIndex:  c.log.lastIndex(),
		SnapshotIndex: c.snapshotIndex(),
	}
	if c.role == Leader {
		s.Peers = make(map[string]PeerStatus, len(c.others))
		for _, p := range c.others {
			s.Peers[p] = PeerStatus{MatchIndex: c.prs[p].match, LastContact: n.lastContact[p]}
		}
	}
	n.mu.Lock()
	n.status = s
	n.mu.Unlock()
}
