package raft_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"

	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/memnet"
)

// ---------------------------------------------------------------------------
// Harness: real Nodes, MemStorage, memnet.
// ---------------------------------------------------------------------------

type clusterOpts struct {
	threshold uint64
	trailing  uint64
	tick      time.Duration // default 10ms
	wrap      func(id string, s raft.Storage) raft.Storage
}

type cluster struct {
	t    *testing.T
	net  *memnet.Network
	ids  []string
	opts clusterOpts

	mu     sync.Mutex
	nodes  map[string]raft.Node
	stores map[string]*raft.MemStorage
	kvs    map[string]*raft.KVStore
	seeds  int64

	kvByNode map[raft.Node]*raft.KVStore
}

const tick = 10 * time.Millisecond

func newCluster(t *testing.T, n int, opts clusterOpts) *cluster {
	t.Helper()
	c := &cluster{t: t, net: memnet.New(int64(n) * 7919), opts: opts,
		nodes: map[string]raft.Node{}, stores: map[string]*raft.MemStorage{}, kvs: map[string]*raft.KVStore{},
		kvByNode: map[raft.Node]*raft.KVStore{}}
	for i := 1; i <= n; i++ {
		c.ids = append(c.ids, fmt.Sprintf("n%d", i))
	}
	c.net.SetDelay(0, time.Millisecond)
	for _, id := range c.ids {
		c.stores[id] = raft.NewMemStorage()
		c.start(id)
	}
	t.Cleanup(c.close)
	return c
}

func (c *cluster) start(id string) {
	c.t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodes[id] != nil {
		return
	}
	var st raft.Storage = c.stores[id]
	if c.opts.wrap != nil {
		st = c.opts.wrap(id, st)
	}
	kv := raft.NewKVStore()
	tr := c.net.Join(id)
	c.net.Reconnect(id)
	c.seeds++
	n, err := raft.StartNode(raft.Config{
		ID: id, Peers: c.ids, Storage: st, Transport: tr, StateMachine: kv,
		TickInterval: c.tick(), ElectionTicks: 10, HeartbeatTicks: 1,
		SnapshotThreshold: c.opts.threshold, SnapshotTrailing: c.opts.trailing,
		Seed: c.seeds*1000 + int64(len(id)),
	})
	if err != nil {
		c.t.Fatalf("start %s: %v", id, err)
	}
	c.nodes[id], c.kvs[id] = n, kv
	c.kvByNode[n] = kv
}

func (c *cluster) tick() time.Duration {
	if c.opts.tick > 0 {
		return c.opts.tick
	}
	return tick
}

// stop simulates a crash: the node stops and its network endpoint goes dark.
func (c *cluster) stop(id string) {
	c.mu.Lock()
	n := c.nodes[id]
	delete(c.nodes, id)
	c.mu.Unlock()
	if n == nil {
		return
	}
	c.net.Disconnect(id)
	if err := n.Stop(); err != nil {
		c.t.Errorf("stop %s: %v", id, err)
	}
}

func (c *cluster) close() {
	for _, id := range c.ids {
		c.stop(id)
	}
	c.net.Close()
}

func (c *cluster) node(id string) raft.Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nodes[id]
}

func (c *cluster) kv(id string) *raft.KVStore {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kvs[id]
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// leader waits until exactly one of the given running nodes is leader of the
// highest term among them and the others agree.
func (c *cluster) leader(among ...string) string {
	c.t.Helper()
	if len(among) == 0 {
		among = c.ids
	}
	var lead string
	waitFor(c.t, 10*time.Second, "a leader", func() bool {
		lead = ""
		var term uint64
		for _, id := range among {
			n := c.node(id)
			if n == nil {
				continue
			}
			if s := n.Status(); s.Role == raft.Leader && s.Term >= term {
				lead, term = id, s.Term
			}
		}
		if lead == "" {
			return false
		}
		for _, id := range among {
			if n := c.node(id); n != nil {
				if s := n.Status(); s.Term != term || s.LeaderID != lead {
					return false
				}
			}
		}
		return true
	})
	return lead
}

var reqIDs atomic.Uint64

func put(ctx context.Context, n raft.Node, k, v string) error {
	cmd := raft.EncodeKV(raft.KVCommand{ID: reqIDs.Add(1), Op: "put", Key: k, Value: v})
	_, err := n.Propose(ctx, cmd)
	return err
}

func mustPut(t *testing.T, n raft.Node, k, v string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := put(ctx, n, k, v); err != nil {
		t.Fatalf("put %s=%s: %v", k, v, err)
	}
}

// converged waits until every running node has applied the leader's commit
// index and holds the same state.
func (c *cluster) converged() {
	c.t.Helper()
	waitFor(c.t, 15*time.Second, "convergence", func() bool {
		var want string
		var commit uint64
		first := true
		for _, id := range c.ids {
			n := c.node(id)
			if n == nil {
				continue
			}
			s := n.Status()
			d := c.kv(id).Dump()
			if first {
				want, commit, first = d, s.CommitIndex, false
			}
			if d != want || s.LastApplied != commit || s.CommitIndex != commit {
				return false
			}
		}
		return true
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNodeElectionAndReplication(t *testing.T) {
	for _, size := range []int{1, 3, 5} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			c := newCluster(t, size, clusterOpts{})
			lead := c.leader()
			for i := 0; i < 20; i++ {
				mustPut(t, c.node(c.ids[i%size]), "k", fmt.Sprint(i))
			}
			c.converged()
			for _, id := range c.ids {
				if got := c.kv(id).Get("k"); got != "19" {
					t.Fatalf("%s: k=%q", id, got)
				}
			}
			s := c.node(lead).Status()
			if len(s.Peers) != size-1 {
				t.Fatalf("leader status peers: %+v", s.Peers)
			}
		})
	}
}

func TestNodeLeaderFailover(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{})
	old := c.leader()
	mustPut(t, c.node(old), "a", "1")
	c.stop(old)
	var rest []string
	for _, id := range c.ids {
		if id != old {
			rest = append(rest, id)
		}
	}
	lead := c.leader(rest...)
	if lead == old {
		t.Fatal("stopped node still leader")
	}
	mustPut(t, c.node(lead), "a", "2")
	c.start(old)
	c.converged()
	if got := c.kv(old).Get("a"); got != "2" {
		t.Fatalf("restarted old leader has a=%q", got)
	}
}

func TestNodeMinorityCannotCommit(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{})
	lead := c.leader()
	mustPut(t, c.node(lead), "x", "before")

	// The leader alone on one side.
	c.net.Isolate(lead)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	err := put(ctx, c.node(lead), "x", "minority")
	cancel()
	if err == nil {
		t.Fatal("isolated leader committed a write")
	}
	if !errors.Is(err, raft.ErrUnknownOutcome) {
		t.Fatalf("write appended on the isolated leader must report an unknown outcome, got %v", err)
	}
	var rest []string
	for _, id := range c.ids {
		if id != lead {
			rest = append(rest, id)
		}
	}
	newLead := c.leader(rest...)
	mustPut(t, c.node(newLead), "x", "majority")
	if got := c.kv(lead).Get("x"); got != "before" {
		t.Fatalf("isolated node applied %q", got)
	}
	c.net.Heal()
	c.converged()
	for _, id := range c.ids {
		if got := c.kv(id).Get("x"); got != "majority" {
			t.Fatalf("%s: x=%q; the minority write must be gone", id, got)
		}
	}
}

func TestNodeStaleLeaderCannotServeReads(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{})
	old := c.leader()
	mustPut(t, c.node(old), "x", "1")
	c.net.Isolate(old)
	// Immediately: the old leader still believes it leads, but cannot
	// complete a heartbeat round, so it must not confirm a read.
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	err := c.node(old).ReadBarrier(ctx)
	cancel()
	if err == nil {
		t.Fatal("isolated leader served a linearizable read")
	}
	var rest []string
	for _, id := range c.ids {
		if id != old {
			rest = append(rest, id)
		}
	}
	lead := c.leader(rest...)
	mustPut(t, c.node(lead), "x", "2")
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	err = c.node(old).ReadBarrier(ctx)
	cancel()
	if err == nil && c.kv(old).Get("x") != "2" {
		t.Fatalf("stale read: ReadBarrier succeeded on %s with x=%q", old, c.kv(old).Get("x"))
	}
	// The new side serves reads, also via a follower.
	for _, id := range rest {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.node(id).ReadBarrier(ctx); err != nil {
			t.Fatalf("ReadBarrier on %s: %v", id, err)
		}
		cancel()
		if got := c.kv(id).Get("x"); got != "2" {
			t.Fatalf("%s read x=%q after ReadBarrier", id, got)
		}
	}
}

func TestNodeRestartRecoversAndReapplies(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{threshold: 16, trailing: 4})
	lead := c.leader()
	for i := 0; i < 60; i++ {
		mustPut(t, c.node(lead), fmt.Sprintf("k%d", i%7), fmt.Sprint(i))
	}
	c.converged()
	want := c.kv(lead).Dump()
	for _, id := range c.ids {
		c.stop(id)
	}
	for _, id := range c.ids {
		c.start(id) // fresh state machine, same storage
	}
	c.leader()
	for _, id := range c.ids {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.node(id).ReadBarrier(ctx); err != nil {
			t.Fatalf("ReadBarrier on %s: %v", id, err)
		}
		cancel()
		if got := c.kv(id).Dump(); got != want {
			t.Fatalf("%s after restart:\n got %s\nwant %s", id, got, want)
		}
		if v := c.kv(id).Violation(); v != "" {
			t.Fatalf("%s: %s", id, v)
		}
		if s := c.node(id).Status(); s.SnapshotIndex == 0 {
			t.Fatalf("%s never snapshotted", id)
		}
	}
}

func TestNodeSlowFollowerCatchesUpViaSnapshot(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{threshold: 20, trailing: 5})
	lead := c.leader()
	var follower string
	for _, id := range c.ids {
		if id != lead {
			follower = id
			break
		}
	}
	c.net.Isolate(follower)
	for i := 0; i < 150; i++ {
		mustPut(t, c.node(lead), fmt.Sprintf("k%d", i%5), fmt.Sprint(i))
	}
	if s := c.node(lead).Status(); s.SnapshotIndex < 100 {
		t.Fatalf("leader snapshot index %d", s.SnapshotIndex)
	}
	before := c.node(follower).Status()
	c.net.Heal()
	c.converged()
	after := c.node(follower).Status()
	if after.SnapshotIndex <= before.LastApplied {
		t.Fatalf("follower caught up without a snapshot? snapshot %d, applied before %d", after.SnapshotIndex, before.LastApplied)
	}
	if c.kv(follower).Dump() != c.kv(lead).Dump() {
		t.Fatal("follower state differs")
	}
}

func TestNodeFollowerForwarding(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{})
	lead := c.leader()
	for _, id := range c.ids {
		if id == lead {
			continue
		}
		n := c.node(id)
		cmd := raft.EncodeKV(raft.KVCommand{ID: reqIDs.Add(1), Op: "cas", Key: "f", Old: "", Value: id})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		res, err := n.Propose(ctx, cmd)
		cancel()
		if err != nil {
			t.Fatalf("forwarded proposal from %s: %v", id, err)
		}
		r, err := raft.DecodeKVResult(res)
		if err != nil {
			t.Fatalf("result %q: %v", res, err)
		}
		wantOK := c.kv(lead).Get("f") == id
		if r.OK != wantOK {
			t.Fatalf("cas result relayed wrongly: %+v (f=%q)", r, c.kv(lead).Get("f"))
		}
		// A read on the follower after the write returns sees it.
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		err = n.ReadBarrier(ctx)
		cancel()
		if err != nil {
			t.Fatalf("follower ReadBarrier: %v", err)
		}
		if got := c.kv(id).Get("f"); got == "" {
			t.Fatalf("%s: ReadBarrier returned before applying the write", id)
		}
	}
}

func TestNodePreVotePreventsDisruption(t *testing.T) {
	c := newCluster(t, 3, clusterOpts{})
	lead := c.leader()
	term := c.node(lead).Status().Term
	var follower string
	for _, id := range c.ids {
		if id != lead {
			follower = id
		}
	}
	c.net.Isolate(follower)
	time.Sleep(60 * tick) // several election timeouts
	if s := c.node(follower).Status(); s.Term != term {
		t.Fatalf("isolated follower moved to term %d (PreVote should keep it at %d)", s.Term, term)
	}
	c.net.Heal()
	time.Sleep(30 * tick)
	s := c.node(lead).Status()
	if s.Role != raft.Leader || s.Term != term {
		t.Fatalf("rejoining node disrupted the leader: %s role %s term %d (was %d)", lead, s.Role, s.Term, term)
	}
	mustPut(t, c.node(follower), "p", "v")
}

// TestNodeLargeEntries replicates a 48 MiB entry, forwarded from a follower
// (so it also travels in a MsgProp); the MsgApp carrying it exceeds
// MaxAppendBytes on its own. The run loop persists and applies inline, so the
// election timeout must exceed the time to handle such an entry; with the
// production default (100ms ticks, 1-2s timeout) that holds, except under
// the race detector, where decoding the command alone takes ~1.4s and the
// entry is scaled down. The client retries with the same request ID, as a
// real client would after an unknown outcome.
func TestNodeLargeEntries(t *testing.T) {
	size := 48 << 20
	if raceEnabled {
		size = 12 << 20
	}
	c := newCluster(t, 3, clusterOpts{tick: 100 * time.Millisecond})
	lead := c.leader()
	var follower string
	for _, id := range c.ids {
		if id != lead {
			follower = id
		}
	}
	big := make([]byte, size)
	for i := range big {
		big[i] = byte('a' + i%26)
	}
	cmd := raft.EncodeKV(raft.KVCommand{ID: reqIDs.Add(1), Op: "put", Key: "big", Value: string(big)})
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = c.node(follower).Propose(ctx, cmd)
		cancel()
		if err == nil {
			break
		}
		t.Logf("attempt %d: %v", attempt, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, c.node(lead), "small", "after")
	c.converged()
	for _, id := range c.ids {
		if got := c.kv(id).Get("big"); len(got) != len(big) || got[len(got)-1] != big[len(big)-1] {
			t.Fatalf("%s: big value has %d bytes", id, len(got))
		}
	}
}

// failingStorage turns Append into an error after a number of calls and
// counts calls; flush, if set, is how long each Append takes.
type failingStorage struct {
	raft.Storage
	appends   atomic.Int64
	failAfter int64
	flush     time.Duration
}

var errDiskOnFire = errors.New("disk on fire")

func (f *failingStorage) Append(e []raft.Entry) error {
	if n := f.appends.Add(1); f.failAfter > 0 && n > f.failAfter {
		return errDiskOnFire
	}
	time.Sleep(f.flush)
	return f.Storage.Append(e)
}

func TestNodeGroupCommit(t *testing.T) {
	var fs *failingStorage
	c := newCluster(t, 1, clusterOpts{wrap: func(id string, s raft.Storage) raft.Storage {
		// Proposals that arrive while the loop is flushing share the next
		// Append. With an instant store that depends on scheduling luck, and
		// under heavy CPU load every proposal could get its own Append.
		fs = &failingStorage{Storage: s, flush: time.Millisecond}
		return fs
	}})
	n := c.node(c.leader())
	before := fs.appends.Load()
	var wg sync.WaitGroup
	const k = 200
	errs := make(chan error, k)
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			errs <- put(ctx, n, fmt.Sprint(i), "v")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls := fs.appends.Load() - before; calls >= k {
		t.Fatalf("%d Append calls for %d proposals: no group commit", calls, k)
	} else {
		t.Logf("%d proposals in %d Append calls", k, calls)
	}
}

func TestNodeStorageErrorIsFatal(t *testing.T) {
	var fs *failingStorage
	c := newCluster(t, 1, clusterOpts{wrap: func(id string, s raft.Storage) raft.Storage {
		fs = &failingStorage{Storage: s, failAfter: 1 << 40}
		return fs
	}})
	n := c.node(c.leader())
	mustPut(t, n, "a", "1")
	fs.failAfter = fs.appends.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := put(ctx, n, "a", "2")
	if !errors.Is(err, raft.ErrStopped) || !errors.Is(err, raft.ErrUnknownOutcome) {
		t.Fatalf("in-flight proposal on a failed node: %v", err)
	}
	if err := put(ctx, n, "a", "3"); !errors.Is(err, raft.ErrStopped) {
		t.Fatalf("proposal after failure: %v", err)
	}
	if err := n.ReadBarrier(ctx); !errors.Is(err, raft.ErrStopped) {
		t.Fatalf("read after failure: %v", err)
	}
	c.mu.Lock()
	delete(c.nodes, c.ids[0])
	c.mu.Unlock()
	if err := n.Stop(); err == nil {
		t.Fatal("Stop after a fatal storage error returned nil")
	}
}

func TestNodeLifecycle(t *testing.T) {
	base := runtime.NumGoroutine()
	func() {
		// Fatal storage error: Done closes on its own and Err reports the
		// wrapped storage error.
		var fs *failingStorage
		c := newCluster(t, 1, clusterOpts{wrap: func(id string, s raft.Storage) raft.Storage {
			fs = &failingStorage{Storage: s, failAfter: 1 << 40}
			return fs
		}})
		n := c.node(c.leader())
		lc, ok := n.(raft.Lifecycle)
		if !ok {
			t.Fatal("node returned by StartNode does not implement raft.Lifecycle")
		}
		mustPut(t, n, "a", "1")
		select {
		case <-lc.Done():
			t.Fatal("Done closed while running")
		default:
		}
		if err := lc.Err(); err != nil {
			t.Fatalf("Err while running: %v", err)
		}
		fs.failAfter = fs.appends.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := put(ctx, n, "a", "2"); !errors.Is(err, raft.ErrStopped) || !errors.Is(err, raft.ErrUnknownOutcome) {
			t.Fatalf("in-flight proposal on a failed node: %v", err)
		}
		select {
		case <-lc.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("Done not closed after a fatal storage error")
		}
		if err := lc.Err(); !errors.Is(err, errDiskOnFire) {
			t.Fatalf("Err after fatal storage error = %v, want it to wrap %v", err, errDiskOnFire)
		}
		c.mu.Lock()
		delete(c.nodes, c.ids[0])
		c.mu.Unlock()
		if err := n.Stop(); !errors.Is(err, errDiskOnFire) {
			t.Fatalf("Stop after fatal error = %v", err)
		}
		c.close()

		// Clean Stop: Done closes, Err stays nil.
		c2 := newCluster(t, 3, clusterOpts{})
		n2 := c2.node(c2.leader())
		lc2 := n2.(raft.Lifecycle)
		for _, id := range c2.ids {
			c2.stop(id)
		}
		select {
		case <-lc2.Done():
		default:
			t.Fatal("Done not closed after Stop")
		}
		if err := lc2.Err(); err != nil {
			t.Fatalf("Err after clean Stop = %v", err)
		}
		c2.close()
	}()
	waitFor(t, 5*time.Second, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= base })
}

func TestNodeStopIsClean(t *testing.T) {
	base := runtime.NumGoroutine()
	func() {
		c := newCluster(t, 3, clusterOpts{})
		lead := c.leader()
		// Leave calls pending on a node that cannot reach anyone.
		c.net.Isolate(lead)
		n := c.node(lead)
		done := make(chan error, 2)
		go func() { done <- put(context.Background(), n, "z", "1") }()
		go func() { done <- n.ReadBarrier(context.Background()) }()
		time.Sleep(3 * tick)
		c.stop(lead)
		for i := 0; i < 2; i++ {
			select {
			case err := <-done:
				if !errors.Is(err, raft.ErrStopped) && !errors.Is(err, raft.ErrUnknownOutcome) && !errors.Is(err, raft.ErrNoLeader) {
					t.Errorf("pending call after Stop: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("pending call did not return after Stop")
			}
		}
		if err := n.Stop(); err != nil { // idempotent
			t.Fatal(err)
		}
		c.close()
	}()
	waitFor(t, 5*time.Second, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= base })
}

func TestNodeConfigValidation(t *testing.T) {
	st, kv := raft.NewMemStorage(), raft.NewKVStore()
	net := memnet.New(1)
	defer net.Close()
	for _, cfg := range []raft.Config{
		{ID: "a", Peers: []string{"b"}, Storage: st, Transport: net.Join("a"), StateMachine: kv},
		{ID: "a", Peers: []string{"a", "a"}, Storage: st, Transport: net.Join("a"), StateMachine: kv},
		{ID: "a", Peers: []string{"a"}, Transport: net.Join("a"), StateMachine: kv},
		{ID: "a", Peers: []string{"a"}, Storage: st, Transport: net.Join("a"), StateMachine: kv, ElectionTicks: 2, HeartbeatTicks: 2},
	} {
		if n, err := raft.StartNode(cfg); err == nil {
			n.Stop()
			t.Errorf("config %+v accepted", cfg)
		}
	}
}

// ---------------------------------------------------------------------------
// Chaos: random partitions and crashes under concurrent clients, checked for
// linearizability.
// ---------------------------------------------------------------------------

func TestNodeChaosLinearizable(t *testing.T) {
	duration := 4 * time.Second
	if testing.Short() {
		duration = 1500 * time.Millisecond
	}
	c := newCluster(t, 3, clusterOpts{threshold: 32, trailing: 8})
	c.net.SetDelay(0, 2*time.Millisecond)
	c.net.SetReorder(0.05, 10*time.Millisecond)
	c.leader()
	start := time.Now()
	now := func() int64 { return int64(time.Since(start)) }

	var (
		hmu     sync.Mutex
		history []porcupine.Operation
		stopped atomic.Bool
		wg      sync.WaitGroup
	)
	keys := []string{"a", "b"}
	for cl := 0; cl < 4; cl++ {
		wg.Add(1)
		go func(cl int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(cl), 99))
			for i := 0; !stopped.Load(); i++ {
				key := keys[rng.IntN(len(keys))]
				var in raft.KVInput
				switch x := rng.IntN(10); {
				case x < 4:
					in = raft.KVInput{Op: "get", Key: key}
				case x < 7:
					in = raft.KVInput{Op: "append", Key: key, Value: fmt.Sprintf("%d.%d,", cl, i)}
				case x < 9:
					in = raft.KVInput{Op: "put", Key: key, Value: fmt.Sprintf("%d.%d,", cl, i)}
				default:
					in = raft.KVInput{Op: "cas", Key: key, Old: "", Value: fmt.Sprintf("%d.%d,", cl, i)}
				}
				op := porcupine.Operation{ClientId: cl, Input: in, Call: now()}
				// Client 0 gives up after one attempt, so some writes end
				// with an unknown outcome (modelled as Return = MaxInt64).
				out, ok := runClientOp(c, rng, in, &stopped, cl == 0)
				if !ok {
					continue // certainly had no effect (or a read that failed)
				}
				op.Output = out
				op.Return = now()
				if out.Unknown {
					op.Return = math.MaxInt64
				}
				hmu.Lock()
				history = append(history, op)
				hmu.Unlock()
			}
		}(cl)
	}

	// Nemesis.
	rng := rand.New(rand.NewPCG(4, 2))
	for time.Since(start) < duration {
		time.Sleep(time.Duration(50+rng.IntN(250)) * time.Millisecond)
		switch rng.IntN(6) {
		case 0:
			c.net.Heal()
		case 1:
			c.net.Heal()
			a := c.ids[rng.IntN(3)]
			c.net.Isolate(a)
		case 2:
			a, b := c.ids[rng.IntN(3)], c.ids[rng.IntN(3)]
			if a != b {
				c.net.Cut(a, b)
			}
		case 3:
			id := c.ids[rng.IntN(3)]
			c.stop(id)
			time.Sleep(time.Duration(rng.IntN(200)) * time.Millisecond)
			c.start(id)
		case 4:
			c.net.SetDropRate([]float64{0, 0.05, 0.2}[rng.IntN(3)])
			c.net.SetDuplicateRate([]float64{0, 0.05}[rng.IntN(2)])
		case 5:
			for _, id := range c.ids {
				c.start(id)
			}
		}
	}
	c.net.Heal()
	c.net.SetDropRate(0)
	c.net.SetDuplicateRate(0)
	for _, id := range c.ids {
		c.start(id)
	}
	stopped.Store(true)
	wg.Wait()
	c.leader()
	c.converged()
	// Final reads on every node.
	for i, id := range c.ids {
		for _, k := range keys {
			ts := now()
			history = append(history, porcupine.Operation{ClientId: 10 + i, Input: raft.KVInput{Op: "get", Key: k}, Call: ts, Output: raft.KVOutput{Value: c.kv(id).Get(k)}, Return: ts})
		}
	}
	unknown := 0
	for _, op := range history {
		if op.Output.(raft.KVOutput).Unknown {
			unknown++
		}
	}
	res := porcupine.CheckOperationsTimeout(raft.KVModel, history, 60*time.Second)
	t.Logf("%d operations (%d with unknown outcome): %v", len(history), unknown, res)
	if res != porcupine.Ok {
		t.Fatalf("history is %v", res)
	}
}

// runClientOp performs in against random nodes, retrying with the same
// request ID until it gets a definite answer (or once, if once is set). ok=false means the operation
// certainly had no effect (only possible if no attempt might have been
// proposed) or is a read that never succeeded.
func runClientOp(c *cluster, rng *rand.Rand, in raft.KVInput, stopped *atomic.Bool, once bool) (raft.KVOutput, bool) {
	id := reqIDs.Add(1)
	maybe := false
	for attempt := 0; ; attempt++ {
		if (stopped.Load() || once) && attempt > 0 && in.Op == "get" {
			return raft.KVOutput{}, false
		}
		if (stopped.Load() && attempt > 200) || (once && attempt > 0) {
			if maybe {
				return raft.KVOutput{Unknown: true}, true
			}
			return raft.KVOutput{}, false
		}
		nodeID := c.ids[rng.IntN(len(c.ids))]
		n := c.node(nodeID)
		if n == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		if in.Op == "get" {
			err := n.ReadBarrier(ctx)
			cancel()
			if err == nil {
				return raft.KVOutput{Value: c.kvOf(n).Get(in.Key)}, true
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		res, err := n.Propose(ctx, raft.EncodeKV(raft.KVCommand{ID: id, Op: in.Op, Key: in.Key, Value: in.Value, Old: in.Old}))
		cancel()
		if err == nil {
			r, derr := raft.DecodeKVResult(res)
			if derr != nil {
				panic(derr)
			}
			return raft.KVOutput{OK: r.OK}, true
		}
		if errors.Is(err, raft.ErrUnknownOutcome) {
			maybe = true
		} else if !errors.Is(err, raft.ErrNoLeader) && !errors.Is(err, raft.ErrStopped) {
			panic(fmt.Sprintf("unexpected Propose error: %v", err))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// kvOf returns the state machine of the node instance n (a node that was
// stopped keeps its final state, which is still a valid read after its
// ReadBarrier returned).
func (c *cluster) kvOf(n raft.Node) *raft.KVStore {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kvByNode[n]
}
