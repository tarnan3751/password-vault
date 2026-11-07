package chaos

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// ErrNotSupported is returned by a backend for a fault it cannot inject
// (e.g. pausing an in-process node).
var ErrNotSupported = errors.New("chaos: not supported by this backend")

// Caps describes which faults a backend can inject. The nemesis only
// schedules episodes the backend supports.
type Caps struct {
	Pause     bool // SIGSTOP/SIGCONT
	Loss      bool // per-message loss (in-process) or connection resets (TCP forwarders)
	Dup       bool // per-message duplication
	Delay     bool
	Blackhole bool // accept and stall, distinct from a cut
}

// Digest is a node's view of the replicated state, used for the convergence
// check after the final heal.
type Digest struct {
	Node    string `json:"node"`
	Applied uint64 `json:"applied"`
	Commit  uint64 `json:"commit"`
	Rev     uint64 `json:"rev"`
	Hash    string `json:"hash"` // hex SHA-256 of a canonical state serialization
	// HashKind says what Hash covers: "state" (fsm.StateHash: the complete
	// canonical snapshot) or "backup-state" (SHA-256 of the canonical
	// snapshot served by GET /v1/admin/backup, which omits the cluster key).
	HashKind string `json:"hash_kind"`
}

// Cluster is a running Family Vault cluster under test. All methods are
// safe for concurrent use: the nemesis and the clients use it at the same
// time.
type Cluster interface {
	Mode() string
	IDs() []string
	URL(id string) string // base URL of the node's client API
	// HTTPClient returns a client for the public API (it trusts the
	// household CA in TLS mode).
	HTTPClient() *http.Client
	// Health reports the node's local Raft view (GET /v1/health or its
	// in-process equivalent). It fails for a node that is down or paused.
	Health(ctx context.Context, id string) (*api.HealthResponse, error)

	Kill(id string) error    // abrupt stop; no-op if already down
	Restart(id string) error // rebuild from the same data directory; no-op if up
	Pause(id string) error   // ErrNotSupported where unsupported
	Resume(id string) error
	// SetLink installs a fault on the directed link from -> to (traffic
	// that "from" sends to "to"). The zero LinkFault heals the link.
	SetLink(from, to string, f LinkFault) error
	HealNetwork()
	// Incarnation increases every time a node is (re)started; stale-read
	// monotonicity is only expected within one incarnation.
	Incarnation(id string) int
	Capabilities() Caps

	// SetAdminToken gives the backend an admin session for the endpoints
	// it needs for digests (process mode reads GET /v1/admin/backup).
	SetAdminToken(tok string)
	Digest(ctx context.Context, id string) (*Digest, error)
	// RestoreFromBackup stops every node, seeds FRESH data directories on
	// all of them with `vaultd restore --from <backup>`, and starts them.
	// It returns the state digest printed by each restore.
	RestoreFromBackup(ctx context.Context, vaultdBin, backupPath string) (map[string]string, error)

	// Findings lists unexpected events observed by the backend (a node
	// stopping on its own, a process exiting without being killed).
	Findings() []string
	Shutdown() error
}

// findings is a small concurrency-safe list of unexpected events.
type findings struct {
	mu   sync.Mutex
	list []string
}

func (f *findings) add(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = append(f.list, fmt.Sprintf(format, args...))
}

func (f *findings) get() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.list...)
}

// nodeIDs returns n1..nN.
func nodeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("n%d", i+1)
	}
	return ids
}

// listenNode binds a loopback port for a node listener. The port is drawn
// from below the ephemeral range (49152+ on macOS, 32768+ on Linux, both
// above 20000..32000): a node's port is re-bound after every kill, and an
// ephemeral port could meanwhile have been handed out as the SOURCE port of
// some outbound connection (keep-alive connections live long), which would
// make the restart fail with EADDRINUSE for reasons that have nothing to
// do with the system under test.
func listenNode() (net.Listener, error) {
	var err error
	for i := 0; i < 500; i++ {
		port := 20000 + rand.IntN(12000)
		var ln net.Listener
		if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("no free node port: %w", err)
}

// freeAddr reserves a node port for a child process to bind itself (the
// listener is closed again; in-process listeners are kept open instead).
func freeAddr() (string, error) {
	ln, err := listenNode()
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	return addr, ln.Close()
}

// listenRetry binds addr, retrying briefly: a port released by a killed
// node may take a moment to become bindable again.
func listenRetry(addr string) (net.Listener, error) {
	var err error
	for i := 0; i < 100; i++ {
		var ln net.Listener
		if ln, err = net.Listen("tcp", addr); err == nil {
			return ln, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, err
}

// findLeader asks every node for its health in parallel and returns the
// leader with the highest term ("" if no node claims leadership).
func findLeader(ctx context.Context, c Cluster) (string, uint64) {
	type res struct {
		h   *api.HealthResponse
		err error
	}
	ids := c.IDs()
	out := make([]res, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			h, err := c.Health(hctx, id)
			out[i] = res{h, err}
		}()
	}
	wg.Wait()
	leader, term := "", uint64(0)
	for _, r := range out {
		if r.err == nil && r.h.Role == "leader" && r.h.Term >= term {
			leader, term = r.h.NodeID, r.h.Term
		}
	}
	return leader, term
}

// allHealth returns the health of every node that answered.
func allHealth(ctx context.Context, c Cluster) map[string]*api.HealthResponse {
	ids := c.IDs()
	var mu sync.Mutex
	out := map[string]*api.HealthResponse{}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if h, err := c.Health(hctx, id); err == nil {
				mu.Lock()
				out[id] = h
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// waitConverged waits until every node is reachable, all agree on one
// leader that claims leadership, and every node has applied the leader's
// commit index, with nothing moving for 600 ms (polled every 100 ms, so a
// change at any poll restarts the window). That is the "full recovery" the
// final checks need: no write is still in flight anywhere.
func waitConverged(ctx context.Context, c Cluster, timeout time.Duration) (string, error) {
	return waitSettled(ctx, c, timeout, true, 600*time.Millisecond, "converge")
}

// waitApplied is waitConverged without the quiet window, for a cluster
// nobody has written to yet (its start, or a restore): everything is
// applied everywhere as soon as it is first seen, and whatever reads it
// next retries anyway.
func waitApplied(ctx context.Context, c Cluster, timeout time.Duration) (string, error) {
	return waitSettled(ctx, c, timeout, true, 0, "converge")
}

// waitHealthy waits until every node answers, all follow one leader in one
// term and that leader claims leadership. Unlike waitConverged it tolerates
// writes in flight, so it can be used while the clients are still running.
func waitHealthy(ctx context.Context, c Cluster, timeout time.Duration) (string, error) {
	return waitSettled(ctx, c, timeout, false, 0, "become healthy")
}

func waitSettled(ctx context.Context, c Cluster, timeout time.Duration, applied bool, quiet time.Duration, verb string) (string, error) {
	const poll = 100 * time.Millisecond
	deadline := time.Now().Add(timeout)
	why, last, since := "timeout", "", time.Now()
	for time.Now().Before(deadline) {
		hs := allHealth(ctx, c)
		if why = settledWhy(c.IDs(), hs, applied); why == "" {
			var sig strings.Builder
			for _, id := range c.IDs() {
				h := hs[id]
				fmt.Fprintf(&sig, "%s:%s:%d:%d;", id, h.LeaderID, h.Term, h.AppliedIndex)
			}
			if sig.String() != last {
				last, since = sig.String(), time.Now()
			}
			if time.Since(since) >= quiet {
				return hs[c.IDs()[0]].LeaderID, nil
			}
		} else {
			last = ""
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
	return "", fmt.Errorf("cluster did not %s within %v: %s", verb, timeout, why)
}

// settledWhy says why the cluster is not settled ("" = it is): every node
// answers, all follow one leader in one term and that leader claims
// leadership; with applied, every node has also applied the leader's commit
// index and holds the cluster key.
func settledWhy(ids []string, hs map[string]*api.HealthResponse, applied bool) string {
	if len(hs) != len(ids) {
		return fmt.Sprintf("only %d of %d nodes answer /v1/health", len(hs), len(ids))
	}
	leader := hs[ids[0]].LeaderID
	if leader == "" {
		return ids[0] + " knows no leader"
	}
	lh, ok := hs[leader]
	if !ok || lh.Role != "leader" {
		return "leader " + leader + " does not claim leadership"
	}
	for _, id := range ids {
		h := hs[id]
		if h.LeaderID != leader || h.Term != lh.Term {
			return fmt.Sprintf("%s follows %q in term %d, %s leads term %d", id, h.LeaderID, h.Term, leader, lh.Term)
		}
		if !applied {
			continue
		}
		if h.AppliedIndex != lh.CommitIndex {
			return fmt.Sprintf("%s applied %d, leader commit %d", id, h.AppliedIndex, lh.CommitIndex)
		}
		if !h.Initialized {
			return id + " has no cluster key"
		}
	}
	return ""
}
