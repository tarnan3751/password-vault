// Package clienttest starts real Family Vault server stacks in process for
// the client tests: per node a raft.Node over the in-memory fault-injecting
// network, the real replicated state machine and the real HTTP server. It is
// imported only by tests (internal/client and cmd/fvault); no production code
// depends on it.
package clienttest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/memnet"
	"github.com/tarnan3751/password-vault/internal/server"
)

// BootstrapToken is the configured bootstrap token of every node.
const BootstrapToken = "test-bootstrap-token-0123456789"

// Node is one server stack.
type Node struct {
	ID    string
	Addr  string
	URL   string
	store *raft.MemStorage

	mu   sync.Mutex
	raft raft.Node
	srv  *server.Server
	http *http.Server
	up   bool
}

// Cluster is N nodes that replicate with Raft.
type Cluster struct {
	t     testing.TB
	Net   *memnet.Network
	Nodes []*Node
	ids   []string
	peers []api.ClusterNode
	seed  int64
}

// New starts an n-node cluster and waits until it has a leader and a cluster
// key. It is stopped by t.Cleanup.
func New(t testing.TB, n int) *Cluster {
	t.Helper()
	c := &Cluster{t: t, Net: memnet.New(int64(n) * 104729)}
	c.Net.SetDelay(0, time.Millisecond)
	var lns []net.Listener
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("n%d", i)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		nd := &Node{ID: id, Addr: ln.Addr().String(), URL: "http://" + ln.Addr().String(), store: raft.NewMemStorage()}
		c.Nodes = append(c.Nodes, nd)
		c.ids = append(c.ids, id)
		c.peers = append(c.peers, api.ClusterNode{ID: id, PublicURL: nd.URL})
	}
	for i, nd := range c.Nodes {
		c.boot(nd, lns[i])
	}
	t.Cleanup(c.close)
	c.WaitReady()
	return c
}

// URLs returns every node's client URL.
func (c *Cluster) URLs() []string {
	var u []string
	for _, n := range c.Nodes {
		u = append(u, n.URL)
	}
	return u
}

func (c *Cluster) boot(nd *Node, ln net.Listener) {
	c.t.Helper()
	nd.mu.Lock()
	defer nd.mu.Unlock()
	tr := c.Net.Join(nd.ID)
	c.Net.Reconnect(nd.ID)
	state := fsm.New()
	c.seed++
	rn, err := raft.StartNode(raft.Config{
		ID: nd.ID, Peers: c.ids, Storage: nd.store, Transport: tr, StateMachine: state,
		TickInterval: 15 * time.Millisecond, ElectionTicks: 10, HeartbeatTicks: 1,
		Seed: c.seed*7919 + 1,
	})
	if err != nil {
		c.t.Fatalf("start raft %s: %v", nd.ID, err)
	}
	srv, err := server.New(server.Config{
		NodeID: nd.ID, Raft: rn, FSM: state, Peers: c.peers, BootstrapToken: BootstrapToken,
		ReadTimeout: 1500 * time.Millisecond, ProposeTimeout: 1500 * time.Millisecond, Version: "test",
	})
	if err != nil {
		c.t.Fatalf("server %s: %v", nd.ID, err)
	}
	srv.Start()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	nd.raft, nd.srv, nd.http, nd.up = rn, srv, hs, true
}

// Stop simulates a crash of node i: connections are refused and Raft stops.
func (c *Cluster) Stop(i int) {
	c.t.Helper()
	nd := c.Nodes[i]
	nd.mu.Lock()
	defer nd.mu.Unlock()
	if !nd.up {
		return
	}
	nd.up = false
	_ = nd.http.Close()
	c.Net.Disconnect(nd.ID)
	_ = nd.srv.Close()
	_ = nd.raft.Stop()
}

// Start restarts node i on the same address with its old Raft log.
func (c *Cluster) Start(i int) {
	c.t.Helper()
	nd := c.Nodes[i]
	nd.mu.Lock()
	up := nd.up
	nd.mu.Unlock()
	if up {
		return
	}
	var ln net.Listener
	var err error
	for try := 0; try < 50; try++ {
		if ln, err = net.Listen("tcp", nd.Addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		c.t.Fatalf("re-listen %s: %v", nd.Addr, err)
	}
	c.boot(nd, ln)
}

func (c *Cluster) close() {
	for i := range c.Nodes {
		c.Stop(i)
	}
	c.Net.Close()
}

// WaitReady waits until some running node reports an initialized cluster with a leader.
func (c *Cluster) WaitReady() {
	c.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, nd := range c.Nodes {
			nd.mu.Lock()
			up, rn := nd.up, nd.raft
			nd.mu.Unlock()
			if !up {
				continue
			}
			st := rn.Status()
			if st.LeaderID != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := rn.ReadBarrier(ctx)
				cancel()
				if err == nil && c.initialized(nd) {
					return
				}
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	c.t.Fatal("cluster did not become ready")
}

// initialized reports whether the node has learned the cluster key (until then
// it answers authenticated and prelogin requests with 503).
func (c *Cluster) initialized(nd *Node) bool {
	res, err := http.Get(nd.URL + "/v1/health")
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var h api.HealthResponse
	return json.NewDecoder(res.Body).Decode(&h) == nil && h.Initialized
}

// RestoreFrom stops every node and restarts them all from fresh storage seeded
// with a server backup, exactly as `vaultd restore` does (cmd/vaultd/restore.go):
// the backup state becomes a Raft snapshot at index rev+1, term 1, with a hard
// state of term 1. Tokens are invalid afterwards (the backup omits the cluster
// key), so users log in again.
func (c *Cluster) RestoreFrom(b *api.ServerBackup) {
	c.t.Helper()
	for i := range c.Nodes {
		c.Stop(i)
	}
	for _, nd := range c.Nodes {
		nd.store = raft.NewMemStorage()
		if err := nd.store.InstallSnapshot(raft.Snapshot{Meta: raft.SnapshotMeta{Index: b.Rev + 1, Term: 1}, Data: b.State}); err != nil {
			c.t.Fatal(err)
		}
		if err := nd.store.SaveHardState(raft.HardState{Term: 1}); err != nil {
			c.t.Fatal(err)
		}
	}
	for i := range c.Nodes {
		c.Start(i)
	}
	c.WaitReady()
}
