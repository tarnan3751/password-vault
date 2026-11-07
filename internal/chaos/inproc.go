package chaos

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/filestore"
	"github.com/tarnan3751/password-vault/internal/raft/httptransport"
	"github.com/tarnan3751/password-vault/internal/server"
)

// InprocConfig configures an in-process cluster.
type InprocConfig struct {
	Nodes int
	Dir   string // every node gets <Dir>/<id> as its data_dir (filestore in <data_dir>/raft, as in vaultd)
	// Fsync selects real fsync; false sets filestore NoSync for speed. A
	// "kill" here is a process-level crash (the OS keeps written data
	// either way), so NoSync does not weaken what is being tested.
	Fsync             bool
	TickInterval      time.Duration
	ElectionTicks     int
	SnapshotThreshold uint64
	BootstrapToken    string
	Seed              int64
	// LogDir receives one log file per node ("" = discard logs).
	LogDir string
	// FlushDelay, when positive, makes every durable write of a node take
	// this long (and turns real fsync off): each node then behaves as if it
	// had its own disk. Three nodes sharing this machine's one SSD queue up
	// behind each other's fsync, which no real deployment does, so the
	// benchmarks use this to measure what a separate-machines cluster does.
	FlushDelay time.Duration
}

// ownDisk delays the writes Raft waits for by a fixed flush time.
type ownDisk struct {
	raft.Storage
	flush time.Duration
}

func (d ownDisk) Append(e []raft.Entry) error {
	time.Sleep(d.flush)
	return d.Storage.Append(e)
}

func (d ownDisk) SaveHardState(h raft.HardState) error {
	time.Sleep(d.flush)
	return d.Storage.SaveHardState(h)
}

type inprocCluster struct {
	cfg   InprocConfig
	ids   []string
	peers []api.ClusterNode
	net   *FaultNet
	nodes map[string]*inprocNode
	hc    *http.Client
	find  findings
}

type inprocNode struct {
	c        *inprocCluster
	id       string
	apiAddr  string
	peerAddr string
	log      *slog.Logger
	logFile  *os.File

	mu        sync.Mutex
	dataDir   string
	up        bool
	inc       int
	killedInc int // incarnation we stopped on purpose
	store     *filestore.Store
	ft        *FaultTransport
	rn        raft.Node
	state     *fsm.FSM
	srv       *server.Server
	apiHTTP   *http.Server
	peerHTTP  *http.Server
}

// lifecycle is raft.Lifecycle, declared locally so the harness keeps
// compiling if that optional interface moves.
type lifecycle interface {
	Done() <-chan struct{}
	Err() error
}

// StartInproc starts an in-process cluster and returns once every node is
// running (not necessarily with a leader yet).
func StartInproc(cfg InprocConfig) (Cluster, error) {
	if cfg.Nodes <= 0 {
		cfg.Nodes = 3
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 25 * time.Millisecond
	}
	if cfg.ElectionTicks <= 0 {
		cfg.ElectionTicks = 10
	}
	c := &inprocCluster{cfg: cfg, ids: nodeIDs(cfg.Nodes), net: NewFaultNet(cfg.Seed), nodes: map[string]*inprocNode{}}
	c.hc = &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     30 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
	}}
	type lns struct{ api, peer net.Listener }
	listeners := map[string]lns{}
	fail := func(err error) (Cluster, error) {
		for _, l := range listeners {
			l.api.Close()
			l.peer.Close()
		}
		c.Shutdown()
		return nil, err
	}
	for _, id := range c.ids {
		apiLn, err := listenNode()
		if err != nil {
			return fail(err)
		}
		peerLn, err := listenNode()
		if err != nil {
			apiLn.Close()
			return fail(err)
		}
		listeners[id] = lns{apiLn, peerLn}
		n := &inprocNode{c: c, id: id, apiAddr: apiLn.Addr().String(), peerAddr: peerLn.Addr().String(),
			dataDir: filepath.Join(cfg.Dir, id)}
		n.log = slog.New(slog.DiscardHandler)
		if cfg.LogDir != "" {
			f, err := os.OpenFile(filepath.Join(cfg.LogDir, id+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return fail(err)
			}
			n.logFile = f
			n.log = slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})).With("node", id)
		}
		c.nodes[id] = n
		c.peers = append(c.peers, api.ClusterNode{ID: id, PublicURL: "http://" + n.apiAddr})
	}
	for _, id := range c.ids {
		n := c.nodes[id]
		l := listeners[id]
		delete(listeners, id)
		n.mu.Lock()
		err := n.boot(l.api, l.peer)
		n.mu.Unlock()
		if err != nil {
			return fail(fmt.Errorf("start %s: %w", id, err))
		}
	}
	return c, nil
}

func (c *inprocCluster) Mode() string              { return "inproc" }
func (c *inprocCluster) IDs() []string             { return append([]string(nil), c.ids...) }
func (c *inprocCluster) URL(id string) string      { return "http://" + c.nodes[id].apiAddr }
func (c *inprocCluster) HTTPClient() *http.Client  { return c.hc }
func (c *inprocCluster) SetAdminToken(string)      {}
func (c *inprocCluster) Findings() []string        { return c.find.get() }
func (c *inprocCluster) FaultStats() FaultNetStats { return c.net.Stats() }
func (c *inprocCluster) Capabilities() Caps {
	return Caps{Loss: true, Dup: true, Delay: true}
}

func (c *inprocCluster) Incarnation(id string) int {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.inc
}

// boot wires one node exactly like cmd/vaultd (startNode in run.go):
// storage, peer transport (wrapped by the fault decorator), peer listener
// before Raft, state machine, Raft, API server, client listener. n.mu held.
func (n *inprocNode) boot(apiLn, peerLn net.Listener) (err error) {
	c := n.c
	// undo releases what is built so far, newest first, if boot fails.
	undo := []func(){func() { apiLn.Close(); peerLn.Close() }}
	defer func() {
		for i := len(undo) - 1; err != nil && i >= 0; i-- {
			undo[i]()
		}
	}()
	store, err := filestore.Open(filepath.Join(n.dataDir, "raft"), filestore.Options{
		NoSync: !c.cfg.Fsync || c.cfg.FlushDelay > 0, Logger: n.log.With("component", "filestore"),
	})
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	undo = append(undo, func() { store.Close() })
	var disk raft.Storage = store
	if c.cfg.FlushDelay > 0 {
		disk = ownDisk{store, c.cfg.FlushDelay}
	}
	peerURLs := map[string]string{}
	for _, id := range c.ids {
		if id != n.id {
			peerURLs[id] = "http://" + c.nodes[id].peerAddr
		}
	}
	// Same HTTP client settings as vaultd's peer client, minus TLS.
	peerClient := &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
	}}
	ht, err := httptransport.New(httptransport.Options{
		LocalID: n.id, Peers: peerURLs, Client: peerClient,
		MaxBodyBytes: 256 << 20, Logger: n.log.With("component", "transport"),
	})
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	ft := c.net.Wrap(n.id, ht)
	undo = append(undo, func() { ft.Close() })
	peerMux := http.NewServeMux()
	peerMux.Handle("/raft/", ht.Handler())
	peerHTTP := &http.Server{Handler: peerMux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug)}
	go func() { _ = peerHTTP.Serve(peerLn) }()
	undo = append(undo, func() { peerHTTP.Close() })

	state := fsm.New()
	rn, err := raft.StartNode(raft.Config{
		ID: n.id, Peers: c.ids, Storage: disk, Transport: ft, StateMachine: state,
		TickInterval: c.cfg.TickInterval, ElectionTicks: c.cfg.ElectionTicks, HeartbeatTicks: 1,
		SnapshotThreshold: c.cfg.SnapshotThreshold, Logger: n.log.With("component", "raft"),
	})
	if err != nil {
		return fmt.Errorf("start raft: %w", err)
	}
	undo = append(undo, func() { rn.Stop() })
	srv, err := server.New(server.Config{
		NodeID: n.id, Raft: rn, FSM: state, Peers: c.peers, BootstrapToken: c.cfg.BootstrapToken,
		Version: "chaos", Logger: n.log.With("component", "api"),
	})
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	srv.Start()
	apiHTTP := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug)}
	go func() { _ = apiHTTP.Serve(apiLn) }()

	n.inc++
	n.up = true
	n.store, n.ft, n.rn, n.state, n.srv, n.apiHTTP, n.peerHTTP = store, ft, rn, state, srv, apiHTTP, peerHTTP
	if lc, ok := rn.(lifecycle); ok {
		inc := n.inc
		go func() {
			<-lc.Done()
			n.mu.Lock()
			deliberate := n.killedInc >= inc
			n.mu.Unlock()
			if !deliberate {
				c.find.add("node %s (incarnation %d) stopped on its own: %v", n.id, inc, lc.Err())
			}
		}()
	}
	n.log.Info("chaos: node started", "incarnation", n.inc)
	return nil
}

// kill stops the node abruptly: listeners and connections first (so
// nothing more leaves or enters), then the transport, background loops,
// Raft and finally the store, which releases the directory lock. Nothing
// is flushed or handed over: whatever filestore had made durable is what
// the next incarnation finds. n.mu held.
func (n *inprocNode) kill() {
	if !n.up {
		return
	}
	n.up = false
	n.killedInc = n.inc
	_ = n.apiHTTP.Close()
	_ = n.peerHTTP.Close()
	_ = n.ft.Close()
	_ = n.srv.Close()
	_ = n.rn.Stop()
	_ = n.store.Close()
	n.log.Info("chaos: node killed", "incarnation", n.inc)
}

func (c *inprocCluster) Kill(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	n.kill()
	return nil
}

func (c *inprocCluster) Restart(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up {
		return nil
	}
	apiLn, err := listenRetry(n.apiAddr)
	if err != nil {
		return fmt.Errorf("re-listen %s: %w", n.apiAddr, err)
	}
	peerLn, err := listenRetry(n.peerAddr)
	if err != nil {
		apiLn.Close()
		return fmt.Errorf("re-listen %s: %w", n.peerAddr, err)
	}
	if err := n.boot(apiLn, peerLn); err != nil {
		// A node that cannot start from its own data directory (say,
		// filestore refuses what a crash left behind) is a finding.
		c.find.add("restart of %s failed: %v", id, err)
		return err
	}
	return nil
}

func (c *inprocCluster) Pause(string) error  { return ErrNotSupported }
func (c *inprocCluster) Resume(string) error { return nil }

func (c *inprocCluster) SetLink(from, to string, f LinkFault) error {
	c.net.Set(from, to, f)
	return nil
}

func (c *inprocCluster) HealNetwork() { c.net.Heal() }

func (c *inprocCluster) running(id string) (raft.Node, *fsm.FSM, error) {
	n := c.nodes[id]
	if n == nil {
		return nil, nil, fmt.Errorf("unknown node %q", id)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return nil, nil, fmt.Errorf("%s is down", id)
	}
	return n.rn, n.state, nil
}

func (c *inprocCluster) Health(_ context.Context, id string) (*api.HealthResponse, error) {
	rn, state, err := c.running(id)
	if err != nil {
		return nil, err
	}
	st := rn.Status()
	h := &api.HealthResponse{NodeID: id, Role: st.Role.String(), LeaderID: st.LeaderID, Term: st.Term,
		CommitIndex: st.CommitIndex, AppliedIndex: st.LastApplied}
	state.View(func(v *fsm.View) {
		h.Initialized = v.Initialized()
		h.HasUsers = v.HasUsers()
	})
	return h, nil
}

// Digest hashes the complete canonical snapshot (fsm.StateHash), which
// includes the cluster key and the idempotency table: replicas that applied
// the same log must agree on every byte of it.
func (c *inprocCluster) Digest(_ context.Context, id string) (*Digest, error) {
	rn, state, err := c.running(id)
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		before := rn.Status()
		h := state.StateHash()
		rev := state.Rev()
		after := rn.Status()
		if before.LastApplied == after.LastApplied || i > 20 {
			return &Digest{Node: id, Applied: after.LastApplied, Commit: after.CommitIndex, Rev: rev,
				Hash: hex.EncodeToString(h[:]), HashKind: "state"}, nil
		}
	}
}

// RestoreFromBackup is the disaster-recovery procedure of restoreAll with
// a vaultd config describing this in-process node, so that the real `vaultd
// restore` seeds the directory the node will use.
func (c *inprocCluster) RestoreFromBackup(ctx context.Context, vaultdBin, backupPath string) (map[string]string, error) {
	return restoreAll(ctx, c, vaultdBin, backupPath, func(id string) (string, error) {
		n := c.nodes[id]
		n.mu.Lock()
		n.dataDir = filepath.Join(c.cfg.Dir, id+"-restored-"+fmt.Sprint(n.inc))
		cfg := vaultdConfig{NodeID: id, DataDir: n.dataDir, ClientListen: n.apiAddr, PeerListen: n.peerAddr, Insecure: true}
		n.mu.Unlock()
		for _, p := range c.ids {
			cfg.Peers = append(cfg.Peers, vaultdPeer{ID: p, PeerAddr: c.nodes[p].peerAddr, PublicURL: "http://" + c.nodes[p].apiAddr})
		}
		path := filepath.Join(c.cfg.Dir, id+"-restore-config.json")
		return path, writeVaultdConfig(path, cfg)
	})
}

func (c *inprocCluster) Shutdown() error {
	for _, id := range c.ids {
		if n := c.nodes[id]; n != nil {
			n.mu.Lock()
			n.kill()
			n.mu.Unlock()
		}
	}
	c.hc.CloseIdleConnections()
	for _, n := range c.nodes {
		if n.logFile != nil {
			n.logFile.Close()
		}
	}
	return nil
}
