//go:build unix

package chaos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/tlsutil"
)

// ProcsConfig configures a cluster of real vaultd processes.
type ProcsConfig struct {
	Nodes     int
	Dir       string // per-node directories with config, certificates, data and logs
	VaultdBin string
	// TLS selects real mutual TLS (household CA, node certificates, node
	// identity checks on the peer listener) instead of insecure mode.
	TLS               bool
	TickMs            int
	ElectionTicks     int
	SnapshotThreshold uint64
	BootstrapToken    string
	Seed              int64
	LogLevel          string // vaultd log_level; default "info"
}

type procsCluster struct {
	cfg    ProcsConfig
	ids    []string
	nodes  map[string]*procNode
	fwd    map[link]*Forwarder
	hc     *http.Client
	scheme string
	pidDir string

	tokMu      sync.Mutex
	adminToken string

	watchdog *exec.Cmd
	find     findings

	pidMu   sync.Mutex
	allPids []int
}

type procNode struct {
	c          *procsCluster
	id         string
	dir        string
	cfgPath    string
	logPath    string
	clientAddr string
	peerAddr   string // the node's real peer listener

	mu      sync.Mutex
	dataDir string
	cmd     *exec.Cmd
	done    chan struct{}
	up      bool
	paused  bool
	inc     int
	expect  bool // the next exit is one we caused
}

// StartProcs builds the configuration (and PKI) for a process cluster and
// starts every node.
func StartProcs(cfg ProcsConfig) (_ Cluster, err error) {
	if cfg.Nodes <= 0 {
		cfg.Nodes = 3
	}
	if cfg.TickMs <= 0 {
		cfg.TickMs = 30
	}
	if cfg.ElectionTicks <= 0 {
		cfg.ElectionTicks = 10
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.VaultdBin == "" {
		return nil, errors.New("procs: VaultdBin is required")
	}
	c := &procsCluster{cfg: cfg, ids: nodeIDs(cfg.Nodes), nodes: map[string]*procNode{}, fwd: map[link]*Forwarder{},
		scheme: "http", pidDir: filepath.Join(cfg.Dir, "pids")}
	if cfg.TLS {
		c.scheme = "https"
	}
	defer func() {
		if err != nil {
			c.Shutdown()
		}
	}()
	if err := os.MkdirAll(c.pidDir, 0o700); err != nil {
		return nil, err
	}
	for _, id := range c.ids {
		ca, err := freeAddr()
		if err != nil {
			return nil, err
		}
		pa, err := freeAddr()
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(cfg.Dir, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		c.nodes[id] = &procNode{c: c, id: id, dir: dir, cfgPath: filepath.Join(dir, "config.json"),
			logPath: filepath.Join(dir, "vaultd.log"), clientAddr: ca, peerAddr: pa, dataDir: filepath.Join(dir, "data")}
	}
	// One forwarder per directed link i -> j, relaying to j's real peer
	// listener. Only node i is told about it.
	for i, from := range c.ids {
		for j, to := range c.ids {
			if from == to {
				continue
			}
			f, err := NewForwarder(c.nodes[to].peerAddr, cfg.Seed+int64(i*31+j))
			if err != nil {
				return nil, err
			}
			c.fwd[link{from, to}] = f
		}
	}
	tr := &http.Transport{
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     30 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if cfg.TLS {
		caPEM, err := c.writePKI()
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c.hc = &http.Client{Transport: tr}
	for _, id := range c.ids {
		if err := c.writeConfig(c.nodes[id]); err != nil {
			return nil, err
		}
	}
	if err := c.startWatchdog(); err != nil {
		return nil, err
	}
	for _, id := range c.ids {
		n := c.nodes[id]
		n.mu.Lock()
		err := n.start()
		n.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("start %s: %w", id, err)
		}
	}
	return c, nil
}

// writePKI creates a household CA constrained to the loopback names and
// node ids actually used, and one certificate per node (CN = node id, SANs
// 127.0.0.1 and localhost), exactly what `vaultd init-cluster` would issue.
func (c *procsCluster) writePKI() ([]byte, error) {
	permitted := append([]string{"127.0.0.1", "localhost"}, c.ids...)
	caPEM, caKey, err := tlsutil.GenerateConstrainedCA("Family Vault chaos CA", 0, permitted)
	if err != nil {
		return nil, err
	}
	for _, id := range c.ids {
		n := c.nodes[id]
		cert, key, err := tlsutil.GenerateNodeCert(caPEM, caKey, id, []string{"127.0.0.1", "localhost"}, 0)
		if err != nil {
			return nil, err
		}
		if err := tlsutil.WriteCertFile(filepath.Join(n.dir, "ca.pem"), caPEM); err != nil {
			return nil, err
		}
		if err := tlsutil.WriteCertFile(filepath.Join(n.dir, "node.pem"), cert); err != nil {
			return nil, err
		}
		if err := tlsutil.WriteKeyFile(filepath.Join(n.dir, "node-key.pem"), key); err != nil {
			return nil, err
		}
	}
	return caPEM, nil
}

func (c *procsCluster) writeConfig(n *procNode) error {
	cfg := vaultdConfig{
		NodeID: n.id, DataDir: n.dataDir, ClientListen: n.clientAddr, PeerListen: n.peerAddr,
		BootstrapToken: c.cfg.BootstrapToken, Insecure: !c.cfg.TLS,
		Raft: &vaultdRaft{TickMs: c.cfg.TickMs, ElectionTicks: c.cfg.ElectionTicks, HeartbeatTicks: 1,
			SnapshotThreshold: c.cfg.SnapshotThreshold},
		// The periodic local dump would only add noise (and a read barrier)
		// to the runs; the backup drill exercises the endpoint explicitly.
		Backup:   &vaultdBackup{IntervalHours: -1},
		LogLevel: c.cfg.LogLevel,
	}
	if c.cfg.TLS {
		cfg.TLS = &vaultdTLS{CAFile: "ca.pem", CertFile: "node.pem", KeyFile: "node-key.pem"}
	}
	for _, p := range c.ids {
		addr := c.nodes[p].peerAddr
		if p != n.id {
			addr = c.fwd[link{n.id, p}].Addr()
		}
		cfg.Peers = append(cfg.Peers, vaultdPeer{ID: p, PeerAddr: addr, PublicURL: c.scheme + "://" + c.nodes[p].clientAddr})
	}
	return writeVaultdConfig(n.cfgPath, cfg)
}

// startWatchdog launches a tiny shell process that outlives us: once this
// process is gone (crashed, SIGKILLed, killed by `go test -timeout`) it
// SIGKILLs every vaultd whose pid file is still present. Deferred cleanup
// handles every orderly exit; the watchdog covers the disorderly ones.
func (c *procsCluster) startWatchdog() error {
	script := fmt.Sprintf(`while kill -0 %d 2>/dev/null; do sleep 0.5; done
for f in %q/*.pid; do [ -f "$f" ] || continue; p=$(cat "$f"); kill -9 -"$p" 2>/dev/null; kill -9 "$p" 2>/dev/null; rm -f "$f"; done`,
		os.Getpid(), c.pidDir)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("watchdog: %w", err)
	}
	c.watchdog = cmd
	go func() { _ = cmd.Wait() }()
	return nil
}

// start launches the node's process in its own process group (so a
// terminal Ctrl-C reaches only the harness, which then reaps the group). n.mu held.
func (n *procNode) start() error {
	logf, err := os.OpenFile(n.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fmt.Fprintf(logf, "=== chaos: starting %s incarnation %d at %s ===\n", n.id, n.inc+1, time.Now().Format(time.RFC3339Nano))
	cmd := exec.Command(n.c.cfg.VaultdBin, "run", "--config", n.cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	pid := cmd.Process.Pid
	pidFile := filepath.Join(n.c.pidDir, n.id+".pid")
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o600)
	n.c.pidMu.Lock()
	n.c.allPids = append(n.c.allPids, pid)
	n.c.pidMu.Unlock()
	n.inc++
	n.cmd, n.up, n.paused, n.expect = cmd, true, false, false
	done := make(chan struct{})
	n.done = done
	inc := n.inc
	go func() {
		err := cmd.Wait()
		logf.Close()
		_ = os.Remove(pidFile)
		n.mu.Lock()
		expected := n.expect && n.inc == inc
		if n.inc == inc {
			n.up = false
		}
		n.mu.Unlock()
		if !expected {
			n.c.find.add("vaultd %s (incarnation %d, pid %d) exited on its own: %v; log tail:\n%s", n.id, inc, pid, err, tailFile(n.logPath, 2048))
		}
		close(done)
	}()
	return nil
}

// kill SIGKILLs the node's process group and reaps it. n.mu held.
func (n *procNode) kill() {
	if n.cmd == nil || !n.up {
		return
	}
	n.expect = true
	pid := n.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	done, inc := n.done, n.inc
	// The reaper goroutine needs n.mu to record the exit.
	n.mu.Unlock()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		n.c.find.add("vaultd %s (pid %d) did not exit within 15s of SIGKILL", n.id, pid)
	}
	n.mu.Lock()
	if n.inc == inc {
		n.up, n.paused = false, false
	}
}

func (c *procsCluster) Mode() string { return "procs" }
func (c *procsCluster) IDs() []string {
	return append([]string(nil), c.ids...)
}
func (c *procsCluster) URL(id string) string     { return c.scheme + "://" + c.nodes[id].clientAddr }
func (c *procsCluster) HTTPClient() *http.Client { return c.hc }
func (c *procsCluster) Findings() []string       { return c.find.get() }
func (c *procsCluster) Capabilities() Caps {
	return Caps{Pause: true, Loss: true, Delay: true, Blackhole: true}
}
func (c *procsCluster) SetAdminToken(tok string) {
	c.tokMu.Lock()
	c.adminToken = tok
	c.tokMu.Unlock()
}

func (c *procsCluster) Incarnation(id string) int {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.inc
}

func (c *procsCluster) Kill(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	n.kill()
	return nil
}

func (c *procsCluster) Restart(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up {
		return nil
	}
	return n.start()
}

func (c *procsCluster) Pause(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up || n.paused {
		return nil
	}
	if err := syscall.Kill(-n.cmd.Process.Pid, syscall.SIGSTOP); err != nil {
		return err
	}
	n.paused = true
	return nil
}

func (c *procsCluster) Resume(id string) error {
	n := c.nodes[id]
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up || !n.paused {
		return nil
	}
	if err := syscall.Kill(-n.cmd.Process.Pid, syscall.SIGCONT); err != nil {
		return err
	}
	n.paused = false
	return nil
}

func (c *procsCluster) SetLink(from, to string, f LinkFault) error {
	fw := c.fwd[link{from, to}]
	if fw == nil {
		return fmt.Errorf("no link %s -> %s", from, to)
	}
	fw.Set(f)
	return nil
}

func (c *procsCluster) HealNetwork() {
	for _, f := range c.fwd {
		f.Set(LinkFault{})
	}
}

func (c *procsCluster) getJSON(ctx context.Context, id, path, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL(id)+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s on %s: %d %s", path, id, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func (c *procsCluster) Health(ctx context.Context, id string) (*api.HealthResponse, error) {
	n := c.nodes[id]
	n.mu.Lock()
	up, paused := n.up, n.paused
	n.mu.Unlock()
	if !up || paused {
		return nil, fmt.Errorf("%s is down or paused", id)
	}
	var h api.HealthResponse
	if err := c.getJSON(ctx, id, "/v1/health", "", &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Digest hashes the `state` of GET /v1/admin/backup: the node's canonical
// snapshot minus the cluster key. It is taken after a read barrier on that
// node; at the end of a run nothing is being written, so every node's
// snapshot reflects the same applied index (checked via /v1/health before
// and after).
func (c *procsCluster) Digest(ctx context.Context, id string) (*Digest, error) {
	c.tokMu.Lock()
	tok := c.adminToken
	c.tokMu.Unlock()
	if tok == "" {
		return nil, errors.New("no admin token for GET /v1/admin/backup")
	}
	h1, err := c.Health(ctx, id)
	if err != nil {
		return nil, err
	}
	var b api.ServerBackup
	if err := c.getJSON(ctx, id, "/v1/admin/backup", tok, &b); err != nil {
		return nil, err
	}
	h2, err := c.Health(ctx, id)
	if err != nil {
		return nil, err
	}
	if h1.AppliedIndex != h2.AppliedIndex {
		return nil, fmt.Errorf("%s applied index moved during the digest (%d -> %d)", id, h1.AppliedIndex, h2.AppliedIndex)
	}
	sum := sha256.Sum256(b.State)
	return &Digest{Node: id, Applied: h2.AppliedIndex, Commit: h2.CommitIndex, Rev: b.Rev,
		Hash: hex.EncodeToString(sum[:]), HashKind: "backup-state"}, nil
}

func (c *procsCluster) RestoreFromBackup(ctx context.Context, vaultdBin, backupPath string) (map[string]string, error) {
	return restoreAll(ctx, c, vaultdBin, backupPath, func(id string) (string, error) {
		n := c.nodes[id]
		n.mu.Lock()
		n.dataDir = filepath.Join(n.dir, fmt.Sprintf("data-restored-%d", n.inc))
		n.mu.Unlock()
		return n.cfgPath, c.writeConfig(n)
	})
}

func (c *procsCluster) Shutdown() error {
	for _, id := range c.ids {
		if n := c.nodes[id]; n != nil {
			n.mu.Lock()
			n.kill()
			n.mu.Unlock()
		}
	}
	for _, f := range c.fwd {
		f.Close()
	}
	if c.hc != nil {
		c.hc.CloseIdleConnections()
	}
	if c.watchdog != nil && c.watchdog.Process != nil {
		_ = syscall.Kill(-c.watchdog.Process.Pid, syscall.SIGKILL)
		_ = c.watchdog.Process.Kill()
	}
	return nil
}

// Leftovers reports any vaultd process this cluster started that is still
// alive (it must be none after Shutdown), checked both by pid and by
// scanning the process table for our config paths.
func (c *procsCluster) Leftovers() []string {
	var out []string
	c.pidMu.Lock()
	pids := append([]int(nil), c.allPids...)
	c.pidMu.Unlock()
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err == nil || errors.Is(err, syscall.EPERM) {
			out = append(out, fmt.Sprintf("pid %d still exists", pid))
		}
	}
	if b, err := exec.Command("ps", "-axo", "pid=,command=").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, c.cfg.Dir) && strings.Contains(line, "vaultd") && strings.Contains(line, " run ") {
				out = append(out, "process still running: "+strings.TrimSpace(line))
			}
		}
	}
	return out
}

func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	if len(b) > n {
		b = b[len(b)-n:]
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return string(b)
}
