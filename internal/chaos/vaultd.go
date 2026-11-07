package chaos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const modulePath = "github.com/tarnan3751/password-vault"

// moduleRoot finds the repository root: first by walking up from the
// working directory, then from this source file's location (which works for
// `go test` and for a vault-chaos binary built on this machine).
func moduleRoot() (string, error) {
	try := func(dir string) (string, bool) {
		for {
			b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
			if err == nil && strings.Contains(string(b), "module "+modulePath+"\n") {
				return dir, true
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return "", false
			}
			dir = parent
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if d, ok := try(wd); ok {
			return d, nil
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		if d, ok := try(filepath.Dir(file)); ok {
			return d, nil
		}
	}
	return "", errors.New("cannot locate the password-vault module; pass the path of a vaultd binary instead")
}

var vaultdBuild struct {
	sync.Mutex
	dir, bin string
}

// vaultdBinary returns cfg.VaultdBin, or a vaultd compiled once per process
// from ./cmd/vaultd into a temporary directory (CleanupBuild removes it).
// Other packages may be mid-edit by someone else, so a failing build is
// retried for a while before giving up.
func vaultdBinary(ctx context.Context, cfg RunConfig) (string, error) {
	if cfg.VaultdBin != "" {
		return cfg.VaultdBin, nil
	}
	b := &vaultdBuild
	b.Lock()
	defer b.Unlock()
	if _, err := os.Stat(b.bin); b.bin != "" && err == nil {
		return b.bin, nil
	}
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	if b.dir == "" {
		if b.dir, err = os.MkdirTemp("", "vault-chaos-bin-"); err != nil {
			return "", fmt.Errorf("cannot create a temp dir for the vaultd build: %w", err)
		}
	}
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(b.dir, "vaultd")
	deadline := time.Now().Add(3 * time.Minute)
	for {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/vaultd")
		cmd.Dir = root
		msg, err := cmd.CombinedOutput()
		if err == nil {
			b.bin = out
			return out, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return "", fmt.Errorf("go build ./cmd/vaultd: %v\n%s", err, msg)
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

// CleanupBuild removes the vaultd build directory (call at process exit).
func CleanupBuild() {
	vaultdBuild.Lock()
	defer vaultdBuild.Unlock()
	if vaultdBuild.dir != "" {
		os.RemoveAll(vaultdBuild.dir)
	}
}

var digestRe = regexp.MustCompile(`State digest: ([0-9a-f]{64})`)

// runVaultdRestore runs `vaultd restore --config cfg --from backup` and
// returns the state digest it prints.
func runVaultdRestore(ctx context.Context, bin, cfgPath, backupPath string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "restore", "--config", cfgPath, "--from", backupPath)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vaultd restore: %v: %s", err, strings.TrimSpace(buf.String()))
	}
	m := digestRe.FindStringSubmatch(buf.String())
	if m == nil {
		return "", fmt.Errorf("vaultd restore printed no state digest: %s", strings.TrimSpace(buf.String()))
	}
	return m[1], nil
}

// vaultdConfig is the part of a vaultd config file the harness writes. Only
// `vaultd run` reads the Raft and backup sections; `vaultd restore` needs
// the node, its directories and its peers.
type vaultdConfig struct {
	NodeID         string        `json:"node_id"`
	DataDir        string        `json:"data_dir"`
	ClientListen   string        `json:"client_listen"`
	PeerListen     string        `json:"peer_listen"`
	Peers          []vaultdPeer  `json:"peers"`
	TLS            *vaultdTLS    `json:"tls,omitempty"`
	BootstrapToken string        `json:"bootstrap_token,omitempty"`
	Insecure       bool          `json:"insecure,omitempty"`
	Raft           *vaultdRaft   `json:"raft,omitempty"`
	Backup         *vaultdBackup `json:"backup,omitempty"`
	LogLevel       string        `json:"log_level,omitempty"`
}

type vaultdPeer struct {
	ID        string `json:"id"`
	PeerAddr  string `json:"peer_addr"`
	PublicURL string `json:"public_url"`
}

type vaultdTLS struct {
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type vaultdRaft struct {
	TickMs            int    `json:"tick_ms,omitempty"`
	ElectionTicks     int    `json:"election_ticks,omitempty"`
	HeartbeatTicks    int    `json:"heartbeat_ticks,omitempty"`
	SnapshotThreshold uint64 `json:"snapshot_threshold,omitempty"`
}

type vaultdBackup struct {
	IntervalHours int `json:"interval_hours"`
}

func writeVaultdConfig(path string, cfg vaultdConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// restoreAll runs the documented disaster-recovery procedure with the real
// `vaultd restore`: stop every node, restore the same backup into a fresh
// data directory on every node (concurrently), then start them all. prepare
// points a node at its fresh directory and returns the config file to
// restore with. The result maps node id to the state digest it printed.
func restoreAll(ctx context.Context, c Cluster, bin, backupPath string, prepare func(id string) (string, error)) (map[string]string, error) {
	if bin == "" {
		return nil, errors.New("no vaultd binary configured for the restore drill")
	}
	ids := c.IDs()
	for _, id := range ids {
		_ = c.Kill(id)
	}
	digests := map[string]string{}
	errs := make([]error, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfgPath, err := prepare(id)
			if err == nil {
				var d string
				if d, err = runVaultdRestore(ctx, bin, cfgPath, backupPath); err == nil {
					mu.Lock()
					digests[id] = d
					mu.Unlock()
				}
			}
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", id, err)
			}
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := c.Restart(id); err != nil {
			return digests, err
		}
	}
	return digests, nil
}
