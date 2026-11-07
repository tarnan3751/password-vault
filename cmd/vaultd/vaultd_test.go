package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft/filestore"
	"github.com/tarnan3751/password-vault/internal/tlsutil"
)

// writeConfig writes cfg as JSON into a fresh directory and returns its path.
func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func devConfig() map[string]any {
	return map[string]any{
		"node_id":       "n1",
		"data_dir":      "data",
		"client_listen": "127.0.0.1:8001",
		"peer_listen":   "127.0.0.1:9001",
		"peers": []map[string]any{
			{"id": "n1", "peer_addr": "127.0.0.1:9001", "public_url": "http://127.0.0.1:8001"},
			{"id": "n2", "peer_addr": "127.0.0.1:9002", "public_url": "http://127.0.0.1:8002"},
			{"id": "n3", "peer_addr": "127.0.0.1:9003", "public_url": "http://127.0.0.1:8003"},
		},
		"bootstrap_token": "dev-bootstrap-token-0000",
		"insecure":        true,
	}
}

func TestLoadConfigDevCluster(t *testing.T) {
	path := writeConfig(t, devConfig())
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("valid dev config rejected: %v", err)
	}
	if want := filepath.Join(filepath.Dir(path), "data"); cfg.DataDir != want {
		t.Errorf("data_dir = %q, want it resolved against the config file: %q", cfg.DataDir, want)
	}
	if cfg.peerScheme() != "http" {
		t.Errorf("insecure config should use http between peers")
	}
}

func TestLoadConfigRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c map[string]any)
		want   string // substring of the error
	}{
		{"unknown key (a typo must not silently disable a setting)", func(c map[string]any) { c["boostrap_token"] = "x" }, "unknown field"},
		{"node not in peers", func(c map[string]any) { c["node_id"] = "n9" }, "not listed in peers"},
		{"even number of peers", func(c map[string]any) {
			c["peers"] = c["peers"].([]map[string]any)[:2]
		}, "odd number"},
		{"duplicate peer", func(c map[string]any) {
			p := c["peers"].([]map[string]any)
			p[2]["id"] = "n2"
		}, "duplicate peer"},
		{"bad node id", func(c map[string]any) { c["node_id"] = "../etc" }, "node_id"},
		{"short bootstrap token", func(c map[string]any) { c["bootstrap_token"] = "short" }, "at least 16"},
		{"bad log level", func(c map[string]any) { c["log_level"] = "loud" }, "log_level"},
		{"TLS required unless insecure", func(c map[string]any) {
			delete(c, "insecure")
			for _, p := range c["peers"].([]map[string]any) {
				p["public_url"] = strings.Replace(p["public_url"].(string), "http://", "https://", 1)
			}
		}, "tls.ca_file"},
		{"plain-http public URL without insecure", func(c map[string]any) { delete(c, "insecure") }, "plain http"},
		// Insecure mode has no transport authentication at all, so it must
		// not be reachable from anywhere but this machine.
		{"insecure on a public client address", func(c map[string]any) { c["client_listen"] = "0.0.0.0:8001" }, "loopback"},
		{"insecure on a public peer address", func(c map[string]any) { c["peer_listen"] = "192.168.1.5:9001" }, "loopback"},
		{"insecure with a remote peer", func(c map[string]any) {
			c["peers"].([]map[string]any)[1]["peer_addr"] = "vps.example.com:9002"
		}, "loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(allowInsecureNetworkEnv, "")
			c := devConfig()
			tc.mutate(c)
			_, err := loadConfig(writeConfig(t, c))
			if err == nil {
				t.Fatalf("config accepted, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestInsecureNetworkOverride(t *testing.T) {
	c := devConfig()
	c["client_listen"] = "0.0.0.0:8001"
	path := writeConfig(t, c)
	t.Setenv(allowInsecureNetworkEnv, "1")
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("explicit override not honoured: %v", err)
	}
}

func TestBootstrapTokenFile(t *testing.T) {
	c := devConfig()
	delete(c, "bootstrap_token")
	c["bootstrap_token_file"] = "bootstrap-token"
	path := writeConfig(t, c)

	// A missing file is the normal state once the first user exists.
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("missing token file should be tolerated: %v", err)
	}
	if cfg.BootstrapToken != "" {
		t.Errorf("token = %q, want empty", cfg.BootstrapToken)
	}

	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "bootstrap-token"), []byte("  ABCD-EFGH-IJKL-MNOP-QRST\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapToken != "ABCD-EFGH-IJKL-MNOP-QRST" {
		t.Errorf("token = %q, want the trimmed file content", cfg.BootstrapToken)
	}
}

func TestInitClusterProducesLoadableConfigs(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cluster")
	err := cmdInitCluster([]string{"--out", out,
		"--node", "pi=pi.vault.internal,192.168.1.10",
		"--node", "vps=vps.vault.internal",
		"--node", "laptop=laptop.vault.internal"})
	if err != nil {
		t.Fatalf("init-cluster: %v", err)
	}

	// Secrets are private; the CA certificate is meant to be handed out.
	for path, want := range map[string]os.FileMode{
		"ca-key.pem":         0o600,
		"ca.pem":             0o644,
		"pi/node-key.pem":    0o600,
		"pi/config.json":     0o600,
		"pi/bootstrap-token": 0o600,
	} {
		st, err := os.Stat(filepath.Join(out, path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}

	var tokens []string
	for _, n := range []string{"pi", "vps", "laptop"} {
		cfg, err := loadConfig(filepath.Join(out, n, "config.json"))
		if err != nil {
			t.Fatalf("generated config for %s does not load: %v", n, err)
		}
		if cfg.NodeID != n || len(cfg.Peers) != 3 || cfg.Insecure {
			t.Errorf("%s: unexpected config %+v", n, cfg)
		}
		if cfg.BootstrapToken == "" {
			t.Errorf("%s: no bootstrap token", n)
		}
		tokens = append(tokens, cfg.BootstrapToken)
		if _, err := tlsutil.PeerServerConfig(cfg.TLS.CAFile, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			t.Errorf("%s: peer TLS material unusable: %v", n, err)
		}
		if _, err := tlsutil.APIServerConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			t.Errorf("%s: API TLS material unusable: %v", n, err)
		}
	}
	if tokens[0] != tokens[1] || tokens[1] != tokens[2] {
		t.Errorf("nodes got different bootstrap tokens")
	}

	// A second run must not silently replace the CA every device trusts.
	if err := cmdInitCluster([]string{"--out", out, "--node", "a=a.x", "--node", "b=b.x", "--node", "c=c.x"}); err == nil {
		t.Fatal("init-cluster overwrote an existing CA")
	}

	// The CA only vouches for this cluster's names.
	if err := cmdIssueCert([]string{"--ca-dir", out, "--node", "pi=bank.example.com", "--out", filepath.Join(out, "x")}); err == nil {
		t.Fatal("issued a certificate for a host outside the CA's name constraints")
	}
	if err := cmdIssueCert([]string{"--ca-dir", out, "--node", "pi=pi.vault.internal", "--out", filepath.Join(out, "renewed")}); err != nil {
		t.Fatalf("renewing a node certificate failed: %v", err)
	}
}

func TestInitClusterArgumentChecks(t *testing.T) {
	out := t.TempDir()
	for name, args := range map[string][]string{
		"even node count": {"--out", out, "--node", "a=a.x", "--node", "b=b.x"},
		"duplicate id":    {"--out", out, "--node", "a=a.x", "--node", "a=b.x", "--node", "c=c.x"},
		"missing out":     {"--node", "a=a.x"},
		"bad node id":     {"--out", out, "--node", "A_B=a.x"},
		"no host":         {"--out", out, "--node", "a="},
	} {
		if err := cmdInitCluster(args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRestore(t *testing.T) {
	// A real (empty) state machine snapshot, wrapped the way the admin
	// backup endpoint does.
	state, rev, err := fsm.New().BackupSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeBackup := func(name string, b api.ServerBackup) string {
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := writeBackup("good.json", api.ServerBackup{Format: "fpv-server-backup", Version: 1, NodeID: "n1", Rev: rev + 41, State: state})
	cfgPath := writeConfig(t, devConfig())

	for name, path := range map[string]string{
		"a user export is not a server backup": writeBackup("export.json", api.ServerBackup{Format: "fpv-backup", Version: 1, State: state}),
		"unsupported version":                  writeBackup("v2.json", api.ServerBackup{Format: "fpv-server-backup", Version: 2, State: state}),
		"garbage state":                        writeBackup("bad.json", api.ServerBackup{Format: "fpv-server-backup", Version: 1, State: []byte(`{"nope":true}`)}),
	} {
		if err := cmdRestore([]string{"--config", cfgPath, "--from", path}); err == nil {
			t.Errorf("%s: restore accepted it", name)
		}
	}

	if err := cmdRestore([]string{"--config", cfgPath, "--from", good}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// The data directory now holds exactly a snapshot at index rev+1, so
	// that of two differently restored nodes the newer state wins.
	store, err := filestore.Open(filepath.Join(filepath.Dir(cfgPath), "data", "raft"), filestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	hs, snap, entries, err := store.Load()
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	if snap == nil || snap.Meta.Index != rev+42 || snap.Meta.Term != 1 || hs.Term != 1 || len(entries) != 0 {
		t.Fatalf("after restore: hard state %+v, snapshot %+v, %d entries", hs, snap, len(entries))
	}
	if string(snap.Data) != string(state) {
		t.Fatal("restored snapshot differs from the backup's state")
	}

	// Restoring over existing Raft state would mix two histories.
	if err := cmdRestore([]string{"--config", cfgPath, "--from", good}); err == nil {
		t.Fatal("restore into a non-empty data directory was accepted")
	}
}
