package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config is the on-disk configuration of one vaultd node (docs/DESIGN.md §8).
// Relative paths are resolved against the directory containing the file.
type Config struct {
	NodeID       string       `json:"node_id"`
	DataDir      string       `json:"data_dir"`
	ClientListen string       `json:"client_listen"`
	PeerListen   string       `json:"peer_listen"`
	Peers        []PeerConfig `json:"peers"`
	TLS          TLSConfig    `json:"tls"`

	// The bootstrap token authorizes the registration of the very first user
	// (who becomes the household admin). Prefer the file form so the secret
	// does not sit in the main config.
	BootstrapToken     string `json:"bootstrap_token,omitempty"`
	BootstrapTokenFile string `json:"bootstrap_token_file,omitempty"`

	// Insecure serves plain HTTP on both listeners. Development only.
	Insecure bool `json:"insecure,omitempty"`

	Raft   RaftConfig   `json:"raft,omitempty"`
	Backup BackupConfig `json:"backup,omitempty"`

	TokenTTLHours int `json:"token_ttl_hours,omitempty"` // default 12
	// MaxSessionAgeDays is how long a session can be kept alive without
	// typing the master password again. Default 30.
	MaxSessionAgeDays int `json:"max_session_age_days,omitempty"`
	// StaleReadWindowHours bounds how long a node that has lost contact with
	// the cluster keeps serving explicitly-stale reads (the "last server
	// standing" fallback). 0 means the default (168 = 7 days); negative
	// disables stale reads.
	StaleReadWindowHours int `json:"stale_read_window_hours,omitempty"`
	// TrustedProxyHeader names a header (e.g. "X-Forwarded-For") to take the
	// client address from when vaultd sits behind a reverse proxy.
	// TrustedProxies lists the proxies (CIDRs or addresses) whose header is
	// believed; empty means loopback only.
	TrustedProxyHeader string   `json:"trusted_proxy_header,omitempty"`
	TrustedProxies     []string `json:"trusted_proxies,omitempty"`
	LogLevel           string   `json:"log_level,omitempty"` // debug | info | warn | error
}

type PeerConfig struct {
	ID        string `json:"id"`
	PeerAddr  string `json:"peer_addr"`  // host:port of the node's peer listener
	PublicURL string `json:"public_url"` // base URL of the node's client API
}

type TLSConfig struct {
	CAFile   string `json:"ca_file"`   // household CA: the only authority trusted for peer connections
	CertFile string `json:"cert_file"` // this node's certificate (CN = node id)
	KeyFile  string `json:"key_file"`
	// Optional separate certificate for the client-facing API, e.g. one from
	// a public CA. Defaults to the node certificate.
	APICertFile string `json:"api_cert_file,omitempty"`
	APIKeyFile  string `json:"api_key_file,omitempty"`
}

type RaftConfig struct {
	TickMs            int    `json:"tick_ms,omitempty"`            // default 100
	ElectionTicks     int    `json:"election_ticks,omitempty"`     // default 10
	HeartbeatTicks    int    `json:"heartbeat_ticks,omitempty"`    // default 1
	SnapshotThreshold uint64 `json:"snapshot_threshold,omitempty"` // default 4096
}

type BackupConfig struct {
	// IntervalHours between automatic local dumps of the replicated state
	// into <data_dir>/backups. 0 means the default (24); negative disables.
	IntervalHours int `json:"interval_hours,omitempty"`
	Keep          int `json:"keep,omitempty"` // default 14
}

var nodeIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// loadConfig reads, resolves and validates a configuration file.
func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // a typo in a security-relevant key must not be silently ignored
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	base := filepath.Dir(path)
	resolve := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	resolve(&cfg.DataDir)
	resolve(&cfg.TLS.CAFile)
	resolve(&cfg.TLS.CertFile)
	resolve(&cfg.TLS.KeyFile)
	resolve(&cfg.TLS.APICertFile)
	resolve(&cfg.TLS.APIKeyFile)
	resolve(&cfg.BootstrapTokenFile)

	if cfg.BootstrapTokenFile != "" {
		b, err := os.ReadFile(cfg.BootstrapTokenFile)
		switch {
		case err == nil:
			cfg.BootstrapToken = strings.TrimSpace(string(b))
		case errors.Is(err, os.ErrNotExist):
			// The file is meant to be deleted once the first user exists.
		default:
			return nil, fmt.Errorf("bootstrap_token_file: %w", err)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if !nodeIDRe.MatchString(c.NodeID) {
		return fmt.Errorf("node_id %q must match %s", c.NodeID, nodeIDRe)
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	for name, addr := range map[string]string{"client_listen": c.ClientListen, "peer_listen": c.PeerListen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s %q: %v", name, addr, err)
		}
	}
	if n := len(c.Peers); n == 0 || n%2 == 0 {
		return fmt.Errorf("peers must list an odd number of nodes including this one (got %d); the intended deployment is 3", n)
	}
	seen := map[string]bool{}
	self := false
	for _, p := range c.Peers {
		if !nodeIDRe.MatchString(p.ID) {
			return fmt.Errorf("peer id %q must match %s", p.ID, nodeIDRe)
		}
		if seen[p.ID] {
			return fmt.Errorf("duplicate peer id %q", p.ID)
		}
		seen[p.ID] = true
		if p.ID == c.NodeID {
			self = true
		}
		if _, _, err := net.SplitHostPort(p.PeerAddr); err != nil {
			return fmt.Errorf("peer %s: peer_addr %q: %v", p.ID, p.PeerAddr, err)
		}
		u, err := url.Parse(p.PublicURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("peer %s: public_url %q must be an http(s) URL", p.ID, p.PublicURL)
		}
		if u.Scheme == "http" && !c.Insecure {
			return fmt.Errorf("peer %s: public_url %q is plain http but insecure mode is off", p.ID, p.PublicURL)
		}
	}
	if !self {
		return fmt.Errorf("node_id %q is not listed in peers", c.NodeID)
	}
	if c.Insecure && os.Getenv(allowInsecureNetworkEnv) != "1" {
		// Without TLS anyone who can reach the peer port can inject Raft
		// messages as any node, and login keys cross the client port in the
		// clear. A log warning is not a fence; confining insecure mode to
		// the loopback interface is.
		for name, addr := range map[string]string{"client_listen": c.ClientListen, "peer_listen": c.PeerListen} {
			if !isLoopbackAddr(addr) {
				return fmt.Errorf("insecure mode is for local development: %s %q must be a loopback address (set %s=1 to override at your own risk)", name, addr, allowInsecureNetworkEnv)
			}
		}
		for _, p := range c.Peers {
			if !isLoopbackAddr(p.PeerAddr) {
				return fmt.Errorf("insecure mode is for local development: peer %s peer_addr %q must be a loopback address (set %s=1 to override at your own risk)", p.ID, p.PeerAddr, allowInsecureNetworkEnv)
			}
		}
	}
	if !c.Insecure {
		if c.TLS.CAFile == "" || c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("tls.ca_file, tls.cert_file and tls.key_file are required (or set insecure: true for local development)")
		}
		if (c.TLS.APICertFile == "") != (c.TLS.APIKeyFile == "") {
			return errors.New("tls.api_cert_file and tls.api_key_file must be set together")
		}
	}
	if c.BootstrapToken != "" && len(c.BootstrapToken) < 16 {
		return errors.New("bootstrap token must be at least 16 characters")
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q: want debug, info, warn or error", c.LogLevel)
	}
	return nil
}

// allowInsecureNetworkEnv lets a deliberate operator run insecure mode on
// non-loopback addresses (e.g. inside an already-encrypted overlay network).
const allowInsecureNetworkEnv = "VAULTD_ALLOW_INSECURE_NETWORK"

// isLoopbackAddr reports whether a host:port names the loopback interface.
// Host names other than "localhost" are not resolved: a name that happens to
// resolve to 127.0.0.1 today is not a guarantee.
func isLoopbackAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) peerScheme() string {
	if c.Insecure {
		return "http"
	}
	return "https"
}
