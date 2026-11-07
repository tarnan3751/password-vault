package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/filestore"
	"github.com/tarnan3751/password-vault/internal/raft/httptransport"
	"github.com/tarnan3751/password-vault/internal/server"
	"github.com/tarnan3751/password-vault/internal/tlsutil"
	"github.com/tarnan3751/password-vault/web"
)

func cmdRun(args []string) error {
	fs := newFlagSet("run", "--config FILE",
		`Start this server and keep it running until it is interrupted. It joins the
other servers named in its configuration; the vault is usable as soon as a
majority of them (2 of 3) are up. Every setting is explained in
docs/OPERATIONS.md, "Configuration reference".`)
	configPath := fs.String("config", "", "this server's config.json `file` (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("run: --config is required")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel).With("node", cfg.NodeID)

	n, err := startNode(cfg, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-n.fatal:
		logger.Error("fatal error, shutting down", "err", err)
		n.shutdown()
		return err
	}
	n.shutdown()
	return nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level                   // info, also for "" (loadConfig allows only the four names)
	_ = lv.UnmarshalText([]byte(level)) // leaves lv unchanged on error
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

// node is one fully wired vaultd instance.
type node struct {
	cfg       *Config
	logger    *slog.Logger
	store     *filestore.Store
	transport *httptransport.Transport
	raft      raft.Node
	srv       *server.Server
	peerHTTP  *http.Server
	apiHTTP   *http.Server
	fatal     chan error
	stopBg    context.CancelFunc
	bgDone    chan struct{}
}

func startNode(cfg *Config, logger *slog.Logger) (_ *node, err error) {
	n := &node{cfg: cfg, logger: logger, fatal: make(chan error, 4), bgDone: make(chan struct{})}
	// Unwind whatever was started if a later step fails.
	defer func() {
		if err != nil {
			n.shutdown()
		}
	}()

	if cfg.Insecure {
		logger.Warn("INSECURE MODE: plain HTTP on both listeners; for local development only")
	}

	n.store, err = filestore.Open(filepath.Join(cfg.DataDir, "raft"), filestore.Options{Logger: logger.With("component", "filestore")})
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}

	// TLS material.
	var peerServerTLS, peerClientTLS, apiTLS *tls.Config
	if !cfg.Insecure {
		if peerServerTLS, err = tlsutil.PeerServerConfig(cfg.TLS.CAFile, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			return nil, fmt.Errorf("peer TLS: %w", err)
		}
		if peerClientTLS, err = tlsutil.PeerClientConfig(cfg.TLS.CAFile, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			return nil, fmt.Errorf("peer TLS: %w", err)
		}
		apiCert, apiKey := cfg.TLS.CertFile, cfg.TLS.KeyFile
		if cfg.TLS.APICertFile != "" {
			apiCert, apiKey = cfg.TLS.APICertFile, cfg.TLS.APIKeyFile
		}
		if apiTLS, err = tlsutil.APIServerConfig(apiCert, apiKey); err != nil {
			return nil, fmt.Errorf("API TLS: %w", err)
		}
	}

	// Peer transport.
	peerURLs := make(map[string]string, len(cfg.Peers))
	ids := make([]string, 0, len(cfg.Peers))
	clusterNodes := make([]api.ClusterNode, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		ids = append(ids, p.ID)
		clusterNodes = append(clusterNodes, api.ClusterNode{ID: p.ID, PublicURL: strings.TrimRight(p.PublicURL, "/")})
		if p.ID != cfg.NodeID {
			peerURLs[p.ID] = cfg.peerScheme() + "://" + p.PeerAddr
		}
	}
	sort.Strings(ids)
	peerClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig:       peerClientTLS,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
	}}
	n.transport, err = httptransport.New(httptransport.Options{
		LocalID: cfg.NodeID,
		Peers:   peerURLs,
		Client:  peerClient,
		// A snapshot travels as one message. The state machine's storage
		// quotas keep a snapshot near 100 MiB at the very most; this limit
		// leaves generous headroom so a full cluster can always resync a
		// follower.
		MaxBodyBytes:       256 << 20,
		RequireTLSIdentity: !cfg.Insecure,
		Logger:             logger.With("component", "transport"),
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	// The peer listener goes up before Raft starts so that no early message
	// from an already-running peer is refused.
	peerMux := http.NewServeMux()
	peerMux.Handle("/raft/", n.transport.Handler())
	n.peerHTTP = &http.Server{
		Handler:           peerMux,
		TLSConfig:         peerServerTLS,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.With("component", "peer-http").Handler(), slog.LevelDebug),
	}
	peerLn, err := net.Listen("tcp", cfg.PeerListen)
	if err != nil {
		return nil, fmt.Errorf("peer listener: %w", err)
	}
	go n.serve("peer", n.peerHTTP, peerLn, peerServerTLS != nil)

	// Replicated state machine + consensus.
	state := fsm.New()
	n.raft, err = raft.StartNode(raft.Config{
		ID:                cfg.NodeID,
		Peers:             ids,
		Storage:           n.store,
		Transport:         n.transport,
		StateMachine:      state,
		TickInterval:      time.Duration(cfg.Raft.TickMs) * time.Millisecond,
		ElectionTicks:     cfg.Raft.ElectionTicks,
		HeartbeatTicks:    cfg.Raft.HeartbeatTicks,
		SnapshotThreshold: cfg.Raft.SnapshotThreshold,
		Logger:            logger.With("component", "raft"),
	})
	if err != nil {
		return nil, fmt.Errorf("start raft: %w", err)
	}
	// A node that stops itself on a fatal storage error must take the
	// process down with it: a vaultd that keeps answering health checks
	// without a consensus module would look alive while serving nothing,
	// and the service manager would never restart it.
	if lc, ok := n.raft.(raft.Lifecycle); ok {
		go func() {
			<-lc.Done()
			if err := lc.Err(); err != nil {
				select {
				case n.fatal <- fmt.Errorf("raft stopped: %w", err):
				default:
				}
			}
		}()
	}

	// Client API.
	ttl := time.Duration(cfg.TokenTTLHours) * time.Hour
	n.srv, err = server.New(server.Config{
		NodeID:             cfg.NodeID,
		Raft:               n.raft,
		FSM:                state,
		Peers:              clusterNodes,
		BootstrapToken:     cfg.BootstrapToken,
		TokenTTL:           ttl,
		MaxSessionAge:      time.Duration(cfg.MaxSessionAgeDays) * 24 * time.Hour,
		StaleReadWindow:    time.Duration(cfg.StaleReadWindowHours) * time.Hour,
		WebFS:              web.Dist(), // web/dist, built with `make web` and committed, so building vaultd never needs Node.js
		TrustedProxyHeader: cfg.TrustedProxyHeader,
		TrustedProxies:     cfg.TrustedProxies,
		Version:            version,
		Logger:             logger.With("component", "api"),
	})
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	n.srv.Start()
	n.apiHTTP = &http.Server{
		Handler:           n.srv.Handler(),
		TLSConfig:         apiTLS,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute, // a 32 MiB rekey over a slow uplink
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.With("component", "api-http").Handler(), slog.LevelDebug),
	}
	apiLn, err := net.Listen("tcp", cfg.ClientListen)
	if err != nil {
		return nil, fmt.Errorf("client listener: %w", err)
	}
	go n.serve("client", n.apiHTTP, apiLn, apiTLS != nil)

	bgCtx, cancel := context.WithCancel(context.Background())
	n.stopBg = cancel
	go n.backupLoop(bgCtx)

	logger.Info("vaultd started", "version", version, "client_listen", apiLn.Addr().String(),
		"peer_listen", peerLn.Addr().String(), "peers", ids, "data_dir", cfg.DataDir)
	if cfg.BootstrapToken != "" {
		logger.Info("a bootstrap token is configured: the first registration on an empty cluster becomes the admin; remove the token afterwards")
	}
	return n, nil
}

func (n *node) serve(name string, s *http.Server, ln net.Listener, useTLS bool) {
	var err error
	if useTLS {
		err = s.ServeTLS(ln, "", "")
	} else {
		err = s.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		select {
		case n.fatal <- fmt.Errorf("%s listener: %w", name, err):
		default:
		}
	}
}

// shutdown stops everything that was started, in reverse dependency order.
// It tolerates a partially constructed node.
func (n *node) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if n.stopBg != nil {
		n.stopBg()
		<-n.bgDone
	}
	if n.apiHTTP != nil {
		_ = n.apiHTTP.Shutdown(ctx)
	}
	if n.srv != nil {
		_ = n.srv.Close()
	}
	if n.raft != nil {
		_ = n.raft.Stop()
	}
	if n.peerHTTP != nil {
		_ = n.peerHTTP.Shutdown(ctx)
	}
	if n.transport != nil {
		_ = n.transport.Close()
	}
	if n.store != nil {
		_ = n.store.Close()
	}
}

// backupLoop periodically dumps the replicated state to <data_dir>/backups.
// The dump contains ciphertext and password verifiers only. It guards
// against a logic bug wiping replicated data; it is on the same disk, so it
// is not a substitute for off-site copies or users' encrypted exports.
func (n *node) backupLoop(ctx context.Context) {
	defer close(n.bgDone)
	interval := time.Duration(n.cfg.Backup.IntervalHours) * time.Hour
	if n.cfg.Backup.IntervalHours == 0 {
		interval = 24 * time.Hour
	}
	if interval < 0 {
		return
	}
	keep := n.cfg.Backup.Keep
	if keep <= 0 {
		keep = 14
	}
	dir := filepath.Join(n.cfg.DataDir, "backups")
	// The first dump happens shortly after start so a fresh install has one.
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	var lastRev uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		timer.Reset(interval)
		bctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		b, err := n.srv.BuildBackup(bctx)
		cancel()
		if err != nil {
			n.logger.Warn("automatic backup skipped", "err", err)
			continue
		}
		if b.Rev == lastRev {
			continue // nothing changed since the last dump
		}
		if err := writeBackupFile(dir, b, keep); err != nil {
			n.logger.Warn("automatic backup failed", "err", err)
			continue
		}
		lastRev = b.Rev
		n.logger.Info("automatic backup written", "dir", dir, "rev", b.Rev)
	}
}

func writeBackupFile(dir string, b *api.ServerBackup, keep int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("state-%s-rev%d.json", time.UnixMilli(b.CreatedAt).UTC().Format("20060102T150405Z"), b.Rev)
	if err := tlsutil.WriteFileAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	// Prune: names sort chronologically.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "state-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
	return nil
}
