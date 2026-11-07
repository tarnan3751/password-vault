package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tarnan3751/password-vault/internal/tlsutil"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	nodeValidity = 800 * 24 * time.Hour // Apple platforms reject server certificates valid for more than 825 days
)

// nodeSpec is one "--node id=host[,host...]" argument.
type nodeSpec struct {
	id    string
	hosts []string
}

type nodeFlags []nodeSpec

func (f *nodeFlags) String() string { return fmt.Sprint(*f) }

func (f *nodeFlags) Set(v string) error {
	id, hostList, ok := strings.Cut(v, "=")
	if !ok || hostList == "" {
		return fmt.Errorf("want <id>=<host>[,<host>...], got %q", v)
	}
	if !nodeIDRe.MatchString(id) {
		return fmt.Errorf("node id %q must match %s", id, nodeIDRe)
	}
	var hosts []string
	for _, h := range strings.Split(hostList, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return fmt.Errorf("node %q needs at least one host name or IP address", id)
	}
	*f = append(*f, nodeSpec{id: id, hosts: hosts})
	return nil
}

// cmdInitCluster generates everything a new cluster needs:
//
//	<out>/ca.pem, <out>/ca-key.pem     household CA (keep the key offline)
//	<out>/<node>/config.json           ready-to-run node configuration
//	<out>/<node>/{ca,node,node-key}.pem
//	<out>/<node>/bootstrap-token       same token on every node
//
// Each <out>/<node> directory is then copied to its machine.
func cmdInitCluster(args []string) error {
	fs := newFlagSet("init-cluster", "--out DIR --node ID=HOST[,HOST...] (three times)",
		`Create everything a new household needs: a certificate authority, one
directory per server (configuration, certificate, key) and the bootstrap
token for the first account. Run it once, on a computer you trust. Example:

  vaultd init-cluster --out cluster \
    --node pi=pi.vault.internal --node vps=vps.vault.internal --node laptop=laptop.vault.internal`)
	out := fs.String("out", "", "`directory` to write into (required; must not already hold a cluster)")
	var nodes nodeFlags
	fs.Var(&nodes, "node", "`id=host[,host...]`: a short name for one server and the DNS names or IP addresses it is reachable at (the first is used in URLs); give it once per server")
	clientPort := fs.Int("client-port", 8443, "`port` people's browsers and fvault connect to, on every server")
	peerPort := fs.Int("peer-port", 8444, "`port` the servers use to talk to each other")
	dataDir := fs.String("data-dir", "data", "where each server keeps its data: the `path` written into every config.json (relative to that file)")
	var permit stringList
	fs.Var(&permit, "permit", "extra `name` the certificate authority may vouch for: a DNS domain (covers its subdomains), an IP address or a CIDR range; repeatable. "+
		"Without it the authority is limited to the names given with --node")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("init-cluster: --out is required")
	}
	if len(nodes)%2 == 0 {
		return fmt.Errorf("init-cluster: need an odd number of --node flags (3 for the intended deployment), got %d", len(nodes))
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.id] {
			return fmt.Errorf("init-cluster: duplicate node id %q", n.id)
		}
		seen[n.id] = true
	}
	if len(nodes) != 3 {
		fmt.Fprintf(os.Stderr, "note: %d node(s) given; the design tolerates one failure only with 3\n", len(nodes))
	}
	if _, err := os.Stat(filepath.Join(*out, "ca-key.pem")); err == nil {
		return fmt.Errorf("init-cluster: %s already contains a CA; refusing to overwrite it", *out)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}

	// The CA is name-constrained to this cluster. Family members install
	// ca.pem on their devices; without constraints whoever holds ca-key.pem
	// could mint a trusted certificate for any website.
	permitted := append([]string(nil), permit...)
	for _, n := range nodes {
		permitted = append(permitted, n.id) // the node id is a DNS SAN of its certificate
		permitted = append(permitted, n.hosts...)
	}
	caCert, caKey, err := tlsutil.GenerateConstrainedCA("Family Vault household CA", caValidity, dedupe(permitted))
	if err != nil {
		return err
	}
	if err := tlsutil.WriteFileAtomic(filepath.Join(*out, "ca.pem"), caCert, 0o644); err != nil {
		return err
	}
	if err := tlsutil.WriteFileAtomic(filepath.Join(*out, "ca-key.pem"), caKey, 0o600); err != nil {
		return err
	}

	token, err := randomToken()
	if err != nil {
		return err
	}

	peers := make([]PeerConfig, 0, len(nodes))
	for _, n := range nodes {
		host := n.hosts[0]
		peers = append(peers, PeerConfig{
			ID:        n.id,
			PeerAddr:  net.JoinHostPort(host, fmt.Sprint(*peerPort)),
			PublicURL: "https://" + net.JoinHostPort(host, fmt.Sprint(*clientPort)),
		})
	}
	for _, n := range nodes {
		dir := filepath.Join(*out, n.id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		cert, key, err := tlsutil.GenerateNodeCert(caCert, caKey, n.id, n.hosts, nodeValidity)
		if err != nil {
			return fmt.Errorf("node %s: %w", n.id, err)
		}
		cfg := Config{
			NodeID:             n.id,
			DataDir:            *dataDir,
			ClientListen:       fmt.Sprintf("0.0.0.0:%d", *clientPort),
			PeerListen:         fmt.Sprintf("0.0.0.0:%d", *peerPort),
			Peers:              peers,
			TLS:                TLSConfig{CAFile: "ca.pem", CertFile: "node.pem", KeyFile: "node-key.pem"},
			BootstrapTokenFile: "bootstrap-token",
		}
		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		files := []struct {
			name string
			data []byte
			mode os.FileMode
		}{
			{"config.json", append(cfgJSON, '\n'), 0o600},
			{"ca.pem", caCert, 0o644},
			{"node.pem", cert, 0o644},
			{"node-key.pem", key, 0o600},
			{"bootstrap-token", []byte(token + "\n"), 0o600},
		}
		for _, f := range files {
			if err := tlsutil.WriteFileAtomic(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
				return err
			}
		}
	}

	first := peers[0].PublicURL
	fmt.Printf("Cluster files written to %s\n\nWhat to do next:\n\n"+
		"  1. Copy each server's directory to its machine and start vaultd there:\n", *out)
	for _, n := range nodes {
		fmt.Printf("       %-12s vaultd run --config %s/config.json\n", n.id+"/", n.id)
	}
	fmt.Printf(`     (deploy/vaultd.service runs it as a systemd service.)

  2. Give ca.pem to everyone who will use the vault and have them install it
     on their devices (docs/OPERATIONS.md, "Install the CA certificate"). It lets a device check
     that it is talking to your servers, and it can vouch only for:
       %s

  3. Create the first account, which becomes the administrator. Either open
       %s
     in a browser and choose "First-time setup", or use the command line:
       fvault init --server %s --ca %s
       fvault register --username YOUR_NAME
     Both ask for this bootstrap token (a one-time setup code):

       %s

  4. When that account exists, delete the bootstrap-token file on every server.

  5. Move ca-key.pem somewhere offline (a USB stick in a drawer). It is needed
     only to issue or renew server certificates, which are valid for %d days
     ("vaultd issue-cert").
`, strings.Join(dedupe(permitted), ", "), first, first, filepath.Join(*out, "ca.pem"), token, int(nodeValidity.Hours()/24))
	return nil
}

// cmdIssueCert issues (or renews) a single node certificate from an existing CA.
func cmdIssueCert(args []string) error {
	fs := newFlagSet("issue-cert", "--ca-dir DIR --node ID=HOST[,HOST...] --out DIR",
		`Issue a new certificate for one server: to renew one that is about to
expire, or to replace one whose key was lost. Needs the certificate
authority's key (ca-key.pem), so bring it back from wherever you keep it.
Copy the two files it writes to the server and restart vaultd there. Example:

  vaultd issue-cert --ca-dir cluster --node pi=pi.vault.internal --out cluster/pi`)
	caDir := fs.String("ca-dir", "", "`directory` holding ca.pem and ca-key.pem (required)")
	var nodes nodeFlags
	fs.Var(&nodes, "node", "`id=host[,host...]`: the server's name and the DNS names or IP addresses it is reachable at (required, once)")
	out := fs.String("out", "", "`directory` to write node.pem and node-key.pem into (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *caDir == "" || *out == "" || len(nodes) != 1 {
		return errors.New("issue-cert: --ca-dir, --out and exactly one --node are required")
	}
	caCert, err := os.ReadFile(filepath.Join(*caDir, "ca.pem"))
	if err != nil {
		return err
	}
	caKey, err := os.ReadFile(filepath.Join(*caDir, "ca-key.pem"))
	if err != nil {
		return err
	}
	n := nodes[0]
	cert, key, err := tlsutil.GenerateNodeCert(caCert, caKey, n.id, n.hosts, nodeValidity)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	if err := tlsutil.WriteFileAtomic(filepath.Join(*out, "node-key.pem"), key, 0o600); err != nil {
		return err
	}
	if err := tlsutil.WriteFileAtomic(filepath.Join(*out, "node.pem"), cert, 0o644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s and %s for node %q (valid %d days). Restart the node to pick them up.\n",
		filepath.Join(*out, "node.pem"), filepath.Join(*out, "node-key.pem"), n.id, int(nodeValidity.Hours()/24))
	return nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	if v = strings.TrimSpace(v); v == "" {
		return errors.New("empty value")
	}
	*l = append(*l, v)
	return nil
}

// dedupe returns in without repeated entries, preserving order.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// randomToken returns 160 bits of randomness as 32 base32 characters in
// dash-separated groups of four, the same shape as an invite code.
func randomToken() (string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}
