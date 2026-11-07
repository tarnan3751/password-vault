package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type pki struct {
	dir    string
	caCert []byte
	caKey  []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	c, k, err := GenerateCA("Test CA", 0)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{dir: t.TempDir(), caCert: c, caKey: k}
}

func (p *pki) caFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(p.dir, "ca.pem")
	if err := WriteCertFile(f, p.caCert); err != nil {
		t.Fatal(err)
	}
	return f
}

// node writes a node cert/key and returns file paths.
func (p *pki) node(t *testing.T, id string, hosts []string, validFor time.Duration) (cert, key string) {
	t.Helper()
	c, k, err := GenerateNodeCert(p.caCert, p.caKey, id, hosts, validFor)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(p.dir, id+".crt"), filepath.Join(p.dir, id+".key")
	if err := WriteCertFile(cert, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(key, k); err != nil {
		t.Fatal(err)
	}
	return
}

func TestCAAndNodeCertFields(t *testing.T) {
	p := newPKI(t)
	ca, err := parseCert(p.caCert)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Errorf("CA constraints wrong: %+v", ca)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("CA key usage = %v", ca.KeyUsage)
	}
	if d := time.Until(ca.NotAfter); d < 9*365*24*time.Hour {
		t.Errorf("CA validity too short: %v", d)
	}

	c, _, err := GenerateNodeCert(p.caCert, p.caKey, "vps", []string{"vps.vault.internal", "10.0.0.5", "::1", "vps.vault.internal"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseCert(c)
	if err != nil {
		t.Fatal(err)
	}
	if n.Subject.CommonName != "vps" || n.IsCA {
		t.Errorf("bad subject/IsCA: %v %v", n.Subject, n.IsCA)
	}
	if len(n.DNSNames) != 2 || n.DNSNames[0] != "vps.vault.internal" || n.DNSNames[1] != "vps" {
		t.Errorf("DNSNames = %v", n.DNSNames)
	}
	if len(n.IPAddresses) != 2 {
		t.Errorf("IPs = %v", n.IPAddresses)
	}
	if n.KeyUsage != x509.KeyUsageDigitalSignature || len(n.ExtKeyUsage) != 2 {
		t.Errorf("usages: %v %v", n.KeyUsage, n.ExtKeyUsage)
	}
	if d := n.NotAfter.Sub(n.NotBefore); d > 825*24*time.Hour {
		t.Errorf("node validity %v exceeds Apple's 825 day limit", d)
	}
	if n.NotBefore.After(time.Now().Add(-4 * time.Minute)) {
		t.Errorf("NotBefore not backdated: %v", n.NotBefore)
	}
	if n.SerialNumber.BitLen() < 100 {
		t.Errorf("serial suspiciously small")
	}
	// A nodeID that is not a hostname gets no DNS SAN.
	c2, _, err := GenerateNodeCert(p.caCert, p.caKey, "Mom's Laptop", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := parseCert(c2)
	if len(n2.DNSNames) != 0 {
		t.Errorf("unexpected SANs %v", n2.DNSNames)
	}
}

func TestGenerateNodeCertRejectsBadCA(t *testing.T) {
	p := newPKI(t)
	nc, nk, _ := GenerateNodeCert(p.caCert, p.caKey, "a", nil, 0)
	if _, _, err := GenerateNodeCert(nc, nk, "b", nil, 0); err == nil {
		t.Error("leaf accepted as CA")
	}
	if _, _, err := GenerateNodeCert([]byte("junk"), p.caKey, "b", nil, 0); err == nil {
		t.Error("junk CA accepted")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	p := newPKI(t)
	f := p.caFile(t)
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	blk, rest := pem.Decode(b)
	if blk == nil || len(rest) != 0 || blk.Type != "CERTIFICATE" {
		t.Fatal("bad cert PEM")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatal(err)
	}
	k, err := parseKey(p.caKey)
	if err != nil || k.Curve.Params().Name != "P-256" {
		t.Fatalf("key round trip: %v", err)
	}
	cert, key := p.node(t, "a", nil, 0)
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	p := newPKI(t)
	cert, key := p.node(t, "a", nil, 0)
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(cert); st.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %v", st.Mode().Perm())
	}
	// Overwrite keeps 0600 and leaves no temp files behind.
	if err := WriteKeyFile(key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode after overwrite = %v", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(p.dir)
	for _, e := range ents {
		if len(e.Name()) > 4 && e.Name()[:5] == ".tmp-" {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

// startPeerServer serves identity of the caller as the response body.
func startPeerServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := PeerNodeID(r.TLS)
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		w.Write([]byte(id))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clientFor(cfg *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func TestMutualTLS(t *testing.T) {
	p := newPKI(t)
	ca := p.caFile(t)
	sc, sk := p.node(t, "server", []string{"127.0.0.1"}, 0)
	cc, ck := p.node(t, "client", nil, 0)

	scfg, err := PeerServerConfig(ca, sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	srv := startPeerServer(t, scfg)

	ccfg, err := PeerClientConfig(ca, cc, ck)
	if err != nil {
		t.Fatal(err)
	}
	if ccfg.MinVersion != tls.VersionTLS13 || scfg.MinVersion != tls.VersionTLS13 {
		t.Error("peer configs must require TLS 1.3")
	}
	resp, err := clientFor(ccfg).Get(srv.URL)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 32)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "client" {
		t.Errorf("peer ID = %q", buf[:n])
	}
}

func TestMutualTLSRejections(t *testing.T) {
	p := newPKI(t)
	ca := p.caFile(t)
	sc, sk := p.node(t, "server", []string{"127.0.0.1"}, 0)
	cc, ck := p.node(t, "client", nil, 0)
	scfg, err := PeerServerConfig(ca, sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	srv := startPeerServer(t, scfg)
	good, _ := PeerClientConfig(ca, cc, ck)

	t.Run("no client cert", func(t *testing.T) {
		cfg := good.Clone()
		cfg.Certificates = nil
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected failure")
		}
	})
	t.Run("cert from other CA", func(t *testing.T) {
		other := newPKI(t)
		oc, ok := other.node(t, "client", nil, 0)
		cfg, _ := PeerClientConfig(ca, oc, ok)
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected failure")
		}
	})
	t.Run("expired cert", func(t *testing.T) {
		// NotBefore is backdated only 5 minutes, so a 1ns validity is
		// already expired.
		ec, ek := p.node(t, "expired", nil, time.Nanosecond)
		time.Sleep(10 * time.Millisecond)
		cfg, _ := PeerClientConfig(ca, ec, ek)
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected failure")
		}
	})
	t.Run("server not trusted", func(t *testing.T) {
		other := newPKI(t)
		cfg, _ := PeerClientConfig(other.caFile(t), cc, ck)
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected failure")
		}
	})
	t.Run("host not in SANs", func(t *testing.T) {
		// Dial the same listener under a name the cert does not cover.
		cfg := good.Clone()
		cfg.ServerName = "evil.example.com"
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected hostname verification failure")
		}
	})
	t.Run("old TLS rejected", func(t *testing.T) {
		cfg := good.Clone()
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		if resp, err := clientFor(cfg).Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("expected failure")
		}
	})
}

func TestAPIServerConfig(t *testing.T) {
	p := newPKI(t)
	sc, sk := p.node(t, "api", []string{"127.0.0.1"}, 0)
	cfg, err := APIServerConfig(sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("unexpected API config: %+v", cfg)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = cfg
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.caCert)
	// TLS 1.2 client must work.
	c := clientFor(&tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestPeerNodeIDErrors(t *testing.T) {
	if _, err := PeerNodeID(nil); err == nil {
		t.Error("nil state accepted")
	}
	if _, err := PeerNodeID(&tls.ConnectionState{}); err == nil {
		t.Error("unverified state accepted")
	}
}

func TestBadConfigInputs(t *testing.T) {
	p := newPKI(t)
	cert, key := p.node(t, "a", nil, 0)
	bad := filepath.Join(p.dir, "bad.pem")
	os.WriteFile(bad, []byte("nope"), 0o600)
	if _, err := PeerServerConfig(bad, cert, key); err == nil {
		t.Error("bad CA accepted")
	}
	if _, err := PeerClientConfig(filepath.Join(p.dir, "missing"), cert, key); err == nil {
		t.Error("missing CA accepted")
	}
	if _, err := APIServerConfig(cert, bad); err == nil {
		t.Error("bad key accepted")
	}
	_ = net.IPv4zero
}
