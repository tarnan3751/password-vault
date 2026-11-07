package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"strings"
	"testing"
	"time"
)

func constrainedPKI(t *testing.T, permitted ...string) *pki {
	t.Helper()
	c, k, err := GenerateConstrainedCA("Constrained CA", 0, permitted)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{dir: t.TempDir(), caCert: c, caKey: k}
}

// signManually bypasses GenerateNodeCert's own verification so we can check
// that the CA's constraints are enforced by the verifier itself.
func signManually(t *testing.T, p *pki, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	ca, _ := parseCert(p.caCert)
	caKey, _ := parseKey(p.caKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl.SerialNumber, _ = randomSerial()
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.Subject = pkix.Name{CommonName: "x"}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func verifies(t *testing.T, p *pki, leaf *x509.Certificate, name string, eku x509.ExtKeyUsage) error {
	t.Helper()
	ca, _ := parseCert(p.caCert)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{eku}})
	return err
}

var bothEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

func TestConstrainedCAContents(t *testing.T) {
	p := constrainedPKI(t, "vault.internal", "192.168.1.0/24", "10.0.0.5", "fd00::1")
	ca, _ := parseCert(p.caCert)
	if !ca.IsCA || !ca.PermittedDNSDomainsCritical || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Errorf("bad CA basics: %+v", ca)
	}
	if len(ca.ExtKeyUsage) != 2 {
		t.Errorf("CA EKU = %v", ca.ExtKeyUsage)
	}
	var ips []string
	for _, n := range ca.PermittedIPRanges {
		ips = append(ips, n.String())
	}
	t.Logf("permitted DNS=%q IP=%v", ca.PermittedDNSDomains, ips)
	t.Logf("excluded DNS=%q IP=%v email=%q uri=%q", ca.ExcludedDNSDomains, ca.ExcludedIPRanges, ca.ExcludedEmailAddresses, ca.ExcludedURIDomains)
	if len(ca.PermittedDNSDomains) != 1 || len(ips) != 3 {
		t.Errorf("permitted lists wrong: %v %v", ca.PermittedDNSDomains, ips)
	}
	if len(ca.ExcludedDNSDomains) != 0 || len(ca.ExcludedIPRanges) != 0 {
		t.Errorf("unexpected DNS/IP exclusions when both types are permitted")
	}
	if len(ca.ExcludedEmailAddresses) != 1 || len(ca.ExcludedURIDomains) != 1 {
		t.Errorf("email/URI not excluded")
	}
}

func TestConstrainedNodeCertAndMTLS(t *testing.T) {
	p := constrainedPKI(t, "vault.internal", "127.0.0.1")
	ca := p.caFile(t)
	// Node IDs "server"/"client" are not hostnames under vault.internal, so
	// use ones that are.
	sc, sk := p.node(t, "pi.vault.internal", []string{"127.0.0.1", "vps.vault.internal"}, 0)
	cc, ck := p.node(t, "laptop.vault.internal", nil, 0)

	leafPEM, _, _ := GenerateNodeCert(p.caCert, p.caKey, "deep.sub.vault.internal", []string{"vault.internal"}, 0)
	leaf, _ := parseCert(leafPEM)
	for _, n := range []string{"deep.sub.vault.internal", "vault.internal"} {
		for _, u := range bothEKU {
			if err := verifies(t, p, leaf, n, u); err != nil {
				t.Errorf("%s eku %v: %v", n, u, err)
			}
		}
	}

	scfg, err := PeerServerConfig(ca, sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	srv := startPeerServer(t, scfg)
	ccfg, _ := PeerClientConfig(ca, cc, ck)
	resp, err := clientFor(ccfg).Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS handshake with constrained CA: %v", err)
	}
	resp.Body.Close()
}

func TestConstrainedRefusesForbiddenNames(t *testing.T) {
	p := constrainedPKI(t, "vault.internal", "10.0.0.0/24")
	for _, h := range []string{"bank.example.com", "notvault.internal", "10.0.1.1", "::1", "vault.internal.evil.com"} {
		_, _, err := GenerateNodeCert(p.caCert, p.caKey, "ok.vault.internal", []string{h}, 0)
		if err == nil {
			t.Errorf("host %q accepted", h)
			continue
		}
		if !strings.Contains(err.Error(), h) {
			t.Errorf("error does not name %q: %v", h, err)
		}
	}
	// Permitted ones pass.
	if _, _, err := GenerateNodeCert(p.caCert, p.caKey, "ok.vault.internal", []string{"10.0.0.77"}, 0); err != nil {
		t.Errorf("permitted IP rejected: %v", err)
	}
	// A node ID that is a hostname outside the permitted set is refused too.
	if _, _, err := GenerateNodeCert(p.caCert, p.caKey, "pi", nil, 0); err == nil || !strings.Contains(err.Error(), `"pi"`) {
		t.Errorf("node ID outside constraints: %v", err)
	}
}

func TestVerifierEnforcesConstraints(t *testing.T) {
	p := constrainedPKI(t, "vault.internal", "10.0.0.0/24")
	bad := []struct {
		name string
		tmpl *x509.Certificate
		host string
	}{
		{"bank", &x509.Certificate{DNSNames: []string{"bank.example.com"}}, "bank.example.com"},
		{"unlisted ip", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}}, "8.8.8.8"},
		{"suffix trick", &x509.Certificate{DNSNames: []string{"evilvault.internal"}}, "evilvault.internal"},
		{"email SAN", &x509.Certificate{DNSNames: []string{"a.vault.internal"}, EmailAddresses: []string{"me@vault.internal"}}, "a.vault.internal"},
	}
	for _, c := range bad {
		c.tmpl.ExtKeyUsage = bothEKU
		leaf := signManually(t, p, c.tmpl)
		for _, u := range bothEKU {
			if err := verifies(t, p, leaf, c.host, u); err == nil {
				t.Errorf("%s: chain verified for eku %v", c.name, u)
			}
		}
	}
	// EKU the CA lacks is rejected even for a permitted name.
	leaf := signManually(t, p, &x509.Certificate{DNSNames: []string{"a.vault.internal"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err := verifies(t, p, leaf, "", x509.ExtKeyUsageCodeSigning); err == nil {
		t.Error("code signing certificate verified")
	}
	// Control: a good one passes.
	ok := signManually(t, p, &x509.Certificate{DNSNames: []string{"a.vault.internal"}, ExtKeyUsage: bothEKU})
	if err := verifies(t, p, ok, "a.vault.internal", x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("control failed: %v", err)
	}
}

func TestSubdomainSemantics(t *testing.T) {
	p := constrainedPKI(t, "vault.internal", "10.0.0.1")
	for host, want := range map[string]bool{
		"vault.internal":     true,
		"pi.vault.internal":  true,
		"a.b.vault.internal": true,
		"internal":           false,
		"xvault.internal":    false,
	} {
		leaf := signManually(t, p, &x509.Certificate{DNSNames: []string{host}, ExtKeyUsage: bothEKU})
		if err := verifies(t, p, leaf, host, x509.ExtKeyUsageServerAuth); (err == nil) != want {
			t.Errorf("%s: verified=%v want %v (%v)", host, err == nil, want, err)
		}
	}
	// Exact host entry: its subdomains are also covered (documented X.509 behaviour).
	q := constrainedPKI(t, "pi.vault.internal")
	leaf := signManually(t, q, &x509.Certificate{DNSNames: []string{"x.pi.vault.internal"}, ExtKeyUsage: bothEKU})
	if err := verifies(t, q, leaf, "x.pi.vault.internal", x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("subdomain of host entry: %v", err)
	}
	leaf = signManually(t, q, &x509.Certificate{DNSNames: []string{"vps.vault.internal"}, ExtKeyUsage: bothEKU})
	if err := verifies(t, q, leaf, "vps.vault.internal", x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("sibling host accepted")
	}
}

func TestIPOnlyExcludesDNS(t *testing.T) {
	p := constrainedPKI(t, "192.168.0.0/16")
	ca, _ := parseCert(p.caCert)
	t.Logf("DNS-excluded encoding: ExcludedDNSDomains=%q", ca.ExcludedDNSDomains)
	leaf := signManually(t, p, &x509.Certificate{DNSNames: []string{"anything.example.com"}, ExtKeyUsage: bothEKU})
	if err := verifies(t, p, leaf, "anything.example.com", x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("DNS name accepted by IP-only CA")
	}
	ok := signManually(t, p, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.168.4.4")}, ExtKeyUsage: bothEKU})
	if err := verifies(t, p, ok, "192.168.4.4", x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("permitted IP rejected: %v", err)
	}
	// Node cert helper: node ID that is a hostname gets a DNS SAN, hence fails.
	if _, _, err := GenerateNodeCert(p.caCert, p.caKey, "pi", []string{"192.168.1.2"}, 0); err == nil {
		t.Error("hostname node ID accepted by IP-only CA")
	}
	if _, _, err := GenerateNodeCert(p.caCert, p.caKey, "Mom's Pi", []string{"192.168.1.2"}, 0); err != nil {
		t.Errorf("non-hostname ID with permitted IP: %v", err)
	}
}

func TestDNSOnlyExcludesIP(t *testing.T) {
	p := constrainedPKI(t, "vault.internal")
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "::1", "2001:db8::1"} {
		leaf := signManually(t, p, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP(ip)}, ExtKeyUsage: bothEKU})
		if err := verifies(t, p, leaf, ip, x509.ExtKeyUsageServerAuth); err == nil {
			t.Errorf("IP %s accepted by DNS-only CA", ip)
		}
	}
}

func TestInvalidPermittedEntries(t *testing.T) {
	for _, bad := range [][]string{
		nil, {}, {""}, {"not a host"}, {"*.vault.internal"}, {"10.0.0.0/33"}, {"foo/bar"},
		{".vault.internal"}, {"-bad.internal"}, {"ok.internal", "bad_name"},
	} {
		if _, _, err := GenerateConstrainedCA("CA", 0, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
