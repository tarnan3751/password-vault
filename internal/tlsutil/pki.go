// Package tlsutil implements the household PKI (a private CA plus per-node
// certificates) and the TLS configurations built on it.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultCAValidity is how long a household CA lives.
	DefaultCAValidity = 10 * 365 * 24 * time.Hour
	// DefaultNodeValidity is deliberately under 825 days: Apple platforms
	// reject TLS server certificates valid for longer than that, even when
	// they chain to a user-installed CA, and family devices include iPhones.
	DefaultNodeValidity = 800 * 24 * time.Hour

	// clockSkew backdates NotBefore so a freshly issued cert is usable on
	// machines whose clocks run slightly behind.
	clockSkew = 5 * time.Minute
)

func randomSerial() (*big.Int, error) {
	// 128 random bits: unique without keeping a serial database.
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// GenerateCA creates an UNCONSTRAINED self-signed CA (ECDSA P-256). Anyone
// holding its key can mint a certificate for any website that every device
// trusting it will accept, so this exists for tests; production must use
// GenerateConstrainedCA. A zero validFor selects DefaultCAValidity.
func GenerateCA(commonName string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	return generateCA(commonName, validFor, nil)
}

// GenerateConstrainedCA creates a CA that can only vouch for the given names,
// so a leaked or misused CA key cannot impersonate arbitrary websites to
// devices that installed the CA.
//
// permitted entries are DNS names (a name also permits all its subdomains:
// "vault.internal" covers "pi.vault.internal"), single IP addresses (/32 or
// /128) or CIDRs. At least one is required. Node IDs that become DNS SANs
// (see GenerateNodeCert) must be covered too, so list them (or their domain).
//
// Name types with no permitted entry are explicitly EXCLUDED, because under
// RFC 5280 a name type without any constraint is unrestricted: with no IPs
// listed all of 0.0.0.0/0 and ::/0 are excluded; with no DNS names listed the
// empty DNS constraint "" is excluded (which Go and NSS treat as matching every
// name); email addresses and URIs are always excluded. The CA also carries
// EKU serverAuth+clientAuth, which limits every certificate below it.
func GenerateConstrainedCA(commonName string, validFor time.Duration, permitted []string) (certPEM, keyPEM []byte, err error) {
	if len(permitted) == 0 {
		return nil, nil, errors.New("tlsutil: at least one permitted name is required")
	}
	nc := &nameConstraints{}
	for _, e := range permitted {
		e = strings.TrimSpace(e)
		switch {
		case strings.Contains(e, "/"):
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, nil, fmt.Errorf("tlsutil: invalid permitted CIDR %q", e)
			}
			nc.ips = append(nc.ips, n)
		case net.ParseIP(e) != nil:
			ip := net.ParseIP(e)
			if v4 := ip.To4(); v4 != nil {
				nc.ips = append(nc.ips, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
			} else {
				nc.ips = append(nc.ips, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		case validHostname(strings.TrimPrefix(e, ".")) && !strings.HasPrefix(e, "."):
			nc.dns = append(nc.dns, e)
		default:
			return nil, nil, fmt.Errorf("tlsutil: permitted entry %q is not a DNS name, IP address or CIDR", e)
		}
	}
	return generateCA(commonName, validFor, nc)
}

type nameConstraints struct {
	dns []string
	ips []*net.IPNet
}

func generateCA(commonName string, validFor time.Duration, nc *nameConstraints) (certPEM, keyPEM []byte, err error) {
	if commonName == "" {
		return nil, nil, errors.New("tlsutil: empty CA common name")
	}
	if validFor <= 0 {
		validFor = DefaultCAValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validFor),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true, // the CA signs leaves only
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if nc != nil {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = nc.dns
		tmpl.PermittedIPRanges = nc.ips
		if len(nc.dns) == 0 {
			tmpl.ExcludedDNSDomains = []string{""}
		}
		if len(nc.ips) == 0 {
			_, v4, _ := net.ParseCIDR("0.0.0.0/0")
			_, v6, _ := net.ParseCIDR("::/0")
			tmpl.ExcludedIPRanges = []*net.IPNet{v4, v6}
		}
		tmpl.ExcludedEmailAddresses = []string{""}
		tmpl.ExcludedURIDomains = []string{""}
		// Without an EKU, a constrained CA could still issue certificates
		// for other purposes; EKU is enforced along the chain.
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCert(der), keyPEM, nil
}

// GenerateNodeCert issues a certificate for nodeID signed by the CA. The
// subject CN is nodeID (the Raft transport authenticates peers by it). hosts
// become IP or DNS SANs; nodeID is added as a DNS SAN when it is a valid
// hostname, so with a constrained CA the node ID (or its domain) must be among
// the permitted names. The result is verified against the CA for every SAN
// and both usages; an error names the host the CA's constraints forbid, so a
// certificate every client would reject is never handed out.
// A zero validFor selects DefaultNodeValidity.
func GenerateNodeCert(caCertPEM, caKeyPEM []byte, nodeID string, hosts []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	if nodeID == "" {
		return nil, nil, errors.New("tlsutil: empty node ID")
	}
	if validFor <= 0 {
		validFor = DefaultNodeValidity
	}
	caCert, err := parseCert(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, errors.New("tlsutil: certificate is not a CA")
	}
	caKey, err := parseKey(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsutil: CA key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	var dnsNames []string
	var ips []net.IP
	seen := map[string]bool{}
	addDNS := func(n string) {
		if !seen[n] {
			seen[n] = true
			dnsNames = append(dnsNames, n)
		}
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			addDNS(h)
		}
	}
	if validHostname(nodeID) {
		addDNS(nodeID)
	}

	now := time.Now()
	notAfter := now.Add(validFor)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter // never outlive the issuer
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyIssued(caCert, leaf); err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCert(der), keyPEM, nil
}

// validHostname reports whether s is usable as a DNS SAN (RFC 1123 labels).
func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ek, nil
}

// WriteFileAtomic writes data to path via a temp file in the same directory,
// fsyncs, then renames, so a crash never leaves a truncated certificate or
// key. The mode is applied before any data is written, so private keys are
// never briefly world-readable.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { f.Close(); os.Remove(tmp) }
	if err := f.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// WriteCertFile writes a public certificate (0644).
func WriteCertFile(path string, certPEM []byte) error {
	return WriteFileAtomic(path, certPEM, 0o644)
}

// WriteKeyFile writes a private key (0600).
func WriteKeyFile(path string, keyPEM []byte) error {
	return WriteFileAtomic(path, keyPEM, 0o600)
}

// verifyIssued checks leaf chains to ca (as sole root) for each of its SANs
// and for both serverAuth and clientAuth.
func verifyIssued(ca, leaf *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	var names []string
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		names = []string{""} // still verify the chain and usages
	}
	for _, name := range names {
		for _, u := range usages {
			// Checked at the start of the leaf's validity: this is about
			// name/usage constraints, and must not fail for a deliberately
			// short-lived (even already expired) certificate.
			opts := x509.VerifyOptions{
				Roots: roots, KeyUsages: []x509.ExtKeyUsage{u}, DNSName: name,
				CurrentTime: leaf.NotBefore.Add(time.Second),
			}
			if _, err := leaf.Verify(opts); err != nil {
				if name == "" {
					return fmt.Errorf("tlsutil: CA does not allow this certificate: %w", err)
				}
				return fmt.Errorf("tlsutil: CA constraints forbid host %q: %w", name, err)
			}
		}
	}
	return nil
}
