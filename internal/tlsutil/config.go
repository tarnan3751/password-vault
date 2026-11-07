package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// loadPeer loads the household CA (as the only trusted root) and this
// node's key pair.
func loadPeer(caFile, certFile, keyFile string) (*x509.CertPool, tls.Certificate, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, tls.Certificate{}, fmt.Errorf("tlsutil: no certificates found in %s", caFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	return pool, cert, err
}

// PeerServerConfig is for the node-to-node listener: every client must
// present a certificate issued by the household CA (and only that CA).
func PeerServerConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	pool, cert, err := loadPeer(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// PeerClientConfig is for outbound peer connections. RootCAs is set
// explicitly so the system trust store is never consulted: a public CA must
// not be able to impersonate a household node.
func PeerClientConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	pool, cert, err := loadPeer(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

// APIServerConfig is for the client-facing HTTPS listener. TLS 1.2 stays
// enabled for old household devices; Go's default cipher suites exclude the
// unsafe ones.
func APIServerConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// PeerNodeID returns the node ID (leaf certificate Subject CN) of the peer
// on a TLS connection. It only trusts VerifiedChains, so it fails for
// connections where the chain was not verified.
func PeerNodeID(cs *tls.ConnectionState) (string, error) {
	if cs == nil {
		return "", errors.New("tlsutil: connection is not TLS")
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errors.New("tlsutil: no verified client certificate")
	}
	cn := cs.VerifiedChains[0][0].Subject.CommonName
	if cn == "" {
		return "", errors.New("tlsutil: client certificate has empty common name")
	}
	return cn, nil
}
