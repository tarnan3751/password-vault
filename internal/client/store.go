package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// Local state. Everything here is either public configuration, ciphertext
// the server already holds, public keys, or (optionally) a short-lived bearer
// token. Master keys, the account key, private keys, vault keys and passwords
// are NEVER written to disk.

// ErrNotConfigured means no config.json exists yet.
var ErrNotConfigured = errors.New("fvault is not configured yet; run `fvault init --server URL` first")

// Config is config.json.
type Config struct {
	Servers []string `json:"servers"`
	// CAFile is a PEM file with the household CA ("" => system roots).
	CAFile string `json:"ca_file,omitempty"`
	// CAWithSystemRoots trusts CAFile in addition to (not instead of) system roots.
	CAWithSystemRoots bool   `json:"ca_with_system_roots,omitempty"`
	Username          string `json:"username,omitempty"`
	// UserID of the account last logged in (names its trust store file).
	UserID string `json:"user_id,omitempty"`
	// AllowInsecure permits plain http:// servers (local development only).
	AllowInsecure bool `json:"allow_insecure,omitempty"`
	// NoTokenCache stops the bearer token from being kept in token.json.
	NoTokenCache bool `json:"no_token_cache,omitempty"`
}

// Cache is cache.json: the last SyncResponse verbatim (ciphertext only).
type Cache struct {
	Version  int              `json:"version"`
	Username string           `json:"username"`
	SavedAt  int64            `json:"saved_at"` // unix ms
	Sync     api.SyncResponse `json:"sync"`
}

// TokenFile is token.json.
type TokenFile struct {
	Username  string `json:"username"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"` // unix ms
}

// Store is the on-disk state directory.
type Store struct {
	Dir string
	mu  sync.Mutex
}

// DefaultHome returns $FVAULT_HOME or os.UserConfigDir()/fvault.
func DefaultHome() (string, error) {
	if h := os.Getenv("FVAULT_HOME"); h != "" {
		return h, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find a config directory (set FVAULT_HOME): %w", err)
	}
	return filepath.Join(d, "fvault"), nil
}

// OpenStore opens (creating, mode 0700) the state directory. An existing
// directory with looser permissions is tightened: it holds the offline cache.
func OpenStore(dir string) (*Store, error) {
	if dir == "" {
		var err error
		if dir, err = DefaultHome(); err != nil {
			return nil, err
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("cannot restrict %s to mode 0700: %w", dir, err)
		}
	}
	return &Store{Dir: dir}, nil
}

const (
	configFile = "config.json"
	cacheFile  = "cache.json"
	tokenFile  = "token.json"
)

// writeAtomic writes data to dir/name via temp file + fsync + rename, mode 0600,
// so a crash leaves either the old or the new file, never a torn one.
func writeAtomic(dir, name string, data []byte) error {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// WriteFileAtomic is writeAtomic for a path (the CLI's export and backup files).
func WriteFileAtomic(path string, data []byte) error {
	return writeAtomic(filepath.Dir(path), filepath.Base(path), data)
}

func (s *Store) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.Dir, name, append(b, '\n'))
}

func (s *Store) readJSON(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s is corrupt: %w", filepath.Join(s.Dir, name), err)
	}
	return nil
}

// LoadConfig reads config.json (ErrNotConfigured if absent).
func (s *Store) LoadConfig() (*Config, error) {
	var c Config
	if err := s.readJSON(configFile, &c); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotConfigured
		}
		return nil, err
	}
	return &c, nil
}

// SaveConfig writes config.json.
func (s *Store) SaveConfig(c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeJSON(configFile, c)
}

// UpdateConfig applies f to the current config and saves it.
func (s *Store) UpdateConfig(f func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c Config
	if err := s.readJSON(configFile, &c); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f(&c)
	return s.writeJSON(configFile, &c)
}

// load reads a JSON state file (nil, nil if absent).
func load[T any](s *Store, name string) (*T, error) {
	var v T
	if err := s.readJSON(name, &v); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// LoadCache reads cache.json (nil, nil if absent).
func (s *Store) LoadCache() (*Cache, error) { return load[Cache](s, cacheFile) }

// SaveCacheUnlessOlder writes the cache unless its rev is lower than what is
// already on disk for the same user. It reports whether it
// wrote. Checking against the file (not against memory) also protects against
// another fvault process having cached something newer in the meantime.
func (s *Store) SaveCacheUnlessOlder(c *Cache) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Never replace a cached sync with a lower rev, stale or not: a lower rev
	// is either an out-of-date node or a rolled-back server, and in both
	// cases the copy we already hold is the better offline copy.
	// Only the user and the rev are decoded: the rest of a large cache is skipped.
	var prev struct {
		Username string `json:"username"`
		Sync     struct {
			Rev uint64 `json:"rev"`
		} `json:"sync"`
	}
	if err := s.readJSON(cacheFile, &prev); err == nil && prev.Username == c.Username && c.Sync.Rev < prev.Sync.Rev {
		return false, nil
	}
	c.Version = 1
	return true, s.writeJSON(cacheFile, c)
}

func (s *Store) remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(filepath.Join(s.Dir, name)); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// DeleteCache removes cache.json.
func (s *Store) DeleteCache() error { return s.remove(cacheFile) }

// LoadToken reads token.json (nil, nil if absent or expired).
func (s *Store) LoadToken() (*TokenFile, error) {
	t, err := load[TokenFile](s, tokenFile)
	if t == nil || err != nil || t.Token == "" || (t.ExpiresAt > 0 && time.Now().UnixMilli() >= t.ExpiresAt) {
		return nil, err
	}
	return t, nil
}

// SaveToken writes token.json.
func (s *Store) SaveToken(t *TokenFile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeJSON(tokenFile, t)
}

// DeleteToken removes token.json.
func (s *Store) DeleteToken() error { return s.remove(tokenFile) }

// LoadTrustBlob returns the sealed trust store (nil, nil if absent).
func (s *Store) LoadTrustBlob(userID string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, trustName(userID)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// SaveTrustBlob writes the sealed trust store atomically (0600).
func (s *Store) SaveTrustBlob(userID string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.Dir, trustName(userID), b)
}

// DeleteTrust removes the trust store: every contact becomes unverified again
// and the recorded vault epochs and rev floor are forgotten.
func (s *Store) DeleteTrust(userID string) error { return s.remove(trustName(userID)) }

// trustName is the trust store's file name: one per account (it is sealed
// under that account's key), "trust-<userID>.bin".
func trustName(userID string) string { return "trust-" + userID + ".bin" }

// TrustFileName returns the trust store file name of an account.
func TrustFileName(userID string) string { return trustName(userID) }
