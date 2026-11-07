package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// The local trust store (crypto.md §6.2). Per account and per device it holds:
// the contacts seen so far as immutable (userID, username, publicKey) triples
// with a verified flag; permanent key-mismatch events; per vault the accepted
// key epoch, a commitment to that epoch's key and the owners listed in the
// last accepted roster; and the highest rev of any sync stored.
//
// On disk it is sealed under a key derived from the account key
// (vaultcrypto.SealLocalTrust) in trust.bin, so someone holding the locked
// device cannot flip a "verified" flag. If the file is missing or does not
// open, the client starts empty (everything unverified), which is safe.

// Contact is one known household member.
type Contact struct {
	UserID    string `json:"id"`
	Username  string `json:"username"`
	PublicKey []byte `json:"pk"`
	Verified  bool   `json:"verified,omitempty"`
	FirstSeen int64  `json:"first_seen"`
}

// Mismatch kinds.
const (
	MismatchKey      = "key"      // known user ID, different public key
	MismatchUsername = "username" // known user ID, different username
	MismatchUserID   = "user_id"  // known username under a different user ID
	MismatchRoster   = "roster"   // a roster lists a different key than the contact triple
)

// MismatchEvent is a permanent record that a server (or a roster) presented
// something that contradicts the trust store.
type MismatchEvent struct {
	UserID             string `json:"id"`
	Username           string `json:"username"`
	Kind               string `json:"kind"`
	PinnedFingerprint  string `json:"pinned_fp,omitempty"`
	OfferedFingerprint string `json:"offered_fp,omitempty"`
	At                 int64  `json:"at"`
	Dismissed          bool   `json:"dismissed,omitempty"`
}

func (e MismatchEvent) key() string { return e.UserID + "|" + e.Kind + "|" + e.OfferedFingerprint }

// OwnerKey is an owner (ID and public key) listed in an accepted roster.
type OwnerKey struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"pk"`
}

// VaultTrust is what this device has accepted for one vault.
type VaultTrust struct {
	Epoch      uint32     `json:"epoch"`
	Commitment string     `json:"commit"`
	Owners     []OwnerKey `json:"owners,omitempty"`
	// Prior is set while a rekey this device started is in flight: if the
	// server still offers the prior epoch afterwards, the rekey did not happen
	// and the prior state is restored (otherwise a rekey whose outcome was
	// unknown would lock the vault for good under the continuity rule).
	Prior *VaultTrust `json:"prior,omitempty"`
}

func (v *VaultTrust) clone() *VaultTrust {
	if v == nil {
		return nil
	}
	c := *v
	c.Owners = append([]OwnerKey(nil), v.Owners...)
	c.Prior = v.Prior.clone()
	return &c
}

func (v *VaultTrust) ownerKey(id string) ([]byte, bool) {
	for _, o := range v.Owners {
		if o.ID == id {
			return o.PublicKey, true
		}
	}
	return nil, false
}

// OlderState is the persistent record that the servers showed older data than
// this device has seen (see RestoredStateError).
type OlderState struct {
	ServerRev uint64   `json:"server_rev"`
	SeenRev   uint64   `json:"seen_rev"`
	Vaults    []string `json:"vaults,omitempty"`
	At        int64    `json:"at"`
}

type trustData struct {
	V        int                    `json:"v"`
	Contacts map[string]*Contact    `json:"contacts"`
	Events   []MismatchEvent        `json:"events,omitempty"`
	Vaults   map[string]*VaultTrust `json:"vaults"`
	MaxRev   uint64                 `json:"max_rev"`
	Older    *OlderState            `json:"older,omitempty"`
}

// TrustStore is the in-memory trust store plus its sealed file.
type TrustStore struct {
	store  *Store
	key    vaultcrypto.SymmetricKey // account key (the seal key is derived on use)
	userID string

	mu      sync.Mutex
	d       trustData
	dirty   bool
	touched map[string]bool // vault IDs changed by this process: memory wins in a merge
	// resetRecords: vault records and the rev floor were deliberately cleared
	// (recovery); a merge must not bring the disk copy's back.
	resetRecords bool
	olderTouched bool
	// Reset: the file was missing although this device had cached data, or did
	// not open; the store started empty.
	Reset bool
}

func newTrustData() trustData {
	return trustData{V: 1, Contacts: map[string]*Contact{}, Vaults: map[string]*VaultTrust{}}
}

func (t *TrustStore) openBlob(blob []byte) (*trustData, bool) {
	pt, err := vaultcrypto.OpenLocalTrust(&t.key, t.userID, blob)
	if err != nil {
		return nil, false
	}
	var d trustData
	if json.Unmarshal(pt, &d) != nil || d.V != 1 {
		return nil, false
	}
	if d.Contacts == nil {
		d.Contacts = map[string]*Contact{}
	}
	if d.Vaults == nil {
		d.Vaults = map[string]*VaultTrust{}
	}
	return &d, true
}

// loadTrust opens the trust store for an unlocked account. hadState says
// whether this device already has cached data for the user (a missing trust
// file is then suspicious and reported).
func loadTrust(store *Store, acct *vaultcrypto.AccountSecrets, hadState bool) *TrustStore {
	t := &TrustStore{store: store, key: acct.AccountKey, userID: acct.UserID, d: newTrustData(), touched: map[string]bool{}}
	if store == nil {
		return t
	}
	blob, err := store.LoadTrustBlob(acct.UserID)
	if err != nil {
		t.Reset = true
		return t
	}
	if blob == nil {
		t.Reset = hadState
		return t
	}
	d, ok := t.openBlob(blob)
	if !ok {
		t.Reset = true
		return t
	}
	t.d = *d
	return t
}

func (t *TrustStore) zero() { t.key.Zero() }

// Save persists the store if it changed, merging with what another fvault
// process may have written meanwhile so neither loses a verification, an
// event or a vault epoch.
func (t *TrustStore) Save() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty || t.store == nil {
		return nil
	}
	if blob, err := t.store.LoadTrustBlob(t.userID); err == nil && blob != nil {
		if disk, ok := t.openBlob(blob); ok {
			t.merge(disk)
		}
	}
	js, err := json.Marshal(&t.d)
	if err != nil {
		return err
	}
	sealed, err := vaultcrypto.SealLocalTrust(&t.key, t.userID, js)
	if err != nil {
		return err
	}
	if err := t.store.SaveTrustBlob(t.userID, sealed); err != nil {
		return err
	}
	t.dirty = false
	t.touched = map[string]bool{}
	t.resetRecords = false
	t.olderTouched = false
	return nil
}

func (t *TrustStore) merge(disk *trustData) {
	for id, dc := range disk.Contacts {
		mc, ok := t.d.Contacts[id]
		switch {
		case !ok:
			c := *dc
			t.d.Contacts[id] = &c
		case bytes.Equal(mc.PublicKey, dc.PublicKey) && mc.Username == dc.Username:
			mc.Verified = mc.Verified || dc.Verified
		case dc.FirstSeen <= mc.FirstSeen:
			c := *dc // the older triple is the real one
			t.d.Contacts[id] = &c
		}
	}
	seen := map[string]int{}
	for i, e := range t.d.Events {
		seen[e.key()] = i
	}
	for _, e := range disk.Events {
		if i, ok := seen[e.key()]; ok {
			t.d.Events[i].Dismissed = t.d.Events[i].Dismissed || e.Dismissed
		} else {
			t.d.Events = append(t.d.Events, e)
		}
	}
	if !t.olderTouched && t.d.Older == nil && disk.Older != nil {
		o := *disk.Older
		t.d.Older = &o
	}
	if t.resetRecords {
		return
	}
	for id, dv := range disk.Vaults {
		mv, ok := t.d.Vaults[id]
		if t.touched[id] {
			continue
		}
		if !ok || dv.Epoch > mv.Epoch {
			t.d.Vaults[id] = dv.clone()
		}
	}
	if disk.MaxRev > t.d.MaxRev {
		t.d.MaxRev = disk.MaxRev
	}
}

// ---- accessors (callers hold no lock; each takes it) ----

func (t *TrustStore) contact(id string) (Contact, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.d.Contacts[id]
	if !ok {
		return Contact{}, false
	}
	cc := *c
	cc.PublicKey = append([]byte(nil), c.PublicKey...)
	return cc, true
}

func (t *TrustStore) contactByName(name string) (Contact, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.d.Contacts {
		if c.Username == name {
			return *c, true
		}
	}
	return Contact{}, false
}

func (t *TrustStore) addContact(c Contact) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cc := c
	t.d.Contacts[c.UserID] = &cc
	t.dirty = true
}

func (t *TrustStore) setVerified(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.d.Contacts[id]
	if !ok {
		return false
	}
	if !c.Verified {
		c.Verified = true
		t.dirty = true
	}
	return true
}

func (t *TrustStore) isVerified(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.d.Contacts[id]
	return ok && c.Verified
}

// recordEvent stores a mismatch event once (identical events are not repeated).
func (t *TrustStore) recordEvent(e MismatchEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, x := range t.d.Events {
		if x.key() == e.key() {
			return
		}
	}
	e.At = time.Now().UnixMilli()
	t.d.Events = append(t.d.Events, e)
	t.dirty = true
}

// Events returns the mismatch events.
func (t *TrustStore) events() []MismatchEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]MismatchEvent(nil), t.d.Events...)
}

func (t *TrustStore) dismiss(userID, username string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for i := range t.d.Events {
		if (t.d.Events[i].UserID == userID || t.d.Events[i].Username == username) && !t.d.Events[i].Dismissed {
			t.d.Events[i].Dismissed = true
			n++
		}
	}
	if n > 0 {
		t.dirty = true
	}
	return n
}

func (t *TrustStore) vault(id string) *VaultTrust {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.d.Vaults[id].clone()
}

// setVault records what is accepted for a vault; mem wins in later merges.
func (t *TrustStore) setVault(id string, v *VaultTrust) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v == nil {
		delete(t.d.Vaults, id)
	} else {
		t.d.Vaults[id] = v.clone()
	}
	t.touched[id] = true
	t.dirty = true
}

func (t *TrustStore) maxRev() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.d.MaxRev
}

func (t *TrustStore) noteRev(r uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r > t.d.MaxRev {
		t.d.MaxRev = r
		t.dirty = true
	}
}

func (t *TrustStore) allContacts() []Contact {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Contact, 0, len(t.d.Contacts))
	for _, c := range t.d.Contacts {
		out = append(out, *c)
	}
	return out
}

func fingerprintOf(userID, username string, pub []byte) string {
	var pk vaultcrypto.PublicKey
	copy(pk[:], pub)
	fp, err := vaultcrypto.Fingerprint(userID, username, pk)
	if err != nil {
		return fmt.Sprintf("(invalid: %v)", err)
	}
	return fp
}

func (t *TrustStore) older() *OlderState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.d.Older == nil {
		return nil
	}
	o := *t.d.Older
	return &o
}

func (t *TrustStore) setOlder(o *OlderState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o == nil && t.d.Older == nil {
		return
	}
	t.d.Older = o
	t.olderTouched = true
	t.dirty = true
}

// clearRecords forgets the highest rev and the per-vault records (epoch,
// commitment, owners) and the older-state flag. Contacts, verified flags and
// mismatch events are NOT touched.
func (t *TrustStore) clearRecords() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.d.Vaults = map[string]*VaultTrust{}
	t.d.MaxRev = 0
	t.d.Older = nil
	t.olderTouched = true
	t.resetRecords = true
	t.dirty = true
}
