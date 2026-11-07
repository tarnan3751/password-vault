package client

import (
	"context"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// Deliberate recovery (crypto.md §6.4). After the administrator restores the
// servers from a backup they legitimately show a lower rev and possibly older
// key epochs. A client cannot tell that from a rollback attack, so it never
// decides: it reports RestoredStateError / ModeOlder and waits for one explicit
// user action, implemented here. It is never automatic and never available for
// a key mismatch or for a different key at an epoch already recorded.

// Recovery is a prepared, not yet accepted, recovery.
type Recovery struct {
	// Info describes what the servers show compared with what this device saw.
	Info RestoredStateError

	s    *Session
	resp *api.SyncResponse
}

// BeginRecovery logs in (the same checks as Login) and examines the state the
// servers show. It changes nothing locally. It returns ErrNothingToRecover if
// the servers do not show older data, and *RecoveryRefusedError if the state
// is not a pure rev/epoch step backward (key mismatches, or the same epoch
// with a different key).
func BeginRecovery(ctx context.Context, d Deps, username, password string) (*Recovery, error) {
	s, resp, err := loginRaw(ctx, d, username, password)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Recovery, error) {
		s.Lock()
		return nil, e
	}
	if err := s.validateSync(resp); err != nil {
		return fail(err)
	}
	baseline := s.trust.maxRev()
	lower := s.lowerEpochVaults(resp)
	if resp.Stale {
		return fail(&RecoveryRefusedError{Reason: "the answer came from a node that could not confirm a majority; try again when the cluster is healthy"})
	}
	if resp.Rev >= baseline && len(lower) == 0 {
		return fail(ErrNothingToRecover)
	}
	s.directory = make(map[string]api.DirectoryUser, len(resp.Directory))
	for _, du := range resp.Directory {
		s.directory[du.UserID] = du
	}
	s.observeContacts()
	if ms := s.KeyMismatches(); len(ms) > 0 {
		return fail(&RecoveryRefusedError{Reason: fmt.Sprintf("the key or identity of %q contradicts what this device recorded", ms[0].Username)})
	}
	for i := range resp.Vaults {
		v := &resp.Vaults[i]
		vt := s.trust.vault(v.ID)
		if vt == nil || v.KeyEpoch != vt.Epoch {
			continue
		}
		if vt.Prior != nil {
			continue
		}
		if c, ok := s.commitmentOf(v); ok && c != vt.Commitment {
			return fail(&RecoveryRefusedError{Reason: fmt.Sprintf("vault %s is offered with a different key at the epoch (%d) this device already recorded", short8(v.ID), v.KeyEpoch)})
		}
	}
	seen := baseline
	if resp.Rev >= baseline {
		seen = resp.Rev
	}
	return &Recovery{Info: RestoredStateError{ServerRev: resp.Rev, SeenRev: seen, LowerEpochVaults: lower}, s: s, resp: resp}, nil
}

// Close discards a recovery that was not accepted.
func (r *Recovery) Close() { r.s.Lock() }

// Accept performs the recovery: it clears the stored highest rev and the
// per-vault records (epoch, commitment, owners) ONLY, replaces the offline
// cache, and evaluates every vault again as if this device had not seen it
// before: keys from the user themself and from verified contacts are accepted,
// the rest become pending. Contacts, verified flags and mismatch events are
// untouched. The returned session is online.
func (r *Recovery) Accept() (*Session, error) {
	s := r.s
	s.trust.clearRecords()
	if err := s.trust.Save(); err != nil {
		s.Lock()
		return nil, err
	}
	if s.d.Store != nil {
		if err := s.d.Store.DeleteCache(); err != nil {
			s.Lock()
			return nil, err
		}
	}
	s.raw = nil
	s.vaults = nil
	s.mode = ModeOnline
	if err := s.applySync(r.resp, true); err != nil {
		s.Lock()
		return nil, err
	}
	s.learnNodes(context.Background())
	return s, nil
}

// commitmentOf unwraps the vault key offered for v exactly as acceptVault would
// (sender self, or a non-mismatching known contact) and returns its commitment.
func (s *Session) commitmentOf(v *api.Vault) (string, bool) {
	sender := v.MyKey.SenderID
	var pub vaultcrypto.PublicKey
	if sender == s.UserID {
		pub = s.secrets.PublicKey
	} else {
		c, ok := s.trust.contact(sender)
		if !ok || s.mismatch[sender] != nil {
			return "", false
		}
		copy(pub[:], c.PublicKey)
	}
	vk, err := vaultcrypto.UnwrapVaultKey(v.MyKey.Blob, vaultcrypto.WrapContext{VaultID: v.ID, KeyEpoch: v.KeyEpoch, SenderID: sender, RecipientID: s.UserID}, &s.secrets.PrivateKey, &pub)
	if err != nil {
		return "", false
	}
	defer vk.Zero()
	return vaultcrypto.VaultKeyCommitment(vk, v.ID, v.KeyEpoch), true
}

// loginRaw is Login up to (not including) applying the sync response.
func loginRaw(ctx context.Context, d Deps, username, password string) (*Session, *api.SyncResponse, error) {
	if d.API == nil {
		return nil, nil, fmt.Errorf("recovery needs a server")
	}
	username, err := vaultcrypto.NormalizeUsername(username)
	if err != nil {
		return nil, nil, &UserError{Msg: "invalid username: " + err.Error()}
	}
	pre, err := d.API.Prelogin(ctx, username)
	if err != nil {
		return nil, nil, err
	}
	cache := cacheOf(d, username)
	if cache != nil && cache.Sync.Account != nil {
		if err := vaultcrypto.CheckKDFNotWeaker(cache.Sync.Account.KDF, pre.KDF); err != nil {
			return nil, nil, fmt.Errorf("the server offered weaker key-derivation parameters than this device has on record (refusing): %w", err)
		}
	}
	mk, err := vaultcrypto.DeriveMasterKeys(username, password, pre.KDF)
	if err != nil {
		return nil, nil, fmt.Errorf("the server offered unacceptable key-derivation parameters (refusing): %w", err)
	}
	defer mk.EncKey.Zero()
	lr, err := d.API.Login(ctx, username, mk.LoginKey[:])
	if err != nil {
		if IsCode(err, api.CodeUnauthorized) {
			return nil, nil, ErrWrongPassword
		}
		return nil, nil, err
	}
	resp, err := d.API.Sync(ctx, 0)
	if err != nil {
		return nil, nil, err
	}
	if resp.Account == nil {
		return nil, nil, &ProtocolError{Msg: "no account block"}
	}
	if lr.UserID != resp.Account.UserID || lr.Username != username {
		return nil, nil, &ProtocolError{Msg: "the account in the sync response is not the one that logged in"}
	}
	s, err := newFromAccount(d, resp.Account, username, mk, cache != nil)
	if err != nil {
		return nil, nil, err
	}
	s.isAdmin = lr.IsAdmin
	s.saveToken(lr)
	return s, resp, nil
}
