package vaultcrypto_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	vc "github.com/tarnan3751/password-vault/internal/vaultcrypto"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto/vectorgen"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

func loadVectors(t testing.TB) *vectorgen.File {
	t.Helper()
	f, err := vectorgen.Load("../../testvectors/crypto-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func h(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func sym(t testing.TB, s string) *vc.SymmetricKey {
	t.Helper()
	b := h(t, s)
	if len(b) != 32 {
		t.Fatalf("key length %d", len(b))
	}
	var k vc.SymmetricKey
	copy(k[:], b)
	return &k
}

func priv(t testing.TB, s string) *vc.PrivateKey {
	t.Helper()
	k := vc.PrivateKey(*sym(t, s))
	return &k
}

func pub(t testing.TB, s string) *vc.PublicKey {
	t.Helper()
	var k vc.PublicKey
	copy(k[:], h(t, s))
	return &k
}

func kdfp(t testing.TB, k vectorgen.AccountKDF) api.KDFParams {
	return api.KDFParams{Alg: "argon2id", Salt: h(t, k.SaltHex), Time: k.Time, MemoryKiB: k.MemoryKiB, Parallelism: k.Parallelism}
}

func TestVectors(t *testing.T) {
	f := loadVectors(t)
	if f.Suite != "fpv/v1" || f.SchemaVersion != 1 {
		t.Fatalf("unexpected suite/schema %q %d", f.Suite, f.SchemaVersion)
	}

	t.Run("argon2id_published", func(t *testing.T) {
		for _, c := range f.Argon2idPublished {
			t.Run(c.ID, func(t *testing.T) {
				got := argon2.IDKey(h(t, c.PasswordHex), h(t, c.SaltHex), c.Time, c.MemoryKiB, c.Parallelism, c.OutLen)
				if hex.EncodeToString(got) != c.ExpectedHex {
					t.Fatalf("got %x want %s", got, c.ExpectedHex)
				}
			})
		}
	})
	t.Run("hkdf_published", func(t *testing.T) {
		for _, c := range f.HKDFPublished {
			t.Run(c.ID, func(t *testing.T) {
				prk, err := hkdf.Extract(sha256.New, h(t, c.IKMHex), h(t, c.SaltHex))
				if err != nil || hex.EncodeToString(prk) != c.PRKHex {
					t.Fatalf("prk %x err %v", prk, err)
				}
				okm, err := hkdf.Key(sha256.New, h(t, c.IKMHex), h(t, c.SaltHex), string(h(t, c.InfoHex)), c.Length)
				if err != nil || hex.EncodeToString(okm) != c.OKMHex {
					t.Fatalf("okm %x err %v", okm, err)
				}
			})
		}
	})
	t.Run("x25519_published", func(t *testing.T) {
		for _, c := range f.X25519Published {
			t.Run(c.ID, func(t *testing.T) {
				got, err := curve25519.X25519(h(t, c.ScalarHex), h(t, c.UHex))
				if err != nil || hex.EncodeToString(got) != c.ExpectedHex {
					t.Fatalf("got %x err %v", got, err)
				}
			})
		}
	})
	t.Run("xchacha20poly1305_published", func(t *testing.T) {
		for _, c := range f.XChaChaPublished {
			t.Run(c.ID, func(t *testing.T) {
				key := sym(t, c.KeyHex)
				box, err := vc.SealWithNonce(key, h(t, c.NonceHex), h(t, c.PlaintextHex), h(t, c.AADHex))
				if err != nil {
					t.Fatal(err)
				}
				want := append(append([]byte{1}, h(t, c.NonceHex)...), h(t, c.CiphertextHex+c.TagHex)...)
				if !bytes.Equal(box, want) {
					t.Fatalf("got %x want %x", box, want)
				}
				pt, err := vc.Open(key, want, h(t, c.AADHex))
				if err != nil || !bytes.Equal(pt, h(t, c.PlaintextHex)) {
					t.Fatalf("open: %v", err)
				}
			})
		}
	})

	t.Run("master_keys", func(t *testing.T) {
		byID := map[string]vectorgen.MasterKeyCase{}
		for _, c := range f.MasterKeys {
			byID[c.ID] = c
			t.Run(c.ID, func(t *testing.T) {
				if got := vc.NormalizePassword(c.Password); hex.EncodeToString(got) != c.NormalizedPasswordHex {
					t.Fatalf("normalized %x want %s", got, c.NormalizedPasswordHex)
				}
				if hex.EncodeToString([]byte(c.Password)) != c.PasswordHex {
					t.Fatal("password_hex mismatch")
				}
				p := api.KDFParams{Alg: "argon2id", Salt: h(t, c.SaltHex), Time: c.Time, MemoryKiB: c.MemoryKiB, Parallelism: c.Parallelism}
				// Independent recomputation.
				as := sha256.Sum256(append([]byte("fpv/v1/kdf-salt|"+c.Username+"|"), p.Salt...))
				if hex.EncodeToString(as[:]) != c.ArgonSaltHex {
					t.Fatal("argon salt mismatch")
				}
				mkRaw := argon2.IDKey(h(t, c.NormalizedPasswordHex), as[:], p.Time, p.MemoryKiB, p.Parallelism, 32)
				if hex.EncodeToString(mkRaw) != c.MasterKeyHex {
					t.Fatalf("master key %x", mkRaw)
				}
				enc, _ := hkdf.Key(sha256.New, mkRaw, nil, "fpv/v1/enc-key", 32)
				login, _ := hkdf.Key(sha256.New, mkRaw, nil, "fpv/v1/login-key", 32)
				if hex.EncodeToString(enc) != c.EncKeyHex || hex.EncodeToString(login) != c.LoginKeyHex {
					t.Fatal("sub-key mismatch (independent HKDF)")
				}
				mk, err := vc.DeriveMasterKeysUnsafeParams(c.Username, c.Password, p)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(mk.EncKey[:]) != c.EncKeyHex || hex.EncodeToString(mk.LoginKey[:]) != c.LoginKeyHex {
					t.Fatal("DeriveMasterKeysUnsafeParams mismatch")
				}
				if c.BelowProductionMin {
					if _, err := vc.DeriveMasterKeys(c.Username, c.Password, p); !errors.Is(err, vc.ErrKDFParams) {
						t.Fatalf("DeriveMasterKeys must refuse weak parameters, got %v", err)
					}
				} else {
					mk2, err := vc.DeriveMasterKeys(c.Username, c.Password, p)
					if err != nil || mk2.EncKey != mk.EncKey || mk2.LoginKey != mk.LoginKey {
						t.Fatalf("DeriveMasterKeys: %v", err)
					}
				}
			})
		}
		a, b := byID["mk-nfkc-ligature-fullwidth-cheap"], byID["mk-nfkc-already-normalized-cheap"]
		if a.Password == b.Password || a.EncKeyHex != b.EncKeyHex || a.LoginKeyHex != b.LoginKeyHex || a.PasswordHex == a.NormalizedPasswordHex {
			t.Fatal("NFKC vector pair is not what it claims to be")
		}
		if byID["mk-ascii-cheap"].EncKeyHex == byID["mk-other-username-cheap"].EncKeyHex {
			t.Fatal("username does not influence the keys")
		}
	})
	t.Run("kdf_params_validation", func(t *testing.T) {
		for _, c := range f.KDFValidation {
			t.Run(c.ID, func(t *testing.T) {
				p := api.KDFParams{Alg: c.Alg, Salt: h(t, c.SaltHex), Time: c.Time, MemoryKiB: c.MemoryKiB}
				if c.Parallelism > 255 {
					t.Fatal("parallelism does not fit uint8")
				}
				p.Parallelism = uint8(c.Parallelism)
				if err := vc.ValidateKDFParams(p); (err == nil) != c.Valid {
					t.Fatalf("valid=%v err=%v", c.Valid, err)
				}
			})
		}
	})
	t.Run("kdf_not_weaker", func(t *testing.T) {
		for _, c := range f.KDFNotWeaker {
			t.Run(c.ID, func(t *testing.T) {
				cached := api.KDFParams{Time: c.CachedTime, MemoryKiB: c.CachedMemoryKiB}
				offered := api.KDFParams{Time: c.OfferedTime, MemoryKiB: c.OfferedMemoryKiB}
				if err := vc.CheckKDFNotWeaker(cached, offered); (err == nil) != c.Acceptable {
					t.Fatalf("acceptable=%v err=%v", c.Acceptable, err)
				}
			})
		}
	})

	t.Run("box", func(t *testing.T) {
		for _, c := range f.Box {
			t.Run(c.ID, func(t *testing.T) {
				key := sym(t, c.KeyHex)
				box, err := vc.SealWithNonce(key, h(t, c.NonceHex), h(t, c.PlaintextHex), h(t, c.AADHex))
				if err != nil || hex.EncodeToString(box) != c.BoxHex {
					t.Fatalf("seal: %x err %v", box, err)
				}
				pt, err := vc.Open(key, h(t, c.BoxHex), h(t, c.AADHex))
				if err != nil || !bytes.Equal(pt, h(t, c.PlaintextHex)) {
					t.Fatalf("open: %v", err)
				}
			})
		}
		for _, c := range f.BoxNegative {
			t.Run(c.ID, func(t *testing.T) {
				if _, err := vc.Open(sym(t, c.KeyHex), h(t, c.BoxHex), h(t, c.AADHex)); !errors.Is(err, vc.ErrDecrypt) {
					t.Fatalf("want ErrDecrypt, got %v", err)
				}
			})
		}
	})

	t.Run("key_pairs", func(t *testing.T) {
		for _, c := range f.KeyPairs {
			t.Run(c.ID, func(t *testing.T) {
				got, err := vc.PublicFromPrivate(priv(t, c.PrivateKeyHex))
				if err != nil || got.String() != c.PublicKeyHex {
					t.Fatalf("got %s err %v", got, err)
				}
			})
		}
		for _, c := range f.Fingerprints {
			t.Run(c.ID, func(t *testing.T) {
				got, err := vc.Fingerprint(c.UserID, c.Username, *pub(t, c.PublicKeyHex))
				if err != nil || got != c.Fingerprint {
					t.Fatalf("got %s want %s (%v)", got, c.Fingerprint, err)
				}
			})
		}
	})

	t.Run("vault_key_wrap", func(t *testing.T) {
		for _, c := range f.VaultKeyWrap {
			t.Run(c.ID, func(t *testing.T) {
				ctx := vc.WrapContext{VaultID: c.VaultID, KeyEpoch: c.KeyEpoch, SenderID: c.SenderID, RecipientID: c.RecipientID}
				if string(vc.WrapAAD(ctx)) != c.AADString {
					t.Fatalf("aad %q", vc.WrapAAD(ctx))
				}
				vk := sym(t, c.VaultKeyHex)
				w, err := vc.WrapVaultKeyDeterministic(vk, ctx, priv(t, c.SenderPrivateHex), pub(t, c.RecipientPublicHex), priv(t, c.EphemeralPrivateHex), h(t, c.NonceHex))
				if err != nil || hex.EncodeToString(w) != c.WrapHex || len(w) != 105 {
					t.Fatalf("wrap: %x err %v", w, err)
				}
				got, err := vc.UnwrapVaultKey(h(t, c.WrapHex), ctx, priv(t, c.RecipientPrivateHex), pub(t, c.SenderPublicHex))
				if err != nil || *got != *vk {
					t.Fatalf("unwrap: %v", err)
				}
				if pk, _ := vc.PublicFromPrivate(priv(t, c.SenderPrivateHex)); pk.String() != c.SenderPublicHex {
					t.Fatal("sender public mismatch")
				}
			})
		}
		for _, c := range f.VaultKeyWrapNegative {
			t.Run(c.ID, func(t *testing.T) {
				ctx := vc.WrapContext{VaultID: c.VaultID, KeyEpoch: c.KeyEpoch, SenderID: c.SenderID, RecipientID: c.RecipientID}
				if got, err := vc.UnwrapVaultKey(h(t, c.WrapHex), ctx, priv(t, c.RecipientPrivateHex), pub(t, c.SenderPublicHex)); err == nil {
					t.Fatalf("accepted; key %v", got != nil)
				}
			})
		}
	})

	t.Run("padding", func(t *testing.T) {
		for _, c := range f.Padding {
			t.Run(c.ID, func(t *testing.T) {
				if got := vc.Pad(h(t, c.InputHex), c.N); hex.EncodeToString(got) != c.PaddedHex {
					t.Fatalf("got %d bytes", len(got))
				}
			})
		}
	})
	t.Run("vault_meta", func(t *testing.T) {
		for _, c := range f.VaultMeta {
			t.Run(c.ID, func(t *testing.T) {
				key := sym(t, c.KeyHex)
				if string(vc.VaultMetaAAD(c.VaultID, c.KeyEpoch)) != c.AADString {
					t.Fatal("aad")
				}
				padded := vc.Pad([]byte(c.PlaintextJSON), 64)
				if len(padded) != c.PaddedLength {
					t.Fatal("padded length")
				}
				blob, err := vc.SealWithNonce(key, h(t, c.NonceHex), padded, []byte(c.AADString))
				if err != nil || hex.EncodeToString(blob) != c.BlobHex {
					t.Fatalf("seal err %v", err)
				}
				m, err := vc.DecryptVaultMeta(key, c.VaultID, c.KeyEpoch, h(t, c.BlobHex))
				if err != nil {
					t.Fatal(err)
				}
				if js, err := m.Encode(); err != nil || string(js) != c.PlaintextJSON {
					t.Fatalf("re-encode differs (%v): %s", err, js)
				}
				if b2, err := vc.EncryptVaultMeta(key, c.VaultID, c.KeyEpoch, m); err != nil {
					t.Fatal(err)
				} else if _, err := vc.DecryptVaultMeta(key, c.VaultID, c.KeyEpoch, b2); err != nil {
					t.Fatal(err)
				}
			})
		}
		for _, c := range f.VaultMetaNeg {
			t.Run(c.ID, func(t *testing.T) {
				if _, err := vc.DecryptVaultMeta(sym(t, c.KeyHex), c.VaultID, c.KeyEpoch, h(t, c.BlobHex)); !errors.Is(err, vc.ErrDecrypt) {
					t.Fatalf("want ErrDecrypt, got %v", err)
				}
			})
		}
	})
	t.Run("items", func(t *testing.T) {
		for _, c := range f.Items {
			t.Run(c.ID, func(t *testing.T) {
				key := sym(t, c.KeyHex)
				if string(vc.ItemAAD(c.VaultID, c.ItemID, c.KeyEpoch)) != c.AADString {
					t.Fatal("aad")
				}
				padded := vc.Pad([]byte(c.PlaintextJSON), 256)
				if len(padded) != c.PaddedLength || len(padded)%256 != 0 {
					t.Fatal("padded length")
				}
				blob, err := vc.SealWithNonce(key, h(t, c.NonceHex), padded, []byte(c.AADString))
				if err != nil || hex.EncodeToString(blob) != c.BlobHex {
					t.Fatalf("seal err %v", err)
				}
				it, err := vc.DecryptItem(key, c.VaultID, c.ItemID, c.KeyEpoch, h(t, c.BlobHex))
				if err != nil {
					t.Fatal(err)
				}
				js, err := it.Encode()
				if err != nil || string(js) != c.PlaintextJSON {
					t.Fatalf("re-encode differs (%v):\n%s\n%s", err, js, c.PlaintextJSON)
				}
				b2, err := vc.EncryptItem(key, c.VaultID, c.ItemID, c.KeyEpoch, it)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := vc.DecryptItem(key, c.VaultID, c.ItemID, c.KeyEpoch, b2); err != nil {
					t.Fatal(err)
				}
			})
		}
		for _, c := range f.ItemsNeg {
			t.Run(c.ID, func(t *testing.T) {
				if _, err := vc.DecryptItem(sym(t, c.KeyHex), c.VaultID, c.ItemID, c.KeyEpoch, h(t, c.BlobHex)); !errors.Is(err, vc.ErrDecrypt) {
					t.Fatalf("want ErrDecrypt, got %v", err)
				}
			})
		}
	})
	t.Run("rosters", func(t *testing.T) {
		for _, c := range f.Rosters {
			t.Run(c.ID, func(t *testing.T) {
				key := sym(t, c.KeyHex)
				if string(vc.RosterAAD(c.VaultID, c.KeyEpoch)) != c.AADString {
					t.Fatal("aad")
				}
				blob, err := vc.SealWithNonce(key, h(t, c.NonceHex), []byte(c.PlaintextJSON), []byte(c.AADString))
				if err != nil || hex.EncodeToString(blob) != c.BlobHex {
					t.Fatalf("seal err %v", err)
				}
				r, err := vc.DecryptRoster(key, c.VaultID, c.KeyEpoch, h(t, c.BlobHex))
				if err != nil {
					t.Fatal(err)
				}
				if js, err := r.Encode(); err != nil || string(js) != c.PlaintextJSON {
					t.Fatalf("re-encode differs (%v)", err)
				}
				if len(r.Owners()) == 0 {
					t.Fatal("no owners")
				}
			})
		}
		for _, c := range f.RostersNeg {
			t.Run(c.ID, func(t *testing.T) {
				if r, err := vc.DecryptRoster(sym(t, c.KeyHex), c.VaultID, c.KeyEpoch, h(t, c.BlobHex)); err == nil {
					t.Fatalf("accepted: %+v", r)
				}
			})
		}
	})
	t.Run("decoding", func(t *testing.T) {
		decode := func(kind string, pt []byte) (string, error) {
			switch kind {
			case vectorgen.KindItem:
				it, err := vc.DecodeItem(pt)
				if err != nil {
					return "", err
				}
				js, err := it.Encode()
				return string(js), err
			case vectorgen.KindMeta:
				m, err := vc.DecodeVaultMeta(pt)
				if err != nil {
					return "", err
				}
				js, err := m.Encode()
				return string(js), err
			default:
				r, err := vc.DecodeRoster(pt)
				if err != nil {
					return "", err
				}
				js, err := r.Encode()
				return string(js), err
			}
		}
		for _, c := range f.DecodingAccept {
			t.Run(c.ID, func(t *testing.T) {
				got, err := decode(c.Kind, h(t, c.PlaintextHex))
				if err != nil || got != c.CanonicalJSON {
					t.Fatalf("err=%v\n got %s\nwant %s", err, got, c.CanonicalJSON)
				}
				// canonical output is itself accepted and a fixed point
				again, err := decode(c.Kind, []byte(got))
				if err != nil || again != got {
					t.Fatalf("canonical form is not a fixed point: %v", err)
				}
			})
		}
		for _, c := range f.DecodingReject {
			t.Run(c.ID, func(t *testing.T) {
				if got, err := decode(c.Kind, h(t, c.PlaintextHex)); err == nil {
					t.Fatalf("accepted as %s", got)
				} else if !errors.Is(err, vc.ErrUnreadable) {
					t.Fatalf("error does not wrap ErrUnreadable: %v", err)
				}
			})
		}
		for _, c := range f.EditPreserve {
			t.Run(c.ID, func(t *testing.T) {
				var got []byte
				if c.Kind == vectorgen.KindItem {
					it, err := vc.DecodeItem(h(t, c.PlaintextHex))
					if err != nil {
						t.Fatal(err)
					}
					it.Name = c.NewName
					got, err = it.Encode()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					m, err := vc.DecodeVaultMeta(h(t, c.PlaintextHex))
					if err != nil {
						t.Fatal(err)
					}
					m.Name = c.NewName
					got, err = m.Encode()
					if err != nil {
						t.Fatal(err)
					}
				}
				if string(got) != c.ExpectedJSON {
					t.Fatalf("got  %s\nwant %s", got, c.ExpectedJSON)
				}
			})
		}
	})
	t.Run("reencrypt", func(t *testing.T) {
		for _, c := range f.Reencrypt {
			t.Run(c.ID, func(t *testing.T) {
				oldK, newK := sym(t, c.OldKeyHex), sym(t, c.NewKeyHex)
				in := h(t, c.InputBlobHex)
				var out []byte
				var opened bool
				var err error
				if c.Kind == vectorgen.KindMeta {
					out, opened, err = vc.ReencryptMetaWithNonce(oldK, newK, c.VaultID, c.OldEpoch, c.NewEpoch, in, h(t, c.NonceHex))
				} else {
					out, opened, err = vc.ReencryptItemWithNonce(oldK, newK, c.VaultID, c.ItemID, c.OldEpoch, c.NewEpoch, in, h(t, c.NonceHex))
				}
				if err != nil || opened != c.Opened || hex.EncodeToString(out) != c.OutputBlobHex {
					t.Fatalf("opened=%v err=%v out=%x", opened, err, out)
				}
				if !c.Opened && !bytes.Equal(out, in) {
					t.Fatal("unopened blob must be carried over unchanged")
				}
				if c.Opened {
					// the plaintext bytes are identical before and after
					var aadOld, aadNew []byte
					if c.Kind == vectorgen.KindMeta {
						aadOld, aadNew = vc.VaultMetaAAD(c.VaultID, c.OldEpoch), vc.VaultMetaAAD(c.VaultID, c.NewEpoch)
					} else {
						aadOld, aadNew = vc.ItemAAD(c.VaultID, c.ItemID, c.OldEpoch), vc.ItemAAD(c.VaultID, c.ItemID, c.NewEpoch)
					}
					p1, err1 := vc.Open(oldK, in, aadOld)
					p2, err2 := vc.Open(newK, out, aadNew)
					if err1 != nil || err2 != nil || !bytes.Equal(p1, p2) {
						t.Fatal("plaintext changed")
					}
				}
			})
		}
	})
	t.Run("vault_key_commitments", func(t *testing.T) {
		for _, c := range f.Commitments {
			t.Run(c.ID, func(t *testing.T) {
				vk := sym(t, c.VaultKeyHex)
				sum := sha256.Sum256(append([]byte(fmt.Sprintf("fpv/v1/vault-key-commit|%s|%d|", c.VaultID, c.KeyEpoch)), vk[:]...))
				if hex.EncodeToString(sum[:]) != c.CommitmentHex || vc.VaultKeyCommitment(vk, c.VaultID, c.KeyEpoch) != c.CommitmentHex {
					t.Fatal("commitment mismatch")
				}
			})
		}
	})
	t.Run("local_trust", func(t *testing.T) {
		for _, c := range f.LocalTrust {
			t.Run(c.ID, func(t *testing.T) {
				ak := sym(t, c.AccountKeyHex)
				if hex.EncodeToString(vc.LocalTrustKey(ak)[:]) != c.TrustKeyHex {
					t.Fatal("trust key")
				}
				if string(vc.LocalTrustAAD(c.UserID)) != c.AADString {
					t.Fatal("aad")
				}
				blob, err := vc.SealLocalTrustWithNonce(ak, c.UserID, h(t, c.PlaintextHex), h(t, c.NonceHex))
				if err != nil || hex.EncodeToString(blob) != c.BlobHex {
					t.Fatalf("seal: %v", err)
				}
				pt, err := vc.OpenLocalTrust(ak, c.UserID, h(t, c.BlobHex))
				if err != nil || !bytes.Equal(pt, h(t, c.PlaintextHex)) {
					t.Fatalf("open: %v", err)
				}
			})
		}
		for _, c := range f.LocalTrustNeg {
			t.Run(c.ID, func(t *testing.T) {
				if _, err := vc.OpenLocalTrust(sym(t, c.AccountKeyHex), c.UserID, h(t, c.BlobHex)); !errors.Is(err, vc.ErrDecrypt) {
					t.Fatalf("want ErrDecrypt, got %v", err)
				}
			})
		}
	})
	t.Run("password_policy", func(t *testing.T) {
		list := vc.CommonPasswords()
		if len(list) < 200 || !sort.StringsAreSorted(list) || fmt.Sprint(list) != fmt.Sprint(f.PasswordPolicyCommon) {
			t.Fatalf("common list differs from the vectors (%d entries)", len(list))
		}
		for _, c := range f.PasswordPolicy {
			t.Run(c.ID, func(t *testing.T) {
				err := vc.CheckMasterPassword(c.Password, c.Username)
				if c.Expect == "ok" {
					if err != nil {
						t.Fatalf("rejected: %v", err)
					}
				} else {
					var pe *vc.PolicyError
					if !errors.As(err, &pe) || pe.Code != c.Expect || pe.Reason == "" {
						t.Fatalf("want %s, got %v", c.Expect, err)
					}
				}
				if (vc.PasswordHint(c.Password) != "") != c.Hint {
					t.Fatalf("hint mismatch")
				}
			})
		}
	})

	t.Run("accounts", func(t *testing.T) {
		for _, c := range f.Accounts {
			t.Run(c.ID, func(t *testing.T) {
				mk, err := vc.DeriveMasterKeys(c.Username, c.Password, kdfp(t, c.KDF))
				if err != nil || hex.EncodeToString(mk.EncKey[:]) != c.EncKeyHex || hex.EncodeToString(mk.LoginKey[:]) != c.LoginKeyHex {
					t.Fatalf("master keys: %v", err)
				}
				sec, up, err := vc.NewAccountDeterministic(c.UserID, mk, sym(t, c.AccountKeyHex), priv(t, c.PrivateKeyHex), h(t, c.NonceWrapHex), h(t, c.NonceEncPrivHex))
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(up.PublicKey) != c.PublicKeyHex || hex.EncodeToString(up.WrappedAccountKey) != c.WrappedAccountKeyHex || hex.EncodeToString(up.EncPrivateKey) != c.EncPrivateKeyHex {
					t.Fatal("uploaded artifacts differ")
				}
				got, err := vc.UnlockAccount(c.UserID, mk, h(t, c.PublicKeyHex), h(t, c.WrappedAccountKeyHex), h(t, c.EncPrivateKeyHex))
				if err != nil || got.AccountKey != sec.AccountKey || got.PrivateKey != sec.PrivateKey {
					t.Fatalf("unlock: %v", err)
				}
				pc := c.PasswordChange
				nmk, err := vc.DeriveMasterKeys(c.Username, pc.NewPassword, kdfp(t, pc.NewKDF))
				if err != nil || hex.EncodeToString(nmk.EncKey[:]) != pc.NewEncKeyHex || hex.EncodeToString(nmk.LoginKey[:]) != pc.NewLoginKeyHex {
					t.Fatalf("new master keys: %v", err)
				}
				w, err := vc.RewrapAccountKeyWithNonce(c.UserID, &got.AccountKey, nmk, h(t, pc.NewNonceHex))
				if err != nil || hex.EncodeToString(w) != pc.NewWrappedAccountKeyHex {
					t.Fatalf("rewrap: %v", err)
				}
				got2, err := vc.UnlockAccount(c.UserID, nmk, h(t, c.PublicKeyHex), w, h(t, c.EncPrivateKeyHex))
				if err != nil || got2.PrivateKey != got.PrivateKey {
					t.Fatalf("unlock after change: %v", err)
				}
			})
		}
		for _, c := range f.AccountsNeg {
			t.Run(c.ID, func(t *testing.T) {
				mk, err := vc.DeriveMasterKeys(c.Username, c.Password, kdfp(t, c.KDF))
				if err != nil {
					t.Fatal(err)
				}
				_, err = vc.UnlockAccount(c.UserID, mk, h(t, c.PublicKeyHex), h(t, c.WrappedAccountKeyHex), h(t, c.EncPrivateKeyHex))
				switch c.ExpectError {
				case vectorgen.ErrKindDecrypt:
					if !errors.Is(err, vc.ErrDecrypt) {
						t.Fatalf("want ErrDecrypt, got %v", err)
					}
				case vectorgen.ErrKindPublicKeyMismatch:
					if !errors.Is(err, vc.ErrPublicKeyMismatch) {
						t.Fatalf("want ErrPublicKeyMismatch, got %v", err)
					}
				default:
					t.Fatalf("unknown expectation %q", c.ExpectError)
				}
			})
		}
	})
}
