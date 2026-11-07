package client

import (
	"context"
	"fmt"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/client/clienttest"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

const benchPassword = "correct horse battery staple, measured"

// benchSession returns an unlocked session whose personal vault holds n
// entries. They are written straight through the API: seeding them one by one
// through the Session would sync the whole vault n times.
func benchSession(b *testing.B, n int) (*Session, string, Deps) {
	b.Helper()
	cl := clienttest.New(b, 3)
	st, err := OpenStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	a, err := New(Options{Nodes: cl.URLs()[:1], AllowInsecure: true})
	if err != nil {
		b.Fatal(err)
	}
	deps := Deps{API: a, Store: st, CacheToken: true, KDF: fastKDF}
	ctx := context.Background()
	s, err := Register(ctx, deps, RegisterParams{Username: "pat", Password: benchPassword, InviteCode: clienttest.BootstrapToken})
	if err != nil {
		b.Fatal(err)
	}
	vault := s.Vaults()[0].ID
	sec := s.vaultKeys[vault]
	for i := 0; i < n; i++ {
		id := vaultcrypto.NewID()
		it := &vaultcrypto.Item{V: 1, Type: vaultcrypto.ItemTypeLogin, Name: fmt.Sprintf("Site %04d", i), Username: "someone@example.com",
			Password: "kV7#pQ2!xR9$mT4&", URLs: []string{fmt.Sprintf("https://site%04d.example/login", i)}}
		blob, err := s.encodeItem(sec, vault, id, it)
		if err != nil {
			b.Fatal(err)
		}
		if err := a.PutItem(ctx, vault, id, &api.PutItemRequest{Blob: blob, KeyEpoch: sec.epoch}); err != nil {
			b.Fatal(err)
		}
	}
	if err := s.Sync(ctx); err != nil {
		b.Fatal(err)
	}
	return s, vault, deps
}

// BenchmarkSyncUnchanged is "anything new?" on a 2000-entry vault.
func BenchmarkSyncUnchanged(b *testing.B) {
	s, _, _ := benchSession(b, 2000)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Sync(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSave is one saved change in a 2000-entry vault: the write, the
// sync that follows it, the rebuilt views, the cache and the trust store.
func BenchmarkSave(b *testing.B) {
	s, vault, _ := benchSession(b, 2000)
	ctx := context.Background()
	id := s.Vault(vault).Items[0].ID
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.UpdateItem(ctx, vault, id, func(it *vaultcrypto.Item) { it.Notes = fmt.Sprint(i) }); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkApplyFull is the client-side cost of a first sync of 2000 entries
// (check and decrypt everything), without the network.
func BenchmarkApplyFull(b *testing.B) {
	s, _, deps := benchSession(b, 2000)
	cache, err := deps.Store.LoadCache()
	if err != nil || cache == nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.raw, s.vaults = nil, nil
		if err := s.applySync(&cache.Sync, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpenCached is `fvault ls` with a warm cache and a cached token
// (the KDF is the cheapest the client accepts).
func BenchmarkOpenCached(b *testing.B) {
	s, _, deps := benchSession(b, 2000)
	s.Lock()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s2, err := Open(ctx, deps, "pat", benchPassword)
		if err != nil {
			b.Fatal(err)
		}
		s2.Lock()
	}
}
