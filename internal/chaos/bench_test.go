package chaos

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/client"
	"github.com/tarnan3751/password-vault/internal/vaultcrypto"
)

// End-to-end benchmarks: the Go client library against three in-process
// nodes with the real HTTP API, the real peer transport and the real log on
// disk. They measure what a person waits for, not one function.
//
//	go test ./internal/chaos -run '^$' -bench . -benchtime 3s

const benchToken = "bench-bootstrap-token-000000"

// benchCluster starts a cluster with one registered user and returns a
// function that opens a new session for that user, plus the session's API
// handle for raw requests.
func benchCluster(b *testing.B, fsync bool) func() (*client.Session, *client.API) {
	return benchClusterWith(b, InprocConfig{Fsync: fsync})
}

func benchClusterWith(b *testing.B, cfg InprocConfig) func() (*client.Session, *client.API) {
	b.Helper()
	cfg.Dir, cfg.BootstrapToken, cfg.Seed, cfg.SnapshotThreshold = b.TempDir(), benchToken, 1, 4096
	c, err := StartInproc(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Shutdown() })
	ctx := context.Background()
	if _, err := waitHealthy(ctx, c, 20*time.Second); err != nil {
		b.Fatal(err)
	}
	var urls []string
	for _, id := range c.IDs() {
		urls = append(urls, c.URL(id))
	}
	const user, password = "pat", "correct horse battery staple, measured"
	deps := func() client.Deps {
		a, err := client.New(client.Options{Nodes: urls, HTTPClient: c.HTTPClient(), AllowInsecure: true})
		if err != nil {
			b.Fatal(err)
		}
		return client.Deps{API: a}
	}
	if _, err := client.Register(ctx, deps(), client.RegisterParams{Username: user, Password: password, InviteCode: benchToken}); err != nil {
		b.Fatal(err)
	}
	return func() (*client.Session, *client.API) {
		d := deps()
		s, err := client.Login(ctx, d, user, password)
		if err != nil {
			b.Fatal(err)
		}
		return s, d.API
	}
}

func personalVault(b *testing.B, s *client.Session) string {
	b.Helper()
	for _, v := range s.Vaults() {
		if v.Personal {
			return v.ID
		}
	}
	b.Fatal("no personal vault")
	return ""
}

func benchItem(i int) *vaultcrypto.Item {
	return &vaultcrypto.Item{Type: "login", Name: fmt.Sprintf("Site %04d", i), Username: "someone@example.com",
		Password: "kV7#pQ2!xR9$mT4&", URLs: []string{fmt.Sprintf("https://site%04d.example/login", i)}}
}

// BenchmarkWrite is one person saving one entry at a time, each save made
// durable on a majority (fsync on two of three disks) before it returns.
// All three nodes share this machine's disk here, so their fsyncs queue up.
func BenchmarkWrite(b *testing.B) { benchWrite(b, InprocConfig{Fsync: true}) }

// BenchmarkWriteOwnDisks is the same save on a cluster where every node has
// its own disk, as three separate machines do: 3 ms per flush is a laptop
// SSD, 10 ms an SD card.
func BenchmarkWriteOwnDisks(b *testing.B) {
	for _, flush := range []time.Duration{3 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(flush.String(), func(b *testing.B) { benchWrite(b, InprocConfig{FlushDelay: flush}) })
	}
}

func benchWrite(b *testing.B, cfg InprocConfig) {
	s, _ := benchClusterWith(b, cfg)()
	ctx := context.Background()
	vault := personalVault(b, s)
	id, err := s.CreateItem(ctx, vault, benchItem(0))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.UpdateItem(ctx, vault, id, func(it *vaultcrypto.Item) { it.Notes = strconv.Itoa(i) }); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteParallel is 16 devices saving at once, each to its own
// entry: it shows how well concurrent saves share one fsync.
func BenchmarkWriteParallel(b *testing.B) {
	login := benchCluster(b, true)
	ctx := context.Background()
	const writers = 16
	type writer struct {
		s         *client.Session
		vault, id string
	}
	ws := make([]writer, writers)
	for i := range ws {
		s, _ := login()
		vault := personalVault(b, s)
		id, err := s.CreateItem(ctx, vault, benchItem(i))
		if err != nil {
			b.Fatal(err)
		}
		ws[i] = writer{s, vault, id}
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	b.ResetTimer()
	for _, w := range ws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := next.Add(1)
				if n > int64(b.N) {
					return
				}
				// Other writers change the vault between this session's saves;
				// catch up first, as a device does.
				if err := w.s.Sync(ctx); err != nil {
					errs <- err
					return
				}
				if err := w.s.UpdateItem(ctx, w.vault, w.id, func(it *vaultcrypto.Item) { it.Notes = strconv.FormatInt(n, 10) }); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errs:
		b.Fatal(err)
	default:
	}
}

// BenchmarkRead is a device asking "anything new?" when nothing is: one
// linearizable read (the leader confirms with a majority that it still leads).
func BenchmarkRead(b *testing.B) {
	s, _ := benchCluster(b, false)()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Sync(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncFull is a new device downloading a vault of 1000 entries
// (the server assembling the response, the transfer and the JSON decoding;
// not the Argon2id of logging in, which is deliberately slow).
func BenchmarkSyncFull(b *testing.B) {
	login := benchCluster(b, false)
	ctx := context.Background()
	s, a := login()
	vault := personalVault(b, s)
	for i := 0; i < 1000; i++ {
		if _, err := s.CreateItem(ctx, vault, benchItem(i)); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := a.Sync(ctx, 0)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			var n int
			for _, v := range resp.Vaults {
				n += len(v.Items)
			}
			if n != 1000 {
				b.Fatalf("sync returned %d items, want 1000", n)
			}
		}
	}
}

// BenchmarkUnlock is opening a session on a vault of 1000 entries: the
// Argon2id of the master password plus fetching, checking and decrypting
// everything.
func BenchmarkUnlock(b *testing.B) {
	login := benchCluster(b, false)
	ctx := context.Background()
	s, _ := login()
	vault := personalVault(b, s)
	for i := 0; i < 1000; i++ {
		if _, err := s.CreateItem(ctx, vault, benchItem(i)); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		login()
	}
}
