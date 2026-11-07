package fsm

import (
	"fmt"
	"sync"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// Benchmarks of the paths that hold the state lock or the Raft event loop:
// snapshots of a large state (Raft takes one every snapshot_threshold
// applied entries, on its event loop), restore, the state hash, and the
// apply and sync-view paths.
//
//	go test ./internal/fsm -run '^$' -bench . -benchmem

// benchShape is a state of about mib MiB of item ciphertext in blobs of
// blob bytes each, spread over as many vaults and users as the quotas need,
// with a full idempotency table. 36 MiB of 512-byte entries is the
// household quota (each entry is also charged 128 bytes).
type benchShape struct {
	name string
	mib  int
	blob int
}

var benchShapes = []benchShape{
	{"small-1MiB", 1, 512}, {"small-10MiB", 10, 512}, {"small-36MiB", 36, 512},
	{"large-1MiB", 1, 32 << 10}, {"large-10MiB", 10, 32 << 10}, {"large-40MiB", 40, 32 << 10},
}

var benchStates sync.Map // benchShape -> *FSM

// benchFSM builds the state for sh once per process. Items are inserted
// directly (applying 80 000 commands would dominate the benchmark run);
// the result is checked to be a valid, canonical state.
func benchFSM(b testing.TB, sh benchShape) *FSM {
	if f, ok := benchStates.Load(sh); ok {
		return f.(*FSM)
	}
	h := newHarness(b)
	perItem := int64(sh.blob) + ItemOverheadBytes
	perVault := min(int64(MaxItemsPerVault), (MaxVaultBytes-64<<10)/perItem)
	total := int64(sh.mib<<20) / int64(sh.blob)
	nVaults := int((total + perVault - 1) / perVault)
	nUsers := max(3, (nVaults+1)/2)
	users := []*tuser{h.bootstrap(1, "user1")}
	for i := 2; i <= nUsers; i++ {
		users = append(users, h.addUser(users[0], i, fmt.Sprintf("user%d", i)))
	}
	left := total
	for vi := 0; vi < nVaults; vi++ {
		owner := users[vi%nUsers]
		vid := h.createVault(owner, vi+1)
		for _, m := range []*tuser{users[(vi+1)%nUsers], users[(vi+2)%nUsers]} {
			h.addMember(owner, vid, m, api.RoleEditor)
		}
		n := min(left, perVault)
		left -= n
		h.f.mu.Lock()
		v := h.f.s.vaults[vid]
		for i := 0; i < int(n); i++ {
			id := hexID(byte(0x40+vi), i*7919%1_000_003)
			v.Items[id] = &item{ID: id, Blob: box(sh.blob), Version: v.Rev, UpdatedAt: h.now, UpdatedBy: owner.id}
		}
		v.recount()
		h.f.mu.Unlock()
	}
	// Fill the idempotency table with real results.
	ver := uint64(0)
	for i := 0; i < IdempotencyCapacity; i++ {
		out := h.mustOK(users[0], &PutItemArgs{VaultID: users[0].personal, ItemID: itemID(1), Blob: box(64), BaseVersion: ver, KeyEpoch: 1})
		ver = out.Version
	}
	snapshotRoundTrip(b, h.f)
	benchStates.Store(sh, h.f)
	return h.f
}

func benchEachShape(b *testing.B, fn func(b *testing.B, f *FSM, snap []byte)) {
	for _, sh := range benchShapes {
		b.Run(sh.name, func(b *testing.B) {
			f := benchFSM(b, sh)
			snap, err := f.Snapshot()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(snap)))
			b.ReportAllocs()
			b.ResetTimer()
			fn(b, f, snap)
		})
	}
}

func BenchmarkSnapshot(b *testing.B) {
	benchEachShape(b, func(b *testing.B, f *FSM, _ []byte) {
		for range b.N {
			if _, err := f.Snapshot(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSnapshotLayout is the part of Snapshot, BackupSnapshot and
// StateHash that holds the state lock (laying out the document); the rest
// is encoding.
func BenchmarkSnapshotLayout(b *testing.B) {
	benchEachShape(b, func(b *testing.B, f *FSM, _ []byte) {
		for range b.N {
			f.mu.RLock()
			f.s.doc(true)
			f.mu.RUnlock()
		}
	})
}

func BenchmarkBackupSnapshot(b *testing.B) {
	benchEachShape(b, func(b *testing.B, f *FSM, _ []byte) {
		for range b.N {
			if _, _, err := f.BackupSnapshot(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkStateHash(b *testing.B) {
	benchEachShape(b, func(b *testing.B, f *FSM, _ []byte) {
		for range b.N {
			f.StateHash()
		}
	})
}

func BenchmarkRestore(b *testing.B) {
	benchEachShape(b, func(b *testing.B, _ *FSM, snap []byte) {
		g := New()
		for range b.N {
			if err := g.Restore(snap); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkValidateSnapshot(b *testing.B) {
	benchEachShape(b, func(b *testing.B, _ *FSM, snap []byte) {
		for range b.N {
			if err := ValidateSnapshot(snap); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkApply measures single commands against a household-sized state
// (10 MiB in 512-byte entries).
func BenchmarkApply(b *testing.B) {
	sh := benchShape{"small-10MiB", 10, 512}
	setup := func(b *testing.B) (*harness, *tuser) {
		f := benchFSM(b, sh)
		snap, _ := f.Snapshot()
		h := newHarness(b)
		// The vault is at its item limit; lift the limits so that b.N
		// creates succeed. The quota checks still run at full cost.
		h.f = newWithLimits(limits{users: MaxUsers, vaultsPerCreator: MaxVaultsPerOwner, itemsPerVault: 1 << 30,
			vaultBytes: 1 << 40, userBytes: 1 << 40, clusterBytes: 1 << 40})
		if err := h.f.Restore(snap); err != nil {
			b.Fatal(err)
		}
		h.seq = 1 << 40 // request ids distinct from those in the table
		return h, &tuser{id: userID(1), ep: 1}
	}
	blob := box(700)
	b.Run("put_item_create", func(b *testing.B) {
		h, u := setup(b)
		cmds := make([][]byte, b.N)
		for i := range cmds {
			cmds[i] = h.cmd(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, i), Blob: blob, KeyEpoch: 1})
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			h.f.Apply(1, cmds[i])
		}
	})
	b.Run("put_item_update", func(b *testing.B) {
		h, u := setup(b)
		ver := h.mustOK(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, 0), Blob: blob, KeyEpoch: 1}).Version
		cmds := make([][]byte, b.N)
		for i := range cmds {
			// Every applied command bumps rev by one, so the versions are known.
			cmds[i] = h.cmd(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, 0), Blob: blob, BaseVersion: ver + uint64(i), KeyEpoch: 1})
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			h.f.Apply(1, cmds[i])
		}
		b.StopTimer()
		if r, _ := DecodeResult(h.f.Apply(1, h.cmd(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, 0), Blob: blob, BaseVersion: ver + uint64(b.N), KeyEpoch: 1}))); r.Err != nil {
			b.Fatal("updates did not apply:", r.Err.Message)
		}
	})
	b.Run("delete_item", func(b *testing.B) {
		h, u := setup(b)
		cmds := make([][]byte, b.N)
		for i := range cmds {
			ver := h.mustOK(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, i), Blob: blob, KeyEpoch: 1}).Version
			cmds[i] = h.cmd(u, &DeleteItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, i), BaseVersion: ver})
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			h.f.Apply(1, cmds[i])
		}
	})
	b.Run("idempotent_hit", func(b *testing.B) {
		h, u := setup(b)
		cmd := h.cmd(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, 0), Blob: blob, KeyEpoch: 1})
		h.f.Apply(1, cmd)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			h.f.Apply(1, cmd)
		}
	})
	b.Run("conflict", func(b *testing.B) {
		// A refused command is still recorded (a miss in the table).
		h, u := setup(b)
		cmds := make([][]byte, b.N)
		for i := range cmds {
			cmds[i] = h.cmd(u, &PutItemArgs{VaultID: vaultID(1), ItemID: hexID(0xee, 0), Blob: blob, BaseVersion: 99, KeyEpoch: 1})
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := range b.N {
			h.f.Apply(1, cmds[i])
		}
	})
}

// BenchmarkSyncView measures building a user's sync view for a vault of n
// entries, and the "nothing changed" answer.
func BenchmarkSyncView(b *testing.B) {
	for _, n := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("full-%d", n), func(b *testing.B) {
			h := newHarness(b)
			u := h.bootstrap(1, "alice")
			for i := 0; i < n; i++ {
				h.mustOK(u, &PutItemArgs{VaultID: u.personal, ItemID: itemID(i * 7919 % 1_000_003), Blob: box(600), KeyEpoch: 1})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, ok := h.f.SyncView(u.id, 0); !ok {
					b.Fatal("no view")
				}
			}
		})
	}
	b.Run("unchanged", func(b *testing.B) {
		h := newHarness(b)
		u := h.bootstrap(1, "alice")
		rev := h.f.Rev()
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if r, _ := h.f.SyncView(u.id, rev); !r.Unchanged {
				b.Fatal("changed")
			}
		}
	})
}
