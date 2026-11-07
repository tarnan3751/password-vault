package filestore

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// TestCrashRandomized runs long random sequences of Storage operations
// against the store on the fault-injecting filesystem and against the
// model, crashing (or failing an I/O call) at random steps, and after every
// crash checks that Load returns a state the contract allows: everything
// acknowledged, the in-flight operation all-or-nothing (with the contract's
// allowances), Load's structural guarantees, a clean disk, and a store that
// keeps working.
//
// Environment:
//
//	FILESTORE_CRASH_ITERS      number of seeds (default 2000; 100 with -short)
//	FILESTORE_CRASH_OPS        operations per seed (default 120)
//	FILESTORE_CRASH_BASE_SEED  first seed (default 1)
//	FILESTORE_CRASH_SEED       run only this seed (to replay a failure)
func TestCrashRandomized(t *testing.T) {
	nops := envInt("FILESTORE_CRASH_OPS", 120)
	if s := os.Getenv("FILESTORE_CRASH_SEED"); s != "" {
		seed, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("bad FILESTORE_CRASH_SEED: %v", err)
		}
		h := runCrashSeed(t, seed, nops)
		t.Logf("seed %d: %d ops, %d crashes, %d recovery crashes", seed, h.ops, h.crashes, h.recoveryCrashes)
		return
	}
	iters := envInt("FILESTORE_CRASH_ITERS", 2000)
	if testing.Short() {
		iters = min(iters, 100)
	}
	base := uint64(envInt("FILESTORE_CRASH_BASE_SEED", 1))
	workers := min(runtime.GOMAXPROCS(0), max(iters, 1))

	var mu sync.Mutex
	var ops, crashes, recCrashes, injected, invalid int
	hits := map[string]int{}
	start := time.Now()
	t.Run("seeds", func(t *testing.T) {
		for w := 0; w < workers; w++ {
			t.Run(fmt.Sprintf("worker%d", w), func(t *testing.T) {
				t.Parallel()
				for i := w; i < iters; i += workers {
					h := runCrashSeed(t, base+uint64(i), nops)
					mu.Lock()
					ops += h.ops
					crashes += h.crashes
					recCrashes += h.recoveryCrashes
					injected += h.injected
					invalid += h.invalid
					for k, v := range h.outcomeHits {
						hits[k] += v
					}
					mu.Unlock()
				}
			})
		}
	})
	t.Logf("seeds %d..%d (%d), %d ops, %d crashes + %d crashes during recovery, %d injected I/O errors, %d invalid ops rejected, in %v",
		base, base+uint64(iters)-1, iters, ops, crashes, recCrashes, injected, invalid, time.Since(start).Round(time.Millisecond))
	for _, k := range slices.Sorted(maps.Keys(hits)) {
		t.Logf("  in-flight outcome %-24s %d", k, hits[k])
	}
}

// ---------------------------------------------------------------------------
// Systematic crash-point enumeration
// ---------------------------------------------------------------------------

func testEntries(start uint64, n int, term uint64) []raft.Entry {
	es := make([]raft.Entry, n)
	for i := range es {
		idx := start + uint64(i)
		data := []byte(fmt.Sprintf("entry %d term %d %s", idx, term, string(make([]byte, int(idx%7)*9))))
		es[i] = raft.Entry{Index: idx, Term: term, Type: raft.EntryType(idx % 2), Data: data}
	}
	return es
}

func testSnap(i, t uint64) raft.Snapshot {
	return raft.Snapshot{Meta: raft.SnapshotMeta{Index: i, Term: t}, Data: []byte(fmt.Sprintf("state machine through %d/%d", i, t))}
}

type enumScenario struct {
	name  string
	small bool // tiny record limit, to force multi-record appends
	setup []op
	op    op
}

func appendOp(start uint64, n int, term uint64) op {
	return op{kind: opAppend, entries: testEntries(start, n, term)}
}

var enumScenarios = []enumScenario{
	{name: "hardstate-first", op: op{kind: opHardState, hs: raft.HardState{Term: 1, VotedFor: "pi"}}},
	{name: "hardstate-replace",
		setup: []op{{kind: opHardState, hs: raft.HardState{Term: 1, VotedFor: "pi"}}},
		op:    op{kind: opHardState, hs: raft.HardState{Term: 2}}},
	{name: "append-first", op: appendOp(1, 3, 1)},
	{name: "append-end", setup: []op{appendOp(1, 5, 1)}, op: appendOp(6, 3, 1)},
	{name: "append-conflict-middle", setup: []op{appendOp(1, 8, 1)}, op: appendOp(4, 3, 2)},
	{name: "append-conflict-all", setup: []op{appendOp(1, 8, 1)}, op: appendOp(1, 2, 2)},
	{name: "append-conflict-longer", setup: []op{appendOp(1, 4, 1), appendOp(5, 4, 1)}, op: appendOp(3, 9, 3)},
	{name: "append-multi-record", small: true, setup: []op{appendOp(1, 4, 1)}, op: appendOp(3, 12, 2)},
	{name: "append-trailing-before-compacted",
		setup: []op{appendOp(1, 14, 1), {kind: opSaveSnap, snap: testSnap(10, 1)}, {kind: opCompact, through: 10}},
		op:    op{kind: opAppend, entries: testEntries(8, 5, 1)}},
	{name: "savesnap-first", setup: []op{appendOp(1, 10, 1)}, op: op{kind: opSaveSnap, snap: testSnap(5, 1)}},
	{name: "savesnap-prunes-old",
		setup: []op{appendOp(1, 10, 1), {kind: opSaveSnap, snap: testSnap(3, 1)}, {kind: opSaveSnap, snap: testSnap(5, 1)}},
		op:    op{kind: opSaveSnap, snap: testSnap(8, 1)}},
	{name: "install-ahead", setup: []op{appendOp(1, 5, 1)}, op: op{kind: opInstallSnap, snap: testSnap(20, 3)}},
	{name: "install-within-matching", setup: []op{appendOp(1, 10, 1)}, op: op{kind: opInstallSnap, snap: testSnap(5, 1)}},
	{name: "install-within-conflicting", setup: []op{appendOp(1, 10, 1)}, op: op{kind: opInstallSnap, snap: testSnap(5, 2)}},
	{name: "install-after-compaction",
		setup: []op{appendOp(1, 10, 1), {kind: opSaveSnap, snap: testSnap(5, 1)}, {kind: opCompact, through: 5}},
		op:    op{kind: opInstallSnap, snap: testSnap(30, 4)}},
	{name: "compact-partial", setup: []op{appendOp(1, 10, 1), {kind: opSaveSnap, snap: testSnap(6, 1)}}, op: op{kind: opCompact, through: 4}},
	{name: "compact-all", setup: []op{appendOp(1, 10, 1), {kind: opSaveSnap, snap: testSnap(10, 1)}}, op: op{kind: opCompact, through: 10}},
	{name: "compact-across-truncated-records",
		setup: []op{appendOp(1, 6, 1), appendOp(4, 6, 2), appendOp(8, 4, 3), {kind: opSaveSnap, snap: testSnap(9, 3)}},
		op:    op{kind: opCompact, through: 5}},
}

// enumKnobs gives deterministic salts so every rebuild of a scenario
// performs exactly the same I/O.
func enumKnobs(small bool) *knobs {
	var n uint64
	k := &knobs{salt: func() uint64 { n++; return n * 0x9e3779b97f4a7c15 }, lim: limits{maxEntry: 4096, maxRecord: 4096 + entHeaderSize + 4096}}
	if small {
		k.lim = limits{maxEntry: 100, maxRecord: 100 + entHeaderSize + 40}
	}
	return k
}

func buildScenario(t *testing.T, sc enumScenario) (*memFS, *Store, model, *knobs) {
	t.Helper()
	fs := newMemFS(testDir)
	k := enumKnobs(sc.small)
	st, err := open(fs, testDir, Options{}, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.Load(); err != nil {
		t.Fatal(err)
	}
	var m model
	for _, o := range sc.setup {
		if !m.valid(o, k.lim) {
			t.Fatalf("scenario setup op %s is invalid", o)
		}
		if err := o.run(st); err != nil {
			t.Fatalf("setup %s: %v", o, err)
		}
		m = m.apply(o)
	}
	return fs, st, m, k
}

func TestCrashEnumeration(t *testing.T) {
	modes := []crashMode{crashKeepNone, crashKeepAll, crashRandom, crashRandom, crashRandom, crashRandom, crashRandom, crashRandom}
	for _, sc := range enumScenarios {
		t.Run(sc.name, func(t *testing.T) {
			fs, st, m, _ := buildScenario(t, sc)
			if !m.valid(sc.op, enumKnobs(sc.small).lim) {
				t.Fatalf("scenario op %s is invalid", sc.op)
			}
			s0 := fs.steps
			if err := sc.op.run(st); err != nil {
				t.Fatalf("%s without a crash: %v", sc.op, err)
			}
			nsteps := fs.steps - s0
			if nsteps == 0 {
				t.Fatalf("%s performed no I/O", sc.op)
			}
			rng := rand.New(rand.NewPCG(uint64(len(sc.name)), 7))
			seen := map[int]int{}
			runs := 0
			for i := 1; i <= nsteps; i++ {
				for _, perform := range []bool{false, true} {
					for _, mode := range modes {
						fs, st, m, k := buildScenario(t, sc)
						fs.crashAt, fs.crashPerform = fs.steps+i, perform
						err := sc.op.run(st)
						var outcomes []model
						switch {
						case err == nil:
							outcomes = []model{m.apply(sc.op)}
						case errors.Is(err, errCrashed):
							outcomes = m.crashOutcomes(sc.op)
						default:
							t.Fatalf("crash at step %d: unexpected error %v", i, err)
						}
						st.Close()
						h := &harness{t: t, rng: rng, fs: fs.Crash(rng, mode), k: k, g: &gen{rng: rng, lim: k.lim}}
						h.where = fmt.Sprintf("%s: crash at step %d of %d (performed=%v, %v)", sc.op, i, nsteps, perform, mode)
						got := h.open(outcomes, false)
						if err == nil {
							got = 1 // the only outcome is the new state
						}
						seen[min(got, 2)]++
						runs++

						// The store keeps working after recovery.
						h.where += ", then continuing"
						more := appendOp(h.m.next(), 2, 50)
						if err := more.run(h.st); err != nil {
							h.fatalf("append after recovery: %v", err)
						}
						h.m = h.m.apply(more)
						hs := op{kind: opHardState, hs: raft.HardState{Term: 50, VotedFor: "vps"}}
						if err := hs.run(h.st); err != nil {
							h.fatalf("save hard state after recovery: %v", err)
						}
						h.m = h.m.apply(hs)
						h.cleanRestart()
						h.st.Close()
					}
				}
			}
			t.Logf("%s: %d I/O steps, %d crash runs; recovered old=%d new=%d partial=%d",
				sc.op, nsteps, runs, seen[0], seen[1], seen[2])
			// Sanity: the enumeration must actually straddle the commit
			// point, otherwise it is not testing anything.
			if seen[0] == 0 || seen[1] == 0 {
				t.Errorf("crash enumeration never observed both the old and the new state (old=%d new=%d)", seen[0], seen[1])
			}
		})
	}
}

// TestCrashDuringRecovery enumerates crash points inside Load's own repairs
// (creating the WAL in a new directory, truncating a torn tail, discarding
// a log after an interrupted InstallSnapshot): a second Load must return
// the same state.
func TestCrashDuringRecovery(t *testing.T) {
	type prep func(t *testing.T) (*memFS, *knobs, model)

	fresh := func(t *testing.T) (*memFS, *knobs, model) {
		return newMemFS(testDir), enumKnobs(false), model{}
	}
	torn := func(t *testing.T) (*memFS, *knobs, model) {
		fs, st, m, k := buildScenario(t, enumScenario{setup: []op{appendOp(1, 5, 1), {kind: opHardState, hs: raft.HardState{Term: 1}}}})
		st.Close()
		b, _ := fs.fileData(walFileName)
		w, err := parseWAL(b, k.lim)
		if err != nil {
			t.Fatal(err)
		}
		rec := newWALCodec(w.salt).appendRecord(nil, testEntries(6, 3, 1))
		fs.setFileData(walFileName, append(b, rec[:len(rec)-5]...)) // torn final record
		return fs, k, m
	}
	discard := func(t *testing.T) (*memFS, *knobs, model) {
		fs, st, m, k := buildScenario(t, enumScenario{setup: []op{appendOp(1, 5, 1)}})
		// Crash InstallSnapshot right after the snapshot is durable, before
		// the WAL is replaced.
		o := op{kind: opInstallSnap, snap: testSnap(20, 3)}
		fs.crashAt = fs.steps + 6 // create, write hdr, write data, sync, rename, syncdir: crash at syncdir
		fs.crashPerform = true
		if err := o.run(st); !errors.Is(err, errCrashed) {
			t.Fatalf("expected crash, got %v", err)
		}
		st.Close()
		fs = fs.Crash(nil, crashKeepAll)
		names := fs.names()
		if !slices.Contains(names, newSnapFile(1, o.snap.Meta).name) {
			t.Fatalf("setup did not leave the new snapshot: %v", names)
		}
		s := o.snap
		m.snap, m.log = &s, nil
		return fs, k, m
	}

	for _, tc := range []struct {
		name string
		prep prep
	}{{"fresh-directory", fresh}, {"torn-tail", torn}, {"discard-after-install", discard}} {
		t.Run(tc.name, func(t *testing.T) {
			fs, k, m := tc.prep(t)
			s0 := fs.steps
			h := &harness{t: t, rng: rand.New(rand.NewPCG(1, 2)), fs: fs, k: k}
			h.where = "load without crash"
			h.open([]model{m}, false)
			h.st.Close()
			nsteps := fs.steps - s0
			if nsteps == 0 {
				t.Fatalf("recovery performed no I/O")
			}
			rng := rand.New(rand.NewPCG(3, 4))
			for i := 1; i <= nsteps; i++ {
				for _, perform := range []bool{false, true} {
					for _, mode := range []crashMode{crashKeepNone, crashKeepAll, crashRandom, crashRandom, crashRandom} {
						fs, k, m := tc.prep(t)
						fs.crashAt, fs.crashPerform = fs.steps+i, perform
						st, err := open(fs, testDir, Options{}, k)
						if err == nil {
							_, _, _, err = st.Load()
							st.Close()
						}
						if !errors.Is(err, errCrashed) {
							t.Fatalf("step %d: expected a crash, got %v", i, err)
						}
						h := &harness{t: t, rng: rng, fs: fs.Crash(rng, mode), k: k}
						h.where = fmt.Sprintf("crash at recovery step %d of %d (performed=%v, %v)", i, nsteps, perform, mode)
						h.open([]model{m}, false)
						h.st.Close()
					}
				}
			}
			t.Logf("%d recovery I/O steps enumerated", nsteps)
		})
	}
}
