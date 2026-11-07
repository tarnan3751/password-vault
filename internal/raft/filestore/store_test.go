package filestore

import (
	"bytes"
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// TestRoundTripRealFS drives the store through every operation on the real
// filesystem, with fsync enabled, reopening after each step and comparing
// with the model.
func TestRoundTripRealFS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	st, err := Open(dir, Options{})
	must(t, err)
	if hs, snap, ents, err := st.Load(); err != nil || hs != (raft.HardState{}) || snap != nil || len(ents) != 0 {
		t.Fatalf("fresh store: %+v %v %v %v", hs, snap, ents, err)
	}
	var m model
	steps := []op{
		{kind: opHardState, hs: raft.HardState{Term: 1, VotedFor: "pi"}},
		appendOp(1, 10, 1),
		appendOp(11, 5, 1),
		{kind: opHardState, hs: raft.HardState{Term: 2}},
		appendOp(8, 6, 2), // conflict truncation
		{kind: opSaveSnap, snap: testSnap(6, 1)},
		{kind: opCompact, through: 3},
		appendOp(14, 3, 2),
		{kind: opSaveSnap, snap: testSnap(12, 2)},
		{kind: opCompact, through: 12},
		{kind: opInstallSnap, snap: testSnap(40, 3)},
		appendOp(41, 4, 3),
		{kind: opInstallSnap, snap: testSnap(42, 3)}, // within the log, matching
		appendOp(43, 2, 4),
		{kind: opCompact, through: 42},
		{kind: opHardState, hs: raft.HardState{Term: 4, VotedFor: "laptop"}},
	}
	for _, o := range steps {
		if !m.valid(o, defaultLimits()) {
			t.Fatalf("test bug: %s invalid", o)
		}
		if err := o.run(st); err != nil {
			t.Fatalf("%s: %v", o, err)
		}
		m = m.apply(o)
		must(t, st.Close())
		st, err = Open(dir, Options{})
		must(t, err)
		hs, snap, ents, err := st.Load()
		must(t, err)
		if !equalState(m, hs, snap, ents) {
			t.Fatalf("after %s:\n got  %s\n want %s", o, model{hs, snap, ents}, m)
		}
	}
	must(t, st.Close())
	must(t, st.Close()) // idempotent
	if err := st.Append(testEntries(1, 1, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after close: %v", err)
	}
}

func TestLockExclusion(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(dir, Options{NoSync: true})
	must(t, err)
	if _, err := Open(dir, Options{NoSync: true}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: want ErrLocked, got %v", err)
	}
	must(t, a.Close())
	b, err := Open(dir, Options{NoSync: true})
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	must(t, b.Close())
}

func TestLargeEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~100 MiB")
	}
	dir := t.TempDir()
	st, err := Open(dir, Options{})
	must(t, err)
	_, _, _, err = st.Load()
	must(t, err)
	big := make([]byte, 48<<20)
	rng := rand.New(rand.NewPCG(1, 1))
	for i := 0; i < len(big); i += 8 {
		v := rng.Uint64()
		for j := 0; j < 8; j++ {
			big[i+j] = byte(v >> (8 * j))
		}
	}
	ents := []raft.Entry{{Index: 1, Term: 1, Data: []byte("small")}, {Index: 2, Term: 1, Data: big}, {Index: 3, Term: 1}}
	must(t, st.Append(ents))
	must(t, st.SaveSnapshot(raft.Snapshot{Meta: raft.SnapshotMeta{Index: 2, Term: 1}, Data: big}))
	must(t, st.Compact(1)) // copies the large entry into a new WAL
	must(t, st.Close())
	st, err = Open(dir, Options{})
	must(t, err)
	defer st.Close()
	_, snap, got, err := st.Load()
	must(t, err)
	if len(got) != 2 || !bytes.Equal(got[0].Data, big) || got[1].Index != 3 || !bytes.Equal(snap.Data, big) {
		t.Fatalf("large entry did not round-trip")
	}
}

func TestEntrySizeLimit(t *testing.T) {
	fsys := newMemFS(testDir)
	// A record fits one maximal entry plus a 1-byte one (1013 + 14 bytes).
	k := &knobs{lim: limits{maxEntry: 1000, maxRecord: 1000 + entHeaderSize + 14}}
	st, err := open(fsys, testDir, Options{}, k)
	must(t, err)
	_, _, _, err = st.Load()
	must(t, err)
	if err := st.Append([]raft.Entry{{Index: 1, Term: 1, Data: make([]byte, 1001)}}); !errors.Is(err, errInvalid) {
		t.Fatalf("oversized entry: %v", err)
	}
	// Exactly at the limit is fine, and a batch over the record limit is
	// split into several records.
	batch := []raft.Entry{{Index: 1, Term: 1, Data: make([]byte, 1000)}, {Index: 2, Term: 1, Data: make([]byte, 1000)}, {Index: 3, Term: 1, Data: []byte("x")}}
	s0 := fsys.steps
	must(t, st.Append(batch))
	if n := fsys.steps - s0; n != 4 {
		t.Fatalf("split append took %d I/O steps, want 2 records x (write+sync)", n)
	}
	must(t, st.Close())
	st, err = open(fsys, testDir, Options{}, k)
	must(t, err)
	_, _, got, err := st.Load()
	must(t, err)
	if !sameEntries(got, batch) {
		t.Fatalf("split append did not round-trip")
	}
}

// TestAppendIsOneWriteOneSync checks the group-commit property: one Append
// of many entries is exactly one write and one fsync.
func TestAppendIsOneWriteOneSync(t *testing.T) {
	fsys := newMemFS(testDir)
	st, err := open(fsys, testDir, Options{}, nil)
	must(t, err)
	_, _, _, err = st.Load()
	must(t, err)
	must(t, st.Append(testEntries(1, 10, 1)))
	fsys.trace = nil
	s0 := fsys.steps
	must(t, st.Append(testEntries(5, 200, 2))) // with conflict truncation
	if n := fsys.steps - s0; n != 2 || !strings.Contains(fsys.trace[0], "write wal") || !strings.Contains(fsys.trace[1], "sync wal") {
		t.Fatalf("append of 200 entries did %d I/O steps: %v", n, fsys.trace)
	}
	s0 = fsys.steps
	must(t, st.SaveHardState(raft.HardState{}))
	must(t, st.Append(nil))
	if fsys.steps != s0 {
		t.Fatalf("no-op calls performed I/O")
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	// No umask fiddling needed: a umask can only clear bits, and the store
	// already asks for no group/other bits.
	dir := filepath.Join(t.TempDir(), "vault")
	st, err := Open(dir, Options{NoSync: true})
	must(t, err)
	_, _, _, err = st.Load()
	must(t, err)
	must(t, st.SaveHardState(raft.HardState{Term: 1}))
	must(t, st.Append(testEntries(1, 5, 1)))
	must(t, st.SaveSnapshot(testSnap(3, 1)))
	must(t, st.Compact(3))
	must(t, st.InstallSnapshot(testSnap(9, 2)))
	must(t, st.Close())
	fi, err := os.Stat(dir)
	must(t, err)
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", fi.Mode().Perm())
	}
	n := 0
	must(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", d.Name(), fi.Mode().Perm())
		}
		return nil
	}))
	if n < 4 { // LOCK, wal, hardstate, snapshots
		t.Fatalf("only %d files", n)
	}
}

func TestOpenRemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	st, _, _, _ := openLoad(t, dir)
	must(t, st.Append(testEntries(1, 3, 1)))
	must(t, st.Close())
	for _, n := range []string{"wal.tmp", "hardstate.tmp", newSnapFile(9, raft.SnapshotMeta{Index: 1, Term: 1}).name + tmpSuffix} {
		writeF(t, dir, n, []byte("half-written"))
	}
	writeF(t, dir, "notes.txt", []byte("an operator's file is left alone"))
	st, _, _, ents := openLoad(t, dir)
	defer st.Close()
	if len(ents) != 3 {
		t.Fatalf("lost entries")
	}
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if strings.HasSuffix(de.Name(), tmpSuffix) {
			t.Errorf("%s not removed", de.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Errorf("unknown file removed")
	}
}

func TestValidation(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, Options{NoSync: true})
	must(t, err)
	defer st.Close()
	if err := st.Append(testEntries(1, 1, 1)); err == nil || errors.Is(err, errInvalid) {
		t.Fatalf("append before Load: %v", err)
	}
	_, _, _, err = st.Load()
	must(t, err)
	if _, _, _, err := st.Load(); err == nil {
		t.Fatalf("second Load succeeded")
	}
	bad := []struct {
		name string
		run  func() error
	}{
		{"gap", func() error { return st.Append(testEntries(2, 1, 1)) }},
		{"index 0", func() error { return st.Append(testEntries(0, 1, 1)) }},
		{"not contiguous", func() error { e := testEntries(1, 2, 1); e[1].Index = 3; return st.Append(e) }},
		{"compact without snapshot", func() error { return st.Compact(0) }},
		{"snapshot not in log", func() error { return st.SaveSnapshot(testSnap(1, 1)) }},
		{"votedFor too long", func() error {
			return st.SaveHardState(raft.HardState{Term: 1, VotedFor: strings.Repeat("x", maxVotedFor+1)})
		}},
	}
	for _, b := range bad {
		if err := b.run(); !errors.Is(err, errInvalid) {
			t.Errorf("%s: want errInvalid, got %v", b.name, err)
		}
	}
	// Rejected calls leave the store usable.
	must(t, st.Append(testEntries(1, 10, 1)))
	must(t, st.SaveSnapshot(testSnap(5, 1)))
	for _, b := range []struct {
		name string
		run  func() error
	}{
		{"compact past snapshot", func() error { return st.Compact(6) }},
		{"snapshot term mismatch", func() error { return st.SaveSnapshot(testSnap(7, 2)) }},
		{"trailing entries disagree with snapshot", func() error { return st.Append(testEntries(4, 3, 2)) }},
	} {
		if err := b.run(); !errors.Is(err, errInvalid) {
			t.Errorf("%s: want errInvalid, got %v", b.name, err)
		}
	}
	must(t, st.Compact(5))
	if err := st.InstallSnapshot(testSnap(3, 1)); !errors.Is(err, errInvalid) {
		t.Errorf("install snapshot older than the compacted log: %v", err)
	}
	must(t, st.Append(testEntries(11, 1, 1)))
}

// TestFailedSyncPoisonsStore checks that after an fsync failure the store
// refuses further work (a retried fsync could falsely report success), and
// that reopening recovers a valid state.
func TestFailedSyncPoisonsStore(t *testing.T) {
	for _, target := range []string{"append", "hardstate", "snapshot", "compact"} {
		t.Run(target, func(t *testing.T) {
			fsys := newMemFS(testDir)
			st, err := open(fsys, testDir, Options{}, nil)
			must(t, err)
			_, _, _, err = st.Load()
			must(t, err)
			must(t, st.Append(testEntries(1, 5, 1)))
			must(t, st.SaveSnapshot(testSnap(2, 1)))
			fsys.trace = nil
			var run func() error
			switch target {
			case "append":
				run = func() error { return st.Append(testEntries(6, 1, 1)) }
			case "hardstate":
				run = func() error { return st.SaveHardState(raft.HardState{Term: 3}) }
			case "snapshot":
				run = func() error { return st.SaveSnapshot(testSnap(4, 1)) }
			case "compact":
				run = func() error { return st.Compact(2) }
			}
			fsys.failNextSync = true // the operation's first fsync fails
			err = run()
			if !errors.Is(err, errInjected) {
				t.Fatalf("want the injected error, got %v (trace %v)", err, fsys.trace)
			}
			if err := st.Append(testEntries(6, 1, 1)); err == nil {
				t.Fatalf("store accepted work after a failed fsync")
			}
			st.Close()
			nfs := fsys.Crash(rand.New(rand.NewPCG(1, 2)), crashKeepNone)
			st, err = open(nfs, testDir, Options{}, nil)
			must(t, err)
			_, _, ents, err := st.Load()
			must(t, err)
			if len(ents) != 5 {
				t.Fatalf("lost acknowledged entries: have %d, want 5", len(ents))
			}
		})
	}
}
