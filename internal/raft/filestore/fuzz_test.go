package filestore

import (
	"errors"
	"runtime"
	"testing"

	"github.com/tarnan3751/password-vault/internal/raft"
)

func fuzzSeedWALs() [][]byte {
	c := newWALCodec(42)
	one := c.appendRecord(nil, testEntries(1, 3, 1))
	two := c.appendRecord(nil, testEntries(2, 4, 2)) // conflict truncation
	big := c.appendRecord(nil, []raft.Entry{{Index: 6, Term: 2, Data: make([]byte, 3000)}})
	full := craftWAL(1, 42, one, two, big)
	return [][]byte{
		encodeWALHeader(1, 42),
		encodeWALHeader(101, 42),
		full,
		full[:len(full)-7],
		append(full, 0, 0, 0, 0, 0),
		craftWAL(1, 42, one, craftHeader(c, 0xffffffff, 0, 4, 1)),
		craftWAL(1, 42, one, craftHeader(c, 13, 0, 4, 0xffffffff)),
		nil,
		[]byte("PVWL"),
	}
}

// FuzzParseWAL feeds arbitrary bytes to the WAL decoder. It must never
// panic, must never allocate much more than the input (a hostile length
// field must not cause a huge allocation), and whatever it accepts must be
// a well-formed log.
func FuzzParseWAL(f *testing.F) {
	for _, b := range fuzzSeedWALs() {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		w, err := parseWAL(b, defaultLimits())
		runtime.ReadMemStats(&after)
		// Worst case is one 48-byte raft.Entry plus a 24-byte entryMeta per
		// 13 input bytes, doubled by slice growth: well under 16x.
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 16*uint64(len(b))+1<<20 {
			t.Fatalf("parsing %d bytes allocated %d bytes", len(b), alloc)
		}
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if w.end < walHeaderSize || w.end > int64(len(b)) || (!w.torn && w.end != int64(len(b))) {
			t.Fatalf("bad end %d (size %d, torn %v)", w.end, len(b), w.torn)
		}
		if len(w.metas) != len(w.entries) {
			t.Fatalf("index has %d entries, log %d", len(w.metas), len(w.entries))
		}
		for i := range w.entries {
			if w.entries[i].Index != w.first+uint64(i) || w.metas[i].term != w.entries[i].Term {
				t.Fatalf("malformed log at %d", i)
			}
			if m := w.metas[i]; m.recOff < walHeaderSize || m.recOff+m.recLen > w.end {
				t.Fatalf("index points outside the valid region: %+v", m)
			}
		}
		// Truncating at end must parse to the same log with no torn tail.
		if w.torn {
			w2, err := parseWAL(b[:w.end], defaultLimits())
			if err != nil || w2.torn || !sameEntries(w2.entries, w.entries) {
				t.Fatalf("repaired prefix does not parse to the same log: %v", err)
			}
		}
	})
}

// FuzzLoad runs Open+Load over arbitrary WAL, snapshot and hard state
// bytes. Load must not panic; if it succeeds its structural guarantees must
// hold and the store must keep working.
func FuzzLoad(f *testing.F) {
	snap := append(encodeSnapHeader(raft.SnapshotMeta{Index: 2, Term: 1}, []byte("sm")), "sm"...)
	hs := encodeHardState(raft.HardState{Term: 3, VotedFor: "pi"})
	for _, w := range fuzzSeedWALs() {
		f.Add(w, snap, hs)
		f.Add(w, []byte(nil), []byte(nil))
	}
	sf := newSnapFile(1, raft.SnapshotMeta{Index: 2, Term: 1})
	f.Fuzz(func(t *testing.T, wal, snapBytes, hsBytes []byte) {
		fsys := newMemFS(testDir)
		fsys.setFileData(walFileName, wal)
		if snapBytes != nil {
			fsys.setFileData(sf.name, snapBytes)
		}
		if hsBytes != nil {
			fsys.setFileData(hsFileName, hsBytes)
		}
		st, err := open(fsys, testDir, Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		_, sn, ents, err := st.Load()
		if err != nil {
			return
		}
		if err := checkStructure(sn, ents); err != nil {
			t.Fatal(err)
		}
		next := uint64(1)
		switch {
		case len(ents) > 0:
			next = ents[len(ents)-1].Index + 1
		case sn != nil:
			next = sn.Meta.Index + 1
		}
		e := []raft.Entry{{Index: next, Term: 1 << 40, Data: []byte("after fuzz")}}
		if err := st.Append(e); err != nil {
			t.Fatalf("append after a successful Load: %v", err)
		}
		st.Close()
		st, err = open(fsys, testDir, Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, ents2, err := st.Load()
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if len(ents2) == 0 || ents2[len(ents2)-1].Index != next {
			t.Fatalf("appended entry lost")
		}
	})
}
