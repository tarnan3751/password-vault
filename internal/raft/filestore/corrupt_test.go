package filestore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// Helpers shared by the real-filesystem tests.

func openLoad(t *testing.T, dir string) (*Store, raft.HardState, *raft.Snapshot, []raft.Entry) {
	t.Helper()
	st, err := Open(dir, Options{NoSync: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	hs, snap, ents, err := st.Load()
	if err != nil {
		st.Close()
		t.Fatalf("load: %v", err)
	}
	if err := checkStructure(snap, ents); err != nil {
		t.Fatalf("structure: %v", err)
	}
	return st, hs, snap, ents
}

// loadErr opens dir and returns Load's error (which must be non-nil).
func loadErr(t *testing.T, dir string) error {
	t.Helper()
	st, err := Open(dir, Options{NoSync: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	_, _, _, err = st.Load()
	if err == nil {
		t.Fatalf("Load succeeded on damaged data")
	}
	if !errors.Is(st.Append(testEntries(1, 1, 1)), err) {
		t.Fatalf("store usable after a failed Load")
	}
	return err
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func readF(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	must(t, err)
	return b
}

func writeF(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(dir, name), b, 0o600))
}

func sameEntries(a, b []raft.Entry) bool {
	return slices.EqualFunc(a, b, func(x, y raft.Entry) bool {
		return x.Index == y.Index && x.Term == y.Term && x.Type == y.Type && bytes.Equal(x.Data, y.Data)
	})
}

// buildLog writes n single-entry appends and returns the WAL record offsets
// (and the end of the file as the last element).
func buildLog(t *testing.T, dir string, n int) ([]raft.Entry, []int64) {
	t.Helper()
	st, _, _, _ := openLoad(t, dir)
	var all []raft.Entry
	offs := []int64{walHeaderSize}
	for i := 1; i <= n; i++ {
		e := testEntries(uint64(i), 1, 1)
		e[0].Data = bytes.Repeat([]byte{byte(i)}, 40+i)
		must(t, st.Append(e))
		all = append(all, e...)
		offs = append(offs, st.walEnd)
	}
	must(t, st.Close())
	return all, offs
}

func TestCorruptionInMiddleOfWALIsAnError(t *testing.T) {
	base := t.TempDir()
	_, offs := buildLog(t, base, 10)
	orig := readF(t, base, walFileName)
	r3 := offs[2] // third record
	cases := []struct {
		name string
		at   int64
		bit  byte
	}{
		{"payload byte", r3 + recHeaderSize + 20, 0x10},
		{"payload crc", r3 + 4, 0x01},
		{"length field", r3 + 1, 0x40},
		{"length field high bit", r3 + 3, 0x80},
		{"index field", r3 + 8, 0x02},
		{"header crc", r3 + 25, 0x08},
		{"first record", offs[0] + recHeaderSize + 3, 0x01},
		{"second-to-last record", offs[8] + recHeaderSize + 1, 0x04},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := slices.Clone(orig)
			b[tc.at] ^= tc.bit
			writeF(t, dir, walFileName, b)
			err := loadErr(t, dir)
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "offset") {
				t.Fatalf("want a corruption error naming the offset, got %v", err)
			}
			t.Logf("%v", err)
			if !bytes.Equal(readF(t, dir, walFileName), b) {
				t.Fatalf("Load modified a corrupt WAL")
			}
		})
	}
}

func TestTornTailIsDroppedAndRepaired(t *testing.T) {
	base := t.TempDir()
	all, offs := buildLog(t, base, 5)
	orig := readF(t, base, walFileName)
	last := offs[4] // start of the 5th (last) record
	check := func(t *testing.T, dir string, wantN int) {
		t.Helper()
		st, _, _, ents := openLoad(t, dir)
		if !sameEntries(ents, all[:wantN]) {
			t.Fatalf("got %d entries, want the first %d", len(ents), wantN)
		}
		if fi, _ := os.Stat(filepath.Join(dir, walFileName)); fi.Size() != offs[wantN] {
			t.Fatalf("wal not repaired: size %d, want %d", fi.Size(), offs[wantN])
		}
		// New appends go right after the last valid record and survive.
		e := testEntries(uint64(wantN+1), 2, 2)
		must(t, st.Append(e))
		must(t, st.Close())
		st, _, _, ents = openLoad(t, dir)
		defer st.Close()
		if !sameEntries(ents, append(slices.Clone(all[:wantN]), e...)) {
			t.Fatalf("append after repair not durable")
		}
	}
	t.Run("every truncation point of the last record", func(t *testing.T) {
		for cut := last; cut < int64(len(orig)); cut++ {
			dir := t.TempDir()
			writeF(t, dir, walFileName, orig[:cut])
			check(t, dir, 4)
		}
	})
	t.Run("garbage after the last record", func(t *testing.T) {
		for _, g := range [][]byte{make([]byte, 1), make([]byte, 27), make([]byte, 4096), []byte("\x01\x00\x00\x00garbage that is not a record header at all"), bytes.Repeat([]byte{0xff}, 100)} {
			dir := t.TempDir()
			writeF(t, dir, walFileName, append(slices.Clone(orig), g...))
			check(t, dir, 5)
		}
	})
	t.Run("torn record followed by zeros", func(t *testing.T) {
		dir := t.TempDir()
		b := slices.Clone(orig[:last+recHeaderSize+10])
		b = append(b, make([]byte, 200)...) // size reached the disk, data did not
		writeF(t, dir, walFileName, b)
		check(t, dir, 4)
	})
	t.Run("checksum failure in the last record with nothing after it", func(t *testing.T) {
		// Indistinguishable from a torn write, so it is dropped (see the
		// report: this is the one case where media damage to the newest
		// record is not reported).
		for _, at := range []int64{last + 2, last + recHeaderSize + 5, int64(len(orig)) - 1} {
			dir := t.TempDir()
			b := slices.Clone(orig)
			b[at] ^= 0x20
			writeF(t, dir, walFileName, b)
			check(t, dir, 4)
		}
	})
}

func craftWAL(base, salt uint64, records ...[]byte) []byte {
	b := encodeWALHeader(base, salt)
	for _, r := range records {
		b = append(b, r...)
	}
	return b
}

// craftHeader builds an authentic (correctly salted) record header with
// arbitrary fields.
func craftHeader(c walCodec, plen, pcrc uint32, first uint64, count uint32) []byte {
	h := make([]byte, recHeaderSize)
	binary.LittleEndian.PutUint32(h[0:], plen)
	binary.LittleEndian.PutUint32(h[4:], pcrc)
	binary.LittleEndian.PutUint64(h[8:], first)
	binary.LittleEndian.PutUint32(h[16:], count)
	h[20] = recKindEntries
	binary.LittleEndian.PutUint32(h[24:], c.headerCRC(h))
	return h
}

func TestHostileLengthFields(t *testing.T) {
	const salt = 0x1234
	c := newWALCodec(salt)
	good := c.appendRecord(nil, testEntries(1, 2, 1))
	lim := defaultLimits()
	cases := []struct {
		name    string
		wal     []byte
		corrupt bool // else: parses with the good record only (torn tail)
	}{
		{"authentic header, huge payload length", craftWAL(1, salt, good, craftHeader(c, 0xffffffff, 0, 3, 1)), true},
		{"authentic header, payload just over the limit", craftWAL(1, salt, good, craftHeader(c, uint32(lim.maxRecord+1), 0, 3, 1)), true},
		{"authentic header, huge count", craftWAL(1, salt, good, craftHeader(c, 13, 0, 3, 0xffffffff)), true},
		{"authentic header, zero count", craftWAL(1, salt, good, craftHeader(c, 13, 0, 3, 0)), true},
		{"authentic header, index 0", craftWAL(1, salt, good, craftHeader(c, 13, 0, 0, 1)), true},
		{"authentic header, index overflow", craftWAL(1, salt, good, craftHeader(c, 26, 0, ^uint64(0), 2)), true},
		{"authentic header, gap", craftWAL(1, salt, good, c.appendRecord(nil, testEntries(5, 1, 1))), true},
		{"unauthentic header, huge length, nothing after", craftWAL(1, salt, good, []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4}), false},
		{"header with the wrong salt", craftWAL(1, salt, good, newWALCodec(salt+1).appendRecord(nil, testEntries(3, 1, 1))), false},
	}
	// An authentic record whose entry data length lies (payload CRC valid).
	p := binary.LittleEndian.AppendUint64(nil, 1)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, 0xfffffff0)
	cases = append(cases, struct {
		name    string
		wal     []byte
		corrupt bool
	}{"authentic record, hostile entry length", craftWAL(1, salt, good, append(craftHeader(c, uint32(len(p)), crc32c(p), 3, 1), p...)), true})
	// An authentic record with bytes left over after its last entry.
	stray := append(binary.LittleEndian.AppendUint64(nil, 1), 0, 0, 0, 0, 0, 0xAA, 0xBB)
	cases = append(cases, struct {
		name    string
		wal     []byte
		corrupt bool
	}{"authentic record, stray bytes after last entry", craftWAL(1, salt, good, append(craftHeader(c, uint32(len(stray)), crc32c(stray), 3, 1), stray...)), true})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := parseWAL(tc.wal, lim)
			if tc.corrupt {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("want corruption, got %v", err)
				}
				return
			}
			if err != nil || !w.torn || len(w.entries) != 2 {
				t.Fatalf("want 2 entries and a torn tail, got err=%v torn=%v n=%d", err, w != nil && w.torn, len(w.entries))
			}
		})
	}
}

// TestForgedHeaderInEntryData: entry data comes from vault clients, so it
// can contain bytes that look exactly like a WAL record. If a crash tears
// the write of such an entry, the torn-tail scan must not mistake the fake
// record for a real one (which would make the node refuse to start). The
// per-file salt in the header CRC is what prevents that.
func TestForgedHeaderInEntryData(t *testing.T) {
	const salt = 0x5eed
	c := newWALCodec(salt)
	prefix := craftWAL(1, salt, c.appendRecord(nil, testEntries(1, 2, 1)))
	for _, tc := range []struct {
		name      string
		forger    walCodec
		wantTorn  bool
		wantError bool
	}{
		{"attacker does not know the salt", newWALCodec(0), true, false},
		{"attacker somehow knows the salt", c, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.forger.appendRecord(nil, testEntries(4, 1, 1))
			data := append(bytes.Repeat([]byte("x"), 50), fake...)
			rec := c.appendRecord(nil, []raft.Entry{{Index: 3, Term: 1, Data: data}})
			// Torn: the record's tail (after the embedded fake) is missing.
			b := append(slices.Clone(prefix), rec[:len(rec)-3]...)
			w, err := parseWAL(b, defaultLimits())
			if tc.wantError {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("want corruption, got %v", err)
				}
				return
			}
			if err != nil || !w.torn || len(w.entries) != 2 {
				t.Fatalf("want a torn tail after 2 entries, got err=%v", err)
			}
		})
	}
}

func TestBadWALHeader(t *testing.T) {
	base := t.TempDir()
	buildLog(t, base, 3)
	orig := readF(t, base, walFileName)
	fix := func(b []byte) []byte { // recompute the header CRC
		binary.LittleEndian.PutUint32(b[24:28], crc32c(b[:24]))
		return b
	}
	cases := []struct {
		name string
		mut  func([]byte) []byte
		want error
	}{
		{"bad magic", func(b []byte) []byte { b[0] = 'X'; return fix(b) }, ErrCorrupt},
		{"newer version", func(b []byte) []byte { b[4] = 2; return fix(b) }, ErrUnsupportedVersion},
		{"header checksum", func(b []byte) []byte { b[10] ^= 1; return b }, ErrCorrupt},
		{"base 0", func(b []byte) []byte { clear(b[8:16]); return fix(b) }, ErrCorrupt},
		{"short header", func(b []byte) []byte { return b[:walHeaderSize-1] }, ErrCorrupt},
		{"empty file", func(b []byte) []byte { return nil }, ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := tc.mut(slices.Clone(orig))
			writeF(t, dir, walFileName, b)
			if err := loadErr(t, dir); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if !bytes.Equal(readF(t, dir, walFileName), b) {
				t.Fatalf("Load modified a WAL with a bad header")
			}
		})
	}
}

// TestCompactionDoesNotLaunderCorruption: bit rot that appears after Load
// in a record Compact must copy is reported, not rewritten under a fresh
// checksum, and the old WAL is left in place.
func TestCompactionDoesNotLaunderCorruption(t *testing.T) {
	dir := t.TempDir()
	st, _, _, _ := openLoad(t, dir)
	for i := uint64(1); i <= 6; i++ {
		must(t, st.Append(testEntries(i, 1, 1)))
	}
	must(t, st.SaveSnapshot(testSnap(2, 1)))
	b := readF(t, dir, walFileName)
	b[st.ents[5-st.first].recOff+recHeaderSize+2] ^= 0x01 // entry 5's record
	writeF(t, dir, walFileName, b)                        // same inode, so the open store sees it
	if err := st.Compact(2); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("compact over a corrupt record: %v", err)
	}
	if err := st.Append(testEntries(7, 1, 1)); err == nil {
		t.Fatalf("store still usable after detecting corruption")
	}
	st.Close()
	if !bytes.Equal(readF(t, dir, walFileName), b) {
		t.Fatalf("WAL was replaced despite the corruption")
	}
	if _, err := os.Stat(filepath.Join(dir, walFileName+tmpSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file left behind: %v", err)
	}
	if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load: %v", err)
	}
}

func TestCorruptHardState(t *testing.T) {
	base := t.TempDir()
	st, _, _, _ := openLoad(t, base)
	must(t, st.SaveHardState(raft.HardState{Term: 7, VotedFor: "laptop"}))
	must(t, st.Close())
	orig := readF(t, base, hsFileName)
	for i := range orig {
		dir := t.TempDir()
		writeF(t, dir, walFileName, readF(t, base, walFileName))
		b := slices.Clone(orig)
		b[i] ^= 0x01
		writeF(t, dir, hsFileName, b)
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("flip at %d: got %v", i, err)
		}
	}
	dir := t.TempDir()
	writeF(t, dir, walFileName, readF(t, base, walFileName))
	writeF(t, dir, hsFileName, orig[:len(orig)-1])
	if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated hardstate: got %v", err)
	}
}

func TestMissingFiles(t *testing.T) {
	t.Run("wal missing next to other state", func(t *testing.T) {
		dir := t.TempDir()
		st, _, _, _ := openLoad(t, dir)
		must(t, st.SaveHardState(raft.HardState{Term: 1}))
		must(t, st.Close())
		must(t, os.Remove(filepath.Join(dir, walFileName)))
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("snapshot missing behind a compacted log", func(t *testing.T) {
		dir := t.TempDir()
		st, _, _, _ := openLoad(t, dir)
		must(t, st.Append(testEntries(1, 10, 1)))
		must(t, st.SaveSnapshot(testSnap(5, 1)))
		must(t, st.Compact(5))
		must(t, st.Close())
		must(t, os.Remove(filepath.Join(dir, newSnapFile(1, raft.SnapshotMeta{Index: 5, Term: 1}).name)))
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "no snapshot") {
			t.Fatalf("got %v", err)
		}
	})
}

// snapshotFixture builds a log 1..30 (term 1) with snapshots at 10 and 20
// (seq 1 and 2), compacted through compactThrough (0 = not compacted).
func snapshotFixture(t *testing.T, compactThrough uint64) (string, []raft.Entry) {
	t.Helper()
	dir := t.TempDir()
	st, _, _, _ := openLoad(t, dir)
	all := testEntries(1, 30, 1)
	must(t, st.Append(all))
	must(t, st.SaveSnapshot(testSnap(10, 1)))
	must(t, st.SaveSnapshot(testSnap(20, 1)))
	if compactThrough > 0 {
		must(t, st.Compact(compactThrough))
	}
	must(t, st.Close())
	return dir, all
}

func damageSnapshot(t *testing.T, dir string, seq, index, term uint64, at int) {
	t.Helper()
	name := newSnapFile(seq, raft.SnapshotMeta{Index: index, Term: term}).name
	b := readF(t, dir, name)
	if at < 0 {
		at += len(b)
	}
	b[at] ^= 0x01
	writeF(t, dir, name, b)
}

func TestCorruptSnapshot(t *testing.T) {
	t.Run("falls back when the log still covers the corrupt snapshot", func(t *testing.T) {
		dir, all := snapshotFixture(t, 5) // log 6..30 still covers 11..20
		damageSnapshot(t, dir, 2, 20, 1, -1)
		st, _, snap, ents := openLoad(t, dir)
		if snap == nil || snap.Meta.Index != 10 || !sameEntries(ents, all[5:]) {
			t.Fatalf("got snap %+v and %d entries", snap, len(ents))
		}
		if len(st.recovery.fellBackFrom) != 1 {
			t.Fatalf("fallback not recorded")
		}
		// The next snapshot deletes the corrupt one and keeps the one in use.
		must(t, st.SaveSnapshot(testSnap(25, 1)))
		must(t, st.Close())
		var snaps []string
		des, _ := os.ReadDir(dir)
		for _, de := range des {
			if strings.HasSuffix(de.Name(), snapSuffix) {
				snaps = append(snaps, de.Name())
			}
		}
		want := []string{newSnapFile(1, raft.SnapshotMeta{Index: 10, Term: 1}).name, newSnapFile(3, raft.SnapshotMeta{Index: 25, Term: 1}).name}
		if !slices.Equal(snaps, want) {
			t.Fatalf("snapshot files %v, want %v", snaps, want)
		}
		st, _, snap, _ = openLoad(t, dir)
		defer st.Close()
		if snap.Meta.Index != 25 || len(st.recovery.fellBackFrom) != 0 {
			t.Fatalf("got %+v", snap.Meta)
		}
	})
	t.Run("refuses when the log no longer continues the older snapshot", func(t *testing.T) {
		dir, _ := snapshotFixture(t, 15) // log 16..30: replaying from 10 is impossible
		damageSnapshot(t, dir, 2, 20, 1, snapHeaderSize+3)
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "does not continue") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("refuses when the log lacks the corrupt snapshot's last entry", func(t *testing.T) {
		dir, _ := snapshotFixture(t, 0)
		// A newer snapshot whose position (index 25, term 9) the log does
		// not contain: the node might have acknowledged state the log
		// cannot rebuild.
		writeF(t, dir, newSnapFile(3, raft.SnapshotMeta{Index: 25, Term: 9}).name, []byte("garbage"))
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "no longer holds") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("refuses after InstallSnapshot discarded the log", func(t *testing.T) {
		dir, _ := snapshotFixture(t, 0)
		st, _, _, _ := openLoad(t, dir)
		must(t, st.InstallSnapshot(testSnap(50, 2)))
		must(t, st.Close())
		damageSnapshot(t, dir, 3, 50, 2, snapHeaderSize)
		if err := loadErr(t, dir); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("only snapshot corrupt but the log from index 1 covers it", func(t *testing.T) {
		dir := t.TempDir()
		st, _, _, _ := openLoad(t, dir)
		all := testEntries(1, 12, 1)
		must(t, st.Append(all))
		must(t, st.SaveSnapshot(testSnap(8, 1)))
		must(t, st.Close())
		damageSnapshot(t, dir, 1, 8, 1, 0)
		st, _, snap, ents := openLoad(t, dir)
		defer st.Close()
		if snap != nil || !sameEntries(ents, all) {
			t.Fatalf("want no snapshot and the full log, got %+v / %d entries", snap, len(ents))
		}
	})
	t.Run("newer format version is not treated as corruption", func(t *testing.T) {
		dir, _ := snapshotFixture(t, 5)
		name := newSnapFile(2, raft.SnapshotMeta{Index: 20, Term: 1}).name
		b := readF(t, dir, name)
		b[4] = 9
		binary.LittleEndian.PutUint32(b[36:40], crc32c(b[:36]))
		writeF(t, dir, name, b)
		if err := loadErr(t, dir); !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("damage anywhere in the file is detected", func(t *testing.T) {
		dir, _ := snapshotFixture(t, 15)
		name := newSnapFile(2, raft.SnapshotMeta{Index: 20, Term: 1}).name
		orig := readF(t, dir, name)
		for i := range orig {
			b := slices.Clone(orig)
			b[i] ^= 0x80
			if _, err := decodeSnapshot(b, snapFile{name: name, seq: 2, meta: raft.SnapshotMeta{Index: 20, Term: 1}}); !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("flip at byte %d not detected: %v", i, err)
			}
		}
		for _, n := range []int{0, 1, snapHeaderSize - 1, snapHeaderSize, len(orig) - 1} {
			if _, err := decodeSnapshot(orig[:n], snapFile{name: name, seq: 2, meta: raft.SnapshotMeta{Index: 20, Term: 1}}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("truncation to %d not detected: %v", n, err)
			}
		}
		if _, err := decodeSnapshot(append(slices.Clone(orig), 0), snapFile{name: name, seq: 2, meta: raft.SnapshotMeta{Index: 20, Term: 1}}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("trailing byte not detected: %v", err)
		}
		// A header whose length field disagrees with the file, everything
		// else (both CRCs) consistent.
		lied := slices.Clone(orig)
		binary.LittleEndian.PutUint64(lied[24:32], uint64(len(orig)-snapHeaderSize-1))
		binary.LittleEndian.PutUint32(lied[36:40], crc32c(lied[:36]))
		if _, err := decodeSnapshot(lied, snapFile{name: name, seq: 2, meta: raft.SnapshotMeta{Index: 20, Term: 1}}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("length field mismatch not detected: %v", err)
		}
		// Contents that do not match the name.
		if _, err := decodeSnapshot(orig, snapFile{name: name, seq: 2, meta: raft.SnapshotMeta{Index: 21, Term: 1}}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("name/header mismatch not detected: %v", err)
		}
	})
}

func TestSnapFileNames(t *testing.T) {
	sf := newSnapFile(0x2a, raft.SnapshotMeta{Index: 0xbeef, Term: 3})
	got, ok := parseSnapFileName(sf.name)
	if !ok || got != sf {
		t.Fatalf("round trip of %q failed: %+v", sf.name, got)
	}
	for _, bad := range []string{
		"snap-000000000000002a-000000000000beef-0000000000000003.snap.tmp",
		"snap-000000000000002A-000000000000beef-0000000000000003.snap",
		"snap-2a-beef-3.snap",
		"snap-000000000000002a-000000000000beef.snap",
		"snap-000000000000002a-000000000000beef-0000000000000003-0000000000000000.snap",
		"snap-+00000000000002a-000000000000beef-0000000000000003.snap",
		"wal",
	} {
		if _, ok := parseSnapFileName(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
