package filestore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// MaxEntrySize is the largest Entry.Data the store accepts. Append rejects
// larger entries, and Load treats a larger length field as corruption.
const MaxEntrySize = 256 << 20

const (
	lockFileName = "LOCK"
	tmpSuffix    = ".tmp"
	filePerm     = 0o600 // snapshots hold password verifier hashes and ciphertext
	dirPerm      = 0o700
)

var (
	// ErrCorrupt is wrapped by errors reporting on-disk data that fails
	// verification somewhere other than a torn final WAL record. The store
	// never repairs such data; recovering usually means wiping this node's
	// directory and letting it catch up from the other nodes.
	ErrCorrupt = errors.New("corrupt data")
	// ErrUnsupportedVersion is wrapped when a file was written by a newer
	// (or unknown) format version.
	ErrUnsupportedVersion = errors.New("unsupported on-disk format version")
	// ErrLocked is returned by Open when another Store (in this or another
	// process) has the directory open.
	ErrLocked = errors.New("directory locked by another store")
	// ErrClosed is returned by methods called after Close.
	ErrClosed = errors.New("filestore: store closed")

	// errInvalid marks calls rejected before any I/O because they violate
	// the Storage contract or would create a state Load could not return
	// faithfully. Such calls leave the store unchanged and usable.
	errInvalid = errors.New("invalid argument")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, args...)...)
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("filestore: %w: "+format, append([]any{errInvalid}, args...)...)
}

// Options configures a Store.
type Options struct {
	// NoSync disables every fsync, of files and of the directory. FOR TESTS
	// ONLY: it is unsafe. Without fsync a power failure can lose writes the
	// store has acknowledged, which can lose committed Raft entries.
	NoSync bool
	// Logger receives recovery events (torn tails dropped, logs discarded
	// by the recovery rule, snapshot fallbacks, leftover files). nil
	// discards them.
	Logger *slog.Logger
}

// knobs are test-only overrides.
type knobs struct {
	lim  limits
	salt func() uint64
}

// Store is a crash-safe raft.Storage in one directory. It is safe for
// concurrent use, although the contract only requires one caller at a time.
type Store struct {
	mu      sync.Mutex
	fs      fileSystem
	dir     string
	noSync  bool
	log     *slog.Logger
	lim     limits
	newSalt func() uint64
	lock    io.Closer

	loaded bool
	closed bool
	failed error // set by the first I/O failure of a mutating method

	hs raft.HardState // durable hard state (zero if never saved)

	cur       *snapFile  // latest valid snapshot; nil if none
	snapFiles []snapFile // snapshot files believed to exist on disk
	nextSeq   uint64

	// The WAL and its in-memory index. ents[i] describes log index
	// first+i. walBase is the index the next entry gets while ents is
	// empty. walEnd is where the next record is written.
	wal     file
	codec   walCodec
	walBase uint64
	walEnd  int64
	first   uint64
	ents    []entryMeta

	buf []byte // reusable record encoding buffer

	recovery recoveryInfo
}

// recoveryInfo records what Load had to do (for logging and tests).
type recoveryInfo struct {
	tornBytes    int64    // bytes of torn WAL tail truncated
	discarded    int      // entries dropped by the recovery rule
	fellBackFrom []string // corrupt snapshots skipped in favour of an older one
}

var _ raft.Storage = (*Store)(nil)

// Open opens (creating if necessary, mode 0700) the store in dir and takes
// an exclusive lock on it, so a second Open of the same directory fails
// with ErrLocked until Close. Temporary files left by an interrupted
// atomic replace are deleted. Load must be called next.
func Open(dir string, opts Options) (*Store, error) {
	s, err := open(osFS{}, dir, opts, nil)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		s.log.Warn("data directory is accessible to other users; it should be mode 0700",
			"dir", dir, "mode", fi.Mode().Perm().String())
	}
	return s, nil
}

func open(fsys fileSystem, dir string, opts Options, k *knobs) (*Store, error) {
	s := &Store{
		fs:      fsys,
		dir:     dir,
		noSync:  opts.NoSync,
		log:     opts.Logger,
		lim:     defaultLimits(),
		newSalt: randomSalt,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if k != nil {
		if k.lim != (limits{}) {
			s.lim = k.lim
		}
		if k.salt != nil {
			s.newSalt = k.salt
		}
	}
	if s.lim.maxRecord < s.lim.maxEntry+entHeaderSize || s.lim.maxRecord > math.MaxUint32 {
		return nil, fmt.Errorf("filestore: bad limits %+v", s.lim)
	}

	created, err := fsys.MkdirAll(dir, dirPerm)
	if err != nil {
		return nil, fmt.Errorf("filestore: open %s: %w", dir, err)
	}
	for _, d := range created {
		// Make each new directory's own entry durable.
		if err := s.syncPath(filepath.Dir(d)); err != nil {
			return nil, fmt.Errorf("filestore: open %s: sync parent of %s: %w", dir, d, err)
		}
	}
	lock, err := fsys.Lock(s.path(lockFileName))
	if err != nil {
		return nil, fmt.Errorf("filestore: open %s: %w", dir, err)
	}
	names, err := fsys.ReadDir(dir)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("filestore: open %s: %w", dir, err)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, tmpSuffix) {
			continue
		}
		// An atomic replace was interrupted before its rename was durable,
		// so the target name still holds the complete previous version
		// (or never existed). The temp file is garbage. Not fsyncing the
		// directory after removal is fine: if the removal is rolled back by
		// a crash, the next Open removes it again.
		if err := fsys.Remove(s.path(name)); err != nil {
			lock.Close()
			return nil, fmt.Errorf("filestore: open %s: remove leftover %s: %w", dir, name, err)
		}
		s.log.Info("removed leftover temporary file from an interrupted write", "file", name)
	}
	s.lock = lock
	return s, nil
}

func randomSalt() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (it crashes the program instead)
	return binary.LittleEndian.Uint64(b[:])
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

// Load implements raft.Storage. It also performs the repairs that make the
// on-disk state match what it returns: truncating a torn final WAL record,
// and physically discarding a log the recovery rule rejected. Both repairs
// are idempotent, so a crash during Load just means the next Load redoes
// them.
func (s *Store) Load() (raft.HardState, *raft.Snapshot, []raft.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return raft.HardState{}, nil, nil, ErrClosed
	case s.loaded:
		return raft.HardState{}, nil, nil, errors.New("filestore: Load called more than once")
	case s.failed != nil:
		return raft.HardState{}, nil, nil, s.failed
	}
	hs, snap, entries, err := s.load()
	if err != nil {
		s.failed = fmt.Errorf("filestore: load %s: %w", s.dir, err)
		return raft.HardState{}, nil, nil, s.failed
	}
	s.loaded = true
	return hs, snap, entries, nil
}

func (s *Store) load() (raft.HardState, *raft.Snapshot, []raft.Entry, error) {
	names, err := s.fs.ReadDir(s.dir)
	if err != nil {
		return raft.HardState{}, nil, nil, err
	}
	var haveWAL, haveHS bool
	var snaps []snapFile
	for _, name := range names {
		switch {
		case name == walFileName:
			haveWAL = true
		case name == hsFileName:
			haveHS = true
		case name == lockFileName, strings.HasSuffix(name, tmpSuffix):
		default:
			if sf, ok := parseSnapFileName(name); ok {
				snaps = append(snaps, sf)
			} else {
				s.log.Warn("ignoring unrecognised file in data directory", "file", name)
			}
		}
	}

	var hs raft.HardState
	if haveHS {
		b, err := s.readFile(hsFileName, maxHSFileLen)
		if err != nil {
			return raft.HardState{}, nil, nil, err
		}
		if hs, err = decodeHardState(b); err != nil {
			return raft.HardState{}, nil, nil, err
		}
	}

	if !haveWAL {
		// The WAL is created before anything else can be written and is
		// only ever replaced by rename, never removed, so its absence next
		// to other state means it was lost or deleted outside the store.
		if haveHS || len(snaps) > 0 {
			return raft.HardState{}, nil, nil, corruptf("%s is missing although other state exists", walFileName)
		}
		// A brand-new store. Creating the WAL atomically means a crash here
		// leaves either no WAL (still a brand-new store) or a complete one.
		f, codec, end, _, err := s.replaceWAL(1, nil)
		if err != nil {
			return raft.HardState{}, nil, nil, fmt.Errorf("create %s: %w", walFileName, err)
		}
		s.hs = hs
		s.nextSeq = 1
		s.swapWAL(f, codec, 1, end, 0, nil)
		return hs, nil, nil, nil
	}

	f, err := s.fs.OpenFile(s.path(walFileName), os.O_RDWR, 0)
	if err != nil {
		return raft.HardState{}, nil, nil, err
	}
	hs, snap, entries, err := s.loadWithWAL(f, hs, snaps)
	if err != nil {
		f.Close()
		return raft.HardState{}, nil, nil, err
	}
	return hs, snap, entries, nil
}

func (s *Store) loadWithWAL(f file, hs raft.HardState, snaps []snapFile) (raft.HardState, *raft.Snapshot, []raft.Entry, error) {
	buf, err := readWhole(f)
	if err != nil {
		return raft.HardState{}, nil, nil, err
	}
	w, err := parseWAL(buf, s.lim)
	buf = nil
	if err != nil {
		return raft.HardState{}, nil, nil, err
	}

	// Pick the snapshot: the newest by sequence number whose contents
	// verify, falling back past corrupt ones only when that provably loses
	// nothing (see checkFallback).
	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].seq != snaps[j].seq {
			return snaps[i].seq > snaps[j].seq
		}
		return snaps[i].name > snaps[j].name // never written by us; just be deterministic
	})
	s.nextSeq = 1
	if len(snaps) > 0 {
		s.nextSeq = snaps[0].seq + 1
	}
	var cur *snapFile
	var snap *raft.Snapshot
	var corrupt []snapFile
	for i := range snaps {
		sn, err := s.readSnapshot(snaps[i])
		if err == nil {
			c := snaps[i]
			cur, snap = &c, sn
			break
		}
		if !errors.Is(err, ErrCorrupt) {
			return raft.HardState{}, nil, nil, err // I/O error or unknown version: never a reason to fall back
		}
		s.log.Error("snapshot failed verification", "file", snaps[i].name, "err", err)
		corrupt = append(corrupt, snaps[i])
	}
	if len(corrupt) > 0 {
		var cand raft.SnapshotMeta // the zero meta stands for "no snapshot": the log must start at 1
		if cur != nil {
			cand = cur.meta
		}
		if err := checkFallback(cand, corrupt, w); err != nil {
			return raft.HardState{}, nil, nil, err
		}
		for _, c := range corrupt {
			s.recovery.fellBackFrom = append(s.recovery.fellBackFrom, c.name)
		}
		s.log.Warn("newest snapshot is corrupt; using an older snapshot plus the log, which still covers everything the corrupt one did",
			"corrupt", s.recovery.fellBackFrom, "using_index", cand.Index)
	}

	// The recovery rule from the raft.Storage contract.
	discard := false
	if cur == nil {
		if fi := w.firstIndex(); fi != 1 {
			return raft.HardState{}, nil, nil, corruptf("log starts at index %d but there is no snapshot", fi)
		}
	} else {
		switch decide(cur.meta, w.firstIndex(), w.termAt) {
		case keepLog:
		case discardLog:
			discard = true
		case gapLog:
			return raft.HardState{}, nil, nil, corruptf("snapshot %s covers up to index %d but the log starts at %d: entries are missing",
				cur.name, cur.meta.Index, w.firstIndex())
		}
	}

	codec, base, end, first, metas, entries := newWALCodec(w.salt), w.base, w.end, w.first, w.metas, w.entries
	switch {
	case discard:
		// Only reachable after a crash inside InstallSnapshot (between the
		// snapshot becoming durable and the WAL being replaced). Finish the
		// job now so the store's on-disk state matches what we return;
		// replacing the file also disposes of any torn tail.
		newBase := cur.meta.Index + 1
		nf, ncodec, nend, _, err := s.replaceWAL(newBase, nil)
		if err != nil {
			return raft.HardState{}, nil, nil, fmt.Errorf("discard log: %w", err)
		}
		f.Close()
		f, codec, base, end, first, metas = nf, ncodec, newBase, nend, 0, nil
		s.recovery.discarded = len(entries)
		s.log.Info("discarded log that does not continue the snapshot (interrupted InstallSnapshot)",
			"snapshot_index", cur.meta.Index, "snapshot_term", cur.meta.Term, "entries", len(entries))
		entries = nil
	case w.torn:
		// Drop the torn tail before anything is appended after it, so new
		// records are never preceded by garbage. Strictly, the fsync of the
		// next Append would also persist this truncation (and a crash before
		// then just leaves the same torn tail for the next Load), but
		// syncing here means the repaired file is durable before we return
		// and the old torn bytes are released before new data is written
		// over their range, so correctness does not depend on how a
		// filesystem orders an unsynced truncate against a later write.
		// It costs one fsync, only after a crash.
		if err := f.Truncate(w.end); err != nil {
			return raft.HardState{}, nil, nil, fmt.Errorf("truncate torn wal tail: %w", err)
		}
		if err := s.sync(f); err != nil {
			return raft.HardState{}, nil, nil, fmt.Errorf("truncate torn wal tail: %w", err)
		}
		s.recovery.tornBytes = w.size - w.end
		s.log.Warn("dropped torn record at the end of the wal (interrupted append; it was never acknowledged)",
			"offset", w.end, "bytes", w.size-w.end, "reason", w.tornReason)
	}

	s.hs = hs
	s.cur = cur
	s.snapFiles = snaps
	s.swapWAL(f, codec, base, end, first, metas)
	return hs, snap, entries, nil
}

type logDecision int

const (
	keepLog logDecision = iota
	discardLog
	gapLog
)

// decide is the contract's recovery rule for snapshot sn and a log whose
// first index is f (for an empty log: the index its next entry would get).
func decide(sn raft.SnapshotMeta, f uint64, termAt func(uint64) (uint64, bool)) logDecision {
	switch {
	case f == sn.Index+1:
		return keepLog
	case f > sn.Index+1:
		return gapLog
	}
	if t, ok := termAt(sn.Index); ok && t == sn.Term {
		return keepLog
	}
	return discardLog
}

// checkFallback decides whether Load may use the older snapshot cand
// because every newer snapshot (corrupt) failed verification.
//
// Snapshot files are complete before they are renamed into place, so a
// corrupt one means media damage, not an interrupted write. Falling back is
// only safe if nothing the node acknowledged depends on the lost snapshot.
// A node acknowledges a snapshot's position (MatchIndex in MsgSnapResp)
// and may have compacted the log behind it, so we require that
//   - the log still continues cand (the recovery rule would keep it), so
//     replaying it from cand rebuilds the state, and
//   - the log still contains the last entry of every corrupt snapshot with
//     the same term. By Raft's log matching property the log then holds
//     everything those snapshots covered, and nothing acknowledged is lost.
//
// Otherwise the node must not start: it would silently forget state it
// told the leader it had. In practice the condition holds only when the
// core retains trailing log entries spanning the previous snapshot
// interval; after an InstallSnapshot it never holds (that log is gone).
func checkFallback(cand raft.SnapshotMeta, corrupt []snapFile, w *walContents) error {
	if decide(cand, w.firstIndex(), w.termAt) != keepLog {
		return corruptf("snapshot %s is corrupt, and the log (starting at index %d) does not continue the next older snapshot (index %d), so it cannot be rebuilt",
			corrupt[0].name, w.firstIndex(), cand.Index)
	}
	for _, c := range corrupt {
		if t, ok := w.termAt(c.meta.Index); !ok || t != c.meta.Term {
			return corruptf("snapshot %s is corrupt, and the log no longer holds its last entry (index %d, term %d), so falling back to an older snapshot could forget acknowledged state",
				c.name, c.meta.Index, c.meta.Term)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

// SaveHardState implements raft.Storage.
//
// Crash safety: the new hard state is written to hardstate.tmp, fsynced,
// renamed over hardstate, and the directory is fsynced. rename(2) is
// atomic, so after a crash the name refers to either the complete old file
// or the complete new one; the directory fsync makes it the new one before
// we return. A leftover temp file is removed by Open.
func (s *Store) SaveHardState(hs raft.HardState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if hs == s.hs {
		return nil // already durable (Load returns the zero value when no file exists)
	}
	if len(hs.VotedFor) > maxVotedFor {
		return invalidf("save hard state: votedFor is %d bytes, limit %d", len(hs.VotedFor), maxVotedFor)
	}
	if err := s.writeFileAtomic(hsFileName, encodeHardState(hs)); err != nil {
		return s.fail("save hard state", err)
	}
	s.hs = hs
	return nil
}

// Append implements raft.Storage.
//
// All of entries normally go into ONE record, written with one write and
// made durable with one fsync. Conflict truncation is not done by
// shortening the file: the record carries its first index, and a reader
// applying records in order discards every entry from that index onward
// before adding the record's entries. Truncation and new entries therefore
// live in the same CRC-protected record and become durable together.
//
// Crash safety: the record is appended after the last valid record (Load
// truncates any torn tail before the first append). If we crash before the
// fsync completes, any prefix of the record's bytes may have reached the
// disk, possibly followed by garbage. Load either finds the record intact
// (old prefix + all new entries) or finds it invalid with nothing valid
// after it, which is a torn tail and is dropped (the old log, untouched).
// The old suffix is never physically overwritten, so stale old entries
// cannot reappear after new ones, and there is no intermediate state where
// the old suffix is gone but the new entries are not yet written.
//
// Only in the rare case that the entries do not fit in one record (more
// than about MaxEntrySize in total) are they split, and then each record is
// fsynced before the next is written. That keeps the invariant the torn
// tail detection relies on, at most one unsynced record in the file at a
// time, and a crash between records leaves old prefix + a prefix of the
// new entries, which the contract allows (the first record carries the
// truncation). If such a prefix stops short of the snapshot index, Load's
// recovery rule then discards it; that only drops entries the snapshot
// already covers.
func (s *Store) Append(entries []raft.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if err := s.checkAppend(entries); err != nil {
		return err
	}
	for _, group := range splitRecords(entries, s.lim) {
		s.buf = s.codec.appendRecord(s.buf[:0], group)
		off, n := s.walEnd, int64(len(s.buf))
		if _, err := s.wal.WriteAt(s.buf, off); err != nil {
			return s.fail("append", err)
		}
		if err := s.sync(s.wal); err != nil {
			return s.fail("append", err)
		}
		s.indexRecord(group, off, n)
		s.walEnd = off + n
	}
	if cap(s.buf) > 1<<20 {
		s.buf = nil // do not pin a large buffer between appends
	}
	return nil
}

func (s *Store) checkAppend(entries []raft.Entry) error {
	start := entries[0].Index
	last := start + uint64(len(entries)) - 1
	if start == 0 {
		return invalidf("append: entry index 0 (indexes start at 1)")
	}
	if last < start {
		return invalidf("append: index overflow")
	}
	for i := range entries {
		if want := start + uint64(i); entries[i].Index != want {
			return invalidf("append: entries not contiguous: entry %d has index %d, want %d", i, entries[i].Index, want)
		}
		if len(entries[i].Data) > s.lim.maxEntry {
			return invalidf("append: entry %d is %d bytes, limit %d", entries[i].Index, len(entries[i].Data), s.lim.maxEntry)
		}
	}
	if next := s.nextIndex(); start > next {
		return invalidf("append: first index %d leaves a gap (next index is %d)", start, next)
	}
	// Refuse to create a log the recovery rule would throw away on the
	// next Load: that would silently lose entries this call acknowledged.
	// A correct core never does this (entries at or before a snapshot are
	// committed and match it), so this only turns a latent bug into a loud
	// one.
	if s.cur != nil {
		f := min(start, s.logFirst())
		termAt := func(i uint64) (uint64, bool) {
			if i >= start && i <= last {
				return entries[i-start].Term, true
			}
			if i < start {
				return s.termAt(i)
			}
			return 0, false
		}
		if decide(s.cur.meta, f, termAt) != keepLog {
			return invalidf("append [%d, %d]: resulting log does not continue the snapshot at index %d term %d, so Load would discard it",
				start, last, s.cur.meta.Index, s.cur.meta.Term)
		}
	}
	return nil
}

// SaveSnapshot implements raft.Storage.
//
// Crash safety: the snapshot is written under a new, never-before-used name
// via a temp file, fsync, rename and directory fsync, so it either exists
// complete or not at all, and the log is not touched. Older snapshots are
// deleted only after that directory fsync (see pruneSnapshots); the one
// that was current before is kept as a fallback.
func (s *Store) SaveSnapshot(snap raft.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	// The contract says the log already contains snap.Meta.Index with a
	// matching term. If it does not, Load would discard the log (or fail)
	// on the next start, losing acknowledged entries; refuse instead.
	if d := decide(snap.Meta, s.logFirst(), s.termAt); d != keepLog {
		return invalidf("save snapshot (index %d, term %d): the log (first index %d, next index %d) does not contain that entry with that term; use InstallSnapshot",
			snap.Meta.Index, snap.Meta.Term, s.logFirst(), s.nextIndex())
	}
	prev, err := s.writeSnapshot(snap)
	if err != nil {
		return s.fail("save snapshot", err)
	}
	s.pruneSnapshots(prev)
	return nil
}

// InstallSnapshot implements raft.Storage.
//
// Crash safety, in two durable steps:
//  1. The snapshot is written exactly as in SaveSnapshot. A crash before it
//     is durable leaves the old state.
//  2. The WAL is atomically replaced (temp file, fsync, rename, directory
//     fsync) by an empty one whose base is snap.Meta.Index+1.
//
// A crash between the steps leaves the new snapshot next to the old log,
// and Load's recovery rule handles it: the old log is kept only if it
// provably continues the snapshot (it holds snap.Meta.Index with the same
// term, so by log matching its prefix is exactly what the snapshot covers
// and its suffix is entries the node legitimately had before), otherwise it
// is discarded. Either way Load returns a consistent state.
func (s *Store) InstallSnapshot(snap raft.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if snap.Meta.Index == math.MaxUint64 {
		return invalidf("install snapshot: index overflow")
	}
	// A snapshot that ends before the first index still in the log is older
	// than what this node already compacted. A crash between the two steps
	// below would leave it next to a log that starts after it, which the
	// recovery rule classifies as corruption (f > s.Index+1), so the node
	// could not restart. A correct core never installs a snapshot older
	// than its own (it covers only entries this node already has
	// committed), so refuse rather than risk an unloadable store.
	if f := s.logFirst(); f > snap.Meta.Index+1 {
		return invalidf("install snapshot (index %d, term %d): older than the compacted log, which starts at %d",
			snap.Meta.Index, snap.Meta.Term, f)
	}
	prev, err := s.writeSnapshot(snap)
	if err != nil {
		return s.fail("install snapshot", err)
	}
	base := snap.Meta.Index + 1
	f, codec, end, _, err := s.replaceWAL(base, nil)
	if err != nil {
		return s.fail("install snapshot", err)
	}
	s.swapWAL(f, codec, base, end, 0, nil)
	s.pruneSnapshots(prev)
	return nil
}

// Compact implements raft.Storage.
//
// The retained entries (through+1 onward) are copied into a new WAL whose
// base is through+1, which then replaces the old one by temp file, fsync,
// rename and directory fsync. The rename is the commit point, so after a
// crash Load sees exactly the old or exactly the compacted log. Copied
// records are re-verified (CRCs and index) on the way, so compaction never
// launders a corrupt record into a freshly checksummed one.
//
// The contract allows Compact to return before it is durable; this
// implementation is durable anyway. The directory fsync is required
// regardless: appends after Compact go to the new file, and if the rename
// could still be rolled back by a crash, acknowledged appends would vanish
// with it.
func (s *Store) Compact(through uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if s.cur == nil {
		return invalidf("compact through %d: there is no snapshot", through)
	}
	if through > s.cur.meta.Index {
		return invalidf("compact through %d: beyond the latest snapshot index %d", through, s.cur.meta.Index)
	}
	if len(s.ents) == 0 || through < s.first {
		return nil
	}
	var keep []entryMeta
	if n := through - s.first + 1; n < uint64(len(s.ents)) {
		keep = s.ents[n:]
	}
	f, codec, end, metas, err := s.replaceWAL(through+1, func(dst file, dc walCodec, off int64) (int64, []entryMeta, error) {
		return s.copyEntries(dst, dc, off, through+1, keep)
	})
	if err != nil {
		return s.fail("compact", err)
	}
	var first uint64
	if len(metas) > 0 {
		first = through + 1
	}
	s.swapWAL(f, codec, through+1, end, first, metas)
	return nil
}

// copyEntries writes the live entries keep (indexes from, from+1, ...) to
// dst starting at off, re-reading and re-verifying the records that hold
// them in the current WAL. It returns the end offset and the new index.
func (s *Store) copyEntries(dst file, dc walCodec, off int64, from uint64, keep []entryMeta) (int64, []entryMeta, error) {
	metas := make([]entryMeta, 0, len(keep))
	idx := from
	for i := 0; i < len(keep); {
		j := i
		for j < len(keep) && keep[j].recOff == keep[i].recOff {
			j++
		}
		frame := make([]byte, keep[i].recLen)
		if n, err := s.wal.ReadAt(frame, keep[i].recOff); err != nil && !(errors.Is(err, io.EOF) && n == len(frame)) {
			return 0, nil, err
		}
		rec, prob := s.codec.decodeRecordAt(frame, 0, s.lim)
		if prob != nil {
			return 0, nil, corruptf("wal record at offset %d failed verification during compaction: %s", keep[i].recOff, prob.reason)
		}
		lo, hi := idx, idx+uint64(j-i) // [lo, hi)
		if lo < rec.first || hi > rec.first+uint64(len(rec.entries)) {
			return 0, nil, corruptf("wal record at offset %d holds [%d, %d), expected it to hold [%d, %d)",
				keep[i].recOff, rec.first, rec.first+uint64(len(rec.entries)), lo, hi)
		}
		sel := rec.entries[lo-rec.first : hi-rec.first]
		for k := range sel {
			if sel[k].Term != keep[i+k].term {
				return 0, nil, corruptf("wal entry %d has term %d on disk but %d in the index", sel[k].Index, sel[k].Term, keep[i+k].term)
			}
		}
		s.buf = dc.appendRecord(s.buf[:0], sel)
		n := int64(len(s.buf))
		if _, err := dst.WriteAt(s.buf, off); err != nil {
			return 0, nil, err
		}
		for k := range sel {
			metas = append(metas, entryMeta{term: sel[k].Term, recOff: off, recLen: n})
		}
		off += n
		idx, i = hi, j
	}
	if cap(s.buf) > 1<<20 {
		s.buf = nil
	}
	return off, metas, nil
}

// Close implements raft.Storage. It releases the directory lock.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.wal != nil {
		err = s.wal.Close()
	}
	if s.lock != nil {
		if e := s.lock.Close(); err == nil {
			err = e
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) usable() error {
	switch {
	case s.closed:
		return ErrClosed
	case s.failed != nil:
		return fmt.Errorf("filestore: unusable after an earlier failure; reopen and Load: %w", s.failed)
	case !s.loaded:
		return errors.New("filestore: Load must be called before any other method")
	}
	return nil
}

// fail poisons the store. After a failed write or fsync the in-memory index
// and the file may disagree, and after a failed fsync the kernel may have
// dropped the dirty pages, so a retried fsync could report success without
// the data being on disk. The only safe way forward is to reopen and Load,
// which re-derives everything from what is actually on disk. (The node
// treats any Storage error as fatal anyway.)
func (s *Store) fail(op string, err error) error {
	s.failed = fmt.Errorf("filestore: %s: %w", op, err)
	return s.failed
}

func (s *Store) sync(f file) error {
	if s.noSync {
		return nil
	}
	return f.Sync()
}

func (s *Store) syncDir() error { return s.syncPath(s.dir) }

func (s *Store) syncPath(dir string) error {
	if s.noSync {
		return nil
	}
	return s.fs.SyncDir(dir)
}

func (s *Store) logFirst() uint64 {
	if len(s.ents) > 0 {
		return s.first
	}
	return s.walBase
}

func (s *Store) nextIndex() uint64 {
	if len(s.ents) > 0 {
		return s.first + uint64(len(s.ents))
	}
	return s.walBase
}

func (s *Store) termAt(i uint64) (uint64, bool) {
	if len(s.ents) == 0 || i < s.first || i-s.first >= uint64(len(s.ents)) {
		return 0, false
	}
	return s.ents[i-s.first].term, true
}

// indexRecord updates the in-memory index for a durable record holding
// group, mirroring what parseWAL does when it reads the record back.
func (s *Store) indexRecord(group []raft.Entry, off, size int64) {
	start := group[0].Index
	switch {
	case len(s.ents) == 0:
	case start <= s.first:
		s.ents = s.ents[:0]
	case start-s.first < uint64(len(s.ents)):
		s.ents = s.ents[:start-s.first]
	}
	if len(s.ents) == 0 {
		s.first = start
	}
	for i := range group {
		s.ents = append(s.ents, entryMeta{term: group[i].Term, recOff: off, recLen: size})
	}
}

func (s *Store) swapWAL(f file, codec walCodec, base uint64, end int64, first uint64, metas []entryMeta) {
	old := s.wal
	s.wal, s.codec, s.walBase, s.walEnd, s.first, s.ents = f, codec, base, end, first, metas
	if old != nil && old != f {
		_ = old.Close() // nothing was written through it since its last fsync
	}
}

// replaceWAL atomically replaces the WAL with a new file: a header with
// base and a fresh salt, followed by whatever fill writes. It returns the
// new file, still open, positioned for appends at end.
//
// Crash safety: the new file is complete and fsynced under a temporary name
// before the rename, so "wal" always names either the complete old file or
// the complete new one. The directory fsync then makes the rename durable
// before the caller relies on it: in particular before any record is
// appended to the new file, which would vanish if the rename were rolled
// back.
func (s *Store) replaceWAL(base uint64, fill func(f file, c walCodec, off int64) (int64, []entryMeta, error)) (file, walCodec, int64, []entryMeta, error) {
	tmp := s.path(walFileName + tmpSuffix)
	f, err := s.fs.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return nil, walCodec{}, 0, nil, err
	}
	abort := func(err error) (file, walCodec, int64, []entryMeta, error) {
		f.Close()
		_ = s.fs.Remove(tmp)
		return nil, walCodec{}, 0, nil, err
	}
	salt := s.newSalt()
	codec := newWALCodec(salt)
	if _, err := f.WriteAt(encodeWALHeader(base, salt), 0); err != nil {
		return abort(err)
	}
	end := int64(walHeaderSize)
	var metas []entryMeta
	if fill != nil {
		if end, metas, err = fill(f, codec, end); err != nil {
			return abort(err)
		}
	}
	if err := s.sync(f); err != nil {
		return abort(err)
	}
	if err := s.fs.Rename(tmp, s.path(walFileName)); err != nil {
		return abort(err)
	}
	if err := s.syncDir(); err != nil {
		// The rename may or may not survive a crash; both are valid states.
		f.Close()
		return nil, walCodec{}, 0, nil, err
	}
	return f, codec, end, metas, nil
}

// writeFileAtomic replaces name with the concatenation of parts: temp file,
// fsync, rename, directory fsync. See SaveHardState for the argument.
func (s *Store) writeFileAtomic(name string, parts ...[]byte) error {
	tmp := s.path(name + tmpSuffix)
	f, err := s.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	var off int64
	for _, p := range parts {
		if _, err = f.WriteAt(p, off); err != nil {
			break
		}
		off += int64(len(p))
	}
	if err == nil {
		err = s.sync(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.fs.Rename(tmp, s.path(name))
	}
	if err != nil {
		_ = s.fs.Remove(tmp)
		return err
	}
	return s.syncDir()
}

// writeSnapshot durably writes snap under the next sequence number and makes
// it current. It returns the previously current snapshot.
func (s *Store) writeSnapshot(snap raft.Snapshot) (prev *snapFile, err error) {
	sf := newSnapFile(s.nextSeq, snap.Meta)
	if err := s.writeFileAtomic(sf.name, encodeSnapHeader(snap.Meta, snap.Data), snap.Data); err != nil {
		return nil, err
	}
	s.nextSeq++
	prev = s.cur
	s.snapFiles = append(s.snapFiles, sf)
	s.cur = &sf
	return prev, nil
}

// pruneSnapshots deletes every snapshot file except the current one and
// prev (the one current before it), which is kept as a fallback in case the
// current one is later found corrupt (see checkFallback).
//
// This runs only after the current snapshot is durable (writeFileAtomic
// fsyncs the directory after its rename), so the previous snapshot is never
// deleted before its replacement is safe. The removals themselves are not
// fsynced: if a crash rolls one back, the file reappears as an older
// snapshot, which Load consults only under the fallback safety check, and
// the next save deletes it again. Failure to delete is logged, not
// returned: the snapshot operation itself is already durable.
func (s *Store) pruneSnapshots(prev *snapFile) {
	kept := make([]snapFile, 0, 2)
	for _, sf := range s.snapFiles {
		if sf.name == s.cur.name || (prev != nil && sf.name == prev.name) {
			kept = append(kept, sf)
			continue
		}
		if err := s.fs.Remove(s.path(sf.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn("could not remove old snapshot", "file", sf.name, "err", err)
			kept = append(kept, sf)
		}
	}
	s.snapFiles = kept
}

func (s *Store) readFile(name string, max int64) ([]byte, error) {
	f, err := s.fs.OpenFile(s.path(name), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if max > 0 {
		size, err := f.Size()
		if err != nil {
			return nil, err
		}
		if size > max {
			return nil, corruptf("%s is %d bytes, more than the possible %d", name, size, max)
		}
	}
	return readWhole(f)
}

func (s *Store) readSnapshot(sf snapFile) (*raft.Snapshot, error) {
	b, err := s.readFile(sf.name, 0)
	if err != nil {
		return nil, err
	}
	return decodeSnapshot(b, sf)
}
