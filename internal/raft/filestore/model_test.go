package filestore

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// model is the trivially correct reference: the state Load must return.
type model struct {
	hs   raft.HardState
	snap *raft.Snapshot
	log  []raft.Entry
}

func (m model) next() uint64 {
	switch {
	case len(m.log) > 0:
		return m.log[len(m.log)-1].Index + 1
	case m.snap != nil:
		return m.snap.Meta.Index + 1
	}
	return 1
}

func (m model) first() uint64 {
	if len(m.log) > 0 {
		return m.log[0].Index
	}
	return m.next()
}

func (m model) termAt(i uint64) (uint64, bool) {
	if len(m.log) == 0 || i < m.log[0].Index || i > m.log[len(m.log)-1].Index {
		return 0, false
	}
	return m.log[i-m.log[0].Index].Term, true
}

// recover applies the contract's recovery rule, as Load does.
func (m model) recover() model {
	if m.snap != nil && decide(m.snap.Meta, m.first(), m.termAt) == discardLog {
		m.log = nil
	}
	return m
}

func (m model) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "hs=%+v ", m.hs)
	if m.snap != nil {
		fmt.Fprintf(&sb, "snap={i=%d t=%d %dB crc=%08x} ", m.snap.Meta.Index, m.snap.Meta.Term, len(m.snap.Data), crc32c(m.snap.Data))
	} else {
		sb.WriteString("snap=nil ")
	}
	parts := make([]string, 0, len(m.log))
	for i, e := range m.log {
		if len(m.log) > 12 && i == 6 {
			parts = append(parts, fmt.Sprintf("...(%d more)...", len(m.log)-9))
		}
		if len(m.log) > 12 && i >= 6 && i < len(m.log)-3 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d/%d:%08x", e.Index, e.Term, crc32c(e.Data)))
	}
	return sb.String() + "log=[" + strings.Join(parts, " ") + "]"
}

func equalState(m model, hs raft.HardState, snap *raft.Snapshot, ents []raft.Entry) bool {
	if m.hs != hs || (m.snap == nil) != (snap == nil) || len(m.log) != len(ents) {
		return false
	}
	if snap != nil && (m.snap.Meta != snap.Meta || !bytes.Equal(m.snap.Data, snap.Data)) {
		return false
	}
	for i := range ents {
		a, b := m.log[i], ents[i]
		if a.Index != b.Index || a.Term != b.Term || a.Type != b.Type || !bytes.Equal(a.Data, b.Data) {
			return false
		}
	}
	return true
}

// checkStructure verifies the guarantees Load documents.
func checkStructure(snap *raft.Snapshot, ents []raft.Entry) error {
	for i := 1; i < len(ents); i++ {
		if ents[i].Index != ents[i-1].Index+1 {
			return fmt.Errorf("entries not contiguous at %d: %d after %d", i, ents[i].Index, ents[i-1].Index)
		}
	}
	if len(ents) == 0 {
		return nil
	}
	if snap == nil {
		if ents[0].Index != 1 {
			return fmt.Errorf("no snapshot but entries start at %d", ents[0].Index)
		}
		return nil
	}
	if ents[0].Index > snap.Meta.Index+1 {
		return fmt.Errorf("entries start at %d, after snapshot index %d + 1", ents[0].Index, snap.Meta.Index)
	}
	if last := ents[len(ents)-1].Index; ents[0].Index <= snap.Meta.Index && snap.Meta.Index <= last {
		if t := ents[snap.Meta.Index-ents[0].Index].Term; t != snap.Meta.Term {
			return fmt.Errorf("entry at snapshot index %d has term %d, snapshot term %d", snap.Meta.Index, t, snap.Meta.Term)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

type opKind int

const (
	opHardState opKind = iota
	opAppend
	opSaveSnap
	opInstallSnap
	opCompact
)

type op struct {
	kind    opKind
	hs      raft.HardState
	entries []raft.Entry
	snap    raft.Snapshot
	through uint64
}

func (o op) String() string {
	switch o.kind {
	case opHardState:
		return fmt.Sprintf("SaveHardState(%+v)", o.hs)
	case opAppend:
		var parts []string
		for _, e := range o.entries {
			parts = append(parts, fmt.Sprintf("%d/%d(%dB)", e.Index, e.Term, len(e.Data)))
		}
		return "Append(" + strings.Join(parts, " ") + ")"
	case opSaveSnap:
		return fmt.Sprintf("SaveSnapshot(i=%d t=%d %dB)", o.snap.Meta.Index, o.snap.Meta.Term, len(o.snap.Data))
	case opInstallSnap:
		return fmt.Sprintf("InstallSnapshot(i=%d t=%d %dB)", o.snap.Meta.Index, o.snap.Meta.Term, len(o.snap.Data))
	case opCompact:
		return fmt.Sprintf("Compact(%d)", o.through)
	}
	return "?"
}

func (o op) run(s *Store) error {
	switch o.kind {
	case opHardState:
		return s.SaveHardState(o.hs)
	case opAppend:
		return s.Append(o.entries)
	case opSaveSnap:
		return s.SaveSnapshot(o.snap)
	case opInstallSnap:
		return s.InstallSnapshot(o.snap)
	case opCompact:
		return s.Compact(o.through)
	}
	panic("bad op")
}

// valid mirrors the store's validation: the contract's preconditions plus
// the refusal of states the recovery rule would not keep.
func (m model) valid(o op, lim limits) bool {
	switch o.kind {
	case opHardState:
		return len(o.hs.VotedFor) <= maxVotedFor
	case opAppend:
		if len(o.entries) == 0 {
			return true
		}
		start := o.entries[0].Index
		last := start + uint64(len(o.entries)) - 1
		if start == 0 || last < start || start > m.next() {
			return false
		}
		for i, e := range o.entries {
			if e.Index != start+uint64(i) || len(e.Data) > lim.maxEntry {
				return false
			}
		}
		if m.snap != nil {
			post := m.apply(o)
			return decide(m.snap.Meta, post.first(), post.termAt) == keepLog
		}
		return true
	case opSaveSnap:
		return decide(o.snap.Meta, m.first(), m.termAt) == keepLog
	case opInstallSnap:
		return o.snap.Meta.Index != math.MaxUint64 && m.first() <= o.snap.Meta.Index+1
	case opCompact:
		return m.snap != nil && o.through <= m.snap.Meta.Index
	}
	return false
}

func (m model) apply(o op) model {
	switch o.kind {
	case opHardState:
		m.hs = o.hs
	case opAppend:
		if len(o.entries) == 0 {
			return m
		}
		m.log = append(m.prefixBefore(o.entries[0].Index), o.entries...)
	case opSaveSnap:
		s := o.snap
		m.snap = &s
	case opInstallSnap:
		s := o.snap
		m.snap, m.log = &s, nil
	case opCompact:
		var kept []raft.Entry
		for _, e := range m.log {
			if e.Index > o.through {
				kept = append(kept, e)
			}
		}
		m.log = kept
	}
	return m
}

func (m model) prefixBefore(i uint64) []raft.Entry {
	var p []raft.Entry
	for _, e := range m.log {
		if e.Index < i {
			p = append(p, e)
		}
	}
	return p
}

// crashOutcomes lists every state Load may return if a crash interrupts o,
// exactly as the contract allows, each passed through the recovery rule.
func (m model) crashOutcomes(o op) []model {
	out := []model{m, m.apply(o)}
	switch o.kind {
	case opAppend:
		// Old prefix plus any prefix of the new entries.
		for k := 0; k < len(o.entries); k++ {
			p := m
			p.log = append(m.prefixBefore(o.entries[0].Index), o.entries[:k]...)
			out = append(out, p)
		}
	case opInstallSnap:
		// New snapshot durable, old log not yet discarded.
		p := m
		s := o.snap
		p.snap = &s
		out = append(out, p)
	}
	for i := range out {
		out[i] = out[i].recover()
	}
	return out
}

// ---------------------------------------------------------------------------
// Operation generator: roughly what a Raft core does, plus some junk.
// ---------------------------------------------------------------------------

type gen struct {
	rng  *rand.Rand
	term uint64
	lim  limits
}

func (g *gen) data(maxLen int) []byte {
	var n int
	switch r := g.rng.IntN(100); {
	case r < 70:
		n = g.rng.IntN(33)
	case r < 95:
		n = 33 + g.rng.IntN(300)
	default:
		n = 300 + g.rng.IntN(3000)
	}
	n = min(n, maxLen)
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.rng.Uint32())
	}
	return b
}

func (g *gen) entries(start uint64, n int, termFor func(i uint64) uint64) []raft.Entry {
	es := make([]raft.Entry, n)
	for i := range es {
		idx := start + uint64(i)
		es[i] = raft.Entry{Index: idx, Term: termFor(idx), Type: raft.EntryType(g.rng.IntN(2)), Data: g.data(g.lim.maxEntry)}
	}
	return es
}

func (g *gen) next(m model) op {
	for {
		switch r := g.rng.IntN(100); {
		case r < 10:
			return g.hardState(m)
		case r < 62:
			return g.append(m)
		case r < 74:
			if o, ok := g.saveSnap(m); ok {
				return o
			}
		case r < 82:
			return g.installSnap(m)
		case r < 95:
			if o, ok := g.compact(m); ok {
				return o
			}
		default:
			return g.junk(m)
		}
	}
}

func (g *gen) hardState(m model) op {
	hs := m.hs
	if g.rng.IntN(3) > 0 {
		g.term += uint64(g.rng.IntN(2))
		hs.Term = max(hs.Term, g.term)
	}
	hs.VotedFor = []string{"", "pi", "vps", "laptop"}[g.rng.IntN(4)]
	return op{kind: opHardState, hs: hs}
}

func (g *gen) append(m model) op {
	next := m.next()
	lo := m.first()
	if m.snap != nil && lo <= m.snap.Meta.Index {
		lo = m.snap.Meta.Index + 1
	}
	n := 1 + g.rng.IntN(4)
	if g.rng.IntN(10) == 0 {
		n += g.rng.IntN(12)
	}
	switch r := g.rng.IntN(100); {
	case r < 70 || lo > next:
		return op{kind: opAppend, entries: g.entries(next, n, func(uint64) uint64 { return g.term })}
	case r < 92:
		// Conflict: a new leader overwrites part of the suffix.
		g.term++
		start := lo + g.rng.Uint64N(next-lo+1)
		return op{kind: opAppend, entries: g.entries(start, n, func(uint64) uint64 { return g.term })}
	default:
		// Entries that overlap the snapshot (trailing entries), possibly
		// starting before the compacted region. They must match it.
		if m.snap == nil || m.snap.Meta.Index == 0 {
			return op{kind: opAppend, entries: g.entries(next, n, func(uint64) uint64 { return g.term })}
		}
		s := m.snap.Meta
		start := max(1, s.Index-min(s.Index-1, g.rng.Uint64N(6)))
		start = min(start, next)
		cnt := int(s.Index-start) + 1 + g.rng.IntN(3)
		return op{kind: opAppend, entries: g.entries(start, cnt, func(i uint64) uint64 {
			if i <= s.Index {
				return s.Term
			}
			return max(g.term, s.Term)
		})}
	}
}

func (g *gen) saveSnap(m model) (op, bool) {
	var meta raft.SnapshotMeta
	switch {
	case len(m.log) > 0:
		lo := m.log[0].Index
		if m.snap != nil && g.rng.IntN(4) > 0 {
			lo = max(lo, m.snap.Meta.Index) // usually move forward
		}
		hi := m.log[len(m.log)-1].Index
		i := lo + g.rng.Uint64N(hi-lo+1)
		t, _ := m.termAt(i)
		meta = raft.SnapshotMeta{Index: i, Term: t}
	case m.snap != nil:
		meta = m.snap.Meta
	default:
		return op{}, false
	}
	return op{kind: opSaveSnap, snap: raft.Snapshot{Meta: meta, Data: g.data(1 << 20)}}, true
}

func (g *gen) installSnap(m model) op {
	lo := max(1, m.first()-min(m.first()-1, 2))
	i := lo + g.rng.Uint64N(m.next()+6-lo)
	t, ok := m.termAt(i)
	if !ok || g.rng.IntN(2) == 0 {
		t = g.term + uint64(g.rng.IntN(2))
	}
	g.term = max(g.term, t)
	return op{kind: opInstallSnap, snap: raft.Snapshot{Meta: raft.SnapshotMeta{Index: i, Term: t}, Data: g.data(1 << 20)}}
}

func (g *gen) compact(m model) (op, bool) {
	if m.snap == nil {
		return op{}, false
	}
	lo := m.first() - 1
	hi := m.snap.Meta.Index
	if lo > hi {
		lo = hi
	}
	through := hi
	if g.rng.IntN(3) == 0 {
		through = lo + g.rng.Uint64N(hi-lo+1)
	}
	return op{kind: opCompact, through: through}, true
}

// junk produces operations that are often invalid, to check that the store
// rejects exactly what the model rejects, without I/O and without breaking.
func (g *gen) junk(m model) op {
	next := m.next()
	switch g.rng.IntN(7) {
	case 0: // gap
		return op{kind: opAppend, entries: g.entries(next+1+g.rng.Uint64N(3), 2, func(uint64) uint64 { return g.term })}
	case 1: // not contiguous
		es := g.entries(next, 3, func(uint64) uint64 { return g.term })
		es[2].Index++
		return op{kind: opAppend, entries: es}
	case 2: // index 0
		return op{kind: opAppend, entries: g.entries(0, 1, func(uint64) uint64 { return g.term })}
	case 3: // compact beyond the snapshot (or without one)
		var si uint64
		if m.snap != nil {
			si = m.snap.Meta.Index
		}
		return op{kind: opCompact, through: si + 1 + g.rng.Uint64N(3)}
	case 4: // snapshot with a term that does not match the log
		o := g.installSnap(m)
		o.kind = opSaveSnap
		return o
	case 5: // trailing entries that disagree with the snapshot
		if m.snap != nil && m.snap.Meta.Index > 0 {
			s := m.snap.Meta
			return op{kind: opAppend, entries: g.entries(s.Index, 2, func(uint64) uint64 { return s.Term + 1 })}
		}
		return g.append(m)
	default: // oversized entry
		es := g.entries(next, 1, func(uint64) uint64 { return g.term })
		es[0].Data = make([]byte, g.lim.maxEntry+1)
		return op{kind: opAppend, entries: es}
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const testDir = "/vault/data"

type harness struct {
	t     testing.TB
	seed  uint64
	rng   *rand.Rand
	fs    *memFS
	k     *knobs
	m     model
	st    *Store
	g     *gen
	where string // context for failure messages

	crashes, recoveryCrashes, injected, invalid, ops int
	outcomeHits                                      map[string]int
}

func newHarness(t testing.TB, seed uint64) *harness {
	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	k := &knobs{salt: rng.Uint64, lim: defaultLimits()}
	if rng.IntN(3) == 0 {
		// Small limits force Appends that span several records.
		k.lim = limits{maxEntry: 1200, maxRecord: 1200 + entHeaderSize + 400}
	} else {
		k.lim = limits{maxEntry: 64 << 10, maxRecord: 64<<10 + entHeaderSize + recordSlack}
	}
	return &harness{t: t, seed: seed, rng: rng, fs: newMemFS(testDir), k: k,
		g: &gen{rng: rng, lim: k.lim}, outcomeHits: map[string]int{}}
}

func (h *harness) fatalf(format string, args ...any) {
	h.t.Helper()
	h.t.Fatalf("seed %d (rerun with FILESTORE_CRASH_SEED=%d): %s: %s\nfilesystem:\n%s",
		h.seed, h.seed, h.where, fmt.Sprintf(format, args...), h.fs.describe())
}

// open opens and loads the store, possibly crashing during recovery, and
// checks the result is one of outcomes. It sets h.m to the matching outcome
// and returns its position in outcomes.
func (h *harness) open(outcomes []model, allowRecoveryCrash bool) int {
	h.t.Helper()
	for attempt := 0; ; attempt++ {
		if allowRecoveryCrash && attempt < 3 && h.rng.IntN(4) == 0 {
			h.fs.crashAt = h.fs.steps + 1 + h.rng.IntN(6)
			h.fs.crashPerform = h.rng.IntN(2) == 0
		}
		st, err := open(h.fs, testDir, Options{}, h.k)
		var hs raft.HardState
		var snap *raft.Snapshot
		var ents []raft.Entry
		if err == nil {
			hs, snap, ents, err = st.Load()
		}
		h.fs.crashAt = 0
		if errors.Is(err, errCrashed) {
			h.recoveryCrashes++
			if st != nil {
				st.Close()
			}
			h.fs = h.fs.Crash(h.rng, crashRandom)
			continue
		}
		if err != nil {
			h.fatalf("load failed: %v", err)
		}
		if err := checkStructure(snap, ents); err != nil {
			h.fatalf("Load broke its structural guarantees: %v", err)
		}
		if len(st.recovery.fellBackFrom) > 0 {
			h.fatalf("Load fell back past snapshots %v, but crashes must never corrupt a snapshot", st.recovery.fellBackFrom)
		}
		matched := -1
		for i, o := range outcomes {
			if equalState(o, hs, snap, ents) {
				matched = i
				break
			}
		}
		if matched < 0 {
			var sb strings.Builder
			for i, o := range outcomes {
				fmt.Fprintf(&sb, "\n  allowed[%d]: %s", i, o)
			}
			h.fatalf("Load returned a state the contract does not allow:\n  got:        %s%s",
				model{hs: hs, snap: snap, log: ents}, sb.String())
		}
		h.m = outcomes[matched]
		h.checkDisk()
		h.st = st
		return matched
	}
}

// checkDisk verifies what Load left on disk: no temp files, a WAL with no
// torn tail, and a WAL that parses to exactly the loaded log.
func (h *harness) checkDisk() {
	h.t.Helper()
	for _, n := range h.fs.names() {
		if strings.HasSuffix(n, tmpSuffix) {
			h.fatalf("temporary file %s left after Open", n)
		}
	}
	b, ok := h.fs.fileData(walFileName)
	if !ok {
		h.fatalf("no wal after Load")
	}
	w, err := parseWAL(b, h.k.lim)
	if err != nil {
		h.fatalf("wal does not parse after Load: %v", err)
	}
	if w.torn || w.end != int64(len(b)) {
		h.fatalf("wal still has a torn tail after Load (end %d, size %d)", w.end, len(b))
	}
	got := model{hs: h.m.hs, snap: h.m.snap, log: w.entries}.recover()
	if !equalState(h.m, got.hs, got.snap, got.log) {
		h.fatalf("wal on disk does not match the loaded log after repair: %s", got)
	}
}

// crashAndRecover simulates a power failure while inFlight (or nothing)
// was running.
func (h *harness) crashAndRecover(outcomes []model) int {
	h.t.Helper()
	h.crashes++
	h.st.Close()
	mode := crashMode(h.rng.IntN(5)) // mostly random, sometimes the extremes
	if mode > crashKeepAll {
		mode = crashRandom
	}
	h.fs = h.fs.Crash(h.rng, mode)
	return h.open(outcomes, true)
}

func (h *harness) cleanRestart() {
	h.t.Helper()
	if err := h.st.Close(); err != nil {
		h.fatalf("close: %v", err)
	}
	h.open([]model{h.m}, false)
}

func (h *harness) step(i int) {
	h.t.Helper()
	switch r := h.rng.IntN(100); {
	case r < 3:
		h.where = fmt.Sprintf("op %d: clean restart", i)
		h.cleanRestart()
		return
	case r < 6:
		h.where = fmt.Sprintf("op %d: crash while idle", i)
		h.crashAndRecover([]model{h.m})
		return
	}
	o := h.g.next(h.m)
	h.where = fmt.Sprintf("op %d: %s", i, o)
	h.ops++
	switch {
	case h.rng.IntN(6) == 0:
		h.fs.crashAt = h.fs.steps + 1 + h.rng.IntN(8)
		h.fs.crashPerform = h.rng.IntN(2) == 0
	case h.rng.IntN(30) == 0:
		h.fs.failAt = h.fs.steps + 1 + h.rng.IntN(6)
		h.fs.failPerform = h.rng.IntN(2) == 0
		h.fs.failErr = errInjected
	}
	err := o.run(h.st)
	h.fs.crashAt, h.fs.failAt = 0, 0
	valid := h.m.valid(o, h.k.lim)
	switch {
	case err == nil:
		if !valid {
			h.fatalf("store accepted an operation the model rejects")
		}
		h.m = h.m.apply(o)
		if h.fs.crashed {
			// The crash hit a best-effort step (deleting old snapshots)
			// after the operation was already durable.
			h.crashAndRecover([]model{h.m})
		}
	case errors.Is(err, errInvalid):
		h.invalid++
		if valid {
			h.fatalf("store rejected a valid operation: %v", err)
		}
		if h.fs.crashed {
			h.fatalf("invalid operation performed I/O")
		}
	default:
		if !valid {
			h.fatalf("invalid operation failed with an I/O error instead of being rejected: %v", err)
		}
		if !errors.Is(err, errCrashed) && !errors.Is(err, errInjected) {
			h.fatalf("unexpected error: %v", err)
		}
		if errors.Is(err, errInjected) {
			h.injected++
			// The store must refuse to continue after an I/O failure.
			if err := h.st.SaveHardState(raft.HardState{Term: math.MaxUint64, VotedFor: "x"}); err == nil {
				h.fatalf("store kept working after an I/O error")
			}
		}
		i := h.crashAndRecover(h.m.crashOutcomes(o))
		h.outcomeHits[fmt.Sprintf("%s:%s", opNames[o.kind], [...]string{"old", "new", "partial"}[min(i, 2)])]++
	}
}

var opNames = [...]string{"SaveHardState", "Append", "SaveSnapshot", "InstallSnapshot", "Compact"}

func runCrashSeed(t testing.TB, seed uint64, nops int) *harness {
	h := newHarness(t, seed)
	h.where = "initial open"
	h.open([]model{{}}, true)
	for i := 0; i < nops; i++ {
		h.step(i)
	}
	h.where = "final clean restart"
	h.cleanRestart()
	h.st.Close()
	return h
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil {
			return n
		}
	}
	return def
}
