package raft

import "fmt"

// raftLog is a node's in-memory copy of its log.
//
// It starts with a "dummy" position (offset, offsetTerm): the last entry that
// has been compacted away (or the snapshot position), whose term is still
// known so that the AppendEntries consistency check works at the boundary.
// entries holds offset+1 .. lastIndex.
//
// Entries with Index >= unstable exist only in memory. The core hands them to
// the driver in a ready, the driver persists them before sending any message
// of that ready that depends on them (a leader's MsgApps carrying them may go
// out first; see ready.takeEarly), and advance() marks them stable. The
// leader counts only stable entries towards its own vote when deciding
// commitment.
//
// Slices handed out (messages, readies) are capacity-limited, and truncation
// always copies into a fresh array, so nothing outside the log ever observes
// an entry being overwritten in place.
type raftLog struct {
	offset     uint64
	offsetTerm uint64
	entries    []Entry
	unstable   uint64
}

func newRaftLog(offset, offsetTerm uint64, ents []Entry) raftLog {
	l := raftLog{offset: offset, offsetTerm: offsetTerm}
	l.entries = append([]Entry(nil), ents...)
	l.unstable = l.lastIndex() + 1
	return l
}

func (l *raftLog) lastIndex() uint64 { return l.offset + uint64(len(l.entries)) }

func (l *raftLog) lastTerm() uint64 {
	if len(l.entries) == 0 {
		return l.offsetTerm
	}
	return l.entries[len(l.entries)-1].Term
}

// stableIndex is the highest index known to be durable.
func (l *raftLog) stableIndex() uint64 { return l.unstable - 1 }

// term returns the term of entry i, if it is known (offset <= i <= last).
func (l *raftLog) term(i uint64) (uint64, bool) {
	if i == l.offset {
		return l.offsetTerm, true
	}
	if i < l.offset || i > l.lastIndex() {
		return 0, false
	}
	return l.entries[i-l.offset-1].Term, true
}

func (l *raftLog) matchTerm(i, t uint64) bool {
	lt, ok := l.term(i)
	return ok && lt == t
}

// slice returns entries [lo, hi), stopping once maxBytes is exceeded but
// always returning at least one entry when lo < hi. maxBytes <= 0 means
// unlimited.
func (l *raftLog) slice(lo, hi uint64, maxBytes int) []Entry {
	if lo >= hi {
		return nil
	}
	if lo <= l.offset || hi > l.lastIndex()+1 {
		panic(fmt.Sprintf("raft: slice [%d, %d) out of range (%d, %d]", lo, hi, l.offset, l.lastIndex()))
	}
	a, b := lo-l.offset-1, hi-l.offset-1
	if maxBytes > 0 {
		size := 0
		for i := a; i < b; i++ {
			size += entrySize(l.entries[i])
			if size > maxBytes && i > a {
				b = i
				break
			}
		}
	}
	return l.entries[a:b:b]
}

func entrySize(e Entry) int { return len(e.Data) + 24 }

func (l *raftLog) unstableEntries() []Entry {
	if l.unstable > l.lastIndex() {
		return nil
	}
	return l.slice(l.unstable, l.lastIndex()+1, 0)
}

// append adds entries at the end of the log (leader path; no truncation).
func (l *raftLog) append(ents ...Entry) {
	if len(ents) == 0 {
		return
	}
	if ents[0].Index != l.lastIndex()+1 {
		panic(fmt.Sprintf("raft: append at %d, last index %d", ents[0].Index, l.lastIndex()))
	}
	l.entries = append(l.entries, ents...)
}

// truncateAndAppend replaces the suffix starting at ents[0].Index with ents.
// The caller guarantees that ents[0].Index is above the commit index, which
// is the only thing that makes discarding entries safe.
func (l *raftLog) truncateAndAppend(ents []Entry) {
	first := ents[0].Index
	switch {
	case first == l.lastIndex()+1:
		l.entries = append(l.entries, ents...)
	case first <= l.offset || first > l.lastIndex()+1:
		panic(fmt.Sprintf("raft: truncateAndAppend at %d outside (%d, %d]", first, l.offset, l.lastIndex()+1))
	default:
		keep := l.entries[:first-l.offset-1]
		fresh := make([]Entry, 0, len(keep)+len(ents))
		fresh = append(fresh, keep...)
		l.entries = append(fresh, ents...)
	}
	if first < l.unstable {
		l.unstable = first
	}
}

func (l *raftLog) stableTo(i uint64) {
	if i+1 > l.unstable {
		l.unstable = i + 1
	}
}

// compact drops entries up to and including through, keeping its term as the
// new dummy position.
func (l *raftLog) compact(through uint64) {
	if through <= l.offset {
		return
	}
	t, ok := l.term(through)
	if !ok || through > l.stableIndex() {
		panic(fmt.Sprintf("raft: compact(%d) beyond stable log (offset %d, stable %d)", through, l.offset, l.stableIndex()))
	}
	l.entries = append([]Entry(nil), l.entries[through-l.offset:]...)
	l.offset, l.offsetTerm = through, t
}

// restore replaces the whole log with a snapshot position.
func (l *raftLog) restore(index, term uint64) {
	l.entries = nil
	l.offset, l.offsetTerm = index, term
	l.unstable = index + 1
}
