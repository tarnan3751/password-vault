package raft

import (
	"bytes"
	"fmt"
	"sync"
)

// MemStorage is an in-memory Storage for tests and development. Every method
// takes effect atomically, so "durable" means "the method returned nil".
// It outlives the node that uses it: a test can stop a node and start a new
// one on the same MemStorage to simulate a restart that keeps exactly what
// was persisted. Close does not discard anything.
//
// All data is copied on the way in and out, so callers can never alias the
// stored state.
type MemStorage struct {
	mu   sync.Mutex
	hs   HardState
	snap *Snapshot
	ents []Entry // contiguous; may start at or before snap.Meta.Index (trailing entries)
}

// NewMemStorage returns an empty store.
func NewMemStorage() *MemStorage { return &MemStorage{} }

var _ Storage = (*MemStorage)(nil)

func (s *MemStorage) Load() (HardState, *Snapshot, []Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var snap *Snapshot
	if s.snap != nil {
		c := copySnapshot(*s.snap)
		snap = &c
	}
	ents := s.ents
	if snap != nil && len(ents) > 0 {
		// The recovery rule from the Storage contract. MemStorage never
		// produces an inconsistent state itself, but the simulator plants
		// one (a crash inside InstallSnapshot). Like filestore, discarding
		// also repairs the stored state, so later appends do not see it.
		f := ents[0].Index
		switch {
		case f == snap.Meta.Index+1:
		case f <= snap.Meta.Index:
			k := snap.Meta.Index - f
			if k >= uint64(len(ents)) || ents[k].Term != snap.Meta.Term {
				s.ents, ents = nil, nil
			}
		default:
			return HardState{}, nil, nil, fmt.Errorf("memstorage: gap between snapshot %d and log start %d", snap.Meta.Index, f)
		}
	}
	return s.hs, snap, copyEntries(ents), nil
}

func (s *MemStorage) SaveHardState(hs HardState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hs = hs
	return nil
}

func (s *MemStorage) lastIndexLocked() uint64 {
	if n := len(s.ents); n > 0 {
		return s.ents[n-1].Index
	}
	if s.snap != nil {
		return s.snap.Meta.Index
	}
	return 0
}

func (s *MemStorage) Append(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Index != entries[i-1].Index+1 {
			return fmt.Errorf("memstorage: append not contiguous at %d", entries[i].Index)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	first := entries[0].Index
	last := s.lastIndexLocked()
	if first > last+1 {
		return fmt.Errorf("memstorage: append at %d leaves a gap after %d", first, last)
	}
	if first == 0 {
		return fmt.Errorf("memstorage: append at index 0")
	}
	if s.snap != nil && first <= s.snap.Meta.Index {
		return fmt.Errorf("memstorage: append at %d would rewrite entries covered by snapshot %d", first, s.snap.Meta.Index)
	}
	kept := s.ents
	if len(kept) > 0 {
		f := kept[0].Index
		if first < f {
			return fmt.Errorf("memstorage: append at %d before first stored entry %d", first, f)
		}
		kept = kept[:first-f]
	}
	merged := make([]Entry, 0, len(kept)+len(entries))
	merged = append(merged, kept...)
	s.ents = append(merged, copyEntries(entries)...)
	return nil
}

// SaveSnapshot enforces the same preconditions as the on-disk store: the
// snapshot must not be older than the stored one, and the log must provably
// continue it (contain Index with Term, or start exactly at Index+1);
// otherwise the recovery rule would discard acknowledged entries on the
// next Load.
func (s *MemStorage) SaveSnapshot(snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap != nil && snap.Meta.Index < s.snap.Meta.Index {
		return fmt.Errorf("memstorage: snapshot %d older than stored %d", snap.Meta.Index, s.snap.Meta.Index)
	}
	if !s.continuesLocked(snap.Meta) {
		return fmt.Errorf("memstorage: log does not continue snapshot %d/%d", snap.Meta.Index, snap.Meta.Term)
	}
	c := copySnapshot(snap)
	s.snap = &c
	return nil
}

func (s *MemStorage) continuesLocked(m SnapshotMeta) bool {
	if len(s.ents) == 0 {
		return s.snap != nil && s.snap.Meta == m
	}
	f := s.ents[0].Index
	if f == m.Index+1 {
		return true
	}
	if f > m.Index || m.Index-f >= uint64(len(s.ents)) {
		return false
	}
	return s.ents[m.Index-f].Term == m.Term
}

// InstallSnapshot enforces the on-disk store's precondition that the
// snapshot does not end before the first stored log entry
// (snap.Meta.Index+1 >= first index): a crash midway through such an install
// would leave a log that starts after the snapshot, which Load must treat as
// corruption. It also refuses to go back to an older snapshot.
func (s *MemStorage) InstallSnapshot(snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap != nil && snap.Meta.Index < s.snap.Meta.Index {
		return fmt.Errorf("memstorage: install of snapshot %d older than stored %d", snap.Meta.Index, s.snap.Meta.Index)
	}
	if len(s.ents) > 0 && snap.Meta.Index+1 < s.ents[0].Index {
		return fmt.Errorf("memstorage: install of snapshot %d before first log index %d", snap.Meta.Index, s.ents[0].Index)
	}
	c := copySnapshot(snap)
	s.snap = &c
	s.ents = nil
	return nil
}

func (s *MemStorage) Compact(through uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil || through > s.snap.Meta.Index {
		return fmt.Errorf("memstorage: compact through %d beyond snapshot", through)
	}
	if len(s.ents) == 0 || through < s.ents[0].Index {
		return nil
	}
	k := through - s.ents[0].Index + 1
	if k > uint64(len(s.ents)) {
		k = uint64(len(s.ents))
	}
	s.ents = append([]Entry(nil), s.ents[k:]...)
	return nil
}

// Close is a no-op; the contents survive for a later Load.
func (s *MemStorage) Close() error { return nil }

func copyEntries(ents []Entry) []Entry {
	if len(ents) == 0 {
		return nil
	}
	out := make([]Entry, len(ents))
	for i, e := range ents {
		e.Data = bytes.Clone(e.Data)
		out[i] = e
	}
	return out
}

func copySnapshot(s Snapshot) Snapshot {
	s.Data = bytes.Clone(s.Data)
	return s
}
