package raft

import "fmt"

// driver carries out the durable and state-machine side of a ready. Both the
// real node runtime and the deterministic simulator use it, so the
// persistence order the simulator verifies is the one production runs.
type driver struct {
	id        string
	storage   Storage
	sm        StateMachine
	threshold uint64 // snapshot after this many applied entries since the last snapshot
	trailing  uint64 // entries kept behind a snapshot

	applied   uint64 // index of the last entry applied (or restored from a snapshot)
	snapIndex uint64 // index of the latest durable snapshot
	compacted uint64 // storage holds no entries at or below this index
}

// restart loads st, restores sm from the latest snapshot (entries after it
// are re-applied as they are learned to be committed) and returns the core
// and driver that carry on from there. The node runtime and the simulator
// both start and restart through it.
func restart(cfg coreConfig, st Storage, sm StateMachine, threshold, trailing uint64) (*core, driver, error) {
	hs, snap, ents, err := st.Load()
	if err != nil {
		return nil, driver{}, fmt.Errorf("raft: load storage: %w", err)
	}
	if snap != nil {
		if err := sm.Restore(snap.Data); err != nil {
			return nil, driver{}, fmt.Errorf("raft: restore snapshot %d: %w", snap.Meta.Index, err)
		}
	}
	c, err := newCore(cfg, hs, snap, ents)
	if err != nil {
		return nil, driver{}, err
	}
	return c, driver{id: cfg.id, storage: st, sm: sm, threshold: threshold, trailing: trailing,
		applied: c.applying, snapIndex: c.snapshotIndex(), compacted: c.log.offset}, nil
}

// localResult is the apply result of a local proposal.
type localResult struct {
	id    uint64
	index uint64
	data  []byte
}

type processed struct {
	local []localResult
	msgs  []Message // to send now: rd.messages not sent early, plus MsgPropResp for proposals forwarded to us
}

// process persists and applies rd. The order matters:
//
//  0. the messages ready.takeEarly allows (a leader's MsgApps, heartbeat
//     acknowledgements) go to sendEarly before anything is written;
//  1. hard state, so a durable log never has entries from a term newer
//     than the durable term;
//  2. snapshot install (storage first, then Restore), which must precede
//     applying anything after it;
//  3. apply committed entries; they were durable before this ready, so this
//     does not have to wait for step 4;
//  4. append new entries.
//
// The caller sends out.msgs only after process returns successfully, then
// calls core.advance(rd).
func (d *driver) process(rd *ready, sendEarly func([]Message)) (out processed, err error) {
	if early := rd.takeEarly(); len(early) > 0 {
		sendEarly(early)
	}
	out.msgs = rd.messages
	if rd.hardState != nil {
		if err := d.storage.SaveHardState(*rd.hardState); err != nil {
			return out, fmt.Errorf("save hard state: %w", err)
		}
	}
	if s := rd.snapshot; s != nil {
		if err := d.storage.InstallSnapshot(*s); err != nil {
			return out, fmt.Errorf("install snapshot %d: %w", s.Meta.Index, err)
		}
		if err := d.sm.Restore(s.Data); err != nil {
			return out, fmt.Errorf("restore snapshot %d: %w", s.Meta.Index, err)
		}
		d.applied, d.snapIndex, d.compacted = s.Meta.Index, s.Meta.Index, s.Meta.Index
	}
	wi := 0
	for _, e := range rd.committed {
		if e.Index <= d.applied {
			return out, fmt.Errorf("raft: entry %d handed out for application twice (applied %d)", e.Index, d.applied)
		}
		var res []byte
		if e.Type == EntryNormal {
			res = d.sm.Apply(e.Index, e.Data)
		}
		d.applied = e.Index
		for ; wi < len(rd.waiters) && rd.waiters[wi].index == e.Index; wi++ {
			w := rd.waiters[wi]
			if w.from == "" {
				out.local = append(out.local, localResult{id: w.id, index: e.Index, data: res})
			} else {
				out.msgs = append(out.msgs, Message{Type: MsgPropResp, From: d.id, To: w.from, RequestID: w.id, Index: e.Index, Data: res})
			}
		}
	}
	if len(rd.entries) > 0 {
		if err := d.storage.Append(rd.entries); err != nil {
			return out, fmt.Errorf("append entries %d..%d: %w", rd.entries[0].Index, rd.entries[len(rd.entries)-1].Index, err)
		}
	}
	return out, nil
}

// maybeSnapshot takes a local snapshot once enough entries have been applied
// since the last one, makes it durable, compacts storage behind it and tells
// the core. Called after advance, never concurrently with Apply.
func (d *driver) maybeSnapshot(c *core) error {
	if d.threshold == 0 || d.applied < d.snapIndex+d.threshold || d.applied <= c.snapshotIndex() {
		return nil
	}
	term, ok := c.log.term(d.applied)
	if !ok {
		return nil
	}
	data, err := d.sm.Snapshot()
	if err != nil {
		return fmt.Errorf("state machine snapshot at %d: %w", d.applied, err)
	}
	snap := &Snapshot{Meta: SnapshotMeta{Index: d.applied, Term: term}, Data: data}
	if err := d.storage.SaveSnapshot(*snap); err != nil {
		return fmt.Errorf("save snapshot %d: %w", snap.Meta.Index, err)
	}
	d.snapIndex = snap.Meta.Index
	var compactTo uint64
	if d.applied > d.trailing {
		compactTo = d.applied - d.trailing
	}
	if compactTo > d.compacted {
		if err := d.storage.Compact(compactTo); err != nil {
			return fmt.Errorf("compact through %d: %w", compactTo, err)
		}
		d.compacted = compactTo
	}
	c.compact(snap, compactTo)
	return nil
}
