package chaos

// The Porcupine model.
//
// WHAT IS MODELLED. Each item is an independent register whose value is the
// IDENTITY OF THE WRITE that produced its current content ("" = the item
// does not exist). Every put carries a blob naming its own write id, so a
// read tells us exactly which write it observed, and the harness always
// knows which write produced a version it bases a CAS on (it learned the
// version either from that write's acknowledgement or from a read showing
// that write's blob). The API operations then map onto compare-and-set:
//
//	PUT  base_version=0          CAS(expect = absent,          new = this write)
//	PUT  base_version=v          CAS(expect = write that made v, new = this write)
//	DELETE base_version=v        CAS(expect = write that made v, new = absent)
//	GET  /v1/sync (one item)     read -> write id or absent
//
// A successful CAS requires the register to hold the expected write at its
// linearization point. A 409 version_conflict requires that it did NOT, and
// when the conflict reports current_version c: c = 0 means absent; a c the
// harness can map to a write (from any acknowledgement or read in the run)
// must be the register's write; a c it cannot map must at least not be the
// version of some other known write.
//
// An operation with an unknown outcome (the client never got a definite
// answer and could not resolve it) may take effect at ANY point after its
// invocation or not at all: its Return is set past the end of the history
// and Step lets it either succeed (if the expectation holds there) or do
// nothing. Porcupine can always linearize it last, which is "never
// happened". An unknown put whose blob some read later showed certainly
// happened; it is entered as a success that returned no later than the
// first read that showed it.
//
// Histories are partitioned per item (Porcupine is exponential in
// concurrency, linear in partitions), which is sound because every
// operation touches one item: a sync is entered as one read per item it
// showed, all with the sync's interval.
//
// WHAT THIS PROVES: per item, there is a total order of all recorded
// operations, consistent with their real-time order, in which every read
// returns the latest write, every successful CAS saw its expected value and
// every conflict did not; idempotent retries took effect at most once; no
// acknowledged write was lost or applied twice.
//
// WHAT IT DOES NOT PROVE: atomicity ACROSS items of one sync (it is split
// per item; the rev-oracle checks in check.go cover cross-item snapshot
// consistency); anything about consistency=stale reads (checked separately,
// against weaker properties); the other API operations (vaults, members,
// accounts are only exercised during setup); durability against power loss
// (kills are process crashes; the OS keeps what was written). Unknown
// outcomes weaken the check locally: the more of them, the more freedom the
// checker has, which is why the workload retries with the same key and
// resolves them after the heal.

import (
	"fmt"
	"hash/fnv"
	"maps"
	"slices"

	"github.com/anishathalye/porcupine"
)

// CASInput is the Porcupine input of one operation.
type CASInput struct {
	Op     string `json:"op"` // read | put | delete
	Item   string `json:"item"`
	Expect string `json:"expect,omitempty"` // put/delete: expected write id ("" = absent)
	Write  string `json:"write,omitempty"`  // put: new write id
	Base   uint64 `json:"base,omitempty"`   // for descriptions
	Rec    int    `json:"rec"`              // OpRecord.ID, for descriptions and artifacts
}

// CASOutput is the Porcupine output of one operation.
type CASOutput struct {
	Unknown  bool   `json:"unknown,omitempty"`
	OK       bool   `json:"ok,omitempty"`
	Conflict bool   `json:"conflict,omitempty"`
	HasCur   bool   `json:"has_cur,omitempty"`
	Cur      uint64 `json:"cur,omitempty"`
	Value    string `json:"value,omitempty"`   // read: write id ("" = absent)
	Version  uint64 `json:"version,omitempty"` // read: version seen; put ok: new version
}

// VersionIndex maps versions to writes (from every acknowledgement and
// read of the run). The bijection check verifies it is consistent; the
// model only consults it to interpret conflict responses.
type VersionIndex struct {
	WriteVersion  map[string]uint64
	VersionWriter map[uint64]string
}

// conflictMatches reports whether a register holding write `state` is
// consistent with a conflict that reported current version cur.
func (ix *VersionIndex) conflictMatches(state string, cur uint64) bool {
	if cur == 0 {
		return state == ""
	}
	if state == "" {
		return false
	}
	if v, ok := ix.WriteVersion[state]; ok {
		return v == cur
	}
	if w, ok := ix.VersionWriter[cur]; ok {
		return w == state
	}
	return true // neither side known: nothing to contradict
}

// NewCASModel returns the per-item CAS-register model.
func NewCASModel(ix *VersionIndex) porcupine.Model {
	return porcupine.Model{
		Partition: func(history []porcupine.Operation) [][]porcupine.Operation {
			by := map[string][]porcupine.Operation{}
			for _, op := range history {
				k := op.Input.(CASInput).Item
				by[k] = append(by[k], op)
			}
			out := make([][]porcupine.Operation, 0, len(by))
			for _, k := range slices.Sorted(maps.Keys(by)) {
				out = append(out, by[k])
			}
			return out
		},
		Init: func() any { return "" },
		Step: func(state, input, output any) (bool, any) {
			st := state.(string)
			in := input.(CASInput)
			out := output.(CASOutput)
			switch in.Op {
			case KindRead:
				return out.Value == st, st
			case KindPut, KindDelete:
				next := in.Write
				if in.Op == KindDelete {
					next = ""
				}
				matches := st == in.Expect
				switch {
				case out.Unknown:
					if matches {
						return true, next
					}
					return true, st
				case out.OK:
					return matches, next
				case out.Conflict:
					if matches {
						return false, st
					}
					if out.HasCur && !ix.conflictMatches(st, out.Cur) {
						return false, st
					}
					return true, st
				}
			}
			return false, st
		},
		Equal: func(a, b any) bool { return a.(string) == b.(string) },
		Hash: func(s any) uint64 {
			h := fnv.New64a()
			h.Write([]byte(s.(string)))
			return h.Sum64()
		},
		DescribeOperation: func(input, output any) string {
			in := input.(CASInput)
			out := output.(CASOutput)
			res := "?"
			switch {
			case out.Unknown:
				res = "unknown"
			case in.Op == KindRead:
				res = orAbsent(out.Value)
				if out.Version != 0 {
					res += fmt.Sprintf("@%d", out.Version)
				}
			case out.OK && in.Op == KindPut:
				res = fmt.Sprintf("ok v%d", out.Version)
			case out.OK:
				res = "ok"
			case out.Conflict && out.HasCur:
				res = fmt.Sprintf("conflict(cur=%d)", out.Cur)
			case out.Conflict:
				res = "conflict"
			}
			switch in.Op {
			case KindRead:
				return fmt.Sprintf("#%d read(%s) -> %s", in.Rec, in.Item, res)
			case KindPut:
				return fmt.Sprintf("#%d put(%s, base=%d:%s -> %s) -> %s", in.Rec, in.Item, in.Base, orAbsent(in.Expect), in.Write, res)
			default:
				return fmt.Sprintf("#%d delete(%s, base=%d:%s) -> %s", in.Rec, in.Item, in.Base, orAbsent(in.Expect), res)
			}
		},
		DescribeState: func(s any) string { return orAbsent(s.(string)) },
	}
}

// BuildPorcupineHistory turns records into Porcupine operations. end is a
// timestamp after every recorded event; unknown operations return there.
//
// replaced (optional) maps a write id E to the earliest time by which some
// operation that replaced E (a write based on E's version that certainly
// took effect) had returned. An unknown CAS that expects E and was invoked
// after that time can only ever be linearized as a failed CAS: the
// register never holds E again (write ids are unique; a second application
// of E would be caught by the bijection check), so the operation has no
// effect and, its output being unknown, no constraint. Such operations are
// dropped: Porcupine's search is exponential in operations that stay open
// to the end of the history, and dropping a provable no-op cannot change
// the verdict. Operations whose write some read showed are never dropped.
// The second result is the number dropped.
func BuildPorcupineHistory(recs []*OpRecord, end int64, replaced map[string]int64) ([]porcupine.Operation, int) {
	pruned := 0
	// First (earliest-returning) read that showed each write.
	firstSeen := map[string]int64{}
	for _, r := range recs {
		if (r.Kind != KindRead && r.Kind != KindStaleRead) || r.Outcome != OutOK {
			continue
		}
		for _, o := range r.Reads {
			if o.Present && o.Write != "" {
				if t, ok := firstSeen[o.Write]; !ok || r.Return < t {
					firstSeen[o.Write] = r.Return
				}
			}
		}
	}
	var ops []porcupine.Operation
	for _, r := range recs {
		switch {
		case r.linearizableRead():
			for _, o := range r.Reads {
				if o.Bad != "" {
					// Not a value any write produced; the bijection check
					// reports it. Entering it would only confuse the
					// visualization.
					continue
				}
				ops = append(ops, porcupine.Operation{ClientId: r.Client,
					Input:  CASInput{Op: KindRead, Item: o.Item, Rec: r.ID},
					Output: CASOutput{Value: o.Write, Version: o.Version},
					Call:   r.Call, Return: r.Return})
			}
		case r.isWrite() && (r.Outcome == OutOK || r.Outcome == OutConflict || r.Outcome == OutUnknown):
			in := CASInput{Op: r.Kind, Item: r.Item, Expect: r.Expect, Write: r.Write, Base: r.Base, Rec: r.ID}
			var out CASOutput
			ret := r.Return
			switch r.Outcome {
			case OutOK:
				out = CASOutput{OK: true, Version: r.Version}
			case OutConflict:
				out = CASOutput{Conflict: true}
				if r.CurVer != nil {
					out.HasCur, out.Cur = true, *r.CurVer
				}
			case OutUnknown:
				out = CASOutput{Unknown: true}
				ret = end
				if t, ok := firstSeen[r.Write]; ok && r.Kind == KindPut && t >= r.Call {
					out = CASOutput{OK: true}
					ret = t
				} else if t, ok := replaced[r.Expect]; ok && r.Expect != "" && t < r.Call {
					pruned++
					continue
				}
			}
			ops = append(ops, porcupine.Operation{ClientId: r.Client, Input: in, Output: out, Call: r.Call, Return: ret})
		}
	}
	return ops, pruned
}
