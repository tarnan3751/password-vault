package chaos

// Checks that do not rely on Porcupine.
//
// They use the system's own global revision as an oracle. Every successful
// item write gets version == the new global rev, a delete reports the rev
// it produced, and every sync reports the rev of the state it shows. In a
// correct system the rev order IS the order in which the state machine
// applied the writes, so:
//
//   - bijection: a version names one write of one item, forever, and a
//     read's blob is a write the harness actually issued and that did not
//     report failure;
//   - rev real-time order: if A returned before B was invoked, rev(B) >=
//     rev(A), strictly for a successful write B (this is where a stale read
//     passed off as linearizable shows up);
//   - read snapshots: a read at rev r showing item K at version v means no
//     known write or delete touched K in (v, r]; showing K absent means the
//     last known event on K at or before r was a delete. This holds for
//     stale reads too: a lagging node still shows a consistent prefix;
//   - chains: per item, the effective writes sorted by rev must form a
//     chain in which each one's base version is the previous one's result
//     (no CAS ever succeeded twice on the same version, no write was based
//     on a version that had already been replaced), ending in the final
//     state. Gaps are tolerated only where an unresolved unknown-outcome
//     operation on that item could fill them;
//   - acknowledged writes are final or provably superseded: the final state
//     is that write, a later version, or absent after a later delete.
//
// These checks are cheap (n log n) and complement Porcupine: they catch
// cross-item snapshot inconsistencies Porcupine cannot see (it checks each
// item alone), and Porcupine catches violations the system could hide by
// misreporting revs.

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/anishathalye/porcupine"
)

// Check is the result of one check.
type Check struct {
	Name       string   `json:"name"`
	Pass       bool     `json:"pass"`
	Skipped    bool     `json:"skipped,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Violations []string `json:"violations,omitempty"`
}

func (c *Check) fail(format string, args ...any) {
	c.Pass = false
	if len(c.Violations) < 50 {
		c.Violations = append(c.Violations, fmt.Sprintf(format, args...))
	} else if len(c.Violations) == 50 {
		c.Violations = append(c.Violations, "... (more violations omitted)")
	}
}

func newCheck(name string) *Check { return &Check{Name: name, Pass: true} }

// effOp is a write that certainly took effect, with its position in the
// rev order.
type effOp struct {
	rec     *OpRecord
	rev     uint64
	base    uint64
	del     bool
	version uint64 // put: new version (== rev)
}

type analysis struct {
	recs      []*OpRecord
	items     []string
	puts      map[string]*OpRecord // write id -> put record
	firstSeen map[string]*OpRecord // write id -> first read (by return) that showed it
	seenVer   map[string]uint64    // write id -> version a read showed it with
	eff       map[string][]effOp   // item -> effective ops by rev
	// Unknown-outcome operations nobody could resolve; they may fill gaps.
	openPuts, openDels map[string]int
	ix                 *VersionIndex
	final              map[string]ReadObs // item -> final state (first node's final reads)
	hasFinal           bool
}

func analyze(recs []*OpRecord, items []string) *analysis {
	a := &analysis{recs: recs, items: items, puts: map[string]*OpRecord{}, firstSeen: map[string]*OpRecord{},
		seenVer: map[string]uint64{}, eff: map[string][]effOp{}, openPuts: map[string]int{}, openDels: map[string]int{},
		ix: &VersionIndex{WriteVersion: map[string]uint64{}, VersionWriter: map[uint64]string{}}, final: map[string]ReadObs{}}
	for _, r := range recs {
		if r.Kind == KindPut {
			a.puts[r.Write] = r
		}
	}
	for _, r := range recs {
		if (r.Kind != KindRead && r.Kind != KindStaleRead) || r.Outcome != OutOK {
			continue
		}
		for _, o := range r.Reads {
			if !o.Present || o.Write == "" {
				continue
			}
			if f, ok := a.firstSeen[o.Write]; !ok || r.Return < f.Return {
				a.firstSeen[o.Write] = r
			}
			if _, ok := a.seenVer[o.Write]; !ok {
				a.seenVer[o.Write] = o.Version
			}
		}
	}
	for _, r := range recs {
		switch {
		case r.Kind == KindPut && r.Outcome == OutOK:
			a.eff[r.Item] = append(a.eff[r.Item], effOp{rec: r, rev: r.Version, base: r.Base, version: r.Version})
		case r.Kind == KindPut && r.Outcome == OutUnknown:
			if v, ok := a.seenVer[r.Write]; ok {
				a.eff[r.Item] = append(a.eff[r.Item], effOp{rec: r, rev: v, base: r.Base, version: v})
			} else {
				a.openPuts[r.Item]++
			}
		case r.Kind == KindDelete && r.Outcome == OutOK:
			a.eff[r.Item] = append(a.eff[r.Item], effOp{rec: r, rev: r.Rev, base: r.Base, del: true})
		case r.Kind == KindDelete && r.Outcome == OutUnknown:
			a.openDels[r.Item]++
		}
	}
	for k := range a.eff {
		ops := a.eff[k]
		sort.SliceStable(ops, func(i, j int) bool { return ops[i].rev < ops[j].rev })
	}
	// The final state as seen by the first node's final read of the user
	// who sees every item (convergence across nodes is checked
	// separately).
	for _, r := range recs {
		if r.Final && r.Outcome == OutOK && r.User == "alice" {
			for _, o := range r.Reads {
				a.final[o.Item] = o
			}
			a.hasFinal = true
			break
		}
	}
	return a
}

// checkBijection: a version, once observed for an item, always maps to the
// same content; every observed blob is a write the harness issued for that
// item and that did not report failure.
func (a *analysis) checkBijection() *Check {
	c := newCheck("version/content bijection")
	verItem := map[uint64]string{}
	note := func(version uint64, item, write, where string) {
		if version == 0 {
			c.fail("%s: version 0 for item %s", where, item)
			return
		}
		if it, ok := verItem[version]; ok && it != item {
			c.fail("%s: version %d belongs to item %s and item %s", where, version, it, item)
		}
		verItem[version] = item
		if write == "" {
			return
		}
		if w, ok := a.ix.VersionWriter[version]; ok && w != write {
			c.fail("%s: version %d of %s maps to write %s and to write %s", where, version, item, w, write)
		} else if !ok {
			a.ix.VersionWriter[version] = write
		}
		if v, ok := a.ix.WriteVersion[write]; ok && v != version {
			c.fail("%s: write %s of %s has version %d and version %d", where, write, item, v, version)
		} else if !ok {
			a.ix.WriteVersion[write] = version
		}
	}
	n := 0
	for _, r := range a.recs {
		switch {
		case r.Kind == KindPut && r.Outcome == OutOK:
			n++
			if r.Version != r.Rev {
				c.fail("#%d put %s: version %d != rev %d", r.ID, r.Item, r.Version, r.Rev)
			}
			if r.Base != 0 && r.Version <= r.Base {
				c.fail("#%d put %s: new version %d is not above base %d", r.ID, r.Item, r.Version, r.Base)
			}
			note(r.Version, r.Item, r.Write, fmt.Sprintf("#%d ack", r.ID))
		case r.Kind == KindDelete && r.Outcome == OutOK:
			if r.Rev <= r.Base {
				c.fail("#%d delete %s: rev %d is not above base %d", r.ID, r.Item, r.Rev, r.Base)
			}
		case r.isWrite() && r.Outcome == OutConflict && r.CurVer != nil && *r.CurVer != 0:
			note(*r.CurVer, r.Item, "", fmt.Sprintf("#%d conflict", r.ID))
		case (r.Kind == KindRead || r.Kind == KindStaleRead) && r.Outcome == OutOK:
			for _, o := range r.Reads {
				if o.Bad != "" {
					c.fail("#%d read on %s: item %s: %s", r.ID, r.Node, o.Item, o.Bad)
					continue
				}
				if !o.Present {
					continue
				}
				n++
				where := fmt.Sprintf("#%d read on %s", r.ID, r.Node)
				w := a.puts[o.Write]
				switch {
				case w == nil:
					c.fail("%s: item %s shows write %s that the harness never issued", where, o.Item, o.Write)
					continue
				case w.Item != o.Item:
					c.fail("%s: item %s shows write %s of item %s", where, o.Item, o.Write, w.Item)
				case w.Outcome == OutFailed:
					c.fail("%s: item %s shows write %s (#%d), which was reported as certainly not applied (%v)", where, o.Item, o.Write, w.ID, attemptsSummary(w))
				case w.Outcome == OutConflict:
					c.fail("%s: item %s shows write %s (#%d), which was answered with a version conflict", where, o.Item, o.Write, w.ID)
				case w.Outcome == OutError:
					c.fail("%s: item %s shows write %s (#%d), which was answered with an error (%s)", where, o.Item, o.Write, w.ID, w.Detail)
				}
				if r.Return < w.Call {
					c.fail("%s: write %s observed (read returned %s) before it was issued (%s)", where, o.Write, fmtNs(r.Return), fmtNs(w.Call))
				}
				note(o.Version, o.Item, o.Write, where)
			}
		}
	}
	c.Detail = fmt.Sprintf("%d observations, %d distinct versions", n, len(verItem))
	return c
}

func attemptsSummary(r *OpRecord) []string {
	var s []string
	for _, at := range r.Attempts {
		s = append(s, at.Node+":"+at.Result)
	}
	return s
}

// span is an operation with an interval and a value (a rev or a version).
type span struct {
	rec       *OpRecord
	call, ret int64 // ret is 0 for an operation whose return is unknown
	v         uint64
}

// sweepPrior visits every span of all in call order together with the
// highest value among the spans of done that returned strictly before it was
// called (and the record that carried it). Spans for which nothing had
// returned yet are not visited. A checker that wants "values never go back
// across non-overlapping operations" fails when b.v is below that maximum.
func sweepPrior(all, done []span, visit func(b span, maxV uint64, maxRec *OpRecord)) {
	byRet := slices.Clone(done)
	slices.SortFunc(byRet, func(x, y span) int { return cmp.Compare(x.ret, y.ret) })
	byCall := slices.Clone(all)
	slices.SortFunc(byCall, func(x, y span) int { return cmp.Compare(x.call, y.call) })
	j := 0
	var maxV uint64
	var maxRec *OpRecord
	for _, b := range byCall {
		for j < len(byRet) && byRet[j].ret < b.call {
			if byRet[j].v > maxV {
				maxV, maxRec = byRet[j].v, byRet[j].rec
			}
			j++
		}
		if maxRec != nil {
			visit(b, maxV, maxRec)
		}
	}
}

// checkRevOrder: revs respect real time.
func (a *analysis) checkRevOrder() *Check {
	c := newCheck("rev real-time order")
	var all, done []span
	for _, r := range a.recs {
		switch {
		case r.linearizableRead(), r.isWrite() && r.Outcome == OutOK:
			s := span{r, r.Call, r.Return, r.Rev}
			all, done = append(all, s), append(done, s)
		case r.Kind == KindPut && r.Outcome == OutUnknown:
			// Its return is unknown: it can only be the later operation.
			if v, ok := a.seenVer[r.Write]; ok {
				all = append(all, span{r, r.Call, 0, v})
			}
		}
	}
	sweepPrior(all, done, func(b span, maxRev uint64, maxRec *OpRecord) {
		if b.rec.isWrite() && b.v <= maxRev {
			c.fail("write #%d (%s) got rev %d, but #%d (%s) had already completed at rev %d", b.rec.ID, b.rec, b.v, maxRec.ID, maxRec, maxRev)
		}
		if !b.rec.isWrite() && b.v < maxRev {
			c.fail("read #%d on %s returned rev %d, but #%d (%s) had already completed at rev %d", b.rec.ID, b.rec.Node, b.v, maxRec.ID, maxRec, maxRev)
		}
	})
	c.Detail = fmt.Sprintf("%d operations with a known rev", len(all))
	return c
}

// checkReadMonotonic: versions of an item seen by linearizable reads in
// non-overlapping operations never decrease.
func (a *analysis) checkReadMonotonic() *Check {
	c := newCheck("read version monotonicity")
	per := map[string][]span{}
	total := 0
	for _, r := range a.recs {
		if !r.linearizableRead() {
			continue
		}
		for _, o := range r.Reads {
			if o.Present {
				per[o.Item] = append(per[o.Item], span{r, r.Call, r.Return, o.Version})
				total++
			}
		}
	}
	for item, list := range per {
		sweepPrior(list, list, func(b span, maxV uint64, maxR *OpRecord) {
			if b.v < maxV {
				c.fail("item %s: read #%d on %s saw version %d after read #%d on %s had seen %d", item, b.rec.ID, b.rec.Node, b.v, maxR.ID, maxR.Node, maxV)
			}
		})
	}
	c.Detail = fmt.Sprintf("%d item observations", total)
	return c
}

// checkReadSnapshots: every read (linearizable or stale) shows, for each
// item, the state the rev order implies at the read's rev.
func (a *analysis) checkReadSnapshots() *Check {
	c := newCheck("read snapshot consistency")
	n := 0
	for _, r := range a.recs {
		if (r.Kind != KindRead && r.Kind != KindStaleRead) || r.Outcome != OutOK {
			continue
		}
		for _, o := range r.Reads {
			if o.Bad != "" {
				continue
			}
			n++
			ops := a.eff[o.Item]
			if o.Present {
				if o.Version > r.Rev {
					c.fail("#%d %s on %s at rev %d shows %s at version %d > rev", r.ID, r.Kind, r.Node, r.Rev, o.Item, o.Version)
					continue
				}
				i := sort.Search(len(ops), func(i int) bool { return ops[i].rev > o.Version })
				if i < len(ops) && ops[i].rev <= r.Rev {
					c.fail("#%d %s on %s at rev %d shows %s@%d (%s), but #%d changed %s at rev %d", r.ID, r.Kind, r.Node, r.Rev, o.Item, o.Version, o.Write, ops[i].rec.ID, o.Item, ops[i].rev)
				}
				continue
			}
			i := sort.Search(len(ops), func(i int) bool { return ops[i].rev > r.Rev })
			if i > 0 && !ops[i-1].del && a.openDels[o.Item] == 0 {
				p := ops[i-1]
				c.fail("#%d %s on %s at rev %d shows %s absent, but #%d wrote it at rev %d and no later delete is known", r.ID, r.Kind, r.Node, r.Rev, o.Item, p.rec.ID, p.rev)
			}
		}
	}
	c.Detail = fmt.Sprintf("%d item observations", n)
	return c
}

// checkChains: per item, the effective writes in rev order form one CAS
// chain ending in the final state.
func (a *analysis) checkChains() *Check {
	c := newCheck("no forked or lost writes (CAS chains)")
	nOps := 0
	for _, item := range a.items {
		ops := a.eff[item]
		nOps += len(ops)
		var cur uint64 // 0 = absent
		replaced := map[uint64]*OpRecord{}
		var lastRev uint64
		for _, op := range ops {
			if op.rev == lastRev && lastRev != 0 {
				c.fail("item %s: #%d and another write both claim rev %d", item, op.rec.ID, op.rev)
			}
			lastRev = op.rev
			if op.base != cur {
				switch {
				case op.base != 0 && replaced[op.base] != nil:
					c.fail("item %s: #%d (%s) applied at rev %d on top of version %d, which #%d had already replaced (lost update / fork)", item, op.rec.ID, op.rec, op.rev, op.base, replaced[op.base].ID)
				case op.base == 0 && cur != 0 && a.openDels[item] == 0:
					c.fail("item %s: #%d re-created it at rev %d while version %d existed and no delete of it is known", item, op.rec.ID, op.rev, cur)
				case op.base != 0 && op.base < cur:
					c.fail("item %s: #%d applied at rev %d on base %d, older than the current version %d", item, op.rec.ID, op.rev, op.base, cur)
				case op.base != 0 && a.openPuts[item] == 0:
					c.fail("item %s: #%d applied at rev %d on base %d, a version no known write produced (current %d)", item, op.rec.ID, op.rev, op.base, cur)
				}
			}
			if cur != 0 {
				replaced[cur] = op.rec
			}
			if op.del {
				cur = 0
			} else {
				cur = op.version
			}
		}
		if !a.hasFinal {
			continue
		}
		f, ok := a.final[item]
		if !ok {
			c.fail("item %s missing from the final read", item)
			continue
		}
		fv := uint64(0)
		if f.Present {
			fv = f.Version
		}
		if fv != cur {
			switch {
			case fv != 0 && replaced[fv] != nil:
				c.fail("item %s: final state is version %d, which #%d had replaced (lost writes)", item, fv, replaced[fv].ID)
			case fv == 0 && a.openDels[item] == 0:
				c.fail("item %s: final state is absent, but its last known write is version %d and no later delete is known", item, cur)
			case fv != 0 && fv < cur:
				c.fail("item %s: final state is version %d, older than the last known write %d", item, fv, cur)
			case fv != 0 && a.openPuts[item] == 0 && a.ix.VersionWriter[fv] == "":
				c.fail("item %s: final state is version %d, which no known write produced", item, fv)
			}
		}
	}
	c.Detail = fmt.Sprintf("%d effective writes on %d items", nOps, len(a.items))
	return c
}

// checkAckedWritesSurvive: every write acknowledged with 2xx is the final
// value or provably superseded (a later version, or absent after a later
// delete).
func (a *analysis) checkAckedWritesSurvive() *Check {
	c := newCheck("acknowledged writes final or superseded")
	if !a.hasFinal {
		c.Skipped, c.Detail = true, "no final read"
		return c
	}
	n := 0
	for _, r := range a.recs {
		if r.Kind != KindPut || r.Outcome != OutOK {
			continue
		}
		n++
		f := a.final[r.Item]
		switch {
		case f.Present && f.Version == r.Version:
		case f.Present && f.Version > r.Version:
		case f.Present:
			c.fail("acked #%d %s@%d is lost: the final state is the older version %d", r.ID, r.Item, r.Version, f.Version)
		default:
			later := a.openDels[r.Item] > 0
			for _, op := range a.eff[r.Item] {
				if op.del && op.rev > r.Version {
					later = true
				}
			}
			if !later {
				c.fail("acked #%d %s@%d is lost: the item is absent at the end and no later delete exists", r.ID, r.Item, r.Version)
			}
		}
	}
	c.Detail = fmt.Sprintf("%d acknowledged puts", n)
	return c
}

// checkStaleReads: the weak guarantees of consistency=stale reads, plus
// the response flags of every read.
func (a *analysis) checkStaleReads() *Check {
	c := newCheck("stale reads")
	per := map[string][]span{}
	n := 0
	for _, r := range a.recs {
		if (r.Kind != KindRead && r.Kind != KindStaleRead) || r.Outcome != OutOK {
			continue
		}
		staleReq := r.Kind == KindStaleRead || r.Lie
		if r.Stale != staleReq {
			c.fail("#%d: requested stale=%v, response says stale=%v", r.ID, staleReq, r.Stale)
		}
		if r.ServedBy != r.Node {
			c.fail("#%d: sent to %s, served_by %q", r.ID, r.Node, r.ServedBy)
		}
		if r.Kind != KindStaleRead {
			continue
		}
		n++
		if r.Inc == r.IncAfter {
			k := fmt.Sprintf("%s/%d", r.Node, r.Inc)
			per[k] = append(per[k], span{r, r.Call, r.Return, r.Rev})
		}
	}
	for k, list := range per {
		sweepPrior(list, list, func(b span, maxRev uint64, maxR *OpRecord) {
			if b.v < maxRev {
				c.fail("node/incarnation %s: stale read #%d returned rev %d after stale read #%d had returned rev %d", k, b.rec.ID, b.v, maxR.ID, maxRev)
			}
		})
	}
	// Across a restart a node may legitimately go back: the commit index is
	// not persisted, so a restarted node serves its last snapshot plus
	// nothing until it hears the commit index from a leader. Counted, not
	// failed.
	perNode := map[string][]*OpRecord{}
	for _, r := range a.recs {
		if r.Kind == KindStaleRead && r.Outcome == OutOK {
			perNode[r.Node] = append(perNode[r.Node], r)
		}
	}
	regress := 0
	for _, list := range perNode {
		sort.Slice(list, func(i, j int) bool { return list[i].Call < list[j].Call })
		var maxRev uint64
		var maxRet int64
		maxInc := -1
		for _, r := range list {
			if maxInc >= 0 && r.Inc > maxInc && r.Call > maxRet && r.Rev < maxRev {
				regress++
			}
			if r.Rev > maxRev {
				maxRev, maxRet, maxInc = r.Rev, r.Return, r.Inc
			}
		}
	}
	c.Detail = fmt.Sprintf("%d stale reads, rev monotone within every node incarnation; %d went back across a restart (expected: the commit index is not persisted)", n, regress)
	return c
}

// checkAnomalies reports operations that got an answer no correct server
// gives this workload (400s, 401s, 404s...).
func (a *analysis) checkAnomalies() *Check {
	c := newCheck("no unexpected API errors")
	n := 0
	for _, r := range a.recs {
		if r.Outcome == OutError {
			n++
			c.fail("#%d %s: %s", r.ID, r, r.Detail)
		}
	}
	c.Detail = fmt.Sprintf("%d unexpected answers", n)
	return c
}

// PorcupineResult is the outcome of the linearizability check.
type PorcupineResult struct {
	Check
	Result     porcupine.CheckResult `json:"result"`
	Ops        int                   `json:"ops"`
	Partitions int                   `json:"partitions"`
	Elapsed    time.Duration         `json:"elapsed_ns"`
	VizPath    string                `json:"viz_path,omitempty"`
}

// checkPorcupine runs the linearizability check. On a violation (or a
// timeout) it writes Porcupine's visualization and the model history to
// outDir.
// replacedTimes: for each write E, the earliest return of an operation that
// certainly replaced it (an effective write based on E's version). Needs
// the version index, i.e. checkBijection first.
func (a *analysis) replacedTimes() map[string]int64 {
	out := map[string]int64{}
	for _, ops := range a.eff {
		for _, op := range ops {
			if op.base == 0 {
				continue
			}
			e, ok := a.ix.VersionWriter[op.base]
			if !ok {
				continue
			}
			t := op.rec.Return
			if op.rec.Outcome == OutUnknown {
				f := a.firstSeen[op.rec.Write]
				if f == nil {
					continue
				}
				t = f.Return
			}
			if t == 0 {
				continue
			}
			if old, ok := out[e]; !ok || t < old {
				out[e] = t
			}
		}
	}
	return out
}

func (a *analysis) checkPorcupine(end int64, timeout time.Duration, outDir string) *PorcupineResult {
	ops, pruned := BuildPorcupineHistory(a.recs, end, a.replacedTimes())
	model := NewCASModel(a.ix)
	res := &PorcupineResult{Check: Check{Name: "linearizability (Porcupine)", Pass: true}, Ops: len(ops)}
	res.Partitions = len(model.Partition(ops))
	start := time.Now()
	result, info := porcupine.CheckOperationsVerbose(model, ops, timeout)
	res.Elapsed = time.Since(start)
	res.Result = result
	res.Detail = fmt.Sprintf("%d operations in %d partitions, %v", len(ops), res.Partitions, res.Elapsed.Round(time.Millisecond))
	if pruned > 0 {
		res.Detail += fmt.Sprintf(" (%d unknown CASes dropped as provable no-ops)", pruned)
	}
	if result == porcupine.Ok {
		return res
	}
	res.Pass = false
	if result == porcupine.Unknown {
		res.Violations = append(res.Violations, fmt.Sprintf("Porcupine timed out after %v without deciding (INCONCLUSIVE, counted as a failure)", timeout))
	} else {
		res.Violations = append(res.Violations, "history is not linearizable")
		// Name the offending items: re-check each partition alone.
		for _, part := range model.Partition(ops) {
			if len(part) == 0 {
				continue
			}
			if porcupine.CheckOperationsTimeout(model, part, timeout) != porcupine.Ok {
				res.Violations = append(res.Violations, fmt.Sprintf("item %s (%d operations) has no linearization",
					part[0].Input.(CASInput).Item, len(part)))
			}
		}
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err == nil {
			path := filepath.Join(outDir, "porcupine.html")
			if err := porcupine.VisualizePath(model, info, path); err == nil {
				res.VizPath = path
			} else {
				res.Violations = append(res.Violations, "visualization failed: "+err.Error())
			}
			if b, err := json.MarshalIndent(ops, "", " "); err == nil {
				_ = os.WriteFile(filepath.Join(outDir, "porcupine-history.json"), b, 0o644)
			}
		}
	}
	return res
}
