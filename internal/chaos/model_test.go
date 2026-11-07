package chaos

import (
	"strings"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
)

// recBuilder makes synthetic histories for the model and check tests.
type recBuilder struct{ recs []*OpRecord }

func (b *recBuilder) add(r *OpRecord) *OpRecord {
	r.ID = len(b.recs)
	b.recs = append(b.recs, r)
	return r
}

func (b *recBuilder) put(client int, item, expect, write string, base uint64, call, ret int64, outcome string, version uint64) *OpRecord {
	return b.add(&OpRecord{Client: client, Kind: KindPut, Item: item, Expect: expect, Write: write, Base: base,
		Call: call, Return: ret, Outcome: outcome, Version: version, Rev: version})
}

func (b *recBuilder) del(client int, item, expect string, base uint64, call, ret int64, outcome string, rev uint64) *OpRecord {
	return b.add(&OpRecord{Client: client, Kind: KindDelete, Item: item, Expect: expect, Base: base,
		Call: call, Return: ret, Outcome: outcome, Rev: rev})
}

func (b *recBuilder) read(client int, item, write string, version, rev uint64, call, ret int64) *OpRecord {
	o := ReadObs{Item: item, Present: write != "", Version: version, Write: write}
	return b.add(&OpRecord{Client: client, Kind: KindRead, Call: call, Return: ret, Outcome: OutOK, Rev: rev,
		Reads: []ReadObs{o}, Node: "n1", ServedBy: "n1"})
}

func checkModel(t *testing.T, recs []*OpRecord) porcupine.CheckResult {
	t.Helper()
	a := analyze(recs, []string{"i0"})
	a.checkBijection() // fills the version index
	ops, _ := BuildPorcupineHistory(recs, 1_000_000, a.replacedTimes())
	return porcupine.CheckOperationsTimeout(NewCASModel(a.ix), ops, 10*time.Second)
}

func TestPruneProvableNoOps(t *testing.T) {
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b.put(1, "i0", "w0.1", "w1.1", 5, 21, 30, OutOK, 6)     // replaces w0.1, returned at 30
	b.put(2, "i0", "w0.1", "w2.1", 5, 40, 0, OutUnknown, 0) // invoked after: can only fail
	b.put(2, "i0", "w0.1", "w2.2", 5, 25, 0, OutUnknown, 0) // concurrent with the replacement: kept
	b.put(2, "i0", "", "w2.3", 0, 50, 0, OutUnknown, 0)     // expects absent, which can recur: kept
	a := analyze(b.recs, []string{"i0"})
	a.checkBijection()
	ops, pruned := BuildPorcupineHistory(b.recs, 1000, a.replacedTimes())
	if pruned != 1 || len(ops) != 4 {
		t.Fatalf("pruned %d, kept %d operations; want 1 and 4", pruned, len(ops))
	}
	// An unknown op whose write was observed is never pruned, even if its
	// expectation was replaced: here the read proves a double CAS.
	b.read(3, "i0", "w2.1", 9, 9, 60, 70)
	a = analyze(b.recs, []string{"i0"})
	a.checkBijection()
	if _, pruned := BuildPorcupineHistory(b.recs, 1000, a.replacedTimes()); pruned != 0 {
		t.Fatalf("pruned an observed write")
	}
	if got := checkModel(t, b.recs); got != porcupine.Illegal {
		t.Fatalf("double CAS through an unknown op: got %v, want Illegal", got)
	}
}

func TestModelLinearizableHistory(t *testing.T) {
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)           // create -> v5
	b.read(1, "i0", "w0.1", 5, 5, 25, 30)                     // sees it
	b.put(1, "i0", "w0.1", "w1.1", 5, 31, 40, OutOK, 7)       // CAS from v5
	b.put(0, "i0", "w0.1", "w0.2", 5, 35, 45, OutConflict, 0) // concurrent, stale base: conflict
	b.recs[len(b.recs)-1].CurVer = ptr(uint64(7))
	b.del(2, "i0", "w1.1", 7, 50, 60, OutOK, 9)
	b.read(0, "i0", "", 0, 9, 61, 62)
	if got := checkModel(t, b.recs); got != porcupine.Ok {
		t.Fatalf("got %v, want Ok", got)
	}
}

func TestModelStaleReadIsViolation(t *testing.T) {
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b.put(0, "i0", "w0.1", "w0.2", 5, 21, 30, OutOK, 6)
	b.read(1, "i0", "w0.1", 5, 5, 31, 32) // returns the overwritten value after the overwrite completed
	if got := checkModel(t, b.recs); got != porcupine.Illegal {
		t.Fatalf("got %v, want Illegal", got)
	}
}

func TestModelDoubleCASIsViolation(t *testing.T) {
	// Two CASes from the same base both succeed: a fork.
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b.put(1, "i0", "w0.1", "w1.1", 5, 21, 30, OutOK, 6)
	b.put(2, "i0", "w0.1", "w2.1", 5, 21, 31, OutOK, 7)
	if got := checkModel(t, b.recs); got != porcupine.Illegal {
		t.Fatalf("got %v, want Illegal", got)
	}
}

func TestModelConflictMustMatchState(t *testing.T) {
	// A conflict while the expectation holds is impossible.
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	c := b.put(1, "i0", "w0.1", "w1.1", 5, 30, 40, OutConflict, 0)
	c.CurVer = ptr(uint64(5))
	if got := checkModel(t, b.recs); got != porcupine.Illegal {
		t.Fatalf("got %v, want Illegal", got)
	}
	// A conflict whose current_version names a different write than the
	// register holds is impossible too.
	var b2 recBuilder
	b2.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b2.put(0, "i0", "w0.1", "w0.2", 5, 21, 25, OutOK, 6)
	c = b2.put(1, "i0", "", "w1.1", 0, 30, 40, OutConflict, 0)
	c.CurVer = ptr(uint64(5)) // but the item is at v6 now
	if got := checkModel(t, b2.recs); got != porcupine.Illegal {
		t.Fatalf("stale current_version: got %v, want Illegal", got)
	}
}

func TestModelUnknownOutcomes(t *testing.T) {
	// An unknown put may have happened (a later read sees it) ...
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b.put(1, "i0", "w0.1", "w1.1", 5, 21, 0, OutUnknown, 0)
	b.read(2, "i0", "w1.1", 8, 8, 50, 60)
	if got := checkModel(t, b.recs); got != porcupine.Ok {
		t.Fatalf("observed unknown: got %v, want Ok", got)
	}
	// ... or not (nobody ever sees it) ...
	var b2 recBuilder
	b2.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b2.put(1, "i0", "w0.1", "w1.1", 5, 21, 0, OutUnknown, 0)
	b2.read(2, "i0", "w0.1", 5, 9, 50, 60)
	if got := checkModel(t, b2.recs); got != porcupine.Ok {
		t.Fatalf("invisible unknown: got %v, want Ok", got)
	}
	// ... but not before it was invoked.
	var b3 recBuilder
	b3.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b3.read(2, "i0", "w1.1", 8, 8, 21, 22)
	b3.put(1, "i0", "w0.1", "w1.1", 5, 30, 0, OutUnknown, 0)
	if got := checkModel(t, b3.recs); got != porcupine.Illegal {
		t.Fatalf("time travel: got %v, want Illegal", got)
	}
}

func TestBlobRoundTrip(t *testing.T) {
	b := makeBlob("i3", "w2.17")
	if len(b) < 41 {
		t.Fatalf("blob too short for a box: %d", len(b))
	}
	item, w, ok := parseBlob(b)
	if !ok || item != "i3" || w != "w2.17" {
		t.Fatalf("parse = %q %q %v", item, w, ok)
	}
	b[len(b)-1] = 'x'
	if _, _, ok := parseBlob(b); ok {
		t.Fatal("tampered blob accepted")
	}
	if _, _, ok := parseBlob([]byte(strings.Repeat("z", 64))); ok {
		t.Fatal("foreign blob accepted")
	}
}

func TestRevOracleChecks(t *testing.T) {
	// A clean history passes every check.
	var b recBuilder
	b.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	b.read(1, "i0", "w0.1", 5, 5, 25, 30)
	b.put(1, "i0", "w0.1", "w1.1", 5, 31, 40, OutOK, 7)
	f := b.read(0, "i0", "w1.1", 7, 7, 50, 60)
	f.Final, f.User = true, "alice"
	a := analyze(b.recs, []string{"i0"})
	for _, c := range []*Check{a.checkBijection(), a.checkRevOrder(), a.checkReadMonotonic(), a.checkReadSnapshots(), a.checkChains(), a.checkAckedWritesSurvive(), a.checkStaleReads()} {
		if !c.Pass {
			t.Errorf("%s failed on a clean history: %v", c.Name, c.Violations)
		}
	}

	// A read that returns an older rev after a write completed.
	var s recBuilder
	s.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	s.put(0, "i0", "w0.1", "w0.2", 5, 21, 30, OutOK, 6)
	s.read(1, "i0", "w0.1", 5, 5, 31, 32)
	a = analyze(s.recs, []string{"i0"})
	a.checkBijection()
	if c := a.checkRevOrder(); c.Pass {
		t.Error("rev order missed a stale read")
	}

	// A read whose snapshot misses a write applied before its rev.
	var r recBuilder
	r.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	r.put(0, "i0", "w0.1", "w0.2", 5, 21, 30, OutOK, 6)
	r.read(1, "i0", "w0.1", 5, 9, 15, 35) // claims rev 9 but shows v5
	a = analyze(r.recs, []string{"i0"})
	a.checkBijection()
	if c := a.checkReadSnapshots(); c.Pass {
		t.Error("snapshot check missed an inconsistent read")
	}

	// A fork: two writes on the same base.
	var k recBuilder
	k.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	k.put(1, "i0", "w0.1", "w1.1", 5, 21, 30, OutOK, 6)
	k.put(2, "i0", "w0.1", "w2.1", 5, 21, 31, OutOK, 7)
	a = analyze(k.recs, []string{"i0"})
	if c := a.checkChains(); c.Pass {
		t.Error("chain check missed a fork")
	}

	// A lost acknowledged write: the final state is older.
	var l recBuilder
	l.put(0, "i0", "", "w0.1", 0, 10, 20, OutOK, 5)
	l.put(1, "i0", "w0.1", "w1.1", 5, 21, 30, OutOK, 6)
	fl := l.read(0, "i0", "w0.1", 5, 9, 50, 60)
	fl.Final, fl.User = true, "alice"
	a = analyze(l.recs, []string{"i0"})
	if c := a.checkAckedWritesSurvive(); c.Pass {
		t.Error("lost write not detected")
	}
	if c := a.checkChains(); c.Pass {
		t.Error("chain check missed a lost write")
	}

	// A write reported as certainly not applied that shows up anyway.
	var p recBuilder
	p.put(0, "i0", "", "w0.1", 0, 10, 20, OutFailed, 0)
	p.read(1, "i0", "w0.1", 5, 5, 30, 40)
	a = analyze(p.recs, []string{"i0"})
	if c := a.checkBijection(); c.Pass {
		t.Error("phantom of a failed write not detected")
	}
}

func ptr[T any](v T) *T { return &v }
