package chaos

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// Operation kinds.
const (
	KindRead      = "read"       // linearizable GET /v1/sync
	KindStaleRead = "stale_read" // GET /v1/sync?consistency=stale (not part of the linearizability history)
	KindPut       = "put"        // PUT .../items/{item} (create when Base == 0)
	KindDelete    = "delete"     // DELETE .../items/{item}?base_version=Base
)

// Outcomes.
const (
	OutOK       = "ok"
	OutConflict = "conflict" // 409 version_conflict
	OutFailed   = "failed"   // certainly had no effect (every attempt unavailable / not sent)
	OutUnknown  = "unknown"  // may or may not have taken effect, at any time after Call
	OutError    = "error"    // an unexpected definite answer (a bug somewhere); excluded from Porcupine, always reported
)

// Attempt is one HTTP request of an operation.
type Attempt struct {
	Node   string `json:"node"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Result string `json:"result"`
}

// ReadObs is what a sync showed about one item.
type ReadObs struct {
	Item    string `json:"item"`
	Present bool   `json:"present"`
	Version uint64 `json:"version,omitempty"`
	Write   string `json:"write,omitempty"` // write id decoded from the blob
	Bad     string `json:"bad,omitempty"`   // the blob is not one the harness wrote (corruption)
}

// OpRecord is one client operation, from invocation to completion. Times
// are nanoseconds since the start of the run on the harness's monotonic
// clock (all clients share it).
type OpRecord struct {
	ID       int    `json:"id"`
	Client   int    `json:"client"`
	User     string `json:"user"`
	Kind     string `json:"kind"`
	Item     string `json:"item,omitempty"`
	Base     uint64 `json:"base,omitempty"`
	Expect   string `json:"expect,omitempty"` // write id that produced Base ("" = item absent)
	Write    string `json:"write,omitempty"`  // put: this op's write id
	StaleCAS bool   `json:"stale_cas,omitempty"`
	IdemKey  string `json:"idem_key,omitempty"`
	// KeySeq is the number of idempotency keys the harness had issued when
	// this op got its key: the distance to the current count bounds how many
	// newer entries can have pushed it out of the server's 4096-entry table.
	KeySeq int64 `json:"key_seq,omitempty"`

	Call   int64 `json:"call"`
	Return int64 `json:"return"` // 0 while unknown

	Outcome string  `json:"outcome"`
	Version uint64  `json:"version,omitempty"` // put ok: the new version
	Rev     uint64  `json:"rev,omitempty"`     // write ok: MutationResponse.rev; read: SyncResponse.rev
	CurVer  *uint64 `json:"current_version,omitempty"`
	Detail  string  `json:"detail,omitempty"`

	Reads []ReadObs `json:"reads,omitempty"`
	// Node/incarnation that answered (reads). IncAfter differs from Inc if
	// the node restarted while the request was in flight.
	Node     string `json:"node,omitempty"`
	Inc      int    `json:"inc,omitempty"`
	IncAfter int    `json:"inc_after,omitempty"`
	Stale    bool   `json:"stale_flag,omitempty"` // the response's "stale" field
	ServedBy string `json:"served_by,omitempty"`
	// Since is the ?since= sent; Unchanged means the server answered
	// "unchanged", so Reads are the client's sync at rev Since.
	Since     uint64 `json:"since,omitempty"`
	Unchanged bool   `json:"unchanged,omitempty"`

	Attempts []Attempt `json:"attempts,omitempty"`
	// Lie marks a self-test read: issued with consistency=stale but
	// recorded as linearizable, to prove the checker catches it.
	Lie      bool `json:"lie,omitempty"`
	Resolved bool `json:"resolved,omitempty"` // unknown outcome learned by re-sending the same key after the heal
	Final    bool `json:"final,omitempty"`    // a read of the final convergence phase
	Setup    bool `json:"setup,omitempty"`
}

// linearizableRead reports whether the record is a successful read that
// belongs in the linearizability history.
func (r *OpRecord) linearizableRead() bool { return r.Kind == KindRead && r.Outcome == OutOK }

func (r *OpRecord) isWrite() bool { return r.Kind == KindPut || r.Kind == KindDelete }

func (r *OpRecord) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d c%d %s", r.ID, r.Client, r.Kind)
	if r.Item != "" {
		fmt.Fprintf(&b, " %s", r.Item)
	}
	if r.isWrite() {
		fmt.Fprintf(&b, " base=%d(%s)", r.Base, orAbsent(r.Expect))
		if r.Write != "" {
			fmt.Fprintf(&b, " write=%s", r.Write)
		}
	}
	fmt.Fprintf(&b, " [%s .. %s] -> %s", fmtNs(r.Call), fmtNs(r.Return), r.Outcome)
	if r.Version != 0 {
		fmt.Fprintf(&b, " v=%d", r.Version)
	}
	if r.Rev != 0 {
		fmt.Fprintf(&b, " rev=%d", r.Rev)
	}
	if r.CurVer != nil {
		fmt.Fprintf(&b, " cur=%d", *r.CurVer)
	}
	if r.Node != "" {
		fmt.Fprintf(&b, " node=%s", r.Node)
	}
	if r.Lie {
		b.WriteString(" LIE")
	}
	if r.Resolved {
		b.WriteString(" resolved")
	}
	return b.String()
}

func orAbsent(w string) string {
	if w == "" {
		return "absent"
	}
	return w
}

func fmtNs(ns int64) string {
	if ns == 0 {
		return "?"
	}
	return fmt.Sprintf("%.3fs", float64(ns)/1e9)
}

// History collects records from all clients.
type History struct {
	mu   sync.Mutex
	recs []*OpRecord
}

func (h *History) add(r *OpRecord) *OpRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	r.ID = len(h.recs)
	h.recs = append(h.recs, r)
	return r
}

// Records returns the records. Callers must only read them once every
// client has stopped.
func (h *History) Records() []*OpRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*OpRecord(nil), h.recs...)
}

// Blob format. Every put writes a fresh blob that names its write, so a
// read identifies exactly which write it observed. The server treats it
// as an opaque ciphertext box (>= 41 bytes).
const blobPrefix = "fvchaos1|"

func makeBlob(item, write string) []byte {
	b := []byte(blobPrefix + item + "|" + write + "|")
	for len(b) < 72 {
		b = append(b, '.')
	}
	return b
}

// parseBlob returns the item and write id a blob names.
func parseBlob(b []byte) (item, write string, ok bool) {
	if !bytes.HasPrefix(b, []byte(blobPrefix)) {
		return "", "", false
	}
	parts := strings.SplitN(string(b[len(blobPrefix):]), "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if !bytes.Equal(b, makeBlob(parts[0], parts[1])) {
		return "", "", false
	}
	return parts[0], parts[1], true
}
