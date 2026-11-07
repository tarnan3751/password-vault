package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// SafeResendWindow bounds how many idempotency keys may have been issued
// after an operation's own key before the harness stops re-sending it.
//
// The server remembers the 4096 most recently APPLIED request ids
// (api.md §1). An entry is evicted once 4096 later entries were applied;
// those can only be our own later keys plus the few keys that were already
// in flight when this one was issued (at most one per client, plus
// operations still being retried), plus the cluster's own init command. A
// re-send after eviction would EXECUTE AGAIN instead of returning the
// recorded result, and the checker would rightly see a double application,
// so we stay far below the limit and record the operation as unknown
// instead.
const SafeResendWindow = 3000

// WorkloadConfig shapes the client load.
type WorkloadConfig struct {
	Clients int
	Items   int
	Seed    int64
	// SelfTest makes the harness lie to its own checker: while a fault is
	// active, linearizable reads are sent with consistency=stale but
	// recorded as linearizable. A correct checker must flag the run.
	SelfTest bool
	// AttemptTimeout bounds one HTTP request. It exceeds the server's
	// default propose (10 s) and read-barrier (5 s) timeouts so that the
	// server, not the client, usually decides: the server knows whether a
	// failed write certainly did nothing (503 unavailable) and the client
	// does not.
	AttemptTimeout time.Duration
	// OpBudget bounds how long one operation is retried with the same key
	// before it is recorded as unknown (it is resolved after the heal when
	// still within SafeResendWindow).
	OpBudget time.Duration
	ThinkMax time.Duration
}

func (c *WorkloadConfig) fill() {
	if c.Clients <= 0 {
		c.Clients = 5
	}
	if c.Items <= 0 {
		c.Items = 6
	}
	if c.AttemptTimeout <= 0 {
		c.AttemptTimeout = 12 * time.Second
	}
	if c.OpBudget <= 0 {
		c.OpBudget = 30 * time.Second
	}
	if c.ThinkMax <= 0 {
		c.ThinkMax = 25 * time.Millisecond
	}
}

type userAcct struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	LoginKey []byte `json:"-"`
	Token    string `json:"-"`
	Admin    bool   `json:"admin"`
	Personal string `json:"personal_vault"`
}

type itemRef struct {
	Key    string `json:"key"` // short name used in histories: i0, i1, ...
	Vault  string `json:"vault"`
	ID     string `json:"id"`
	Shared bool   `json:"shared"`
}

// knowledge is the harness's shared map between versions and the writes
// that produced them, learned from acknowledgements and reads. Versions are
// global revs, so a version names at most one write anywhere; the checks
// verify that the server never contradicts this.
type knowledge struct{ verWrite sync.Map }

func (k *knowledge) learn(version uint64, write string) {
	if version != 0 && write != "" {
		k.verWrite.LoadOrStore(version, write)
	}
}

func (k *knowledge) writerOf(version uint64) (string, bool) {
	w, ok := k.verWrite.Load(version)
	if !ok {
		return "", false
	}
	return w.(string), true
}

// resendReq is everything needed to re-send a write with the same key.
type resendReq struct {
	method, path string
	body         any
	user         *userAcct
	key          string
}

// Workload owns the users, items, clients and the history of a run.
type Workload struct {
	cfg   WorkloadConfig
	c     Cluster
	hc    *http.Client
	hist  *History
	start time.Time
	rng   *rand.Rand // setup only

	users     []*userAcct
	items     []itemRef
	shared    string
	know      knowledge
	keySeq    atomic.Int64
	keyBudget atomic.Int64 // ops abandoned because of SafeResendWindow

	// FaultActive is consulted in self-test mode (set by Run from the
	// nemesis).
	FaultActive func() bool

	resendMu sync.Mutex
	resend   map[int]*resendReq
	lies     atomic.Int64
}

// NewWorkload prepares (but does not start) the workload.
func NewWorkload(c Cluster, cfg WorkloadConfig, start time.Time) *Workload {
	cfg.fill()
	return &Workload{cfg: cfg, c: c, hc: c.HTTPClient(), hist: &History{}, start: start,
		rng:    rand.New(rand.NewPCG(uint64(cfg.Seed), 0xa11ce)),
		resend: map[int]*resendReq{}}
}

func (w *Workload) now() int64 {
	n := int64(time.Since(w.start))
	if n <= 0 {
		n = 1
	}
	return n
}

// History returns the recorded history.
func (w *Workload) History() *History { return w.hist }

// Items returns the item set.
func (w *Workload) Items() []itemRef { return w.items }

func (w *Workload) randHex(n int) string { return hex.EncodeToString(w.randBytes(n)) }

func (w *Workload) randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(w.rng.UintN(256))
	}
	return b
}

// idemKey derives a request id deterministically from the seed, so a seed
// replays with the same keys.
func (w *Workload) idemKey(client, seq int) string {
	var buf [24]byte
	binary.LittleEndian.PutUint64(buf[0:], uint64(w.cfg.Seed))
	binary.LittleEndian.PutUint64(buf[8:], uint64(client))
	binary.LittleEndian.PutUint64(buf[16:], uint64(seq))
	h := sha256.Sum256(buf[:])
	return hex.EncodeToString(h[:16])
}

// box returns an opaque "ciphertext" of n >= 41 bytes. The server only
// checks sizes.
func (w *Workload) box(n int) []byte { return w.randBytes(n) }

func (w *Workload) kdf() api.KDFParams {
	// Inside the bounds the state machine enforces for client KDF
	// parameters (memory 64-256 MiB, time 3-8, parallelism 1-16, salt
	// 16-64 bytes). The server never runs this KDF.
	return api.KDFParams{Alg: "argon2id", Salt: w.randBytes(16), Time: 3, MemoryKiB: 65536, Parallelism: 4}
}

// setupCall performs a setup request with retries (same key) across nodes
// until it succeeds. Setup happens before any fault, but the cluster may
// still be electing its first leader.
func (w *Workload) setupCall(ctx context.Context, method, path, token string, mutating bool, body, out any) error {
	key := ""
	if mutating {
		w.keySeq.Add(1)
		key = w.randHex(16)
	}
	ids := w.c.IDs()
	var last callResult
	deadline := time.Now().Add(90 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		node := ids[i%len(ids)]
		actx, cancel := context.WithTimeout(ctx, w.cfg.AttemptTimeout)
		last = apiCall(actx, w.hc, method, w.c.URL(node)+path, token, key, body)
		cancel()
		if last.ok() {
			if out != nil {
				return decodeInto(last, out)
			}
			return nil
		}
		retry := last.NetErr != nil || last.Status >= 500
		if !retry {
			return fmt.Errorf("%s %s on %s: %s: %s", method, path, node, last.short(), last.Err.Message)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s %s: gave up: %s", method, path, last.short())
}

func (w *Workload) newUser(name string) *userAcct {
	return &userAcct{Name: name, ID: w.randHex(16), LoginKey: w.randBytes(32), Personal: w.randHex(16)}
}

func (w *Workload) register(ctx context.Context, u *userAcct, invite string) error {
	req := api.RegisterRequest{
		InviteCode: invite, UserID: u.ID, Username: u.Name, KDF: w.kdf(), LoginKey: u.LoginKey,
		PublicKey: w.randBytes(32), WrappedAccountKey: w.box(72), EncPrivateKey: w.box(80),
		PersonalVault: api.CreateVaultRequest{VaultID: u.Personal, EncMeta: w.box(64), EncRoster: w.box(96),
			WrappedKey: api.WrappedKey{SenderID: u.ID, Blob: w.randBytes(105)}},
	}
	var lr api.LoginResponse
	if err := w.setupCall(ctx, http.MethodPost, "/v1/register", "", true, req, &lr); err != nil {
		return fmt.Errorf("register %s: %w", u.Name, err)
	}
	u.Token, u.Admin = lr.Token, lr.IsAdmin
	return nil
}

// Setup registers two users (the first with the bootstrap token), creates
// a shared vault with both as members, and chooses the items: some in the
// shared vault (both users contend on them), the rest in the first user's
// personal vault. It runs before any fault.
func (w *Workload) Setup(ctx context.Context, bootstrapToken string) error {
	alice, bob := w.newUser("alice"), w.newUser("bob")
	if err := w.register(ctx, alice, bootstrapToken); err != nil {
		return err
	}
	if !alice.Admin {
		return errors.New("bootstrap registration did not produce an admin")
	}
	var inv api.CreateInviteResponse
	if err := w.setupCall(ctx, http.MethodPost, "/v1/invites", alice.Token, true, api.CreateInviteRequest{}, &inv); err != nil {
		return fmt.Errorf("create invite: %w", err)
	}
	if err := w.register(ctx, bob, inv.Code); err != nil {
		return err
	}
	w.users = []*userAcct{alice, bob}
	w.shared = w.randHex(16)
	if err := w.setupCall(ctx, http.MethodPost, "/v1/vaults", alice.Token, true, api.CreateVaultRequest{
		VaultID: w.shared, EncMeta: w.box(64), EncRoster: w.box(96),
		WrappedKey: api.WrappedKey{SenderID: alice.ID, Blob: w.randBytes(105)},
	}, nil); err != nil {
		return fmt.Errorf("create shared vault: %w", err)
	}
	var sync api.SyncResponse
	if err := w.setupCall(ctx, http.MethodGet, "/v1/sync", alice.Token, false, nil, &sync); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	var rosterVer uint64
	var epoch uint32
	found := false
	for _, v := range sync.Vaults {
		if v.ID == w.shared {
			rosterVer, epoch, found = v.RosterVersion, v.KeyEpoch, true
		}
	}
	if !found {
		return errors.New("shared vault missing from sync")
	}
	if err := w.setupCall(ctx, http.MethodPut, "/v1/vaults/"+w.shared+"/members/"+bob.ID, alice.Token, true, api.PutMemberRequest{
		Role: api.RoleEditor, WrappedKey: &api.WrappedKey{SenderID: alice.ID, Blob: w.randBytes(105)},
		KeyEpoch: epoch, EncRoster: w.box(128), BaseRosterVersion: rosterVer,
	}, nil); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	nShared := (w.cfg.Items*2 + 2) / 3
	if w.cfg.Items == 1 {
		nShared = 1
	}
	for i := 0; i < w.cfg.Items; i++ {
		it := itemRef{Key: fmt.Sprintf("i%d", i), ID: w.randHex(16)}
		if i < nShared {
			it.Vault, it.Shared = w.shared, true
		} else {
			it.Vault = alice.Personal
		}
		w.items = append(w.items, it)
	}
	w.c.SetAdminToken(alice.Token)
	return nil
}

// accessible returns the items a user can see in a sync.
func (w *Workload) accessible(u *userAcct) []itemRef {
	var out []itemRef
	for _, it := range w.items {
		if it.Shared || u == w.users[0] {
			out = append(out, it)
		}
	}
	return out
}

type verWrite struct {
	Version uint64
	Write   string
}

type itemView struct {
	known   bool
	present bool
	version uint64
	write   string
	past    []verWrite
}

type wclient struct {
	id      int
	user    *userAcct
	rng     *rand.Rand
	node    int
	repick  time.Time
	items   []itemRef
	view    map[string]*itemView
	seq     int
	nodeIDs []string
	// lastSync is this client's last full linearizable sync, the base of
	// ?since= reads.
	lastSync *OpRecord
}

func (cl *wclient) observe(item string, present bool, version uint64, write string) {
	v := cl.view[item]
	v.known, v.present, v.version, v.write = true, present, version, write
	if present && (len(v.past) == 0 || v.past[len(v.past)-1].Version != version) {
		v.past = append(v.past, verWrite{version, write})
		if len(v.past) > 8 {
			v.past = v.past[1:]
		}
	}
}

// Run drives the clients until stop is closed; each client then finishes
// its current operation (retrying until it has an answer, within its
// budget). hard aborts everything.
func (w *Workload) Run(hard context.Context, stop <-chan struct{}) {
	var wg sync.WaitGroup
	ids := w.c.IDs()
	for i := 0; i < w.cfg.Clients; i++ {
		u := w.users[0]
		if i%3 == 2 {
			u = w.users[1]
		}
		cl := &wclient{id: i, user: u, rng: rand.New(rand.NewPCG(uint64(w.cfg.Seed), uint64(i)+1)),
			items: w.accessible(u), view: map[string]*itemView{}, nodeIDs: ids}
		cl.node = cl.rng.IntN(len(ids))
		for _, it := range cl.items {
			cl.view[it.Key] = &itemView{}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.clientLoop(hard, stop, cl)
		}()
	}
	wg.Wait()
}

func (w *Workload) clientLoop(hard context.Context, stop <-chan struct{}, cl *wclient) {
	for {
		select {
		case <-stop:
			return
		case <-hard.Done():
			return
		default:
		}
		if time.Now().After(cl.repick) {
			cl.node = cl.rng.IntN(len(cl.nodeIDs))
			cl.repick = time.Now().Add(time.Second + time.Duration(cl.rng.Int64N(int64(3*time.Second))))
		}
		w.step(hard, cl)
		if t := time.Duration(cl.rng.Int64N(int64(w.cfg.ThinkMax) + 1)); t > 0 {
			select {
			case <-time.After(t):
			case <-hard.Done():
				return
			}
		}
	}
}

// step chooses and executes one operation. Mix: reads ~30%, stale reads
// ~10%, puts ~45% (creates when the item is believed absent), deletes
// ~15%; a CAS is sometimes based on an older version on purpose, which
// must produce a conflict.
func (w *Workload) step(ctx context.Context, cl *wclient) {
	it := cl.items[cl.rng.IntN(len(cl.items))]
	v := cl.view[it.Key]
	r := cl.rng.Float64()
	switch {
	case !v.known || r < 0.30:
		w.doRead(ctx, cl, false)
	case r < 0.40:
		w.doRead(ctx, cl, true)
	case r < 0.85 || !v.present:
		base, expect, staleCAS := w.chooseBase(cl, v)
		cl.seq++
		write := fmt.Sprintf("w%d.%d", cl.id, cl.seq)
		w.doWrite(ctx, cl, it, KindPut, base, expect, write, staleCAS)
	default:
		base, expect, staleCAS := w.chooseBase(cl, v)
		if base == 0 {
			// Believed absent after all: a delete needs a version.
			w.doRead(ctx, cl, false)
			return
		}
		cl.seq++
		w.doWrite(ctx, cl, it, KindDelete, base, expect, "", staleCAS)
	}
}

func (w *Workload) chooseBase(cl *wclient, v *itemView) (uint64, string, bool) {
	if !v.present {
		return 0, "", false
	}
	if cl.rng.Float64() < 0.15 && len(v.past) > 1 {
		old := v.past[cl.rng.IntN(len(v.past)-1)]
		if old.Version != v.version {
			return old.Version, old.Write, true
		}
	}
	return v.version, v.write, false
}

func (w *Workload) nodeOf(cl *wclient) string { return cl.nodeIDs[cl.node] }

// attemptTimeout varies per attempt. Half the attempts wait long enough
// for the server to decide (it knows whether a failed write certainly did
// nothing); the other half give up after 0.8-4 s and fail over with the
// same key while the first copy may still be pending on a cut-off node,
// which is exactly the duplicate-proposal path the idempotency table has
// to get right. Without the short ones, clients pile up on an isolated
// node for the whole partition.
func (w *Workload) attemptTimeout(cl *wclient) time.Duration {
	if cl.rng.IntN(2) == 0 {
		return w.cfg.AttemptTimeout
	}
	short := 800*time.Millisecond + time.Duration(cl.rng.Int64N(int64(3200*time.Millisecond)))
	return min(short, w.cfg.AttemptTimeout)
}

func (w *Workload) rotate(cl *wclient) {
	cl.node = (cl.node + 1 + cl.rng.IntN(max(len(cl.nodeIDs)-1, 1))) % len(cl.nodeIDs)
}

func (w *Workload) backoff(ctx context.Context, attempt int, rng *rand.Rand) {
	d := 50 * time.Millisecond << min(attempt, 5)
	d = min(d, time.Second)
	d = d/2 + time.Duration(rng.Int64N(int64(d/2)+1))
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// attempt sends one request of rec to node and logs it as an Attempt; label
// prefixes the logged result.
func (w *Workload) attempt(ctx context.Context, rec *OpRecord, timeout time.Duration, node, method, path, token, key string, body any, label string) (res callResult, start, end int64) {
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start = w.now()
	res = apiCall(actx, w.hc, method, w.c.URL(node)+path, token, key, body)
	end = w.now()
	rec.Attempts = append(rec.Attempts, Attempt{Node: node, Start: start, End: end, Result: label + res.short()})
	return res, start, end
}

// setError records an unexpected definite answer.
func (r *OpRecord) setError(res callResult, end int64, prefix string) {
	r.Outcome, r.Return, r.Detail = OutError, end, prefix+res.short()
	if res.Err != nil {
		r.Detail += ": " + res.Err.Message
	}
}

func (w *Workload) itemPath(it itemRef) string {
	return "/v1/vaults/" + it.Vault + "/items/" + it.ID
}

// doWrite performs a put or delete with one idempotency key, retried on
// every answer that leaves the outcome open (network errors, timeouts,
// 503 outcome_unknown, 500) and on 503 unavailable, rotating nodes.
func (w *Workload) doWrite(ctx context.Context, cl *wclient, it itemRef, kind string, base uint64, expect, write string, staleCAS bool) {
	rec := &OpRecord{Client: cl.id, User: cl.user.Name, Kind: kind, Item: it.Key, Base: base, Expect: expect,
		Write: write, StaleCAS: staleCAS, IdemKey: w.idemKey(cl.id, cl.seq)}
	method, path := http.MethodPut, w.itemPath(it)
	var body any
	if kind == KindPut {
		body = api.PutItemRequest{Blob: makeBlob(it.Key, write), BaseVersion: base, KeyEpoch: 1}
	} else {
		method = http.MethodDelete
		path += fmt.Sprintf("?base_version=%d", base)
	}
	rec.KeySeq = w.keySeq.Add(1)
	rec.Call = w.now()
	w.hist.add(rec)
	req := &resendReq{method: method, path: path, body: body, user: cl.user, key: rec.IdemKey}
	maybe := false
	for attempt := 0; ; attempt++ {
		res, _, en := w.attempt(ctx, rec, w.attemptTimeout(cl), w.nodeOf(cl), method, path, cl.user.Token, rec.IdemKey, body, "")
		if done := w.settleWrite(rec, res, en); done {
			w.afterWrite(cl, rec)
			return
		}
		if res.maybeApplied() {
			maybe = true
		}
		retryable := res.NetErr != nil || res.Status >= 500
		if !retryable {
			rec.setError(res, en, "")
			w.afterWrite(cl, rec)
			return
		}
		w.rotate(cl)
		switch {
		case ctx.Err() != nil:
			rec.Detail = "aborted"
		case en-rec.Call > int64(w.cfg.OpBudget):
			rec.Detail = "retry budget exhausted"
		case w.keySeq.Load()-rec.KeySeq > SafeResendWindow:
			rec.Detail = "stopped retrying: idempotency window"
			w.keyBudget.Add(1)
		default:
			w.backoff(ctx, attempt, cl.rng)
			continue
		}
		break
	}
	if maybe {
		rec.Outcome = OutUnknown
		w.resendMu.Lock()
		w.resend[rec.ID] = req
		w.resendMu.Unlock()
	} else {
		rec.Outcome = OutFailed
		rec.Return = rec.Attempts[len(rec.Attempts)-1].End
	}
	w.afterWrite(cl, rec)
}

// settleWrite records a definite answer. It reports whether res was one.
func (w *Workload) settleWrite(rec *OpRecord, res callResult, en int64) bool {
	if res.ok() {
		var mr api.MutationResponse
		if err := decodeInto(res, &mr); err != nil {
			rec.Outcome, rec.Return, rec.Detail = OutError, en, "undecodable success: "+err.Error()
			return true
		}
		rec.Outcome, rec.Return, rec.Rev = OutOK, en, mr.Rev
		if rec.Kind == KindPut {
			rec.Version = mr.Version
			w.know.learn(mr.Version, rec.Write)
		}
		return true
	}
	if res.NetErr == nil && res.Status == http.StatusConflict && res.code() == api.CodeVersionConflict {
		rec.Outcome, rec.Return = OutConflict, en
		if res.Err.CurrentVersion != nil {
			cv := *res.Err.CurrentVersion
			rec.CurVer = &cv
		}
		return true
	}
	return false
}

func (w *Workload) afterWrite(cl *wclient, rec *OpRecord) {
	v := cl.view[rec.Item]
	switch rec.Outcome {
	case OutOK:
		if rec.Kind == KindPut {
			cl.observe(rec.Item, true, rec.Version, rec.Write)
		} else {
			cl.observe(rec.Item, false, 0, "")
		}
	case OutConflict:
		if rec.CurVer == nil {
			v.known = false
		} else if *rec.CurVer == 0 {
			cl.observe(rec.Item, false, 0, "")
		} else if wr, ok := w.know.writerOf(*rec.CurVer); ok {
			cl.observe(rec.Item, true, *rec.CurVer, wr)
		} else {
			v.known = false
		}
	default:
		v.known = false
	}
}

// doRead performs a sync. Linearizable reads are retried on another node
// when a node cannot confirm leadership; only the attempt that answered
// defines the operation's interval. A stale read is a single attempt.
func (w *Workload) doRead(ctx context.Context, cl *wclient, stale bool) {
	lie := false
	if !stale && w.cfg.SelfTest && w.FaultActive != nil && w.FaultActive() {
		stale, lie = true, true
	}
	rec := &OpRecord{Client: cl.id, User: cl.user.Name, Kind: KindRead, Lie: lie}
	if stale && !lie {
		rec.Kind = KindStaleRead
	}
	rec.Call = w.now()
	w.hist.add(rec)
	path := "/v1/sync"
	if stale {
		path += "?consistency=stale"
	} else if !lie && cl.lastSync != nil && cl.rng.Float64() < 0.35 {
		// "?since=N" answers {"unchanged": true} iff the state's rev is
		// still N, i.e. the state is exactly what this client's sync at rev
		// N showed. Recorded that way, an "unchanged" judged against a
		// stale view is a linearizability violation like any stale read.
		rec.Since = cl.lastSync.Rev
		path += fmt.Sprintf("?since=%d", rec.Since)
	}
	maxAttempts := 4
	if stale {
		maxAttempts = 1
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		node := w.nodeOf(cl)
		if lie {
			// A broken server would answer every client from local state,
			// including clients of the cut-off minority. Spreading the
			// lies over all nodes reproduces that: about 1/N of them land
			// on the isolated side.
			node = cl.nodeIDs[cl.rng.IntN(len(cl.nodeIDs))]
		}
		inc := w.c.Incarnation(node)
		res, st, en := w.attempt(ctx, rec, w.attemptTimeout(cl), node, http.MethodGet, path, cl.user.Token, "", nil, "")
		if res.ok() {
			var sr api.SyncResponse
			if err := decodeInto(res, &sr); err != nil {
				rec.Outcome, rec.Return, rec.Detail = OutError, en, "undecodable sync: "+err.Error()
				return
			}
			rec.Call, rec.Return, rec.Node, rec.Inc, rec.IncAfter = st, en, node, inc, w.c.Incarnation(node)
			switch {
			case sr.Unchanged && (rec.Since == 0 || sr.Rev != rec.Since):
				rec.Outcome, rec.Return = OutError, en
				rec.Detail = fmt.Sprintf("unchanged=true with rev %d for since=%d", sr.Rev, rec.Since)
				return
			case sr.Unchanged:
				rec.Unchanged = true
				rec.Outcome, rec.Rev, rec.Stale, rec.ServedBy = OutOK, sr.Rev, sr.Stale, sr.ServedBy
				rec.Reads = append([]ReadObs(nil), cl.lastSync.Reads...)
			default:
				w.fillRead(rec, cl.user, &sr)
				if rec.Since != 0 && rec.Outcome == OutOK && sr.Rev == rec.Since {
					rec.Outcome = OutError
					rec.Detail = fmt.Sprintf("full response at rev %d for since=%d (api.md: unchanged expected)", sr.Rev, rec.Since)
					return
				}
			}
			if lie {
				w.lies.Add(1)
			}
			if rec.Outcome == OutOK && rec.Kind == KindRead {
				clean := true
				for _, o := range rec.Reads {
					if o.Bad == "" {
						cl.observe(o.Item, o.Present, o.Version, o.Write)
					} else {
						clean = false
					}
				}
				if clean && !lie && !rec.Unchanged {
					cl.lastSync = rec
				}
			}
			return
		}
		if res.NetErr == nil && res.Status < 500 {
			rec.setError(res, en, "")
			return
		}
		w.rotate(cl)
		if ctx.Err() != nil {
			break
		}
		w.backoff(ctx, attempt, cl.rng)
	}
	rec.Outcome, rec.Return = OutFailed, rec.Attempts[len(rec.Attempts)-1].End
}

// fillRead extracts every item the user can see from a sync response.
func (w *Workload) fillRead(rec *OpRecord, u *userAcct, sr *api.SyncResponse) {
	rec.Outcome, rec.Rev, rec.Stale, rec.ServedBy = OutOK, sr.Rev, sr.Stale, sr.ServedBy
	vaults := map[string]*api.Vault{}
	for i := range sr.Vaults {
		vaults[sr.Vaults[i].ID] = &sr.Vaults[i]
	}
	for _, it := range w.accessible(u) {
		v := vaults[it.Vault]
		if v == nil {
			rec.Outcome = OutError
			rec.Detail = fmt.Sprintf("vault of %s missing from the sync of %s", it.Key, u.Name)
			return
		}
		obs := ReadObs{Item: it.Key}
		for _, item := range v.Items {
			if item.ID != it.ID {
				continue
			}
			obs.Present, obs.Version = true, item.Version
			bi, bw, ok := parseBlob(item.Blob)
			switch {
			case !ok:
				obs.Bad = fmt.Sprintf("unrecognized blob %q", truncate(item.Blob, 48))
			case bi != it.Key:
				obs.Bad = fmt.Sprintf("blob of item %s found in item %s", bi, it.Key)
			default:
				obs.Write = bw
				w.know.learn(item.Version, bw)
			}
		}
		rec.Reads = append(rec.Reads, obs)
	}
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// Resolve re-sends, after the final heal, every write whose outcome is
// still unknown and whose key is young enough to still be in the server's
// idempotency table; the recorded answer (or, if it never committed, the
// effect of applying it now) completes the operation. The operation's
// interval simply extends to the answer: its effect happened somewhere in
// [Call, answer], which is all linearizability needs.
func (w *Workload) Resolve(ctx context.Context) (resolved, stale int) {
	w.resendMu.Lock()
	pending := maps.Clone(w.resend)
	w.resendMu.Unlock()
	recs := w.hist.Records()
	ids := w.c.IDs()
	var mu sync.Mutex // guards the counters
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16) // a broken cluster must not make this serial
	for id, req := range pending {
		rec := recs[id]
		if rec.Outcome != OutUnknown {
			continue
		}
		if w.keySeq.Load()-rec.KeySeq > SafeResendWindow {
			rec.Detail += "; too old to resolve safely"
			stale++
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			for attempt := 0; attempt < 10; attempt++ {
				node := ids[(id+attempt)%len(ids)]
				res, _, en := w.attempt(ctx, rec, w.cfg.AttemptTimeout, node, req.method, req.path, req.user.Token, req.key, req.body, "resolve: ")
				if w.settleWrite(rec, res, en) {
					rec.Resolved = true
					mu.Lock()
					resolved++
					mu.Unlock()
					return
				}
				if res.NetErr == nil && res.Status < 500 {
					rec.setError(res, en, "resolve: ")
					rec.Resolved = true
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	return resolved, stale
}

// FinalReads performs a linearizable sync of every user on every node
// once the cluster has converged. They enter the history (as the last
// operations) and are compared across nodes.
func (w *Workload) FinalReads(ctx context.Context) error {
	ids := w.c.IDs()
	for ni, node := range ids {
		for ui, u := range w.users {
			rec := &OpRecord{Client: w.cfg.Clients + ni*len(w.users) + ui, User: u.Name, Kind: KindRead, Final: true}
			w.hist.add(rec)
			var ok bool
			// At most a minute per read: a cluster that cannot serve one by now
			// has failed the run, and each attempt may take AttemptTimeout.
			for deadline := time.Now().Add(time.Minute); !ok && time.Now().Before(deadline); {
				inc := w.c.Incarnation(node)
				res, st, en := w.attempt(ctx, rec, w.cfg.AttemptTimeout, node, http.MethodGet, "/v1/sync", u.Token, "", nil, "")
				if res.ok() {
					var sr api.SyncResponse
					if err := decodeInto(res, &sr); err != nil {
						return err
					}
					rec.Call, rec.Return, rec.Node, rec.Inc, rec.IncAfter = st, en, node, inc, w.c.Incarnation(node)
					w.fillRead(rec, u, &sr)
					ok = true
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				time.Sleep(250 * time.Millisecond)
			}
			if !ok {
				rec.Outcome = OutFailed
				rec.Return = rec.Attempts[len(rec.Attempts)-1].End
				return fmt.Errorf("final read of %s on %s failed: %s", u.Name, node, rec.Attempts[len(rec.Attempts)-1].Result)
			}
		}
	}
	return nil
}

// marshalUsers is for artifacts (no secrets).
func (w *Workload) marshalSetup() json.RawMessage {
	b, _ := json.Marshal(struct {
		Users []*userAcct `json:"users"`
		Items []itemRef   `json:"items"`
	}{w.users, w.items})
	return b
}
