package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
)

// RunConfig configures one chaos run (one seed).
type RunConfig struct {
	Mode     string // "inproc" or "procs"
	Seed     int64
	Duration time.Duration // length of the fault phase
	Nodes    int
	Clients  int
	Items    int
	Fsync    bool // in-process: real fsync (vaultd always fsyncs)
	TLS      bool // process mode: mutual TLS with a household CA
	Faults   string
	// OutDir receives the artifacts of this run in OutDir/seed-<seed>. If
	// empty, artifacts are written only when a check fails, into the work
	// directory (which is then kept).
	OutDir string
	// WorkDir holds node data and logs ("" = a fresh temp dir, removed
	// after a passing run unless KeepData).
	WorkDir     string
	KeepData    bool
	SelfTest    bool
	BackupDrill bool
	VaultdBin   string // "" = build ./cmd/vaultd when needed
	// PorcupineTimeout bounds the linearizability search (a timeout is a
	// failure: an undecided check is not a pass).
	PorcupineTimeout time.Duration
	// Nemesis timing; zero values select the defaults.
	MinFault, MaxFault, MinGap, MaxGap time.Duration
	// SnapshotThreshold 0 = chosen from the seed (small values make
	// snapshots and snapshot installs frequent).
	SnapshotThreshold uint64
	// OpBudget overrides how long a client retries one write (default
	// 30 s). A budget shorter than the faults turns operations into
	// unknown outcomes on purpose, exercising the resolution path and the
	// model's treatment of indeterminate operations.
	OpBudget time.Duration
	// AttemptTimeout overrides the long per-attempt timeout (default 12 s).
	AttemptTimeout time.Duration
	// NoResolve leaves unknown outcomes unresolved after the heal, so the
	// checker must cope with operations that may or may not have taken
	// effect at any time (a test of the harness, not of the system).
	NoResolve bool
	Log       io.Writer
}

// Availability numbers are reported, not asserted (unless absurd).
type Availability struct {
	MajorityOps       int     `json:"majority_ops"`
	MajoritySucceeded int     `json:"majority_succeeded"`
	MajorityFraction  float64 `json:"majority_fraction"`
	AllOps            int     `json:"all_ops"`
	AllSucceeded      int     `json:"all_succeeded"`
	LeaderKills       int     `json:"leader_kills"`
	// Leader kills that removed quorum (or were followed by another fault
	// before writes resumed): excluded from the failover numbers.
	LeaderKillsNoQuorum int           `json:"leader_kills_no_quorum"`
	MaxGapAfterKill     time.Duration `json:"max_gap_after_leader_kill_ns"`
	MeanGapAfterKill    time.Duration `json:"mean_gap_after_leader_kill_ns"`
	MaxWriteGap         time.Duration `json:"max_write_gap_ns"`
	MajorityTime        time.Duration `json:"majority_connected_ns"`
	FaultPhase          time.Duration `json:"fault_phase_ns"`
	// How hard the faults bit: operations answered on their first attempt,
	// and latency (invocation to definite answer, retries included).
	FirstAttempt int           `json:"first_attempt"`
	Retried      int           `json:"retried"`
	P50          time.Duration `json:"p50_ns"`
	P99          time.Duration `json:"p99_ns"`
	Max          time.Duration `json:"max_ns"`
}

// Result summarizes a run.
type Result struct {
	Config       RunConfig        `json:"-"`
	Seed         int64            `json:"seed"`
	Mode         string           `json:"mode"`
	Counts       map[string]int   `json:"counts"`
	Lies         int64            `json:"lies,omitempty"`
	Episodes     int              `json:"episodes"`
	Events       int              `json:"events"`
	Availability Availability     `json:"availability"`
	Checks       []*Check         `json:"checks"`
	Porcupine    *PorcupineResult `json:"porcupine,omitempty"`
	Pass         bool             `json:"pass"`
	ArtifactDir  string           `json:"artifact_dir,omitempty"`
	WorkDir      string           `json:"work_dir,omitempty"`
	Elapsed      time.Duration    `json:"elapsed_ns"`
	FaultStats   *FaultNetStats   `json:"fault_stats,omitempty"`
	Snapshot     uint64           `json:"snapshot_threshold"`
	Err          string           `json:"error,omitempty"`
	Timeline     []Event          `json:"-"`

	recs  []*OpRecord
	setup json.RawMessage
}

// PorcupineViolation reports whether Porcupine found (decided) a
// non-linearizable history.
func (r *Result) PorcupineViolation() bool {
	return r.Porcupine != nil && r.Porcupine.Result == "Illegal"
}

const bootstrapToken = "chaos-bootstrap-token-0123456789"

func (cfg *RunConfig) fill() {
	if cfg.Mode == "" {
		cfg.Mode = "inproc"
	}
	if cfg.Nodes <= 0 {
		cfg.Nodes = 3
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 30 * time.Second
	}
	if cfg.PorcupineTimeout <= 0 {
		cfg.PorcupineTimeout = 3 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
}

func (cfg *RunConfig) durability() string {
	if cfg.Mode == "procs" {
		if cfg.TLS {
			return "fsync=always tls=mutual"
		}
		return "fsync=always tls=off(insecure)"
	}
	return fmt.Sprintf("fsync=%v", cfg.Fsync)
}

// Run executes one seed: start a cluster, set it up, run the workload
// under the nemesis, heal, check everything, and tear down.
func Run(ctx context.Context, cfg RunConfig) (res *Result) {
	cfg.fill()
	t0 := time.Now()
	res = &Result{Config: cfg, Seed: cfg.Seed, Mode: cfg.Mode, Counts: map[string]int{}}
	logf := func(format string, args ...any) {
		fmt.Fprintf(cfg.Log, "[seed %d %s] %s\n", cfg.Seed, time.Since(t0).Round(100*time.Millisecond), fmt.Sprintf(format, args...))
	}
	addCheck := func(c *Check) { res.Checks = append(res.Checks, c) }

	workDir := cfg.WorkDir
	if workDir == "" {
		d, err := os.MkdirTemp("", fmt.Sprintf("vault-chaos-%d-", cfg.Seed))
		if err != nil {
			res.Err = err.Error()
			return res
		}
		workDir = d
	} else if err := os.MkdirAll(workDir, 0o700); err != nil {
		res.Err = err.Error()
		return res
	}
	res.WorkDir = workDir
	// Artifacts go to OutDir/seed-<seed>, or, without OutDir and only for a
	// failing run, into the work directory (which is then kept).
	artifactDir := filepath.Join(workDir, "artifacts")
	if cfg.OutDir != "" {
		artifactDir = filepath.Join(cfg.OutDir, fmt.Sprintf("seed-%d", cfg.Seed))
	}
	defer func() {
		res.Elapsed = time.Since(t0)
		if ctx.Err() != nil && res.Err == "" {
			// Checks of a run cut short are meaningless either way.
			res.Err = "interrupted"
		}
		res.Pass = res.Err == ""
		for _, c := range res.Checks {
			if !c.Pass && !c.Skipped {
				res.Pass = false
			}
		}
		if (cfg.OutDir != "" || !res.Pass) && res.ArtifactDir == "" {
			res.ArtifactDir = artifactDir
		}
		if res.ArtifactDir != "" {
			writeResultArtifacts(res)
			writeHistory(res.ArtifactDir, res.recs, res.setup)
		}
		if res.Pass && cfg.WorkDir == "" && !cfg.KeepData {
			os.RemoveAll(workDir)
			res.WorkDir = ""
		}
	}()

	// The snapshot threshold is part of the seed's configuration: small
	// thresholds make followers that were down catch up by snapshot.
	thr := cfg.SnapshotThreshold
	if thr == 0 {
		thr = []uint64{64, 256, 1024, 4096}[rand.New(rand.NewPCG(uint64(cfg.Seed), 0x5ba9)).IntN(4)]
	}
	res.Snapshot = thr

	// Process mode needs vaultd at once; in-process mode only for the backup
	// drill at the end, so building it overlaps with the run.
	type built struct {
		path string
		err  error
	}
	buildc := make(chan built, 1)
	if cfg.Mode == "procs" || cfg.BackupDrill {
		go func() {
			p, err := vaultdBinary(ctx, cfg)
			buildc <- built{p, err}
		}()
	}
	getBin := sync.OnceValues(func() (string, error) {
		b := <-buildc
		return b.path, b.err
	})

	var c Cluster
	var err error
	switch cfg.Mode {
	case "inproc":
		logDir := filepath.Join(workDir, "logs")
		_ = os.MkdirAll(logDir, 0o700)
		c, err = StartInproc(InprocConfig{Nodes: cfg.Nodes, Dir: filepath.Join(workDir, "nodes"), Fsync: cfg.Fsync,
			SnapshotThreshold: thr, BootstrapToken: bootstrapToken, Seed: cfg.Seed, LogDir: logDir})
	case "procs":
		var bin string
		if bin, err = getBin(); err != nil {
			res.Err = "build vaultd: " + err.Error()
			return res
		}
		c, err = StartProcs(ProcsConfig{Nodes: cfg.Nodes, Dir: filepath.Join(workDir, "nodes"), VaultdBin: bin, TLS: cfg.TLS,
			SnapshotThreshold: thr, BootstrapToken: bootstrapToken, Seed: cfg.Seed})
	default:
		err = fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if err != nil {
		res.Err = "start cluster: " + err.Error()
		return res
	}
	shutdown := sync.OnceFunc(func() {
		_ = c.Shutdown()
		if pc, ok := c.(interface{ Leftovers() []string }); ok {
			chk := newCheck("no leftover vaultd processes")
			for _, l := range pc.Leftovers() {
				chk.fail("%s", l)
			}
			addCheck(chk)
		}
	})
	defer shutdown()
	faults, err := ParseFaults(cfg.Faults, c.Capabilities())
	if err != nil {
		res.Err = err.Error()
		return res
	}
	logf("mode=%s nodes=%d clients=%d items=%d duration=%v %s snapshot_threshold=%d faults=%s",
		cfg.Mode, cfg.Nodes, cfg.Clients, cfg.Items, cfg.Duration, cfg.durability(), thr, strings.Join(faults, ","))

	if _, err := waitApplied(ctx, c, 60*time.Second); err != nil {
		res.Err = "initial cluster: " + err.Error()
		return res
	}
	start := time.Now()
	w := NewWorkload(c, WorkloadConfig{Clients: cfg.Clients, Items: cfg.Items, Seed: cfg.Seed, SelfTest: cfg.SelfTest,
		OpBudget: cfg.OpBudget, AttemptTimeout: cfg.AttemptTimeout}, start)
	if err := w.Setup(ctx, bootstrapToken); err != nil {
		res.Err = "setup: " + err.Error()
		return res
	}
	logf("setup done: 2 users, %d items; running faults for %v", len(w.Items()), cfg.Duration)

	nem := NewNemesis(c, NemesisConfig{Seed: cfg.Seed, Faults: faults, MinFault: cfg.MinFault, MaxFault: cfg.MaxFault,
		MinGap: cfg.MinGap, MaxGap: cfg.MaxGap}, start)
	w.FaultActive = nem.PartitionActive
	phaseStart := w.now()
	stop := make(chan struct{})
	hard, cancelHard := context.WithCancel(ctx)
	defer cancelHard()
	clientsDone := make(chan struct{})
	go func() {
		w.Run(hard, stop)
		close(clientsDone)
	}()
	nctx, cancelN := context.WithTimeout(ctx, cfg.Duration)
	nem.Run(nctx)
	cancelN()
	phaseEnd := w.now()
	nem.HealAll()
	logf("fault phase over (%d episodes); healed, waiting for recovery", nem.Episodes())

	// Recovery is judged with the clients still running: every node must
	// be back and following one leader. Only then do the clients stop.
	recovery := newCheck("recovery after the final heal")
	healStart := time.Now()
	leader, err := waitHealthy(ctx, c, 90*time.Second)
	if err != nil {
		recovery.fail("%v", err)
	} else {
		recovery.Detail = fmt.Sprintf("leader %s after %v", leader, time.Since(healStart).Round(10*time.Millisecond))
	}
	close(stop)
	select {
	case <-clientsDone:
	case <-time.After(w.cfg.OpBudget + w.cfg.AttemptTimeout + 10*time.Second):
		recovery.fail("clients did not finish their last operations")
		cancelHard()
		<-clientsDone
	}
	resolved, tooOld := 0, 0
	// A cluster that did not recover cannot answer the re-sends either; the
	// run has failed already.
	if !cfg.NoResolve && recovery.Pass {
		resolved, tooOld = w.Resolve(ctx)
	}
	logf("clients stopped; resolved %d unknown outcomes (%d too old to re-send)", resolved, tooOld)
	// With nothing in flight any more, every node must reach the same
	// applied index.
	if l, err := waitConverged(ctx, c, 60*time.Second); err != nil {
		recovery.fail("after the clients stopped: %v", err)
	} else {
		leader = l
	}
	addCheck(recovery)

	final := newCheck("final reads agree on every node")
	if err := w.FinalReads(ctx); err != nil {
		final.fail("%v", err)
	}
	end := w.now() + 1

	conv := newCheck("convergence (same applied index and state on every node)")
	digests := map[string]*Digest{}
	for _, id := range c.IDs() {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		d, err := c.Digest(dctx, id)
		cancel()
		if err != nil {
			conv.fail("%s: %v", id, err)
			continue
		}
		digests[id] = d
	}
	var ref *Digest
	for _, id := range c.IDs() {
		d := digests[id]
		if d == nil {
			continue
		}
		if ref == nil {
			ref = d
			continue
		}
		if d.Applied != ref.Applied {
			conv.fail("%s applied %d, %s applied %d", d.Node, d.Applied, ref.Node, ref.Applied)
		}
		if d.Hash != ref.Hash {
			conv.fail("%s state %s (%s) != %s state %s at applied %d/%d", d.Node, d.Hash[:16], d.HashKind, ref.Node, ref.Hash[:16], d.Applied, ref.Applied)
		}
		if d.Rev != ref.Rev {
			conv.fail("%s rev %d != %s rev %d", d.Node, d.Rev, ref.Node, ref.Rev)
		}
	}
	if ref != nil && conv.Pass {
		conv.Detail = fmt.Sprintf("leader %s; applied %d, rev %d, %s %s on all %d nodes", leader, ref.Applied, ref.Rev, ref.HashKind, ref.Hash[:16], len(digests))
	}
	addCheck(conv)

	recs := w.History().Records()
	res.recs, res.setup = recs, w.marshalSetup()
	compareFinalReads(final, recs)
	addCheck(final)

	if cfg.BackupDrill {
		addCheck(backupDrill(ctx, c, w, recs, workDir, getBin, logf))
	}
	shutdown()
	logf("cluster shut down; checking %d records", len(recs))

	findingsCheck := newCheck("no unexpected node failures")
	for _, f := range c.Findings() {
		findingsCheck.fail("%s", f)
	}
	addCheck(findingsCheck)

	itemKeys := make([]string, 0, len(w.Items()))
	for _, it := range w.Items() {
		itemKeys = append(itemKeys, it.Key)
	}
	a := analyze(recs, itemKeys)
	addCheck(a.checkBijection())
	pr := a.checkPorcupine(end, cfg.PorcupineTimeout, artifactDir)
	res.Porcupine = pr
	if !pr.Pass {
		res.ArtifactDir = artifactDir
	}
	addCheck(&pr.Check)
	addCheck(a.checkRevOrder())
	addCheck(a.checkReadMonotonic())
	addCheck(a.checkReadSnapshots())
	addCheck(a.checkChains())
	addCheck(a.checkAckedWritesSurvive())
	addCheck(a.checkStaleReads())
	addCheck(a.checkAnomalies())

	for _, r := range recs {
		if r.Final {
			continue
		}
		res.Counts[r.Kind+"/"+r.Outcome]++
		if r.Resolved {
			res.Counts[r.Kind+"/resolved"]++
		}
	}
	res.Lies = w.lies.Load()
	res.Counts["abandoned_idempotency_window"] = int(w.keyBudget.Load())
	res.Timeline = nem.Timeline()
	res.Episodes, res.Events = nem.Episodes(), len(res.Timeline)
	res.Availability = computeAvailability(recs, nem.Connectivity(), res.Timeline, phaseStart, phaseEnd)
	avail := newCheck("availability not absurd")
	if res.Availability.MajorityOps >= 50 && res.Availability.MajorityFraction < 0.25 {
		avail.fail("only %.1f%% of %d operations succeeded while a majority was connected", 100*res.Availability.MajorityFraction, res.Availability.MajorityOps)
	}
	if res.Availability.AllSucceeded == 0 {
		avail.fail("no operation succeeded at all")
	}
	addCheck(avail)
	if ic, ok := c.(*inprocCluster); ok {
		s := ic.FaultStats()
		res.FaultStats = &s
	}
	return res
}

// compareFinalReads: every node's final read shows the same items, and
// they agree with each other per user.
func compareFinalReads(chk *Check, recs []*OpRecord) {
	ref := map[string]map[string]ReadObs{}
	refNode := map[string]string{}
	n := 0
	for _, r := range recs {
		if !r.Final || r.Outcome != OutOK {
			continue
		}
		n++
		m := map[string]ReadObs{}
		for _, o := range r.Reads {
			m[o.Item] = o
		}
		if ref[r.User] == nil {
			ref[r.User], refNode[r.User] = m, r.Node
			continue
		}
		for item, o := range ref[r.User] {
			p := m[item]
			if p.Present != o.Present || p.Version != o.Version || p.Write != o.Write {
				chk.fail("user %s item %s: %s shows %s, %s shows %s", r.User, item, refNode[r.User], descObs(o), r.Node, descObs(p))
			}
		}
	}
	if chk.Pass {
		chk.Detail = fmt.Sprintf("%d final reads", n)
	}
}

func descObs(o ReadObs) string {
	if !o.Present {
		return "absent"
	}
	return fmt.Sprintf("%s@%d", o.Write, o.Version)
}

// computeAvailability derives the reported availability numbers from the
// history and the nemesis's connectivity samples.
func computeAvailability(recs []*OpRecord, conn []connSample, evs []Event, phaseStart, phaseEnd int64) Availability {
	var av Availability
	av.FaultPhase = time.Duration(phaseEnd - phaseStart)
	// majority reports whether a majority was connected during the whole of
	// [from, to].
	majority := func(from, to int64) bool {
		state := true
		for _, s := range conn {
			if s.T <= from {
				state = s.Majority
				continue
			}
			if s.T > to {
				break
			}
			if !s.Majority {
				return false
			}
		}
		return state
	}
	// A grace second before an op lets a leader be elected after a heal;
	// without it every op right after a heal would count against
	// availability for a fault that had just ended.
	const grace = int64(time.Second)
	for i, s := range conn {
		endT := phaseEnd
		if i+1 < len(conn) {
			endT = min(conn[i+1].T, phaseEnd)
		}
		if s.Majority && endT > s.T {
			av.MajorityTime += time.Duration(endT - max(s.T, phaseStart))
		}
	}
	var writeOK []int64
	var lat []time.Duration
	for _, r := range recs {
		if r.Final || r.Setup || r.Call < phaseStart || r.Call > phaseEnd {
			continue
		}
		if r.Kind == KindStaleRead {
			continue
		}
		succeeded := r.Outcome == OutOK || r.Outcome == OutConflict
		if r.Resolved {
			succeeded = false // only learned after the heal
		}
		av.AllOps++
		if succeeded {
			av.AllSucceeded++
			lat = append(lat, time.Duration(r.Return-r.Call))
			if len(r.Attempts) == 1 {
				av.FirstAttempt++
			}
		}
		if len(r.Attempts) > 1 {
			av.Retried++
		}
		ret := r.Return
		if ret == 0 || r.Resolved {
			ret = r.Call + int64(30*time.Second)
		}
		if majority(r.Call-grace, ret) {
			av.MajorityOps++
			if succeeded {
				av.MajoritySucceeded++
			}
		}
		if r.isWrite() && r.Outcome == OutOK && !r.Resolved {
			writeOK = append(writeOK, r.Return)
		}
	}
	if av.MajorityOps > 0 {
		av.MajorityFraction = float64(av.MajoritySucceeded) / float64(av.MajorityOps)
	}
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		av.P50, av.P99, av.Max = lat[len(lat)/2], lat[len(lat)*99/100], lat[len(lat)-1]
	}
	sort.Slice(writeOK, func(i, j int) bool { return writeOK[i] < writeOK[j] })
	prev := phaseStart
	for _, t := range writeOK {
		if t > phaseEnd {
			break
		}
		if d := time.Duration(t - prev); d > av.MaxWriteGap {
			av.MaxWriteGap = d
		}
		prev = t
	}
	// Failover time: from a leader kill to the next successful write, for
	// kills after which a majority stayed connected until that write.
	// Kills that left no quorum (or were followed by a fault that removed
	// it) measure the schedule, not failover, and are counted separately.
	var sum time.Duration
	for _, e := range evs {
		if !e.LeaderKill {
			continue
		}
		i := sort.Search(len(writeOK), func(i int) bool { return writeOK[i] > e.T })
		if i == len(writeOK) {
			continue
		}
		if !majority(e.T+1, writeOK[i]) {
			av.LeaderKillsNoQuorum++
			continue
		}
		av.LeaderKills++
		gap := time.Duration(writeOK[i] - e.T)
		sum += gap
		av.MaxGapAfterKill = max(av.MaxGapAfterKill, gap)
	}
	if av.LeaderKills > 0 {
		av.MeanGapAfterKill = sum / time.Duration(av.LeaderKills)
	}
	return av
}

// backupDrill: download the admin backup, stop the cluster, `vaultd
// restore` it into fresh data directories on every node, start, log in
// again (the backup carries no cluster key, so old tokens must be dead),
// and verify that every node serves the same items and accepts a write.
func backupDrill(ctx context.Context, c Cluster, w *Workload, recs []*OpRecord, workDir string, getBin func() (string, error), logf func(string, ...any)) *Check {
	chk := newCheck("backup drill (admin backup -> vaultd restore on fresh dirs -> same items)")
	var expect map[string]ReadObs
	for _, r := range recs {
		if r.Final && r.Outcome == OutOK && r.User == "alice" {
			expect = map[string]ReadObs{}
			for _, o := range r.Reads {
				expect[o.Item] = o
			}
			break
		}
	}
	if expect == nil {
		chk.fail("no final read to compare with")
		return chk
	}
	alice, bob := w.users[0], w.users[1]
	hc := c.HTTPClient()
	ids := c.IDs()
	var backup api.ServerBackup
	raw, ok := getRetry(ctx, hc, func(i int) string { return c.URL(ids[i%len(ids)]) + "/v1/admin/backup" }, alice.Token, 15*time.Second, &backup)
	if !ok {
		chk.fail("GET /v1/admin/backup failed")
		return chk
	}
	path := filepath.Join(workDir, "backup.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		chk.fail("write backup: %v", err)
		return chk
	}
	sum := sha256.Sum256(backup.State)
	want := hex.EncodeToString(sum[:])
	logf("backup drill: backup of rev %d (%d bytes); restoring on every node", backup.Rev, len(backup.State))
	bin, err := getBin()
	if err != nil {
		chk.fail("build vaultd: %v", err)
		return chk
	}
	digests, err := c.RestoreFromBackup(ctx, bin, path)
	if err != nil {
		chk.fail("restore: %v", err)
		return chk
	}
	for id, d := range digests {
		if d != want {
			chk.fail("vaultd restore on %s printed digest %s, backup state hashes to %s", id, d, want)
		}
	}
	if _, err := waitApplied(ctx, c, 60*time.Second); err != nil {
		chk.fail("restored cluster: %v", err)
		return chk
	}
	// Old sessions must be gone: the restored cluster minted a new key.
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	r := apiCall(actx, hc, http.MethodGet, c.URL(ids[0])+"/v1/sync", alice.Token, "", nil)
	cancel()
	if r.NetErr != nil || r.Status != http.StatusUnauthorized {
		chk.fail("an old token on the restored cluster got %s, want 401", r.short())
	}
	for _, u := range []*userAcct{alice, bob} {
		var lr api.LoginResponse
		if err := w.setupCall(ctx, http.MethodPost, "/v1/login", "", false, api.LoginRequest{Username: u.Name, LoginKey: u.LoginKey}, &lr); err != nil {
			chk.fail("login %s after restore: %v", u.Name, err)
			return chk
		}
		u.Token = lr.Token
	}
	c.SetAdminToken(alice.Token)
	for _, id := range ids {
		var sr api.SyncResponse
		if _, ok := getRetry(ctx, hc, func(int) string { return c.URL(id) + "/v1/sync" }, alice.Token, 10*time.Second, &sr); !ok {
			chk.fail("sync on restored %s failed", id)
			continue
		}
		rec := &OpRecord{}
		w.fillRead(rec, alice, &sr)
		for _, o := range rec.Reads {
			e := expect[o.Item]
			if o.Present != e.Present || o.Version != e.Version || o.Write != e.Write || o.Bad != "" {
				chk.fail("restored %s: item %s is %s, before the backup it was %s", id, o.Item, descObs(o), descObs(e))
			}
		}
	}
	// The restored cluster must accept writes.
	it := w.items[0]
	e := expect[it.Key]
	body := api.PutItemRequest{Blob: makeBlob(it.Key, "w-restore"), BaseVersion: e.Version, KeyEpoch: 1}
	var mr api.MutationResponse
	if err := w.setupCall(ctx, http.MethodPut, w.itemPath(it), alice.Token, true, body, &mr); err != nil {
		chk.fail("write after restore: %v", err)
	}
	if chk.Pass {
		chk.Detail = fmt.Sprintf("backup rev %d restored on %d nodes (digest %s), %d items identical, users logged in again, write accepted at rev %d",
			backup.Rev, len(digests), want[:16], len(expect), mr.Rev)
	}
	return chk
}

// getRetry GETs url(i) on attempt i, up to 20 times, until the answer is a
// success that decodes into out, and returns the raw body.
func getRetry(ctx context.Context, hc *http.Client, url func(int) string, token string, timeout time.Duration, out any) ([]byte, bool) {
	for i := 0; i < 20; i++ {
		actx, cancel := context.WithTimeout(ctx, timeout)
		r := apiCall(actx, hc, http.MethodGet, url(i), token, "", nil)
		cancel()
		if r.ok() && json.Unmarshal(r.Body, out) == nil {
			return r.Body, true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil, false
}

// writeResultArtifacts writes the history, timeline and summary.
func writeResultArtifacts(res *Result) {
	dir := res.ArtifactDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if b, err := json.MarshalIndent(res, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "result.json"), b, 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "timeline.txt"), []byte(FormatTimeline(res.Timeline)), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "summary.txt"), []byte(res.Summary()), 0o644)
}

// writeHistory writes the raw records and the setup (users without
// secrets, items).
func writeHistory(dir string, recs []*OpRecord, setup json.RawMessage) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	b, err := json.MarshalIndent(struct {
		Setup   json.RawMessage `json:"setup"`
		Records []*OpRecord     `json:"records"`
	}{setup, recs}, "", " ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(dir, "history.json"), b, 0o644)
	}
}

// Summary renders the end-of-run report.
func (r *Result) Summary() string {
	var b strings.Builder
	cfg := r.Config
	fmt.Fprintf(&b, "vault-chaos seed %d: mode=%s nodes=%d clients=%d items=%d duration=%v %s snapshot_threshold=%d selftest=%v\n",
		r.Seed, r.Mode, cfg.Nodes, cfg.Clients, cfg.Items, cfg.Duration, cfg.durability(), r.Snapshot, cfg.SelfTest)
	if r.Err != "" {
		fmt.Fprintf(&b, "  ERROR: %s\n", r.Err)
	}
	kinds := []string{KindRead, KindStaleRead, KindPut, KindDelete}
	outs := []string{OutOK, OutConflict, OutFailed, OutUnknown, OutError, "resolved"}
	total := 0
	for _, k := range kinds {
		for _, o := range outs[:5] {
			total += r.Counts[k+"/"+o]
		}
	}
	fmt.Fprintf(&b, "  operations: %d\n", total)
	for _, k := range kinds {
		var parts []string
		sum := 0
		for _, o := range outs {
			if n := r.Counts[k+"/"+o]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", o, n))
				if o != "resolved" {
					sum += n
				}
			}
		}
		fmt.Fprintf(&b, "    %-10s %6d  (%s)\n", k, sum, strings.Join(parts, ", "))
	}
	if n := r.Counts["abandoned_idempotency_window"]; n > 0 {
		fmt.Fprintf(&b, "    %d writes stopped retrying to stay inside the idempotency window\n", n)
	}
	if r.Lies > 0 {
		fmt.Fprintf(&b, "  SELF-TEST: %d stale reads were recorded as linearizable\n", r.Lies)
	}
	fmt.Fprintf(&b, "  nemesis: %d episodes, %d timeline events\n", r.Episodes, r.Events)
	av := r.Availability
	fmt.Fprintf(&b, "  availability: %.1f%% of %d ops succeeded while a majority was connected (majority connected %.0f%% of the fault phase); %.1f%% of all %d ops\n",
		100*av.MajorityFraction, av.MajorityOps, 100*safeDiv(float64(av.MajorityTime), float64(av.FaultPhase)),
		100*safeDiv(float64(av.AllSucceeded), float64(av.AllOps)), av.AllOps)
	fmt.Fprintf(&b, "  fault impact: %d ops needed retries, %d answered on the first attempt; latency p50 %v p99 %v max %v\n",
		av.Retried, av.FirstAttempt, av.P50.Round(100*time.Microsecond), av.P99.Round(time.Millisecond), av.Max.Round(time.Millisecond))
	fmt.Fprintf(&b, "  write gaps: longest after a leader kill %v (mean %v over %d kills with a majority left; %d more kills left no quorum); longest overall %v\n",
		av.MaxGapAfterKill.Round(time.Millisecond), av.MeanGapAfterKill.Round(time.Millisecond), av.LeaderKills, av.LeaderKillsNoQuorum, av.MaxWriteGap.Round(time.Millisecond))
	if r.FaultStats != nil {
		s := r.FaultStats
		fmt.Fprintf(&b, "  network: %d sent (%d InstallSnapshot), cut %d on send + %d on receive + %d after delay, dropped %d, duplicated %d, delayed %d\n",
			s.Sent, s.Snapshots, s.CutOnSend, s.CutOnReceive, s.CutAfterDelay, s.Dropped, s.Duplicated, s.Delayed)
	}
	b.WriteString("  checks:\n")
	for _, c := range r.Checks {
		status := "PASS"
		switch {
		case c.Skipped:
			status = "SKIP"
		case !c.Pass:
			status = "FAIL"
		}
		fmt.Fprintf(&b, "    %s %s", status, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(&b, ": %s", c.Detail)
		}
		b.WriteString("\n")
		for i, v := range c.Violations {
			if i >= 10 {
				fmt.Fprintf(&b, "        ... %d more (see result.json)\n", len(c.Violations)-10)
				break
			}
			fmt.Fprintf(&b, "        - %s\n", v)
		}
	}
	if r.ArtifactDir != "" {
		fmt.Fprintf(&b, "  artifacts: %s\n", r.ArtifactDir)
	}
	if r.WorkDir != "" {
		fmt.Fprintf(&b, "  node data and logs: %s\n", r.WorkDir)
	}
	verdict := "PASS"
	switch {
	case r.Err == "interrupted":
		verdict = "INTERRUPTED"
	case !r.Pass:
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "  RESULT: %s (%v)\n", verdict, r.Elapsed.Round(100*time.Millisecond))
	return b.String()
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}
