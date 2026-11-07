package chaos

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fault episode kinds.
const (
	FIsolate         = "isolate"           // one node cut off (both directions)
	FIsolateLeader   = "isolate-leader"    // the current leader cut off
	FSplit           = "split"             // minority | majority, leader on either side
	FOneWay          = "one-way"           // a node can only send, or only receive
	FBridge          = "bridge"            // A-B and B-C connected, A-C cut
	FFlap            = "flap"              // rapid isolate/heal cycles of random nodes
	FKill            = "kill"              // kill one node, restart after a random delay
	FKillLeader      = "kill-leader"       // kill the current leader, restart later
	FKillMajority    = "kill-majority"     // kill a majority (no quorum), restart one by one
	FPause           = "pause"             // SIGSTOP one node, SIGCONT later (process mode)
	FPauseLeader     = "pause-leader"      // SIGSTOP the leader: it wakes up believing it still leads
	FLossy           = "lossy"             // loss, duplication and jitter on every link
	FSlow            = "slow"              // high latency on every link
	FLate            = "late"              // 0.2-2.5 s jittered delay on one or two links: very late, reordered messages
	FDupStorm        = "dup-storm"         // most messages delivered twice, with jitter (in-process)
	FPartitionKill   = "partition+kill"    // isolate A, then kill a majority-side node (no quorum)
	FKillPartition   = "kill+partition"    // kill A, split the rest (no quorum), restart A as the bridge
	FPausePartition  = "pause+partition"   // pause the leader, isolate it while paused, wake it isolated
	FLossyKillLeader = "lossy+kill-leader" // kill the leader on a lossy network
)

// FaultGroups are the names accepted by --faults besides individual kinds.
var FaultGroups = map[string][]string{
	"partition": {FIsolate, FIsolateLeader, FSplit, FOneWay, FBridge, FFlap},
	"kill":      {FKill, FKillLeader, FKillMajority},
	"pause":     {FPause, FPauseLeader},
	"net":       {FLossy, FSlow, FLate, FDupStorm},
	"combo":     {FPartitionKill, FKillPartition, FPausePartition, FLossyKillLeader},
}

// AllFaults lists every episode kind.
func AllFaults() []string {
	var out []string
	for _, g := range []string{"partition", "kill", "pause", "net", "combo"} {
		out = append(out, FaultGroups[g]...)
	}
	return out
}

func needsCap(kind string, caps Caps) bool {
	switch kind {
	case FPause, FPauseLeader, FPausePartition:
		return caps.Pause
	case FLossy, FLossyKillLeader:
		return caps.Loss || caps.Delay
	case FSlow, FLate:
		return caps.Delay
	case FDupStorm:
		return caps.Dup
	}
	return true
}

// ParseFaults resolves a --faults spec ("all", or a comma-separated list of
// kinds and group names, "-kind" removes) against what the backend
// supports. Unsupported kinds are dropped silently only when they came
// from a group; naming one explicitly is an error.
func ParseFaults(spec string, caps Caps) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		spec = "all"
	}
	known := map[string]bool{}
	for _, k := range AllFaults() {
		known[k] = true
	}
	set := map[string]bool{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == "none" {
			continue
		}
		remove := strings.HasPrefix(tok, "-")
		tok = strings.TrimPrefix(tok, "-")
		var kinds []string
		explicit := false
		switch {
		case tok == "all":
			kinds = AllFaults()
		case FaultGroups[tok] != nil:
			kinds = FaultGroups[tok]
		case known[tok]:
			kinds, explicit = []string{tok}, true
		default:
			return nil, fmt.Errorf("unknown fault %q (kinds: %s; groups: all, partition, kill, pause, net, combo)", tok, strings.Join(AllFaults(), ", "))
		}
		for _, k := range kinds {
			if remove {
				delete(set, k)
				continue
			}
			if !needsCap(k, caps) {
				if explicit {
					return nil, fmt.Errorf("fault %q is not supported by this backend", k)
				}
				continue
			}
			set[k] = true
		}
	}
	var out []string
	for _, k := range AllFaults() {
		if set[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

// NemesisConfig shapes the schedule.
type NemesisConfig struct {
	Seed   int64
	Faults []string
	// Fault episodes last [MinFault, MaxFault]; healthy periods between
	// them last [MinGap, MaxGap].
	MinFault, MaxFault time.Duration
	MinGap, MaxGap     time.Duration
}

func (c *NemesisConfig) fill() {
	if c.MaxFault <= 0 {
		c.MinFault, c.MaxFault = time.Second, 5*time.Second
	}
	if c.MaxGap <= 0 {
		c.MinGap, c.MaxGap = 500*time.Millisecond, 2500*time.Millisecond
	}
}

// Event is one entry of the nemesis timeline.
type Event struct {
	T          int64  `json:"t"` // ns since run start
	Episode    int    `json:"episode"`
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	LeaderKill bool   `json:"leader_kill,omitempty"`
}

// connSample records, after every change, whether a majority of nodes was
// up and mutually connected.
type connSample struct {
	T        int64
	Majority bool
}

// episode is one scheduled fault. Every episode consumes the same number
// of random draws whatever its kind, so the schedule for a seed does not
// depend on run-time conditions (who happens to be leader).
type episode struct {
	N          int
	Kind       string
	Dur, Gap   time.Duration
	Perm       []int
	F1, F2     float64
	D1         time.Duration
	Sub        uint64
	leaderName string
}

// Nemesis injects the faults of a seeded schedule and records a timeline.
type Nemesis struct {
	cfg   NemesisConfig
	c     Cluster
	ids   []string
	caps  Caps
	rng   *rand.Rand
	start time.Time

	mu       sync.Mutex
	events   []Event
	conn     []connSample
	down     map[string]bool
	paused   map[string]bool
	blocked  map[link]bool
	episodes int

	partitioned atomic.Bool
}

// NewNemesis prepares a nemesis; Run starts it.
func NewNemesis(c Cluster, cfg NemesisConfig, start time.Time) *Nemesis {
	cfg.fill()
	n := &Nemesis{cfg: cfg, c: c, ids: c.IDs(), caps: c.Capabilities(),
		rng:   rand.New(rand.NewPCG(uint64(cfg.Seed), 0x7e3e515)),
		start: start, down: map[string]bool{}, paused: map[string]bool{}, blocked: map[link]bool{}}
	n.conn = append(n.conn, connSample{T: 0, Majority: true})
	return n
}

// PartitionActive reports whether some link is cut or blackholed right
// now (used by the self-test to decide when to lie).
func (n *Nemesis) PartitionActive() bool { return n.partitioned.Load() }

func (n *Nemesis) now() int64 { return int64(time.Since(n.start)) }

func (n *Nemesis) log(ep *episode, format string, args ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logLocked(ep, false, format, args...)
}

// logLocked appends a timeline event; ep may be nil. n.mu held.
func (n *Nemesis) logLocked(ep *episode, leaderKill bool, format string, args ...any) {
	e := Event{T: n.now(), Action: fmt.Sprintf(format, args...), LeaderKill: leaderKill}
	if ep != nil {
		e.Episode, e.Kind = ep.N, ep.Kind
	}
	n.events = append(n.events, e)
}

// Timeline returns the recorded events.
func (n *Nemesis) Timeline() []Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Event(nil), n.events...)
}

// Episodes returns how many episodes were started.
func (n *Nemesis) Episodes() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.episodes
}

// Connectivity returns the majority-connectivity samples.
func (n *Nemesis) Connectivity() []connSample {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]connSample(nil), n.conn...)
}

// sampleLocked recomputes majority connectivity after a change. n.mu held.
func (n *Nemesis) sampleLocked() {
	n.partitioned.Store(len(n.blocked) > 0)
	maj := n.majorityLocked()
	if last := n.conn[len(n.conn)-1]; last.Majority != maj {
		n.conn = append(n.conn, connSample{T: n.now(), Majority: maj})
	}
}

// majorityLocked: is there a set of >= quorum nodes, all up and running,
// every pair connected in both directions?
func (n *Nemesis) majorityLocked() bool {
	N := len(n.ids)
	q := N/2 + 1
	for mask := 1; mask < 1<<N; mask++ {
		var set []string
		for i := 0; i < N; i++ {
			if mask&(1<<i) != 0 {
				set = append(set, n.ids[i])
			}
		}
		if len(set) < q {
			continue
		}
		ok := true
		for _, a := range set {
			if n.down[a] || n.paused[a] {
				ok = false
				break
			}
			for _, b := range set {
				if a != b && n.blocked[link{a, b}] {
					ok = false
				}
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (n *Nemesis) setLink(from, to string, f LinkFault) {
	_ = n.c.SetLink(from, to, f)
	n.mu.Lock()
	if f.Blocked() {
		n.blocked[link{from, to}] = true
	} else {
		delete(n.blocked, link{from, to})
	}
	n.sampleLocked()
	n.mu.Unlock()
}

// setAllLinks installs f on every directed link.
func (n *Nemesis) setAllLinks(f LinkFault) {
	for _, a := range n.ids {
		for _, b := range n.ids {
			if a != b {
				n.setLink(a, b, f)
			}
		}
	}
}

// holdThenHeal keeps the fault in place for the episode's duration, then
// heals the network.
func (n *Nemesis) holdThenHeal(ctx context.Context, ep *episode) {
	sleepCtx(ctx, ep.Dur)
	n.healNet(ep)
}

func (n *Nemesis) cutPair(a, b string, f LinkFault) {
	n.setLink(a, b, f)
	n.setLink(b, a, f)
}

func (n *Nemesis) healNet(ep *episode) {
	n.c.HealNetwork()
	n.mu.Lock()
	n.blocked = map[link]bool{}
	n.sampleLocked()
	n.mu.Unlock()
	n.log(ep, "heal network")
}

// act performs a node-level fault on the cluster and, if it worked, records
// it: update changes the bookkeeping, connectivity is resampled and the
// event ok is logged.
func (n *Nemesis) act(ep *episode, what string, leaderKill bool, do func() error, update func(), ok string) {
	if err := do(); err != nil {
		n.log(ep, "%s FAILED: %v", what, err)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	update()
	n.sampleLocked()
	n.logLocked(ep, leaderKill, "%s", ok)
}

func (n *Nemesis) kill(ep *episode, id string, leader bool) {
	ok := "kill " + id
	if leader {
		ok += " (leader)"
	}
	n.act(ep, "kill "+id, leader, func() error { return n.c.Kill(id) }, func() {
		n.down[id] = true
		delete(n.paused, id)
	}, ok)
}

func (n *Nemesis) restart(ep *episode, id string) {
	n.act(ep, "restart "+id, false, func() error { return n.c.Restart(id) }, func() { delete(n.down, id) }, "restart "+id)
}

func (n *Nemesis) pause(ep *episode, id string) {
	n.act(ep, "pause "+id, false, func() error { return n.c.Pause(id) }, func() { n.paused[id] = true }, "pause "+id+" (SIGSTOP)")
}

func (n *Nemesis) resume(ep *episode, id string) {
	n.act(ep, "resume "+id, false, func() error { return n.c.Resume(id) }, func() { delete(n.paused, id) }, "resume "+id+" (SIGCONT)")
}

// isolate cuts every link of id in both directions.
func (n *Nemesis) isolate(id string, f LinkFault) {
	for _, o := range n.ids {
		if o != id {
			n.cutPair(id, o, f)
		}
	}
}

func (n *Nemesis) cutGroups(a, b []string, f LinkFault) {
	for _, x := range a {
		for _, y := range b {
			n.cutPair(x, y, f)
		}
	}
}

func (n *Nemesis) next() episode {
	n.mu.Lock()
	n.episodes++
	num := n.episodes
	n.mu.Unlock()
	r := n.rng
	ep := episode{N: num}
	ep.Kind = n.cfg.Faults[r.IntN(len(n.cfg.Faults))]
	ep.Dur = n.cfg.MinFault + time.Duration(r.Int64N(int64(n.cfg.MaxFault-n.cfg.MinFault)+1))
	ep.Gap = n.cfg.MinGap + time.Duration(r.Int64N(int64(n.cfg.MaxGap-n.cfg.MinGap)+1))
	ep.Perm = r.Perm(len(n.ids))
	ep.F1, ep.F2 = r.Float64(), r.Float64()
	ep.D1 = 300*time.Millisecond + time.Duration(r.Int64N(int64(3700*time.Millisecond)))
	ep.Sub = r.Uint64()
	return ep
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// leader resolves "the current leader", falling back to the episode's
// first random pick when nobody claims leadership.
func (n *Nemesis) leader(ctx context.Context, ep *episode) (string, bool) {
	l, _ := findLeader(ctx, n.c)
	n.mu.Lock()
	bad := l == "" || n.down[l] || n.paused[l]
	n.mu.Unlock()
	if bad {
		return n.ids[ep.Perm[0]], false
	}
	return l, true
}

func (n *Nemesis) others(id string) []string {
	var o []string
	for _, x := range n.ids {
		if x != id {
			o = append(o, x)
		}
	}
	return o
}

// Run executes episodes until ctx is done. Faults that are still in place
// when ctx ends are left for HealAll.
func (n *Nemesis) Run(ctx context.Context) {
	if len(n.cfg.Faults) == 0 {
		<-ctx.Done()
		return
	}
	for ctx.Err() == nil {
		ep := n.next()
		n.log(&ep, "begin %s (%v)", ep.Kind, ep.Dur.Round(time.Millisecond))
		n.runEpisode(ctx, &ep)
		if ctx.Err() != nil {
			return
		}
		n.log(&ep, "end; healthy for %v", ep.Gap.Round(time.Millisecond))
		if !sleepCtx(ctx, ep.Gap) {
			return
		}
	}
}

func (n *Nemesis) partitionFault(ep *episode) LinkFault {
	if n.caps.Blackhole && ep.F2 < 0.35 {
		return LinkFault{Blackhole: true}
	}
	return LinkFault{Cut: true}
}

func (n *Nemesis) faultName(f LinkFault) string {
	if f.Blackhole {
		return "blackhole"
	}
	return "cut"
}

func (n *Nemesis) runEpisode(ctx context.Context, ep *episode) {
	N := len(n.ids)
	pick := func(i int) string { return n.ids[ep.Perm[i%N]] }
	sub := rand.New(rand.NewPCG(ep.Sub, 0x50b))
	switch ep.Kind {
	case FIsolate, FIsolateLeader:
		x := pick(0)
		if ep.Kind == FIsolateLeader {
			x, _ = n.leader(ctx, ep)
		}
		f := n.partitionFault(ep)
		n.isolate(x, f)
		n.log(ep, "isolate %s (%s)", x, n.faultName(f))
		n.holdThenHeal(ctx, ep)

	case FSplit:
		k := N / 2
		var minority []string
		if ep.F1 < 0.5 {
			l, _ := n.leader(ctx, ep)
			minority = append(minority, l)
		}
		for i := 0; len(minority) < k; i++ {
			if c := pick(i); !slices.Contains(minority, c) {
				minority = append(minority, c)
			}
		}
		var majority []string
		for _, id := range n.ids {
			if !slices.Contains(minority, id) {
				majority = append(majority, id)
			}
		}
		f := n.partitionFault(ep)
		n.cutGroups(minority, majority, f)
		n.log(ep, "split %v | %v (%s)", minority, majority, n.faultName(f))
		n.holdThenHeal(ctx, ep)

	case FOneWay:
		x := pick(0)
		if ep.F2 < 0.5 {
			x, _ = n.leader(ctx, ep)
		}
		for _, o := range n.others(x) {
			if ep.F1 < 0.5 {
				n.setLink(x, o, LinkFault{Cut: true})
			} else {
				n.setLink(o, x, LinkFault{Cut: true})
			}
		}
		if ep.F1 < 0.5 {
			n.log(ep, "one-way: %s can receive but not send", x)
		} else {
			n.log(ep, "one-way: %s can send but not receive", x)
		}
		n.holdThenHeal(ctx, ep)

	case FBridge:
		var order []string
		if ep.F1 < 0.5 {
			// Keep the leader off the bridge: it loses half its followers.
			l, _ := n.leader(ctx, ep)
			order = append(order, l)
		}
		for i := 0; len(order) < N; i++ {
			if c := pick(i); !slices.Contains(order, c) {
				order = append(order, c)
			}
		}
		bridge := order[N-1]
		rest := order[:N-1]
		a, c := rest[:len(rest)/2], rest[len(rest)/2:]
		n.cutGroups(a, c, LinkFault{Cut: true})
		n.log(ep, "bridge: %v - %s - %v (%v and %v cut from each other)", a, bridge, c, a, c)
		n.holdThenHeal(ctx, ep)

	case FFlap:
		deadline := time.Now().Add(ep.Dur)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			x := n.ids[sub.IntN(N)]
			n.isolate(x, LinkFault{Cut: true})
			n.log(ep, "flap: isolate %s", x)
			sleepCtx(ctx, 150*time.Millisecond+time.Duration(sub.Int64N(int64(450*time.Millisecond))))
			n.healNet(ep)
			sleepCtx(ctx, 100*time.Millisecond+time.Duration(sub.Int64N(int64(300*time.Millisecond))))
		}

	case FKill, FKillLeader:
		x, isLeader := pick(0), false
		if ep.Kind == FKillLeader {
			x, isLeader = n.leader(ctx, ep)
		} else if l, _ := findLeader(ctx, n.c); l == x {
			isLeader = true
		}
		n.kill(ep, x, isLeader)
		sleepCtx(ctx, ep.D1)
		if ctx.Err() == nil {
			n.restart(ep, x)
		}

	case FKillMajority:
		q := N/2 + 1
		l, _ := findLeader(ctx, n.c)
		var victims []string
		for i := 0; i < q; i++ {
			victims = append(victims, pick(i))
		}
		for _, v := range victims {
			n.kill(ep, v, v == l)
		}
		sleepCtx(ctx, ep.Dur)
		for _, v := range victims {
			if ctx.Err() != nil {
				return
			}
			n.restart(ep, v)
			sleepCtx(ctx, 100*time.Millisecond+time.Duration(sub.Int64N(int64(700*time.Millisecond))))
		}

	case FPause, FPauseLeader:
		x := pick(0)
		if ep.Kind == FPauseLeader {
			x, _ = n.leader(ctx, ep)
		}
		n.pause(ep, x)
		sleepCtx(ctx, ep.Dur)
		n.resume(ep, x)

	case FLossy:
		n.applyLossy(ep)
		n.holdThenHeal(ctx, ep)

	case FSlow:
		hi := 20*time.Millisecond + time.Duration(ep.F1*float64(130*time.Millisecond))
		n.setAllLinks(LinkFault{DelayMin: 5 * time.Millisecond, DelayMax: hi})
		n.log(ep, "slow: every link delayed 5ms..%v", hi.Round(time.Millisecond))
		n.holdThenHeal(ctx, ep)

	case FLate:
		// Stale messages are a classic source of bugs: an old term's
		// append, a read-index answer or a proposal result that arrives
		// seconds late and is matched to the wrong request. One link of
		// the leader (or two) gets huge jittered delays, so messages also
		// overtake each other.
		l, _ := n.leader(ctx, ep)
		o := n.others(l)
		peer := o[sub.IntN(len(o))]
		hi := 200*time.Millisecond + time.Duration(ep.F1*float64(2300*time.Millisecond))
		f := LinkFault{DelayMin: 20 * time.Millisecond, DelayMax: hi}
		n.setLink(l, peer, f)
		desc := fmt.Sprintf("%s -> %s", l, peer)
		if ep.F2 < 0.5 {
			n.setLink(peer, l, f)
			desc += " and back"
		}
		n.log(ep, "late: %s delayed 20ms..%v", desc, hi.Round(time.Millisecond))
		n.holdThenHeal(ctx, ep)

	case FDupStorm:
		f := LinkFault{Dup: 0.5 + ep.F1*0.4, DelayMax: 10*time.Millisecond + time.Duration(ep.F2*float64(40*time.Millisecond))}
		n.setAllLinks(f)
		n.log(ep, "dup-storm: %.0f%% of messages duplicated, jitter <= %v", f.Dup*100, f.DelayMax.Round(time.Millisecond))
		n.holdThenHeal(ctx, ep)

	case FPartitionKill:
		a, b := pick(0), pick(1)
		f := n.partitionFault(ep)
		n.isolate(a, f)
		n.log(ep, "isolate %s (%s)", a, n.faultName(f))
		if !sleepCtx(ctx, ep.Dur/2) {
			return
		}
		l, _ := findLeader(ctx, n.c)
		n.kill(ep, b, b == l)
		sleepCtx(ctx, min(ep.D1, ep.Dur/2))
		if ctx.Err() == nil {
			n.restart(ep, b)
		}
		sleepCtx(ctx, ep.Dur/2-min(ep.D1, ep.Dur/2))
		n.healNet(ep)

	case FKillPartition:
		a := pick(0)
		l, _ := findLeader(ctx, n.c)
		n.kill(ep, a, a == l)
		rest := n.others(a)
		sub.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
		g1, g2 := rest[:len(rest)/2], rest[len(rest)/2:]
		n.cutGroups(g1, g2, LinkFault{Cut: true})
		n.log(ep, "split survivors %v | %v", g1, g2)
		if !sleepCtx(ctx, ep.Dur/2) {
			return
		}
		n.restart(ep, a) // a can reach both halves: it is the bridge now
		sleepCtx(ctx, ep.Dur/2)
		n.healNet(ep)

	case FPausePartition:
		x, _ := n.leader(ctx, ep)
		n.pause(ep, x)
		if !sleepCtx(ctx, ep.Dur/3) {
			return
		}
		n.isolate(x, LinkFault{Cut: true})
		n.log(ep, "isolate %s while it is paused", x)
		n.resume(ep, x) // wakes up alone, still believing it leads
		sleepCtx(ctx, ep.Dur/3)
		n.healNet(ep)

	case FLossyKillLeader:
		n.applyLossy(ep)
		if !sleepCtx(ctx, ep.Dur/3) {
			return
		}
		x, isLeader := n.leader(ctx, ep)
		n.kill(ep, x, isLeader)
		sleepCtx(ctx, ep.D1)
		if ctx.Err() == nil {
			n.restart(ep, x)
		}
		sleepCtx(ctx, ep.Dur/3)
		n.healNet(ep)
	}
}

func (n *Nemesis) applyLossy(ep *episode) {
	var f LinkFault
	if n.caps.Dup {
		// In-process: per-message loss and duplication plus jitter.
		f = LinkFault{Drop: 0.05 + ep.F1*0.30, Dup: ep.F2 * 0.15, DelayMax: 20 * time.Millisecond}
	} else {
		// TCP forwarders: a "lost" chunk resets the connection, which
		// loses the HTTP request (and every message batched in it).
		f = LinkFault{Drop: 0.005 + ep.F1*0.03, DelayMax: 30 * time.Millisecond}
	}
	n.setAllLinks(f)
	n.log(ep, "lossy: drop %.1f%% dup %.1f%% jitter <= %v on every link", f.Drop*100, f.Dup*100, f.DelayMax)
}

// HealAll ends every fault: heals the network, wakes paused nodes and
// restarts killed ones.
func (n *Nemesis) HealAll() {
	n.c.HealNetwork()
	n.mu.Lock()
	n.blocked = map[link]bool{}
	paused := slices.Sorted(maps.Keys(n.paused))
	down := slices.Sorted(maps.Keys(n.down))
	n.sampleLocked()
	n.mu.Unlock()
	n.log(nil, "final heal: network healed")
	for _, id := range paused {
		n.resume(nil, id)
	}
	for _, id := range down {
		n.restart(nil, id)
	}
}

// FormatTimeline renders the timeline for humans.
func FormatTimeline(evs []Event) string {
	var b strings.Builder
	for _, e := range evs {
		ep := "  "
		if e.Episode > 0 {
			ep = fmt.Sprintf("#%d %s:", e.Episode, e.Kind)
		}
		fmt.Fprintf(&b, "%9.3fs %s %s\n", float64(e.T)/1e9, ep, e.Action)
	}
	return b.String()
}
