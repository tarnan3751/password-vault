// Command vault-chaos runs the whole-system fault-injection harness: a real
// Family Vault cluster (in-process nodes or real vaultd processes), a
// nemesis that partitions, kills and pauses the servers, concurrent
// clients, and a Porcupine linearizability check of every run's history
// plus independent consistency checks. See internal/chaos/README.md.
//
//	vault-chaos                                   # one in-process run, random seed
//	vault-chaos --seed 42 --duration 2m           # reproduce / lengthen a seed
//	vault-chaos --mode procs --tls --nodes 5      # real processes, mutual TLS
//	vault-chaos --runs 20 --out /tmp/chaos        # 20 consecutive seeds, keep artifacts
//	vault-chaos --selftest                        # prove the checker catches stale reads
//
// The exit status is 0 only if every check of every run passed (with
// --selftest: only if every run's violation was detected).
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tarnan3751/password-vault/internal/chaos"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("vault-chaos", flag.ContinueOnError)
	mode := fs.String("mode", "inproc", "cluster backend: inproc (nodes in this process) or procs (real vaultd processes)")
	seed := fs.Int64("seed", 0, "seed of the first run (0 = random; always printed)")
	duration := fs.Duration("duration", 30*time.Second, "length of the fault phase of each run")
	clients := fs.Int("clients", 5, "concurrent clients")
	items := fs.Int("items", 6, "items the clients contend on (spread over a shared and a personal vault)")
	nodes := fs.Int("nodes", 3, "cluster size (odd)")
	fsync := fs.Bool("fsync", false, "inproc: real fsync instead of filestore NoSync (vaultd processes always fsync)")
	useTLS := fs.Bool("tls", true, "procs: mutual TLS with a generated household CA (false = insecure mode)")
	out := fs.String("out", "", "artifact directory (each run writes <out>/seed-<seed>/); default: only failing runs keep artifacts, in their work dir")
	faults := fs.String("faults", "all", "fault kinds or groups, comma-separated (all, partition, kill, pause, net, combo, or kinds such as kill-leader; -kind removes)")
	runs := fs.Int("runs", 1, "number of consecutive seeds to run")
	selftest := fs.Bool("selftest", false, "record stale reads issued during partitions as linearizable: the checker MUST report a violation")
	drill := fs.Bool("backup-drill", true, "after the checks, back up, restore with `vaultd restore` on fresh dirs and verify")
	vaultd := fs.String("vaultd", "", "vaultd binary to use (default: build ./cmd/vaultd)")
	keep := fs.Bool("keep", false, "keep node data directories and logs of passing runs")
	ptimeout := fs.Duration("porcupine-timeout", 3*time.Minute, "linearizability search budget per run (a timeout counts as a failure)")
	snapThr := fs.Uint64("snapshot-threshold", 0, "Raft snapshot threshold (0 = chosen from the seed among 64, 256, 1024, 4096; printed in the summary)")
	opBudget := fs.Duration("op-budget", 0, "how long a client retries one write with the same key before recording it as unknown (default 30s; short values force unknown outcomes)")
	attemptTimeout := fs.Duration("attempt-timeout", 0, "per-request timeout of the long attempts (default 12s, above the server's 10s propose loop)")
	noResolve := fs.Bool("no-resolve", false, "leave unknown outcomes unresolved after the heal (stresses the checker's handling of indeterminate operations)")
	quiet := fs.Bool("quiet", false, "print only the per-run summaries")
	listFaults := fs.Bool("list-faults", false, "list the fault kinds and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *listFaults {
		fmt.Println("kinds:", strings.Join(chaos.AllFaults(), " "))
		for _, g := range []string{"partition", "kill", "pause", "net", "combo"} {
			fmt.Printf("group %-9s %s\n", g+":", strings.Join(chaos.FaultGroups[g], " "))
		}
		return 0
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if *selftest && !explicit["runs"] {
		// The lie only bites when a partition isolates a node that some
		// client reads from; a few seeds make that a certainty.
		*runs = 5
	}
	if *mode != "inproc" && *mode != "procs" {
		fmt.Fprintln(os.Stderr, "vault-chaos: --mode must be inproc or procs")
		return 2
	}
	if *nodes < 1 || *nodes%2 == 0 {
		fmt.Fprintln(os.Stderr, "vault-chaos: --nodes must be odd")
		return 2
	}
	if *seed == 0 {
		var b [8]byte
		_, _ = crand.Read(b[:])
		*seed = int64(binary.LittleEndian.Uint64(b[:]) >> 2)
	}
	// SIGINT/SIGTERM cancel the run; Run's deferred cleanup then kills and
	// reaps every vaultd it started before we exit.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer chaos.CleanupBuild()

	failed, violations := 0, 0
	var failedSeeds []int64
	for i := 0; i < *runs; i++ {
		if ctx.Err() != nil {
			break
		}
		s := *seed + int64(i)
		replay := ""
		if *selftest {
			replay = " --selftest"
		}
		fmt.Printf("=== run %d/%d: seed %d (reproduce: vault-chaos --mode %s --seed %d --duration %v --nodes %d --clients %d --items %d --faults %s%s)\n",
			i+1, *runs, s, *mode, s, *duration, *nodes, *clients, *items, *faults, replay)
		cfg := chaos.RunConfig{
			Mode: *mode, Seed: s, Duration: *duration, Nodes: *nodes, Clients: *clients, Items: *items,
			Fsync: *fsync, TLS: *useTLS, Faults: *faults, OutDir: *out, KeepData: *keep, SelfTest: *selftest,
			BackupDrill: *drill && !*selftest, VaultdBin: *vaultd, PorcupineTimeout: *ptimeout,
			SnapshotThreshold: *snapThr, OpBudget: *opBudget, AttemptTimeout: *attemptTimeout, NoResolve: *noResolve,
		}
		if !*quiet {
			cfg.Log = os.Stderr
		}
		res := chaos.Run(ctx, cfg)
		fmt.Print(res.Summary())
		if *selftest {
			if res.PorcupineViolation() {
				violations++
				fmt.Printf("SELF-TEST seed %d: Porcupine caught the lie after %d run(s), as it must\n", s, i+1)
				break
			}
			fmt.Printf("SELF-TEST seed %d: no violation detected (%d lies recorded); trying the next seed\n", s, res.Lies)
			continue
		}
		if !res.Pass {
			failed++
			failedSeeds = append(failedSeeds, s)
		}
	}
	if ctx.Err() != nil {
		fmt.Println("interrupted")
		return 130
	}
	if *selftest {
		if violations == 0 {
			fmt.Printf("=== SELF-TEST FAILED: %d seeds from %d produced no detected violation\n", *runs, *seed)
			return 1
		}
		fmt.Println("=== SELF-TEST PASSED: the checker has teeth")
		return 0
	}
	if *runs > 1 {
		fmt.Printf("=== %d runs from seed %d: %d failed %v\n", *runs, *seed, failed, failedSeeds)
	}
	if failed > 0 {
		return 1
	}
	return 0
}
