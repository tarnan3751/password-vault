package chaos

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := m.Run()
	CleanupBuild()
	os.Exit(code)
}

// testLog forwards run progress to t.Log.
type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(string(p[:len(p)-1]))
	return len(p), nil
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// TestInprocChaos runs a few short in-process seeds in parallel: real
// filestore, real HTTP between nodes, real servers, the whole fault
// catalogue the backend supports. CHAOS_SEED replays one seed;
// CHAOS_DURATION (seconds) lengthens the runs.
func TestInprocChaos(t *testing.T) {
	seeds := []int64{101, 202, 303}
	if s := os.Getenv("CHAOS_SEED"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		seeds = []int64{v}
	}
	dur := time.Duration(envInt("CHAOS_DURATION", 10)) * time.Second
	for i, seed := range seeds {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			t.Parallel()
			cfg := RunConfig{Mode: "inproc", Seed: seed, Duration: dur, Clients: 5, Items: 5,
				// One seed also runs with real fsync and does the backup
				// drill (which builds vaultd for `vaultd restore`).
				Fsync: i == 0, BackupDrill: i == 0, Log: testLog{t},
				MinFault: 500 * time.Millisecond, MaxFault: 3 * time.Second,
				MinGap: 300 * time.Millisecond, MaxGap: 1500 * time.Millisecond}
			if i == 2 {
				// Short retry budgets and no resolution: writes caught by a
				// fault stay indeterminate, so the checker must cope with
				// operations that may or may not have happened.
				cfg.OpBudget, cfg.AttemptTimeout, cfg.NoResolve = 200*time.Millisecond, 500*time.Millisecond, true
			}
			res := Run(context.Background(), cfg)
			t.Log("\n" + res.Summary())
			if !res.Pass {
				t.Fatalf("seed %d failed (reproduce: CHAOS_SEED=%d go test -run TestInprocChaos ./internal/chaos/)", seed, seed)
			}
			if res.Counts[KindPut+"/"+OutOK] == 0 || res.Episodes == 0 {
				t.Fatalf("degenerate run: %v, %d episodes", res.Counts, res.Episodes)
			}
			if cfg.NoResolve {
				t.Logf("indeterminate writes left unresolved: %d", res.Counts[KindPut+"/"+OutUnknown]+res.Counts[KindDelete+"/"+OutUnknown])
			}
		})
	}
}

// TestSelfTestFindsViolation proves the checker has teeth: with the harness
// lying (stale reads taken during partitions recorded as linearizable), a
// violation must be found within a few seeds.
func TestSelfTestFindsViolation(t *testing.T) {
	for i, seed := range []int64{7, 8, 9, 10, 11} {
		res := Run(context.Background(), RunConfig{Mode: "inproc", Seed: seed, Duration: 8 * time.Second,
			Clients: 6, Items: 3, SelfTest: true, Faults: "isolate,isolate-leader,split",
			MinFault: 1500 * time.Millisecond, MaxFault: 3 * time.Second, MinGap: 300 * time.Millisecond, MaxGap: time.Second})
		if res.Err != "" {
			t.Fatalf("seed %d: %s", seed, res.Err)
		}
		if res.PorcupineViolation() {
			t.Logf("seed %d (attempt %d): Porcupine rejected the history after %d lies: %v", seed, i+1, res.Lies, res.Porcupine.Violations)
			for _, c := range res.Checks {
				if !c.Pass {
					t.Logf("  also FAIL: %s", c.Name)
				}
			}
			os.RemoveAll(res.WorkDir)
			return
		}
		t.Logf("seed %d: %d lies, no violation; next seed", seed, res.Lies)
		os.RemoveAll(res.WorkDir)
	}
	t.Fatal("the checker accepted every lying history: it has no teeth")
}

// TestProcsChaos runs real vaultd processes with mutual TLS, SIGKILL,
// SIGSTOP/SIGCONT and TCP-forwarder partitions.
func TestProcsChaos(t *testing.T) {
	if testing.Short() {
		t.Skip("process mode builds and runs vaultd binaries")
	}
	seed := int64(envInt("CHAOS_PROCS_SEED", 4242))
	res := Run(context.Background(), RunConfig{Mode: "procs", Seed: seed, TLS: true, Duration: 12 * time.Second,
		Clients: 4, Items: 4, BackupDrill: true, Log: testLog{t},
		MinFault: 700 * time.Millisecond, MaxFault: 3 * time.Second, MinGap: 300 * time.Millisecond, MaxGap: 1200 * time.Millisecond})
	t.Log("\n" + res.Summary())
	if !res.Pass {
		t.Fatalf("procs seed %d failed (reproduce: CHAOS_PROCS_SEED=%d go test -run TestProcsChaos ./internal/chaos/)", seed, seed)
	}
}
