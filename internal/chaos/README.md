# internal/chaos: whole-system fault injection

The Raft core has its own deterministic simulator (`internal/raft`). This
harness tests everything above it, for real: filestore on disk, the HTTP peer
transport, the replicated state machine, and the public HTTP API with its
retries and idempotency, while a nemesis cuts servers off from each other,
kills, restarts and pauses them. Every run's history is checked with
Porcupine and with independent checks.

```
go test ./internal/chaos/                 # short seeds, teeth test, unit tests, one process-mode run (~45 s; also under -race)
go test -short ./internal/chaos/          # without the process-mode run
go run ./cmd/vault-chaos --help
```

## Backends

| | in-process (`--mode inproc`) | processes (`--mode procs`) |
|---|---|---|
| nodes | N stacks in one process, each wired exactly like `cmd/vaultd` (filestore in `<data_dir>/raft`, httptransport over loopback HTTP, `raft.StartNode`, `fsm.New`, `server.New` behind a real listener) | real `vaultd run` processes built from `./cmd/vaultd`, real config files |
| TLS | plain HTTP | household CA from `tlsutil.GenerateConstrainedCA`, node certificates, mutual TLS and node-identity checks on the peer listener, HTTPS for the client API (`--tls`, default on) |
| durability | `--fsync` real fsync, default NoSync (a kill is a process crash: the OS keeps written data either way) | always fsync (F_FULLFSYNC on macOS) |
| kill / restart | close listeners, transport, Raft, store; rebuild from the same directory | SIGKILL the process group, reap, re-exec |
| pause | not supported | SIGSTOP / SIGCONT |
| network faults | `FaultTransport`, a `raft.Transport` decorator: per directed link cut (checked on send AND on receive, so batches in flight are cut too), loss, duplication, delay | a TCP forwarder per directed link (node i's config names it as node j's `peer_addr`): cut (close + refuse), blackhole (accept and stall; stalled bytes resume after the heal), delay, connection resets |
| cleanup | in-process | every child in its own process group; deferred SIGKILL + reap; SIGINT/SIGTERM handled by `vault-chaos`; a watchdog shell kills every vaultd from the pid files if the harness itself dies (`go test -timeout`, SIGKILL); a final scan verifies none is left |

## Fault catalogue (`--faults`)

Groups: `partition`, `kill`, `pause`, `net`, `combo`, `all` (default); `-kind`
removes a kind. Episodes are drawn from the seed and separated by short
healthy periods; at the end everything is healed, paused nodes resumed,
killed nodes restarted, and the cluster must fully recover.

| kind | what happens |
|---|---|
| `isolate` | one node cut off in both directions (procs: cut or blackhole) |
| `isolate-leader` | the current leader cut off |
| `split` | minority / majority split, the leader on either side |
| `one-way` | a node (often the leader) can only send, or only receive |
| `bridge` | A-B and B-C connected, A-C cut (5 nodes: two groups joined by one node) |
| `flap` | random nodes isolated and healed every few hundred ms |
| `kill` | kill a random node, restart after 0.3-4 s |
| `kill-leader` | kill the leader, restart later (used for the write-gap metric) |
| `kill-majority` | kill a majority (no quorum), restart them one by one |
| `pause` / `pause-leader` | SIGSTOP a node / the leader, SIGCONT later: the old leader wakes up believing it still leads (procs) |
| `lossy` | loss, duplication and jitter on every link (procs: connection resets and jitter) |
| `slow` | 5-150 ms latency on every link |
| `late` | 0.2-2.5 s jittered delay on one or two of the leader's links: messages from old terms, late read-index answers and proposal results arrive late and out of order |
| `dup-storm` | 50-90% of messages delivered twice, with jitter (in-process) |
| `partition+kill` | isolate A, then kill a majority-side node: no quorum until it restarts |
| `kill+partition` | kill A, split the survivors (no quorum), restart A, which becomes the bridge |
| `pause+partition` | pause the leader, isolate it while paused, wake it up alone (procs) |
| `lossy+kill-leader` | kill the leader on a lossy network |

## Workload

Two users (the first registered with the bootstrap token, the second with an
invite), a shared vault with both as members and the first user's personal
vault; items spread over both. Several clients, each bound to a user and to a
node it re-picks every 1-4 s, do linearizable reads (`GET /v1/sync`, about a
third of them with `?since=<rev of the client's last full sync>`; an
`unchanged` answer is recorded as showing exactly that earlier state, so an
"unchanged" judged against a stale view is caught like any stale read), stale
reads (`?consistency=stale`), puts with optimistic concurrency (from the
version they last observed, sometimes deliberately from an older one) and
deletes. Every blob names the write that produced it, so a read tells the
harness exactly which write it observed.

Every mutation carries an `Idempotency-Key`. On a network error, a timeout,
`503 outcome_unknown` or `500` the client retries the SAME key on another
node; on `503 unavailable` (nothing changed) it retries too. Half the
attempts wait 12 s (longer than the server's own 10 s propose loop, so the
server decides and can say "certainly nothing changed"); the other half give
up after 0.8-4 s and fail over while the first copy may still be pending on a
cut-off node, which is the duplicate-proposal path the idempotency table must
get right. Whether a failed attempt may have reached the server is decided
with `httptrace` (`WroteRequest`), not from the error type: net/http silently
re-sends requests carrying an `Idempotency-Key` when a reused connection dies,
and against a killed node that hidden retry fails to dial although the first
copy was delivered. An operation
that never got a definite answer is recorded as unknown, and is resolved
after the final heal by re-sending the same key, but only while fewer than
`SafeResendWindow` (3000) newer keys were issued: the server remembers the
4096 most recently applied request ids, and a re-send after eviction would
execute again. The same bound stops a client's own retries.

## The Porcupine model

Each item is a register holding the identity of the write that produced its
content ("" = absent). `PUT base_version=v` is `CAS(expect = the write that
produced v, new = this write)`; create is CAS from absent; delete is CAS to
absent; a read returns the write identity. A 409 must find the expectation
false, and its `current_version`, when it maps to a known write, must name
the register's write. An unknown-outcome operation may take effect at any
point after its invocation or never (its return is past the end of the
history); an unknown put whose blob a read showed certainly happened and is
entered as a success returning no later than that read. Histories are
partitioned per item; a sync becomes one read per item it showed. To keep
the search tractable (it is exponential in operations left open to the
end), an unobserved unknown CAS whose expected write had provably been
replaced before it was invoked is dropped: it can only ever be a failed CAS
with an unconstrained output, so it cannot change the verdict.

Proves, per item: a real-time-consistent total order in which reads see the
latest write, CASes succeed exactly when their expectation holds, retries
take effect at most once and nothing acknowledged is lost. Does not prove:
atomicity across items of one sync (the rev checks below cover snapshot
consistency), anything about stale reads (separate checks), the other API
operations (only exercised in setup), durability against power loss.

## Other checks (no Porcupine)

The global `rev` is used as an oracle: item versions are revs, deletes report
their rev, syncs report theirs.

* **bijection**: a version names one write of one item, forever; every
  observed blob is a write the harness issued for that item and that did not
  report failure, observed only after it was issued;
* **rev real-time order**: A returned before B was invoked implies rev(B) >=
  rev(A), strictly when B is a successful write;
* **read version monotonicity**: per item, linearizable reads in
  non-overlapping operations never see a lower version;
* **read snapshot consistency** (also for stale reads): a read at rev r
  showing K@v means no known write touched K in (v, r];
* **CAS chains**: per item, effective writes sorted by rev form one chain
  (each based on its predecessor's version) ending in the final state; no
  version is CASed twice; gaps only where an unresolved unknown operation
  could fill them;
* **acknowledged writes final or superseded**;
* **stale reads**: flagged stale, served by the node asked, rev never goes
  backwards within one node incarnation (a restarted node may restart from an
  older snapshot until it learns the commit index);
* **convergence** after the final heal: one leader, the same applied index,
  byte-identical state (in-process `fsm.StateHash`; processes: SHA-256 of the
  `state` of `GET /v1/admin/backup`), identical final reads on every node;
* **backup drill**: admin backup, stop, `vaultd restore` into fresh data
  directories on every node, start, old tokens rejected, users log in again,
  identical items on every node, a write accepted;
* **no unexpected node failures** (a node stopping on its own, a process
  exiting without being killed) and, in process mode, **no leftover vaultd**.

Availability is reported, not asserted (unless absurd): the fraction of
operations that succeeded while a majority was connected, how many needed
retries, latency, and the longest stretch without a successful write after a
leader kill.

## Teeth

`--selftest` (and `TestSelfTestFindsViolation`) makes the harness lie: while a
partition is active, linearizable reads are sent with `consistency=stale` to
a random node and recorded as linearizable, which is what a server answering
reads from local state would do. Porcupine must reject the history, and does
within one or two seeds; the rev-order and monotonicity checks flag it too.

## Stressing the checker itself

`--op-budget 300ms --attempt-timeout 600ms --no-resolve` makes clients give
up quickly and skips the resolution after the heal, so every write caught by
a fault stays indeterminate. The checks must still pass on a correct system
(a test of the harness: indeterminate operations must not cause false
alarms); `TestInprocChaos/seed-303` runs in this mode.

## Reproducing a seed

Every run prints its seed and a reproduce line:

```
vault-chaos --mode inproc --seed 1234 --duration 1m --faults all
CHAOS_SEED=1234 go test -run TestInprocChaos ./internal/chaos/
```

The nemesis schedule (episode kinds, durations, targets as positions in a
random permutation, loss rates), the Raft snapshot threshold (64, 256, 1024
or 4096; override with `--snapshot-threshold`) and every id and idempotency
key are functions of the seed. Thread scheduling and real time are not, so a seed
reproduces the same fault schedule and workload shape, not the same
interleaving: rerun a failing seed a few times. A failing run keeps its work
directory (node data and logs) and writes `history.json` (every operation
with every attempt), `timeline.txt`, `result.json`, `summary.txt` and, for a
linearizability violation, `porcupine.html` and `porcupine-history.json`.
