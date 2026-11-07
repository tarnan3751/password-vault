// Package chaos is the whole-system fault-injection harness of Family Vault
// (DESIGN.md §7.2).
//
// The Raft core has its own deterministic simulator (internal/raft). This
// package tests the layer above it: the REAL stack (filestore on disk, the
// HTTP peer transport, the replicated state machine, the HTTP API with its
// retries and idempotency) while a nemesis cuts servers off from each other,
// kills, restarts and pauses them. Concurrent clients drive the public API;
// every operation is recorded with its invocation and completion time, and
// the history is checked afterwards:
//
//   - linearizability, with Porcupine, per item (model.go explains exactly
//     what the model does and does not prove);
//   - independent "rev oracle" checks that do not rely on Porcupine
//     (check.go): versions map to one content, revs respect real time, reads
//     are consistent snapshots, no acknowledged write is lost and no CAS
//     forks;
//   - weaker properties of consistency=stale reads;
//   - convergence after the final heal (one leader, same applied index,
//     byte-identical state on every node), and a backup/restore drill.
//
// Two cluster backends implement Cluster:
//
//   - in-process (inproc.go): N nodes in this process, each wired exactly
//     like cmd/vaultd, with a raft.Transport decorator (faultnet.go) that
//     injects partitions, loss, delay and duplication per directed link;
//   - processes (procs.go): real vaultd binaries with real config files and
//     mutual TLS, SIGKILL / SIGSTOP / SIGCONT, and TCP forwarders
//     (forwarder.go) between the nodes for cuts, blackholes and delay.
//
// Run (run.go) ties a backend, the nemesis (nemesis.go), the workload
// (workload.go) and the checks together for one seed. cmd/vault-chaos is the
// command-line entry point; README.md explains how to reproduce a seed.
package chaos
