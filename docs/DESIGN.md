# Family Vault: design

A self-hosted password manager for a household. Three servers replicate the
vault with our own Raft implementation; it keeps working when any one of them
dies; and the servers only ever see ciphertext.

Binaries: `vaultd` (server), `fvault` (command-line client), `vault-chaos`
(fault-injection test harness). A browser client is embedded in `vaultd`.

## 1. Goals and non-goals

Goals
* Survive the loss of any single server with no data loss and no manual steps.
* Zero-knowledge servers: every secret, including entry names and URLs, is
  encrypted on the client. A fully compromised server learns usernames, who
  shares with whom, sizes and timing, and nothing else.
* Sharing between family members with per-member wrapped vault keys.
* Offline reads from an encrypted client-side cache; writes need a majority.
* Evidence of correctness: fault-injection runs checked with Porcupine,
  cross-language crypto test vectors, encrypted export backups as a safety net.

Non-goals (v1)
* Changing cluster membership at runtime. The three members are fixed in the
  configuration file.
* Byzantine servers: a malicious server can deny service, roll back, or hide
  data, but cannot read or undetectably forge vault contents.
* Account recovery. A forgotten master password is unrecoverable by design.
* Attachments, browser extension/autofill, mobile apps.

## 2. Components

```
            browser (web/)            fvault CLI (cmd/fvault)
                 |  HTTPS, JSON, client-side crypto  |
                 v                                   v
   +------------------------- vaultd --------------------------+
   | internal/server   HTTP API, auth, tokens, rate limiting   |
   | internal/fsm      replicated state machine (ciphertext)   |
   | internal/raft     consensus core + node runtime           |
   |   filestore       WAL + hard state + snapshots on disk    |
   |   httptransport   node-to-node messages over mutual TLS   |
   +-----------------------------------------------------------+
            ^ raft messages (peer listener, mTLS) ^
            |                                     |
          vaultd  <----------------------------> vaultd
```

| Path                          | Responsibility |
|-------------------------------|----------------|
| `internal/raft`               | Contract (`types.go`), deterministic core, node runtime, in-memory storage and simulated network, simulation + linearizability tests |
| `internal/raft/filestore`     | Crash-safe `raft.Storage` on the local filesystem |
| `internal/raft/httptransport` | `raft.Transport` over HTTP(S) |
| `internal/tlsutil`            | Household CA / node certificate generation, TLS configs |
| `internal/api`                | Wire types of the client API |
| `internal/fsm`                | Deterministic state machine: users, invites, vaults, members, items, idempotency table |
| `internal/server`             | HTTP handlers, authentication, CORS/CSP, static web UI |
| `internal/vaultcrypto`        | Client-side cryptography (spec: `docs/spec/crypto.md`) |
| `internal/backup`             | Encrypted export backup format |
| `internal/client`             | Go client: failover, offline cache, high-level vault operations |
| `internal/chaos`              | Whole-system fault injection + Porcupine models |
| `cmd/vaultd`, `cmd/fvault`, `cmd/vault-chaos`, `cmd/gen-vectors` | Binaries |
| `web/`                        | Browser client (TypeScript); built bundle in `web/dist` is embedded |
| `testvectors/`                | Crypto vectors shared by Go and TypeScript |

## 3. Consensus

Our own Raft, structured so that it can be tested deterministically.

**Core.** A single-threaded state machine with no clocks, goroutines or I/O.
It consumes `Tick()`, `Step(Message)`, proposals and read requests, and emits
a batch of effects: hard state and entries to persist, messages to send,
committed entries to apply, snapshots to install. Because it is deterministic,
a simulator can drive three cores through millions of steps of partitions,
crashes, message loss and reordering from a seed, and replay any failure.

**Protocol features.**
* Leader election with randomized timeouts, **PreVote** (a node that was
  partitioned away cannot disrupt a healthy leader when it returns) and
  **CheckQuorum** (a leader that cannot reach a majority steps down).
* Log replication with conflict hints for fast backtracking, batching and
  group commit (one fsync covers many proposals).
* A no-op entry at the start of each term, so earlier-term entries commit and
  read-index is safe.
* **Snapshots**: after `SnapshotThreshold` applied entries the state machine
  is serialized, the log prefix is dropped, and far-behind followers receive
  the snapshot instead of the log.
* **Linearizable reads without logging** (ReadIndex): the leader records its
  commit index, proves it is still leader with a round of heartbeats, and the
  reader waits until its local state machine has applied that index. Followers
  can serve reads by asking the leader for the index. No clock assumptions.
* **Proposal forwarding**: a follower hands client writes to the leader over
  the peer transport and relays the result.
* Static three-member configuration.

**Durability.** A node persists term, vote and log entries (fsync) before it
sends any message that depends on them. Messages that promise nothing about
the sender's own disk go out first: a leader sends new entries to the
followers and then writes them itself, so the two disk flushes a save needs
overlap instead of running one after the other, and the leader counts its own
copy only once it is durable (the argument is the comment on
`ready.takeEarly` in `internal/raft/core.go`). `filestore` uses a CRC-framed
write-ahead log, an atomically replaced hard-state file, and atomically
written snapshot files; the load-time recovery rule in `raft.Storage` makes
snapshot installation crash-atomic.

**Messaging.** All node-to-node communication is one-way, best-effort
`raft.Message`s (responses are just messages going the other way). The
production transport POSTs gob-encoded batches to the peer's `/raft/msgs`
over mutual TLS.

**Exactly-once.** Raft gives at-least-once delivery of a retried proposal, so
every command carries a request ID and the state machine keeps a bounded,
deterministic table of recent request IDs and their results.

## 4. Replicated state

The state machine (`internal/fsm`) holds only what the server needs to
enforce access control plus opaque ciphertext: users (username, KDF
parameters, password verifier, public key, wrapped account key, encrypted
private key, token epoch, flags), invites (hash, expiry), vaults (encrypted
metadata, encrypted roster, key epoch, members with roles and wrapped keys),
items (blob, version) and the idempotency table. Commands and snapshots are
JSON. Commands carry a timestamp chosen by the proposing node, so the state
machine itself never reads a clock.

Storage quotas (8 MiB per vault, 16 MiB per user, 48 MiB per cluster, 32
users) are part of the replicated state machine. They are what guarantees
that a snapshot of the whole state always fits in a single peer message, so a
node that fell far behind, or was replaced, can always be brought back.

## 5. Security model (summary; details in docs/THREAT_MODEL.md)

* Master password → Argon2id → HKDF → `encKey` (stays on the device) and
  `loginKey` (sent to the server, stored only as a salted Argon2id hash).
* Entries are XChaCha20-Poly1305 boxes bound by AAD to their vault and ID.
* Each member has an X25519 key pair; vault keys are wrapped per member with
  an authenticated ECIES construction.
* The servers hand out public keys, member lists and wrapped keys, and none
  of that is taken on faith. A key is trusted on a device only after its
  fingerprint was compared with its owner (*verified contacts*); each vault's
  member list is sealed under the vault key (the *roster*), so a server cannot
  add a recipient; a vault key is accepted only from the user's own key pair,
  a recorded owner of that vault, or a verified contact, and is otherwise held
  *pending*; devices remember the key epoch they accepted and refuse to go
  back (crypto.md §6).
* Removing a member is a rekey: one atomic request drops the member, installs
  a new key for the rest and re-encrypts the vault.
* Client ↔ server: TLS. Server ↔ server: mutual TLS with a household CA that
  is name-constrained to the cluster's own hosts.

## 6. Clients and offline use

The browser client is served by every node, compressed once at start-up and
cached by content hash, so a device downloads about 100 KB the first time and
nothing afterwards until a new version is installed.

Both clients keep the last `SyncResponse` (ciphertext) on local storage:
the CLI in a `0600` file, the browser in IndexedDB (with a service worker
caching the app shell), next to a *trust store* (verified contacts, accepted
vault keys) that is sealed under a key derived from the account key. Unlocking offline derives `encKey` and opens the
wrapped account key, which doubles as the password check. Clients know all
node URLs (`GET /v1/cluster`) and fail over between them. When a majority is
unreachable they fall back to a stale read from any reachable node, then to
the cache; writes are refused with a clear message.

Every `fvault` command derives the keys from the master password again
(Argon2id, deliberately slow) and holds them only while it runs. `fvault
shell` is the same thing for several commands in a row: it asks once, keeps
the keys in that one process's memory, and wipes them after five idle minutes.
Nothing derived from the password is ever written to disk or handed to
another process.

## 7. Verification

1. **Deterministic simulation** of the Raft core (seeded; partitions,
   crashes with loss of unsynced state, drops, duplication, reordering),
   with invariant checks (election safety, log matching, leader completeness,
   state-machine safety) and Porcupine linearizability checks.
2. **Real-time chaos** on the full stack (`vault-chaos`): three real nodes
   with on-disk storage and the real HTTP API, a nemesis that partitions and
   kills them, concurrent clients, and a Porcupine check of the recorded
   history; plus a mode that runs real `vaultd` processes and SIGKILLs /
   SIGSTOPs them.
3. **Crypto vectors** shared by Go and TypeScript, including published RFC
   vectors and negative cases.
4. **Backups**: user-level encrypted exports and admin-level server state
   dumps, each with a tested restore path.
5. **Benchmarks** (`make bench`): end to end through the Go client against
   three in-process nodes (`internal/chaos/bench_test.go`), plus per-package
   benchmarks for the state machine, the server, the crypto library and the
   client; `npm run perf` in `web/` measures the browser client on a
   2,000-entry vault.

### Results

Numbers are from the runs made while building it (Apple M5).

| Layer | How it is tested | Result |
|-------|------------------|--------|
| Raft core | **Deterministic simulation**: the core is a pure state machine, so a seeded simulator drives 1–5 nodes through partitions (symmetric, one-way, bridge, flapping), crashes inside any storage call, message loss, duplication and reordering, checking election safety, log matching, leader completeness and state-machine safety at every step, and client histories with **Porcupine** | 625,000 seeds pass (230,000 of them after the leader started replicating in parallel with its own disk write); injected protocol bugs (committing old-term entries by counting, reads without a quorum round, unpersisted votes, sending acknowledgements before the write, …) are caught |
| On-disk storage | Fault-injecting filesystem (lost or torn unsynced writes, un-fsynced renames, failing fsync) with a crash at every I/O step, compared against a model | ~132,000 seeds, ~2.5 million simulated power cuts |
| Whole system | **`vault-chaos`**: three (or five) real nodes with real disks and the real HTTP API, either in one process or as real `vaultd` processes over mutual TLS. A nemesis partitions them, kills them (`SIGKILL`), freezes them (`SIGSTOP`) and disturbs the network while clients read and write; every run's history is checked with Porcupine plus independent checks (no lost or forked writes, replicas byte-identical, backup → restore round trip) | 110 runs, about 950,000 operations, all linearizable, nothing lost; a self-test proves the checker rejects a wrong history, and planted server bugs (a skipped version check, a read served without its barrier, a commit counted too early, a vote not persisted) are caught |
| Crypto | **Shared test vectors** (`testvectors/crypto-v1.json`, 33 groups) that the Go and TypeScript implementations must both reproduce exactly, including published RFC vectors and several hundred negative cases | both pass every case |
| Clients together | `scripts/interop.sh`: the CLI and the browser client's code read and write each other's data on a live cluster | passes |
| Browser client | Headless Chromium against a real cluster: sharing between two users, failover when the page's own server is killed, read-only without a majority, offline unlock with every server down, keyboard-only operation of every dialog, 44 px touch targets at phone width, zero Content-Security-Policy violations | passes |
| Upgrades | A cluster of the previous binaries was upgraded one node at a time while both old and new clients kept writing; the old backup restores to the same state digest with either binary | nothing lost |

Run them yourself (from the repository root):

```sh
make test                        # everything (about 3 minutes)
make race                        # under the race detector (much slower)
make sim SEEDS=20000             # more Raft simulation
bin/vault-chaos --mode inproc --runs 5 --duration 60s
bin/vault-chaos --mode procs --tls --runs 3 --duration 60s --backup-drill
bin/vault-chaos --selftest       # must report that it caught the lie
scripts/interop.sh               # needs Node.js
cd web && npm ci && npm test && npm run smoke -- --real
```

A failing chaos or simulation run prints its seed and how to replay it.

**Speed** (`make bench`; Apple M5, three nodes in one process). Saving an
entry takes about one disk flush plus a round trip, because the leader
replicates to the followers while it writes to its own disk: with 3 ms
flushes (a laptop SSD) a save takes 4.5 ms, with 10 ms flushes (an SD card)
12 ms. Checking for changes takes 0.4 ms; downloading a 1,000-entry vault
2-3 ms; logging in 80 ms, almost all of it the deliberately slow Argon2id.
The browser client is a 101 KB download the first time and nothing on
later visits; on a 2,000-entry vault it unlocks in about 350 ms (110 ms of
Argon2id) and applies a change from another device in 15 ms. Restoring a
server from a backup at the storage quota takes about 50 ms.

Backups exist for the case the tests do not cover: a bug that loses data
without ever exposing it. Every node dumps the replicated state daily, an
admin can download it (`fvault admin backup`), and every user can make a
self-contained encrypted export (`fvault export`).

## 8. Configuration (vaultd)

A JSON file (`vaultd run --config path`):

```json
{
  "node_id": "pi",
  "data_dir": "/var/lib/vaultd",
  "client_listen": "0.0.0.0:8443",
  "peer_listen": "0.0.0.0:8444",
  "peers": [
    {"id": "pi",     "peer_addr": "pi.vault.internal:8444",     "public_url": "https://pi.vault.internal:8443"},
    {"id": "vps",    "peer_addr": "vps.vault.internal:8444",    "public_url": "https://vps.vault.internal:8443"},
    {"id": "laptop", "peer_addr": "laptop.vault.internal:8444", "public_url": "https://laptop.vault.internal:8443"}
  ],
  "tls": {"ca_file": "ca.pem", "cert_file": "pi.pem", "key_file": "pi-key.pem"},
  "bootstrap_token_file": "/etc/vaultd/bootstrap-token",
  "insecure": false
}
```

`insecure: true` (plain HTTP on both listeners) exists for local development
and tests only, and is refused on anything but loopback addresses. The full
list of settings is in OPERATIONS.md, "Configuration reference".
