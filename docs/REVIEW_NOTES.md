# Review notes

Two independent reviews were run on the first complete version of the code,
by reviewers that had not written it. This file records what they found and
what was done about each finding, so that a later reader (or auditor) can see
which parts of the design exist *because* of a review, and what was knowingly
left open.

**Status of the reviews themselves.** The server-side review was completed
and its findings were reproduced with tests. The client-side review
(`docs/reviews/client-crypto-review.md`, kept verbatim) was only partly
reproduced: its parser/encoding findings were confirmed with tests, but the
harness meant to demonstrate the hostile-server findings end to end was never
run, so those findings rest on code reading. They were treated as real and the
protocol was changed. **The revised protocol has not been reviewed again by an
independent party**, and no third-party audit has taken place.

## A. Server side (state machine, HTTP API, peer transport, PKI, `vaultd`)

No authentication bypass, cross-vault access, privilege escalation or way to
crash the state machine was found.

| # | Finding | Severity | Resolution |
|---|---------|----------|------------|
| 1 | No bound on total stored bytes: one user could grow the state past what fits in a snapshot message, after which a lagging or replaced node could never catch up; memory and backup disk exhaustion | medium | **Fixed.** Replicated quotas: 8 MiB per vault, 16 MiB per user, 48 MiB per cluster (items are charged 128 bytes of overhead each), 32 users, 32 vaults per creator. Worst-case snapshot measured at 74.8 MiB; the peer transport accepts 256 MiB. |
| 2 | A full vault could not be rekeyed (the request exceeded the body limit), leaving a removed member's key in use | low–medium | **Fixed** by the per-vault quota: the largest possible rekey body is 10.7 MiB against a 32 MiB limit (tested). |
| 3 | Replaying a change-password request ran Argon2 before the rate limiter | low | **Fixed.** The limiter is consulted before every verifier computation. |
| 4 | The household CA could issue a certificate for any website, yet users install it on their devices | hardening | **Fixed.** The CA is name-constrained to the cluster's hosts (critical extension), carries server/client-auth EKUs only, and `issue-cert` refuses a host outside the constraints. |
| 5 | `insecure: true` was accepted on public addresses | hardening | **Fixed.** Insecure mode is refused unless every listener and peer address is loopback (override: `VAULTD_ALLOW_INSECURE_NETWORK=1`). |
| 6 | A node cut off from the cluster keeps honouring revoked credentials for stale reads, indefinitely | low | **Bounded and documented.** Stale reads stop after `stale_read_window_hours` (7 days) without contact with a leader. |
| 7 | Creating a vault with an existing ID reveals that the ID exists | low | **Documented** as the one exception in api.md (IDs are 128-bit random). |
| 8a | Tokens could be refreshed forever | hardening | **Fixed.** Tokens carry the time the password was last proven; `max_session_age_days` (30) is absolute. |
| 8b | Token-minting paths trusted the user ID in the apply result | hardening | **Fixed.** Must equal the authenticated caller. |
| 8c | A client reaching the node directly could choose its own rate-limit identity via the proxy header | hardening | **Fixed.** The header is honoured only from `trusted_proxies`. |
| 8d | Large bodies accepted on unauthenticated endpoints | hardening | **Fixed.** 4 KiB (prelogin, login), 32 KiB (register). |
| 8e | Restoring different backups on different nodes would diverge silently | hardening | **Mitigated.** The restored snapshot sits at log index `rev+1`, so the newest state wins and overwrites the others; `vaultd restore` prints a state digest to compare. |
| 8f | Anyone can lock a named user out of online login on a node for a few minutes | — | **Accepted**, documented in the threat model. |
| doc | "Admin backup is ciphertext only"; "removal revokes access immediately" | — | **Corrected** in THREAT_MODEL.md, api.md and the API types. |

## B. Client side (protocol, Go and TypeScript crypto, session logic)

The primitives and their use (AEAD box, key separation, authenticated key
wrap, KDF floor) were found sound and consistent between the two
implementations. The protocol around them was not: nothing authenticated
*who* a vault key was wrapped for or came from.

| # | Finding | Severity | Resolution |
|---|---------|----------|------------|
| 1 | A rekey wrapped the new key for whoever the server listed as a member, including invented identities | critical | **Fixed (protocol).** Each vault carries a roster sealed under its key (crypto.md §6.3); recipients are computed from it, must be verified contacts, and are shown before the request is built (§6.6). |
| 2 | A vault key was accepted from any sender the server named, including for the personal vault and for vaults the device had just created | critical | **Fixed (protocol).** Acceptance rules of §6.4: own key, a recorded owner, or a verified contact; otherwise the vault is *pending*. Keys a device generates are never replaced by what the server returns. |
| 3 | An older key epoch was accepted, so new entries could be written under a revoked key | high | **Fixed for devices that saw the newer epoch** (continuity record in the sealed trust store; epoch bound into every AAD). A brand-new device cannot detect it: documented. Restores from backup go through an explicit "accept the restored state" action. |
| 4 | One unreadable entry blocked rekeying forever | medium–high | **Fixed.** A rekey re-encrypts raw plaintext without parsing and carries unopenable boxes over; unreadable entries can be deleted. |
| 5 | Changing the master password does not revoke a compromised one (keys never rotate) | medium | **Documented**, with the cache now replaced and the new wrapped key verified on change. Key rotation is future work. |
| 6 | Login KDF parameters could be lowered to a weak floor with a server-chosen salt; a captured login key is an offline guessing oracle | medium | **Fixed / documented.** The floor is now the default (64 MiB, 3 passes), parameters weaker than cached ones are refused, and the Argon2 salt is bound to the username. The oracle property is inherent without a PAKE and is stated in the threat model. |
| 7 | Pins keyed by user ID only, unvalidated usernames, verification unused, local stores unauthenticated | medium | **Fixed.** Contacts are pinned as (user ID, username, key); directory entries are validated; mismatch events are permanent; the trust store is sealed under a key derived from the account key; verification gates sharing, acceptance and rekey. |
| 8 | Server-supplied IDs used as plain-object keys in the browser client | low | **Fixed.** Maps throughout; IDs validated first. |
| 9 | Account block fields trusted | low | **Fixed.** Must equal the unlocked identity and the typed username. |
| 10 | Offline cache overwritten by any answer | low | **Fixed.** The cache's `rev` never decreases. |
| 11 | Rekey wrote "(unreadable name)" into metadata | low | **Fixed** (raw re-encryption). |
| 12 | Go and TypeScript decoded the same plaintext differently | low | **Fixed.** Normative decoding rules (§5.3), identical strict decoders, 97 accept/reject vectors. |
| 13 | Go accepts non-canonical base64 on the wire, TypeScript rejects it | low | **Open.** Availability only: a misbehaving server can make the two clients disagree about whether a response is well-formed. Roster keys are checked canonically in both. |
| 14 | A TypeScript edit did not preserve unknown numeric fields exactly | low | **Fixed.** Unknown members are carried as raw text in both clients (pinned by vectors). |
| 15 | Learned node URLs unrestricted | low | **Fixed.** HTTPS only (unless the user configured HTTP), no downgrade, bounded count. |
| 16 | 80-bit fingerprints binding only the key | hardening | **Fixed.** 128 bits, covering user ID, username and key. |
| 17 | Test-vector-only functions callable from production code | hardening | **Mitigated.** Go: a test fails if anything outside the crypto packages references them. TypeScript: they live in a module the bundle must not contain (tested). |
| 18 | KDF ceiling allowed a 16 GiB request | low | **Fixed.** Ceiling 256 MiB, 8 passes. |
| 19 | Browser spellcheck active on secret fields | low | **Fixed.** |
| 20 | Zeroisation gaps | hardening | **Fixed** (best effort, as before). |
| 21 | NFKC depends on the runtime's Unicode version | low | **Documented.** |
| 22 | Service-worker cache had no integrity check | hardening | **Fixed.** Hash manifest embedded at build time. |
| 23 | Weak master-password gate | hardening | **Improved.** A shared policy (12+ characters, no username, no trivial patterns, common-password list) pinned by vectors; it is a floor, not a strength meter. |

## C. Changed after the reviews (usability, performance and size pass)

Neither review saw these. None changes a wire format, an on-disk format or a
trust rule, and each was checked as described, but a later reviewer should
read them as new code.

| Change | Where | How it was checked |
|--------|-------|--------------------|
| A leader sends new entries to the followers before writing them to its own disk; a follower acknowledges a heartbeat before writing entries that arrived with it, claiming only what was already durable | `internal/raft` (`ready.takeEarly`, `driver.process`) | The simulator runs the same order and crashes between the early send and the write: 230,000 fresh seeds pass on the final code; four planted misordering bugs (everything sent early, acknowledgements unbounded or off by one, vote grants early) are each caught. Unmodified chaos harness passes in both modes. A cluster of old binaries was upgraded one node at a time under load with nothing lost. |
| Hand-written encoder and decoder for state-machine snapshots, producing and accepting exactly the previous JSON (anything else falls back to the standard decoder) | `internal/fsm/snapshot.go` | Encoder compared with `json.Marshal` and decoder with `encoding/json` in tests and by fuzzing; an old log, old snapshots and an old backup replay to identical bytes and state hash; old and new `vaultd restore` print the same digest for the same backup. |
| Static files compressed once and cached by content hash; API responses are still never compressed | `internal/server/web.go` | Decoded bytes equal the built files and the service worker's integrity manifest; security headers present on 200 and 304. |
| The command-line client sends its first sync, with the session token it already has, while the master password is being stretched; the answer is used only after the password has opened the local copy | `internal/client` (`prefetch`) | Tests for wrong password, expired token and no token; race detector. |
| Faster strict JSON scanner (Go) and base64 decoder (TypeScript) | `internal/vaultcrypto/strictjson.go`, `web/src/crypto/encoding.ts` | Shared vectors unchanged and byte-identical when regenerated; the TypeScript decoder was compared with the old one on 400,000 random inputs. |
| Browser client keeps decrypted entries between syncs when ciphertext, version, key epoch, key commitment and server metadata are all unchanged; dropped on lock, never stored | `web/src/vault/session.ts` | Test that a different ciphertext under the same ID and version is decrypted again. |
| `fvault shell` keeps the unlocked session in one process's memory for several commands, with an idle lock | `cmd/fvault/shell.go` | Tests for the idle lock and re-unlock; nothing is written to disk or the environment. |
| The browser client translates server refusals into plain sentences; a few are recognised by the server's message text because the API has one code for several causes | `web/src/ui/errors.ts` | Falls back to a generic sentence if the server's wording changes. A per-cause error code would be cleaner; adding one changes what the state machine records for a command, so it needs a versioned rollout. |

## Still open, by design or for lack of time

* Independent re-review of the revised sharing protocol.
* Snapshots are still taken and written on the Raft event loop. At the
  storage quota that is tens of milliseconds on a laptop SSD; on a slow SD
  card it can exceed the election timeout and cost a leader change (see
  "Slow disks" in OPERATIONS.md). Doing the write in the background needs a
  change to the storage contract and its crash tests.
* A device cannot tell "nothing changed" from "the servers were restored to
  an older state that happens to have the same revision number" without
  downloading the vault, so the command-line client downloads it on every
  start. A state digest in the sync answer would remove that.
* Key rotation (B5), trust-store synchronization between a user's devices,
  signatures on rosters, an augmented PAKE for login.
* B13 (base64 strictness in the Go client).
* Cluster membership changes; snapshotting off the Raft loop.
* TOTP code generation in the clients (seeds are stored and copyable).
* Browser coverage beyond headless Chromium; Windows for the CLI; the systemd
  unit and the CI workflow have not been run.
