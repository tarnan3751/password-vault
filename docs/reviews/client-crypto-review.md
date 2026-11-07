# Family Vault: client-side crypto and key-handling review

## Scope and method

**Read in full:**
- Specs and docs: `docs/spec/crypto.md`, `docs/spec/api.md`, `docs/THREAT_MODEL.md`, `testvectors/README.md`, `internal/api/types.go`.
- Go: all of `internal/vaultcrypto` (including `vectorgen`) and `internal/backup`.
- TypeScript: `web/src/crypto`, `web/src/vault`, `web/src/api`, `web/src/sw.ts`.
- UI: I read `app.tsx`, `welcome.tsx`, `account.tsx`, `vault-dialogs.tsx` and `detail.tsx` in full. The other UI files I only searched for secret handling (rendering, clipboard, storage, logging, spellcheck).
- Server code, read only to learn what a client can be sent: `internal/server/server.go` (CSP construction) and `internal/fsm/validate.go` (blob validation).

**Proofs.** I ran temporary tests:
- Go: `internal/vaultcrypto/zz_review_divergence_test.go`.
- TS: `web/test/zz-review-parse.test.ts`.

Their outputs are quoted below; findings proven this way are marked **CONFIRMED**.

A second TS harness (a malicious subclass of `web/test/fake-server.ts` attacking a live `Session`) was cut off before it ran. The malicious-server findings (1–4, 7, 10, 11) are therefore **LIKELY**. In each case I cite the exact unconditional code path and explain why nothing on it blocks the attack. They are the first thing to turn into regression tests once fixed.

**Cleanup.** All temporary files are deleted. `find . -name '*zz*review*'` returns nothing. `git status --short` lists only the repo's existing untracked top-level paths (there are no commits yet), the same as at the start. No non-temporary file was modified, `web/dist` was not rebuilt, and nothing was committed.

**Bottom line.** The primitives are sound, and Go and TS agree on them (box, AAD domain separation, authenticated ECIES wrap, KDF floor enforcement). The protocol is not sound against the threat model's main adversary, a fully malicious server. Two things are missing:
- Nothing authenticates **who a vault key is wrapped for**: the member list and directory are server-controlled.
- Nothing authenticates **who a vault key comes from**: any sender ID the server names is accepted, and new identities are TOFU-pinned silently.

Comparing fingerprints, the defence the threat model recommends, does not stop either. A compromised node can obtain the key of a shared vault at the next member removal. It can also get new entries, edits and whole backup restores encrypted under a key it chose.

---

## Findings, by severity

### 1. Rekey wraps the new vault key for any member the server lists, including identities the server invents
- **Severity:** CRITICAL. **Status:** LIKELY (unconditional code path; end-to-end harness not completed).
- **Where:**
  - `web/src/vault/session.ts:637-652` (`removeMember`: delete, then `sync()`, then `rekeyVault`).
  - `session.ts:676-685` (wraps VK' for every entry of `view.members`, the server's list, using the public key from the server's `directory`).
  - `session.ts:349-359` (`observePins` TOFU-pins every directory entry on first sight).
  - Spec `crypto.md` §6.2: "wrap VK' for every remaining member".
- **Attack:**
  - **Who:** a fully compromised node (or the admin running it).
  - **How:** `removeMember` runs a sync between the delete and the rekey. In that answer the server adds a fabricated user ID with a key pair it controls to `directory`, and to that vault's `members`.
    - A never-seen user ID is "first contact", so it is pinned silently and raises no warning.
    - `rekeyVault` only refuses on a pin *mismatch* (`:679-680`). It does not look at `verified`, and it does not compare the member set with anything the owner authorised.
    - The rekey request therefore contains a wrap of VK' to the server's identity. The server unwraps it using the owner's (real) public key as sender key.
  - **What it gains:** VK', hence every item re-encrypted in that same request, every later entry, and the vault name.
  - **Detection:** comparing every real member's fingerprint does not help, because the injected ID never existed before.
    - "Remove and rekey" is one click (`ui/vault-dialogs.tsx:281-291`), and the injected member exists only in the sync between delete and rekey. The owner never sees the list that is used.
    - The "Rekey now" banner is driven by the server-controlled `rekey_recommended` (`vault-dialogs.tsx:152-163`, `main-view.tsx:66`). The server can raise it on any owned vault, any time.
  - **Personal vaults too:** `rekeyVault` does not refuse personal vaults (only `addMember` checks `personal`), so the same applies to a personal vault for which the server raises `rekey_recommended` and lists an extra member.
- **Proof:** code path above. The only gates in `rekeyVault` are role, unreadable items, directory presence and pin mismatch (`:664-680`).
- **Fix (protocol; breaking, cheap now): an authenticated roster.**
  - Add a vault field `enc_roster = seal(VK_e, pad(rosterJSON, 64), aad = "fpv/v1/roster|" + vaultID + "|" + epoch)`, where `rosterJSON = {"v":1,"seq":n,"members":[{"id":"<id>","pk":"<b64 X25519>","role":"owner|editor|viewer"}]}`.
  - Owners rewrite it, with a CAS on `seq`, on every add, remove or role change.
  - Add it to `CreateVaultRequest`, `PutMemberRequest`, `RekeyRequest` and `api.Vault`.
  - (It cannot go into `enc_meta`: 64 users × about 100 bytes exceeds the 4 KiB `enc_meta` limit.)
- **Rekey rules under the roster:**
  - The client computes recipients **locally**: the roster decrypted under the *current* key, minus the member being removed.
  - It wraps to the pk recorded in the roster, never to `members`/`directory`.
  - It refuses (with a warning) if the server's `members` differ from the roster.
- **Without a protocol change (client-only, compatible):**
  - Never wrap for a member who was not already a recipient at the previous epoch on this device. Persist that set locally, integrity-protected (see finding 7).
  - Show the recipient list with verification status, and require explicit confirmation for any unverified or new recipient before the rekey request is built.
  - Refuse to rekey personal vaults.

### 2. Incoming vault keys are accepted from any sender the server names: personal vault, freshly created vaults, backup restores
- **Severity:** CRITICAL. **Status:** LIKELY.
- **Where:**
  - `session.ts:383-401`:
    - `sender = this.directory.get(v.my_key.sender_id)`, then unwrap with `sender.public_key` from the directory, then the key is used for reads *and writes* (`newSecrets.set`).
    - There is no sender policy: no "personal ⇒ sender is self", no "sender must be an owner/member", no "sender must be verified".
    - When `sender_id == self`, the directory key is used instead of the authenticated `this.publicKey`. The self directory entry is never compared with the account key.
  - `createVault` (`:541-549`) zeroes its locally generated VK and from then on uses whatever key the next sync hands it.
  - `importBackup` (`:803-831`) creates the new vault this way and then encrypts every restored entry under the key from `mustVault(id)`, which came from the server.
  - Duplicate vault IDs in one sync: views keep both entries, but `newSecrets` is last-wins (`:401`), while `mustVault` uses the *first* view (`:424-428`, `vault()` = `find`).
- **Impact:** the client cannot tell whether a vault key was created by a legitimate member. A compromised node can make it read from, and write to, a key the node knows. This covers new entries, edits, freshly created vaults and complete backup restores, the personal vault included. (The full attack narrative is not included in this file.)
- **Proof:** code path above. Nothing on the unwrap path checks the sender's identity, role or verification status, and `createVault` does not keep its own key.
- **Fix (client-only, compatible):**
  - Personal vaults, and vaults this device created: require `sender_id == self`, and unwrap with `this.publicKey`, never the directory entry.
  - `createVault` and `importBackup` must keep the locally generated VK and verify that the server's wrap opens to the same key.
  - Persist an integrity-protected commitment `H("fpv/v1/vk-commit" || VK)` per (vault, epoch) and refuse a different key for a known (vault, epoch).
  - Reject a sync containing duplicate vault IDs or user IDs, and reject a self directory entry that differs from the account public key.
  - A vault whose key comes from a sender who is not verified on this device is shown as "shared by X, not verified" and stays read-only until the user verifies X.
- **Fix (protocol):** with the roster of finding 1, a recipient also checks that `sender_id` is an owner in the roster decrypted under the delivered key, and that its own entry (id, pk) is in it. That alone does not stop a forged key arriving with a forged roster, so the sender-verification rule above remains necessary.

### 3. Key-epoch rollback is accepted, so new entries can be written under a revoked key
- **Severity:** HIGH. **Status:** LIKELY.
- **Where:**
  - `session.ts:379-401`: `buildViews` takes `key_epoch` and `my_key` from each sync with no monotonic check against epochs seen before.
  - `crypto.md` §5: item and meta AAD do not include the epoch.
- **Impact:** the threat model promises that after removal plus rekey "even a copy of future ciphertext is useless" to the removed member. That fails if a malicious server and the removed member cooperate: clients accept an older, authentic vault state and encrypt new entries under the key the removed member still holds. This is a confidentiality break, not just the stale-data issue the threat model admits.
- **Fix:**
  - **Client:** persist the highest epoch (and its VK commitment) per vault, integrity-protected. Refuse writes, and warn, when a sync offers a lower epoch.
  - **Protocol (breaking, cheap now):** bind the epoch into the AADs, `"fpv/v1/item|" + vaultID + "|" + itemID + "|" + epoch` and `"fpv/v1/vault-meta|" + vaultID + "|" + epoch`, so that ciphertext from mixed epochs is detectable.

### 4. Any editor can permanently block rekeying from the web client
- **Severity:** MEDIUM-HIGH. **Status:** CONFIRMED by code; the TS-only variant is CONFIRMED by test (finding 12).
- **Where:**
  - `session.ts:665-666`: `rekeyVault` throws `RekeyBlockedError` if any item fails to decrypt.
  - `ui/detail.tsx:73-80`: an unreadable entry gets no Delete button ("Backups and rekeying will refuse to drop it").
  - `internal/fsm/validate.go`: only checks item blob size, not box format.
- **Impact:** an editor who expects removal can leave one entry the web client cannot read. Afterwards the web UI can never rekey that vault, so the removed member's key stays the vault key for all future entries. Removal (`removeMember`) still goes through and only the rekey fails; the banner stays forever.
  - Because of the Go/TS parser divergences (finding 12), an entry written by the Go client that Go reads fine (for example `"hidden": null`) is unreadable in TS and blocks the web rekey too.
- **Fix:**
  - Rekey should carry an unreadable item over unchanged only if it is not a valid box under the current key (garbage cannot leak anything).
  - Better: let the owner delete unreadable entries in the UI (`Session.deleteItem` already works without plaintext).
  - Make the TS parser at least as lenient as Go (finding 12).

### 5. A compromised master password stays compromised after a password change
- **Severity:** MEDIUM. **Status:** CONFIRMED by spec and code.
- **Where:** `crypto.md` §4 ("accountKey and the key pair do not change"), `session.ts:711-729`.
- **Impact:**
  - `accountKey`, `encPrivateKey` and the X25519 key pair never rotate. Anyone with the old password and any old copy of `wrappedAccountKey` can recover the private key permanently. Such copies exist on servers, node state dumps, admin backups and other devices' offline caches.
  - With the private key they can open every vault key wrapped to this user, including all future rekeys, because rekeys wrap to the same public key. KCI also lets them forge wraps to this user from any member.
  - On this device, if the post-change sync fails, the cache keeps the old `wrappedAccountKey`, so the old password still unlocks it offline. Other devices keep it until they next log in online.
  - The client also never checks that the server stored the new wrapped key: `nk.encKey` is zeroed before the sync.
- **Fix:**
  - Short term: document it (see threat-model corrections). After a change, verify that the new account block opens with the new `encKey` before zeroing it, and overwrite or purge the cached account block.
  - Proper fix (protocol): key rotation on password change. Generate a new `accountKey`, a new key pair and a new self-wrap of every vault key; rekey shared vaults; and give members a key-transition statement they can authenticate. For example, a static-static-DH MAC from the old key to each member, or an Ed25519 identity key whose signature authorises X25519 key changes. Pins would then accept a new key only with a valid transition.

### 6. KDF parameters at login can be downgraded to the floor, with a server-chosen salt, and a captured login key works as an offline password oracle
- **Severity:** MEDIUM. **Status:** CONFIRMED by code.
- **Where:**
  - `session.ts:154-159`: prelogin params are only checked against the floor, never against the cached account params on a device that knows them.
  - `crypto.md` §2: the floor is 19 MiB / t=2 / p=1, roughly 5x cheaper than the default 64 MiB / t=3 / p=4, and the salt is entirely server-chosen.
- **Impact:**
  - A malicious node gets a login key derived at floor cost. It can also use one fixed salt for every user, so a single precomputed dictionary serves all victims.
  - A captured `loginKey` lets the holder test password guesses offline (one client-side Argon2id each). The threat model's statement that it "does not help decrypt anything" is wrong.
  - The user only sees "wrong password" once and retries.
- **Fix:**
  - Refuse (or warn on) prelogin params weaker than the cached account's.
  - Raise the accepted floor to the defaults; the vectors already use the separate unsafe derivation.
  - Bind the salt to the user (protocol, breaking): `argonSalt = SHA-256(utf8("fpv/v1/kdf-salt|" + username + "|") || salt)`.
  - Longer term, an augmented PAKE (already listed as a limitation).

### 7. Identity binding and pinning are weaker than the documents assume
- **Severity:** MEDIUM. **Status:** CONFIRMED by code.
- **Where:** `vault/pins.ts:21-75`, `session.ts:349-359`, `:577-585`.
- **Problems:**
  - Pins are keyed by user ID only. A username can be moved to a different, new ID silently, and `observe` even updates the stored username of a pinned ID (`pins.ts:53-56`). A verified "bob" can become a new, unverified ID with no warning beyond a "not checked" tag.
  - Usernames from the server are never validated against `^[a-z0-9][a-z0-9._-]{0,31}$`, and duplicates are not rejected. That allows look-alike, RTL and zero-width names next to fingerprints.
  - Verification is per device and not synced. It is used only by the add-member dialog, never by rekey (finding 1) or for incoming keys (finding 2). On a new device everything, including the user's own entry, is first contact.
  - Pin-mismatch warnings are recomputed on each sync. A server that omits the user later makes the warning disappear; nothing records that a mismatch was ever seen.
  - Pins, `verified` flags, the node list and the cached sync sit unauthenticated in IndexedDB. Someone with the locked device can reset them, re-enabling TOFU, or plant cache content.
- **Fix:**
  - Pin the triple (username, userID, pk) and alert on any rebinding.
  - Validate every directory entry: ID format, username regex, a 32-byte key, unique IDs and usernames.
  - Persist mismatch events.
  - MAC the local store with `HKDF(accountKey, info = "fpv/v1/local-integrity")` and verify it on unlock.
  - Use verification status in rekey and for incoming shares.

### 8. PinStore uses a plain object keyed by server-supplied user IDs (prototype pollution)
- **Severity:** LOW. **Status:** CONFIRMED (test).
- **Where:** `pins.ts:22`, `:45-58`, `:60-66`.
- **Proof** (TS test output):
  ```
  observe status: same  ({}).username = bob
  after markVerified("__proto__"): ({}).verified = true
  ```
  A directory entry with `user_id: "__proto__"` and no `public_key` sets `Object.prototype.username`. Entries with a `public_key` make `observePins` throw, so the whole sync fails (DoS).
- **Impact:** limited today. I found no secret-affecting read of polluted properties, but it is unvalidated server data reaching prototypes.
- **Fix:** use `Object.create(null)` or a `Map`, and `validId()` every server-supplied ID before use.

### 9. Account block fields are trusted beyond the public key
- **Severity:** LOW. **Status:** CONFIRMED by code.
- **Where:**
  - `session.ts:207-210`: `Session.username = acct.username` from the server.
  - `:337`: that username is the cache key `K.sync(username)`.
  - The account's `user_id` is never compared with `LoginResponse.user_id`.
- **Impact:** a server can make one user's client write its cache under another local user's key on a shared family device, destroying that user's offline copy. It also controls the name shown and re-sent at re-login.
- **Fix:** use the normalised username the user typed for storage, and require `acct.username` to equal it and `acct.user_id` to equal `lr.user_id`.

### 10. The offline cache can be overwritten by any non-stale answer
- **Severity:** LOW. **Status:** CONFIRMED by code.
- **Where:**
  - `session.ts:336-342`: an answer without `stale` always overwrites the cache, regardless of `rev` or missing vaults.
  - `:321-325`: `unchanged: true` keeps whatever `raw` the cache held.
- **Impact:** a server answer with fewer vaults or a lower `rev` destroys the offline fallback. Pins are stored separately and only ever added to, so the cache cannot roll back pins.
- **Fix:** never let the cache's `rev` decrease; ask the user before persisting a sync that drops vaults the user did not leave or delete; authenticate the cache (finding 7).

### 11. Rekey with an unreadable vault name writes "(unreadable name)" into the new metadata
- **Severity:** LOW. **Status:** CONFIRMED by code.
- **Where:** `session.ts:397-400` (meta failure sets `base.name = '(unreadable name)'`, `metaExtra = {}`), `:673` (rekey re-encrypts `view.name`).
- **Impact:** the vault name and any metadata extension fields are destroyed. A metadata format the TS client rejects (for example `{"v":1}` without a name, which Go accepts) triggers this.
- **Fix:** block the rekey (or carry the old meta plaintext over) when the metadata did not decrypt.

### 12. Go and TS parse the same authenticated plaintext differently
- **Severity:** LOW (integrity of what each client displays, and the rekey block in finding 4). **Status:** CONFIRMED (tests).

**Item and meta parsing:**

| Input (inside a valid item or meta box) | Go `DecryptItem` / `DecryptVaultMeta` | TS `parseItemJson` / `decryptVaultMeta` |
|---|---|---|
| `"hidden": null` in a field | accepts | rejects ("fields") |
| `"v": 1.0` | rejects | accepts |
| `"created_at": 1.5` | rejects | accepts (`optInt` allows non-integers, `item.ts:117-122`) |
| `fields:[{"name":"PIN","value":"1111","VALUE":"2222"}]` | shows `PIN=2222` (case-insensitive struct matching) | shows `PIN=1111` |
| `"urls": ["https://a.example", null]` | accepts (`""`) | rejects |
| invalid UTF-8 byte in a string | accepts (U+FFFD substituted, rewritten on edit) | rejects (strict `TextDecoder`) |
| meta `{"v":1,"name":"Family","NAME":"Evil"}` | `"Evil"` | `"Family"` |
| meta `{"v":1}` (no name) | accepts (`""`) | rejects |

**Fix:** specify the item and meta JSON grammar precisely (exact-case keys, integers only, null policy, UTF-8 validity) and give both decoders the same rules: in Go a `DisallowUnknownFields`-style exact-key decoder for nested objects, in TS integer checks. Add these cases to `items_negative` and to a new `items` "lenient" group.

### 13. Go accepts non-canonical base64; TS is strict
- **Severity:** LOW. **Status:** CONFIRMED (test).
- **Proof:** Go `encoding/json` `[]byte` decoding accepts `"AB=="` (non-zero trailing bits) and embedded `\r\n` (`QUJD\r\nREVG` decodes to `414243444546`), and a non-canonical KDF salt passes `ValidateKDFParams`. TS `b64decode` rejects all of these.
- **Impact:** a server can make the two clients disagree. A non-canonical directory key also makes the TS member-view build throw, so the whole sync fails (`session.ts:375`).
- **Fix:** add strict base64 in the Go client for all wire `[]byte` fields (a custom type using `base64.StdEncoding.Strict()` and rejecting `\r\n`), or specify the lenient behaviour.

### 14. Unknown item fields are not preserved exactly by a TS edit
- **Severity:** LOW. **Status:** CONFIRMED (test).
- **Proof:** an item containing `"x_future":{"id":12345678901234567890,"f":1.0,"z":-0}` comes back from a TS edit as `"x_future":{"id":12345678901234567000,"f":1,"z":0}`. Go keeps the raw bytes.
- **Fix:** keep unknown members as raw JSON text in TS (track source slices, or use a lossless parser) so forward compatibility matches Go.

### 15. Learned node URLs are not restricted
- **Severity:** LOW (browser) / not assessed (CLI). **Status:** CONFIRMED by code.
- **Where:** `api/client.ts:30-38` (accepts `http:`), `:92-100` (merges every URL from `GET /v1/cluster`), persisted via `K.nodes`.
- **Impact:** the bearer token and login key are sent to whichever node is tried. In the browser this is contained by the CSP `connect-src`, which is fixed to the configured peers (`internal/server/server.go:137-151`). The client logic itself enforces nothing, and the Go CLI (out of scope) must not rely on this.
- **Fix:** accept only `https:` learned URLs (unless the initial origin is `http:`), only origins in the initially configured set, and never persist new origins without user confirmation.

### 16. Fingerprints are 80 bits and bind only the key
- **Severity:** HARDENING. **Status:** analysis.
- **Analysis:** a substitution at first contact needs a key whose fingerprint equals the victim's: a targeted second preimage of truncated SHA-256 at about 2^80 trials, each needing an X25519 point (batched point additions plus one SHA-256). That is about 1.2e24 operations, on the order of 10^7 GPU-years: infeasible for a household adversary, marginal against a nation state, and divided by N when any of N users will do. The practical weakness is humans comparing only part of the string.
- **Fix:** 128 bits (8 groups), and cover the identity: `SHA-256("fpv/v1/fingerprint" || userID || username || pk)`. Cheap before deployment.

### 17. Misuse-prone APIs
- **Severity:** HARDENING. **Status:** CONFIRMED by code.
- **Go:** `SealWithNonce`, `WrapVaultKeyDeterministic`, `NewAccountDeterministic`, `RewrapAccountKeyWithNonce`, `DeriveMasterKeysUnsafeParams` and `backup.EncodeDeterministic` are exported. Today they are called outside tests only by their randomising wrappers in the same packages; `internal/client` and `cmd/fvault` did not call them.
- **TS:** production functions take an optional nonce or fixed inputs: `encryptItem`, `encryptVaultMeta`, `rewrapAccountKey`, `createAccountMaterial`, `encodeBackup`. No production caller passes one today. `rewrapAccountKey(userId, newEncKey, accountKey)` has a different argument order from Go and takes two same-typed byte arrays, so a swap would fail silently.
- **Fix:** move deterministic variants into test-only modules (Go: an `internal/.../vectoronly` package or a build tag; TS: a separate file the bundle does not import), and use branded key types in TS.

### 18. The KDF ceiling allows a heavy DoS
- **Severity:** LOW. **Status:** CONFIRMED by code.
- **Impact:** a server prelogin answer, or a hostile backup file, may request 1 GiB × t=16. In a browser tab or on a phone this can take minutes or crash; it is DoS only.
- **Fix:** a lower ceiling for login and backup import (for example 256 MiB and t ≤ 8) unless the user confirms.

### 19. Browser spellcheck is active on secrets
- **Severity:** LOW. **Status:** CONFIRMED by code.
- **Where:** the notes `TextArea` (`ui/kit.tsx:87-92`) and non-hidden custom-field value inputs (`ui/editor.tsx:116`) do not set `spellcheck=false`. Enhanced cloud spellcheckers send that text off-device.
- **Fix:** `spellcheck={false}`, `autocorrect="off"` and `autocapitalize="off"` on all item fields.

### 20. Zeroisation gaps (best effort, as documented)
- **Severity:** HARDENING.
- **Where:**
  - Go `UnlockAccount` (`account.go:99-126`) copies `*ak` into the result but never zeroes the heap `ak` on success.
  - TS `unlockAccount` (`crypto/account.ts:54-57`) does not zero `accountKey` when the second open fails.
- **Fix:** zero the heap copy on success, and zero `accountKey` on the failure path.

### 21. NFKC depends on the runtime's Unicode version
- **Severity:** LOW. **Status:** LIKELY.
- **Detail:** here Go `x/text` is Unicode 17.0 and Node is 18.0; both map U+1CCD6/U+1CCF1 to `A1`. A browser with older ICU leaves newly assigned compatibility characters unnormalised, so the same password derives different keys on different clients.
- **Fix:** refuse (or warn on) passwords containing code points unassigned in a pinned Unicode version, or document the risk.

### 22. Service-worker asset cache can persist tampered content
- **Severity:** HARDENING.
- **Where:** `sw.ts:46-53`: `/assets/*` is cache-first with no integrity check.
- **Impact:** an asset served during a server compromise remains cached after remediation, until the build ID changes. `/v1/` is never cached (`sw.ts:58-59`), which is correct.
- **Fix:** embed asset hashes in the precache manifest and verify them before `cache.put`.

### 23. The master-password strength gate is weak
- **Severity:** HARDENING.
- **Detail:** `estimateStrengthBits` rates patterns like `Football1` above the "too weak" cutoff. Use a zxcvbn-class estimator for the master password.

---

## Threat-model and spec sentences that must change

1. **THREAT_MODEL.md:30-32**, "They do **not** obtain any entry content, vault name, vault key…". This is true only of a *passive* copy of server data. An active compromised server can obtain vault keys (findings 1–3). Qualify the sentence, and add these active attacks to the list below it.
2. **THREAT_MODEL.md:36-39**, "Each guess costs one Argon2id evaluation at the client parameters … plus the server verifier's." The stolen state includes `wrappedAccountKey`, which checks a guess with the client Argon2id alone, so the verifier adds nothing.
3. **THREAT_MODEL.md:40-44**, "A login key … does not help decrypt anything". Wrong: it is an offline password-guessing oracle, at parameters the server may lower to the floor and with a salt the server picks (finding 6).
4. **THREAT_MODEL.md:48-53**, the public-key substitution paragraph and "Compare fingerprints once". Comparing fingerprints does not stop the server from **adding** identities to member lists or naming new senders. Verification is per device. Usernames can be rebound to new IDs. Rekey ignores verification entirely (findings 1, 2, 7).
5. **THREAT_MODEL.md:54-57**, "Replacing a wrapped vault key … reduces to the public-key substitution above." False: the client accepts any named sender, including invented ones and the user themself with a directory key the server chose, and accepts older epochs (findings 2, 3).
6. **THREAT_MODEL.md:58-62**, rollback is "freshness" only. A rollback of the key epoch is a confidentiality issue: new entries get encrypted under a revoked key (finding 3).
7. **THREAT_MODEL.md:79-84**, the locked-device paragraph. Add: pins, `verified` flags, the node list and the cache are unauthenticated and can be tampered with; and the cache can hold an old `wrappedAccountKey` that a previous password still opens (findings 5, 7).
8. **THREAT_MODEL.md:93-95**, "the client then rekeys the vault so that even a copy of future ciphertext is useless to them." Does not hold when an editor planted an unreadable entry (finding 4), when the server rolls back the epoch (finding 3), or when the rekey simply fails and is left pending.
9. **THREAT_MODEL.md, Known limitations (130-146).** Add:
   - membership and recipient lists are not authenticated;
   - key pairs never rotate, so a master password that was ever compromised compromises the account permanently against anyone holding old server or cache data, and changing it does not fix that.
10. **crypto.md §6.2**, "wrap VK' for every remaining member". Must say *the authenticated roster*, not the server's list.
11. **crypto.md §6.1(2)**, "Pin every (userID, publicKey)". Must pin (username, userID, publicKey), validate directory entries, and use the authenticated own key for `sender == self`.
12. **crypto.md §4 "Changing the master password"**. State explicitly that it does not revoke a compromised password's access to the private key.

---

## Verified OK (coverage)

- **Box (§3), both languages:**
  - Fresh 24-byte CSPRNG nonce per seal; version byte checked.
  - 41-byte minimum; one undifferentiated error.
  - Key length checked (TS); matches all vectors.
- **AAD domain separation:**
  - `account-key|`, `private-key|`, `vault-meta|`, `item|`, `vault-key|`, `backup` are all distinct.
  - IDs are validated as 32 lowercase hex before every interpolation (both languages), so there is no `|` ambiguity; epoch ≥ 1 is enforced.
  - Items cannot be moved across items or vaults, and meta and item ciphertexts cannot be swapped.
  - A blob encrypted under an old vault key fails against the new one (it is then shown as unreadable).
- **Wrap (§6), both languages:**
  - Inputs are dh1 ‖ dh2 with salt pkE ‖ pkS ‖ pkR and an ordered sender|recipient AAD. Reflection and relabelling (A→B presented as B→A) fail, and so does unknown-key-share via IDs.
  - All-zero DH output is rejected on both sides (Go `curve25519.X25519` error plus explicit check; noble throws plus `isAllZero`).
  - Exact 105-byte and 32-byte checks; sender compromise does not expose wraps (dh1).
  - KCI after recipient compromise is inherent to the design; noted in finding 5.
- **KDF floor and ceiling** are enforced before any Argon2 run in: registration, online login (`session.ts:158-159`), offline unlock (`deriveMasterKeys` on the cached params), password change (current: cached params, validated; new: defaults), and backup import (Go `backup.go:144`, TS `backup.ts:98-103`; the 2 GiB vector is refused first). Integer and type checks exist in TS.
- **Username normalisation** is identical in Go and TS (ASCII-only trim, reject non-ASCII before lower-casing).
- **Password normalisation:** NFKC; Go `ToValidUTF8` and TS `toWellFormed` handle malformed input equivalently for any real input.
- **TS base64** is strict (canonical, padding, no whitespace or URL alphabet), and hex IDs are lowercase only.
- **`encKey`** is never stored or sent. Keys are zeroed at lock. No secret goes to `localStorage` (only the server URL and auto-lock minutes) or to IndexedDB (only ciphertext, pins, nodes and last user). There is no `console.*` anywhere in `web/src`.
- **Unlock:** the private key is checked against the account public key at unlock, and the account public key is re-checked on every sync (`session.ts:329`).
- **Prototype pollution through item JSON or API bodies:** not possible. `JSON.parse` and `Object.fromEntries` produce own properties, and `structuredClone` and `itemToJson` keep `"__proto__"` as an own member (test: output contained `"__proto__":{"polluted":1}` and `({}).polluted` stayed undefined). Rekey's `wrapped[...]` is guarded by `checkIds`. The only pollution found is in `PinStore` (finding 8).
- **No retry loops:** `version_conflict` raises `ConflictError` after one sync, `key_epoch_mismatch` retries once, 401 triggers one re-login, rekey makes at most 4 attempts. Idempotency keys are 16 random bytes, reused only within one logical request.
- **Service worker:** never touches `/v1/`, non-GET or cross-origin requests; `/sw.js` is excluded.
- **UI rendering:** all through Preact text nodes, no `innerHTML` or `dangerouslySetInnerHTML`. Links go through `safeHref` (http/https only) with `rel="noopener noreferrer"`. The clipboard is cleared after 30 s; the password field has `spellcheck=false`.
- **Backup:**
  - Restore always uses new vault and item IDs, so nothing is overwritten. Entries are re-validated through `itemFromObject`.
  - The UI caps the file at 64 MiB.
  - The cleartext envelope holds only `created_at` and the KDF params; the payload, including `exported_at` and `exported_by`, is authenticated.
- **Password generator:** correct rejection sampling (`limit = 2^32 − 2^32 mod n`, both languages); at least one character per class; Fisher–Yates with a uniform `randInt(i+1)`.
  - The "one per class, then shuffle" approach is not exactly uniform: P(s) ∝ the product of per-class counts. The measured deficit is negligible (computed exactly):

    | Case | Uniform over valid set | Generator | Deficit |
    |---|---|---|---|
    | L=8, all four classes | 50.50 bits | 50.46 bits | 0.04 bits |
    | L=20, all four classes | 128.72 bits | 128.64 bits | 0.09 bits |
    | L=20, look-alikes excluded | 126.60 bits | 126.51 bits | 0.09 bits |

  - The "uniform" comment is slightly inaccurate but harmless. The UI never displays an entropy figure.
- **Randomness:** Go `crypto/rand.Read`, which cannot fail under Go 1.27, so the ignored error is safe; TS `crypto.getRandomValues`, chunked at 64 KiB. Key pairs, IDs, nonces and idempotency keys all come from these.
- **Padding and metadata** match the documents: items in 256-byte buckets, meta in 64-byte buckets, wraps of fixed size. The backup blob is unpadded (it is in the user's hands). Counts, `updated_by`, `updated_at`, versions and the sharing graph are visible to the server, as the threat model says.
- **Deterministic and unsafe functions** are not reachable from production paths in either language today (details in finding 17).

## Not assessed

- **Go CLI session logic** (`internal/client`, `cmd/fvault`): out of scope. Findings 1–3, 5–7 are protocol-level and apply to it unless it adds the checks above. Node-URL handling there (finding 15) matters more, because there is no CSP.
- **End-to-end proofs** of findings 1–3 against the fake server: not completed in this run.
- **Server-side enforcement** beyond reading `validate.go` and the CSP construction.
- **Libraries:** the internals of `hash-wasm` and `@noble/*` (trusted via the published vectors).
- **Real-browser behaviour:** the CSP, the service-worker lifecycle and IndexedDB were not run in a browser.
