# Crypto specification (suite `fpv/v1`)

This is the normative description of everything the **clients** do
cryptographically. The Go implementation (`internal/vaultcrypto`) and the
browser implementation (`web/src/crypto`) must both follow it byte for byte;
`testvectors/crypto-v1.json` proves that they agree.

The servers perform no vault cryptography at all. They store what is described
here as opaque bytes.

## 1. Primitives and encodings

| Purpose            | Primitive                                              |
|--------------------|--------------------------------------------------------|
| Password KDF       | Argon2id v1.3 (RFC 9106)                               |
| Key derivation     | HKDF-SHA-256 (RFC 5869), extract-then-expand           |
| AEAD               | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag)        |
| Key agreement      | X25519 (RFC 7748)                                      |
| Hash               | SHA-256                                                |
| Randomness         | OS CSPRNG (`crypto/rand`, `crypto.getRandomValues`)    |

* Binary values inside JSON: **standard base64 with padding** (RFC 4648 §4).
* IDs (user, vault, item): 16 random bytes as **32 lowercase hex characters**.
* IDs that are interpolated into AAD strings must be well-formed (32 lowercase
  hex characters), which also rules out any ambiguity around `|`; key epochs
  are integers >= 1.
* All "info"/AAD strings below are ASCII/UTF-8 with no terminator. `|` is a
  literal separator. Numbers inside AAD strings are base-10 with no padding.
* Usernames: trimmed, lower-cased, must match `^[a-z0-9][a-z0-9._-]{0,31}$`.
  Trimming removes only ASCII whitespace (space, `\t`, `\n`, `\v`, `\f`, `\r`);
  any non-ASCII character makes the name invalid (checked before lower-casing,
  so Unicode case-mapping differences between languages cannot matter).
* Passwords: Unicode **NFKC**-normalized, then UTF-8 encoded. No trimming.

## 2. Keys derived from the master password

```
argonSalt = SHA-256(utf8("fpv/v1/kdf-salt|" + username + "|") || salt)      # 32 bytes
MK        = Argon2id(password, argonSalt, t, m, p, outLen = 32)
encKey    = HKDF-SHA256(ikm = MK, salt = <empty>, info = "fpv/v1/enc-key",   L = 32)
loginKey  = HKDF-SHA256(ikm = MK, salt = <empty>, info = "fpv/v1/login-key", L = 32)
```

* `salt` is 16 random bytes chosen by the client at registration (and again at
  every password change). It is stored by the server and returned by
  `POST /v1/prelogin`.
* `username` is the normalized username (§1). Mixing it into the Argon2 salt
  means a server cannot make every user derive keys under one salt of its
  choosing (which would let a single precomputed dictionary serve all of
  them).
* Default parameters: `t = 3`, `m = 65536` KiB (64 MiB), `p = 4`
  (RFC 9106 second recommended option).
* **Parameters a client will accept:** `alg == "argon2id"`, `len(salt) >= 16`
  (and `<= 64`), `65536 <= m <= 262144`, `3 <= t <= 8`, `1 <= p <= 16`. A
  client must refuse to derive keys with anything else. The floor is the
  default: a malicious server could otherwise hand out weak parameters and
  brute-force the resulting login key cheaply. The ceiling stops a server (or
  a hostile backup file) from freezing a phone with a 16 GiB request.
* A device that holds cached account data for the user must additionally
  refuse prelogin parameters with a smaller `m` or `t` than the cached ones.
* Implementations expose a separate, clearly named function without these
  checks for test vectors only.
* `encKey` **never leaves the device** and is never written to disk.
* `loginKey` is sent to the server over TLS at registration and login. The
  server stores only `Argon2id(loginKey, serverSalt)`; see api.md §3. Anyone
  who captures a `loginKey` (a compromised node that the user logs in to) can
  test password guesses against it offline, at one client-strength Argon2id
  evaluation per guess.

## 3. The AEAD box format

Every ciphertext produced under a symmetric key uses one format:

```
box = 0x01 || nonce (24 bytes) || XChaCha20-Poly1305(key, nonce, plaintext, aad)
```

* `0x01` is the format version. Decryption rejects any other value.
* `nonce` is 24 fresh random bytes per encryption.
* The trailing 16 bytes of the AEAD output are the Poly1305 tag.
* Minimum length of a valid box: 1 + 24 + 16 = 41 bytes.
* Decryption failure (bad version, short input, tag mismatch) is a single
  undifferentiated error.

API shape (both languages): `seal(key, plaintext, aad) -> box`,
`open(key, box, aad) -> plaintext`, plus `sealWithNonce(key, nonce, plaintext,
aad)` used **only** to produce and check deterministic test vectors.

## 4. Account keys

Created by the client at registration:

| Value               | Definition                                                                 |
|---------------------|----------------------------------------------------------------------------|
| `userID`            | random ID                                                                  |
| `accountKey`        | 32 random bytes                                                            |
| `privateKey`        | 32 random bytes (X25519 scalar, used as-is; clamping is done by X25519)    |
| `publicKey`         | `X25519(privateKey, basepoint)`                                            |
| `wrappedAccountKey` | `seal(encKey, accountKey, aad = "fpv/v1/account-key\|" + userID)`          |
| `encPrivateKey`     | `seal(accountKey, privateKey, aad = "fpv/v1/private-key\|" + userID)`      |

`publicKey`, `wrappedAccountKey` and `encPrivateKey` are uploaded.

**Unlocking** (online or offline): derive `encKey` from the password and the
stored KDF parameters, `open` `wrappedAccountKey` (success here *is* the
offline password check), then `open` `encPrivateKey`. A client must verify that
`X25519(privateKey, basepoint)` equals the account's `publicKey`.

**The client's own identity is what it unlocked, never what a server says.**
After unlocking, the client knows its own `userID`, username (the one the user
typed, normalized) and `publicKey`. It must check that the account block of
every sync response carries exactly these three values, and that its own entry
in the directory does too; any difference is a hard error. Whenever a
computation needs "my public key" (for example unwrapping a key whose sender is
the user themself), the unlocked key is used, not a directory lookup.

**Changing the master password**: pick a new salt, derive new `encKey'` and
`loginKey'`, upload `wrappedAccountKey' = seal(encKey', accountKey, ...)`.
`accountKey` and the key pair do not change, so nothing else is re-encrypted.
Before discarding `encKey'` the client syncs and verifies that the account
block now opens with it, then replaces the cached account block so that the
old password no longer unlocks this device offline.

Changing the password stops the old password from logging in. It does **not**
re-key anything: someone who knew the old password *and* holds an old copy of
`wrappedAccountKey` (from a server, a server backup or another device's cache)
can still recover `accountKey` and the private key. Rotating those is future
work; see THREAT_MODEL.md.

## 5. Vaults and items

Each vault has a random 32-byte **vault key** `VK` and a **key epoch**
(starts at 1, incremented by every rekey; each epoch has an unrelated `VK`).

```
encMeta   = seal(VK, pad(metaJSON, 64),  aad = "fpv/v1/vault-meta|" + vaultID + "|" + keyEpoch)
itemBlob  = seal(VK, pad(itemJSON, 256), aad = "fpv/v1/item|" + vaultID + "|" + itemID + "|" + keyEpoch)
encRoster = seal(VK, rosterJSON,         aad = "fpv/v1/roster|" + vaultID + "|" + keyEpoch)
```

(`encRoster` is the authenticated member list; see §6.3.)

`pad(x, n)` appends ASCII spaces (0x20) until the length is a non-zero
multiple of `n` (a non-empty input already a multiple of `n` is left
unchanged; the empty input becomes `n` spaces). JSON
parsers ignore the trailing whitespace; the padding hides exact lengths.

### 5.1 Vault metadata JSON

```json
{"v": 1, "name": "Family"}
```

As with items (§5.2), a client that rewrites the metadata (a rename) must
preserve top-level members it does not understand, byte for byte.

### 5.2 Item JSON

```json
{
  "v": 1,
  "type": "login",
  "name": "Example Bank",
  "username": "alice@example.com",
  "password": "correct horse battery staple",
  "urls": ["https://bank.example.com/login"],
  "notes": "free text",
  "totp": "otpauth://totp/...",
  "fields": [{"name": "PIN", "value": "1234", "hidden": true}],
  "tags": ["finance"],
  "created_at": 1767225600000,
  "updated_at": 1767225600000,
  "password_history": [{"password": "old one", "changed_at": 1767000000000}]
}
```

* `type` is `"login"` or `"note"`. Only `v`, `type` and `name` are required;
  absent fields are treated as empty.
* Times are Unix milliseconds.
* When the password of an existing item changes, the client prepends the old
  password to `password_history` (keep at most 10).
* **Forward compatibility:** a client that edits an item must preserve any
  top-level fields it does not understand, **byte for byte** (the raw JSON
  text of the member's value is carried over, so numbers beyond 2^53 or with
  unusual spellings survive an edit in either client).

### 5.3 Decoding rules (both clients must behave identically)

The plaintext of a meta, item or roster box is decoded under these rules, and
anything that violates them is "unreadable" (it is shown as such, never
guessed at):

* The plaintext must be valid UTF-8 and, after removing trailing ASCII
  whitespace, a single JSON object.
* Member names are matched **exactly** (case-sensitively). `"Name"` is an
  unknown member, not `name`. If a known name appears more than once the
  document is invalid.
* Known members must have exactly the specified JSON type. `null` is not
  accepted in place of a string, number, boolean, array or object, nor as an
  array element.
* Integers (`v`, `created_at`, `updated_at`, `changed_at`) must be written as
  JSON integers (no fraction, no exponent) in the range 0 .. 2^53 − 1.
* `v` must be `1`; an item's `type` must be `"login"` or `"note"`; a vault's
  and an item's `name` must be present (it may be empty).
* Inside `fields[]` and `password_history[]` entries, unknown members are
  ignored and dropped on edit; the known ones follow the rules above.

Precisions (they settle points the rules above leave open; both clients
implement them identically and `testvectors/` pins them):

* "ASCII whitespace" around the object means JSON whitespace: space, TAB, LF,
  CR. Leading whitespace is allowed too. Any other trailing byte (including
  NUL and form feed) makes the document invalid.
* A `\u` escape that denotes a lone surrogate is invalid anywhere in the
  document (in member names and in values, known or unknown).
* An integer is `0` or a non-zero digit followed by digits; `-0`, any minus
  sign, leading zeros, fractions and exponents are all invalid for the integer
  members listed above. Unknown members may hold any valid JSON value.
* Nesting depth is not limited.
* Roster `pk` is standard padded base64 with no whitespace and zero trailing
  bits; the roster decoder ignores unknown members (top level and inside
  entries) and rejects a roster that violates the §6.3 invariants.
* The client's own re-encoding (after an edit) is specified in
  `testvectors/README.md` ("Canonical encoding"); the bytes of unknown members
  are copied from the original text, in their original order, after the known
  members.

Being unreadable never blocks maintenance: a rekey re-encrypts the **raw
plaintext bytes** of every box that opens, without parsing them, and carries a
box that does not open under the current key over unchanged (it was garbage
and stays garbage). Clients let a member with write access delete an
unreadable entry.

The AAD binds each blob to its vault, item ID and key epoch, so a server
cannot move a ciphertext to a different item, vault or epoch without
detection. (It *can* roll an item back to an older ciphertext of the same item
within an epoch; see THREAT_MODEL.md.)

## 6. Wrapping a vault key for a member (authenticated ECIES)

Sharing gives every member their own copy of `VK`, encrypted to their public
key and authenticated by the sharer's key pair.

Inputs: sender key pair `(skS, pkS)` and `senderID`; recipient `pkR` and
`recipientID`; `vaultID`, `keyEpoch`; the 32-byte `VK`.

```
(skE, pkE) = fresh X25519 key pair (32 random bytes -> scalar)
dh1   = X25519(skE, pkR)            # ephemeral-static: forward secrecy for the sender
dh2   = X25519(skS, pkR)            # static-static: authenticates the sender
key   = HKDF-SHA256(ikm  = dh1 || dh2,
                    salt = pkE || pkS || pkR,          # 96 bytes
                    info = "fpv/v1/vault-key-wrap",
                    L    = 32)
nonce = 24 random bytes
aad   = "fpv/v1/vault-key|" + vaultID + "|" + keyEpoch + "|" + senderID + "|" + recipientID
ct    = XChaCha20-Poly1305(key, nonce, VK, aad)       # 32 + 16 bytes

wrap  = 0x01 || pkE (32) || nonce (24) || ct (48)     # 105 bytes total
```

Unwrapping: the recipient computes `dh1 = X25519(skR, pkE)` and
`dh2 = X25519(skR, pkS)` and proceeds identically. Which `pkS` may be used for
a given `sender_id`, and whether the result may be trusted, is governed by
§6.4; it is never simply "whatever the directory says".

* Either side must reject an all-zero X25519 output (low-order point).
* A user wraps their own vault keys the same way (`sender == recipient`).
* The result must be exactly 32 bytes; the wrap must be exactly 105 bytes.
* The deterministic variant taking `skE` and `nonce` as inputs exists only for
  test vectors.

### 6.1 Why the rest of this section exists

The server stores and hands out three things a client cannot take on faith:
the **directory** (who has which public key), each vault's **member list**,
and each member's **wrapped key together with the ID of its sender**. A server
that lies about any of them must not be able to obtain a vault key, or to make
a client encrypt under a key the server knows. The wrap of §6 proves *which
key pair* produced a wrapped key; the rules below settle *whose* key pair that
is allowed to be, and for whom a client is willing to wrap.

Two ideas carry it:

* **Verified contacts.** A user's key is trusted on a device only after the
  person using that device has compared its fingerprint with its owner (§6.2).
  Nothing is ever trusted merely because the server listed it.
* **The roster.** Each vault carries its member list, with every member's
  public key and role, encrypted under the vault key (§6.3). Only someone who
  already holds the vault key can write it, so the server cannot add a
  recipient.

### 6.2 Fingerprints, contacts and the local trust store

**Fingerprint** of a user:

```
fp = SHA-256(utf8("fpv/v1/fingerprint|" + userID + "|" + username + "|") || publicKey)
```

the first 16 bytes, as 32 lowercase hex characters in groups of four separated
by `-` (for example `3f9a-01bc-77de-4410-aa02-9c1e-55d0-0b7f`). It covers the
user ID and username as well as the key, so a matching fingerprint means "this
name, this account, this key".

**Directory validation.** Before using a sync response a client checks every
directory entry: well-formed user ID, username matching the §1 pattern, a
32-byte public key, no user ID and no username appearing twice. Vault IDs and
item IDs are checked for format and uniqueness the same way. A response that
fails is rejected as a whole.

**The local trust store.** Per account and per device, a client keeps:

* `contacts`: for every user it has seen, the triple `(userID, username,
  publicKey)` and a `verified` flag. The triple never changes: if a later
  directory shows the same user ID with a different key or username, or a
  known username under a different user ID, that is a **key mismatch**: the
  client records the event permanently, shows a prominent warning that stays
  until the user dismisses it knowingly, and refuses to wrap for, or accept a
  key from, the user concerned. There is deliberately no "accept the new key"
  button in v1 (key pairs never change).
* `verified` becomes true only by an explicit act of the person at the device:
  they are shown the fingerprint and confirm having compared it with its
  owner.
* `vaults`: per vault, the highest key epoch accepted, a commitment to that
  epoch's key, `SHA-256(utf8("fpv/v1/vault-key-commit|" + vaultID + "|" +
  keyEpoch + "|") || VK)`, and the owners (ID and public key) listed in the
  last roster accepted for it.
* the highest `rev` of any sync response it has stored.

The store is sealed, so that someone holding the locked device cannot edit it:

```
trustKey = HKDF-SHA256(ikm = accountKey, salt = <empty>, info = "fpv/v1/local-trust-key", L = 32)
blob     = seal(trustKey, trustJSON, aad = "fpv/v1/local-trust|" + userID)
```

If it is missing or does not open, the client starts from an empty store (and
says so): every contact is unverified again, which is safe.

### 6.3 The roster

```json
{"v": 1, "members": [{"id": "<userID>", "pk": "<base64 X25519>", "role": "owner"}]}
```

`members` is sorted by `id`; `role` is `owner`, `editor` or `viewer`; there is
at least one owner. It is sealed as `encRoster` (§5) under the vault key and
bound to the vault and key epoch.

* The creator of a vault writes the first roster: themself, as owner.
* An owner who adds a member or changes a role uploads the new roster in the
  same request (compare-and-swap on the roster version, so two owners cannot
  silently overwrite each other).
* A rekey writes the roster of the new epoch.
* An owner removes a member **by rekeying**: one atomic request removes the
  member, installs the new key for everyone else and writes a roster without
  them (§6.6), so there is no moment at which the member is "removed" but the
  old key and old roster are still current.
* A member who leaves on their own just asks the server to drop them. The
  roster still lists them until an owner next rekeys; the server sets
  `rekey_recommended` to prompt that.

A client decrypts the roster of every vault it accepts (§6.4) and requires
that it lists the client's own user ID with its own public key. The roster's
public keys are *the* keys of that vault's members: a roster entry that
disagrees with the trust store's triple for that user is a key mismatch. The
member list shown to the user is the roster; where the server's list differs
the difference is displayed ("left: will lose access at the next rekey",
"listed by the server but not in the roster: ignored").

### 6.4 Accepting a vault key

For each vault in a sync response, with `S = my_key.sender_id`:

1. **Personal vault:** `S` must be the user themself. Anything else is a hard
   error.
2. **`S` is the user themself:** unwrap with the user's own unlocked public
   key as the sender key. Only the holder of the user's private key can have
   produced such a wrap.
3. **`S` is someone else:** the wrap is opened with `S`'s public key from the
   trust store (which, on first sight, comes from the directory), and the
   resulting key is **used only if** one of these holds:
   * the trust store already holds this vault at this epoch with a matching
     key commitment (nothing changed);
   * the trust store holds this vault at a lower epoch and `S` is an owner in
     the roster stored for it, with that same public key (a legitimate rekey
     by a known owner);
   * `S` is a verified contact **and** this device has never accepted the
     vault before (a new share from someone the user has verified).

   Otherwise the vault is **pending**: its contents are not decrypted and
   nothing is written to it. The client shows "shared by `S` — compare this
   fingerprint to open it"; confirming verifies `S` and accepts the vault.
   If the device had accepted the vault before and `S` was not one of its
   owners then, the client says so plainly ("the key of this vault was
   replaced by `S`, who was not an owner when this device last saw it") and
   asks the user to check with `S` before accepting.
4. **Continuity.** A vault offered at a lower epoch than the trust store has
   accepted, or at the same epoch with a different key commitment, is a hard
   error (the vault is shown locked, with a warning), never silently accepted.
5. After accepting, the client records the epoch, the key commitment and the
   roster's owners.

**A key this device generated is never replaced by one the server returns.**
When a client creates a vault (including during backup import) or rekeys one,
it records the epoch and key commitment in the trust store *before* sending
the request and keeps using its own key; a later sync that offers a different
key for that vault and epoch fails rule 4.

**Deliberate recovery.** When the servers have been restored from a backup
they legitimately present an older state: a lower `rev`, and possibly an older
key epoch for some vaults. A client cannot tell this from a rollback, so it
does not decide. It stops using the server's answers (the offline cache stays
readable), says that the servers are showing older data than this device has
seen, that this is expected only after the administrator restored a backup,
and offers one explicit action: *accept the restored state*. Accepting clears
the stored highest `rev` and the per-vault records (epoch, commitment,
owners) — never the contacts, their verified flags, or the recorded
key-mismatch events — and replaces the offline cache. Every vault is then
evaluated again under the rules above as if this device had not seen it
before, so keys from the user themself and from verified contacts are
accepted and the rest become pending. The action is never taken
automatically and never offered for a key mismatch.

### 6.5 Adding a member

An owner adds user `X` only if `X` is a verified contact on the owner's device
(the client asks for the fingerprint comparison if not). The vault key is
wrapped to `X`'s public key **from the trust store**, and the new roster (the
current, authenticated roster plus `X`) is uploaded in the same request.

### 6.6 Rekeying

A rekey gives the vault a new, unrelated key (epoch + 1). It is what revokes a
removed member's access to future data. The owner's client:

1. Opens the current roster under the current key. The **recipients** are its
   members, minus anyone the owner is removing, minus anyone the server no
   longer lists as a member (they left or were removed earlier). Nobody else:
   if the server lists a member who is not in the roster, the client stops and
   warns. Recipients' public keys and roles are taken from the roster.

   Every recipient other than the owner themself must also be a **verified
   contact on this device**; if one is not, the client asks for the
   fingerprint comparison before continuing. (The roster is sealed under the
   vault key, which every current member holds. This check is what stops a
   member who is about to be removed from quietly adding a recipient that
   nobody has ever met.)
2. Generates `VK'`, records its commitment (§6.4), and under `VK'` and the new
   epoch seals: the metadata, every item, and the new roster. Each existing
   box that opens is re-encrypted from its **raw plaintext bytes** without
   parsing; a box that does not open under the current key is carried over
   unchanged (§5.3).
3. Wraps `VK'` for every recipient and submits everything, together with the
   list of members being removed, in one atomic `POST /v1/vaults/{id}/rekey`.

The UI shows the recipient list before the request is built. The server's
`rekey_recommended` flag is only a hint to display; it never triggers a rekey
by itself. A personal vault is never rekeyed for a "member".

**Roster repair.** If a vault's roster does not open or does not parse, an
owner may rebuild it through a rekey whose recipients are the server-listed
members, but only after confirming the list, and only if every one of them is
a verified contact on that device.

## 7. Encrypted export backups

A backup is a self-contained file that can be restored into any cluster, or
simply decrypted, with nothing but its passphrase.

```json
{
  "format": "fpv-backup",
  "version": 1,
  "created_at": 1767225600000,
  "kdf": {"alg": "argon2id", "salt": "<base64 16 bytes>", "time": 3, "memory_kib": 65536, "parallelism": 4},
  "blob": "<base64 box>"
}
```

```
BK        = Argon2id(passphrase (NFKC, UTF-8), kdf.salt, kdf.time, kdf.memory_kib, kdf.parallelism, 32)
backupKey = HKDF-SHA256(ikm = BK, salt = <empty>, info = "fpv/v1/backup-key", L = 32)
blob      = seal(backupKey, payloadJSON, aad = "fpv/v1/backup")
```

The same minimum-parameter rule as §2 applies when reading a backup.

Payload (plaintext JSON, UTF-8, not padded):

```json
{
  "v": 1,
  "exported_at": 1767225600000,
  "exported_by": "alice",
  "vaults": [
    {
      "id": "<original vault id>",
      "name": "Family",
      "personal": false,
      "items": [ {"id": "<original item id>", "item": { ...item JSON of §5.2... }} ]
    }
  ]
}
```

The passphrase may be the master password or (better) a separate one.

## 8. Test vectors

`testvectors/crypto-v1.json` (schema documented in `testvectors/README.md`)
contains, with fixed "random" inputs:

* published vectors for the primitives (RFC 9106 Argon2id, RFC 5869 HKDF,
  RFC 7748 X25519, the XChaCha20-Poly1305 draft vector), to prove each
  library is wired up correctly;
* master-key derivation and the two sub-keys, including a non-ASCII password
  that changes under NFKC;
* box seal/open, including tampered-ciphertext, wrong-AAD, wrong-version and
  truncated negatives;
* key-pair derivation, vault-key wrap/unwrap (with negatives: wrong sender
  key, wrong context, low-order ephemeral key), fingerprints;
* padding and item/meta/roster encryption, vault-key commitments, the local
  trust-store key, and the decoding rules of §5.3 (documents both clients
  must accept and documents both must reject);
* a full account scenario (password to every uploaded artifact);
* a complete backup file.

Both implementations must (a) reproduce every deterministic output exactly and
(b) reject every negative case.
