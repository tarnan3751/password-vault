# Threat model

What Family Vault protects, from whom, and where it deliberately stops.

## Assets

1. **Vault contents**: every field of every entry (name, URL, username,
   password, notes, TOTP seeds, custom fields) and vault names.
2. **Master passwords** and the keys derived from them.
3. **Availability and durability** of the vault.

## Trust boundaries

| Party                         | Trusted for                                             | Not trusted for                    |
|-------------------------------|----------------------------------------------------------|------------------------------------|
| Your unlocked device + client | everything                                               | —                                  |
| The three servers             | availability, storing and replicating bytes, access control between users | confidentiality or integrity of vault contents |
| The network                   | nothing (TLS everywhere)                                 |                                    |
| Other household members       | the vaults you share with them                           | your other vaults                  |
| The household admin           | inviting/disabling users, running servers                | reading anyone's vaults            |

The **admin** is whoever operates the servers. Being admin grants no
cryptographic access to other people's vaults, but an admin can download a
server backup and can run a modified server, so everything said below about a
compromised server applies to an admin who chooses to attack.

## What an attacker gets

### Someone who steals a copy of a server's data (disk, backup file, state dump)

They obtain: usernames; the member list and roles of every vault; public
keys; ciphertext sizes, counts and modification times; for every user the
Argon2id password verifier, KDF salt, wrapped account key and encrypted
private key; invite hashes; TLS private keys of that node. (An admin backup
contains all of this except the token-signing key. Treat backup files like the
server's disk.)

They do **not** obtain any entry content, vault name, vault key, account key,
private key or encryption key: every secret was sealed on a client with
XChaCha20-Poly1305 under keys the server never had.

What it enables is **offline guessing of master passwords**. One guess costs
one Argon2id evaluation at the client parameters (64 MiB, 3 passes, never
less), checked against the wrapped account key. Nothing else stands between
that data and the vault, so the master password must be strong; nothing can
save a weak one.

### Someone who controls a running server (an active, malicious node)

Everything above, plus the ability to lie in every answer the node gives.
The clients are built on the assumption that it will:

* **It cannot make a client use a weak KDF.** Clients refuse parameters below
  the defaults, and refuse parameters weaker than the ones they have cached.
  The Argon2 salt is bound to the username, so one precomputed dictionary
  cannot serve several users.
* **It captures the login key of anyone who logs in through it** (it
  terminates TLS). With that it can authenticate as the user to the other
  nodes (and fetch ciphertext it already has) and it can test password guesses
  offline at one full-strength Argon2id evaluation each — the same guessing
  attack as with a stolen disk, nothing more. The login key and the
  encryption key are independent HKDF outputs: the login key decrypts nothing.
* **It cannot add itself, or anyone, to a vault.** A vault's member list, with
  each member's public key, is sealed under the vault key (the *roster*), so
  only someone who already holds the key can write it. A client wraps a new
  key only for roster members that the person at the device has verified.
* **It cannot hand a client a vault key of its choosing.** A wrapped key is
  accepted only if it was produced by the user's own key pair, by an owner
  already recorded for that vault, or by a contact the user has verified;
  anything else is shown as "pending" and stays closed until the user compares
  the sender's fingerprint. A key the device generated itself (a new vault, a
  rekey, a backup restore) is never replaced by one the server returns.
* **It cannot substitute a public key unnoticed** once a device has seen the
  real one: contacts are pinned as (user ID, username, key) and any change is
  a permanent, prominent warning that blocks sharing with that user.
  Fingerprints cover the user ID and username as well as the key.
* **It can roll back, withhold or delete data, and refuse service.**
  Ciphertexts are bound to their vault, entry and key epoch, so they cannot be
  forged or moved, but freshness is not authenticated: a node can serve an old
  version of an entry or hide a new one. A device that has already seen a
  newer key epoch of a vault refuses an older one. A **brand-new device**
  cannot tell: a malicious node can show it the state from before a member was
  removed, and new entries written from that device would be readable by the
  removed member *if that member is cooperating with the node*.
* **It can serve a tampered web client.** The browser app is delivered by the
  servers; a malicious node can ship JavaScript that steals the master
  password the next time it is typed. This is inherent to any web-delivered
  client. The Content-Security-Policy only stops script injected from
  elsewhere. The `fvault` CLI never loads code from a server; use it if you do
  not want to trust the node you are connecting to.

**What this relies on from you:** verify a family member's fingerprint with
them, in person or over a channel you trust, the first time each of your
devices shares with them or opens something they shared. The clients ask for
exactly that and will not proceed on an unverified key.

### A network attacker

Sees TLS traffic only. Clients verify server certificates (the household CA,
which is name-constrained to the cluster's own host names, or a public one);
nodes authenticate each other with mutual TLS and check that the certificate's
node ID matches the claimed sender of every Raft message. An attacker who can
drop or delay traffic can cause unavailability, never inconsistency: Raft's
safety does not depend on timing.

A node that is **cut off from the others** keeps serving explicitly-stale
reads from the data it has, including to a password or session that was
revoked elsewhere after the cut, for at most the stale-read window (7 days by
default). Nothing newer than the cut is exposed. Writes and normal
(linearizable) reads are refused on such a node.

### Someone with your locked or powered-off device

Finds the offline cache: the same ciphertext a server has, your KDF salt and
wrapped account key, which allows the same offline guessing as a stolen
server disk. The device's trust store (verified contacts, accepted vault
keys) is sealed under a key derived from the account key, so it cannot be
edited to plant a trusted contact; deleting it only makes the client ask for
fingerprints again. The CLI's files are mode 0600. Keys are in memory only
while unlocked.

### Someone with your unlocked, running device, or malware on it

Out of scope. They can read whatever you can.

### Someone who learned your master password

Changing the password stops the old one from logging in, and each of your
devices stops accepting it offline once it has synced. It does **not** re-key
your account: someone who knew the old password and also holds an *old copy*
of your wrapped account key (from a server's disk or backup, or another
device's cache) can still recover your private key, and with it every vault
key ever wrapped for you, including future ones. If a master password may
have leaked to someone who could also have had server or device data, the
remedy today is a new account (new key pair), re-sharing, and changing the
stored passwords that matter. Key rotation is future work.

### A household member removed from a shared vault

Keeps whatever they already saw: assume every password in that vault is
known to them and change the ones that matter. Removing a member *is* a rekey:
one atomic operation drops them, installs a new key for everyone else and
re-encrypts everything, so ciphertext written afterwards is useless to them.

Limits: a member who merely *leaves* (or is cut off by the server-side
"revoke now" action) still holds the current key until an owner rekeys, and
the clients keep saying so. A removed member who cooperates with a malicious
node can benefit from the rollback described above on devices that never saw
the new key.

### A malicious household member

Can read and (if editor/owner) change or delete entries in vaults shared with
them; entry history inside an item is client-maintained and can be rewritten
by an editor. Cannot read vaults they are not a member of. Any member holds
the vault key and can therefore write a roster; the server only lets owners
do so, and a client will not wrap a key for a roster entry its user has not
verified, so a member cannot smuggle in a recipient without a compromised
server *and* the owner verifying a stranger's fingerprint.

Can also be a nuisance: fill a vault up to its storage quota, or repeatedly
fail logins for another username to lock that user out of *online* login on a
node for a few minutes (offline unlock is unaffected).

## Availability and durability

* Any one of the three servers can be lost, permanently, with no data loss
  and no interruption: a write is acknowledged only after two servers have
  fsynced it. Storage quotas keep the whole replicated state small enough to
  be shipped to a replacement node in one piece.
* With two servers down, nothing can be written. The survivor still serves
  explicitly-stale reads (within the stale-read window), and every client can
  read its offline cache.
* If two servers lose their disks at the same time, acknowledged writes can
  be lost. Protect against that with backups: automatic local state dumps on
  every node, `fvault admin backup` (the whole replicated state), and each
  user's own `fvault export` (self-contained, encrypted under a passphrase).
* A server that returns with an **empty disk under its old node ID** has
  forgotten its promises (votes, acknowledged entries). This is safe only if
  the other two nodes are healthy and connected while it rejoins; see
  docs/OPERATIONS.md. Cluster membership changes are not implemented.
* A Raft implementation bug could lose or corrupt replicated data without
  ever exposing a secret; that is why the consensus layer is tested with
  deterministic simulation and Porcupine, and why backups exist anyway.

## Known limitations

* The login key is sent to the server on every login (inside TLS) rather than
  proven with an augmented PAKE such as OPAQUE, so a node you log in to can
  mount offline guessing against your password.
* Account keys and key pairs never rotate; changing the master password does
  not revoke a compromised one (see above).
* No protection against rollback by a malicious server beyond what each
  device remembers; a new device starts with no memory.
* Verification is per device: each new device asks for fingerprints again.
  (The trust store is not yet synchronized between a user's devices.)
* A vault's roster is authenticated by the vault key, not by signatures, so
  it is only as trustworthy as the vault's current members.
* Metadata is visible to servers: usernames, sharing graph, sizes, timing.
  Entry sizes are padded to 256-byte buckets, which blurs but does not hide
  them.
* Forgotten master password = lost personal vault. Shared vaults remain
  available to their other members.
* Password normalization (NFKC) depends on the Unicode version of the
  runtime; a master password using very recently assigned characters could
  derive different keys in an old browser. Prefer a passphrase of ordinary
  words.
* Secrets in process memory are zeroed on a best-effort basis only (Go and
  JavaScript are garbage collected), and the system clipboard is shared with
  other applications.
* Rate limiting of login attempts is per node and in memory.
* The code has not been audited by a third party. An internal review of the
  client-side protocol was cut short before its findings were reproduced end
  to end; see docs/REVIEW_NOTES.md.
