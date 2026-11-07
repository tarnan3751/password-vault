# Family Vault

A self-hosted password manager for a household. Three servers keep the vault
in sync with a from-scratch implementation of Raft, so any one of them can
die without anyone noticing, and the servers only ever store ciphertext.

```
       browser client                 fvault (CLI)
            |      all encryption happens here      |
            +---------------- HTTPS ----------------+
                              |
        +---------------------+---------------------+
        |                     |                     |
   vaultd "pi"  <--mTLS-->  vaultd "vps"  <--mTLS-->  vaultd "laptop"
        \_______________ Raft: a write is saved _______________/
                 once two of the three have fsynced it
```

* **Zero-knowledge servers.** The master password goes through Argon2id;
  the encryption key never leaves the device. Every entry, including its name
  and URL, is sealed with XChaCha20-Poly1305 before upload.
* **Sharing.** Each family member has a key pair; a shared vault's key is
  encrypted separately for each of them, and a vault opens only after the
  sender's key fingerprint has been compared in person.
* **Offline.** Both clients keep an encrypted copy, so passwords can be read
  with no server reachable. Saving needs a majority of the servers.
* **Evidence.** A deterministic Raft simulator, a fault-injection harness
  checked with Porcupine, crypto test vectors shared by the Go and browser
  clients, and encrypted backups as the safety net.

> New code with no independent audit; do not make it the only copy of your
> passwords. See [docs/REVIEW_NOTES.md](docs/REVIEW_NOTES.md).

## Try it

Needs Go 1.27+.

```sh
make build
scripts/dev-cluster.sh        # three servers on this machine; prints what to do next
```

Then open <http://127.0.0.1:8001/>, or in another terminal:

```sh
alias fv='bin/fvault --home /tmp/fvault-demo'
fv init --server http://127.0.0.1:8001 --insecure
fv register --username alice --bootstrap-token dev-bootstrap-token-0000
fv shell                      # unlock once, then: add --name Bank --generate, ls, get Bank --show
```

Kill one of the three `vaultd` processes and keep going; kill a second and
both clients drop to read-only. `make test` runs everything; `make help`
lists the rest.

## Docs

| | |
|---|---|
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running it on three real machines: certificates, first user, backups, what to do when a machine dies |
| [docs/DESIGN.md](docs/DESIGN.md) | How it is built, and the test and benchmark results |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What a compromised server can and cannot do |
| [docs/spec/crypto.md](docs/spec/crypto.md), [docs/spec/api.md](docs/spec/api.md) | The client crypto and the HTTP API, normative |
| [docs/REVIEW_NOTES.md](docs/REVIEW_NOTES.md) | Review findings, what was done about them, what is still open |

Not implemented: changing the cluster's membership at runtime, rotating a
user's keys, TOTP code generation, browser autofill, mobile apps.
