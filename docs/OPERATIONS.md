# Operating a Family Vault cluster

This guide is for the person who runs the servers. To just try the software
on one computer, the README's "Try it" section is enough.

Setting up a household takes five steps, each a section below:

1. Pick three machines that can reach each other (§1).
2. Build the programs (§2).
3. Run `vaultd init-cluster` once; copy one directory to each machine and
   start `vaultd` there (§3).
4. Install the household's CA certificate on the family's devices (§4).
5. Create the first account, then invite everyone else (§5).

After that: what to do when a machine dies (§7), backups (§9), and every
configuration setting (§10).

## 1. What you need

* **Three machines** that stay on: for example a Raspberry Pi at home, a small
  cloud VPS and an old laptop. Any one of them can fail without anyone
  noticing; two failing at once makes the vault read-only until one returns.
* **A network on which all three can reach each other** on the peer port
  (8444 by default), in both directions. Machines behind home routers cannot
  normally be reached from a VPS, so the simplest setup is a private overlay
  network (WireGuard, Tailscale or similar) with stable names such as
  `pi.vault.internal`. Clients (phones, laptops) need to reach the client port
  (8443) of at least two servers to save, and of one server to read.
* **Clocks roughly right** (NTP). Consensus never depends on clocks, but
  certificate validity, token expiry and invite expiry do.

## 2. Build

```sh
make build        # bin/vaultd, bin/fvault, bin/vault-chaos for this machine
make cross        # bin/linux-arm64 (Raspberry Pi) and bin/linux-amd64 (VPS)
```

The browser client is already compiled into `vaultd` (from `web/dist`).
Node.js is only needed to change it (`make web`).

## 3. Create the cluster

On a trusted computer:

```sh
vaultd init-cluster --out cluster \
  --node pi=pi.vault.internal \
  --node vps=vps.vault.internal \
  --node laptop=laptop.vault.internal
```

A node may list several names or addresses (`--node pi=pi.vault.internal,192.168.1.10`);
the first is used in URLs. The command prints what to do next, including the
bootstrap token, and writes:

| Path                         | What it is                                                   |
|------------------------------|--------------------------------------------------------------|
| `cluster/ca.pem`             | The household CA certificate. Install it on every device that will use the vault. |
| `cluster/ca-key.pem`         | The CA's private key. **Move it offline** (a USB stick in a drawer). It is needed only to issue or renew node certificates. |
| `cluster/<node>/`            | Everything one node needs: `config.json`, its certificate and key, `ca.pem`, and the bootstrap token. |

The CA is *name-constrained*: it can only vouch for the node names and
addresses you listed, so installing `ca.pem` on a phone does not let its
holder impersonate other websites. The flip side is that a node cannot later
move to a name the CA does not cover. Use `--permit vault.internal` at this
step if you want the CA to cover a whole domain you control.

Copy each `cluster/<node>/` directory to its machine (for example to
`/etc/vaultd`), set `data_dir` in its `config.json` to where the data should
live, and start it:

```sh
vaultd run --config /etc/vaultd/config.json
```

`deploy/vaultd.service` is a systemd unit for this. The nodes find each other,
elect a leader and are ready within a couple of seconds:

```sh
curl --cacert ca.pem https://pi.vault.internal:8443/v1/health
```

## 4. Install the CA certificate

The servers' certificates are signed by your own household CA, which no
device knows yet. Until `ca.pem` is installed, browsers show a certificate
warning. Installing it is safe in a way most private CAs are not: this one
can vouch only for your servers' names (§3).

`fvault` needs no installation: `fvault init --ca ca.pem` is enough.

For browsers, these are the usual steps (menu names move between OS
versions; none of them has been tested as part of this project):

| Device | Steps |
|--------|-------|
| Mac (Safari, Chrome) | Double-click `ca.pem` to add it to Keychain Access, open the certificate there, expand *Trust* and set *When using this certificate* to *Always Trust*. |
| iPhone, iPad | Send yourself the file (AirDrop, email) and open it, then *Settings → General → VPN & Device Management* to install the profile, then *Settings → General → About → Certificate Trust Settings* to switch on full trust. |
| Android | *Settings → Security → Encryption & credentials → Install a certificate → CA certificate*. |
| Windows (Edge, Chrome) | Rename the file to `ca.crt`, double-click it, *Install Certificate → Current User → Place all certificates in the following store → Trusted Root Certification Authorities*. |
| Linux | Chrome and Firefox keep their own lists: import it under *Settings → Certificates → Authorities*. |
| Firefox (any system) | *Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import*, and tick *Trust this CA to identify websites*. |

If you would rather not install anything on anyone's device, give the
client-facing port a publicly trusted certificate instead (§8).

## 5. First user, then the family

`init-cluster` printed a **bootstrap token**: a one-time setup code, also
stored in each node's `bootstrap-token` file. The first account registered
with it becomes the household administrator:

```sh
fvault init --server https://pi.vault.internal:8443 --ca ca.pem
fvault register --username alice        # asks for the token, then for a master password
```

or open `https://pi.vault.internal:8443/` in a browser and choose *First-time
setup*.

The master password must have at least 12 characters, must not contain the
username, and must not be a repeated pattern, a simple run such as
`abcdefghijkl`, or one of the very common passwords. Four or more unrelated
words make a good one. **It cannot be recovered or reset by anyone**, the
administrator included.

Then **delete the `bootstrap-token` file on every node** (and restart them):
it is useless once a user exists, but there is no reason to keep it.

Everyone else joins with a single-use invite created by an administrator
(`fvault invite create`, or *Administration → Invites* in the browser).

When two people first share a vault, each client shows the other person's
**fingerprint** and asks you to compare it with them, in person or over a
call. Do it; it is the one step that keeps a compromised server from
inserting itself. See docs/THREAT_MODEL.md.

## 6. Day to day

```sh
fvault status          # which nodes are reachable, who leads, how old the offline copy is
fvault admin cluster   # per-node replication progress (admin)
journalctl -u vaultd   # server log; it never contains secrets
```

Each node writes a dump of the replicated state to `<data_dir>/backups` once a
day when something changed (14 are kept). See §9.

## 7. When things break

**One node is down.** Nothing to do. The other two keep serving reads and
writes; when the node comes back it catches up by itself.

**Two nodes are down.** Nothing can be saved, and both clients say so
("read-only"). People can still look passwords up: the surviving node keeps
showing the last copy it has, which may be out of date, for up to 7 days
(`stale_read_window_hours`), and every device can read its own offline copy.
Bring either node back and the cluster resumes on its own.

**A node lost its disk** (dead SD card, reinstalled machine). Its certificate
and config can be reused (re-issue the certificate with `vaultd issue-cert`
if the key was lost). **Before starting it with an empty data directory, make
sure the other two nodes are up and in sync** (`fvault admin cluster` shows a
leader and a follower with the same match index). Then start it: it receives a
snapshot and catches up.

Why the precaution: a node with an empty disk has forgotten what it voted for
and which entries it acknowledged. If it rejoins while one of the remaining
nodes is also unavailable or behind, the forgetful node and the lagging node
can together elect a leader that lacks recent writes. With both other nodes
healthy this cannot happen. (Proper membership changes, which would remove the
caveat, are not implemented.)

**A node's data is corrupt** (`vaultd` refuses to start and reports
corruption). Treat it as a lost disk: move the data directory aside and
follow the procedure above.

**Everything is lost, or the data is wrong** (two disks died together, or you
suspect a bug damaged the replicated state). Restore from a server backup:

1. Stop all three nodes. Move their data directories aside (do not delete
   them yet).
2. On **every** node, with the **same** backup file:
   `vaultd restore --config /etc/vaultd/config.json --from state-....json`
   and check that all three print the same state digest.
3. Start the nodes.

Everyone has to log in again (backups do not contain the key that signs
sessions). If only one or two nodes are restored, start the restored ones
first; never start a majority of empty nodes next to a restored one.

If anything was saved after the backup was taken, each device will then notice
that the servers show *older* data than it has seen and will refuse to
continue: from where it stands, that is exactly what an attack would look
like. Tell the family that you restored a backup and that they should choose
**Accept the restored state** (browser) or run
`fvault recover --accept-restored-state` (CLI), once per device. Entries saved
after the backup are gone from the servers; a device that had them cached can
still show them offline until it accepts, so copy anything important first.

## 8. Certificates

Node certificates are valid for 800 days. To renew one (or issue one for a
replaced machine), bring the CA key back from its drawer:

```sh
vaultd issue-cert --ca-dir cluster --node pi=pi.vault.internal --out cluster/pi
```

copy `node.pem` and `node-key.pem` to the node and restart it. The CA itself
is valid for 10 years.

If you would rather use publicly trusted certificates for the client-facing
port (so that nobody has to install `ca.pem`), set `tls.api_cert_file` and
`tls.api_key_file`; the household CA is then used only between the nodes.

## 9. Backups

There are three kinds, and you want at least the last two off the machines:

| Backup | Made by | Contains | Restored with |
|--------|---------|----------|---------------|
| Automatic state dump | every node, daily, in `<data_dir>/backups` | the whole replicated state | `vaultd restore` |
| Admin backup | `fvault admin backup --out FILE` | the same, on demand, from anywhere | `vaultd restore` |
| Personal export | each user: `fvault export --out FILE` (or *Account → Export* in the browser) | that user's vaults, decrypted and re-encrypted under a passphrase of their choice | `fvault import`, on any cluster |

State dumps and admin backups hold ciphertext plus every user's password
verifier and wrapped keys: nobody can read vault contents from them, but they
allow offline guessing of master passwords, so **guard them like the servers'
disks**. A personal export is protected only by its passphrase: choose a
strong one and keep it somewhere other than the vault.

A personal export is the backup that survives anything, including this
software. Make one occasionally.

## 10. Configuration reference (`config.json`)

| Key | Default | Meaning |
|-----|---------|---------|
| `node_id` | — | This node's ID; must appear in `peers`. Lower-case letters, digits, `-`. |
| `data_dir` | — | Where the Raft log, snapshots and backups live. Relative paths are relative to the config file. |
| `client_listen` | — | `host:port` of the HTTPS API and web client. |
| `peer_listen` | — | `host:port` of the node-to-node listener (mutual TLS). |
| `peers[]` | — | Every node, including this one: `id`, `peer_addr` (how the others reach its peer listener), `public_url` (how clients reach its API). Identical on all nodes. |
| `tls.ca_file`, `tls.cert_file`, `tls.key_file` | — | Household CA and this node's certificate and key. |
| `tls.api_cert_file`, `tls.api_key_file` | node certificate | Optional separate certificate for the client port. |
| `bootstrap_token_file` / `bootstrap_token` | none | Authorizes the first registration. Remove once a user exists. |
| `token_ttl_hours` | 12 | Lifetime of a session token. |
| `max_session_age_days` | 30 | How long a session can be refreshed before the master password is needed again. |
| `stale_read_window_hours` | 168 | How long a node cut off from the cluster keeps answering explicitly-stale reads. Negative disables them. |
| `trusted_proxy_header`, `trusted_proxies[]` | none | Only if a reverse proxy sits in front: the header carrying the client address, and the proxies allowed to set it. |
| `raft.tick_ms` | 100 | Length of one Raft tick. |
| `raft.election_ticks` | 10 | A follower starts an election after 10–20 ticks without a leader. |
| `raft.heartbeat_ticks` | 1 | Leader heartbeat interval. |
| `raft.snapshot_threshold` | 4096 | Log entries between snapshots. |
| `backup.interval_hours` | 24 | Interval of automatic state dumps; negative disables. |
| `backup.keep` | 14 | How many dumps to keep. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |
| `insecure` | false | Plain HTTP on both listeners. Only accepted on loopback addresses; for development. |

Unknown keys are rejected, so a typo cannot silently disable a setting.

**Slow disks and slow links.** A write is acknowledged after two nodes have
fsynced it, so it is as fast as the *second-fastest* disk and link. On an SD
card an fsync can take tens of milliseconds; that is fine. If a node's disk
can stall for more than a second (cheap SD cards under load), or the nodes are
on different continents, raise `raft.election_ticks` to 30 on **all** nodes so
that a slow moment is not mistaken for a dead leader. The cost is a slower
failover (3–6 s instead of 1–2 s).

## 11. Upgrading

Upgrade one node at a time: stop it, replace the binary, start it, wait until
`fvault admin cluster` shows it caught up, then do the next. All nodes must end
up on the same version: the replicated state machine has to behave
identically everywhere.

## 12. Checklist

* [ ] `ca-key.pem` is offline.
* [ ] `bootstrap-token` files are deleted.
* [ ] Every family member has compared fingerprints with the people they share with.
* [ ] Peer ports are reachable only from the other nodes.
* [ ] Someone other than you knows where the backups are.
* [ ] Each person has made a personal export and remembers its passphrase.
