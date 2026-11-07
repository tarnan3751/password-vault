#!/usr/bin/env bash
# Cross-language interoperability test: the Go client (fvault) and the browser
# client's own code (run under Node) must read and write each other's data.
#
#   scripts/interop.sh
#
# 1. builds bin/vaultd and bin/fvault and starts a throw-away 3-node INSECURE
#    cluster on free localhost ports in a temp dir (never the ports or the
#    .dev directory of scripts/dev-cluster.sh);
# 2. fvault: registers alice (bootstrap token), creates a shared vault with
#    non-ASCII items and custom fields, invites and registers bob, shares;
# 3. web client (web/scripts/interop-check.ts): verifies every field, edits,
#    creates an item with an unknown field, changes bob's password, removes bob
#    (rekey);
# 4. fvault: verifies it sees what the browser wrote and still decrypts after
#    the rekey, edits the browser's item; bob's old password is dead;
# 5. web client again: the unknown field survived fvault's edit.
# Prints PASS/FAIL per step; exits non-zero if anything failed. Needs: go, node (26+), curl.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/fvault-interop.XXXXXX")"
TOKEN="interop-bootstrap-token-$RANDOM$RANDOM"
pids=()
FAILS=0

cleanup() {
  trap - EXIT INT TERM
  for p in "${pids[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

# step "name" cmd args... : run, print PASS/FAIL; on failure show the output.
step() {
  local name="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    echo "PASS  $name"
  else
    FAILS=$((FAILS + 1))
    echo "FAIL  $name"
    echo "$out" | sed 's/^/        /'
  fi
}
# fatal_step: a failure aborts the run (later steps depend on it).
fatal_step() {
  local before=$FAILS
  step "$@"
  if [[ $FAILS -gt $before ]]; then echo "aborting: a prerequisite failed"; exit 1; fi
}

jget() { node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const v=eval("j"+process.argv[2]);process.stdout.write(typeof v==="string"?v:JSON.stringify(v))' "$1" "$2"; }
jstr() { node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8"));const v=eval(process.argv[1]);process.stdout.write(typeof v==="string"?v:JSON.stringify(v))' "$1"; }

FV="$ROOT/bin/fvault"
PW_ALICE='ünïcode correct horse 1'
PW_BOB='staple battery ✓ purple 2'
PW_BOB_NEW='purple monkey NEW 🔑 3'
BANK_PW="pässwörd-銀行-🔑-$RANDOM$RANDOM"
VAULT='Family ✓'
BROWSER_VAULT='Browser-made ü'
BANK='Bank ü 銀行 🏦'
NOTE='Secret note ñ'
PERSONAL='Diary ß'
NOTES_BANK=$'Zeile 1\nLine 2 — ✓ “quotes” <&>'
NOTES_SECRET=$'Geheim: Ünïcödé\nsecond line'

fa() { FVAULT_HOME="$T/alice" FVAULT_PASSWORD="$PW_ALICE" "$FV" "$@"; }
fb() { FVAULT_HOME="$T/bob" FVAULT_PASSWORD="$PW_BOB" "$FV" "$@"; }
fb2() { FVAULT_HOME="$T/bob" FVAULT_PASSWORD="$PW_BOB_NEW" "$FV" "$@"; }

echo "== setup: build and start a 3-node cluster in $T"
fatal_step "build bin/vaultd and bin/fvault" bash -c "cd '$ROOT' && go build -o bin/vaultd ./cmd/vaultd && go build -o bin/fvault ./cmd/fvault"

PORTS=($(node -e '
const net=require("net");const n=6;const ps=[];let c=0;const ss=[];
for(let i=0;i<n;i++){const s=net.createServer();ss.push(s);s.listen(0,"127.0.0.1",()=>{ps.push(s.address().port);if(++c===n){console.log(ps.join(" "));ss.forEach(x=>x.close())}})}
'))
if [[ ${#PORTS[@]} -ne 6 ]]; then echo "could not find free ports"; exit 1; fi
for i in 1 2 3; do
  mkdir -p "$T/n$i"
  CP=${PORTS[$((i-1))]}; PP=${PORTS[$((i+2))]}
  eval "CPORT$i=$CP; PPORT$i=$PP"
done
cat_peers() {
  cat <<JSON
    {"id": "n1", "peer_addr": "127.0.0.1:$PPORT1", "public_url": "http://127.0.0.1:$CPORT1"},
    {"id": "n2", "peer_addr": "127.0.0.1:$PPORT2", "public_url": "http://127.0.0.1:$CPORT2"},
    {"id": "n3", "peer_addr": "127.0.0.1:$PPORT3", "public_url": "http://127.0.0.1:$CPORT3"}
JSON
}
for i in 1 2 3; do
  eval "CP=\$CPORT$i; PP=\$PPORT$i"
  cat > "$T/n$i/config.json" <<JSON
{
  "node_id": "n$i",
  "data_dir": "$T/n$i/data",
  "client_listen": "127.0.0.1:$CP",
  "peer_listen": "127.0.0.1:$PP",
  "peers": [
$(cat_peers)
  ],
  "bootstrap_token": "$TOKEN",
  "insecure": true
}
JSON
  "$ROOT/bin/vaultd" run --config "$T/n$i/config.json" >"$T/n$i/log" 2>&1 &
  pids+=($!)
done
BASE="http://127.0.0.1:$CPORT1"

wait_ready() {
  for _ in $(seq 1 200); do
    ok=0
    for p in "$CPORT1" "$CPORT2" "$CPORT3"; do
      h="$(curl -fsS "http://127.0.0.1:$p/v1/health" 2>/dev/null)" || continue
      [[ "$h" == *'"initialized":true'* && "$h" != *'"leader_id":""'* ]] && ok=$((ok+1))
    done
    [[ $ok -eq 3 ]] && return 0
    sleep 0.1
  done
  echo "cluster did not become ready"; tail -n 20 "$T"/n*/log; return 1
}
fatal_step "3-node cluster is up (ports $CPORT1 $CPORT2 $CPORT3)" wait_ready

echo "== fvault writes"
s_init() {
  "$FV" --home "$T/alice" init --server "$BASE" --insecure >/dev/null || return 1
  [[ "$(jget "$T/alice/config.json" .servers.length)" == 3 ]] || { echo "expected 3 discovered nodes"; return 1; }
}
s_register_alice() { fa register --username alice --bootstrap-token "$TOKEN"; }
s_create_items() {
  fa vault create "$VAULT" || return 1
  FVAULT_ITEM_PASSWORD="$BANK_PW" fa add --vault "$VAULT" --name "$BANK" --username 'alice@bänk.example' \
    --url 'https://bank.example/ü' --url 'https://second.example/' --notes "$NOTES_BANK" \
    --set 'Account no=12345-ü' --set-hidden 'PIN=9876' || return 1
  fa add --vault "$VAULT" --name "$NOTE" --type note --notes "$NOTES_SECRET" || return 1
  fa add --name "$PERSONAL" --username me --generate --length 20 >/dev/null
}
s_invite_bob() {
  local code
  code="$(fa invite create --ttl-hours 1 2>/dev/null)" || return 1
  "$FV" --home "$T/bob" init --server "$BASE" --insecure >/dev/null || return 1
  FVAULT_INVITE="$code" fb register --username bob
}
s_fp_agree() {
  [[ -n "$BOB_FP" && "$(fa fingerprint --json | jstr 'j.find(x=>x.username==="bob").fingerprint')" == "$BOB_FP" ]] || { echo "alice sees a different fingerprint for bob"; return 1; }
  [[ "$(fb fingerprint --json | jstr 'j.find(x=>x.username==="alice").fingerprint')" == "$ALICE_FP" ]] || { echo "bob sees a different fingerprint for alice"; return 1; }
}
fatal_step "init discovers all three nodes" s_init
fatal_step "bootstrap-register alice" s_register_alice
fatal_step "create shared vault and items (non-ASCII, custom fields, secret note)" s_create_items
fatal_step "invite and register bob" s_invite_bob
ALICE_FP="$(fa fingerprint --json | jstr 'j.find(x=>x.self).fingerprint')"
BOB_FP="$(fb fingerprint --json | jstr 'j.find(x=>x.self).fingerprint')"
fatal_step "fingerprints agree between both users' views" s_fp_agree
fatal_step "share the vault with bob as editor (verified by explicit fingerprint)" fa vault share "$VAULT" bob --role editor --fingerprint "$BOB_FP"

# Expectations for the web client, as JSON.
PERSONAL_PW="$(fa get "$PERSONAL" --field password)"
export PW_ALICE PW_BOB PW_BOB_NEW ALICE_FP BOB_FP VAULT BROWSER_VAULT BANK NOTE PERSONAL BANK_PW NOTES_BANK NOTES_SECRET PERSONAL_PW
node -e '
const e = {
  alice: { user: "alice", password: process.env.PW_ALICE, fingerprint: process.env.ALICE_FP },
  bob: { user: "bob", password: process.env.PW_BOB, newPassword: process.env.PW_BOB_NEW, fingerprint: process.env.BOB_FP },
  vaultName: process.env.VAULT,
  browserVaultName: process.env.BROWSER_VAULT,
  items: [
    { name: process.env.BANK, type: "login", username: "alice@bänk.example", password: process.env.BANK_PW,
      urls: ["https://bank.example/ü", "https://second.example/"], notes: process.env.NOTES_BANK,
      fields: [{ name: "Account no", value: "12345-ü" }, { name: "PIN", value: "9876", hidden: true }] },
    { name: process.env.NOTE, type: "note", notes: process.env.NOTES_SECRET },
  ],
  personalItem: { name: process.env.PERSONAL, type: "login", username: "me", password: process.env.PERSONAL_PW },
  cliEditedNotes: "cli edited ü ✓",
};
process.stdout.write(JSON.stringify(e));
' > "$T/expect.json"

echo "== web client (independent implementation) reads and writes"
(cd "$ROOT/web" && node scripts/interop-check.ts --phase a --base "$BASE" --expect "$T/expect.json" --state "$T/state.json") 2>&1 | sed 's/^/  web: /'
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then FAILS=$((FAILS + 1)); echo "FAIL  web client phase a"; else echo "PASS  web client phase a (all checks above)"; fi
[[ -f "$T/state.json" ]] || { echo "no state from phase a; aborting"; exit 1; }
BANK_NEW="$(jget "$T/state.json" .bankNewPassword)"
BROWSER_ITEM_ID="$(jget "$T/state.json" .browserItemId)"

echo "== fvault reads what the browser wrote"
eq() { [[ "$1" == "$2" ]] || { echo "got [$1] want [$2]"; return 1; }; }
s_pw_edit() { eq "$(fa get "$BANK" --field password)" "$BANK_NEW"; }
s_history() { eq "$(fa history "$BANK" --show --json | jstr 'j.history[0].password')" "$BANK_PW"; }
s_after_rekey() {
  eq "$(fa get 'Browser item ß' --field password)" 'p4ss-ü-🔑' || return 1
  eq "$(fa get 'Browser item ß' --field url)" 'https://example.org/ü' || return 1
  eq "$(fa get 'Browser item ß' --field notes)" 'made in the browser'
}
s_bobs_note() { eq "$(fa get "Bob's note" --field notes)" 'by bob in the browser'; }
s_epoch() {
  eq "$(fa vault ls --json | jstr "j.find(v=>v.name===process.env.VAULT).key_epoch")" 2 || return 1
  eq "$(fa vault ls --json | jstr "j.find(v=>v.name===process.env.VAULT).members")" 1 || return 1
  eq "$(fa vault ls --json | jstr "j.find(v=>v.name===process.env.VAULT).rekey_recommended")" false
}
s_own_fields() {
  eq "$(fa get "$BANK" --field 'Account no')" '12345-ü' || return 1
  eq "$(fa get "$BANK" --field PIN)" 9876 || return 1
  eq "$(fa get "$BANK" --field notes)" "$NOTES_BANK"
}
s_cli_edit() { fa edit 'Browser item ß' --notes 'cli edited ü ✓'; }
s_bob_old() { ! fb ls >/dev/null 2>&1; }
s_bob_new() {
  local out
  out="$(fb2 ls --json)" || return 1
  [[ "$(printf %s "$out" | jstr "j.some(r=>r.vault===process.env.VAULT)")" == false ]] || { echo "bob still sees the vault"; return 1; }
}
s_export_import() {
  export FVAULT_BACKUP_PASSPHRASE='interop backup passphrase'
  fa export --out "$T/export.json" >/dev/null && fa import "$T/export.json" >/dev/null || return 1
  eq "$(fa ls --json | jstr "j.some(r=>r.vault.endsWith('(restored)')&&r.name==='Browser item ß')")" true
}
s_browser_share() {
  # The browser shared a vault with bob; for fvault it is PENDING until bob compares alice's fingerprint.
  local out
  out="$(fb2 vault ls --json)" || return 1
  [[ "$(printf %s "$out" | jstr "j.filter(v=>v.locked==='pending').length")" == 1 ]] || { echo "expected exactly one pending vault: $out"; return 1; }
  ! fb2 get 'Browser shared item' --field password >/dev/null 2>&1 || { echo "a pending vault was readable"; return 1; }
  local id
  id="$(printf %s "$out" | jstr "j.find(v=>v.locked==='pending').id")"
  ! fb2 vault accept "$id" --yes >/dev/null 2>&1 || { echo "--yes without --fingerprint was accepted"; return 1; }
  fb2 vault accept "$id" --fingerprint "$ALICE_FP" --yes || return 1
  eq "$(fb2 get 'Browser shared item' --field password)" 'shared-ü-pw-1' || return 1
  fb2 add --vault "$id" --name 'Reply from fvault' --notes 'written by the Go client into a vault the browser created' --username me
}
step "fvault: the browser-made vault is pending, accepting needs alice's fingerprint, then it opens" s_browser_share
step "fvault sees the browser's password edit of the bank item" s_pw_edit
step "fvault sees the history entry the browser recorded" s_history
step "fvault decrypts the browser-created item after the browser-side rekey" s_after_rekey
step "fvault sees bob's item written in the browser" s_bobs_note
step "key epoch is 2, only alice is a member, no rekey pending" s_epoch
step "fvault still reads the custom fields it wrote itself, after the rekey" s_own_fields
step "fvault edits the browser's item (non-password edit)" s_cli_edit
step "bob's OLD password is rejected by fvault" s_bob_old
step "bob's NEW password (set in the browser) works in fvault; the vault is gone for him" s_bob_new
step "fvault export/import round trip of everything the browser touched" s_export_import

echo "== web client verifies fvault's edit around an unknown field"
(cd "$ROOT/web" && node scripts/interop-check.ts --phase b --base "$BASE" --expect "$T/expect.json" --state "$T/state.json") 2>&1 | sed 's/^/  web: /'
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then FAILS=$((FAILS + 1)); echo "FAIL  web client phase b"; else echo "PASS  web client phase b (all checks above)"; fi

echo "== teardown"
echo
if [[ $FAILS -eq 0 ]]; then echo "INTEROP: PASS"; exit 0; else echo "INTEROP: FAIL ($FAILS failing step(s))"; exit 1; fi
