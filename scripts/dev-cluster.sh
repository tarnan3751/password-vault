#!/usr/bin/env bash
# Start a three-node cluster on this machine for trying Family Vault out.
# It is INSECURE (plain HTTP) and only reachable from this machine.
#
#   scripts/dev-cluster.sh            start n1, n2, n3 (Ctrl-C stops them all)
#   scripts/dev-cluster.sh --reset    erase the cluster's data first
#
# To run a second, separate cluster next to the first one:
#   VAULT_DEV_PORT=8101 VAULT_DEV_DIR=/some/dir scripts/dev-cluster.sh
# The three nodes listen on VAULT_DEV_PORT .. +2 (default 8001) and talk to
# each other on the ports 1000 above those.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV="${VAULT_DEV_DIR:-$ROOT/.dev}"
PORT="${VAULT_DEV_PORT:-8001}"
TOKEN="dev-bootstrap-token-0000"

if [[ "${1:-}" == "--reset" ]]; then
  rm -rf "$DEV"
elif [[ $# -gt 0 ]]; then
  sed -n '2,11s/^# \{0,1\}//p' "$0"
  exit 2
fi

(cd "$ROOT" && go build -o bin/vaultd ./cmd/vaultd && go build -o bin/fvault ./cmd/fvault)

client_port() { echo $((PORT + $1 - 1)); }
peer_port() { echo $((PORT + 1000 + $1 - 1)); }

for i in 1 2 3; do
  mkdir -p "$DEV/n$i"
  cat > "$DEV/n$i/config.json" <<JSON
{
  "node_id": "n$i",
  "data_dir": "data",
  "client_listen": "127.0.0.1:$(client_port $i)",
  "peer_listen": "127.0.0.1:$(peer_port $i)",
  "peers": [
    {"id": "n1", "peer_addr": "127.0.0.1:$(peer_port 1)", "public_url": "http://127.0.0.1:$(client_port 1)"},
    {"id": "n2", "peer_addr": "127.0.0.1:$(peer_port 2)", "public_url": "http://127.0.0.1:$(client_port 2)"},
    {"id": "n3", "peer_addr": "127.0.0.1:$(peer_port 3)", "public_url": "http://127.0.0.1:$(client_port 3)"}
  ],
  "bootstrap_token": "$TOKEN",
  "insecure": true
}
JSON
done

pids=()
cleanup() {
  trap - INT TERM EXIT
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

for i in 1 2 3; do
  "$ROOT/bin/vaultd" run --config "$DEV/n$i/config.json" > >(sed -u "s/^/[n$i] /") 2>&1 &
  pids+=($!)
done

# Wait until the three nodes have elected a leader, then say what to do next.
URL="http://127.0.0.1:$PORT"
SHOWN="${DEV#"$ROOT"/}" # relative to the project directory when it is inside it
ready=""
for _ in $(seq 1 100); do
  if curl -fsS --max-time 1 "$URL/v1/health" 2>/dev/null | grep -q '"initialized":true'; then
    ready=1
    break
  fi
  sleep 0.2
done

if [[ -z "$ready" ]]; then
  echo
  echo "The cluster did not become ready within 20 seconds; see the log lines above."
else
  cat <<EOF

  Family Vault is running (three servers on this machine, plain HTTP).

    In a browser:   $URL
    In a terminal:  bin/fvault init --server $URL --insecure

    The first account needs the bootstrap token:  $TOKEN
    Servers: $URL  http://127.0.0.1:$(client_port 2)  http://127.0.0.1:$(client_port 3)

  To see it survive a failure, stop one server from another terminal:
    pkill -f '$SHOWN/n2/config.json'
  and start it again with:
    bin/vaultd run --config '$SHOWN/n2/config.json'

  Press Ctrl-C here to stop all three. Your data stays in $SHOWN
  (start with --reset to erase it).

EOF
fi
wait
