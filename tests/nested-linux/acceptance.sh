#!/usr/bin/env bash
# Real SafeYolo-in-SafeYolo acceptance lane. Run inside an outer Linux agent.

set -euo pipefail

die() { echo "nested-linux acceptance: $*" >&2; exit 1; }
step() { echo; echo "=== $* ==="; }

[ "${SAFEYOLO_NESTED_ACCEPT:-}" = "1" ] || die \
    "set SAFEYOLO_NESTED_ACCEPT=1 to confirm this disposable lab run"
[ "$(uname -s)" = "Linux" ] || die "Linux is required"
[ "$(cat /proc/1/comm)" != "systemd" ] || die "run this lane on a non-systemd outer agent"
[ -r /app/agent_token ] || die "outer SafeYolo Agent API token is unavailable"
[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] || die "DBUS_SESSION_BUS_ADDRESS must be absent"
[ -z "${XDG_RUNTIME_DIR:-}" ] || die "XDG_RUNTIME_DIR must be absent"

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LAB_ROOT=${SAFEYOLO_NESTED_LAB_ROOT:-/var/lib/nested-safeyolo-lab}
LAB_SOURCE=${SAFEYOLO_NESTED_SOURCE_ROOT:-$LAB_ROOT/source}
LAB_STATE=${SAFEYOLO_NESTED_CONFIG_DIR:-$LAB_ROOT/state}
INNER_AGENT=${SAFEYOLO_NESTED_AGENT:-nested-worker}
OUTER_PROXY=${SAFEYOLO_NESTED_OUTER_PROXY:-http://127.0.0.1:8080}
INNER_PROXY_PORT=${SAFEYOLO_NESTED_PROXY_PORT:-18080}
INNER_ADMIN_PORT=${SAFEYOLO_NESTED_ADMIN_PORT:-19090}
INNER_WEB_PORT=${SAFEYOLO_NESTED_WEB_PORT:-18081}
TARGET_URL=${SAFEYOLO_NESTED_TARGET_URL:-https://example.com/}
LOOP_TARGET_URL=${SAFEYOLO_NESTED_LOOP_TARGET_URL:-http://example.com/}
RUN_NONCE=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
COORD_ROOM="nested-linux-$RUN_NONCE"

case "$LAB_ROOT" in
    /var/lib/*) ;;
    *) die "lab root must be a dedicated guest-local path under /var/lib" ;;
esac
[ "$LAB_SOURCE" != "$REPO_ROOT" ] || die "nested source must not be the mounted host checkout"
{
    printf 'Authorization: Bearer '
    cat /app/agent_token
    printf '\n'
} | curl -fsS --header @- http://_safeyolo.proxy.internal/health | \
    grep -Eq '"agent_api"[[:space:]]*:[[:space:]]*"ok"' || die \
    "outer SafeYolo Agent API is not healthy"

export SAFEYOLO_CONFIG_DIR="$LAB_STATE"
export SAFEYOLO_COORD_DATA_DIR="$LAB_STATE/coord"
export SAFEYOLO_UPSTREAM_PROXY="$OUTER_PROXY"
export SAFEYOLO_RUNSC_PLATFORM=systrap

step "Prepare guest-local lab storage"
sudo -n install -d -m 0755 -o "$(id -u)" -g "$(id -g)" \
    "$LAB_ROOT" "$LAB_SOURCE" "$LAB_STATE"

step "Install the current rootfs dependency floor"
sudo -n apt-get update
sudo -n apt-get install -y \
    skopeo umoci mmdebstrap debootstrap acl jq rsync e2fsprogs tmux curl

step "Copy the source onto guest-local storage"
rsync -a --delete \
    --exclude .git --exclude .venv --exclude guest/out \
    "$REPO_ROOT/" "$LAB_SOURCE/"
cd "$LAB_SOURCE"

step "Bootstrap and build through the outer proxy with TLS verification"
uv sync
test -r "$SSL_CERT_FILE" || die "outer SSL_CERT_FILE is not readable: $SSL_CERT_FILE"
uv run safeyolo bootstrap
stat -c '%u:%g' "$LAB_STATE/share/rootfs-tree" | grep -qx '100000:100000' || die \
    "installed rootfs tree did not preserve uid/gid 100000"
if cmp -s "$SSL_CERT_FILE" \
    "$LAB_STATE/share/rootfs-tree$SSL_CERT_FILE" 2>/dev/null; then
    die "outer CA was baked into the nested rootfs"
fi

step "Select non-conflicting nested listeners"
uv run python - "$LAB_STATE/config.yaml" \
    "$INNER_PROXY_PORT" "$INNER_ADMIN_PORT" "$INNER_WEB_PORT" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
config = yaml.safe_load(path.read_text())
config["proxy"]["port"] = int(sys.argv[2])
config["proxy"]["admin_port"] = int(sys.argv[3])
config["proxy"]["web_port"] = int(sys.argv[4])
path.write_text(yaml.safe_dump(config, sort_keys=False))
PY

step "Start nested proxy and a direct-runsc agent"
uv run safeyolo start --dev
uv run safeyolo agent add "$INNER_AGENT" "$LAB_SOURCE" \
    --host-script "$LAB_SOURCE/contrib/codex-host-setup.sh" --no-run
uv run safeyolo coord room create "$COORD_ROOM" \
    --member "$INNER_AGENT" --no-operator
uv run safeyolo agent run "$INNER_AGENT" --detach

inner_shell() {
    uv run safeyolo agent shell "$INNER_AGENT" -c "$1"
}

step "Materialize the harness only when explicitly requested"
inner_shell '/home/agent/.safeyolo-command --version'

step "Prove nested Agent API, HTTPS chaining, recording, and attribution"
inner_shell \
    "python3 /workspace/tests/nested-linux/flow_probe.py --agent '$INNER_AGENT' --target '$TARGET_URL'"

step "Prove the outer proxy allows the inner instance Via token"
# This guest has no direct egress. A successful request from the nested agent
# therefore proves that the explicit inner upstream reached the outer proxy.
# The response headers make the old failure mode explicit: it must not be a
# loop-guard 508.
inner_shell \
    "status=\$(curl -sS -o /tmp/nested-forward.body -D /tmp/nested-forward.headers -w '%{http_code}' '$TARGET_URL'); [ \"\$status\" = 200 ]"
inner_shell "! grep -iq '^x-blocked-by: loop-guard' /tmp/nested-forward.headers" || die \
    "outer proxy rejected the nested instance Via token"

step "Prove a genuine same-instance proxy loop is blocked"
INNER_SOCKET=$(jq -er --arg agent "$INNER_AGENT" '.[$agent].socket' \
    "$LAB_STATE/data/agent_map.json")
LOOP_PORT=$((INNER_PROXY_PORT + 2))
uv run safeyolo stop
socat TCP-LISTEN:"$LOOP_PORT",bind=127.0.0.1,reuseaddr,fork \
    UNIX-CONNECT:"$INNER_SOCKET" &
SOCAT_PID=$!
trap 'kill "$SOCAT_PID" 2>/dev/null || true' EXIT
export SAFEYOLO_UPSTREAM_PROXY="http://127.0.0.1:$LOOP_PORT"
uv run safeyolo start --dev
inner_shell \
    "status=\$(curl -sS -o /tmp/nested-loop.body -D /tmp/nested-loop.headers -w '%{http_code}' '$LOOP_TARGET_URL'); [ \"\$status\" = 508 ]"
inner_shell "grep -iq '^x-blocked-by: loop-guard' /tmp/nested-loop.headers" || die \
    "same-instance loop was not attributed to loop-guard"
kill "$SOCAT_PID" 2>/dev/null || true
wait "$SOCAT_PID" 2>/dev/null || true
trap - EXIT

step "Restore the normal outer upstream and leave the lab healthy"
uv run safeyolo stop
export SAFEYOLO_UPSTREAM_PROXY="$OUTER_PROXY"
uv run safeyolo start --dev
inner_shell \
    'for attempt in $(seq 1 30); do { printf "Authorization: Bearer "; cat /app/agent_token; printf "\n"; } | curl -fsS -o /tmp/nested-health.json --header @- http://_safeyolo.proxy.internal/health && cat /tmp/nested-health.json && exit 0; sleep 0.2; done; exit 1'

step "Prove the bundled coord MCP connects"
inner_shell \
    "python3 /workspace/tests/nested-linux/mcp_probe.py --room '$COORD_ROOM'"

echo
echo "nested-linux acceptance: PASS"
