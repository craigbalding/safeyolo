#!/usr/bin/env bash
# T47: namespace-root is useful inside gVisor but cannot escape to the host.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT_NAME="${1:-bbtest}"
CONFIG_DIR="${SAFEYOLO_CONFIG_DIR:-$HOME/.safeyolo}"
AGENT_DIR="$CONFIG_DIR/agents/$AGENT_NAME"
CONFIG_SHARE="$AGENT_DIR/config-share"
USERNS_PID_FILE="$AGENT_DIR/userns.pid"
ROOT_MARKER="t47-sandbox-root-marker"
HOST_CANARY="$(mktemp /tmp/safeyolo-t47-host.XXXXXX)"
PORT_FILE="$(mktemp /tmp/safeyolo-t47-port.XXXXXX)"
LISTENER_PID=""

cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    rm -f \
        "$HOST_CANARY" \
        "$PORT_FILE" \
        "$CONFIG_SHARE/t47-canary" \
        "$CONFIG_SHARE/t47-guest-probe.py"
    safeyolo agent shell "$AGENT_NAME" -c \
        "setpriv --reuid=0 --regid=0 --clear-groups rm -f /etc/$ROOT_MARKER" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$(uname -s)" != "Linux" ]; then
    echo "T47 applies to Linux rootless gVisor" >&2
    exit 2
fi
if [ ! -s "$USERNS_PID_FILE" ]; then
    echo "Agent '$AGENT_NAME' is not a running rootless gVisor agent" >&2
    exit 2
fi
if ! safeyolo agent shell "$AGENT_NAME" -c true >/dev/null 2>&1; then
    echo "Agent '$AGENT_NAME' is not reachable" >&2
    exit 2
fi

USERNS_PID="$(tr -d '[:space:]' < "$USERNS_PID_FILE")"
UID_MAP="$(cat "/proc/$USERNS_PID/uid_map")"
HOST_UID="$(id -u)"

map_uid() {
    local wanted="$1"
    awk -v wanted="$wanted" '
        $1 <= wanted && wanted < ($1 + $3) {
            print $2 + wanted - $1
            exit
        }
    ' "/proc/$USERNS_PID/uid_map"
}

if [ "$(map_uid 0)" != "100000" ]; then
    echo "FAIL: sandbox uid 0 does not map to host subordinate uid 100000" >&2
    echo "$UID_MAP" >&2
    exit 1
fi
if [ "$(map_uid 1000)" != "$HOST_UID" ]; then
    echo "FAIL: sandbox uid 1000 does not map to host operator uid $HOST_UID" >&2
    echo "$UID_MAP" >&2
    exit 1
fi

CANARY_TOKEN="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s' "$CANARY_TOKEN" > "$HOST_CANARY"
chmod 0600 "$HOST_CANARY"
mkdir -p "$CONFIG_SHARE"
printf '%s' "$CANARY_TOKEN" > "$CONFIG_SHARE/t47-canary"
cp "$REPO_ROOT/tests/rootless-experiments/t47_guest_probe.py" \
    "$CONFIG_SHARE/t47-guest-probe.py"

python3 "$REPO_ROOT/tests/blackbox/harness/host_listener.py" > "$PORT_FILE" &
LISTENER_PID=$!
for _ in $(seq 1 30); do
    [ -s "$PORT_FILE" ] && break
    sleep 0.1
done
if [ ! -s "$PORT_FILE" ]; then
    echo "FAIL: host listener did not start" >&2
    exit 1
fi
LISTENER_PORT="$(tr -d '[:space:]' < "$PORT_FILE")"

printf -v GUEST_COMMAND \
    'setpriv --reuid=0 --regid=0 --clear-groups python3 %q --canary-token %q --host-canary %q --listener-port %q --root-marker %q' \
    "/safeyolo/t47-guest-probe.py" \
    "$CANARY_TOKEN" "$HOST_CANARY" "$LISTENER_PORT" "/etc/$ROOT_MARKER"
safeyolo agent shell "$AGENT_NAME" -c "$GUEST_COMMAND"

if [ "$(cat "$HOST_CANARY")" != "$CANARY_TOKEN" ]; then
    echo "FAIL: unmounted host canary changed" >&2
    exit 1
fi
if [ "$(cat "$CONFIG_SHARE/t47-canary")" != "$CANARY_TOKEN" ]; then
    echo "FAIL: read-only config-share canary changed" >&2
    exit 1
fi
if [ -e "$AGENT_DIR/rootfs/etc/$ROOT_MARKER" ]; then
    echo "FAIL: sandbox-root overlay write mutated the host lower rootfs" >&2
    exit 1
fi

echo "PASS: uid map, host mounts, listener, devices, PID namespace, and rootfs lower are contained"
