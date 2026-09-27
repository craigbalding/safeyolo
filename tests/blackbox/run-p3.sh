#!/bin/bash
# Run #637 P3 with frozen installed source and disposable real guests.
# The selected host must support its named guest mechanism and loopback TCP.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
FROZEN_R=d6a947f1343c5a854b735c22a0ce90d641dd5ac0
PLATFORM="${1:-}"

case "$PLATFORM" in
    systrap)
        [ "$(uname -s)" = Linux ] || { echo "ERROR: $PLATFORM needs a Linux host" >&2; exit 2; }
        ;;
    vz)
        [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || {
            echo "ERROR: VZ needs a physical Apple Silicon Mac" >&2; exit 2;
        }
        ;;
    *)
        echo "Usage: $0 {systrap|vz}" >&2
        exit 2
        ;;
esac
for program in uv git python3; do
    command -v "$program" >/dev/null 2>&1 || { echo "ERROR: P3 needs $program" >&2; exit 2; }
done
python3 - <<'PY'
import socket
import sys

try:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2):
            accepted, _ = listener.accept()
            accepted.close()
except OSError as exc:
    sys.exit(f"ERROR: P3 host needs loopback TCP bind and connect for its disposable proxy and origin: {exc}")
PY
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "ERROR: P3 harness checkout must be clean" >&2
    exit 2
fi
if ! git -C "$REPO_ROOT" cat-file -e "$FROZEN_R^{commit}" 2>/dev/null; then
    git -C "$REPO_ROOT" fetch origin feat/rust-proxy-620
fi
if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$FROZEN_R" HEAD; then
    echo "ERROR: P3 harness checkout does not contain frozen R" >&2
    exit 2
fi

PILOT_DIR="$(mktemp -d "$HOME/safeyolo-p3-$PLATFORM.XXXXXX")"
export UV_TOOL_DIR="$PILOT_DIR/uv-tools"
export UV_TOOL_BIN_DIR="$PILOT_DIR/bin"
export SAFEYOLO_CONFIG_DIR="$PILOT_DIR/source-instance"
export SAFEYOLO_TEST_CONFIG_DIR="$PILOT_DIR/test-instance"
export SAFEYOLO_TEST_AGENT=bbtest
export SAFEYOLO_BLACKBOX_ARTIFACTS_DIR="$PILOT_DIR/observations"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_TEST_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export CARGO_BUILD_JOBS=1
unset SAFEYOLO_RUST_PROXY SAFEYOLO_PYTHON_SOURCE SAFEYOLO_TEST_CERT_DIR SAFEYOLO_TEST_KEY_DIR
mkdir -p "$UV_TOOL_DIR" "$UV_TOOL_BIN_DIR" "$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"

cleanup() {
    local result=$?
    local cleanup_failed=0
    trap - EXIT
    rm -f "$SAFEYOLO_TEST_CONFIG_DIR/agents/bbpeer/config-share/p3-stolen-token" || cleanup_failed=1
    if [ -x "$UV_TOOL_BIN_DIR/safeyolo" ]; then
        for agent in bbpeer bbtest; do
            if [ -d "$SAFEYOLO_TEST_CONFIG_DIR/agents/$agent" ]; then
                SAFEYOLO_CONFIG_DIR="$SAFEYOLO_TEST_CONFIG_DIR" \
                    "$UV_TOOL_BIN_DIR/safeyolo" agent stop "$agent" >/dev/null 2>&1 || cleanup_failed=1
            fi
        done
        if [ -f "$SAFEYOLO_TEST_CONFIG_DIR/config.yaml" ]; then
            SAFEYOLO_CONFIG_DIR="$SAFEYOLO_TEST_CONFIG_DIR" \
                "$UV_TOOL_BIN_DIR/safeyolo" stop >/dev/null 2>&1 || cleanup_failed=1
        fi
    fi
    for agent in bbtest bbpeer; do
        [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/agents/$agent/container.pid" ] || cleanup_failed=1
        for owned_socket in "$SAFEYOLO_TEST_CONFIG_DIR"/data/sockets/*_"$agent"/proxy.sock; do
            [ ! -e "$owned_socket" ] || cleanup_failed=1
        done
    done
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/data/proxy-rust.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_COORD_DATA_DIR/nats/nats.pid.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/sinkhole.pid" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/native-parent.pid" ] || cleanup_failed=1
    if [ "$cleanup_failed" -ne 0 ]; then
        echo "ERROR: disposable P3 proxy or guest cleanup failed: $SAFEYOLO_TEST_CONFIG_DIR" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q agent stop bbpeer\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q agent stop bbtest\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q stop\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        result=1
    fi
    local report="$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR/$PLATFORM-p3.json"
    if [ -f "$report" ]; then
        if ! python3 - "$report" "$result" "$cleanup_failed" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text())
report["cleanup"] = "stopped" if sys.argv[3] == "0" else "failed"
report["status"] = "passed" if sys.argv[2] == "0" else "incomplete"
path.write_text(json.dumps(report, indent=2) + "\n")
PY
        then
            result=1
        fi
    fi
    echo "$PLATFORM P3 result: exit $result; records: $PILOT_DIR/observations"
    exit "$result"
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$PILOT_DIR/source-R" "$FROZEN_R"
if [ "$(git -C "$PILOT_DIR/source-R" rev-parse HEAD)" != "$FROZEN_R" ]; then
    echo "ERROR: detached P3 install source is not frozen R" >&2
    exit 2
fi

cd "$REPO_ROOT"
"$REPO_ROOT/tests/blackbox/run-lane.sh" "$PLATFORM" \
    --install-checkout "$PILOT_DIR/source-R" --proxy-impl rust --p3
