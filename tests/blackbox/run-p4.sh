#!/bin/bash
# Run #637 P4/P6 at frozen R by default, or at an explicitly selected commit.
# The selected host must support its named guest mechanism and loopback TCP.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
FROZEN_R=2faba3306de7c099e2913e0eebc8907ff3eba148
PLATFORM="${1:-}"
INSTALL_COMMIT="$FROZEN_R"
INSTALL_CHECKOUT=""
if { [ "$#" -eq 3 ] || [ "$#" -eq 5 ]; } && \
   [ "$2" = "--install-commit" ] && [[ "$3" =~ ^[0-9a-f]{40}$ ]]; then
    INSTALL_COMMIT="$3"
    if [ "$#" -eq 5 ] && [ "$4" = "--install-checkout" ]; then
        INSTALL_CHECKOUT="$5"
    elif [ "$#" -eq 5 ]; then
        echo "Usage: $0 {systrap|vz} [--install-commit FULL_SHA [--install-checkout PATH]]" >&2
        exit 2
    fi
elif [ "$#" -ne 1 ]; then
    echo "Usage: $0 {systrap|vz} [--install-commit FULL_SHA [--install-checkout PATH]]" >&2
    exit 2
fi

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
    command -v "$program" >/dev/null 2>&1 || { echo "ERROR: P4 needs $program" >&2; exit 2; }
done
python3 - <<'PY'
import socket
import sys

try:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 46375 if sys.platform == "darwin" else 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2):
            accepted, _ = listener.accept()
            accepted.close()
except OSError as exc:
    sys.exit(f"ERROR: P4 host needs loopback TCP bind and connect for its disposable proxy and origin: {exc}")
PY
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "ERROR: P4 harness checkout must be clean" >&2
    exit 2
fi
if ! git -C "$REPO_ROOT" cat-file -e "$INSTALL_COMMIT^{commit}" 2>/dev/null; then
    if [ "$INSTALL_COMMIT" = "$FROZEN_R" ]; then
        git -C "$REPO_ROOT" fetch origin feat/rust-proxy-620
    else
        git -C "$REPO_ROOT" fetch origin "$INSTALL_COMMIT"
    fi
fi
if [ "$INSTALL_COMMIT" = "$FROZEN_R" ] && ! git -C "$REPO_ROOT" merge-base --is-ancestor "$FROZEN_R" HEAD; then
    echo "ERROR: P4 harness checkout does not contain frozen R" >&2
    exit 2
fi

PILOT_DIR="$(mktemp -d "$HOME/safeyolo-p4-$PLATFORM.XXXXXX")"
export UV_TOOL_DIR="$PILOT_DIR/uv-tools"
export UV_TOOL_BIN_DIR="$PILOT_DIR/bin"
export SAFEYOLO_CONFIG_DIR="$PILOT_DIR/source-instance"
export SAFEYOLO_TEST_CONFIG_DIR="$PILOT_DIR/test-instance"
export SAFEYOLO_P4_OWNER_CONFIG_DIR="$PILOT_DIR/owner-instance"
export SAFEYOLO_P4_SOURCE_CONFIG_DIR="$SAFEYOLO_CONFIG_DIR"
export SAFEYOLO_TEST_AGENT=bbtest
export SAFEYOLO_BLACKBOX_ARTIFACTS_DIR="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$PILOT_DIR/observations}"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_TEST_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export CARGO_BUILD_JOBS=1
unset SAFEYOLO_RUST_PROXY SAFEYOLO_PYTHON_SOURCE SAFEYOLO_TEST_CERT_DIR SAFEYOLO_TEST_KEY_DIR
mkdir -p "$UV_TOOL_DIR" "$UV_TOOL_BIN_DIR" "$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"

cleanup() {
    local result=$?
    local cleanup_failed=0
    trap - EXIT
    rm -f "$SAFEYOLO_TEST_CONFIG_DIR/agents/bbtest/config-share/p4-passthrough-go" || cleanup_failed=1
    if [ -x "$UV_TOOL_BIN_DIR/safeyolo" ]; then
        if [ -f "$SAFEYOLO_P4_OWNER_CONFIG_DIR/config.yaml" ]; then
            if [ -d "$SAFEYOLO_P4_OWNER_CONFIG_DIR/agents/bbowner" ]; then
                SAFEYOLO_CONFIG_DIR="$SAFEYOLO_P4_OWNER_CONFIG_DIR" \
                    SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/coord" SAFEYOLO_SUBNET_BASE=76 \
                    "$UV_TOOL_BIN_DIR/safeyolo" agent stop bbowner >/dev/null 2>&1 || cleanup_failed=1
            fi
            SAFEYOLO_CONFIG_DIR="$SAFEYOLO_P4_OWNER_CONFIG_DIR" \
                SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/coord" \
                "$UV_TOOL_BIN_DIR/safeyolo" stop >/dev/null 2>&1 || cleanup_failed=1
        fi
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
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/data/proxy-readiness.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/proxy-rust.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/proxy-readiness.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_P4_OWNER_CONFIG_DIR/agents/bbowner/container.pid" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/coord/nats/nats.pid.json" ] || cleanup_failed=1
    for owned_socket in "$SAFEYOLO_P4_OWNER_CONFIG_DIR"/data/sockets/*_bbowner/proxy.sock; do
        [ ! -e "$owned_socket" ] || cleanup_failed=1
    done
    [ ! -e "$SAFEYOLO_COORD_DATA_DIR/nats/nats.pid.json" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/sinkhole.pid" ] || cleanup_failed=1
    [ ! -e "$SAFEYOLO_TEST_CONFIG_DIR/native-parent.pid" ] || cleanup_failed=1
    if [ "$cleanup_failed" -ne 0 ]; then
        echo "ERROR: disposable P4/P6 cleanup failed: $SAFEYOLO_TEST_CONFIG_DIR or $SAFEYOLO_P4_OWNER_CONFIG_DIR" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q agent stop bbpeer\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q agent stop bbtest\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q stop\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q SAFEYOLO_COORD_DATA_DIR=%q SAFEYOLO_SUBNET_BASE=76 %q agent stop bbowner\n' \
            "$SAFEYOLO_P4_OWNER_CONFIG_DIR" "$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/coord" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q SAFEYOLO_COORD_DATA_DIR=%q %q stop\n' \
            "$SAFEYOLO_P4_OWNER_CONFIG_DIR" "$SAFEYOLO_P4_OWNER_CONFIG_DIR/data/coord" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        result=1
    fi
    local report="$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR/$PLATFORM-p4.json"
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
    echo "$PLATFORM P4 result: exit $result; records: $SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"
    exit "$result"
}
trap cleanup EXIT

if [ -n "$INSTALL_CHECKOUT" ]; then
    SOURCE_DIR="$(cd "$INSTALL_CHECKOUT" && pwd -P)"
    if [ "$(git -C "$SOURCE_DIR" rev-parse --show-toplevel)" != "$SOURCE_DIR" ] || \
       [ "$SOURCE_DIR" = "$REPO_ROOT" ] || [ ! -f "$SOURCE_DIR/install.sh" ]; then
        echo "ERROR: selected P4 source must be a separate SafeYolo checkout" >&2
        exit 2
    fi
    if [ -n "$(git -C "$SOURCE_DIR" status --porcelain=v1 --untracked-files=all)" ]; then
        echo "ERROR: selected P4 install checkout must be clean" >&2
        exit 2
    fi
else
    SOURCE_DIR="$PILOT_DIR/source-selected"
    git -C "$REPO_ROOT" worktree add --detach "$SOURCE_DIR" "$INSTALL_COMMIT"
fi
if [ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" != "$INSTALL_COMMIT" ]; then
    echo "ERROR: detached P4 install source is not selected commit $INSTALL_COMMIT" >&2
    exit 2
fi

cd "$REPO_ROOT"
"$REPO_ROOT/tests/blackbox/run-lane.sh" "$PLATFORM" \
    --install-checkout "$SOURCE_DIR" --proxy-impl rust --p4 --install-commit "$INSTALL_COMMIT"
