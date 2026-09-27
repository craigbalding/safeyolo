#!/bin/bash
# Run #637 P1 on the operator's disposable Ubuntu 24.04 KVM guest.
# Execute from a clean checkout containing this script. The guest must already
# be reachable through the approved operator harness; this script runs there.
# One invocation keeps its records under ~/safeyolo-kvm-p1.* for inspection.
# Expected: "KVM P1: ... verified" and "KVM P1 result: exit 0". The
# observations/kvm-p1.json record names the installed binary/hash/version,
# authenticated runtime, KVM guest bridge, exact origin marker and local deny.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
FROZEN_R=d229907079695cb464e81273f38d46c42522f57d

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "ERROR: KVM P1 requires the selected Ubuntu x86_64 guest" >&2
    exit 2
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "ERROR: pilot harness checkout must be clean" >&2
    exit 2
fi
if ! git -C "$REPO_ROOT" cat-file -e "$FROZEN_R^{commit}" 2>/dev/null; then
    timeout --signal=TERM --kill-after=10s 90s \
        git -C "$REPO_ROOT" fetch origin feat/rust-proxy-620
fi
if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$FROZEN_R" HEAD; then
    echo "ERROR: current harness checkout does not contain frozen R" >&2
    exit 2
fi

PILOT_DIR="$(mktemp -d "$HOME/safeyolo-kvm-p1.XXXXXX")"
export UV_TOOL_DIR="$PILOT_DIR/uv-tools"
export UV_TOOL_BIN_DIR="$PILOT_DIR/bin"
export SAFEYOLO_CONFIG_DIR="$PILOT_DIR/source-instance"
export SAFEYOLO_TEST_CONFIG_DIR="$PILOT_DIR/test-instance"
export SAFEYOLO_BLACKBOX_ARTIFACTS_DIR="$PILOT_DIR/observations"
export CARGO_BUILD_JOBS=1
unset SAFEYOLO_RUST_PROXY SAFEYOLO_PYTHON_SOURCE
mkdir -p "$UV_TOOL_DIR" "$UV_TOOL_BIN_DIR" "$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"

cleanup() {
    local result=$?
    local cleanup_failed=0
    trap - EXIT
    if [ -x "$UV_TOOL_BIN_DIR/safeyolo" ]; then
        if [ -d "$SAFEYOLO_TEST_CONFIG_DIR/agents/bbtest" ]; then
            SAFEYOLO_CONFIG_DIR="$SAFEYOLO_TEST_CONFIG_DIR" \
                timeout --signal=TERM --kill-after=5s 25s \
                "$UV_TOOL_BIN_DIR/safeyolo" agent stop bbtest >/dev/null 2>&1 || cleanup_failed=1
        fi
        if [ -f "$SAFEYOLO_TEST_CONFIG_DIR/config.yaml" ]; then
            SAFEYOLO_CONFIG_DIR="$SAFEYOLO_TEST_CONFIG_DIR" \
                timeout --signal=TERM --kill-after=5s 25s \
                "$UV_TOOL_BIN_DIR/safeyolo" stop >/dev/null 2>&1 || cleanup_failed=1
        fi
    fi
    if [ -e "$SAFEYOLO_TEST_CONFIG_DIR/agents/bbtest/container.pid" ] || \
       [ -e "$SAFEYOLO_TEST_CONFIG_DIR/data/proxy-rust.json" ]; then
        cleanup_failed=1
    fi
    for owned_socket in "$SAFEYOLO_TEST_CONFIG_DIR"/data/sockets/*_bbtest/proxy.sock; do
        [ ! -e "$owned_socket" ] || cleanup_failed=1
    done
    if [ "$cleanup_failed" -ne 0 ]; then
        echo "ERROR: disposable instance cleanup failed; inspect only $SAFEYOLO_TEST_CONFIG_DIR" >&2
        result=1
    fi
    if [ -f "$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR/kvm-p1.json" ]; then
        if ! python3 - "$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR/kvm-p1.json" "$result" "$cleanup_failed" <<'PY'
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
            echo "ERROR: could not record disposable instance cleanup" >&2
            result=1
        fi
    fi
    echo "KVM P1 result: exit $result; records: $PILOT_DIR/observations"
    exit "$result"
}
trap cleanup EXIT

timeout --signal=TERM --kill-after=10s 60s \
    git -C "$REPO_ROOT" worktree add --detach "$PILOT_DIR/source-R" "$FROZEN_R"
if [ "$(git -C "$PILOT_DIR/source-R" rev-parse HEAD)" != "$FROZEN_R" ]; then
    echo "ERROR: detached install source is not frozen R" >&2
    exit 2
fi

# The whole procedure is bounded to about 38 minutes: at most 2m50s for
# source preparation, 34 minutes for a cold locked Rust build, installation,
# bootstrap, guest launch and probe, and 60 seconds for scoped CLI cleanup.
# The caller's parent proxy and CA environment remains available.
cd "$REPO_ROOT"
timeout --signal=TERM --kill-after=60s 33m \
    "$REPO_ROOT/tests/blackbox/run-lane.sh" kvm \
    --install-checkout "$PILOT_DIR/source-R" \
    --proxy-impl rust --kvm-p1
