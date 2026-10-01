#!/bin/bash
# Run #637 P2 through an installed native proxy and one real Linux guest.
# Use only a disposable supported Ubuntu host with prepared KVM or systrap.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
FROZEN_R=a1f85d90bacdb271fc9681847ad2202b46c0e4ad
PLATFORM="${1:-}"
INSTALL_COMMIT="$FROZEN_R"
if [ "$#" -eq 3 ] && [ "$2" = "--install-commit" ] && [[ "$3" =~ ^[0-9a-f]{40}$ ]]; then
    INSTALL_COMMIT="$3"
elif [ "$#" -ne 1 ]; then
    echo "Usage: $0 {kvm|systrap} [--install-commit FULL_SHA]" >&2
    exit 2
fi

if [ "$PLATFORM" != kvm ] && [ "$PLATFORM" != systrap ]; then
    echo "Usage: $0 {kvm|systrap} [--install-commit FULL_SHA]" >&2
    exit 2
fi
if [ "$(uname -s)" != Linux ] || { [ "$PLATFORM" = kvm ] && [ "$(uname -m)" != x86_64 ]; }; then
    echo "ERROR: selected P2 Linux guest host does not match $PLATFORM" >&2
    exit 2
fi
for program in uv git dpkg-deb ssh-keygen; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "ERROR: P2 host requires $program" >&2
        exit 2
    fi
done
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    echo "ERROR: P2 host requires openssh-server (sshd)" >&2
    exit 2
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "ERROR: pilot harness checkout must be clean" >&2
    exit 2
fi
if ! git -C "$REPO_ROOT" cat-file -e "$INSTALL_COMMIT^{commit}" 2>/dev/null; then
    if [ "$INSTALL_COMMIT" = "$FROZEN_R" ]; then
        timeout --signal=TERM --kill-after=10s 90s \
            git -C "$REPO_ROOT" fetch origin feat/rust-proxy-620
    else
        timeout --signal=TERM --kill-after=10s 90s \
            git -C "$REPO_ROOT" fetch origin "$INSTALL_COMMIT"
    fi
fi
if [ "$INSTALL_COMMIT" = "$FROZEN_R" ] && ! git -C "$REPO_ROOT" merge-base --is-ancestor "$FROZEN_R" HEAD; then
    echo "ERROR: current harness checkout does not contain frozen R" >&2
    exit 2
fi

PILOT_DIR="$(mktemp -d "$HOME/safeyolo-linux-p2-$PLATFORM.XXXXXX")"
export UV_TOOL_DIR="$PILOT_DIR/uv-tools"
export UV_TOOL_BIN_DIR="$PILOT_DIR/bin"
export SAFEYOLO_CONFIG_DIR="$PILOT_DIR/source-instance"
export SAFEYOLO_TEST_CONFIG_DIR="$PILOT_DIR/test-instance"
export SAFEYOLO_TEST_AGENT=bbtest
export SAFEYOLO_BLACKBOX_ARTIFACTS_DIR="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$PILOT_DIR/observations}"
export CARGO_BUILD_JOBS=1
unset SAFEYOLO_RUST_PROXY SAFEYOLO_PYTHON_SOURCE SAFEYOLO_TEST_CERT_DIR SAFEYOLO_TEST_KEY_DIR
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
        echo "ERROR: disposable proxy or guest cleanup failed; inspect $SAFEYOLO_TEST_CONFIG_DIR" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q agent stop bbtest\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        printf 'Cleanup command: SAFEYOLO_CONFIG_DIR=%q %q stop\n' \
            "$SAFEYOLO_TEST_CONFIG_DIR" "$UV_TOOL_BIN_DIR/safeyolo" >&2
        result=1
    fi
    local report="$SAFEYOLO_BLACKBOX_ARTIFACTS_DIR/linux-$PLATFORM-p2.json"
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
            echo "ERROR: could not record disposable instance cleanup" >&2
            result=1
        fi
    fi
    echo "Linux $PLATFORM P2 result: exit $result; records: $SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"
    exit "$result"
}
trap cleanup EXIT

timeout --signal=TERM --kill-after=10s 60s \
    git -C "$REPO_ROOT" worktree add --detach "$PILOT_DIR/source-selected" "$INSTALL_COMMIT"
if [ "$(git -C "$PILOT_DIR/source-selected" rev-parse HEAD)" != "$INSTALL_COMMIT" ]; then
    echo "ERROR: detached install source is not selected commit $INSTALL_COMMIT" >&2
    exit 2
fi

# The parent proxy and CA environment remain available to the installed lane.
cd "$REPO_ROOT"
timeout --signal=TERM --kill-after=60s 40m \
    "$REPO_ROOT/tests/blackbox/run-lane.sh" "$PLATFORM" \
    --install-checkout "$PILOT_DIR/source-selected" \
    --proxy-impl rust --p2 --install-commit "$INSTALL_COMMIT"
