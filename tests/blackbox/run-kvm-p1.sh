#!/bin/bash
# Run #637 P1 on the operator's disposable Ubuntu 24.04 KVM guest.
# Execute from a clean checkout containing this script. The guest must already
# be reachable through the approved operator harness; this script runs there.
# One invocation keeps its records under ~/safeyolo-kvm-p1.* for inspection.
# --reuse-pilot DIR reuses a prior verified install and bootstrap from DIR,
# but creates a fresh disposable test instance and checks its runtime again.
# Expected: "KVM P1: ... verified" and "KVM P1 result: exit 0". The
# observations/kvm-p1.json record names the installed binary/hash/version,
# authenticated runtime, KVM guest bridge, exact origin marker and local deny.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
FROZEN_R=0af5c7e22d5e8a45fc321e24eab8355414358f10
REUSE_PILOT=""

if [ "$#" -ne 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != "--reuse-pilot" ] || [ ! -d "$2" ]; then
        echo "Usage: $0 [--reuse-pilot PRIOR_PILOT_DIR]" >&2
        exit 2
    fi
    REUSE_PILOT="$(cd "$2" && pwd -P)"
fi

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
export UV_TOOL_DIR="${REUSE_PILOT:-$PILOT_DIR}/uv-tools"
export UV_TOOL_BIN_DIR="${REUSE_PILOT:-$PILOT_DIR}/bin"
export SAFEYOLO_CONFIG_DIR="${REUSE_PILOT:-$PILOT_DIR}/source-instance"
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

INSTALL_CHECKOUT="${REUSE_PILOT:-$PILOT_DIR}/source-R"
if [ -z "$REUSE_PILOT" ]; then
    timeout --signal=TERM --kill-after=10s 60s \
        git -C "$REPO_ROOT" worktree add --detach "$INSTALL_CHECKOUT" "$FROZEN_R"
fi
if [ "$(git -C "$INSTALL_CHECKOUT" rev-parse HEAD)" != "$FROZEN_R" ]; then
    echo "ERROR: detached install source is not frozen R" >&2
    exit 2
fi

cd "$REPO_ROOT"
if [ -n "$REUSE_PILOT" ]; then
    # The previous attached-runtime observation is the install-path witness.
    # Compare its frozen source, installed wheel and built binary before
    # reusing anything. The new run checks runtime identity and guest traffic.
    python3 - "$REUSE_PILOT" "$FROZEN_R" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

prior = Path(sys.argv[1])
revision = sys.argv[2]
report = json.loads((prior / "observations/installed-rust-runtime.json").read_text())
assert report["status"] == "attached_ready", "prior installed runtime was not verified"
cli = Path(report["cli"]["path"]).resolve()
assert cli == (prior / "bin/safeyolo").resolve(), "prior CLI is not this pilot's installed tool"
assert cli.is_file() and hashlib.sha256(cli.read_bytes()).hexdigest() == report["cli"]["sha256"], (
    "prior installed CLI changed"
)
package = Path(report["cli"]["package_location"]).resolve().parent
package.relative_to((prior / "uv-tools").resolve())
stamp = json.loads((package / "_build_identity.json").read_text())
assert stamp["source_revision"] == revision and stamp["state"] == "known"
packaged = (package / "bin/safeyolo-proxy").resolve()
built = prior / "source-R/proxy/target/release/safeyolo-proxy"
expected = report["candidate"]["sha256"]
assert Path(report["candidate"]["path"]).resolve() == packaged
assert Path(report["runtime"]["actual_executable"]).resolve() == packaged
for binary in (packaged, built):
    assert binary.is_file() and binary.stat().st_mode & 0o111, f"missing executable: {binary}"
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected, f"binary changed: {binary}"
for artifact in ("share", "bin"):
    assert (prior / "source-instance" / artifact).exists(), f"missing bootstrap artifact: {artifact}"
print(f"KVM P1: reusing verified frozen-R install and build from {prior}")
PY
    # Only the current harness's Python development environment is synced.
    # The frozen native build, installed wheel and guest artifacts stay in the
    # prior pilot and are checked again by the attached-runtime probe.
    timeout --signal=TERM --kill-after=10s 3m uv sync --frozen --group dev
    export PATH="$UV_TOOL_BIN_DIR:$REPO_ROOT/.venv/bin:$PATH"
    export SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT="$INSTALL_CHECKOUT"
    unset SAFEYOLO_RUNSC_PLATFORM
    # Reuse has no Cargo build, wheel install or guest bootstrap. Allow 12
    # minutes for native startup, the KVM guest and marker/denial probes.
    timeout --signal=TERM --kill-after=30s 12m \
        "$REPO_ROOT/tests/blackbox/run-tests.sh" \
        --expect-platform kvm --proxy-impl rust --kvm-p1
else
    # Cold path: at most 2m50s for source preparation, 34 minutes for the
    # locked build, install, bootstrap, guest probe and scoped CLI cleanup.
    # The caller's parent proxy and CA environment remains available.
    timeout --signal=TERM --kill-after=60s 33m \
        "$REPO_ROOT/tests/blackbox/run-lane.sh" kvm \
        --install-checkout "$INSTALL_CHECKOUT" \
        --proxy-impl rust --kvm-p1
fi
