#!/bin/bash
#
# Run SafeYolo blackbox tests (split execution model)
#
# Host-side pytest: proxy functional tests (credential guard, network guard)
# VM-side pytest:   isolation tests (including intended guest-root capability)
#
# Runs as an ISOLATED INSTANCE alongside production SafeYolo:
#   - Separate config dir (~/.safeyolo-test)
#   - Separate ports (proxy 8180, admin 9190 on Linux)
#   - Separate netns slot on Linux (SAFEYOLO_SUBNET_BASE=75 shifts the
#     namespace name so it doesn't collide with production)
#   - Production agents are unaffected
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh --proxy      # Proxy functional tests only
#   ./run-tests.sh --isolation  # VM isolation tests only
#   ./run-tests.sh --expect-platform systrap|kvm|vz
#   ./run-tests.sh --proxy --proxy-impl python|rust|both
#   ./run-tests.sh --expect-platform systrap|kvm|vz --proxy-impl rust
#   ./run-tests.sh --expect-platform kvm --proxy-impl rust --kvm-p1
#   ./run-tests.sh --expect-platform kvm|systrap --proxy-impl rust --p2
#   ./run-tests.sh --expect-platform systrap|vz --proxy-impl rust --p3
#   ./run-tests.sh --expect-platform systrap|vz --proxy-impl rust --p4
#   ./run-tests.sh --expect-platform systrap --proxy-impl rust --p3-config-only
#   ./run-tests.sh --proxy --proxy-impl rust --rust-bin PATH
#   ./run-tests.sh --proxy --proxy-impl python --python-source PATH
#   ./run-tests.sh --proxy -- --collect-only
#   ./run-tests.sh --verbose    # Verbose pytest output
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Infrastructure error
#

set -euo pipefail

CALLER_DIR="$(pwd -P)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

# --- Isolated test instance configuration ---
# These env vars scope all SafeYolo operations to a separate instance
# so blackbox tests don't interfere with production agents.
#
# We preserve the CALLER's SAFEYOLO_CONFIG_DIR as the "source" instance
# that owns the built rootfs + helper binaries (share/, bin/). The test
# instance symlinks to these at provisioning time (lines ~130-145). This
# matters for users whose main SafeYolo install is at a non-default path
# (e.g. SAFEYOLO_CONFIG_DIR=~/.safeyolo-dev via ~/.zshrc): without this,
# run-tests.sh would hardcode ~/.safeyolo as the artifact source -- wrong
# for anyone not running production there.
SAFEYOLO_SOURCE_CONFIG_DIR="${SAFEYOLO_CONFIG_DIR:-$HOME/.safeyolo}"
export SAFEYOLO_CONFIG_DIR="${SAFEYOLO_TEST_CONFIG_DIR:-$HOME/.safeyolo-test}"
export SAFEYOLO_SUBNET_BASE=75
# Logs + flow store scoped to the test instance so blackbox runs
# don't pollute production logs/flows.sqlite3.
export SAFEYOLO_LOGS_DIR="${SAFEYOLO_CONFIG_DIR}/logs"
# Generated public certificates and private keys also belong to the test
# instance. Keeping both outside the checkout and the source instance makes
# --force regeneration harmless to production state and the worktree.
export SAFEYOLO_TEST_CERT_DIR="${SAFEYOLO_TEST_CERT_DIR:-$SAFEYOLO_CONFIG_DIR/test-certs/public}"
export SAFEYOLO_TEST_KEY_DIR="${SAFEYOLO_TEST_KEY_DIR:-$SAFEYOLO_CONFIG_DIR/test-certs/private}"

# Test instance ports (different from production 8080/9090)
TEST_PROXY_PORT=8180
TEST_ADMIN_PORT=9190
TEST_WEB_PORT=8181
SINKHOLE_HTTP_PORT=18080
SINKHOLE_HTTPS_PORT=18443
SINKHOLE_CONTROL_PORT=19999
SINKHOLE_SCRIPT="$SCRIPT_DIR/sinkhole/server.py"

# Parse arguments
RUN_PROXY=true
RUN_ISOLATION=true
VERBOSE=""
AGENT_NAME="${SAFEYOLO_TEST_AGENT:-bbtest}"
EXPECTED_PLATFORM=""
PROXY_IMPL="python"
PROXY_IMPL_SELECTED=false
PYTHON_SOURCE=""
RUST_BIN=""
KVM_P1=false
P2=false
P3=false
P4=false
P3_CONFIG_ONLY=false
INSTALL_COMMIT=""
PYTEST_FORWARD_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --proxy)
            RUN_ISOLATION=false
            shift
            ;;
        --isolation)
            RUN_PROXY=false
            shift
            ;;
        --verbose|-v)
            VERBOSE="-v"
            shift
            ;;
        --expect-platform)
            if [ "$#" -lt 2 ]; then
                echo "ERROR: --expect-platform requires systrap, kvm, or vz" >&2
                exit 2
            fi
            EXPECTED_PLATFORM="$2"
            case "$EXPECTED_PLATFORM" in
                systrap|kvm|vz) ;;
                *)
                    echo "ERROR: unsupported platform '$EXPECTED_PLATFORM'" >&2
                    exit 2
                    ;;
            esac
            shift 2
            ;;
        --proxy-impl)
            if [ "$#" -lt 2 ]; then
                echo "ERROR: --proxy-impl requires python, rust, or both" >&2
                exit 2
            fi
            PROXY_IMPL="$2"
            case "$PROXY_IMPL" in
                python|rust|both) ;;
                *)
                    echo "ERROR: unsupported proxy implementation '$PROXY_IMPL'" >&2
                    exit 2
                    ;;
            esac
            PROXY_IMPL_SELECTED=true
            shift 2
            ;;
        --python-source)
            if [ "$#" -lt 2 ]; then
                echo "ERROR: --python-source requires a checkout path" >&2
                exit 2
            fi
            PYTHON_SOURCE="$2"
            shift 2
            ;;
        --rust-bin)
            if [ "$#" -lt 2 ]; then
                echo "ERROR: --rust-bin requires an executable path" >&2
                exit 2
            fi
            RUST_BIN="$2"
            shift 2
            ;;
        --kvm-p1)
            KVM_P1=true
            shift
            ;;
        --p2)
            P2=true
            shift
            ;;
        --p3)
            P3=true
            shift
            ;;
        --p4)
            P4=true
            shift
            ;;
        --install-commit)
            if [ "$#" -lt 2 ] || [[ ! "$2" =~ ^[0-9a-f]{40}$ ]]; then
                echo "ERROR: --install-commit requires a full lowercase commit SHA" >&2
                exit 2
            fi
            INSTALL_COMMIT="$2"
            shift 2
            ;;
        --p3-config-only)
            P3=true
            P3_CONFIG_ONLY=true
            shift
            ;;
        --)
            shift
            PYTEST_FORWARD_ARGS=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: ./run-tests.sh [--proxy|--isolation] [--proxy-impl python|rust|both] [--expect-platform PLATFORM] [--verbose] [-- PYTEST_ARGS...]"
            exit 2
            ;;
    esac
done

if [ -n "$INSTALL_COMMIT" ] && [ "$P2" != true ] && [ "$P3" != true ] && [ "$P4" != true ]; then
    echo "ERROR: --install-commit requires a P2, P3, or P4 installed selection" >&2
    exit 2
fi
INSTALL_COMMIT_ARGS=()
if [ -n "$INSTALL_COMMIT" ]; then
    INSTALL_COMMIT_ARGS=(--install-commit "$INSTALL_COMMIT")
fi

if [ "$KVM_P1" = true ] && { [ "$EXPECTED_PLATFORM" != "kvm" ] || \
   [ "$PROXY_IMPL" != "rust" ] || [ "$RUN_PROXY" != true ] || \
   [ "$RUN_ISOLATION" != true ] || [ "${#PYTEST_FORWARD_ARGS[@]}" -ne 0 ]; }; then
    echo "ERROR: --kvm-p1 requires --expect-platform kvm --proxy-impl rust and no suite override" >&2
    exit 2
fi
if [ "$P2" = true ] && { [ "$KVM_P1" = true ] || \
   [ "$P3" = true ] || [ "$P4" = true ] || \
   { [ "$EXPECTED_PLATFORM" != "kvm" ] && [ "$EXPECTED_PLATFORM" != "systrap" ]; } || \
   [ "$PROXY_IMPL" != "rust" ] || [ "$RUN_PROXY" != true ] || \
   [ "$RUN_ISOLATION" != true ] || [ "${#PYTEST_FORWARD_ARGS[@]}" -ne 0 ]; }; then
    echo "ERROR: --p2 requires --expect-platform kvm|systrap --proxy-impl rust and no suite override" >&2
    exit 2
fi
if [ "$P3" = true ] && { [ "$KVM_P1" = true ] || [ "$P4" = true ] || \
   { [ "$EXPECTED_PLATFORM" != "systrap" ] && [ "$EXPECTED_PLATFORM" != "vz" ]; } || \
   [ "$PROXY_IMPL" != "rust" ] || [ "$RUN_PROXY" != true ] || \
   [ "$RUN_ISOLATION" != true ] || [ "${#PYTEST_FORWARD_ARGS[@]}" -ne 0 ]; }; then
    echo "ERROR: --p3 requires --expect-platform systrap|vz --proxy-impl rust and no suite override" >&2
    exit 2
fi
if [ "$P4" = true ] && { [ "$KVM_P1" = true ] || \
   { [ "$EXPECTED_PLATFORM" != "systrap" ] && [ "$EXPECTED_PLATFORM" != "vz" ]; } || \
   [ "$PROXY_IMPL" != "rust" ] || [ "$RUN_PROXY" != true ] || \
   [ "$RUN_ISOLATION" != true ] || [ "${#PYTEST_FORWARD_ARGS[@]}" -ne 0 ]; }; then
    echo "ERROR: --p4 requires --expect-platform systrap|vz --proxy-impl rust and no suite override" >&2
    exit 2
fi

# The physical VZ test account has six assigned localhost TCP ports. All
# native selections use one HTTP fixture listener for parent, origin, and
# control requests; the HTTPS fixture selects certificate chains by SNI.
VZ_FIXED_PORTS=false
if [ "$EXPECTED_PLATFORM" = "vz" ] && [ "$PROXY_IMPL" = "rust" ]; then
    VZ_FIXED_PORTS=true
    TEST_PROXY_PORT=46370
    TEST_ADMIN_PORT=46371
    TEST_WEB_PORT=46372
    SINKHOLE_HTTP_PORT=46373
    SINKHOLE_HTTPS_PORT=46374
    SINKHOLE_CONTROL_PORT=46373
    SINKHOLE_SCRIPT="$SCRIPT_DIR/harness/vz_fixture.py"
    # Rust uses agent UDS listeners; 46370 and 46372 are available for
    # this disposable instance's NATS client and ownership monitor.
    export SAFEYOLO_NATS_TEST_PORTS=46370,46372
    export SAFEYOLO_P4_OWNER_ADMIN_PORT=46375
fi
export PROXY_URL="http://127.0.0.1:${TEST_PROXY_PORT}"
export ADMIN_URL="http://127.0.0.1:${TEST_ADMIN_PORT}"
export SINKHOLE_API="http://127.0.0.1:${SINKHOLE_CONTROL_PORT}"
export SINKHOLE_RECEIVER="http://127.0.0.1:${SINKHOLE_HTTP_PORT}"
export SAFEYOLO_SINKHOLE_HTTP_PORT="$SINKHOLE_HTTP_PORT"
export SAFEYOLO_SINKHOLE_HTTPS_PORT="$SINKHOLE_HTTPS_PORT"

# Command-line paths are interpreted relative to the caller's directory even
# though the legacy runner changes into tests/blackbox for its setup.
if [ -n "$PYTHON_SOURCE" ] && [[ "$PYTHON_SOURCE" != /* ]] && [[ "$PYTHON_SOURCE" != "~/"* ]]; then
    PYTHON_SOURCE="$CALLER_DIR/$PYTHON_SOURCE"
fi
if [ -n "$RUST_BIN" ] && [[ "$RUST_BIN" != /* ]] && [[ "$RUST_BIN" != "~/"* ]]; then
    RUST_BIN="$CALLER_DIR/$RUST_BIN"
fi

# The VM compatibility lane accepts a command string, so quote forwarded
# pytest arguments before embedding them in that string.  Host-side pytest
# calls below continue to use the original array directly.
PYTEST_FORWARD_SHELL=""
# macOS /bin/bash 3.2 treats an empty array expansion as unbound under -u.
# The + form expands to zero arguments for an empty array on both host shells.
for forwarded_arg in "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}"; do
    printf -v quoted_arg '%q' "$forwarded_arg"
    PYTEST_FORWARD_SHELL+=" $quoted_arg"
done

# The focused migration harness owns explicit proxy-only backend runs. It
# launches a new process for each fixture. A VM lane below instead uses one
# installed CLI process for both host and guest tests.
if [ "$RUN_PROXY" = true ] && [ "$RUN_ISOLATION" = false ] && \
   { [ "$PROXY_IMPL_SELECTED" = true ] || [ -n "$PYTHON_SOURCE" ] || [ -n "$RUST_BIN" ]; }; then
    if ! command -v pytest &>/dev/null; then
        echo "ERROR: pytest is required for selected proxy backend tests" >&2
        exit 2
    fi
    ARTIFACTS_DIR="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts}"
    mkdir -p "$ARTIFACTS_DIR"
    SELECTED_BACKENDS=()
    case "$PROXY_IMPL" in
        python|rust) SELECTED_BACKENDS=("$PROXY_IMPL") ;;
        both) SELECTED_BACKENDS=(python rust) ;;
    esac
    if [ -n "$EXPECTED_PLATFORM" ]; then
        echo "ERROR: --expect-platform cannot be combined with the proxy-only backend selector" >&2
        exit 2
    fi
    if [ -n "$PYTHON_SOURCE" ]; then
        PYTHON_SOURCE_REAL="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$PYTHON_SOURCE")"
        export SAFEYOLO_PYTHON_SOURCE="$PYTHON_SOURCE_REAL"
    else
        unset SAFEYOLO_PYTHON_SOURCE || true
    fi
    if [ -n "$RUST_BIN" ]; then
        RUST_BIN_REAL="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$RUST_BIN")"
        export SAFEYOLO_RUST_PROXY="$RUST_BIN_REAL"
    fi
    PYTEST_ARGS=(--tb=short --timeout=120)
    if [ "$VERBOSE" = "-v" ]; then
        PYTEST_ARGS+=("-v")
    fi
    if [ "${#PYTEST_FORWARD_ARGS[@]}" -gt 0 ]; then
        PYTEST_ARGS+=("${PYTEST_FORWARD_ARGS[@]}")
    fi
    test_failure=false
    infrastructure_failure=false
    for backend in "${SELECTED_BACKENDS[@]}"; do
        evidence="$ARTIFACTS_DIR/proxy-${backend}-runtime.json"
        junit="$ARTIFACTS_DIR/proxy-${backend}-junit.xml"
        selector_args=(--test-suite-root "$REPO_ROOT")
        if [ "$backend" = "python" ] && [ -n "$PYTHON_SOURCE" ]; then
            selector_args+=(--python-source "$PYTHON_SOURCE")
        fi
        if [ "$backend" = "rust" ] && [ -n "$RUST_BIN" ]; then
            selector_args+=(--rust-bin "$RUST_BIN")
        fi
        echo "=== Selected proxy backend: $backend ==="
        echo "  Runtime evidence: $ARTIFACTS_DIR/proxy-${backend}-runtime.json"
        # Validate immediately before this backend's independent process run.
        # A missing second backend must leave the first run's evidence intact
        # and must not prevent the remaining selected backends from running.
        if ! python3 "$SCRIPT_DIR/proxy_backend.py" --backend "$backend" \
            "${selector_args[@]}" --output "$evidence"; then
            if [ "$backend" = "python" ]; then
                # A rejected comparator cannot affect the independent Rust run.
                unset SAFEYOLO_PYTHON_SOURCE || true
            fi
            echo "Infrastructure failure selecting proxy backend '$backend'; continuing" >&2
            infrastructure_failure=true
            continue
        fi
        set +e
        pytest "${PYTEST_ARGS[@]}" \
            --junitxml="$junit" \
            "$REPO_ROOT/tests/proxy_migration" --proxy-backend "$backend"
        backend_result=$?
        set -e
        case "$backend_result" in
            0) ;;
            1)
                # The migration conftest promotes ReadinessError to pytest
                # code 2.  Keep this JUnit check as a guard for older/custom
                # pytest plugins that leave a readiness failure as code 1.
                if [ -s "$junit" ] && grep -Eq 'ReadinessError|Readiness timed out' "$junit"; then
                    infrastructure_failure=true
                else
                    test_failure=true
                fi
                ;;
            2|3|4|5|*)
                infrastructure_failure=true
                ;;
        esac
    done
    if [ "$infrastructure_failure" = true ]; then
        exit 2
    fi
    if [ "$test_failure" = true ]; then
        exit 1
    fi
    exit 0
fi

if [ "$PROXY_IMPL" = "both" ] || [ -n "$PYTHON_SOURCE" ] || [ -n "$RUST_BIN" ]; then
    echo "ERROR: VM lanes select one installed backend; source and binary overrides require --proxy" >&2
    exit 2
fi

export SAFEYOLO_BLACKBOX_PROXY_BACKEND="$PROXY_IMPL"
INSTALLED_CLI=""
INSTALLED_RUST_BIN=""
if [ "$PROXY_IMPL" = "rust" ] && [ "$P3_CONFIG_ONLY" = false ]; then
    INSTALLED_CLI="$(command -v safeyolo || true)"
    if [ -z "$INSTALLED_CLI" ]; then
        echo "ERROR: the installed safeyolo CLI is required for the native VM lane" >&2
        exit 2
    fi
    if ! INSTALLED_RUST_BIN="$(python3 - "$SCRIPT_DIR" "$INSTALLED_CLI" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from installed_host_smoke import _installed_rust_binary

binary, _ = _installed_rust_binary(sys.argv[2])
print(binary)
PY
)"; then
        echo "ERROR: the installed CLI has no usable packaged Rust proxy" >&2
        exit 2
    fi
    # Exercise the installed CLI's package lookup on every start. The attached
    # runtime observation below rejects any process other than this binary.
    unset SAFEYOLO_RUST_PROXY || true
fi

echo "=== SafeYolo Blackbox Tests ==="
echo "  Instance: $SAFEYOLO_CONFIG_DIR"
echo "  Proxy:    localhost:$TEST_PROXY_PORT  Admin: localhost:$TEST_ADMIN_PORT  Web: localhost:$TEST_WEB_PORT"
echo "  Netns base: SAFEYOLO_SUBNET_BASE=${SAFEYOLO_SUBNET_BASE}"
echo ""

# --- Phase 0: Prerequisites ---

if ! command -v safeyolo &>/dev/null; then
    echo "ERROR: safeyolo CLI not found. Activate the venv or install."
    exit 2
fi

# This script removes and recreates agent state beneath the test instance.
# Refuse ambiguous or aliased targets before performing any mutation.
SOURCE_CONFIG_REAL="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$SAFEYOLO_SOURCE_CONFIG_DIR")"
TEST_CONFIG_REAL="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$SAFEYOLO_CONFIG_DIR")"
HOME_REAL="$(python3 -c 'import pathlib; print(pathlib.Path.home().resolve())')"
if [ "$TEST_CONFIG_REAL" = "$SOURCE_CONFIG_REAL" ] || \
   [ "$TEST_CONFIG_REAL" = "$HOME_REAL" ] || \
   [ "$TEST_CONFIG_REAL" = "/" ]; then
    echo "ERROR: blackbox test config is not isolated: $TEST_CONFIG_REAL" >&2
    echo "       Source/live config resolves to: $SOURCE_CONFIG_REAL" >&2
    exit 2
fi

if [ -n "$EXPECTED_PLATFORM" ] && [ "$RUN_ISOLATION" != true ]; then
    echo "ERROR: --expect-platform requires the isolation suite" >&2
    exit 2
fi

# Initialize test config dir on first run
if [ ! -f "$SAFEYOLO_CONFIG_DIR/config.yaml" ]; then
    echo "Initializing test instance at $SAFEYOLO_CONFIG_DIR..."
    safeyolo init --no-interactive
    echo ""
fi

if [ "$KVM_P1" = true ] || [ "$P2" = true ]; then
    # This rule belongs only to the disposable instance and is loaded before
    # the native process starts. The owned parent maps evil.com to the same
    # sinkhole, so its absence there is a meaningful denial observation.
    safeyolo policy host deny evil.com
fi
if [ "$P2" = true ]; then
    safeyolo policy host add failing.test
fi
if [ "$P4" = true ]; then
    safeyolo policy host deny evil.com
    safeyolo policy host add failing.test
    safeyolo policy host add future-leaf.test
    safeyolo policy host add example-chain-test.test
    safeyolo policy host add wrong-san.test
    safeyolo policy host add self-signed.test
    safeyolo policy host add expired-leaf.test
fi
if [ "$P3" = true ]; then
    export SAFEYOLO_COORD_DATA_DIR="${SAFEYOLO_COORD_DATA_DIR:-$SAFEYOLO_CONFIG_DIR/data/coord}"
    export SAFEYOLO_NATS_TEST_INSTANCE="${SAFEYOLO_NATS_TEST_INSTANCE:-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')}"
    python3 "$SCRIPT_DIR/p3_setup.py" "$SAFEYOLO_CONFIG_DIR"
fi

# Restore a parent selected by an interrupted native run before reading or
# changing this disposable instance's configuration.
python3 "$SCRIPT_DIR/harness/native_parent_config.py" restore "$SAFEYOLO_CONFIG_DIR"

# Configure test-specific ports in config.yaml
python3 -c "
import yaml
from pathlib import Path
config_path = Path('$SAFEYOLO_CONFIG_DIR/config.yaml')
config = yaml.safe_load(config_path.read_text())
# Keep the selected backend in the isolated instance across CLI restarts.
config['proxy']['backend'] = '$PROXY_IMPL'
config['proxy']['port'] = $TEST_PROXY_PORT
config['proxy']['admin_port'] = $TEST_ADMIN_PORT
config['proxy']['web_port'] = $TEST_WEB_PORT
config['test']['sinkhole_router'] = '$SCRIPT_DIR/harness/sinkhole_router.py'
config['test']['ca_cert'] = '$SAFEYOLO_TEST_CERT_DIR/ca.crt'
config_path.write_text(yaml.dump(config, default_flow_style=False))
"

# Configure test_context targets before the native process starts. P3's
# basic and contract hosts send no context header; its explicit context
# header still opts the non-target request into provenance and recording.
python3 -c "
import yaml
from pathlib import Path
addons_path = Path('$SAFEYOLO_CONFIG_DIR/addons.yaml')
addons = yaml.safe_load(addons_path.read_text())
if '$P3' == 'true':
    targets = ['failing.test']
else:
    targets = ['httpbin.org']
if '$P2' == 'true':
    targets.append('failing.test')
addons.setdefault('addons', {}).setdefault('test_context', {})['target_hosts'] = targets
addons_path.write_text(yaml.dump(addons, default_flow_style=False))
"

# Focused launcher probe: the final addon file above is the one the installed
# proxy would load. No proxy, fixture, or guest has been started yet.
if [ "$P3_CONFIG_ONLY" = true ]; then
    echo "P3 configuration prepared; no proxy or guest started"
    exit 0
fi

# Symlink shared guest artifacts (rootfs, kernel) from the caller's
# source instance. init creates an empty share/ dir — replace it with
# a symlink. Using SAFEYOLO_SOURCE_CONFIG_DIR (caller's env) means
# `SAFEYOLO_CONFIG_DIR=~/.safeyolo-dev ./run-tests.sh` borrows artifacts
# from ~/.safeyolo-dev, not hardcoded ~/.safeyolo.
PROD_SHARE="$SAFEYOLO_SOURCE_CONFIG_DIR/share"
TEST_SHARE="$SAFEYOLO_CONFIG_DIR/share"
if [ -d "$PROD_SHARE" ] && [ ! -L "$TEST_SHARE" ]; then
    rm -rf "$TEST_SHARE"
    ln -s "$PROD_SHARE" "$TEST_SHARE"
    echo "  Linked guest artifacts: $TEST_SHARE -> $PROD_SHARE"
fi

# Symlink host binaries (safeyolo-vm + vsock-term) from the caller's
# source instance -- same reasoning as share/.
PROD_BIN="$SAFEYOLO_SOURCE_CONFIG_DIR/bin"
TEST_BIN="$SAFEYOLO_CONFIG_DIR/bin"
if [ -d "$PROD_BIN" ] && [ ! -L "$TEST_BIN" ]; then
    rm -rf "$TEST_BIN"
    ln -s "$PROD_BIN" "$TEST_BIN"
    echo "  Linked binaries: $TEST_BIN -> $PROD_BIN"
fi

# Capture and assert the selected runtime before producing isolation evidence.
# Doctor may report unrelated non-fatal setup findings for the isolated test
# config, so this gate deliberately validates the named platform check itself.
if [ -n "$EXPECTED_PLATFORM" ]; then
    ARTIFACTS_DIR="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts}"
    mkdir -p "$ARTIFACTS_DIR"
    DOCTOR_JSON="$ARTIFACTS_DIR/doctor.json"
    DOCTOR_STDERR="$ARTIFACTS_DIR/doctor.stderr"
    safeyolo doctor --json >"$DOCTOR_JSON" 2>"$DOCTOR_STDERR" || true
    if ! python3 "$SCRIPT_DIR/assert-platform.py" "$EXPECTED_PLATFORM" "$DOCTOR_JSON"; then
        echo "ERROR: runtime platform assertion failed" >&2
        [ ! -s "$DOCTOR_STDERR" ] || sed -n '1,80p' "$DOCTOR_STDERR" >&2
        exit 2
    fi
fi

echo "Generating test certificates..."
if ! ./certs/generate-certs.sh --force; then
    echo "ERROR: Failed to generate test certificates"
    exit 2
fi

# --- Track what we started (only clean up our own) ---

STARTED_SINKHOLE=false
STARTED_PARENT=false
STARTED_PROXY=false
STARTED_VM=false
SINKHOLE_PID=""
SINKHOLE_PID_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.pid"
SINKHOLE_ARGV_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.argv"
PARENT_PID=""
PARENT_PID_FILE="$SAFEYOLO_CONFIG_DIR/native-parent.pid"
PARENT_ARGV_FILE="$SAFEYOLO_CONFIG_DIR/native-parent.argv"
PARENT_PORT_FILE="$SAFEYOLO_CONFIG_DIR/native-parent.port"
HOST_LISTENER_PID=""

canonical_path() {
    local candidate="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -- "$candidate" 2>/dev/null
    else
        python3 - "$candidate" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).expanduser().resolve(strict=True))
PY
    fi
}

process_start_identity() {
    local pid="$1"
    if [ -r "/proc/$pid/stat" ]; then
        python3 - "$pid" <<'PY'
from pathlib import Path
import sys

try:
    stat = Path(f"/proc/{sys.argv[1]}/stat").read_text()
    fields = stat.rsplit(") ", 1)[1].split()
    print(fields[19])
except (IndexError, OSError, ValueError):
    raise SystemExit(1)
PY
    elif [ "$(uname -s)" = "Darwin" ]; then
        python3 - "$pid" <<'PY'
import sys

from safeyolo.runtime_identity import process_start_token

token = process_start_token(int(sys.argv[1]))
if token is None:
    raise SystemExit(1)
print(token)
PY
    else
        ps -p "$pid" -o lstart= 2>/dev/null | sed 's/[[:space:]]*$//'
    fi
}

process_argv_bytes() {
    local pid="$1"
    if [ -r "/proc/$pid/cmdline" ]; then
        cat "/proc/$pid/cmdline"
    elif [ "$(uname -s)" = "Darwin" ]; then
        python3 "$SCRIPT_DIR/harness/macos_process_argv.py" "$pid"
    else
        return 1
    fi
}

capture_process_argv() {
    local pid="$1"
    local output="$2"
    if [ -r "/proc/$pid/cmdline" ] || [ "$(uname -s)" = "Darwin" ]; then
        process_argv_bytes "$pid" > "$output"
    else
        # Retain the portable ps fallback for other Unix hosts. The saved
        # line is compared byte-for-byte below, not searched as a substring.
        ps -p "$pid" -o command= > "$output"
    fi
}

process_script_matches() {
    local pid="$1"
    local executable="$2"
    local expected actual token
    expected="$(canonical_path "$executable")" || return 1
    if [ -r "/proc/$pid/cmdline" ] || [ "$(uname -s)" = "Darwin" ]; then
        local -a argv=()
        while IFS= read -r -d '' token; do
            argv+=("$token")
        done < <(process_argv_bytes "$pid")
        [ "${#argv[@]}" -ge 2 ] || return 1
        actual="$(canonical_path "${argv[1]}")" || return 1
    else
        local command_line interpreter script
        command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
        read -r interpreter script _ <<< "$command_line"
        [ -n "${interpreter:-}" ] && [ -n "${script:-}" ] || return 1
        actual="$(canonical_path "$script")" || return 1
    fi
    [ "$actual" = "$expected" ]
}

process_argv_matches() {
    local pid="$1"
    local saved_argv="$2"
    local current_file status
    [ -s "$saved_argv" ] || return 1
    if [ -r "/proc/$pid/cmdline" ] || [ "$(uname -s)" = "Darwin" ]; then
        # Snapshot the current arguments before comparing: procfs can report
        # a changing pseudo-file size to cmp.
        current_file="$(mktemp "${TMPDIR:-/tmp}/safeyolo-argv.XXXXXX")" || return 1
        if ! process_argv_bytes "$pid" > "$current_file"; then
            rm -f "$current_file"
            return 1
        fi
        if cmp -s "$current_file" "$saved_argv"; then
            status=0
        else
            status=$?
        fi
        rm -f "$current_file"
        return "$status"
    else
        local current_argv
        current_argv="$(ps -p "$pid" -o command= 2>/dev/null || true)"
        cmp -s <(printf '%s\n' "$current_argv") "$saved_argv"
    fi
}

stop_owned_pid_file() {
    local pid_file="$1"
    local executable="$2"
    local argv_file="${3:-}"
    local pid recorded_start current_start

    if [ ! -f "$pid_file" ]; then
        return 0
    fi
    pid="$(sed -n '1p' "$pid_file" 2>/dev/null || true)"
    recorded_start="$(sed -n '2p' "$pid_file" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [ -n "$recorded_start" ] && \
       kill -0 "$pid" 2>/dev/null; then
        current_start="$(process_start_identity "$pid" 2>/dev/null || true)"
        if [ -n "$current_start" ] && [ "$recorded_start" = "$current_start" ] && \
           process_script_matches "$pid" "$executable" && \
           process_argv_matches "$pid" "$argv_file"; then
            echo "Stopping owned process $pid ($executable)..."
            kill "$pid" 2>/dev/null || true
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$pid" 2>/dev/null; then
                echo "Escalating owned process $pid ($executable) to KILL"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    fi
    rm -f "$pid_file"
    if [ -n "$argv_file" ]; then
        rm -f "$argv_file"
    fi
}

cleanup() {
    # Stop processes only — leave state (logs, flows.sqlite3, agent_map,
    # config) intact for post-mortem analysis of failures.
    echo ""
    echo "=== Cleanup ==="

    if [ "$STARTED_VM" = true ]; then
        echo "Stopping $AGENT_NAME..."
        safeyolo agent stop "$AGENT_NAME" 2>/dev/null || true
    fi

    if [ "$STARTED_PROXY" = true ]; then
        echo "Stopping test proxy..."
        safeyolo stop 2>/dev/null || true
    fi

    if [ -n "$PARENT_PID" ] && [ "$STARTED_PARENT" = true ]; then
        echo "Stopping native fixture parent (PID $PARENT_PID)..."
        kill "$PARENT_PID" 2>/dev/null || true
        wait "$PARENT_PID" 2>/dev/null || true
        rm -f "$PARENT_PID_FILE" "$PARENT_ARGV_FILE" "$PARENT_PORT_FILE"
    fi

    if [ -n "$SINKHOLE_PID" ] && [ "$STARTED_SINKHOLE" = true ]; then
        echo "Stopping sinkhole (PID $SINKHOLE_PID)..."
        kill "$SINKHOLE_PID" 2>/dev/null || true
        wait "$SINKHOLE_PID" 2>/dev/null || true
        rm -f "$SINKHOLE_PID_FILE"
        rm -f "$SINKHOLE_ARGV_FILE"
    fi

    if [ -n "$HOST_LISTENER_PID" ]; then
        echo "Stopping host listener (PID $HOST_LISTENER_PID)..."
        kill "$HOST_LISTENER_PID" 2>/dev/null || true
        wait "$HOST_LISTENER_PID" 2>/dev/null || true
    fi

    if [ "$PROXY_IMPL" = "rust" ]; then
        python3 "$SCRIPT_DIR/harness/native_parent_config.py" restore "$SAFEYOLO_CONFIG_DIR"
    fi

    echo "Cleanup complete"
}
trap cleanup EXIT

# --- Clean stale state from previous run ---
# Done at start (not end) so post-mortem analysis of failures is possible.
echo "Cleaning stale state..."
safeyolo agent stop "$AGENT_NAME" 2>/dev/null || true
safeyolo agent remove "$AGENT_NAME" 2>/dev/null || true
rm -rf "$SAFEYOLO_CONFIG_DIR/agents/"
rm -f "$SAFEYOLO_CONFIG_DIR/logs/flows.sqlite3"
# Recover only a sinkhole process owned by a previous run.  The PID file and
# command-path check prevent an unrelated process or another test instance
# from being stopped.
stop_owned_pid_file "$SINKHOLE_PID_FILE" "$SINKHOLE_SCRIPT" "$SINKHOLE_ARGV_FILE"
stop_owned_pid_file "$PARENT_PID_FILE" "$SCRIPT_DIR/harness/sinkhole_parent.py" "$PARENT_ARGV_FILE"
rm -f "$PARENT_PORT_FILE"
safeyolo stop 2>/dev/null || true

# --- Phase 1: Start infrastructure (idempotent) ---

# Sinkhole (shared — not instance-specific)
if { [ "$P2" = true ] || [ "$P3" = true ] || [ "$P4" = true ] || [ "$VZ_FIXED_PORTS" = true ]; } && \
   curl -sf "$SINKHOLE_API/health" >/dev/null 2>&1; then
    echo "ERROR: selected lane requires its own owned sinkhole; control port $SINKHOLE_CONTROL_PORT is already in use" >&2
    exit 2
fi
if curl -sf "$SINKHOLE_API/health" >/dev/null 2>&1; then
    echo "Sinkhole already running"
else
    echo "Starting sinkhole..."
    P2_SINKHOLE_ARGS=()
    P4_CERT_ARGS=()
    if [ "$P2" = true ] || [ "$P3" = true ] || [ "$P4" = true ]; then
        rm -rf "$SAFEYOLO_CONFIG_DIR/p2-fixture"
        mkdir -m 0700 "$SAFEYOLO_CONFIG_DIR/p2-fixture"
        P2_SINKHOLE_ARGS=(--p2-dir "$SAFEYOLO_CONFIG_DIR/p2-fixture")
    fi
    if [ "$P4" = true ]; then
        P4_CERT_ARGS=(--extra-cert "future:18452:$SAFEYOLO_TEST_CERT_DIR/future_chain.pem:$SAFEYOLO_TEST_KEY_DIR/future_chain.key")
    fi
    if [ "$VZ_FIXED_PORTS" = true ]; then
        ORIGINAL_PARENT="$(python3 "$SCRIPT_DIR/harness/native_parent_config.py" current "$SAFEYOLO_CONFIG_DIR")"
        ORIGINAL_PARENT_CA="$(python3 "$SCRIPT_DIR/harness/native_parent_config.py" current-ca "$SAFEYOLO_CONFIG_DIR")"
        VZ_PARENT_ARGS=()
        [ -z "$ORIGINAL_PARENT" ] || VZ_PARENT_ARGS+=(--parent "$ORIGINAL_PARENT")
        [ -z "$ORIGINAL_PARENT_CA" ] || VZ_PARENT_ARGS+=(--ca-file "$ORIGINAL_PARENT_CA")
        PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 "$SINKHOLE_SCRIPT" \
            --http-port "$SINKHOLE_HTTP_PORT" --https-port "$SINKHOLE_HTTPS_PORT" \
            --cert "$SAFEYOLO_TEST_CERT_DIR/sinkhole.crt" \
            --key "$SAFEYOLO_TEST_KEY_DIR/sinkhole.key" \
            --extra-cert "example-chain-test.test:$SAFEYOLO_TEST_CERT_DIR/ecc_chain.pem:$SAFEYOLO_TEST_KEY_DIR/ecc_chain.key" \
            --extra-cert "rsa-deep-chain.test:$SAFEYOLO_TEST_CERT_DIR/rsa_deep_chain.pem:$SAFEYOLO_TEST_KEY_DIR/rsa_deep_chain.key" \
            --extra-cert "nc-constrained.test:$SAFEYOLO_TEST_CERT_DIR/nc_chain.pem:$SAFEYOLO_TEST_KEY_DIR/nc_chain.key" \
            --extra-cert "extra-intermediates.test:$SAFEYOLO_TEST_CERT_DIR/extra_chain.pem:$SAFEYOLO_TEST_KEY_DIR/extra_chain.key" \
            --extra-cert "expired-leaf.test:$SAFEYOLO_TEST_CERT_DIR/expired_chain.pem:$SAFEYOLO_TEST_KEY_DIR/expired_chain.key" \
            --extra-cert "wrong-san.test:$SAFEYOLO_TEST_CERT_DIR/wrong_san_chain.pem:$SAFEYOLO_TEST_KEY_DIR/wrong_san_chain.key" \
            --extra-cert "self-signed.test:$SAFEYOLO_TEST_CERT_DIR/self_signed_chain.pem:$SAFEYOLO_TEST_KEY_DIR/self_signed_chain.key" \
            --extra-cert "aia-only.test:$SAFEYOLO_TEST_CERT_DIR/aia_chain.pem:$SAFEYOLO_TEST_KEY_DIR/aia_chain.key" \
            --extra-cert "future-leaf.test:$SAFEYOLO_TEST_CERT_DIR/future_chain.pem:$SAFEYOLO_TEST_KEY_DIR/future_chain.key" \
            "${P2_SINKHOLE_ARGS[@]+"${P2_SINKHOLE_ARGS[@]}"}" \
            "${VZ_PARENT_ARGS[@]+"${VZ_PARENT_ARGS[@]}"}" &
    else
    PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 "$SINKHOLE_SCRIPT" \
        --http-port "$SINKHOLE_HTTP_PORT" \
        --https-port "$SINKHOLE_HTTPS_PORT" \
        --control-port "$SINKHOLE_CONTROL_PORT" \
        --cert "$SAFEYOLO_TEST_CERT_DIR/sinkhole.crt" \
        --key "$SAFEYOLO_TEST_KEY_DIR/sinkhole.key" \
        --extra-cert "ecc-chain:18444:$SAFEYOLO_TEST_CERT_DIR/ecc_chain.pem:$SAFEYOLO_TEST_KEY_DIR/ecc_chain.key" \
        --extra-cert "rsa-deep:18445:$SAFEYOLO_TEST_CERT_DIR/rsa_deep_chain.pem:$SAFEYOLO_TEST_KEY_DIR/rsa_deep_chain.key" \
        --extra-cert "nc-constrained:18446:$SAFEYOLO_TEST_CERT_DIR/nc_chain.pem:$SAFEYOLO_TEST_KEY_DIR/nc_chain.key" \
        --extra-cert "extra-ints:18447:$SAFEYOLO_TEST_CERT_DIR/extra_chain.pem:$SAFEYOLO_TEST_KEY_DIR/extra_chain.key" \
        --extra-cert "expired:18448:$SAFEYOLO_TEST_CERT_DIR/expired_chain.pem:$SAFEYOLO_TEST_KEY_DIR/expired_chain.key" \
        --extra-cert "wrong-san:18449:$SAFEYOLO_TEST_CERT_DIR/wrong_san_chain.pem:$SAFEYOLO_TEST_KEY_DIR/wrong_san_chain.key" \
        --extra-cert "self-signed:18450:$SAFEYOLO_TEST_CERT_DIR/self_signed_chain.pem:$SAFEYOLO_TEST_KEY_DIR/self_signed_chain.key" \
        --extra-cert "aia-only:18451:$SAFEYOLO_TEST_CERT_DIR/aia_chain.pem:$SAFEYOLO_TEST_KEY_DIR/aia_chain.key" \
        "${P4_CERT_ARGS[@]+"${P4_CERT_ARGS[@]}"}" \
        "${P2_SINKHOLE_ARGS[@]+"${P2_SINKHOLE_ARGS[@]}"}" \
        &
    fi
    SINKHOLE_PID=$!
    STARTED_SINKHOLE=true

    for i in $(seq 1 30); do
        if curl -sf "$SINKHOLE_API/health" >/dev/null 2>&1; then
            echo "  Sinkhole ready"
            break
        fi
        sleep 0.5
    done
    if ! curl -sf "$SINKHOLE_API/health" >/dev/null 2>&1; then
        echo "ERROR: Sinkhole failed to start"
        exit 2
    fi
    if ! process_script_matches "$SINKHOLE_PID" "$SINKHOLE_SCRIPT" || \
       ! capture_process_argv "$SINKHOLE_PID" "$SINKHOLE_ARGV_FILE"; then
        echo "ERROR: Sinkhole process identity could not be recorded"
        exit 2
    fi
    SINKHOLE_START_ID="$(process_start_identity "$SINKHOLE_PID" 2>/dev/null || true)"
    if [ -z "$SINKHOLE_START_ID" ]; then
        echo "ERROR: Sinkhole process start identity could not be recorded"
        exit 2
    fi
    printf '%s\n%s\n' "$SINKHOLE_PID" "$SINKHOLE_START_ID" > "$SINKHOLE_PID_FILE"
fi

# The native proxy has no mitmproxy sinkhole addon. Give the installed process
# an owned HTTP parent for synthetic hosts, while chaining all other requests
# through the instance's previous parent when one was configured.
if [ "$PROXY_IMPL" = "rust" ]; then
    if [ "$VZ_FIXED_PORTS" = true ]; then
        SELECTED_PARENT="http://127.0.0.1:$SINKHOLE_HTTP_PORT"
    else
        ORIGINAL_PARENT="$(python3 "$SCRIPT_DIR/harness/native_parent_config.py" current "$SAFEYOLO_CONFIG_DIR")"
        ORIGINAL_PARENT_CA="$(python3 "$SCRIPT_DIR/harness/native_parent_config.py" current-ca "$SAFEYOLO_CONFIG_DIR")"
        echo "Starting native fixture parent..."
        PARENT_ARGS=(--port-file "$PARENT_PORT_FILE")
        if [ -n "$ORIGINAL_PARENT" ]; then
            PARENT_ARGS+=(--parent "$ORIGINAL_PARENT")
        fi
        if [ -n "$ORIGINAL_PARENT_CA" ]; then
            PARENT_ARGS+=(--ca-file "$ORIGINAL_PARENT_CA")
        fi
        if [ "$P2" = true ]; then
            PARENT_ARGS+=(--p2-ssh-port-file "$SAFEYOLO_CONFIG_DIR/p2-fixture/ssh.port")
        fi
        python3 "$SCRIPT_DIR/harness/sinkhole_parent.py" "${PARENT_ARGS[@]}" &
        PARENT_PID=$!
        STARTED_PARENT=true
        for i in $(seq 1 30); do
            [ -s "$PARENT_PORT_FILE" ] && kill -0 "$PARENT_PID" 2>/dev/null && break
            sleep 0.1
        done
        if [ ! -s "$PARENT_PORT_FILE" ] || ! kill -0 "$PARENT_PID" 2>/dev/null; then
            echo "ERROR: native fixture parent did not start" >&2
            exit 2
        fi
        if ! process_script_matches "$PARENT_PID" "$SCRIPT_DIR/harness/sinkhole_parent.py" || \
           ! capture_process_argv "$PARENT_PID" "$PARENT_ARGV_FILE"; then
            echo "ERROR: native fixture parent identity could not be recorded" >&2
            exit 2
        fi
        PARENT_START_ID="$(process_start_identity "$PARENT_PID" 2>/dev/null || true)"
        if [ -z "$PARENT_START_ID" ]; then
            echo "ERROR: native fixture parent start identity could not be recorded" >&2
            exit 2
        fi
        printf '%s\n%s\n' "$PARENT_PID" "$PARENT_START_ID" > "$PARENT_PID_FILE"
        SELECTED_PARENT="http://127.0.0.1:$(cat "$PARENT_PORT_FILE")"
    fi
    python3 "$SCRIPT_DIR/harness/native_parent_config.py" select "$SAFEYOLO_CONFIG_DIR" "$SELECTED_PARENT" \
        --test-ca "$SAFEYOLO_TEST_CERT_DIR/ca.crt"
    export SAFEYOLO_UPSTREAM_PROXY="$SELECTED_PARENT"
fi

# Proxy (test instance on separate ports)
ADMIN_TOKEN=$(cat "$SAFEYOLO_CONFIG_DIR/data/admin_token" 2>/dev/null || echo "")
if [ "$PROXY_IMPL" = "python" ] && \
   curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:${TEST_ADMIN_PORT}/health" >/dev/null 2>&1; then
    echo "Test proxy already running"
else
    echo "Starting installed $PROXY_IMPL test proxy (admin port $TEST_ADMIN_PORT)..."
    STARTED_PROXY=true
    if [ "$PROXY_IMPL" = "rust" ]; then
        if ! safeyolo start --no-wait; then
            echo "ERROR: selected test proxy failed to start" >&2
            exit 2
        fi
    else
        if ! safeyolo start --test --no-wait; then
            echo "ERROR: selected test proxy failed to start" >&2
            exit 2
        fi
    fi

    for i in $(seq 1 30); do
        ADMIN_TOKEN=$(cat "$SAFEYOLO_CONFIG_DIR/data/admin_token" 2>/dev/null || echo "")
        if curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:${TEST_ADMIN_PORT}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:${TEST_ADMIN_PORT}/health" >/dev/null 2>&1; then
        echo "ERROR: selected test proxy did not become healthy" >&2
        exit 2
    fi
    echo "  Test proxy ready"
fi

# VM (only needed for isolation tests)
if [ "$RUN_ISOLATION" = true ]; then
    # Agent was cleaned at the top of the run; create fresh.
    if ! safeyolo agent add "$AGENT_NAME" "$REPO_ROOT" --no-run; then
        echo "ERROR: test guest could not be provisioned" >&2
        exit 2
    fi

    # Start a host TCP listener on a random port. The in-VM
    # test_host_listener_unreachable probes this port to prove a
    # live host listener remains unreachable — stronger than the
    # 44444 test which proves only that an unused port is unreachable.
    echo "Starting host listener..."
    CONFIG_SHARE="$SAFEYOLO_CONFIG_DIR/agents/$AGENT_NAME/config-share"
    mkdir -p "$CONFIG_SHARE"
    install -m 0444 \
        "$SAFEYOLO_TEST_CERT_DIR/self_signed_chain.pem" \
        "$CONFIG_SHARE/guest-only-trust-anchor.crt"
    if [ "$VZ_FIXED_PORTS" = true ]; then
        printf '%s\n' "$TEST_ADMIN_PORT" > "$CONFIG_SHARE/blackbox-admin-ports"
    else
        printf '9090\n%s\n' "$TEST_ADMIN_PORT" > "$CONFIG_SHARE/blackbox-admin-ports"
    fi
    printf 'HTTP %s\nHTTPS %s\ncontrol %s\n' \
        "$SINKHOLE_HTTP_PORT" "$SINKHOLE_HTTPS_PORT" "$SINKHOLE_CONTROL_PORT" \
        > "$CONFIG_SHARE/blackbox-sinkhole-ports"
    if [ "$VZ_FIXED_PORTS" = true ]; then
        # The origin is already known-live and binds on all host interfaces.
        printf '%s\n' "$SINKHOLE_HTTP_PORT" > "$CONFIG_SHARE/host-listener-port"
    else
        python3 "$SCRIPT_DIR/harness/host_listener.py" > "$CONFIG_SHARE/host-listener-port" &
        HOST_LISTENER_PID=$!
        # Wait for the port to be written (listener prints it on bind).
        for i in $(seq 1 20); do
            if [ -s "$CONFIG_SHARE/host-listener-port" ]; then
                echo "  Listener on port $(cat "$CONFIG_SHARE/host-listener-port")"
                break
            fi
            sleep 0.1
        done
    fi
    if [ ! -s "$CONFIG_SHARE/host-listener-port" ]; then
        echo "ERROR: Host listener didn't start"
        exit 2
    fi

    echo "Booting test VM ($AGENT_NAME)..."
    STARTED_VM=true
    if ! safeyolo agent run "$AGENT_NAME" --sandbox-only; then
        echo "ERROR: test guest could not be started" >&2
        exit 2
    fi

    echo "  Waiting for VM..."
    VM_READY=false
    for i in $(seq 1 60); do
        if safeyolo agent shell "$AGENT_NAME" -c true >/dev/null 2>&1; then
            echo "  VM ready"
            VM_READY=true
            break
        fi
        sleep 1
    done
    if [ "$VM_READY" != true ]; then
        echo "ERROR: VM did not become ready"
        exit 2
    fi
fi

if [ "$PROXY_IMPL" = "rust" ] && [ "$RUN_ISOLATION" = true ]; then
    ARTIFACTS_DIR="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts}"
    mkdir -p "$ARTIFACTS_DIR"
    if ! python3 "$SCRIPT_DIR/installed_host_smoke.py" \
        --mode attached --cli "$INSTALLED_CLI" --rust-bin "$INSTALLED_RUST_BIN" \
        --rust-config "$SAFEYOLO_CONFIG_DIR/data/native.json" \
        --config-dir "$SAFEYOLO_CONFIG_DIR" --working-directory "$SCRIPT_DIR" \
        --agent "$AGENT_NAME" --output "$ARTIFACTS_DIR/installed-rust-runtime.json"; then
        echo "ERROR: installed Rust runtime identity was not verified" >&2
        exit 2
    fi
fi

if [ "$KVM_P1" = true ]; then
    python3 "$SCRIPT_DIR/kvm_p1_ingress.py" \
        --config-dir "$SAFEYOLO_CONFIG_DIR" --agent "$AGENT_NAME" \
        --runtime "$ARTIFACTS_DIR/installed-rust-runtime.json" \
        --output "$ARTIFACTS_DIR/kvm-p1.json"
    exit $?
fi
if [ "$P2" = true ]; then
    timeout --signal=TERM --kill-after=10s 6m python3 "$SCRIPT_DIR/p2_installed_linux.py" \
        --config-dir "$SAFEYOLO_CONFIG_DIR" --agent "$AGENT_NAME" \
        --platform "$EXPECTED_PLATFORM" \
        --runtime "$ARTIFACTS_DIR/installed-rust-runtime.json" \
        --output "$ARTIFACTS_DIR/linux-$EXPECTED_PLATFORM-p2.json" \
        "${INSTALL_COMMIT_ARGS[@]+"${INSTALL_COMMIT_ARGS[@]}"}"
    exit $?
fi
if [ "$P3" = true ]; then
    python3 "$SCRIPT_DIR/p3_installed.py" \
        --config-dir "$SAFEYOLO_CONFIG_DIR" --agent "$AGENT_NAME" \
        --platform "$EXPECTED_PLATFORM" \
        --runtime "$ARTIFACTS_DIR/installed-rust-runtime.json" \
        --output "$ARTIFACTS_DIR/$EXPECTED_PLATFORM-p3.json" \
        "${INSTALL_COMMIT_ARGS[@]+"${INSTALL_COMMIT_ARGS[@]}"}"
    exit $?
fi
if [ "$P4" = true ]; then
    python3 "$SCRIPT_DIR/p4_installed.py" \
        --config-dir "$SAFEYOLO_CONFIG_DIR" --agent "$AGENT_NAME" \
        --platform "$EXPECTED_PLATFORM" \
        --runtime "$ARTIFACTS_DIR/installed-rust-runtime.json" \
        --output "$ARTIFACTS_DIR/$EXPECTED_PLATFORM-p4.json" \
        "${INSTALL_COMMIT_ARGS[@]+"${INSTALL_COMMIT_ARGS[@]}"}"
    exit $?
fi

echo ""

# --- Phase 2: Run tests ---

PROXY_RESULT=0
ISOLATION_RESULT=0
ROOT_ISOLATION_RESULT=0

FIREWALL_RESULT=0

if [ "$RUN_PROXY" = true ]; then
    if [ "$PROXY_IMPL" = "rust" ]; then
        echo "=== Installed Native Host Ingress Check ==="
    else
        echo "=== Proxy Functional Tests (host-side) ==="
    fi
    echo ""
    cd "$SCRIPT_DIR/host"
    set +e
    # Keep the retained Python host suite and installed native host checks
    # tied to their selected runtime. Each directory runs in full.
    if [ "$PROXY_IMPL" = "rust" ]; then
        pytest "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}" $VERBOSE --tb=short --timeout=60 native/
    else
        pytest "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}" $VERBOSE --tb=short --timeout=60 proxy/
    fi
    PROXY_RESULT=$?

    # Process security tests (host-side)
    echo ""
    echo "=== Process Security Tests (host-side) ==="
    echo ""
    pytest "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}" $VERBOSE --tb=short --timeout=60 security/
    FIREWALL_RESULT=$?
    set -e
    cd "$SCRIPT_DIR"
    echo ""
fi

IDENTITY_RESULT=0
if [ "$RUN_ISOLATION" = true ]; then
    # Host-side identity validation — agent_map must have correct
    # entries before in-VM tests rely on the identity chain.
    echo "=== Agent Identity Tests (host-side, sandbox running) ==="
    echo ""
    cd "$SCRIPT_DIR/host"
    set +e
    pytest "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}" $VERBOSE --tb=short --timeout=30 identity/
    IDENTITY_RESULT=$?
    set -e
    cd "$SCRIPT_DIR"
    echo ""

    echo "=== VM Isolation Tests (in-VM) ==="
    echo ""
    set +e
    safeyolo agent shell "$AGENT_NAME" -c \
        "cd /workspace/tests/blackbox/isolation && SAFEYOLO_BLACKBOX_ISOLATION=1 pytest${PYTEST_FORWARD_SHELL} $VERBOSE -rs --tb=short --timeout=60 --ignore=test_root_containment.py"
    ISOLATION_RESULT=$?
    set -e
    echo ""

    echo "=== Guest-Root Capability and Containment Tests (in-VM) ==="
    echo ""
    set +e
    safeyolo agent shell "$AGENT_NAME" --root -c \
        "cd /workspace/tests/blackbox/isolation && SAFEYOLO_BLACKBOX_ISOLATION=1 pytest${PYTEST_FORWARD_SHELL} $VERBOSE -rs --tb=short --timeout=60 test_root_containment.py test_key_isolation.py"
    ROOT_ISOLATION_RESULT=$?
    set -e
    echo ""

    # Lifecycle tests — host-side but need the sandbox still running
    # (write/read state across a stop+start cycle, verify agent API
    # after proxy restart, etc.). MUST run BEFORE cleanup tears down
    # the VM. Cross-platform now that home-persistence lives here;
    # individual tests that only apply to one platform carry their
    # own pytest skipif (see test_token_lifecycle.py).
    echo "=== Lifecycle Tests (host-side, sandbox running) ==="
    echo ""
    cd "$SCRIPT_DIR/host"
    set +e
    pytest "${PYTEST_FORWARD_ARGS[@]+"${PYTEST_FORWARD_ARGS[@]}"}" $VERBOSE -rs --tb=short --timeout=120 lifecycle/
    LIFECYCLE_RESULT=$?
    set -e
    cd "$SCRIPT_DIR"
    echo ""
fi

# --- Phase 3: Summary ---

echo "=== Test Summary ==="
if [ "$RUN_PROXY" = true ]; then
    if [ "$PROXY_IMPL" = "rust" ]; then
        PROXY_LABEL="Native host check"
    else
        PROXY_LABEL="Proxy tests"
    fi
    if [ "$PROXY_RESULT" = "0" ]; then
        echo "$PROXY_LABEL: PASSED"
    else
        echo "$PROXY_LABEL: FAILED (exit code: $PROXY_RESULT)"
    fi
fi

if [ "$FIREWALL_RESULT" != "0" ]; then
    echo "Security tests:  FAILED (exit code: $FIREWALL_RESULT)"
elif [ "$RUN_PROXY" = true ]; then
    echo "Security tests:  PASSED"
fi

if [ "$RUN_ISOLATION" = true ]; then
    if [ "$IDENTITY_RESULT" = "0" ]; then
        echo "Identity tests:  PASSED"
    else
        echo "Identity tests:  FAILED (exit code: $IDENTITY_RESULT)"
    fi
    if [ "$ISOLATION_RESULT" = "0" ]; then
        echo "Isolation tests: PASSED"
    else
        echo "Isolation tests: FAILED (exit code: $ISOLATION_RESULT)"
    fi
    if [ "$ROOT_ISOLATION_RESULT" = "0" ]; then
        echo "Guest-root tests: PASSED"
    else
        echo "Guest-root tests: FAILED (exit code: $ROOT_ISOLATION_RESULT)"
    fi
    if [ "${LIFECYCLE_RESULT:-0}" != "0" ]; then
        echo "Lifecycle tests: FAILED (exit code: $LIFECYCLE_RESULT)"
    else
        echo "Lifecycle tests: PASSED"
    fi
fi

if [ "$PROXY_RESULT" != "0" ] || [ "$ISOLATION_RESULT" != "0" ] || [ "$ROOT_ISOLATION_RESULT" != "0" ] || [ "$FIREWALL_RESULT" != "0" ] || [ "${LIFECYCLE_RESULT:-0}" != "0" ] || [ "$IDENTITY_RESULT" != "0" ]; then
    echo ""
    echo "Result: FAILED"
    exit 1
fi

echo ""
echo "Result: ALL PASSED"
exit 0
