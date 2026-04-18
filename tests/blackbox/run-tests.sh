#!/bin/bash
#
# Run SafeYolo blackbox tests (split execution model)
#
# Host-side pytest: proxy functional tests (credential guard, network guard)
# VM-side pytest:   isolation tests (network escape, privilege escalation, key isolation)
#
# Runs as an ISOLATED INSTANCE alongside production SafeYolo:
#   - Separate config dir (~/.safeyolo-test)
#   - Separate ports (proxy 8180, admin 9190)
#   - Separate netns slot on Linux (SAFEYOLO_SUBNET_BASE=75 shifts the
#     namespace name so it doesn't collide with production)
#   - Production agents are unaffected
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh --proxy      # Proxy functional tests only
#   ./run-tests.sh --isolation  # VM isolation tests only
#   ./run-tests.sh --verbose    # Verbose pytest output
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Infrastructure error
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

# --- Isolated test instance configuration ---
# These env vars scope all SafeYolo operations to a separate instance
# so blackbox tests don't interfere with production agents.
export SAFEYOLO_CONFIG_DIR="${SAFEYOLO_TEST_CONFIG_DIR:-$HOME/.safeyolo-test}"
export SAFEYOLO_SUBNET_BASE=75
# Logs + flow store scoped to the test instance so blackbox runs
# don't pollute production logs/flows.sqlite3.
export SAFEYOLO_LOGS_DIR="${SAFEYOLO_CONFIG_DIR}/logs"

# Test instance ports (different from production 8080/9090)
TEST_PROXY_PORT=8180
TEST_ADMIN_PORT=9190

# Export for host-side pytest (conftest.py reads these)
export PROXY_URL="http://127.0.0.1:${TEST_PROXY_PORT}"
export ADMIN_URL="http://127.0.0.1:${TEST_ADMIN_PORT}"

# Parse arguments
RUN_PROXY=true
RUN_ISOLATION=true
VERBOSE=""
AGENT_NAME="${SAFEYOLO_TEST_AGENT:-bbtest}"

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
        *)
            echo "Unknown option: $1"
            echo "Usage: ./run-tests.sh [--proxy|--isolation] [--verbose]"
            exit 2
            ;;
    esac
done

echo "=== SafeYolo Blackbox Tests ==="
echo "  Instance: $SAFEYOLO_CONFIG_DIR"
echo "  Proxy:    localhost:$TEST_PROXY_PORT  Admin: localhost:$TEST_ADMIN_PORT"
echo "  Netns base: SAFEYOLO_SUBNET_BASE=${SAFEYOLO_SUBNET_BASE}"
echo ""

# --- Phase 0: Prerequisites ---

if ! command -v safeyolo &>/dev/null; then
    echo "ERROR: safeyolo CLI not found. Activate the venv or install."
    exit 2
fi

# Initialize test config dir on first run
if [ ! -f "$SAFEYOLO_CONFIG_DIR/config.yaml" ]; then
    echo "Initializing test instance at $SAFEYOLO_CONFIG_DIR..."
    safeyolo init --no-interactive
    echo ""
fi

# Configure test-specific ports in config.yaml
python3 -c "
import yaml
from pathlib import Path
config_path = Path('$SAFEYOLO_CONFIG_DIR/config.yaml')
config = yaml.safe_load(config_path.read_text())
config['proxy']['port'] = $TEST_PROXY_PORT
config['proxy']['admin_port'] = $TEST_ADMIN_PORT
config['test']['sinkhole_router'] = '$SCRIPT_DIR/harness/sinkhole_router.py'
config['test']['ca_cert'] = '$SCRIPT_DIR/certs/ca.crt'
config_path.write_text(yaml.dump(config, default_flow_style=False))
"

# Configure target_hosts for test_context addon so the flow recorder
# captures tagged flows. The blackbox cross-agent isolation test uses
# X-Test-Context headers on httpbin.org probes — without target_hosts,
# test_context doesn't tag them and the flow recorder drops them.
python3 -c "
import yaml
from pathlib import Path
addons_path = Path('$SAFEYOLO_CONFIG_DIR/addons.yaml')
addons = yaml.safe_load(addons_path.read_text())
# target_hosts enables test_context to tag matching traffic with
# ccapt_context metadata → flow recorder captures it. Blocking is
# disabled in test mode via proxy.py (test_context_block=false) so
# host-side proxy tests without X-Test-Context aren't 428'd.
addons.setdefault('addons', {}).setdefault('test_context', {})['target_hosts'] = ['httpbin.org']
addons_path.write_text(yaml.dump(addons, default_flow_style=False))
"

# Symlink shared guest artifacts (rootfs, kernel) from production.
# init creates an empty share/ dir — replace it with a symlink.
PROD_SHARE="$HOME/.safeyolo/share"
TEST_SHARE="$SAFEYOLO_CONFIG_DIR/share"
if [ -d "$PROD_SHARE" ] && [ ! -L "$TEST_SHARE" ]; then
    rm -rf "$TEST_SHARE"
    ln -s "$PROD_SHARE" "$TEST_SHARE"
    echo "  Linked guest artifacts: $TEST_SHARE -> $PROD_SHARE"
fi

# Symlink host binaries (safeyolo-vm + vsock-term) from production
PROD_BIN="$HOME/.safeyolo/bin"
TEST_BIN="$SAFEYOLO_CONFIG_DIR/bin"
if [ -d "$PROD_BIN" ] && [ ! -L "$TEST_BIN" ]; then
    rm -rf "$TEST_BIN"
    ln -s "$PROD_BIN" "$TEST_BIN"
    echo "  Linked binaries: $TEST_BIN -> $PROD_BIN"
fi

echo "Generating test certificates..."
if ! ./certs/generate-certs.sh --force; then
    echo "ERROR: Failed to generate test certificates"
    exit 2
fi

# --- Track what we started (only clean up our own) ---

STARTED_SINKHOLE=false
STARTED_PROXY=false
STARTED_VM=false
SINKHOLE_PID=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ "$STARTED_VM" = true ]; then
        echo "Stopping $AGENT_NAME..."
        safeyolo agent stop "$AGENT_NAME" 2>/dev/null || true
    fi

    if [ -n "$SINKHOLE_PID" ] && [ "$STARTED_SINKHOLE" = true ]; then
        echo "Stopping sinkhole (PID $SINKHOLE_PID)..."
        kill "$SINKHOLE_PID" 2>/dev/null || true
        wait "$SINKHOLE_PID" 2>/dev/null || true
    fi

    if [ "$STARTED_PROXY" = true ]; then
        echo "Stopping test proxy..."
        safeyolo stop 2>/dev/null || true
    fi

    echo "Cleanup complete"
}
trap cleanup EXIT

# --- Phase 1: Start infrastructure (idempotent) ---

# Sinkhole (shared — not instance-specific)
if curl -sf "http://127.0.0.1:19999/health" >/dev/null 2>&1; then
    echo "Sinkhole already running"
else
    echo "Starting sinkhole..."
    python3 "$SCRIPT_DIR/sinkhole/server.py" \
        --http-port 18080 \
        --https-port 18443 \
        --control-port 19999 \
        --cert "$SCRIPT_DIR/certs/sinkhole.crt" \
        --key "$HOME/.safeyolo/test-certs/sinkhole.key" \
        &
    SINKHOLE_PID=$!
    STARTED_SINKHOLE=true

    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:19999/health" >/dev/null 2>&1; then
            echo "  Sinkhole ready"
            break
        fi
        sleep 0.5
    done
    if ! curl -sf "http://127.0.0.1:19999/health" >/dev/null 2>&1; then
        echo "ERROR: Sinkhole failed to start"
        exit 2
    fi
fi

# Proxy (test instance on separate ports)
ADMIN_TOKEN=$(cat "$SAFEYOLO_CONFIG_DIR/data/admin_token" 2>/dev/null || echo "")
if curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:${TEST_ADMIN_PORT}/health" >/dev/null 2>&1; then
    echo "Test proxy already running"
else
    echo "Starting test proxy (port $TEST_PROXY_PORT, test mode)..."
    safeyolo start --test --no-wait
    STARTED_PROXY=true

    for i in $(seq 1 30); do
        ADMIN_TOKEN=$(cat "$SAFEYOLO_CONFIG_DIR/data/admin_token" 2>/dev/null || echo "")
        if curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:${TEST_ADMIN_PORT}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    echo "  Test proxy ready"
fi

# VM (only needed for isolation tests)
if [ "$RUN_ISOLATION" = true ]; then
    # Always recreate agent fresh — avoids stale agent_map entries,
    # orphaned bridge sockets, and identity state from previous runs.
    safeyolo agent stop "$AGENT_NAME" 2>/dev/null || true
    safeyolo agent remove "$AGENT_NAME" 2>/dev/null || true
    safeyolo agent add "$AGENT_NAME" byoa "$REPO_ROOT" --no-run

    echo "Booting test VM ($AGENT_NAME)..."
    safeyolo agent run "$AGENT_NAME" --detach
    STARTED_VM=true

    echo "  Waiting for VM..."
    VM_IP=""
    for i in $(seq 1 15); do
        VM_IP=$(cat "$SAFEYOLO_CONFIG_DIR/agents/$AGENT_NAME/status/vm-ip" 2>/dev/null || echo "")
        [ -n "$VM_IP" ] && break
        sleep 1
    done
    if [ -z "$VM_IP" ]; then
        echo "ERROR: Could not determine VM IP"
        exit 2
    fi
    for i in $(seq 1 60); do
        if safeyolo agent shell "$AGENT_NAME" -c true >/dev/null 2>&1; then
            echo "  VM ready ($VM_IP)"
            break
        fi
        sleep 1
    done
fi

echo ""

# --- Phase 2: Run tests ---

PROXY_RESULT=0
ISOLATION_RESULT=0

FIREWALL_RESULT=0

if [ "$RUN_PROXY" = true ]; then
    echo "=== Proxy Functional Tests (host-side) ==="
    echo ""
    cd "$SCRIPT_DIR/host"
    set +e
    pytest $VERBOSE --tb=short --timeout=60 \
        test_credential_guard.py test_network_guard.py
    PROXY_RESULT=$?

    # Process security tests (host-side)
    echo ""
    echo "=== Process Security Tests (host-side) ==="
    echo ""
    pytest $VERBOSE --tb=short --timeout=60 \
        test_firewall_structural.py
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
    pytest $VERBOSE --tb=short --timeout=30 \
        test_agent_identity.py
    IDENTITY_RESULT=$?
    set -e
    cd "$SCRIPT_DIR"
    echo ""

    echo "=== VM Isolation Tests (in-VM) ==="
    echo ""
    set +e
    safeyolo agent shell "$AGENT_NAME" -c \
        "cd /workspace/tests/blackbox/isolation && SAFEYOLO_BLACKBOX_ISOLATION=1 pytest $VERBOSE --tb=short --timeout=60"
    ISOLATION_RESULT=$?
    set -e
    echo ""

    # Token lifecycle test — runs on the host but needs the sandbox
    # still running (tests agent API across a proxy restart). Must
    # run BEFORE cleanup tears down the VM.
    LIFECYCLE_RESULT=0
    if [[ "$(uname -s)" == "Linux" ]]; then
        echo "=== Token Lifecycle Tests (host-side, sandbox running) ==="
        echo ""
        cd "$SCRIPT_DIR/host"
        set +e
        pytest $VERBOSE --tb=short --timeout=120 \
            test_token_lifecycle.py
        LIFECYCLE_RESULT=$?
        set -e
        cd "$SCRIPT_DIR"
        echo ""
    fi
fi

# --- Phase 3: Summary ---

echo "=== Test Summary ==="
if [ "$RUN_PROXY" = true ]; then
    if [ "$PROXY_RESULT" = "0" ]; then
        echo "Proxy tests:     PASSED"
    else
        echo "Proxy tests:     FAILED (exit code: $PROXY_RESULT)"
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
    if [ "${LIFECYCLE_RESULT:-0}" != "0" ]; then
        echo "Lifecycle tests: FAILED (exit code: $LIFECYCLE_RESULT)"
    elif [[ "$(uname -s)" == "Linux" ]]; then
        echo "Lifecycle tests: PASSED"
    fi
fi

if [ "$PROXY_RESULT" != "0" ] || [ "$ISOLATION_RESULT" != "0" ] || [ "$FIREWALL_RESULT" != "0" ] || [ "${LIFECYCLE_RESULT:-0}" != "0" ] || [ "$IDENTITY_RESULT" != "0" ]; then
    echo ""
    echo "Result: FAILED"
    exit 1
fi

echo ""
echo "Result: ALL PASSED"
exit 0
