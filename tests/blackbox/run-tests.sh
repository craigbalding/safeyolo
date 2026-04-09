#!/bin/bash
#
# Run SafeYolo blackbox tests (split execution model)
#
# Host-side pytest: proxy functional tests (credential guard, network guard)
# VM-side pytest:   isolation tests (network escape, privilege escalation, key isolation)
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh --proxy      # Proxy functional tests only
#   ./run-tests.sh --isolation  # VM isolation tests only
#   ./run-tests.sh --verbose    # Verbose pytest output
#
# Prerequisites:
#   - safeyolo CLI installed (in venv or PATH)
#   - Guest images built (cd guest && ./build-all.sh)
#   - Test certs generated (auto-generated if missing)
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Infrastructure error
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

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
echo ""

# --- Phase 0: Prerequisites ---

echo "Checking test certificates..."
if ! ./certs/generate-certs.sh; then
    echo "ERROR: Failed to generate test certificates"
    exit 2
fi

if ! command -v safeyolo &>/dev/null; then
    echo "ERROR: safeyolo CLI not found. Activate the venv or install."
    exit 2
fi

# --- Cleanup trap ---

SINKHOLE_PID=""
cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Stop test VM
    safeyolo agent stop "$AGENT_NAME" 2>/dev/null || true

    # Stop sinkhole
    if [ -n "$SINKHOLE_PID" ]; then
        kill "$SINKHOLE_PID" 2>/dev/null || true
        wait "$SINKHOLE_PID" 2>/dev/null || true
    fi

    # Stop proxy (but don't tear down agents — they're already stopped)
    safeyolo stop 2>/dev/null || true

    echo "Cleanup complete"
}
trap cleanup EXIT

# --- Phase 1: Start infrastructure ---

echo "Starting sinkhole..."
python3 "$SCRIPT_DIR/sinkhole/server.py" \
    --http-port 18080 \
    --https-port 18443 \
    --control-port 19999 \
    --cert "$SCRIPT_DIR/certs/sinkhole.crt" \
    --key "$SCRIPT_DIR/certs/sinkhole.key" \
    &
SINKHOLE_PID=$!

# Wait for sinkhole
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

echo "Starting proxy (test mode)..."
safeyolo start --test --no-wait
if ! safeyolo doctor 2>/dev/null | grep -q "running"; then
    # Wait for proxy health
    for i in $(seq 1 30); do
        if curl -sf -H "Authorization: Bearer $(cat ~/.safeyolo/data/admin_token 2>/dev/null)" \
            "http://127.0.0.1:9090/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi
echo "  Proxy ready"

if [ "$RUN_ISOLATION" = true ]; then
    echo "Booting test VM ($AGENT_NAME)..."
    # Create agent if not exists
    safeyolo agent add "$AGENT_NAME" byoa "$REPO_ROOT" --no-run 2>/dev/null || true
    # Boot in detach mode
    safeyolo agent run "$AGENT_NAME" --detach

    # Wait for SSH
    echo "  Waiting for SSH..."
    VM_IP=$(cat ~/.safeyolo/agents/$AGENT_NAME/config-share/vm-ip 2>/dev/null || echo "")
    if [ -z "$VM_IP" ]; then
        echo "ERROR: Could not determine VM IP"
        exit 2
    fi
    SSH_KEY="$HOME/.safeyolo/data/vm_ssh_key"
    for i in $(seq 1 60); do
        if ssh -i "$SSH_KEY" -p 22 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 \
            -o BatchMode=yes "agent@$VM_IP" true 2>/dev/null; then
            echo "  SSH ready ($VM_IP)"
            break
        fi
        sleep 1
    done
fi

echo ""

# --- Phase 2: Run tests ---

PROXY_RESULT=0
ISOLATION_RESULT=0

if [ "$RUN_PROXY" = true ]; then
    echo "=== Proxy Functional Tests (host-side) ==="
    echo ""
    cd "$SCRIPT_DIR/host"
    if pytest $VERBOSE --tb=short --timeout=60 \
        test_credential_guard.py test_network_guard.py; then
        PROXY_RESULT=0
    else
        PROXY_RESULT=$?
    fi
    cd "$SCRIPT_DIR"
    echo ""
fi

if [ "$RUN_ISOLATION" = true ]; then
    echo "=== VM Isolation Tests (in-VM) ==="
    echo ""
    safeyolo agent shell "$AGENT_NAME" -c \
        "cd /workspace/tests/blackbox/isolation && pytest $VERBOSE --tb=short --timeout=60"
    ISOLATION_RESULT=$?
    echo ""
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

if [ "$RUN_ISOLATION" = true ]; then
    if [ "$ISOLATION_RESULT" = "0" ]; then
        echo "Isolation tests: PASSED"
    else
        echo "Isolation tests: FAILED (exit code: $ISOLATION_RESULT)"
    fi
fi

if [ "$PROXY_RESULT" != "0" ] || [ "$ISOLATION_RESULT" != "0" ]; then
    echo ""
    echo "Result: FAILED"
    exit 1
fi

echo ""
echo "Result: ALL PASSED"
exit 0
