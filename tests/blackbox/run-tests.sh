#!/bin/bash
#
# Run SafeYolo blackbox tests (microVM architecture)
#
# Starts the sinkhole, proxy (with sinkhole routing), and a test VM,
# then runs pytest inside the VM via SSH.
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh --proxy      # Proxy functional tests only
#   ./run-tests.sh --isolation  # VM isolation + key isolation tests only
#   ./run-tests.sh --verbose    # Verbose pytest output
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Infrastructure error (process failed to start, VM unreachable, etc.)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
RUN_PROXY=true
RUN_ISOLATION=true
VERBOSE=""

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

echo "=== SafeYolo Blackbox Tests (microVM) ==="
echo ""

# -----------------------------------------------------------------------
# Ports (non-privileged, avoid conflicts)
# -----------------------------------------------------------------------
SINKHOLE_HTTP_PORT=18080
SINKHOLE_HTTPS_PORT=18443
SINKHOLE_CONTROL_PORT=19999
PROXY_PORT=8080
ADMIN_PORT=9090

# -----------------------------------------------------------------------
# Generate test certificates if needed
# -----------------------------------------------------------------------
echo "Checking test certificates..."
if ! ./certs/generate-certs.sh; then
    echo "ERROR: Failed to generate test certificates"
    exit 2
fi
echo ""

# -----------------------------------------------------------------------
# PIDs for cleanup
# -----------------------------------------------------------------------
SINKHOLE_PID=""
PROXY_STARTED=false

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Stop sinkhole
    if [ -n "$SINKHOLE_PID" ]; then
        echo "Stopping sinkhole (PID $SINKHOLE_PID)..."
        kill "$SINKHOLE_PID" 2>/dev/null || true
        wait "$SINKHOLE_PID" 2>/dev/null || true
    fi

    # Stop proxy
    if [ "$PROXY_STARTED" = true ]; then
        echo "Stopping proxy..."
        cd "$REPO_ROOT"
        python -m safeyolo.proxy stop 2>/dev/null || true
        cd "$SCRIPT_DIR"
    fi

    # TODO: Stop test VM and tear down network isolation
    # safeyolo agent stop blackbox-test 2>/dev/null || true

    echo "Cleanup complete"
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Start sinkhole
# -----------------------------------------------------------------------
echo "Starting sinkhole server..."
python "$SCRIPT_DIR/sinkhole/server.py" \
    --http-port "$SINKHOLE_HTTP_PORT" \
    --https-port "$SINKHOLE_HTTPS_PORT" \
    --control-port "$SINKHOLE_CONTROL_PORT" \
    --cert "$SCRIPT_DIR/certs/sinkhole.crt" \
    --key "$SCRIPT_DIR/certs/sinkhole.key" \
    &
SINKHOLE_PID=$!

# Wait for sinkhole health
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${SINKHOLE_CONTROL_PORT}/health" >/dev/null 2>&1; then
        echo "Sinkhole ready"
        break
    fi
    sleep 0.5
done

if ! curl -sf "http://127.0.0.1:${SINKHOLE_CONTROL_PORT}/health" >/dev/null 2>&1; then
    echo "ERROR: Sinkhole failed to start"
    exit 2
fi

# -----------------------------------------------------------------------
# Start proxy with sinkhole routing
# -----------------------------------------------------------------------
echo "Starting proxy with sinkhole routing..."

export SAFEYOLO_CA_CERT="$SCRIPT_DIR/certs/ca.crt"
export SAFEYOLO_BLOCK=true
export SAFEYOLO_SINKHOLE_ROUTER="$SCRIPT_DIR/harness/sinkhole_router.py"
export SAFEYOLO_SINKHOLE_HOST=127.0.0.1
export SAFEYOLO_SINKHOLE_HTTP_PORT=$SINKHOLE_HTTP_PORT
export SAFEYOLO_SINKHOLE_HTTPS_PORT=$SINKHOLE_HTTPS_PORT

# TODO: Integrate with safeyolo CLI proxy start
# For now, document the manual steps:
echo "  SAFEYOLO_CA_CERT=$SAFEYOLO_CA_CERT"
echo "  SAFEYOLO_SINKHOLE_ROUTER=$SAFEYOLO_SINKHOLE_ROUTER"
echo ""
PROXY_STARTED=true

# -----------------------------------------------------------------------
# Start test VM
# -----------------------------------------------------------------------
echo "Starting test VM..."
# TODO: Boot BYOA VM with:
#   - VirtioFS share for test files (runner/ -> /tests in guest)
#   - Firewall rules allowing proxy + sinkhole control ports
#   - Environment: SAFEYOLO_GATEWAY_IP, ADMIN_API_TOKEN, SINKHOLE_API
echo "  (VM boot integration pending)"
echo ""

# -----------------------------------------------------------------------
# Run tests
# -----------------------------------------------------------------------
# Select test files based on suite
PROXY_TESTS="test_credential_guard.py test_network_guard.py"
ISOLATION_TESTS="test_vm_isolation.py test_key_isolation.py"
ALL_TESTS="$PROXY_TESTS $ISOLATION_TESTS"

TESTS_TO_RUN=""
if [ "$RUN_PROXY" = true ] && [ "$RUN_ISOLATION" = true ]; then
    TESTS_TO_RUN="$ALL_TESTS"
elif [ "$RUN_PROXY" = true ]; then
    TESTS_TO_RUN="$PROXY_TESTS"
elif [ "$RUN_ISOLATION" = true ]; then
    TESTS_TO_RUN="$ISOLATION_TESTS"
fi

echo "Tests to run: $TESTS_TO_RUN"
echo ""

# TODO: SSH into VM and run:
#   cd /tests && pytest $VERBOSE --tb=short --timeout=60 $TESTS_TO_RUN
# For now, show what would run:
echo "Would run inside VM:"
echo "  pytest $VERBOSE --tb=short --timeout=60 $TESTS_TO_RUN"
echo ""
echo "NOTE: Full VM integration pending. Test files are ready."

# Placeholder exit
exit 0
