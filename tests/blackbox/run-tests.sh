#!/bin/bash
#
# Run SafeYolo blackbox tests (proxy tests + isolation tests)
#
# This script runs both test suites:
#   1. Proxy tests: credential guard, network guard via sinkhole inspection
#   2. Isolation tests: container hardening, network isolation, key isolation
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh --proxy      # Run proxy tests only
#   ./run-tests.sh --isolation  # Run isolation tests only
#   ./run-tests.sh --verbose    # Run with verbose pytest output
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Infrastructure error (build failed, containers crashed, etc.)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

echo "=== SafeYolo Blackbox Tests ==="
echo ""

# Generate test certificates if needed
echo "Checking test certificates..."
if ! ./certs/generate-certs.sh; then
    echo "ERROR: Failed to generate test certificates"
    exit 2
fi
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    docker compose -f docker-compose.yml -f docker-compose.security.yml down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Run a test suite and return exit code
run_suite() {
    local name=$1
    local compose_cmd=$2

    echo "=== $name ==="
    echo ""

    # Build images
    echo "Building images..."
    if ! $compose_cmd --progress=plain build --quiet; then
        echo "ERROR: Build failed"
        return 2
    fi

    # Start services in detached mode
    echo "Starting services..."
    if ! $compose_cmd --progress=plain up -d; then
        echo "ERROR: Failed to start services"
        return 2
    fi

    # Wait for test-runner to complete
    echo "Running tests..."
    echo ""

    # Follow test-runner logs in real-time
    $compose_cmd logs -f test-runner &
    LOGS_PID=$!

    # Wait for test-runner container to exit
    local exit_code=0
    if ! $compose_cmd wait test-runner 2>/dev/null; then
        # Get the actual exit code
        exit_code=$(docker inspect test-runner --format='{{.State.ExitCode}}' 2>/dev/null || echo "2")
    fi

    # Stop following logs
    kill $LOGS_PID 2>/dev/null || true
    wait $LOGS_PID 2>/dev/null || true

    # Show safeyolo logs on failure
    if [ "$exit_code" != "0" ]; then
        echo ""
        echo "--- SafeYolo logs (last 30 lines) ---"
        $compose_cmd logs --tail=30 safeyolo 2>/dev/null || true
    fi

    # Cleanup before next suite
    echo ""
    echo "Stopping containers..."
    $compose_cmd down -v --remove-orphans 2>/dev/null || true

    return "$exit_code"
}

PROXY_RESULT=0
ISOLATION_RESULT=0

# Run proxy tests
if [ "$RUN_PROXY" = true ]; then
    if run_suite "Proxy Tests" "docker compose"; then
        PROXY_RESULT=0
    else
        PROXY_RESULT=$?
    fi
    echo ""
fi

# Run isolation tests
if [ "$RUN_ISOLATION" = true ]; then
    if run_suite "Isolation Tests" "docker compose -f docker-compose.yml -f docker-compose.security.yml"; then
        ISOLATION_RESULT=0
    else
        ISOLATION_RESULT=$?
    fi
    echo ""
fi

# Summary
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

# Exit with failure if any suite failed
if [ "$PROXY_RESULT" != "0" ] || [ "$ISOLATION_RESULT" != "0" ]; then
    echo ""
    echo "Result: FAILED"
    exit 1
fi

echo ""
echo "Result: ALL PASSED"
exit 0
