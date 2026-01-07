#!/bin/bash
#
# Run SafeYolo blackbox tests
#
# This script handles the docker compose lifecycle properly for CI:
# - Builds and starts services in detached mode
# - Waits for test-runner to complete
# - Captures and returns the test exit code
# - Cleans up containers and volumes
#
# Usage:
#   ./run-tests.sh           # Run tests
#   ./run-tests.sh --verbose # Run with verbose pytest output
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
PYTEST_ARGS=""
if [ "$1" = "--verbose" ] || [ "$1" = "-v" ]; then
    PYTEST_ARGS="-v"
fi

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
    docker compose down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Build images
echo "Building images..."
if ! docker compose build --quiet; then
    echo "ERROR: Build failed"
    exit 2
fi

# Start services in detached mode
echo "Starting services..."
if ! docker compose up -d; then
    echo "ERROR: Failed to start services"
    exit 2
fi

# Wait for test-runner to complete
# The test-runner container runs pytest and exits with its exit code
echo "Waiting for tests to complete..."
echo ""

# Follow test-runner logs in real-time
docker compose logs -f test-runner &
LOGS_PID=$!

# Wait for test-runner container to exit
EXIT_CODE=0
if ! docker compose wait test-runner; then
    # Get the actual exit code
    EXIT_CODE=$(docker inspect test-runner --format='{{.State.ExitCode}}' 2>/dev/null || echo "2")
fi

# Stop following logs
kill $LOGS_PID 2>/dev/null || true
wait $LOGS_PID 2>/dev/null || true

echo ""
echo "=== Test Summary ==="
if [ "$EXIT_CODE" = "0" ]; then
    echo "Result: PASSED"
else
    echo "Result: FAILED (exit code: $EXIT_CODE)"

    # Show safeyolo logs on failure for debugging
    echo ""
    echo "=== SafeYolo logs (last 50 lines) ==="
    docker compose logs --tail=50 safeyolo 2>/dev/null || true
fi

exit "$EXIT_CODE"
