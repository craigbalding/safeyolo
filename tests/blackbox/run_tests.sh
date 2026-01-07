#!/bin/bash
#
# Run SafeYolo black box tests
#
# Usage:
#   ./run_tests.sh                    # Run all tests
#   ./run_tests.sh -k credential      # Run credential tests only
#   ./run_tests.sh --debug            # Start services, drop to bash
#   ./run_tests.sh --build-only       # Just build images, don't run
#

set -e

cd "$(dirname "$0")"

# Parse args
DEBUG=false
BUILD_ONLY=false
PYTEST_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            DEBUG=true
            shift
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        *)
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
    esac
done

echo "=== SafeYolo Black Box Test Harness ==="
echo ""

# Build images
echo "Building test images..."
docker compose build

if [ "$BUILD_ONLY" = true ]; then
    echo "Build complete."
    exit 0
fi

if [ "$DEBUG" = true ]; then
    echo "Starting services in debug mode..."
    docker compose up -d safeyolo sinkhole

    echo ""
    echo "Services started:"
    echo "  - SafeYolo proxy: http://localhost:18080"
    echo "  - SafeYolo admin: http://localhost:19090"
    echo "  - Sinkhole API:   http://localhost:19999"
    echo ""
    echo "Entering test-runner shell..."
    echo "Run: pytest -v to execute tests"
    echo ""

    docker compose run --rm test-runner bash
    EXIT_CODE=$?

    echo ""
    echo "Cleaning up..."
    docker compose down -v

    exit $EXIT_CODE
else
    echo "Running tests..."
    docker compose up --abort-on-container-exit --exit-code-from test-runner
    EXIT_CODE=$?

    echo ""
    echo "Cleaning up..."
    docker compose down -v

    exit $EXIT_CODE
fi
