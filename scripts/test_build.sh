#!/bin/bash
#
# Test SafeYolo build targets without interfering with production
#
# Usage:
#   ./scripts/test_build.sh base
#   ./scripts/test_build.sh dev

set -e

TARGET="${1:-base}"
CONTAINER_NAME="safeyolo-${TARGET}-test"

# Find an available port starting from a base port
find_available_port() {
    local base_port=$1
    local max_attempts=100

    for ((i=0; i<max_attempts; i++)); do
        local port=$((base_port + i))
        # Check if port is in use (works on Linux and macOS)
        if ! ss -tuln 2>/dev/null | grep -q ":${port} " && \
           ! netstat -tuln 2>/dev/null | grep -q ":${port} "; then
            echo $port
            return 0
        fi
    done

    echo "ERROR: Could not find available port starting from ${base_port}" >&2
    exit 1
}

echo "=== Testing SafeYolo ${TARGET} build ==="
echo ""

# Find available ports
echo "Finding available ports..."
TEST_PORT=$(find_available_port 8889)
ADMIN_PORT=$(find_available_port 9091)
echo "  Proxy port: ${TEST_PORT}"
echo "  Admin port: ${ADMIN_PORT}"
echo ""

# Build the target
echo "Building ${TARGET} target..."
docker build --target ${TARGET} -t safeyolo:${TARGET}-test . || {
    echo "FAIL: Build failed"
    exit 1
}
echo ""

# Clean up any existing test container
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing test container..."
    docker stop ${CONTAINER_NAME} 2>/dev/null || true
    docker rm ${CONTAINER_NAME} 2>/dev/null || true
fi

# Start test container
echo "Starting test container on ports ${TEST_PORT}:8080, ${ADMIN_PORT}:9090..."
docker run -d \
  --name ${CONTAINER_NAME} \
  -p 127.0.0.1:${TEST_PORT}:8080 \
  -p 127.0.0.1:${ADMIN_PORT}:9090 \
  safeyolo:${TARGET}-test || {
    echo "FAIL: Container failed to start"
    exit 1
}
echo ""

# Wait for startup (can take 30-60s due to admin API health check)
echo "Waiting for SafeYolo to start (may take up to 60s)..."
STARTED=false
for i in {1..60}; do
    # Check if container is still running
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "FAIL: Container exited unexpectedly"
        echo ""
        echo "=== Container logs ==="
        docker logs ${CONTAINER_NAME} 2>&1
        echo ""
        echo "Container '${CONTAINER_NAME}' is stopped. Inspect with:"
        echo "  docker logs ${CONTAINER_NAME}"
        echo "  docker start ${CONTAINER_NAME}"
        echo ""
        echo "To cleanup: docker rm ${CONTAINER_NAME}"
        exit 1
    fi

    if docker logs ${CONTAINER_NAME} 2>&1 | grep -q "SafeYolo ready"; then
        echo "  Container started successfully (${i}s)"
        STARTED=true
        break
    fi

    # Show progress every 10 seconds
    if [ $((i % 10)) -eq 0 ]; then
        echo "  Still waiting... (${i}s)"
    fi

    if [ $i -eq 60 ]; then
        echo "FAIL: Container did not print 'SafeYolo ready' within 60 seconds"
        echo ""
        echo "=== Last 50 lines of container logs ==="
        docker logs --tail 50 ${CONTAINER_NAME} 2>&1
        echo ""
        echo "Container '${CONTAINER_NAME}' is still running. Inspect with:"
        echo "  docker logs -f ${CONTAINER_NAME}"
        echo "  docker exec -it ${CONTAINER_NAME} bash"
        echo ""
        echo "To cleanup: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"
        exit 1
    fi
    sleep 1
done
echo ""

# Additional wait for proxy to be fully ready
echo "Checking if proxy is accepting connections..."
for i in {1..10}; do
    if curl --max-time 1 -x http://localhost:${TEST_PORT} \
            -s -o /dev/null http://example.com 2>/dev/null; then
        echo "  Proxy is ready (${i}s)"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "  WARNING: Proxy not responding after 10s, continuing anyway..."
    fi
    sleep 1
done
echo ""

# Extract mitmproxy CA certificate for HTTPS testing
echo "Extracting mitmproxy CA certificate..."
CA_CERT="/tmp/safeyolo-test-ca-${TARGET}.pem"
docker cp ${CONTAINER_NAME}:/certs/mitmproxy-ca-cert.pem ${CA_CERT} || {
    echo "  FAIL: Could not extract CA certificate"
    exit 1
}
echo "  CA cert extracted to ${CA_CERT}"
echo ""

# Test 1: Credential guard blocking
echo "Test 1: Credential guard blocks fake OpenAI key to httpbin.org..."
RESPONSE=$(curl --max-time 10 --cacert ${CA_CERT} -x http://localhost:${TEST_PORT} \
  -H "Authorization: Bearer sk-test1234567890abcdefghijklmnopqrstuvwxyz123456" \
  -w "%{http_code}" -s -o /dev/null \
  https://httpbin.org/get 2>&1)

# Check if curl succeeded
if [ $? -ne 0 ]; then
    echo "  FAIL: curl command failed or timed out"
    echo "  Response: ${RESPONSE}"
    echo ""
    echo "Checking if proxy is listening..."
    if ! netstat -tuln 2>/dev/null | grep -q ":${TEST_PORT} " && \
       ! ss -tuln 2>/dev/null | grep -q ":${TEST_PORT} "; then
        echo "  ERROR: Proxy not listening on port ${TEST_PORT}"
    fi
    echo ""
    echo "Last 30 lines of container logs:"
    docker logs --tail 30 ${CONTAINER_NAME} 2>&1
    exit 1
fi

if [ "$RESPONSE" != "403" ]; then
    echo "  FAIL: Expected 403, got ${RESPONSE}"
    docker logs --tail 30 ${CONTAINER_NAME}
    exit 1
fi
echo "  ✓ PASS: Got 403 blocked"
echo ""

# Test 2: Admin API responds
echo "Test 2: Admin API returns stats..."
if ! curl --max-time 5 -s http://localhost:${ADMIN_PORT}/stats | jq -e '.proxy == "safeyolo"' > /dev/null 2>&1; then
    echo "  FAIL: Admin API not responding correctly"
    echo ""
    echo "Last 30 lines of container logs:"
    docker logs --tail 30 ${CONTAINER_NAME} 2>&1
    exit 1
fi
echo "  ✓ PASS: Admin API OK"
echo ""

# Test 3: Check which addons loaded
echo "Test 3: Checking addon loading..."
if docker logs ${CONTAINER_NAME} 2>&1 | grep -q "Loading addons"; then
    echo "  Loaded addons:"
    docker logs ${CONTAINER_NAME} 2>&1 | grep -A 15 "Loading addons" | grep "  - " | head -12
    echo "  ✓ PASS: Addons loaded"
else
    echo "  FAIL: Could not find addon loading log"
    docker logs ${CONTAINER_NAME}
    exit 1
fi
echo ""

# Success
echo "=== ✓ All tests passed for ${TARGET} build ==="
echo ""
echo "Test container is still running at:"
echo "  Proxy: http://localhost:${TEST_PORT}"
echo "  Admin: http://localhost:${ADMIN_PORT}"
echo ""
echo "Cleanup options:"
echo "  Keep running: Press Ctrl+C now"
echo "  Auto-cleanup: Wait 5 seconds"
echo ""
sleep 5

echo "Cleaning up test container..."
docker stop ${CONTAINER_NAME} 2>/dev/null
docker rm ${CONTAINER_NAME} 2>/dev/null

# Clean up CA cert
if [ -f "${CA_CERT}" ]; then
    rm -f "${CA_CERT}"
    echo "Removed ${CA_CERT}"
fi

echo "Done!"
