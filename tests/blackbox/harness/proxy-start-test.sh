#!/bin/bash
# Start SafeYolo proxy in blackbox test mode.
# Sets up sinkhole routing and test CA trust.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

export SAFEYOLO_CA_CERT="$REPO_ROOT/tests/blackbox/certs/ca.crt"
export SAFEYOLO_BLOCK=true
export SAFEYOLO_SINKHOLE_ROUTER="$REPO_ROOT/tests/blackbox/harness/sinkhole_router.py"
export SAFEYOLO_SINKHOLE_HOST=127.0.0.1
export SAFEYOLO_SINKHOLE_HTTP_PORT=18080
export SAFEYOLO_SINKHOLE_HTTPS_PORT=18443

echo "Test mode:"
echo "  CA_CERT=$SAFEYOLO_CA_CERT"
echo "  SINKHOLE_ROUTER=$SAFEYOLO_SINKHOLE_ROUTER"
echo "  BLOCK=true"

safeyolo start
