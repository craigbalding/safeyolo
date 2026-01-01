#!/bin/bash
#
# SafeYolo startup script
#
# Generates mitmproxy CA cert if needed, then starts mitmproxy TUI
# in tmux with native addon chain. JSONL logs are tailed to stdout
# for `docker logs -f`.
#
# Attach to TUI: docker exec -it safeyolo tmux attach
#

set -e

CERT_DIR="${CERT_DIR:-/certs}"
LOG_DIR="${LOG_DIR:-/app/logs}"
CONFIG_DIR="${CONFIG_DIR:-/app/config}"
PROXY_PORT="${PROXY_PORT:-8080}"
ADMIN_PORT="${ADMIN_PORT:-9090}"

echo "=== SafeYolo Proxy Starting ==="
echo "Proxy port: ${PROXY_PORT}"
echo "Admin port: ${ADMIN_PORT}"
echo "Cert dir: ${CERT_DIR}"
echo "Log dir: ${LOG_DIR}"

# Ensure directories exist
mkdir -p "${CERT_DIR}" "${LOG_DIR}"

# Generate mitmproxy CA cert if not present
if [ ! -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
    echo "Generating mitmproxy CA certificate..."
    # Run mitmproxy briefly to generate certs
    timeout 3 mitmdump --set confdir="${CERT_DIR}" -p 0 2>/dev/null || true

    if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
        echo "CA certificate generated successfully"
        # Make cert readable by other containers
        chmod 644 "${CERT_DIR}/mitmproxy-ca-cert.pem"
    else
        echo "ERROR: Failed to generate CA certificate"
        exit 1
    fi
else
    echo "Using existing CA certificate"
fi

# Build addon chain - order matters!
# Infrastructure addons first (policy, discovery):
#   1. policy - Unified policy engine (other addons check this)
#   2. service_discovery - Docker container discovery
# Traffic management:
#   3. rate_limiter - Per-domain rate limiting (prevents IP blacklisting)
#   4. circuit_breaker - Fail-fast for unhealthy upstreams
# Security addons (can block requests):
#   5. credential_guard - API key protection
#   6. yara_scanner - YARA-based threat detection (extended build only)
#   7. pattern_scanner - Fast regex scanning
#   8. prompt_injection - ML-based injection detection (extended build only)
# Observability addons (observe but don't block):
#   9. request_logger - JSONL structured logging
#   10. metrics - Per-domain statistics
#   11. admin_api - Control plane REST API

ADDON_ARGS=""

# Helper function to conditionally load addon if file exists
load_addon() {
    local addon_path="$1"
    if [ -f "${addon_path}" ]; then
        ADDON_ARGS="${ADDON_ARGS} -s ${addon_path}"
        echo "  - $(basename ${addon_path})"
    else
        echo "  - $(basename ${addon_path}) (skipped - not in this build)"
    fi
    # Always return 0 to avoid triggering 'set -e'
    return 0
}

echo "Loading addons:"
load_addon "/app/addons/sse_streaming.py"
load_addon "/app/addons/policy.py"
#load_addon "/app/addons/service_discovery.py"
load_addon "/app/addons/rate_limiter.py"
#load_addon "/app/addons/circuit_breaker.py"
load_addon "/app/addons/credential_guard.py"
load_addon "/app/addons/prompt_injection.py"  # Extended build only
#load_addon "/app/addons/yara_scanner.py"  # Extended build only
#load_addon "/app/addons/pattern_scanner.py"
load_addon "/app/addons/request_logger.py"
load_addon "/app/addons/metrics.py"
load_addon "/app/addons/admin_api.py"
echo ""

# mitmproxy options
MITM_OPTS=""
MITM_OPTS="${MITM_OPTS} --set confdir=${CERT_DIR}"
MITM_OPTS="${MITM_OPTS} --set block_global=false"
# Note: SSE endpoints (mcp.apify.com, ntfy.sh) now handled by sse_streaming addon
# They go through the proxy for credential guard inspection, with streaming enabled
# TLS passthrough for frpc - frp protocol doesn't work through MITM
# Port 7000 is frps server, port 443 still gets MITM for health checks
MITM_OPTS="${MITM_OPTS} --ignore-hosts '^api\\.asterfold\\.ai:7000$'"
MITM_OPTS="${MITM_OPTS} --set safeyolo_log_path=${LOG_DIR}/safeyolo.jsonl"
MITM_OPTS="${MITM_OPTS} --set credguard_log_path=${LOG_DIR}/safeyolo.jsonl"
MITM_OPTS="${MITM_OPTS} --set admin_port=${ADMIN_PORT}"
# Stream large responses to prevent OOM on media downloads (podcasts, etc.)
# Security addons operate on request bodies and LLM API responses, not large media files
MITM_OPTS="${MITM_OPTS} --set stream_large_bodies=10m"

# Ollama for async prompt injection verification (phi3.5 catches subtle attacks PIGuard misses)
# NOTE: injection_ollama_url is set by the addon reading OLLAMA_URL env var directly
# Cannot use --set for options defined by script addons (they load after options are parsed)
if [ -n "${OLLAMA_URL}" ]; then
    echo "Ollama async verification: ${OLLAMA_URL}"
fi

# ==============================================================================
# Blocking mode configuration
# By default, all security addons are WARN-ONLY (log but don't block).
# Set SAFEYOLO_BLOCK=true to enable blocking for all security addons.
# Or set individual addon flags for fine-grained control.
#
# NOTE: Runtime mode changes via admin API are in-memory only.
# On restart/reload, SafeYolo returns to these startup defaults.
# For persistent blocking, set SAFEYOLO_BLOCK=true here or in docker-compose.yml.
# ==============================================================================
echo ""
if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
    echo "Security mode: BLOCKING (all addons will block on detection)"
    MITM_OPTS="${MITM_OPTS} --set credguard_block=true"

    # Only set options for addons that are actually loaded
    if [ -f "/app/addons/prompt_injection.py" ]; then
        MITM_OPTS="${MITM_OPTS} --set injection_block=true"
    fi
    if [ -f "/app/addons/yara_scanner.py" ]; then
        MITM_OPTS="${MITM_OPTS} --set yara_block_on_match=true"
    fi
    if [ -f "/app/addons/pattern_scanner.py" ]; then
        MITM_OPTS="${MITM_OPTS} --set pattern_block_input=true"
        MITM_OPTS="${MITM_OPTS} --set pattern_block_output=true"
    fi
else
    echo "Security mode: WARN-ONLY (log detections, don't block)"
    echo "  Set SAFEYOLO_BLOCK=true to enable blocking"
fi
echo ""

# Add credential rules if file exists
if [ -f "${CONFIG_DIR}/credential_rules.json" ]; then
    MITM_OPTS="${MITM_OPTS} --set credguard_rules=${CONFIG_DIR}/credential_rules.json"
    echo "Using credential rules from ${CONFIG_DIR}/credential_rules.json"
fi

# Add YARA rules if custom file exists
if [ -f "${CONFIG_DIR}/custom.yar" ]; then
    MITM_OPTS="${MITM_OPTS} --set yara_rules=${CONFIG_DIR}/custom.yar"
    echo "Using custom YARA rules from ${CONFIG_DIR}/custom.yar"
fi

# Add prompt injection classifier URLs if set
if [ -n "${DEBERTA_URL}" ]; then
    MITM_OPTS="${MITM_OPTS} --set injection_deberta_url=${DEBERTA_URL}"
    echo "DeBERTa classifier: ${DEBERTA_URL}"
fi

# NOTE: injection_ollama_url read from OLLAMA_URL env var by addon directly
#if [ -n "${OLLAMA_URL}" ]; then
#    echo "Ollama classifier: ${OLLAMA_URL}"
#fi

# Add rate limit config if file exists
if [ -f "${CONFIG_DIR}/rate_limits.json" ]; then
    MITM_OPTS="${MITM_OPTS} --set ratelimit_config=${CONFIG_DIR}/rate_limits.json"
    echo "Using rate limits from ${CONFIG_DIR}/rate_limits.json"
fi

# Add policy config if file exists
if [ -f "${CONFIG_DIR}/policy.yaml" ]; then
    MITM_OPTS="${MITM_OPTS} --set policy_file=${CONFIG_DIR}/policy.yaml"
    echo "Using policy from ${CONFIG_DIR}/policy.yaml"
fi

#echo "Addons: policy -> discovery -> rate_limiter -> circuit_breaker -> credential_guard -> yara -> pattern -> injection -> logger -> metrics -> admin"
echo "Attach to TUI: docker exec -it safeyolo tmux attach"

# Ensure log file exists for tail
touch "${LOG_DIR}/safeyolo.jsonl"

# Start shell_mux container agent if configured (for CC command execution)
if [ -f /opt/shell_mux/container_agent.py ] && [ -n "${CONTAINER_NAME}" ]; then
    echo ""
    echo "Starting shell_mux agent (name=${CONTAINER_NAME}, mux=${MUX_HOST}:${MUX_PORT})..."
    python /opt/shell_mux/container_agent.py &
    echo "Agent PID: $!"
fi

# Build the mitmproxy command and save it for reload script
MITMPROXY_CMD="mitmproxy -p ${PROXY_PORT} ${ADDON_ARGS} ${MITM_OPTS} $@"
echo "${MITMPROXY_CMD}" > /tmp/mitmproxy-cmd.sh
chmod +x /tmp/mitmproxy-cmd.sh

# Start mitmproxy TUI in tmux (detached)
# tmux provides the PTY that mitmproxy's TUI needs
tmux new-session -d -s proxy "${MITMPROXY_CMD}"

# Give mitmproxy a moment to start (or crash)
sleep 2

# Check if tmux session is still alive
if ! tmux has-session -t proxy 2>/dev/null; then
    echo "ERROR: mitmproxy failed to start. Check ${LOG_DIR}/mitmproxy.log"
    cat "${LOG_DIR}/mitmproxy.log"
    exit 1
fi

# Configure rate limiter to block mode (fail closed if this fails)
echo "Configuring rate limiter to block mode..."
ADMIN_READY=false
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w '%{http_code}' http://localhost:9090/stats 2>/dev/null | grep -q 200; then
        ADMIN_READY=true
        break
    fi
    sleep 1
done

if [ "$ADMIN_READY" != "true" ]; then
    echo "ERROR: Admin API not ready after 30 seconds - failing closed"
    tmux kill-session -t proxy 2>/dev/null
    exit 1
fi

# Enable blocking for rate limiter and verify
curl -s -X PUT http://localhost:9090/plugins/rate-limiter/mode \
    -H "Content-Type: application/json" \
    -d '{"mode":"block"}' > /dev/null 2>&1

# Verify it took effect via GET /plugins/rate-limiter/mode
MODE=$(curl -s http://localhost:9090/plugins/rate-limiter/mode 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('mode','unknown'))" 2>/dev/null)

if [ "$MODE" != "block" ]; then
    echo "ERROR: Failed to set rate limiter to block mode (got: $MODE) - failing closed"
    tmux kill-session -t proxy 2>/dev/null
    exit 1
fi

echo "Rate limiter confirmed in block mode"

# Tail JSONL logs to stdout (for docker logs -f)
echo "SafeYolo ready - tailing JSONL logs to stdout"
exec tail -f "${LOG_DIR}/safeyolo.jsonl"
