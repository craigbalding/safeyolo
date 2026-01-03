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

# Install CA cert to system trust store for Python/pip SSL verification
if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
    if [ ! -f /usr/local/share/ca-certificates/mitmproxy.crt ]; then
        echo "Installing CA certificate to system trust store..."
        cp "${CERT_DIR}/mitmproxy-ca-cert.pem" /usr/local/share/ca-certificates/mitmproxy.crt
        if ! update-ca-certificates --fresh; then
            echo "ERROR: CA certificate installation failed"
            echo "  pip/curl may fail with SSL errors when going through proxy"
            # Non-fatal - proxy will still work for non-SSL or --insecure requests
        fi
    fi
fi

# Build addon chain - order matters!
# Request ID first (enables event correlation across all addons):
#   1. request_id - Assigns unique ID to every request
# Infrastructure addons (policy, streaming):
#   2. sse_streaming - SSE/streaming support
#   3. policy - Unified policy engine (other addons check this)
# Traffic management:
#   4. rate_limiter - Per-domain rate limiting (prevents IP blacklisting)
#   5. circuit_breaker - Fail-fast for unhealthy upstreams
# Security addons (can block requests):
#   6. credential_guard - API key protection
#   7. yara_scanner - YARA-based threat detection (extended build only)
#   8. pattern_scanner - Fast regex scanning
#   9. prompt_injection - ML-based injection detection (extended build only)
# Observability addons (observe but don't block):
#   10. request_logger - JSONL structured logging
#   11. metrics - Per-domain statistics
#   12. admin_api - Control plane REST API

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
load_addon "/app/addons/request_id.py"
load_addon "/app/addons/sse_streaming.py"
load_addon "/app/addons/policy.py"
#load_addon "/app/addons/service_discovery.py"
load_addon "/app/addons/rate_limiter.py"
load_addon "/app/addons/circuit_breaker.py"
load_addon "/app/addons/credential_guard.py"
load_addon "/app/addons/yara_scanner.py"      # Extended build only
load_addon "/app/addons/prompt_injection.py"  # Extended build only
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
# Each addon has its own blocking default. SAFEYOLO_BLOCK=true overrides all to block.
# Individual addon flags (e.g., credguard_block) can be set for fine-grained control.
#
# NOTE: Runtime mode changes via admin API are in-memory only.
# On restart/reload, SafeYolo returns to these startup defaults.
# ==============================================================================
echo ""
echo "Security addon blocking modes:"

# credential-guard: defaults to BLOCK
CREDGUARD_BLOCK="${CREDGUARD_BLOCK:-true}"
if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
    CREDGUARD_BLOCK="true"
fi
if [ "${CREDGUARD_BLOCK}" = "true" ]; then
    echo "  credential-guard: BLOCK"
    MITM_OPTS="${MITM_OPTS} --set credguard_block=true"
else
    echo "  credential-guard: WARN-ONLY"
    MITM_OPTS="${MITM_OPTS} --set credguard_block=false"
fi

# prompt-injection: defaults to WARN-ONLY
if [ -f "/app/addons/prompt_injection.py" ]; then
    INJECTION_BLOCK="${INJECTION_BLOCK:-false}"
    if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
        INJECTION_BLOCK="true"
    fi
    if [ "${INJECTION_BLOCK}" = "true" ]; then
        echo "  prompt-injection: BLOCK"
        MITM_OPTS="${MITM_OPTS} --set injection_block=true"
    else
        echo "  prompt-injection: WARN-ONLY"
    fi
fi

# yara-scanner: defaults to WARN-ONLY
if [ -f "/app/addons/yara_scanner.py" ]; then
    YARA_BLOCK="${YARA_BLOCK:-false}"
    if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
        YARA_BLOCK="true"
    fi
    if [ "${YARA_BLOCK}" = "true" ]; then
        echo "  yara-scanner: BLOCK"
        MITM_OPTS="${MITM_OPTS} --set yara_block_on_match=true"
    else
        echo "  yara-scanner: WARN-ONLY"
    fi
fi

# pattern-scanner: defaults to WARN-ONLY
if [ -f "/app/addons/pattern_scanner.py" ]; then
    PATTERN_BLOCK="${PATTERN_BLOCK:-false}"
    if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
        PATTERN_BLOCK="true"
    fi
    if [ "${PATTERN_BLOCK}" = "true" ]; then
        echo "  pattern-scanner: BLOCK"
        MITM_OPTS="${MITM_OPTS} --set pattern_block_input=true"
        MITM_OPTS="${MITM_OPTS} --set pattern_block_output=true"
    else
        echo "  pattern-scanner: WARN-ONLY"
    fi
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

# Ensure ntfy topic exists before mitmproxy starts
# credential_guard will use this file; listener starts after admin API ready
NTFY_TOPIC_FILE="/app/data/ntfy_topic"
if [ ! -f "$NTFY_TOPIC_FILE" ] && [ -z "${NTFY_TOPIC}" ]; then
    echo ""
    echo "Generating ntfy topic..."
    mkdir -p /app/data
    python3 -c "import secrets; print(f'safeyolo-{secrets.token_urlsafe(32)}')" > "$NTFY_TOPIC_FILE"
    GENERATED_TOPIC=$(cat "$NTFY_TOPIC_FILE")
    echo "Topic: ${GENERATED_TOPIC}"
    echo "Subscribe: https://ntfy.sh/${GENERATED_TOPIC}"
fi

# Generate admin API token if not provided
ADMIN_TOKEN_FILE="/app/data/admin_token"
if [ ! -f "$ADMIN_TOKEN_FILE" ] && [ -z "${ADMIN_API_TOKEN}" ]; then
    echo ""
    echo "Generating admin API token..."
    mkdir -p /app/data
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$ADMIN_TOKEN_FILE"
    chmod 600 "$ADMIN_TOKEN_FILE"
    GENERATED_TOKEN=$(cat "$ADMIN_TOKEN_FILE")
    echo "=== Admin API Token (save this): ==="
    echo "${GENERATED_TOKEN}"
    echo "===================================="
fi

# Load token for mitmproxy options
if [ -f "$ADMIN_TOKEN_FILE" ]; then
    ADMIN_TOKEN=$(cat "$ADMIN_TOKEN_FILE")
elif [ -n "${ADMIN_API_TOKEN}" ]; then
    ADMIN_TOKEN="${ADMIN_API_TOKEN}"
fi

# Add to mitmproxy options if token exists
if [ -n "${ADMIN_TOKEN}" ]; then
    MITM_OPTS="${MITM_OPTS} --set admin_api_token=${ADMIN_TOKEN}"
fi

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
    if curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/health 2>/dev/null | grep -q 200; then
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
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"mode":"block"}' > /dev/null 2>&1

# Verify it took effect via GET /plugins/rate-limiter/mode
MODE=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/plugins/rate-limiter/mode 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('mode','unknown'))" 2>/dev/null)

if [ "$MODE" != "block" ]; then
    echo "ERROR: Failed to set rate limiter to block mode (got: $MODE) - failing closed"
    tmux kill-session -t proxy 2>/dev/null
    exit 1
fi

echo "Rate limiter confirmed in block mode"

# Start ntfy approval listener (topic was generated before mitmproxy started)
NTFY_TOPIC_FILE="/app/data/ntfy_topic"
if [ -f "$NTFY_TOPIC_FILE" ] || [ -n "${NTFY_TOPIC}" ]; then
    echo ""
    echo "Starting ntfy approval listener..."
    python3 /app/scripts/ntfy_approval_listener.py \
        --admin-url "http://localhost:${ADMIN_PORT}" \
        >> "${LOG_DIR}/approval_listener.log" 2>&1 &
    LISTENER_PID=$!
    echo "Approval listener PID: ${LISTENER_PID}"
else
    echo ""
    echo "Ntfy approval listener disabled (no topic configured)"
    echo "  Set NTFY_TOPIC env var or create data/ntfy_topic to enable"
fi

# Tail JSONL logs to stdout (for docker logs -f)
echo "SafeYolo ready - tailing JSONL logs to stdout"
tail -f "${LOG_DIR}/safeyolo.jsonl" &
TAIL_PID=$!

# Wait for tail (keeps shell alive to reap zombie children)
wait $TAIL_PID
