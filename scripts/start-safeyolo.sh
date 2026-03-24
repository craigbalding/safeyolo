#!/bin/bash
#
# SafeYolo startup script
#
# Generates mitmproxy CA cert if needed, then starts mitmdump (headless)
# with native addon chain. JSONL logs go to file.
#
# For interactive TUI mode: SAFEYOLO_TUI=true
#   Runs mitmproxy in tmux, attach with: docker exec -it safeyolo tmux attach
#

set -e

# ---------------------------------------------------------------------------
# Graceful shutdown: send 'Q' to mitmproxy TUI (triggers done() hooks)
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "=== SafeYolo Shutdown ==="
    tmux send-keys -t proxy Q 2>/dev/null
    for i in 1 2 3 4 5 6 7 8; do
        tmux has-session -t proxy 2>/dev/null || { echo "mitmproxy exited"; break; }
        sleep 1
    done
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

CERT_DIR="${CERT_DIR:-/certs-private}"
PUBLIC_CERT_DIR="${PUBLIC_CERT_DIR:-/certs-public}"
CONFIG_DIR="${CONFIG_DIR:-/safeyolo}"
LOG_DIR="${LOG_DIR:-/app/logs}"
PROXY_PORT="${PROXY_PORT:-8080}"
ADMIN_PORT="${ADMIN_PORT:-9090}"

echo "=== SafeYolo Proxy Starting ==="
echo "Proxy port: ${PROXY_PORT}"
echo "Admin port: ${ADMIN_PORT}"
echo "Cert dir: ${CERT_DIR}"
echo "Log dir: ${LOG_DIR}"

# Ensure directories exist and are writable
mkdir -p "${CERT_DIR}" "${PUBLIC_CERT_DIR}" "${LOG_DIR}" 2>/dev/null || true

# Check write permissions (important for non-root execution)
if ! touch "${CERT_DIR}/.write-test" 2>/dev/null; then
    echo "ERROR: Cannot write to ${CERT_DIR}"
    echo "  If using non-root (SAFEYOLO_UID/GID), the safeyolo-certs volume"
    echo "  may have root ownership from a previous run."
    echo "  Fix: docker volume rm safeyolo-certs && docker volume create safeyolo-certs"
    exit 1
fi
rm -f "${CERT_DIR}/.write-test"

if ! touch "${LOG_DIR}/.write-test" 2>/dev/null; then
    echo "ERROR: Cannot write to ${LOG_DIR}"
    echo "  Check directory permissions on host: ls -la ./logs/"
    exit 1
fi
rm -f "${LOG_DIR}/.write-test"

# Generate mitmproxy CA cert if not present (PRIVATE confdir)
if [ ! -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
    echo "Generating mitmproxy CA certificate..."
    # Run mitmproxy briefly to generate certs into PRIVATE confdir
    timeout 3 mitmdump --set confdir="${CERT_DIR}" -p 0 2>/dev/null || true

    if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
        echo "CA certificate generated successfully"
        # Keep PRIVATE confdir tight (contains private key material)
        chmod 600 "${CERT_DIR}/mitmproxy-ca-cert.pem" 2>/dev/null || true
        chmod 600 "${CERT_DIR}/mitmproxy-ca-cert.p12" 2>/dev/null || true
        chmod 600 "${CERT_DIR}/mitmproxy-ca.pem" 2>/dev/null || true
        chmod 700 "${CERT_DIR}" 2>/dev/null || true
    else
        echo "ERROR: Failed to generate CA certificate"
        exit 1
    fi
else
    echo "Using existing CA certificate"
fi

# Export PUBLIC CA cert for other containers (agents mount this read-only)
if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
    mkdir -p "${PUBLIC_CERT_DIR}" 2>/dev/null || true
    cp -f "${CERT_DIR}/mitmproxy-ca-cert.pem" "${PUBLIC_CERT_DIR}/mitmproxy-ca-cert.pem"
    chmod 644 "${PUBLIC_CERT_DIR}/mitmproxy-ca-cert.pem"
fi

# Install CA cert to system trust store for Python/pip SSL verification
# (Only relevant inside this container)
if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
    if [ "$(id -u)" = "0" ]; then
        if [ ! -f /usr/local/share/ca-certificates/mitmproxy.crt ]; then
            echo "Installing CA certificate to system trust store..."
            cp "${CERT_DIR}/mitmproxy-ca-cert.pem" /usr/local/share/ca-certificates/mitmproxy.crt
            if ! update-ca-certificates --fresh; then
                echo "WARNING: CA certificate installation failed"
                echo "  pip/curl may fail with SSL errors when going through proxy"
            fi
        fi
    else
        echo "Non-root: skipping system CA install (use SSL_CERT_FILE env var instead)"
        # For THIS container’s own clients (httpx/pip etc.)
        export SSL_CERT_FILE="${CERT_DIR}/mitmproxy-ca-cert.pem"
        export REQUESTS_CA_BUNDLE="${CERT_DIR}/mitmproxy-ca-cert.pem"
    fi
fi

# Build addon chain - order matters!
#
# Layer 0: Infrastructure (MUST be first)
#   0. file_logging       - Structured JSONL file logging setup
#   1. memory_monitor     - Process memory + connection tracking
#   2. admin_shield       - Block proxy access to admin API (security gate)
#   3. agent_api          - Read-only PDP agent API for agent self-service
#   4. loop_guard         - Detect and break proxy loops (Via header)
#   5. request_id         - Assign unique ID for event correlation
#   6. service_discovery  - Map container IPs to agent names (stamps flow.metadata["agent"])
#   7. sse_streaming      - SSE/streaming support for LLM responses
#   8. policy_engine      - Unified policy evaluation (other addons query this)
#
# Layer 0.5: Service Gateway (between policy_engine and network_guard)
#   8.5 service_gateway - Credential injection for agents (sgw_ tokens)
#
# Layer 1: Network Policy (single evaluation for access + rate limiting)
#   9. network_guard   - Access control + rate limiting (deny→403, budget→429)
#  10. circuit_breaker - Fail-fast for unhealthy upstreams
#
# Layer 2: Security Inspection (credential and content scanning)
#  11. credential_guard - API key protection and routing
#  12. pattern_scanner  - Fast regex for secrets/jailbreaks
#  13. test_context     - X-Test-Context header enforcement for target hosts
#
# Layer 3: Observability (observe but don't block)
#  14. request_logger - JSONL structured logging
#  15. metrics        - Per-domain statistics
#  16. admin_api      - Control plane REST API
#
# TUI-only (appended when SAFEYOLO_TUI=true):
#  17. flow_pruner    - Prune old flows to prevent memory growth

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
# Layer 0: Infrastructure
load_addon "/app/addons/file_logging.py"
load_addon "/app/addons/memory_monitor.py"
load_addon "/app/addons/admin_shield.py"
load_addon "/app/addons/agent_api.py"
load_addon "/app/addons/loop_guard.py"
load_addon "/app/addons/request_id.py"
load_addon "/app/addons/service_discovery.py"
load_addon "/app/addons/sse_streaming.py"
load_addon "/app/addons/policy_engine.py"
# Layer 0.5: Service Gateway
load_addon "/app/addons/service_gateway.py"
# Layer 1: Network Policy
load_addon "/app/addons/network_guard.py"
load_addon "/app/addons/circuit_breaker.py"
# Layer 2: Security Inspection
load_addon "/app/addons/credential_guard.py"
load_addon "/app/addons/pattern_scanner.py"
load_addon "/app/addons/test_context.py"
# Layer 3: Observability
load_addon "/app/addons/flow_recorder.py"
load_addon "/app/addons/request_logger.py"
load_addon "/app/addons/metrics.py"
load_addon "/app/addons/admin_api.py"
echo ""

# mitmproxy options
MITM_OPTS=""
MITM_OPTS="${MITM_OPTS} --set confdir=${CERT_DIR}"
MITM_OPTS="${MITM_OPTS} --set block_global=false"

# Custom upstream CA trust (SAFEYOLO_CA_CERT)
# Used for: blackbox tests (test CA), corporate environments (internal CA)
# Only affects mitmproxy's upstream TLS verification (SafeYolo doesn't initiate outbound calls)
if [ -n "${SAFEYOLO_CA_CERT}" ]; then
    if [ -f "${SAFEYOLO_CA_CERT}" ]; then
        echo "Trusting upstream CA: ${SAFEYOLO_CA_CERT}"
        MITM_OPTS="${MITM_OPTS} --set ssl_verify_upstream_trusted_ca=${SAFEYOLO_CA_CERT}"
    else
        echo "ERROR: SAFEYOLO_CA_CERT set but file not found: ${SAFEYOLO_CA_CERT}"
        exit 1
    fi
fi
# Note: SSE endpoints (mcp.apify.com, ntfy.sh) now handled by sse_streaming addon
# They go through the proxy for credential guard inspection, with streaming enabled
# TLS passthrough for frpc - frp protocol doesn't work through MITM
# Port 7000 is frps server, port 443 still gets MITM for health checks
MITM_OPTS="${MITM_OPTS} --ignore-hosts '^api\\.asterfold\\.ai:7000$'"
MITM_OPTS="${MITM_OPTS} --set admin_port=${ADMIN_PORT}"
# Stream large responses to prevent OOM on media downloads (podcasts, etc.)
# Security addons operate on request bodies and LLM API responses, not large media files
MITM_OPTS="${MITM_OPTS} --set stream_large_bodies=10m"

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

# network-guard: defaults to BLOCK (combines access control + rate limiting)
NETWORK_GUARD_BLOCK="${NETWORK_GUARD_BLOCK:-true}"
if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
    NETWORK_GUARD_BLOCK="true"
fi
if [ "${NETWORK_GUARD_BLOCK}" = "true" ]; then
    echo "  network-guard: BLOCK"
    MITM_OPTS="${MITM_OPTS} --set network_guard_block=true"
else
    echo "  network-guard: WARN-ONLY"
    MITM_OPTS="${MITM_OPTS} --set network_guard_block=false"
fi

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

# test-context: defaults to BLOCK (428 soft-reject for missing context)
if [ -f "/app/addons/test_context.py" ]; then
    TEST_CONTEXT_BLOCK="${TEST_CONTEXT_BLOCK:-true}"
    if [ "${SAFEYOLO_BLOCK}" = "true" ]; then
        TEST_CONTEXT_BLOCK="true"
    fi
    if [ "${TEST_CONTEXT_BLOCK}" = "true" ]; then
        echo "  test-context: BLOCK"
        MITM_OPTS="${MITM_OPTS} --set test_context_block=true"
    else
        echo "  test-context: WARN-ONLY"
        MITM_OPTS="${MITM_OPTS} --set test_context_block=false"
    fi
fi
echo ""

# Service Gateway — auto-enable when vault key exists
if [ -f "${CONFIG_DIR}/data/vault.key" ] && [ -f "${CONFIG_DIR}/data/vault.yaml.enc" ]; then
    echo "Service gateway: ENABLED (vault found)"
    MITM_OPTS="${MITM_OPTS} --set gateway_enabled=true"
    MITM_OPTS="${MITM_OPTS} --set gateway_services_dir=${CONFIG_DIR}/services"
    MITM_OPTS="${MITM_OPTS} --set gateway_vault_path=${CONFIG_DIR}/data/vault.yaml.enc"
    MITM_OPTS="${MITM_OPTS} --set gateway_vault_key=${CONFIG_DIR}/data/vault.key"
fi

# Add rate limit config if file exists
if [ -f "${CONFIG_DIR}/rate_limits.json" ]; then
    MITM_OPTS="${MITM_OPTS} --set ratelimit_config=${CONFIG_DIR}/rate_limits.json"
    echo "Using rate limits from ${CONFIG_DIR}/rate_limits.json"
fi

# Policy file is REQUIRED - fail closed if missing
if [ ! -f "${CONFIG_DIR}/policy.yaml" ]; then
    echo ""
    echo "=========================================="
    echo "FATAL: Policy file not found"
    echo "=========================================="
    echo ""
    echo "SafeYolo requires a policy file to operate."
    echo "Expected: ${CONFIG_DIR}/policy.yaml"
    echo ""
    echo "To fix:"
    echo "  1. Run 'safeyolo init' to create default policy"
    echo "  2. Or mount your own policy.yaml to ${CONFIG_DIR}/"
    echo ""
    echo "A security proxy cannot run without a policy."
    echo "=========================================="
    exit 1
fi
MITM_OPTS="${MITM_OPTS} --set policy_file=${CONFIG_DIR}/policy.yaml"
echo "Using policy from ${CONFIG_DIR}/policy.yaml"

#echo "Addons: policy -> discovery -> rate_limiter -> circuit_breaker -> credential_guard -> yara -> pattern -> injection -> logger -> metrics -> admin"
echo "For TUI mode: set SAFEYOLO_TUI=true"

# Ensure log files exist
touch "${LOG_DIR}/safeyolo.jsonl"
touch "${LOG_DIR}/mitmproxy.log"
echo "Logs: ${LOG_DIR}/safeyolo.jsonl (structured), ${LOG_DIR}/mitmproxy.log (addon debug)"

# Generate admin API token if not provided
ADMIN_TOKEN_FILE="${CONFIG_DIR}/data/admin_token"
if [ ! -f "$ADMIN_TOKEN_FILE" ] && [ -z "${ADMIN_API_TOKEN}" ]; then
    echo ""
    echo "Generating admin API token..."
    mkdir -p "${CONFIG_DIR}/data"
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$ADMIN_TOKEN_FILE"
    chmod 600 "$ADMIN_TOKEN_FILE"
    GENERATED_TOKEN=$(cat "$ADMIN_TOKEN_FILE")
    echo "=== Admin API Token (save this): ==="
    echo "${GENERATED_TOKEN}"
    echo "===================================="
fi

# Generate agent API token (always regenerated on start)
AGENT_TOKEN_FILE="${CONFIG_DIR}/data/agent_token"
python3 -c "import secrets; print(secrets.token_hex(32))" > "$AGENT_TOKEN_FILE"
chmod 600 "$AGENT_TOKEN_FILE"

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

# ==============================================================================
# TUI mode (SAFEYOLO_TUI=true)
# Runs mitmproxy TUI in tmux - for interactive debugging/monitoring
# ==============================================================================
if [ "${SAFEYOLO_TUI}" = "true" ]; then
    echo ""
    echo "=== Starting in TUI mode (mitmproxy in tmux) ==="
    echo "Attach to TUI: docker exec -it safeyolo tmux attach"

    # TUI mode: load flow pruner to prevent unbounded memory growth.
    # mitmproxy keeps every flow in memory for the scrollable list.
    # Without pruning, this OOM-kills the process after ~1500-2000 flows.
    if [ -f "/app/addons/flow_pruner.py" ]; then
        ADDON_ARGS="${ADDON_ARGS} -s /app/addons/flow_pruner.py"
        echo "  - flow_pruner.py (TUI memory protection)"
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

    # Configure network guard to block mode (fail closed if this fails)
    echo "Configuring network guard to block mode..."
    ADMIN_READY=false
    for i in $(seq 1 30); do
        if python3 -c "import httpx; exit(0 if httpx.get('http://localhost:9090/health', headers={'Authorization': 'Bearer $ADMIN_TOKEN'}, timeout=2).status_code == 200 else 1)" 2>/dev/null; then
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

    # Enable blocking for network guard and verify
    python3 -c "import httpx; httpx.put('http://localhost:9090/plugins/network-guard/mode', json={'mode':'block'}, headers={'Authorization': 'Bearer $ADMIN_TOKEN'})" 2>/dev/null

    # Verify it took effect via GET /plugins/network-guard/mode
    MODE=$(python3 -c "import httpx; r=httpx.get('http://localhost:9090/plugins/network-guard/mode', headers={'Authorization': 'Bearer $ADMIN_TOKEN'}); print(r.json().get('mode','unknown'))" 2>/dev/null)

    if [ "$MODE" != "block" ]; then
        echo "ERROR: Failed to set network guard to block mode (got: $MODE) - failing closed"
        tmux kill-session -t proxy 2>/dev/null
        exit 1
    fi

    echo "Network guard confirmed in block mode"

    # Tail JSONL logs to stdout (for docker logs -f)
    echo "SafeYolo ready - tailing JSONL logs to stdout"
    tail -f "${LOG_DIR}/safeyolo.jsonl" &
    TAIL_PID=$!

    # Wait for tail (keeps shell alive to reap zombie children)
    wait $TAIL_PID
    exit 0
fi

# ==============================================================================
# Headless mode (default) - mitmdump without tmux/TUI
# ==============================================================================
echo ""
echo "=== Starting in headless mode (mitmdump) ==="
# File logging configured via file_logging.py addon's running() hook
# exec replaces shell - Docker manages process lifecycle
exec mitmdump -p ${PROXY_PORT} ${ADDON_ARGS} ${MITM_OPTS} "$@"
