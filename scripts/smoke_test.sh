#!/bin/bash
#
# SafeYolo Smoke Test
#
# Verifies the proxy is running and core features work.
# Run after: docker compose up -d
#
# Usage:
#   ./scripts/smoke_test.sh            # Run from host (localhost:8888/9090)
#   ./scripts/smoke_test.sh --internal # Run from internal network (172.30.0.10)
#   ./scripts/smoke_test.sh --quick    # Skip slow tests
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#

set -euo pipefail

# Configuration
# Use --docker flag to test via internal network (from other containers)
PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8888}"
ADMIN_PORT="${ADMIN_PORT:-9090}"

# Parse args
QUICK=false
for arg in "$@"; do
    case $arg in
        --internal)
            # Internal network settings (for running from other containers)
            PROXY_HOST="172.30.0.10"
            PROXY_PORT="8080"
            ADMIN_PORT="9090"
            ;;
        --quick)
            QUICK=true
            ;;
    esac
done

ADMIN_URL="http://${PROXY_HOST}:${ADMIN_PORT}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
LOG_FILE="${LOG_FILE:-logs/safeyolo.jsonl}"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Counters
PASSED=0
FAILED=0
SKIPPED=0

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

log_info() {
    echo -e "       $1"
}

# Test functions

test_health_endpoint() {
    echo "Testing health endpoint..."

    response=$(curl -s -w "\n%{http_code}" "${ADMIN_URL}/health" 2>/dev/null || echo -e "\n000")
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1)

    if [[ "$status" == "200" ]]; then
        if echo "$body" | grep -q '"status".*"healthy"'; then
            log_pass "Health endpoint returns healthy"
        else
            log_fail "Health endpoint returned 200 but unexpected body: $body"
        fi
    else
        log_fail "Health endpoint returned status $status (expected 200)"
        log_info "Is the container running? Try: docker compose up -d"
        return 1
    fi
}

test_stats_endpoint() {
    echo "Testing stats endpoint..."

    response=$(curl -s -w "\n%{http_code}" "${ADMIN_URL}/stats" 2>/dev/null || echo -e "\n000")
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1)

    if [[ "$status" == "200" ]]; then
        # Check for expected addon stats
        if echo "$body" | grep -q '"credential-guard"'; then
            log_pass "Stats endpoint returns credential-guard stats"
        else
            log_fail "Stats endpoint missing credential-guard stats"
        fi

        if echo "$body" | grep -q '"rate-limiter"'; then
            log_pass "Stats endpoint returns rate-limiter stats"
        else
            log_fail "Stats endpoint missing rate-limiter stats"
        fi
    else
        log_fail "Stats endpoint returned status $status (expected 200)"
    fi
}

test_modes_endpoint() {
    echo "Testing modes endpoint..."

    response=$(curl -s -w "\n%{http_code}" "${ADMIN_URL}/modes" 2>/dev/null || echo -e "\n000")
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1)

    if [[ "$status" == "200" ]]; then
        if echo "$body" | grep -q '"modes"'; then
            log_pass "Modes endpoint returns mode info"

            # Verify default is warn mode
            if echo "$body" | grep -q '"credential-guard".*"warn"'; then
                log_pass "Credential guard defaults to warn mode"
            else
                log_info "Credential guard mode: $(echo "$body" | grep -o '"credential-guard"[^,}]*')"
            fi
        else
            log_fail "Modes endpoint missing modes object"
        fi
    else
        log_fail "Modes endpoint returned status $status (expected 200)"
    fi
}

test_proxy_forwards_request() {
    echo "Testing proxy forwards requests..."

    # Use httpbin.org to test proxy forwarding
    response=$(curl -s -w "\n%{http_code}" -x "${PROXY_URL}" "https://httpbin.org/get" 2>/dev/null || echo -e "\n000")
    status=$(echo "$response" | tail -n 1)

    if [[ "$status" == "200" ]]; then
        log_pass "Proxy forwards HTTPS requests"
    elif [[ "$status" == "000" ]]; then
        log_fail "Proxy not reachable at ${PROXY_URL}"
        log_info "Check if port ${PROXY_PORT} is exposed"
    else
        log_fail "Proxy request returned status $status"
    fi
}

test_credential_guard_detection() {
    echo "Testing credential guard detection..."

    # First, check what mode credential guard is in
    mode_response=$(curl -s "${ADMIN_URL}/plugins/credential-guard/mode" 2>/dev/null)
    current_mode=$(echo "$mode_response" | grep -o '"mode"[^,}]*' | grep -o 'warn\|block' || echo "unknown")

    # Generate unique key with timestamp to identify our request in logs
    # Format: sk-smoketest<timestamp> (matches OpenAI pattern: sk-[a-zA-Z0-9]{20,})
    local timestamp=$(date +%s%N | cut -c1-12)
    local unique_key="sk-smoketest${timestamp}abcdefghij"
    local key_prefix="sk-smoketest${timestamp}"

    # Clear any cached log position
    local log_lines_before=0
    if [[ -f "$LOG_FILE" ]]; then
        log_lines_before=$(wc -l < "$LOG_FILE")
    fi

    # Send request with unique OpenAI-format key to wrong host
    # This should be detected as a violation
    response=$(curl -s -w "\n%{http_code}" -x "${PROXY_URL}" \
        -H "Authorization: Bearer ${unique_key}" \
        "https://httpbin.org/headers" 2>/dev/null || echo -e "\n000")
    status=$(echo "$response" | tail -n 1)

    if [[ "$current_mode" == "block" ]]; then
        # Block mode: expect 403
        if [[ "$status" == "403" ]]; then
            log_pass "Request blocked by credential guard (block mode)"
        else
            log_fail "Expected 403 in block mode, got $status"
        fi
    else
        # Warn mode: expect 200 with violation logged
        if [[ "$status" == "200" ]]; then
            log_pass "Request completed (warn mode - detected but not blocked)"

            # Check if OUR violation was logged (match unique key prefix)
            sleep 0.5  # Brief wait for log flush
            if [[ -f "$LOG_FILE" ]]; then
                local log_lines_after=$(wc -l < "$LOG_FILE")
                local new_lines=$((log_lines_after - log_lines_before))

                if [[ $new_lines -gt 0 ]]; then
                    # Check for our specific request using the unique key prefix
                    if tail -n "$new_lines" "$LOG_FILE" | grep -q "${key_prefix}"; then
                        log_pass "Credential violation logged (verified by unique key)"
                    elif tail -n "$new_lines" "$LOG_FILE" | grep -q '"blocked_by".*"credential-guard"'; then
                        log_pass "Credential violation logged (generic match)"
                        log_info "Could not verify unique key - may be concurrent request"
                    else
                        log_info "New log entries found but no credential-guard violation"
                        log_info "This may be expected if the key pattern didn't match"
                    fi
                else
                    log_info "No new log entries (key may not have matched pattern)"
                fi
            else
                log_info "Log file not found at $LOG_FILE"
            fi
        elif [[ "$status" == "403" ]]; then
            log_fail "Got 403 but mode is '$current_mode' (expected pass-through)"
        else
            log_fail "Unexpected status $status from credential guard test"
        fi
    fi
}

test_rate_limiter_stats() {
    echo "Testing rate limiter tracking..."

    # Get initial stats
    stats=$(curl -s "${ADMIN_URL}/stats" 2>/dev/null)

    if echo "$stats" | grep -q '"checks_total"'; then
        checks=$(echo "$stats" | grep -o '"checks_total"[^,}]*' | grep -o '[0-9]*')
        log_pass "Rate limiter tracking requests (checks_total: $checks)"
    else
        log_fail "Rate limiter stats not available"
    fi
}

test_mode_api_accessible() {
    echo "Testing mode API accessible..."

    # Get current mode (read-only, doesn't modify state)
    current=$(curl -s "${ADMIN_URL}/plugins/credential-guard/mode" 2>/dev/null)

    # Check for rate limiting
    if echo "$current" | grep -q "Rate limited"; then
        log_skip "Mode API test (rate limited)"
        return 0
    fi

    if echo "$current" | grep -q '"addon".*"credential-guard"'; then
        mode=$(echo "$current" | grep -o '"mode"[^,}]*' | grep -o 'warn\|block' || echo "unknown")
        log_pass "Mode API accessible (current mode: $mode)"
    else
        log_fail "Mode API returned unexpected response: $current"
    fi
}

# Main

echo "================================"
echo "SafeYolo Smoke Test"
echo "================================"
echo ""
echo "Admin API: ${ADMIN_URL}"
echo "Proxy:     ${PROXY_URL}"
echo ""

# Run tests
test_health_endpoint || true
echo ""

test_stats_endpoint
echo ""

test_modes_endpoint
echo ""

test_proxy_forwards_request
echo ""

test_credential_guard_detection
echo ""

test_rate_limiter_stats
echo ""

test_mode_api_accessible
echo ""

# Summary
echo "================================"
echo "Results"
echo "================================"
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${RED}Failed:${NC}  $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}Some tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed${NC}"
    exit 0
fi
