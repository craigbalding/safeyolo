#!/bin/bash
#
# approval-handler.sh - Listen for approval callbacks and update SafeYolo allowlist
#
# Usage:
#   ./approval-handler.sh
#
# Environment:
#   NTFY_TOPIC      - ntfy.sh topic to subscribe to (required)
#   SAFEYOLO_HOST   - SafeYolo container host (default: safeyolo for Docker, localhost otherwise)
#   SAFEYOLO_PORT   - SafeYolo admin API port (default: 9090)
#
# Listens for approval messages from ntfy and calls the SafeYolo admin API
# to temporarily allowlist credentials.
#

set -euo pipefail

NTFY_TOPIC="${NTFY_TOPIC:-}"
SAFEYOLO_HOST="${SAFEYOLO_HOST:-safeyolo}"
SAFEYOLO_PORT="${SAFEYOLO_PORT:-9090}"

if [[ -z "$NTFY_TOPIC" ]]; then
    echo "ERROR: NTFY_TOPIC not set" >&2
    exit 1
fi

SAFEYOLO_API="http://${SAFEYOLO_HOST}:${SAFEYOLO_PORT}"

echo "Listening for approvals on ntfy.sh/$NTFY_TOPIC..."
echo "SafeYolo API: $SAFEYOLO_API"

# Subscribe to ntfy topic
curl -s "https://ntfy.sh/$NTFY_TOPIC/json" | while IFS= read -r line; do
    # Skip empty lines
    [[ -z "$line" ]] && continue

    # Parse the message
    message=$(echo "$line" | jq -r '.message // empty' 2>/dev/null) || continue
    [[ -z "$message" ]] && continue

    # Try to parse as JSON (our approval payload)
    action=$(echo "$message" | jq -r '.action // empty' 2>/dev/null) || continue

    if [[ "$action" == "approve_credential" ]]; then
        credential_prefix=$(echo "$message" | jq -r '.credential_prefix')
        host=$(echo "$message" | jq -r '.host')
        ttl=$(echo "$message" | jq -r '.ttl // 300')

        echo "Approval received: $credential_prefix -> $host for ${ttl}s"

        # Call SafeYolo admin API to add temp allowlist
        response=$(curl -s -X POST "${SAFEYOLO_API}/plugins/credential-guard/allowlist" \
            -H "Content-Type: application/json" \
            -d "$(jq -n \
                --arg prefix "$credential_prefix" \
                --arg host "$host" \
                --argjson ttl "$ttl" \
                '{credential_prefix: $prefix, host: $host, ttl_seconds: $ttl}'
            )" 2>&1) || true

        echo "API response: $response"
    fi
done
