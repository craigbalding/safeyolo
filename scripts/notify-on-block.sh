#!/bin/bash
#
# notify-on-block.sh - Send push notification when credential-guard blocks a request
#
# Usage:
#   docker logs -f safeyolo 2>&1 | ./notify-on-block.sh
#
# Environment:
#   PUSHCUT_URL    - Pushcut webhook URL (required)
#   NTFY_TOPIC     - ntfy.sh topic for approval callbacks (required)
#   SAFEYOLO_HOST   - SafeYolo container host (default: localhost)
#   SAFEYOLO_PORT   - SafeYolo admin API port (default: 9090)
#
# When a block is detected, sends a notification with:
#   - Block details (credential type, host)
#   - "Approve" button that temporarily allowlists the credential
#

set -euo pipefail

PUSHCUT_URL="${PUSHCUT_URL:-}"
NTFY_TOPIC="${NTFY_TOPIC:-}"
SAFEYOLO_HOST="${SAFEYOLO_HOST:-localhost}"
SAFEYOLO_PORT="${SAFEYOLO_PORT:-9090}"

if [[ -z "$PUSHCUT_URL" ]]; then
    echo "ERROR: PUSHCUT_URL not set" >&2
    exit 1
fi

if [[ -z "$NTFY_TOPIC" ]]; then
    echo "ERROR: NTFY_TOPIC not set" >&2
    exit 1
fi

echo "Watching for credential-guard blocks..."

while IFS= read -r line; do
    # Parse JSONL, look for block events
    event=$(echo "$line" | jq -r '.event // empty' 2>/dev/null) || continue

    if [[ "$event" != "block" ]]; then
        continue
    fi

    plugin=$(echo "$line" | jq -r '.plugin // "unknown"')
    if [[ "$plugin" != "credential-guard" ]]; then
        continue
    fi

    # Extract block details
    credential_prefix=$(echo "$line" | jq -r '.credential_prefix // empty')
    blocked_host=$(echo "$line" | jq -r '.blocked_host // .host // "unknown"')
    reason=$(echo "$line" | jq -r '.reason // "credential blocked"')
    request_id=$(echo "$line" | jq -r '.id // "unknown"')

    echo "Block detected: $credential_prefix -> $blocked_host"

    # Build approval payload
    # This will be sent to ntfy when user taps "Approve"
    approve_payload=$(jq -n \
        --arg prefix "$credential_prefix" \
        --arg host "$blocked_host" \
        '{action: "approve_credential", credential_prefix: $prefix, host: $host, ttl: 300}'
    )

    # Send Pushcut notification with Approve button
    curl -s -X POST "$PUSHCUT_URL" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
            --arg title "SafeYolo: Credential Blocked" \
            --arg text "$reason to $blocked_host" \
            --arg topic "$NTFY_TOPIC" \
            --arg payload "$approve_payload" \
            '{
                title: $title,
                text: $text,
                actions: [
                    {
                        name: "Approve 5min",
                        url: ("https://ntfy.sh/" + $topic),
                        urlBackgroundOptions: {
                            httpMethod: "POST",
                            httpContentType: "application/json",
                            httpBody: $payload
                        },
                        keepNotification: false
                    },
                    {
                        name: "Ignore",
                        keepNotification: false
                    }
                ]
            }'
        )"

    echo "Notification sent for $request_id"

done
