#!/bin/bash
# Run in the caller sandbox. Keep the gateway token only in this process memory.
set -euo pipefail
cd "${1:-/workspace}"
trap 'unset token listing; rm -f response headers' EXIT
refresh_token() {
    local agent_token listing pattern
    agent_token=$(cat /app/agent_token)
    listing=$(printf 'Authorization: Bearer %s\n' "$agent_token" |
        curl --silent --show-error --fail --max-time 15 --header @- \
        http://_safeyolo.proxy.internal/gateway/services)
    pattern='"token"[[:space:]]*:[[:space:]]*"(sgw_[A-Za-z0-9_-]+)"'
    [[ $listing =~ $pattern ]]
    token=${BASH_REMATCH[1]}
    unset BASH_REMATCH
}
refresh_token
url=http://proofspot.safeyolo.internal:8088/api/v1/value

request() {
    local label=$1 method=$2 target=$3 status digest
    status=$(printf 'Authorization: Bearer %s\n' "$token" |
        curl --silent --show-error --max-time 20 --header @- \
        -H 'X-SafeYolo-Agent: forged' -H 'X-SafeYolo-Agent-ID: forged-id' \
        -H 'X-SafeYolo-Agent-Name: forged-name' --request "$method" \
        --dump-header headers --output response --write-out '%{http_code}' "$target")
    digest=$(sha256sum response)
    printf '%s\t%s\t%s\n' "$label" "$status" "${digest%% *}" >> results.tsv
    rm response headers
}

await_phase() {
    local phase=$1
    for ((attempt = 0; attempt < 900; attempt++)); do
        if [[ -e $phase.go ]]; then return; fi
        sleep 0.1
    done
    printf 'Timed out waiting for host phase %s\n' "$phase" >&2
    return 1
}

request method DELETE "$url"
request path GET http://proofspot.safeyolo.internal:8088/outside
request destination GET http://unrelated.safeyolo.internal:8088/api/v1/value
request port GET http://proofspot.safeyolo.internal:8089/api/v1/value
touch refusals.ready
await_phase allowed
request allowed GET "$url"
touch allowed.ready
await_phase revoked
request revoked GET "$url"
touch revoked.ready
await_phase recovered
refresh_token
request recovered GET "$url"
touch recovered.ready
await_phase closed
request closed GET "$url"
touch closed.ready
await_phase stopped
request stopped GET "$url"
touch stopped.ready
