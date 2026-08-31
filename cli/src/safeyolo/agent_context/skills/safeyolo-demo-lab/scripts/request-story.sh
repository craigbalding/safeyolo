#!/usr/bin/env bash
set -uo pipefail

usage() {
    printf 'Usage: %s [--brief|--full] [HOST]\n' "${0##*/}" >&2
    exit 2
}

detail=brief
case "${1:-}" in
  --brief)
    shift
    ;;
  --full)
    detail=full
    shift
    ;;
esac

[ "$#" -le 1 ] || usage
target_host=${1:-example.com}
if [[ ! "$target_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    printf 'Invalid host: %s\n' "$target_host" >&2
    exit 2
fi

target_url="https://$target_host/"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit
headers_file=$(mktemp) || exit
body_file=$(mktemp) || {
    rm -f "$headers_file"
    exit
}
trace_file=$(mktemp) || {
    rm -f "$headers_file" "$body_file"
    exit
}
trap 'rm -f "$headers_file" "$body_file" "$trace_file"' EXIT

sy_api() (
    sy_path=$1
    shift
    agent_token=$(cat /app/agent_token) || exit
    printf 'Authorization: Bearer %s\n' "$agent_token" |
        curl -sS --header @- \
            "http://_safeyolo.proxy.internal$sy_path" "$@"
)

printf '\n=== Question ===\n'
printf 'Can this agent request %s, and which SafeYolo addons handle it?\n' \
    "$target_url"

printf '\n=== SafeYolo policy view before the request ===\n'
sy_api "/lookup?host=$target_host" | jq .
lookup_rc=$?

printf '\n=== Ordinary application request ===\n'
curl -sS \
    --max-time 30 \
    --header 'X-SafeYolo-Trace: 1' \
    --dump-header "$headers_file" \
    --output "$body_file" \
    --write-out 'http_status=%{http_code} total_seconds=%{time_total}\n' \
    "$target_url"
request_rc=$?
printf 'curl_exit=%s\n' "$request_rc"

printf '\nSelected response headers:\n'
awk '
    {
        lowercase=tolower($0)
        if ($0 ~ /^HTTP\// ||
            lowercase ~ /^x-safeyolo-request-id:/ ||
            lowercase ~ /^x-blocked-by:/ ||
            lowercase ~ /^content-type:/ ||
            lowercase ~ /^content-length:/) {
            sub(/\r$/, "")
            print
        }
    }
' "$headers_file"

content_type=$(
    awk '
        {
            lowercase=tolower($0)
            if (lowercase ~ /^content-type:/) {
                sub(/\r$/, "")
                sub(/^[^:]*:[[:space:]]*/, "")
                value=$0
            }
        }
        END { print value }
    ' "$headers_file"
)
body_bytes=$(wc -c < "$body_file")

printf '\nResponse body: bytes=%s content_type=%s\n' \
    "$body_bytes" "${content_type:-unknown}"
case "$content_type" in
  text/*|application/json*|application/xml*|application/javascript*)
    head -c 16384 "$body_file"
    printf '\n'
    if [ "$body_bytes" -gt 16384 ]; then
        printf '[body display limited to the first 16384 bytes]\n'
    fi
    ;;
  *)
    printf '[body not rendered because the response is not identified as text]\n'
    ;;
esac

request_id=$(
    awk '
        {
            lowercase=tolower($0)
            if (lowercase ~ /^x-safeyolo-request-id:/) {
                sub(/\r$/, "")
                sub(/^[^:]*:[[:space:]]*/, "")
                value=$0
            }
        }
        END { print value }
    ' "$headers_file"
)

trace_rc=0
if [ -n "$request_id" ]; then
    printf '\n=== SafeYolo addon trace for %s ===\n' "$request_id"
    if sy_api "/trace?request_id=$request_id" > "$trace_file" &&
        jq -e . "$trace_file" >/dev/null; then
        if [ "$detail" = full ]; then
            jq '{request_id, truncated, steps, not_loaded}' "$trace_file"
        else
            jq -r '
                "request_id=\(.request_id) truncated=\(.truncated)",
                (.steps[] |
                    "addon=\(.addon) hook=\(.hook) state=\(.state) outcome=\(.outcome)" +
                    (if .reason then " reason=\(.reason)" else "" end)),
                (.not_loaded[]? | "addon=\(.addon) state=not_loaded")
            ' "$trace_file"
        fi
        trace_rc=$?

        printf '\n=== What each addon outcome means ===\n'
        jq -r -f "$script_dir/explain-trace.jq" "$trace_file"
        explanation_rc=$?
        [ "$explanation_rc" -eq 0 ] || trace_rc=$explanation_rc
    else
        printf 'Trace lookup failed or returned invalid JSON. Response follows:\n' >&2
        sed -n '1,80p' "$trace_file" >&2
        trace_rc=1
    fi
else
    printf '\nNo SafeYolo request ID was present. No trace lookup was made.\n'
    trace_rc=1
fi

demo_rc=0
[ "$lookup_rc" -eq 0 ] || demo_rc=$lookup_rc
[ "$request_rc" -eq 0 ] || demo_rc=$request_rc
[ "$trace_rc" -eq 0 ] || demo_rc=$trace_rc

printf '\n__SAFEYOLO_REQUEST_DEMO_DONE__ rc=%s\n' "$demo_rc"
exit "$demo_rc"
