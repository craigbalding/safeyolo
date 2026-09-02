#!/usr/bin/env bash
set -uo pipefail

printf '\n=== SafeYolo guest boundary ===\n'
printf 'identity: '
id

for path in /home/agent /workspace /safeyolo /app/agent_token; do
    stat -c 'path=%n owner=%U:%G mode=%a type=%F' "$path" 2>/dev/null \
        || printf 'path=%s state=absent\n' "$path"
done

for name in HTTP_PROXY HTTPS_PROXY; do
    if [ -n "${!name:-}" ]; then
        printf '%s=set\n' "$name"
    else
        printf '%s=unset\n' "$name"
    fi
done

for name in SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS; do
    printf '%s=%s\n' "$name" "${!name:-unset}"
done

printf '\n=== SafeYolo Agent API health ===\n'
(
    agent_token=$(cat /app/agent_token) || exit
    printf 'Authorization: Bearer %s\n' "$agent_token" |
        curl -sS --header @- http://_safeyolo.proxy.internal/health
)
health_rc=$?
printf '\n__SAFEYOLO_BOUNDARY_DEMO_DONE__ rc=%s\n' "$health_rc"
exit "$health_rc"
