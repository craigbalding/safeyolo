#!/bin/sh
# Example: copy to ~/jobs/post-coord.sh and create ~/jobs/coord-message.json.
# The operator must grant this agent send permission in scheduled-work first.
set -eu
agent_token=$(cat /app/agent_token) || exit
printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl --silent --show-error --fail-with-body --max-time 20 \
        --header @- --header 'Content-Type: application/json' \
        --data-binary @/home/agent/jobs/coord-message.json \
        http://_safeyolo.proxy.internal/api/coord/rooms/scheduled-work/send
