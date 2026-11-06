#!/bin/bash
# Run under socat inside the producer sandbox. Record accepts before HTTP parsing.
set -euo pipefail
cd "${1:-/workspace}"
printf 'accept\n' >> accepts
IFS= read -r request
request=${request%$'\r'}
agent_id= agent_name= host= authorization=0 legacy=0 id_count=0 name_count=0
while IFS= read -r header && [[ $header != $'\r' && -n $header ]]; do
    header=${header%$'\r'}
    name=${header%%:*}
    value=${header#*:}
    value=${value# }
    case ${name,,} in
        host) host=$value ;;
        authorization) authorization=$((authorization + 1)) ;;
        x-safeyolo-agent) legacy=$((legacy + 1)) ;;
        x-safeyolo-agent-id) agent_id=$value; id_count=$((id_count + 1)) ;;
        x-safeyolo-agent-name) agent_name=$value; name_count=$((name_count + 1)) ;;
    esac
done
# Store only the controlled request and caller fields. Never retain credentials.
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$request" "$agent_id" "$agent_name" "$host" "$authorization" "$legacy" "$id_count" "$name_count" \
    >> requests.tsv
printf 'HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nnative-http-service\n'
