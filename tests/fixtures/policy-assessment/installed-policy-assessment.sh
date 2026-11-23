#!/usr/bin/env bash
# Guest-only phases. Prepare JSON on the host with prepare-policy-assessment.py.
# Use the same requester/run for disclosure, read, broad and narrow phases.
set -euo pipefail
phase=${1:?request, read, broad or narrow}
output=${2:-/workspace/policy-assessment-results}
set -a
. /safeyolo/proxy.env
set +a
export SAFEYOLO_COORD_TOKEN_PATH=/safeyolo/agent_token
coord="$HOME/.safeyolo/safeyolo-coord"
cd "$output"
case "$phase" in
  request)
    "$coord" --version > client-version.txt
    printf '%s\n' '{}' | "$coord" call discover_policy_capabilities > capabilities.json
    "$coord" call request_policy_snapshot < snapshot-request.json > disclosure-request.json
    ;;
  read)
    "$coord" call read_policy_snapshot < snapshot-read.json > approved-snapshot.json
    ;;
  broad)
    "$coord" call assess_policy < broad-request.json > broad-assessment.json
    ;;
  narrow)
    "$coord" call assess_policy < narrow-request.json > narrow-assessment.json
    "$coord" call assess_policy < narrow-request.json > narrow-assessment-repeated.json
    ;;
  *) echo 'Choose request, read, broad or narrow' >&2; exit 2 ;;
esac
