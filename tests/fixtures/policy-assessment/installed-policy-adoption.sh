#!/usr/bin/env bash
# Guest phases only. The owning host prepares JSON; no guest Python is needed.
set -euo pipefail
phase=${1:?request, read, broad, narrow, submit or result}
output=${2:?private fixture output directory}
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
  submit)
    "$coord" call submit_policy_change < submission.json > submission-result.json
    ;;
  result)
    "$coord" call read_policy_change < submission-read.json > adoption-result.json
    "$coord" call read_policy_change < submission-read.json > adoption-result-repeated.json
    ;;
  *) echo 'Choose request, read, broad, narrow, submit or result' >&2; exit 2 ;;
esac
