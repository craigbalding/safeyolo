# Source from the private operator binding in the accepted Bash SSH payload.
set +x
: "${CLAUDE_EVENT_OUTPUT:?}" "${CLAUDE_ACCESS_SOURCE:?}" "${CLAUDE_ACCESS_PYTHON:?}"
: "${CLAUDE_PROVISION:?}" "${CLAUDE_CREDENTIAL:?}"
export CLAUDE_PROVISION CLAUDE_CREDENTIAL
export SAFEYOLO_CLAUDE_PROVISION_DIR="${CLAUDE_EVENT_OUTPUT}.provision"
"$CLAUDE_ACCESS_PYTHON" "$(dirname -- "${BASH_SOURCE[0]}")/prepare_claude_access.py" \
  --source "$CLAUDE_ACCESS_SOURCE" --output "$SAFEYOLO_CLAUDE_PROVISION_DIR"
