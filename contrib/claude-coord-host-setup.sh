#!/usr/bin/env bash
# Opt-in SafeYolo host setup for a supervised Claude Code Factory role.
set -euo pipefail

: "${SAFEYOLO_FACTORY_SNAPSHOT:?set the approved factory snapshot}"
: "${SAFEYOLO_FACTORY_ROLE:?set the role bound by the factory snapshot}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export SAFEYOLO_CLAUDE_COORD_SUPERVISOR=1
# Factory roles use their retained agent-local login or selected provider.
export SAFEYOLO_CLAUDE_COPY_HOST_STATE=0
exec "$SCRIPT_DIR/claude-host-setup.sh"
