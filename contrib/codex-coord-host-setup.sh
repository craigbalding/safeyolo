#!/usr/bin/env bash
# Opt-in SafeYolo host setup for a supervised, coord-driven Codex worker.
#
# Required host environment is either an approved factory snapshot + role or
# the legacy room/coordinator pair:
#   SAFEYOLO_CODEX_FACTORY_SNAPSHOT=/absolute/path/to/<sha256>.json
#   SAFEYOLO_CODEX_FACTORY_ROLE=owner
# or:
#   SAFEYOLO_CODEX_COORD_ROOMS=room-one[,room-two]
#   SAFEYOLO_CODEX_COORDINATORS=coordinator-one[,coordinator-two]

set -euo pipefail

if [ -n "${SAFEYOLO_CODEX_FACTORY_SNAPSHOT:-}" ]; then
    : "${SAFEYOLO_CODEX_FACTORY_ROLE:?set the role bound by the factory snapshot}"
else
    : "${SAFEYOLO_CODEX_COORD_ROOMS:?set the factory worker receive room list}"
    : "${SAFEYOLO_CODEX_COORDINATORS:?set the operator-designated coordinator list}"
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export SAFEYOLO_CODEX_COORD_SUPERVISOR=1
exec "$SCRIPT_DIR/codex-host-setup.sh"
