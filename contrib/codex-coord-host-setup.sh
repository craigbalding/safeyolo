#!/usr/bin/env bash
# Opt-in SafeYolo host setup for a supervised, coord-driven Codex worker.
#
# Required host environment:
#   SAFEYOLO_CODEX_COORD_ROOMS=room-one[,room-two]
#   SAFEYOLO_CODEX_COORDINATORS=coordinator-one[,coordinator-two]

set -euo pipefail

: "${SAFEYOLO_CODEX_COORD_ROOMS:?set the factory worker receive room list}"
: "${SAFEYOLO_CODEX_COORDINATORS:?set the operator-designated coordinator list}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export SAFEYOLO_CODEX_COORD_SUPERVISOR=1
exec "$SCRIPT_DIR/codex-host-setup.sh"
