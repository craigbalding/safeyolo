#!/usr/bin/env bash
# Opt-in SafeYolo host setup for a supervised, coord-driven Pi worker.

set -euo pipefail

: "${SAFEYOLO_FACTORY_SNAPSHOT:?set the approved factory snapshot}"
: "${SAFEYOLO_FACTORY_ROLE:?set the role bound by the factory snapshot}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export SAFEYOLO_PI_COORD_SUPERVISOR=1
exec "$SCRIPT_DIR/pi-host-setup.sh"
