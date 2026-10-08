#!/usr/bin/env bash
# Locate installed host staging code and its checked Linux guest artifact.
# Callers set SCRIPT_DIR to the contrib directory; credentials are never inputs.

stage_coord_native() {
    local agent_home=$1 coord_guest
    coord_host=${SAFEYOLO_COORD_EXECUTABLE:-}
    if [[ -z $coord_host && -n ${SAFEYOLO_EXECUTABLE:-} ]]; then
        coord_host=$(dirname -- "$SAFEYOLO_EXECUTABLE")/safeyolo-coord
    fi
    if [[ -z $coord_host ]]; then coord_host=$(command -v safeyolo-coord || true); fi
    if [[ -z $coord_host && -x $SCRIPT_DIR/../bin/safeyolo-coord ]]; then
        coord_host=$SCRIPT_DIR/../bin/safeyolo-coord
    fi
    if [[ -z $coord_host || ! -x $coord_host ]]; then
        echo 'Native Coord host executable is missing; install the native product or set SAFEYOLO_COORD_EXECUTABLE' >&2
        return 1
    fi
    coord_guest=${SAFEYOLO_COORD_GUEST_BINARY:-}
    if [[ -z $coord_guest ]]; then
        coord_guest=$(dirname -- "$coord_host")/../assets/guest/safeyolo-coord
    fi
    "$coord_host" stage-runtime "$agent_home" "$coord_guest"
}
