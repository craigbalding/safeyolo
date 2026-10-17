#!/usr/bin/env bash
# Shared build-time resolution. The JSON freezes a build; it is not a fallback.
guest_inputs() {
    local architecture=$1
    shift
    local resolver="${SAFEYOLO_GUEST_SRC_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}/resolve_inputs.py"
    local temporary= assignments
    if [[ -z ${GUEST_INPUTS:-} ]]; then
        temporary=$(mktemp)
        "${SAFEYOLO_BUILD_PYTHON:-python3}" "$resolver" resolve --output "$temporary" "$@" || { rm -f "$temporary"; return 1; }
        export GUEST_INPUTS=$temporary
    fi
    assignments=$("${SAFEYOLO_BUILD_PYTHON:-python3}" "$resolver" env --inputs "$GUEST_INPUTS" --architecture "$architecture") || return 1
    eval "$assignments"
}

guest_download() {
    local resolver="${SAFEYOLO_GUEST_SRC_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}/resolve_inputs.py"
    "${SAFEYOLO_BUILD_PYTHON:-python3}" "$resolver" download --inputs "$GUEST_INPUTS" --architecture "$1" --tool "$2" --output "$3"
}
