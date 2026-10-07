#!/bin/sh
# Export selected Lab evidence through the installed native guest helper.
exec "${SAFEYOLO_GUEST_EXECUTABLE:-/safeyolo/safeyolo-guest}" lab-evidence capture "$@"
