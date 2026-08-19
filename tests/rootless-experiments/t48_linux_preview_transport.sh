#!/usr/bin/env bash
# Run one bounded Linux preview transport experiment using the interpreter
# that owns the installed `safeyolo` command. No builds or configuration writes.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 exec-socat|port-forward-stream AGENT [probe options]" >&2
    exit 2
fi

SAFEYOLO_BIN="$(command -v safeyolo)" || {
    echo "safeyolo is not installed" >&2
    exit 1
}
SAFEYOLO_PYTHON="$(sed -n '1s/^#!//p' "$SAFEYOLO_BIN")"
case "$SAFEYOLO_PYTHON" in
    /*) ;;
    *) echo "cannot resolve safeyolo interpreter from $SAFEYOLO_BIN" >&2; exit 1 ;;
esac
[ -x "$SAFEYOLO_PYTHON" ] || {
    echo "safeyolo interpreter is not executable: $SAFEYOLO_PYTHON" >&2
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SAFEYOLO_PYTHON" "$SCRIPT_DIR/t48_linux_preview_transport.py" "$@"
