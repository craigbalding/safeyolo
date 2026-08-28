#!/bin/sh
# Launch the coord MCP adapter with SafeYolo's authoritative per-run
# network and TLS environment. First-party harnesses may deliberately
# sanitize stdio MCP child environments, so inheriting the harness process
# environment is not a reliable way to reach the proxy-only Agent API.

set -eu

LAUNCHER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROXY_ENV_FILE=${SAFEYOLO_PROXY_ENV_FILE:-/safeyolo/proxy.env}

if [ ! -r "$PROXY_ENV_FILE" ]; then
    echo "safeyolo-coord-mcp-launcher: cannot read $PROXY_ENV_FILE" >&2
    exit 1
fi
if [ ! -x "$LAUNCHER_DIR/venv/bin/python" ]; then
    echo "safeyolo-coord-mcp-launcher: missing executable $LAUNCHER_DIR/venv/bin/python" >&2
    exit 1
fi
if [ ! -r "$LAUNCHER_DIR/safeyolo-coord-mcp.py" ]; then
    echo "safeyolo-coord-mcp-launcher: cannot read $LAUNCHER_DIR/safeyolo-coord-mcp.py" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090 -- SafeYolo generates and mounts this per run.
. "$PROXY_ENV_FILE"  # DOC: contrib/README.md
set +a

exec "$LAUNCHER_DIR/venv/bin/python" "$LAUNCHER_DIR/safeyolo-coord-mcp.py"
