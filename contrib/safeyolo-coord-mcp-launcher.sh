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
if [ ! -x "$LAUNCHER_DIR/safeyolo-coord" ]; then
    echo "safeyolo-coord-mcp-launcher: missing native executable $LAUNCHER_DIR/safeyolo-coord" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090 -- SafeYolo generates and mounts this per run.
. "$PROXY_ENV_FILE"  # DOC: contrib/README.md
set +a

exec "$LAUNCHER_DIR/safeyolo-coord" mcp
