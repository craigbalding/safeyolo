#!/usr/bin/env bash
# SafeYolo coord MCP bootstrap for agent sandboxes.
#
# Stages the native Coord MCP adapter and SafeYolo-owned launcher into an agent's home
# dir and registers the launcher with the agent's harness (Claude Code or
# Codex) so the agent can hit the proxy-only coord API as MCP tools with zero
# in-sandbox manual setup. Idempotent — safe to re-run.
#
# The bundled Claude Code and Codex host scripts invoke this helper
# automatically. It also supports an explicit retrofit mode:
#
#   Retrofit for an already-running agent (no reprovision needed):
#
#          contrib/coord-mcp-bootstrap.sh --home ~/.safeyolo/agents/<name>/home
#          safeyolo agent stop <name> && safeyolo agent run <name>
#
#      Note the trailing `/home`: the agent's harness config lives in
#      the `home/` subdir, not directly under `agents/<name>/`. See
#      get_agent_home_dir() in cli/src/safeyolo/vm.py.
#
#      The stop+run is required so the harness picks up the new MCP
#      server config; it does NOT touch the sandbox's persistent state.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the host-script contract.

set -euo pipefail

show_help() {
    sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
}

AGENT_HOME=""
HARNESS=""
REQUIRE_AGENT_LOCAL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --home)
            [ $# -ge 2 ] || { echo "coord-mcp-bootstrap: --home needs a directory" >&2; exit 2; }
            AGENT_HOME="$2"
            shift 2
            ;;
        --harness)
            [ $# -ge 2 ] || { echo "coord-mcp-bootstrap: --harness needs claude|codex" >&2; exit 2; }
            HARNESS="$2"
            shift 2
            ;;
        --require-agent-local)
            REQUIRE_AGENT_LOCAL=1
            shift
            ;;
        -h|--help|help)
            show_help
            exit 0
            ;;
        *)
            echo "coord-mcp-bootstrap: unknown arg '$1'" >&2
            show_help >&2
            exit 2
            ;;
    esac
done

# Fall back to the host-script contract when --home is not passed.
: "${AGENT_HOME:=${SAFEYOLO_AGENT_HOME:-}}"
if [ -z "$AGENT_HOME" ] || [ ! -d "$AGENT_HOME" ]; then
    echo "coord-mcp-bootstrap: --home <dir> or SAFEYOLO_AGENT_HOME required" >&2
    exit 2
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LAUNCHER_SRC="$SCRIPT_DIR/safeyolo-coord-mcp-launcher.sh"
FG="$AGENT_HOME/.safeyolo-command"
[ -f "$LAUNCHER_SRC" ] || { echo "coord-mcp-bootstrap: missing $LAUNCHER_SRC" >&2; exit 1; }
[ -f "$FG" ] || { echo "coord-mcp-bootstrap: run the harness host setup first" >&2; exit 1; }
# shellcheck source=lib/stage-coord-native.sh
. "$SCRIPT_DIR/lib/stage-coord-native.sh"
stage_coord_native "$AGENT_HOME"

# Auto-detect harness by staged config, since --host-script mode doesn't
# tell us which harness the operator picked.
if [ -z "$HARNESS" ]; then
    if [ -f "$AGENT_HOME/.claude.json" ] || [ -d "$AGENT_HOME/.claude" ]; then
        HARNESS="claude"
    elif [ -d "$AGENT_HOME/.codex" ]; then
        HARNESS="codex"
    else
        echo "coord-mcp-bootstrap: cannot auto-detect harness under $AGENT_HOME" >&2
        echo "  (expected .claude/, .claude.json, or .codex/)" >&2
        if [ -d "$AGENT_HOME/home" ]; then
            echo "  hint: did you mean --home $AGENT_HOME/home ?" >&2
        fi
        echo "  or pass --harness claude|codex" >&2
        exit 1
    fi
fi

install -m 0755 "$LAUNCHER_SRC" "$AGENT_HOME/.safeyolo/safeyolo-coord-mcp-launcher"
state_args=(stage-mcp "$AGENT_HOME" "$HARNESS")
if [ "$REQUIRE_AGENT_LOCAL" -eq 1 ]; then state_args+=(--require-agent-local); fi
"$coord_host" "${state_args[@]}"
echo "coord-mcp-bootstrap: $HARNESS native runtime staged at $AGENT_HOME/.safeyolo/"
