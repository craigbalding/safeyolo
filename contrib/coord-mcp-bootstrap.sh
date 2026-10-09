#!/usr/bin/env bash
# SafeYolo coord MCP bootstrap for agent sandboxes.
#
# Stages the native Coord MCP adapter and SafeYolo-owned launcher into an agent's home
# dir and registers the launcher with the agent's harness (Claude Code or
# Codex) so the agent can hit the proxy-only coord API as MCP tools with zero
# in-sandbox manual setup. Idempotent — safe to re-run.
#
# The bundled Claude Code and Codex host scripts invoke this helper
# automatically. For an existing agent, stop it before reapplying setup.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the host-script contract.

set -euo pipefail

show_help() {
    cat <<'HELP'
Usage: coord-mcp-bootstrap.sh [--home DIRECTORY] [--harness claude|codex]
                              [--require-agent-local]

Stage the native Coord Model Context Protocol (MCP) adapter and register its
launcher in an agent's existing harness configuration. Run on the operator host.

  --home DIRECTORY       Agent home; defaults to SAFEYOLO_AGENT_HOME.
                         Use ROOT/agents/NAME/home, including the trailing /home.
  --harness claude|codex  Harness; defaults to detection from the agent home.
  --require-agent-local  Require an adopted agent-local Codex login.
  -h, --help             Show this help.

First run the harness host setup. Use the installed native host safeyolo-coord
and its matching Linux guest artifact. Native agent create/configure --host-script
selects these inputs. For direct invocation, set SAFEYOLO_COORD_EXECUTABLE and
SAFEYOLO_COORD_GUEST_BINARY, or put the installed ROOT/bin on PATH. The default
guest artifact is ROOT/assets/guest/safeyolo-coord with its version/checksum receipts.

For an existing agent, replace ROOT and NAME with its installed root and name.
Put ROOT/bin on PATH before invoking the bootstrap directly.
Stop the agent before changing its home, then restart it to load the MCP settings:
  ROOT/bin/safeyolo --root ROOT agent stop NAME
  ROOT/assets/contrib/coord-mcp-bootstrap.sh --home ROOT/agents/NAME/home
  ROOT/bin/safeyolo --root ROOT start
  ROOT/bin/safeyolo --root ROOT agent start NAME

See contrib/HOST_SCRIPT_GUIDE.md for native create/configure --host-script setup.
HELP
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
