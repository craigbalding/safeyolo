#!/usr/bin/env bash
# SafeYolo coord MCP bootstrap for agent sandboxes.
#
# Stages the coord MCP shim and SafeYolo-owned launcher into an agent's home
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
SHIM_SRC="$SCRIPT_DIR/safeyolo-coord-mcp.py"
LAUNCHER_SRC="$SCRIPT_DIR/safeyolo-coord-mcp-launcher.sh"
FG="$AGENT_HOME/.safeyolo-command"

if [ ! -f "$SHIM_SRC" ]; then
    echo "coord-mcp-bootstrap: expected shim at $SHIM_SRC" >&2
    exit 1
fi
if [ ! -f "$LAUNCHER_SRC" ]; then
    echo "coord-mcp-bootstrap: expected launcher at $LAUNCHER_SRC" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "coord-mcp-bootstrap: python3 is required to preserve and update harness config" >&2
    exit 1
fi
if [ ! -f "$FG" ]; then
    echo "coord-mcp-bootstrap: $FG not found; run the Claude or Codex host setup first" >&2
    exit 1
fi

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

# --- 1. Stage the shim into the agent's own .safeyolo/ ----------------------
# Keeps the sandbox owner of a stable copy — the operator's checkout can move
# or be deleted without breaking the running agent.
mkdir -p "$AGENT_HOME/.safeyolo"
install -m 0755 "$SHIM_SRC" "$AGENT_HOME/.safeyolo/safeyolo-coord-mcp.py"
install -m 0755 "$LAUNCHER_SRC" "$AGENT_HOME/.safeyolo/safeyolo-coord-mcp-launcher"

# The sandbox mounts $AGENT_HOME → /home/agent, so the launcher's in-sandbox
# path is fixed.
LAUNCHER_INSANDBOX="/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
# The shim needs mcp+httpx. Debian/Ubuntu rootfs images mark the system
# interpreter externally-managed (PEP 668), so `pip install --user` is
# refused there. Install into a dedicated venv instead and point the
# launcher at that interpreter rather than bare `python3`.

# --- 2. Register the MCP server with the harness ----------------------------
case "$HARNESS" in
    claude)
        # Claude Code reads user-scope MCP servers from ~/.claude.json.
        # Merge into whatever the base host script already wrote — never
        # clobber unrelated keys.
        python3 - "$AGENT_HOME/.claude.json" "$LAUNCHER_INSANDBOX" <<'PY'
import json, os, sys
path, launcher = sys.argv[1], sys.argv[2]
data = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"coord-mcp-bootstrap: cannot update invalid Claude config {path}: {exc}"
        )
if not isinstance(data, dict):
    raise SystemExit(
        f"coord-mcp-bootstrap: cannot update non-object Claude config {path}"
    )
servers = data.setdefault("mcpServers", {})
if not isinstance(servers, dict):
    raise SystemExit(
        f"coord-mcp-bootstrap: mcpServers is not an object in {path}"
    )
servers["safeyolo-coord"] = {
    "command": launcher,
    "args": [],
}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PY
        ;;
    codex)
        # Codex reads MCP servers from ~/.codex/config.toml under an
        # [mcp_servers.<name>] table.
        python3 - "$AGENT_HOME/.codex/config.toml" "$LAUNCHER_INSANDBOX" <<'PY'
import os, sys, tomllib

path, launcher = sys.argv[1], sys.argv[2]
os.makedirs(os.path.dirname(path), exist_ok=True)

existing_lines = []
if os.path.exists(path):
    with open(path) as f:
        existing_lines = f.readlines()
    try:
        tomllib.loads("".join(existing_lines))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(
            f"coord-mcp-bootstrap: cannot update invalid Codex config {path}: {exc}"
        )

# Strip any prior [mcp_servers.safeyolo-coord] table so re-runs stay
# idempotent. Line-based rather than regex so `args = ["..."]` values
# (which contain `[`) can't accidentally close the match early.
out = []
skipping = False
for line in existing_lines:
    stripped = line.lstrip()
    if stripped.startswith("[mcp_servers.safeyolo-coord]"):
        skipping = True
        continue
    if skipping:
        # End the strip window on the next table header (any `[` at
        # column 0), or on EOF.
        if stripped.startswith("[") and not stripped.startswith("[mcp_servers.safeyolo-coord]"):
            skipping = False
            out.append(line)
        # else: consume the k=v line and stay in skip mode.
        continue
    out.append(line)

new_block = (
    "[mcp_servers.safeyolo-coord]\n"
    f'command = "{launcher}"\n'
    'args = []\n'
)

body = "".join(out).rstrip()
if body:
    combined = body + "\n\n" + new_block
else:
    combined = new_block
try:
    tomllib.loads(combined)
except tomllib.TOMLDecodeError as exc:
    raise SystemExit(
        f"coord-mcp-bootstrap: generated invalid Codex config for {path}: {exc}"
    )
with open(path, "w") as f:
    f.write(combined)
PY
        ;;
    *)
        echo "coord-mcp-bootstrap: unknown harness '$HARNESS' (expected claude|codex)" >&2
        exit 1
        ;;
esac

# --- 3. Ensure the shim's Python deps are installed on first agent run ------
# We can't reliably install into the sandbox's user-site from the host (the
# python versions may differ), so we inject a guarded install step into the
# foreground command. Runs at most once per agent lifetime — the import
# guard makes subsequent runs a no-op fast path. A failed install aborts the
# harness launch visibly instead of advertising an MCP server that cannot run.
MARKER="# ---- coord-mcp-bootstrap: mcp+httpx install (guarded, idempotent) ----"

if ! grep -qxF "$MARKER" "$FG"; then
    python3 - "$FG" "$MARKER" <<'PY'
import sys
path, marker = sys.argv[1], sys.argv[2]
with open(path) as f:
    lines = f.readlines()

# Insert before the LAST `exec ` line — that's the handoff to the
# harness. Fall back to appending if the base script doesn't exec.
exec_i = None
for i in range(len(lines) - 1, -1, -1):
    if lines[i].lstrip().startswith("exec "):
        exec_i = i
        break
if exec_i is None:
    exec_i = len(lines)

inject = [
    marker + "\n",
    'SY_COORD_VENV="$HOME/.safeyolo/venv"\n',
    'if ! "$SY_COORD_VENV/bin/python" -c \'import httpx; from mcp.server.mcpserver import MCPServer\' >/dev/null 2>&1; then\n',
    '    if ! { python3 -m venv "$SY_COORD_VENV" \\\n',
    '        && "$SY_COORD_VENV/bin/pip" install --quiet "mcp>=2.0" "httpx>=0.25"; } >&2; then\n',
    '        echo "coord-mcp: could not install mcp+httpx into $SY_COORD_VENV;'
    ' refusing to start the harness without safeyolo-coord" >&2\n',
    '        exit 1\n',
    '    fi\n',
    '    if ! "$SY_COORD_VENV/bin/python" -c \'import httpx; from mcp.server.mcpserver import MCPServer\' >/dev/null 2>&1; then\n',
    '        echo "coord-mcp: dependency verification failed in $SY_COORD_VENV;'
    ' refusing to start the harness without safeyolo-coord" >&2\n',
    '        exit 1\n',
    '    fi\n',
    "fi\n",
    "\n",
]
lines[exec_i:exec_i] = inject
with open(path, "w") as f:
    f.writelines(lines)
PY
fi

echo "coord-mcp-bootstrap: $HARNESS runtime staged at $AGENT_HOME/.safeyolo/"
