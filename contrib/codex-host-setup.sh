#!/usr/bin/env bash
# SafeYolo host setup script for OpenAI Codex CLI.
#
# Runs on the host (macOS or Linux), as you, when native `agent create
# <name> --workspace <folder> --host-script contrib/codex-host-setup.sh` is
# invoked. Stages SafeYolo-owned Codex settings into the agent's persistent
# home without importing host credentials, and writes a foreground command
# script that installs codex via mise on first boot and
# runs it with Codex sandboxing disabled thereafter. SafeYolo remains
# the outer containment boundary.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?run via native agent create/configure --host-script (see HOST_SCRIPT_GUIDE.md)}"
: "${SAFEYOLO_AGENT_HOME:?run via native agent create/configure --host-script (see HOST_SCRIPT_GUIDE.md)}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

# --- Stage SafeYolo baseline + shared skill ---------------------------------
# The baseline is injected as Codex developer instructions at launch. The
# shared skill is linked into ~/.agents/skills/ for automatic discovery.
stage_safeyolo_context "$AGENT_HOME" codex

# The curated @codex-coord wrapper opts into a deterministic guest-side
# supervisor. Normal @codex runs never enter this branch.
if [ "${SAFEYOLO_CODEX_COORD_SUPERVISOR:-0}" = "1" ]; then
    # Native staging uses the host executable and a checked Linux guest artifact.
    # shellcheck source=lib/stage-coord-native.sh
    . "$SCRIPT_DIR/lib/stage-coord-native.sh"
    stage_coord_native "$AGENT_HOME"
    snapshot=${SAFEYOLO_FACTORY_SNAPSHOT:-${SAFEYOLO_CODEX_FACTORY_SNAPSHOT:-}}
    if [ -n "$snapshot" ]; then
        role=${SAFEYOLO_FACTORY_ROLE:-${SAFEYOLO_CODEX_FACTORY_ROLE:-}}
        : "${role:?set the factory role}"
        "$coord_host" factory-stage \
            "$AGENT_HOME/.safeyolo/coord-supervisor.json" \
            "$AGENT_HOME/.safeyolo/AGENTS.md" \
            "$SAFEYOLO_AGENT_NAME" "$snapshot" "$role" codex
    else
        : "${SAFEYOLO_CODEX_COORD_ROOMS:?set a comma-separated receive room list for @codex-coord}"
        : "${SAFEYOLO_CODEX_COORDINATORS:?set a comma-separated coordinator name list for @codex-coord}"
        "$coord_host" ordinary-stage \
            "$AGENT_HOME/.safeyolo/coord-supervisor.json" \
            "$SAFEYOLO_AGENT_NAME" "$SAFEYOLO_CODEX_COORD_ROOMS" "$SAFEYOLO_CODEX_COORDINATORS"
    fi
fi

# --- Write the foreground command --------------------------------------------
install -m 0755 "$SCRIPT_DIR/codex-command.sh" "$AGENT_HOME/.safeyolo-command"
chmod +x "$AGENT_HOME/.safeyolo-command"
install -m 0755 "$AGENT_HOME/.safeyolo-command" "$AGENT_HOME/.safeyolo-interactive-command"

if [ "${SAFEYOLO_CODEX_COORD_SUPERVISOR:-0}" = "1" ]; then
    "$coord_host" supervised-launcher "$AGENT_HOME/.safeyolo-command" codex
fi

# --- Stage and register the coord MCP server ---------------------------------
# The shared bootstrap stages the native adapter and preserves harness config.
if [ "${SAFEYOLO_CODEX_COORD_SUPERVISOR:-0}" = "1" ] &&
   [ "${SAFEYOLO_FACTORY_PREPARE_ONLY:-0}" != "1" ]; then
    "$SCRIPT_DIR/coord-mcp-bootstrap.sh" \
        --home "$AGENT_HOME" \
        --harness codex \
        --require-agent-local
else
    "$SCRIPT_DIR/coord-mcp-bootstrap.sh" --home "$AGENT_HOME" --harness codex
fi

echo "codex-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
