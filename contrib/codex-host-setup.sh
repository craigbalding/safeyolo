#!/usr/bin/env bash
# SafeYolo host setup script for OpenAI Codex CLI.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/codex-host-setup.sh` is
# invoked. Stages host ~/.codex/ into the agent's persistent home and
# writes a foreground command script that installs codex via mise on first boot and
# runs it with Codex sandboxing disabled thereafter. SafeYolo remains
# the outer containment boundary.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME/.codex"

# --- Stage host codex state --------------------------------------------------
# Codex stores auth + config under ~/.codex/. Copy the whole dir if present.
# Session transcripts etc. are inside the same tree -- we're choosing to stage
# the lot because codex doesn't have the same scale of transcript state as
# Claude Code. If that stops being true, narrow this to specific files.
if [ -d "$HOME/.codex" ]; then
    cp -R "$HOME/.codex/." "$AGENT_HOME/.codex/" 2>/dev/null || true
fi

# --- Stage SafeYolo agent guide ----------------------------------------------
# Codex doesn't currently expose a system-prompt file flag, so we stage the
# guide at a conventional path and surface a reminder in the command.
# Users / codex can reference ~/.safeyolo/AGENTS.md as needed.
GUIDE_SRC="$(cd "$(dirname "$0")/.." && pwd)/docs/AGENTS.md"
mkdir -p "$AGENT_HOME/.safeyolo"
if [ -f "$GUIDE_SRC" ]; then
    cp "$GUIDE_SRC" "$AGENT_HOME/.safeyolo/AGENTS.md"
fi

# --- Write the foreground command --------------------------------------------
cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e

export CODEX_HOME=/home/agent/.codex
: "${SAFEYOLO_CODEX_NODE_SPEC:=node@22}"
: "${SAFEYOLO_CODEX_NPM_SPEC:=npm:@openai/codex@latest}"

if ! command -v codex >/dev/null 2>&1; then
    mise use -g "$SAFEYOLO_CODEX_NODE_SPEC" >&2
    mise use -g "$SAFEYOLO_CODEX_NPM_SPEC" >&2
fi

# Brief SafeYolo reminder -- full agent API / troubleshooting guide at
# ~/.safeyolo/AGENTS.md (staged by codex-host-setup.sh on the host).
echo "SafeYolo: see ~/.safeyolo/AGENTS.md for agent API + troubleshooting guide." >&2

exec codex -s danger-full-access -a never "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

echo "codex-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
