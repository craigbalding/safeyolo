#!/usr/bin/env bash
# SafeYolo host setup script for OpenAI Codex CLI.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/codex-host-setup.sh` is
# invoked. Stages host ~/.codex/ into the agent's persistent home and
# writes an entrypoint that installs codex via mise on first boot and
# runs it with --full-auto thereafter.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME/.codex"

# --- Stage host codex state --------------------------------------------------
# Codex stores auth + config under ~/.codex/. Copy the whole dir if present.
# Session transcripts etc. are inside the same tree — we're choosing to stage
# the lot because codex doesn't have the same scale of transcript state as
# Claude Code. If that stops being true, narrow this to specific files.
if [ -d "$HOME/.codex" ]; then
    cp -R "$HOME/.codex/." "$AGENT_HOME/.codex/" 2>/dev/null || true
fi

# --- Write the entrypoint ----------------------------------------------------
cat > "$AGENT_HOME/.safeyolo-entrypoint" <<'EOF'
#!/usr/bin/env bash
set -e

export CODEX_HOME=/home/agent/.codex

if ! command -v codex >/dev/null 2>&1; then
    mise use -g node@22 >&2
    mise use -g npm:@openai/codex@latest >&2
fi

exec codex --full-auto "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-entrypoint"

echo "codex-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
