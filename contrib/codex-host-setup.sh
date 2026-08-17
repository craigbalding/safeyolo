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

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

# --- Stage host codex state --------------------------------------------------
# Codex stores auth + config under ~/.codex/. Copy the whole dir if present.
# Session transcripts etc. are inside the same tree -- we're choosing to stage
# the lot because codex doesn't have the same scale of transcript state as
# Claude Code. If that stops being true, narrow this to specific files.
if [ -d "$HOME/.codex" ]; then
    cp -R "$HOME/.codex/." "$AGENT_HOME/.codex/" 2>/dev/null || true
fi

# --- Stage SafeYolo baseline + shared skill ---------------------------------
# The baseline is injected as Codex developer instructions at launch. The
# shared skill is linked into ~/.agents/skills/ for automatic discovery.
stage_safeyolo_context "$AGENT_HOME" codex

# --- Write the foreground command --------------------------------------------
cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e

export CODEX_HOME=/home/agent/.codex
: "${SAFEYOLO_CODEX_NODE_SPEC:=node@22}"
: "${SAFEYOLO_CODEX_NPM_SPEC:=npm:@openai/codex@latest}"
: "${SAFEYOLO_CODEX_NPM_PACKAGE:=@openai/codex@latest}"
# Do not rely on a login shell or BASH_ENV here. Linux launches this file
# through runsc exec, and /etc/environment may have reset PATH before this
# child shell starts. Keep mise's persistent per-agent layout explicit so a
# tool installed below is immediately executable in this same process.
export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.mise}"
export MISE_CONFIG_DIR="${MISE_CONFIG_DIR:-$HOME/.mise}"
export MISE_CACHE_DIR="${MISE_CACHE_DIR:-$HOME/.mise/cache}"
export PATH="$HOME/.local/bin:$MISE_DATA_DIR/shims:${PATH}"

if ! command -v codex >/dev/null 2>&1; then
    if [ -f /etc/alpine-release ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo apk add nodejs npm >&2
        fi
        npm install --global --prefix /home/agent/.local "$SAFEYOLO_CODEX_NPM_PACKAGE" >&2
    else
        mise use -g "$SAFEYOLO_CODEX_NODE_SPEC" >&2
        mise use -g "$SAFEYOLO_CODEX_NPM_SPEC" >&2
    fi
fi

# Codex has no dedicated append-system-prompt flag, but its generic config
# override supports developer_instructions. Encode the Markdown as a TOML basic
# string without depending on jq/python inside custom rootfs images.
toml_string_from_file() {
    local value
    value="$(cat "$1")"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\b'/\\b}"
    value="${value//$'\f'/\\f}"
    value="${value//$'\t'/\\t}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\n'/\\n}"
    printf '"%s"' "$value"
}

args=(-s danger-full-access -a never)
if [ -f "$HOME/.safeyolo/AGENTS.md" ]; then
    args+=(-c "developer_instructions=$(toml_string_from_file "$HOME/.safeyolo/AGENTS.md")")
fi

exec codex "${args[@]}" "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

echo "codex-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
