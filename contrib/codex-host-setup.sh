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

# --- version policy ---------------------------------------------------------
# Delayed deployment: do not pick up a release published minutes ago. Newer
# mise applies min_release_age to transitive npm dependencies too, which is
# the protection we want. Older mise does not have the setting at all, so
# verify that it took rather than assuming the default is there.
: "${SAFEYOLO_MIN_RELEASE_AGE:=24h}"
if mise settings get min_release_age >/dev/null 2>&1; then
    export MISE_MIN_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE"
else
    echo "codex-host-setup: mise has no min_release_age setting;" \
         "no delayed-deployment protection on this build" >&2
fi

# `mise use -g <tool>@latest` is NOT a remote upgrade -- mise resolves
# `latest` against what is already installed. That matters on the repair
# path: a wrapper whose platform-native binary has gone still fails its
# probe, but mise can decide the existing install already satisfies
# `latest` and do nothing, leaving the agent unable to launch. Resolve the
# remote version explicitly and install that exact value.
sy_remote_version() { mise latest "$1" 2>/dev/null | tail -1; }
sy_local_version()  { mise latest --installed "$1" 2>/dev/null | tail -1; }

# Validate an existing command as well as its absence: the CLI is an npm
# wrapper plus a platform-native optional dependency, so the launcher can
# survive while the native binary does not (mise declining npm lifecycle
# scripts, or macOS Gatekeeper trashing the vendored Mach-O over a revoked
# signing cert). `command -v` alone still succeeds in that state and the
# install below is skipped, leaving the agent permanently unable to launch.
if ! command -v codex >/dev/null 2>&1 || ! codex --version >/dev/null 2>&1; then
    if [ -f /etc/alpine-release ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo -n apk add nodejs npm >&2
        fi
        npm install --global --prefix /home/agent/.local "$SAFEYOLO_CODEX_NPM_PACKAGE" >&2
    else
        mise use -g "$SAFEYOLO_CODEX_NODE_SPEC" >&2
        sy_tool="${SAFEYOLO_CODEX_NPM_SPEC%@*}"
        sy_target="$(sy_remote_version "$sy_tool")"
        if [ -n "$sy_target" ]; then
            mise use -g --force "${sy_tool}@${sy_target}" >&2
        else
            # Remote lookup failed (offline, registry down). Fall back to the
            # configured spec rather than refusing to start.
            echo "codex-host-setup: could not resolve a remote version for" \
                 "$sy_tool; falling back to $SAFEYOLO_CODEX_NPM_SPEC" >&2
            mise use -g "$SAFEYOLO_CODEX_NPM_SPEC" >&2
        fi
    fi
fi

# Report the version actually about to run, and say when a newer one exists
# without silently taking it. A pinned artifact ageing in place is fine; a
# pinned artifact ageing *invisibly* is what left an agent dead for months.
sy_tool="${SAFEYOLO_CODEX_NPM_SPEC%@*}"
sy_running="$(sy_local_version "$sy_tool")"
if [ -n "$sy_running" ]; then
    echo "codex-host-setup: codex $sy_running" >&2
    sy_available="$(sy_remote_version "$sy_tool")"
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "codex-host-setup: codex $sy_available is available; not upgrading" \
             "automatically (run: mise use -g ${sy_tool}@${sy_available})" >&2
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
