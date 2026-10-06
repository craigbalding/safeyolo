# Runs only inside the selected Demo guest through the native shell transport.
# Existing Codex tools and authentication stay in that guest's own home.
set -eu
export PATH="/home/agent/.local/bin:/home/agent/.mise/shims:$PATH"
if ! command -v codex >/dev/null 2>&1 || ! codex --version >/dev/null 2>&1; then
    if mise settings get min_release_age >/dev/null 2>&1; then
        export MISE_MIN_RELEASE_AGE="${SAFEYOLO_MIN_RELEASE_AGE:-24h}"
    fi
    mise use -g node@22 npm:@openai/codex
fi
codex --version
