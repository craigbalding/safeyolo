#!/usr/bin/env bash
# SafeYolo host setup script for Claude Code.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/claude-host-setup.sh` is
# invoked. Stages host auth + user extensions into the agent's
# persistent home, and writes the entrypoint that installs claude-code
# (via mise) on first boot and runs it nag-free thereafter.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME/.claude"

# --- 1. Stage host Claude state (best-effort) ---------------------------------
# Credentials + settings are the core "identity + prefs" bucket. User-authored
# extensions (plugins, commands, agents, skills) are copied so the user's
# curated setup is available inside the sandbox. Everything else in ~/.claude/
# (projects, sessions, history.jsonl, file-history, paste-cache, plans,
# backups, session-env, shell-snapshots, statsig, cache, debug) is deliberately
# NOT staged -- those are session-scope and would leak transcripts cross-agent.

host_claude="$HOME/.claude"

stage_file() {
    local rel="$1"
    if [ -f "$host_claude/$rel" ]; then
        mkdir -p "$(dirname "$AGENT_HOME/.claude/$rel")"
        cp "$host_claude/$rel" "$AGENT_HOME/.claude/$rel"
    fi
}

stage_dir() {
    local rel="$1"
    if [ -d "$host_claude/$rel" ]; then
        mkdir -p "$AGENT_HOME/.claude/$rel"
        cp -R "$host_claude/$rel/." "$AGENT_HOME/.claude/$rel/" 2>/dev/null || true
    fi
}

stage_file .credentials.json
stage_file settings.json

for d in plugins commands agents skills; do
    stage_dir "$d"
done

# --- 2. Seed .claude.json with nag-free defaults ------------------------------
# Minimum set of top-level keys Claude Code checks on launch. /workspace is a
# guest-only path -- the user can't pre-trust it from the host because it
# doesn't exist there -- so we set its entry explicitly.

if command -v python3 >/dev/null 2>&1; then
    python3 - "$AGENT_HOME/.claude.json" <<'PY'
import json, os, sys
path = sys.argv[1]
data = {}
# Preserve identity keys from host's ~/.claude.json if present.
host_json = os.path.expanduser("~/.claude.json")
if os.path.exists(host_json):
    try:
        with open(host_json) as f:
            host_data = json.load(f)
        for k in (
            "userID", "firstStartTime", "oauthAccount",
            "migrationVersion",
            "opusProMigrationComplete", "opus45MigrationComplete",
            "sonnet45MigrationComplete", "sonnet1m45MigrationComplete",
            "opusPlanMigrationComplete", "hasCompletedOnboarding",
        ):
            if k in host_data:
                data[k] = host_data[k]
    except (OSError, json.JSONDecodeError):
        pass

data["hasCompletedOnboarding"] = True
data.setdefault("projects", {})
data["projects"]["/workspace"] = {
    "hasTrustDialogAccepted": True,
    "hasCompletedProjectOnboarding": True,
    "hasClaudeMdExternalIncludesApproved": True,
    "hasClaudeMdExternalIncludesWarningShown": True,
}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PY
else
    cat > "$AGENT_HOME/.claude.json" <<'JSON'
{
  "hasCompletedOnboarding": true,
  "projects": {
    "/workspace": {
      "hasTrustDialogAccepted": true,
      "hasCompletedProjectOnboarding": true,
      "hasClaudeMdExternalIncludesApproved": true,
      "hasClaudeMdExternalIncludesWarningShown": true
    }
  }
}
JSON
fi

# --- 3. Ensure settings.json enables bypass mode ------------------------------
# --dangerously-skip-permissions alone is no longer sufficient in Claude Code
# 2.x; the persistent setting is permissions.defaultMode. Merge rather than
# overwrite so user-staged settings.json keeps its other keys.

if command -v python3 >/dev/null 2>&1; then
    python3 - "$AGENT_HOME/.claude/settings.json" <<'PY'
import json, sys, os
path = sys.argv[1]
data = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
data["skipDangerousModePermissionPrompt"] = True
perms = data.setdefault("permissions", {})
perms["defaultMode"] = "bypassPermissions"
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PY
fi

# --- 4. Write the entrypoint --------------------------------------------------
# Installs claude-code via mise on first run (idempotent: command -v
# short-circuits on subsequent runs, since MISE_DATA_DIR lives in the
# persistent home). Execs claude with nag-free flags. Any args after
# `safeyolo agent run <name> -- ...` come through as "$@".

cat > "$AGENT_HOME/.safeyolo-entrypoint" <<'EOF'
#!/usr/bin/env bash
set -e

# First-boot install. mise stores installs under $HOME/.mise which is
# persistent, so `command -v claude` succeeds from the second boot on.
if ! command -v claude >/dev/null 2>&1; then
    mise use -g node@22 >&2
    mise use -g npm:@anthropic-ai/claude-code@latest >&2
fi

exec claude --dangerously-skip-permissions "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-entrypoint"

echo "claude-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
