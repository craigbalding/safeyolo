#!/usr/bin/env bash
# SafeYolo host setup script for Claude Code.
#
# Runs on the host (macOS or Linux), as you, when `safeyolo agent add
# <name> <folder> --host-script contrib/claude-host-setup.sh` is
# invoked. Stages host auth + user extensions into the agent's
# persistent home, and writes the foreground command that installs claude-code
# on first boot and runs it nag-free thereafter.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add/run --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add/run --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME/.claude"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

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

for d in plugins commands agents; do
    stage_dir "$d"
done

# SafeYolo owns the `safeyolo` skill name in the sandbox. Copy the operator's
# other Claude skills individually so a host-side skill with that name cannot
# overwrite or collide with the managed SafeYolo skill on first or later runs.
if [ -d "$host_claude/skills" ]; then
    mkdir -p "$AGENT_HOME/.claude/skills"
    while IFS= read -r -d '' host_skill; do
        skill_name="$(basename "$host_skill")"
        if [ "$skill_name" = "safeyolo" ]; then
            echo "  Skipped host Claude skill 'safeyolo' (reserved by SafeYolo)" >&2
            continue
        fi
        cp -R "$host_skill" "$AGENT_HOME/.claude/skills/" 2>/dev/null || true
    done < <(find "$host_claude/skills" -mindepth 1 -maxdepth 1 -print0)
fi

# --- 2. Seed .claude.json with nag-free defaults ------------------------------
# Minimum set of top-level keys Claude Code checks on launch. /workspace is a
# guest-only path -- the user can't pre-trust it from the host because it
# doesn't exist there -- so we set its entry explicitly.

if command -v python3 >/dev/null 2>&1; then
    python3 - "$AGENT_HOME/.claude.json" <<'PY'
import json, os, sys
path = sys.argv[1]
data = {}
# Preserve existing agent-side harness and MCP configuration on reapply.
if os.path.exists(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"claude-host-setup: cannot update invalid {path}: {exc}")
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
projects = data.setdefault("projects", {})
if not isinstance(projects, dict):
    raise SystemExit(f"claude-host-setup: projects is not an object in {path}")
workspace = projects.setdefault("/workspace", {})
if not isinstance(workspace, dict):
    raise SystemExit(
        f"claude-host-setup: projects./workspace is not an object in {path}"
    )
workspace.update(
    {
        "hasTrustDialogAccepted": True,
        "hasCompletedProjectOnboarding": True,
        "hasClaudeMdExternalIncludesApproved": True,
        "hasClaudeMdExternalIncludesWarningShown": True,
    }
)
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

# --- 4. Stage SafeYolo baseline + shared skill ------------------------------
# Keep SafeYolo's always-on baseline outside .claude/ so it cannot shadow the
# user's CLAUDE.md. Link the shared on-demand skill into Claude's native path.
stage_safeyolo_context "$AGENT_HOME" claude

# --- 5. Write the foreground command -----------------------------------------
# Installs claude-code on first run and repairs an incomplete native install on
# subsequent runs. On Alpine, Node comes from apk because mise may build Node
# from source against musl; elsewhere we use mise. Appends the SafeYolo agent
# baseline as system context. Detailed operations remain in the on-demand
# safeyolo skill. Any args after `safeyolo agent run <name> -- ...`
# come through as "$@".

cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e

: "${SAFEYOLO_CLAUDE_NODE_SPEC:=node@22}"
: "${SAFEYOLO_CLAUDE_NPM_SPEC:=npm:@anthropic-ai/claude-code@latest}"
: "${SAFEYOLO_CLAUDE_NPM_PACKAGE:=@anthropic-ai/claude-code@latest}"
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
    echo "claude-host-setup: mise has no min_release_age setting;" \
         "no delayed-deployment protection on this build" >&2
fi

# `mise use -g <tool>@latest` is NOT a remote upgrade -- mise resolves
# `latest` against what is already installed, so on the repair path it can
# decide a broken install already satisfies the spec and do nothing.
# Resolve the remote version explicitly and install that exact value.
sy_remote_version() { mise latest "$1" 2>/dev/null | tail -1; }
sy_local_version()  { mise latest --installed "$1" 2>/dev/null | tail -1; }

# First-boot install. Tool installs live under persistent /home/agent. Validate
# an existing command as well: mise 2026.7.12+ downloads npm optional
# dependencies but denies lifecycle scripts by default, so Claude's placeholder
# launcher can exist even though its postinstall did not place the native
# binary.
if ! command -v claude >/dev/null 2>&1 || ! claude --version >/dev/null 2>&1; then
    if [ -f /etc/alpine-release ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo -n apk add nodejs npm >&2
        fi
        npm install --global --prefix /home/agent/.local "$SAFEYOLO_CLAUDE_NPM_PACKAGE" >&2
    else
        mise use -g "$SAFEYOLO_CLAUDE_NODE_SPEC" >&2
        sy_tool="${SAFEYOLO_CLAUDE_NPM_SPEC%@*}"
        sy_target="$(sy_remote_version "$sy_tool")"
        if [ -n "$sy_target" ]; then
            sy_spec="${sy_tool}@${sy_target}"
            mise use -g --force "$sy_spec" >&2
        else
            echo "claude-host-setup: could not resolve a remote version for" \
                 "$sy_tool; falling back to $SAFEYOLO_CLAUDE_NPM_SPEC" >&2
            sy_spec="$SAFEYOLO_CLAUDE_NPM_SPEC"
            mise use -g "$sy_spec" >&2
        fi

        # Claude Code 2.1.235+ ships a small npm wrapper and a platform-native
        # optional dependency. New mise releases intentionally skip npm
        # lifecycle scripts unless approved. Run only Claude's reviewed
        # postinstall explicitly, and only when the installed launcher is still
        # the placeholder. This also repairs installs left broken by an earlier
        # SafeYolo run.
        if ! claude --version >/dev/null 2>&1; then
            claude_install_dir="$(mise where "$sy_spec")"
            claude_package="${SAFEYOLO_CLAUDE_NPM_PACKAGE%@*}"
            claude_postinstall=""
            for candidate in \
                "$claude_install_dir/node_modules/$claude_package/install.cjs" \
                "$claude_install_dir/lib/node_modules/$claude_package/install.cjs"
            do
                if [ -f "$candidate" ]; then
                    claude_postinstall="$candidate"
                    break
                fi
            done
            if [ -n "$claude_postinstall" ]; then
                mise exec "$SAFEYOLO_CLAUDE_NODE_SPEC" -- node "$claude_postinstall" >&2
                mise reshim >&2
            else
                echo "claude-host-setup: could not locate Claude Code postinstall under $claude_install_dir" >&2
            fi
        fi
    fi
fi

if ! command -v claude >/dev/null 2>&1 || ! claude --version >/dev/null 2>&1; then
    echo "claude-host-setup: Claude Code installation is incomplete" >&2
    exit 1
fi

# Report the version actually about to run, and say when a newer one exists
# without silently taking it. A pinned artifact ageing in place is fine; one
# ageing invisibly is what left an agent dead for months.
sy_tool="${SAFEYOLO_CLAUDE_NPM_SPEC%@*}"
sy_running="$(sy_local_version "$sy_tool")"
if [ -n "$sy_running" ]; then
    echo "claude-host-setup: claude $sy_running" >&2
    sy_available="$(sy_remote_version "$sy_tool")"
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "claude-host-setup: claude $sy_available is available; not upgrading" \
             "automatically (run: mise use -g ${sy_tool}@${sy_available})" >&2
    fi
fi

# Inject SafeYolo agent guide as system context (non-fatal if missing).
args=(--dangerously-skip-permissions)
if [ -f "$HOME/.safeyolo/AGENTS.md" ]; then
    args+=(--append-system-prompt "$(cat "$HOME/.safeyolo/AGENTS.md")")
fi

exec claude "${args[@]}" "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

# --- 6. Stage and register the coord MCP server ------------------------------
# This runs after the foreground command is written so the shared bootstrap can
# inject its guarded dependency setup immediately before the harness exec.
"$SCRIPT_DIR/coord-mcp-bootstrap.sh" --home "$AGENT_HOME" --harness claude

echo "claude-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
