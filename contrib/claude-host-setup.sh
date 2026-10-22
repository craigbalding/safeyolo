#!/usr/bin/env bash
# SafeYolo host setup script for Claude Code.
#
# Runs on the host (macOS or Linux), as you, when native `agent create
# <name> --workspace <folder> --host-script contrib/claude-host-setup.sh` is
# invoked. Stages host auth + user extensions into the agent's
# persistent home, and writes the foreground command that installs claude-code
# on first boot and runs it nag-free thereafter.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the contract.

set -euo pipefail
umask 077

: "${SAFEYOLO_AGENT_NAME:?run via agent create/configure --host-script (see HOST_SCRIPT_GUIDE.md)}"
: "${SAFEYOLO_AGENT_HOME:?run via agent create/configure --host-script (see HOST_SCRIPT_GUIDE.md)}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
mkdir -p "$AGENT_HOME"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"
# shellcheck source=lib/stage-coord-native.sh
. "$SCRIPT_DIR/lib/stage-coord-native.sh"
stage_coord_native "$AGENT_HOME"
if [ "${SAFEYOLO_CLAUDE_COPY_HOST_STATE:-1}" = 1 ]; then
    "$coord_host" claude-state "$AGENT_HOME" "$HOME"
else
    "$coord_host" claude-state "$AGENT_HOME"
fi

# --- 1. Stage host Claude state (best-effort) ---------------------------------
# Credentials + settings are the core "identity + prefs" bucket. User-authored
# extensions (plugins, commands, agents, skills) are copied so the user's
# curated setup is available inside the sandbox. Everything else in ~/.claude/
# (projects, sessions, history.jsonl, file-history, paste-cache, plans,
# backups, session-env, shell-snapshots, statsig, cache, debug) is deliberately
# NOT staged -- those are session-scope and would leak transcripts cross-agent.

# --- 2. Stage SafeYolo baseline + shared skill ------------------------------
# Keep SafeYolo's always-on baseline outside .claude/ so it cannot shadow the
# user's CLAUDE.md. Link the shared on-demand skill into Claude's native path.
stage_safeyolo_context "$AGENT_HOME" claude

# --- 3. Write the foreground command -----------------------------------------
# Installs Claude's native release on first run and repairs an incomplete
# installation on subsequent runs. Explicit npm selections retain the legacy
# Node route. Appends the SafeYolo agent
# baseline as system context. Detailed operations remain in the on-demand
# safeyolo skill. Any args after `safeyolo agent start <name> -- ...`
# come through as "$@".

cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -e

# Do not rely on a login shell or BASH_ENV here. Linux launches this file
# through runsc exec, and /etc/environment may have reset PATH before this
# child shell starts. Keep mise's persistent per-agent layout explicit so a
# tool installed below is immediately executable in this same process.
export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.mise}"
export MISE_CONFIG_DIR="${MISE_CONFIG_DIR:-$HOME/.mise}"
export MISE_CACHE_DIR="${MISE_CACHE_DIR:-$HOME/.mise/cache}"
export MISE_OVERRIDE_CONFIG_FILENAMES="/etc/safeyolo/mise-project-config-disabled.toml"
export MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES="none"
export PATH="$HOME/.local/bin:$MISE_DATA_DIR/shims:${PATH}"

if [ -z "${SAFEYOLO_CLAUDE_NPM_SPEC:-}${SAFEYOLO_CLAUDE_NPM_PACKAGE:-}" ]; then
    : "${SAFEYOLO_CLAUDE_NATIVE_SPEC:=aqua:anthropics/claude-code@latest}"
    : "${SAFEYOLO_MIN_RELEASE_AGE:=24h}"
    if MISE_MINIMUM_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE" \
         mise settings get minimum_release_age >/dev/null 2>&1; then
        export MISE_MINIMUM_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE"
    else
        echo "claude-host-setup: mise cannot apply minimum_release_age=$SAFEYOLO_MIN_RELEASE_AGE; no delayed-deployment protection on this build" >&2
    fi
    sy_spec="$SAFEYOLO_CLAUDE_NATIVE_SPEC"
    sy_tool="${sy_spec%@*}"
    sy_target=""
    sy_root="$(mise where "$sy_spec" 2>/dev/null)" || sy_root=""
    sy_expected="$(mise latest --installed "$sy_spec" 2>/dev/null | tail -1)"
    sy_running=""
    if [ -n "$sy_root" ]; then
        sy_running="$("$sy_root/claude" --version 2>/dev/null)" || sy_running=""
    fi
    if [ -z "$sy_root" ] || [ -z "$sy_expected" ] || [ "${sy_running%% *}" != "$sy_expected" ]; then
        echo "SafeYolo: downloading or repairing native Claude Code." >&2
        sy_target="$(mise latest "$sy_spec" 2>/dev/null | tail -1)"
        if [ -n "$sy_target" ]; then
            sy_spec="${sy_tool}@${sy_target}"
        else
            echo "claude-host-setup: could not resolve a remote version for $sy_spec; falling back to $sy_spec" >&2
        fi
        # Aqua verifies the upstream release digest before extraction. Force
        # repair of an installed directory whose executable has gone missing.
        mise use -g --force "$sy_spec" >&2
        sy_root="$(mise where "$sy_spec")"
        sy_expected="$sy_target"
        if [ -z "$sy_expected" ]; then
            sy_expected="$(mise latest --installed "$sy_spec" 2>/dev/null | tail -1)"
        fi
        sy_repaired="$("$sy_root/claude" --version)" || {
            echo "claude-host-setup: native Claude Code installation is incomplete" >&2
            exit 1
        }
        if [ -z "$sy_expected" ] || [ "${sy_repaired%% *}" != "$sy_expected" ]; then
            echo "claude-host-setup: expected Claude $sy_expected after installing $sy_spec, but got $sy_repaired" >&2
            exit 1
        fi
    fi
    # Select this native executable even when a retained npm shim or unrelated
    # command is earlier on PATH. Keep the user's other tools and config.
    export PATH="$sy_root:$PATH"
    # Keep mise's selected version authoritative unless the operator opts in
    # to Claude's independent background updater.
    export DISABLE_AUTOUPDATER="${DISABLE_AUTOUPDATER:-1}"
    sy_running="$(claude --version)"
    sy_running="${sy_running%% *}"
    echo "claude-host-setup: claude $sy_running" >&2
    sy_available="$sy_target"
    if [ -z "$sy_available" ]; then
        sy_available="$(mise latest "$sy_tool" 2>/dev/null | tail -1)"
    fi
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "claude-host-setup: claude $sy_available is available; not upgrading automatically (run: mise use -g ${sy_tool}@${sy_available})" >&2
    fi
else
# Explicit legacy npm selections keep their existing installation behavior.
: "${SAFEYOLO_CLAUDE_NODE_SPEC:=node@22}"
: "${SAFEYOLO_CLAUDE_NPM_SPEC:=npm:@anthropic-ai/claude-code@latest}"
: "${SAFEYOLO_CLAUDE_NPM_PACKAGE:=@anthropic-ai/claude-code@latest}"

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

# Reuse a successful install lookup for this launch's update notice.
sy_target=""

# First-boot install. Tool installs live under persistent /home/agent. Validate
# an existing command as well: mise 2026.7.12+ downloads npm optional
# dependencies but denies lifecycle scripts by default, so Claude's placeholder
# launcher can exist even though its postinstall did not place the native
# binary.
if ! command -v claude >/dev/null 2>&1 || ! claude --version >/dev/null 2>&1; then
    echo "SafeYolo: downloading or repairing Claude Code and its required tools (first use can take several minutes)." >&2
    if [ -f /etc/alpine-release ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo -n apk add nodejs npm >&2
        fi
        npm install --global --prefix /home/agent/.local "$SAFEYOLO_CLAUDE_NPM_PACKAGE" >&2
    else
        # A fresh legacy npm install uses mise's embedded npm installer, which
        # can acquire Claude while Node downloads. Keep configured installs,
        # overrides and prepared tools in their existing order. A failed
        # capability lookup also uses that order.
        sy_node_pid=""
        if [ "$SAFEYOLO_CLAUDE_NODE_SPEC" = node@22 ] &&
           [ "$SAFEYOLO_CLAUDE_NPM_SPEC" = npm:@anthropic-ai/claude-code@latest ] &&
           [ "$SAFEYOLO_CLAUDE_NPM_PACKAGE" = @anthropic-ai/claude-code@latest ] &&
           sy_configs="$(mise config ls --no-header 2>/dev/null)" &&
           [ -z "$sy_configs" ] &&
           sy_installed_node="$(mise ls --installed --no-header node 2>/dev/null)" &&
           [ -z "$sy_installed_node" ] &&
           [ "$(mise settings get npm.package_manager 2>/dev/null)" = auto ] &&
           [ "$(mise settings get npm.shell_out 2>/dev/null)" = false ] &&
           [ "$(mise settings get raw 2>/dev/null)" = false ]; then
            mise install "$SAFEYOLO_CLAUDE_NODE_SPEC" >&2 &
            sy_node_pid=$!
            # Reap our acquisition on any early exit. Leave mise's verified
            # downloads and completed installs available to a later retry.
            trap 'wait "$sy_node_pid" || :' EXIT
        else
            mise use -g "$SAFEYOLO_CLAUDE_NODE_SPEC" >&2
        fi
        sy_tool="${SAFEYOLO_CLAUDE_NPM_SPEC%@*}"
        sy_target="$(sy_remote_version "$sy_tool")"
        if [ -n "$sy_target" ]; then
            sy_spec="${sy_tool}@${sy_target}"
            if [ -n "$sy_node_pid" ]; then
                sy_install_status=0
                mise install --force "$sy_spec" >&2 || sy_install_status=$?
                wait "$sy_node_pid" || sy_install_status=$?
                trap - EXIT
                [ "$sy_install_status" -eq 0 ] || exit "$sy_install_status"
                # Configure both selected tools only after both acquisitions
                # finish. Rebuild shared shims before the existing repair.
                mise use -g "$SAFEYOLO_CLAUDE_NODE_SPEC" "$sy_spec" >&2
            else
                mise use -g --force "$sy_spec" >&2
            fi
        else
            echo "claude-host-setup: could not resolve a remote version for" \
                 "$sy_tool; falling back to $SAFEYOLO_CLAUDE_NPM_SPEC" >&2
            sy_spec="$SAFEYOLO_CLAUDE_NPM_SPEC"
            if [ -n "$sy_node_pid" ]; then
                wait "$sy_node_pid"
                trap - EXIT
                mise use -g "$SAFEYOLO_CLAUDE_NODE_SPEC" >&2
            fi
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
    sy_available="$sy_target"
    if [ -z "$sy_available" ]; then
        sy_available="$(sy_remote_version "$sy_tool")"
    fi
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "claude-host-setup: claude $sy_available is available; not upgrading" \
             "automatically (run: mise use -g ${sy_tool}@${sy_available})" >&2
    fi
fi
fi

# Authentication can still require Claude's supported interactive login.
echo "SafeYolo: Claude Code is installed; opening the session. Sign in if Claude asks." >&2

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
