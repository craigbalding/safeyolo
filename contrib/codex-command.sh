#!/usr/bin/env bash
set -e

export CODEX_HOME=/home/agent/.codex
: "${SAFEYOLO_CODEX_NODE_SPEC:=node@22}"
# Either override supplies the default for the other platform. If both are
# supplied, retain the operator's separate mise and Alpine npm selections.
: "${SAFEYOLO_CODEX_NPM_SPEC:=npm:${SAFEYOLO_CODEX_NPM_PACKAGE:-@openai/codex@latest}}"
: "${SAFEYOLO_CODEX_NPM_PACKAGE:=${SAFEYOLO_CODEX_NPM_SPEC#npm:}}"
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

# --- version policy ---------------------------------------------------------
# Delayed deployment: do not pick up a release published minutes ago. Newer
# mise applies minimum_release_age to transitive npm dependencies too.
# Probe with the requested value: an unset supported setting also makes
# `settings get` fail. Alpine's direct npm path does not apply this setting.
: "${SAFEYOLO_MIN_RELEASE_AGE:=24h}"
sy_alpine=0
if [ -f /etc/alpine-release ]; then sy_alpine=1; fi
if [ "$sy_alpine" = 1 ]; then
    echo "codex-host-setup: direct Alpine npm installation does not apply" \
         "SAFEYOLO_MIN_RELEASE_AGE; no delayed-deployment protection on this path" >&2
elif MISE_MINIMUM_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE" \
     mise settings get minimum_release_age >/dev/null 2>&1; then
    export MISE_MINIMUM_RELEASE_AGE="$SAFEYOLO_MIN_RELEASE_AGE"
else
    echo "codex-host-setup: mise cannot apply minimum_release_age=$SAFEYOLO_MIN_RELEASE_AGE;" \
         "no delayed-deployment protection on this build" >&2
fi

# `mise use -g <tool>@latest` is NOT a remote upgrade -- mise resolves
# `latest` against what is already installed. That matters on the repair
# path: a wrapper whose platform-native binary has gone still fails its
# probe, but mise can decide the existing install already satisfies
# `latest` and do nothing, leaving the agent unable to launch. Resolve the
# remote version explicitly and install that exact value.
sy_remote_version() { mise latest "$1" 2>/dev/null | tail -1; }
sy_npm_version() {
    npm view "$1" version --json 2>/dev/null | node -e '
        let text = "";
        process.stdin.on("data", chunk => text += chunk);
        process.stdin.on("end", () => {
            if (!text.trim()) process.exit(1);
            const versions = JSON.parse(text);
            const version = Array.isArray(versions) ? versions.at(-1) : versions;
            if (typeof version !== "string" || !version) process.exit(1);
            console.log(version);
        });' 2>/dev/null
}

sy_spec="$SAFEYOLO_CODEX_NPM_SPEC"
if [ "$sy_alpine" = 1 ]; then sy_spec="npm:$SAFEYOLO_CODEX_NPM_PACKAGE"; fi
sy_package="${sy_spec#npm:}"
# A scoped package without a version still contains @. Only strip a suffix
# after the package name, never the scope itself.
sy_name="$sy_package"
if [[ "${sy_package#@}" = *@* ]]; then sy_name="${sy_package%@*}"; fi
sy_tool="npm:$sy_name"

# Validate an existing command as well as its absence: the CLI is an npm
# wrapper plus a platform-native optional dependency, so the launcher can
# survive while the native binary does not (mise declining npm lifecycle
# scripts, or macOS Gatekeeper trashing the vendored Mach-O over a revoked
# signing cert). `command -v` alone still succeeds in that state and the
# install below is skipped, leaving the agent permanently unable to launch.
if ! command -v codex >/dev/null 2>&1 || ! codex --version >/dev/null 2>&1; then
    sy_target=""
    if [ "$sy_alpine" = 1 ]; then
        if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
            sudo -n apk add nodejs npm >&2
        fi
        sy_target="$(sy_npm_version "$sy_package")" || sy_target=""
        sy_install="$sy_package"
        if [ -n "$sy_target" ]; then
            sy_install="${sy_name}@${sy_target}"
        else
            echo "codex-host-setup: could not resolve a remote version for" \
                 "$sy_package; falling back to the configured npm selection" >&2
        fi
        # npm checks registry tarballs against their published integrity and
        # reinstalls the selected global package, including its native payload.
        npm install --global --prefix "$HOME/.local" "$sy_install" >&2
    else
        mise use -g "$SAFEYOLO_CODEX_NODE_SPEC" >&2
        sy_target="$(sy_remote_version "$sy_spec")"
        if [ -n "$sy_target" ]; then
            # The npm backend verifies registry package integrity. An exact
            # selection is per repair, not a permanent update policy or a
            # claim that the registry/publisher is independently trusted.
            mise use -g --force "${sy_tool}@${sy_target}" >&2
        else
            # Remote lookup failed (offline, registry down). Fall back to the
            # configured spec rather than refusing to start.
            echo "codex-host-setup: could not resolve a remote version for" \
                 "$sy_spec; falling back to $sy_spec" >&2
            mise use -g --force "$sy_spec" >&2
        fi
    fi
    # Optional native dependencies can fail without failing npm installation.
    # Check the reached executable before either ordinary or supervised use.
    sy_repaired="$(codex --version 2>/dev/null)" || {
        echo "codex-host-setup: installation of $sy_spec left Codex unavailable;" \
             "check the package/native payload and installer diagnostics" >&2
        exit 1
    }
    if [ -n "$sy_target" ] && [ "${sy_repaired##* }" != "$sy_target" ]; then
        echo "codex-host-setup: expected Codex $sy_target after installing $sy_spec," \
             "but got $sy_repaired; check the selected package/native payload and PATH" >&2
        exit 1
    fi
fi

# Report the version actually about to run, and say when a newer one exists
# without silently taking it. A pinned artifact ageing in place is fine; a
# pinned artifact ageing *invisibly* is what left an agent dead for months.
sy_running="$(codex --version 2>/dev/null)"
sy_running="${sy_running##* }"
if [ -n "$sy_running" ]; then
    echo "codex-host-setup: codex $sy_running" >&2
    if [ "$sy_alpine" = 1 ]; then
        sy_available="$(sy_npm_version "$sy_name")" || sy_available=""
        sy_update="npm install --global --prefix $HOME/.local ${sy_name}"
    else
        sy_available="$(sy_remote_version "$sy_tool")"
        sy_update="mise use -g ${sy_tool}"
    fi
    if [ -n "$sy_available" ] && [ "$sy_available" != "$sy_running" ]; then
        echo "codex-host-setup: codex $sy_available is available; not upgrading" \
             "automatically (run: ${sy_update}@${sy_available})" >&2
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
supervised_args=(--dangerously-bypass-approvals-and-sandbox)
if [ -f "$HOME/.safeyolo/AGENTS.md" ]; then
    args+=(-c "developer_instructions=$(toml_string_from_file "$HOME/.safeyolo/AGENTS.md")")
    supervised_args+=(-c "developer_instructions=$(toml_string_from_file "$HOME/.safeyolo/AGENTS.md")")
fi

exec codex "${args[@]}" "$@"
