#!/usr/bin/env bash
# SafeYolo host setup script for Pi coding agent.
#
# This script stages only SafeYolo-owned context and writes a foreground
# command. Pi authentication and all other Pi state are created and retained
# inside the agent; no host ~/.pi path is inspected or copied.
#
# See contrib/HOST_SCRIPT_GUIDE.md for the host-script contract.

set -euo pipefail
umask 077

: "${SAFEYOLO_AGENT_NAME:?must be run via 'safeyolo agent add/run --host-script'}"
: "${SAFEYOLO_AGENT_HOME:?must be run via 'safeyolo agent add/run --host-script'}"

AGENT_HOME="$SAFEYOLO_AGENT_HOME"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib/stage-safeyolo-context.sh
. "$SCRIPT_DIR/lib/stage-safeyolo-context.sh"

# Pi's package and runtime are deliberately reviewed pins. The tarball is
# fetched by exact package/version, checked against the published integrity,
# and only then installed with lifecycle scripts disabled.
PI_PACKAGE="@earendil-works/pi-coding-agent"
PI_VERSION="0.84.3"
PI_INTEGRITY="sha512-Yr2p9PubrbFZmYEPYI+C8KmZP9xlFuLDnAG64RtU0ZDgrdiXYWa+y7WGyJO5OlqPliOkVCMd9IzVszO3/t0D0w=="

# The script never reads any host Pi path. The only host-side filesystem work
# is SafeYolo's own baseline and the native read-only skill link.
stage_safeyolo_context "$AGENT_HOME" pi

cat > "$AGENT_HOME/.safeyolo-command" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${SAFEYOLO_PI_NODE_SPEC:=node@22.19.0}"
: "${SAFEYOLO_PI_PREFIX:=$HOME/.local}"
PI_PACKAGE="@earendil-works/pi-coding-agent"
PI_VERSION="0.84.3"
PI_INTEGRITY="sha512-Yr2p9PubrbFZmYEPYI+C8KmZP9xlFuLDnAG64RtU0ZDgrdiXYWa+y7WGyJO5OlqPliOkVCMd9IzVszO3/t0D0w=="
PI_MIN_NODE="22.19.0"

export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.mise}"
export MISE_CONFIG_DIR="${MISE_CONFIG_DIR:-$HOME/.mise}"
export MISE_CACHE_DIR="${MISE_CACHE_DIR:-$HOME/.mise/cache}"
export MISE_OVERRIDE_CONFIG_FILENAMES="/etc/safeyolo/mise-project-config-disabled.toml"
export MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES="none"
export PATH="$SAFEYOLO_PI_PREFIX/bin:$HOME/.local/bin:$MISE_DATA_DIR/shims:${PATH}"

pi_fail() {
    echo "pi-host-setup: $1" >&2
    exit 1
}

pi_version_tuple() {
    local version="$1"
    case "$version" in
        v*) version="${version#v}" ;;
    esac
    case "$version" in
        ''|*[!0-9.]*|*.*.*.*) return 1 ;;
    esac
    local major minor patch extra
    IFS=. read -r major minor patch extra <<EOF_VERSION
$version
EOF_VERSION
    [ -n "${major:-}" ] && [ -n "${minor:-}" ] && [ -n "${patch:-}" ] &&
        [ -z "${extra:-}" ] || return 1
    printf '%s %s %s\n' "$major" "$minor" "$patch"
}

pi_node_is_supported() {
    local version
    version="$(node --version 2>/dev/null)" || return 1
    local major minor patch
    read -r major minor patch < <(pi_version_tuple "$version") || return 1
    if [ "$major" -gt 22 ]; then
        return 0
    fi
    if [ "$major" -eq 22 ] && [ "$minor" -gt 19 ]; then
        return 0
    fi
    [ "$major" -eq 22 ] && [ "$minor" -eq 19 ] && [ "$patch" -ge 0 ]
}

pi_validate_node() {
    command -v node >/dev/null 2>&1 || return 1
    pi_node_is_supported
}

if [ -f /etc/alpine-release ]; then
    if ! pi_validate_node; then
        sudo -n apk add nodejs npm >&2 ||
            pi_fail "Alpine requires native nodejs/npm with Node >= $PI_MIN_NODE; package installation failed"
    fi
else
    if ! pi_validate_node; then
        command -v mise >/dev/null 2>&1 ||
            pi_fail "mise is required to install Node >= $PI_MIN_NODE"
        mise use -g "$SAFEYOLO_PI_NODE_SPEC" >/dev/null 2>&1 ||
            pi_fail "could not install the requested Node runtime; need Node >= $PI_MIN_NODE"
    fi
fi

pi_validate_node || pi_fail "unsupported Node runtime; Pi requires Node >= $PI_MIN_NODE"

pi_prefix="$SAFEYOLO_PI_PREFIX"
pi_package_dir="$pi_prefix/lib/node_modules/$PI_PACKAGE"
pi_package_json="$pi_package_dir/package.json"
pi_bin="$pi_prefix/bin/pi"

pi_path_is_safe() {
    local path="$1"
    local current="/"
    local component
    local old_ifs="$IFS"
    local path_components
    IFS=/
    read -r -a path_components <<< "${path#/}"
    IFS="$old_ifs"
    for component in "${path_components[@]}"; do
        [ -n "$component" ] || continue
        current="$current$component"
        [ -L "$current" ] && return 1
        if [ -e "$current" ] && [ ! -d "$current" ] &&
           [ "$current" != "$pi_package_json" ]; then
            return 1
        fi
        current="$current/"
    done
}

pi_validate_dir() {
    local path="$1"
    local owner mode mode_value
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    owner="$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path" 2>/dev/null)" || return 1
    [ "$owner" = "$(id -u)" ] || return 1
    mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)" || return 1
    mode_value=$((0$mode))
    [ $((mode_value & 022)) -eq 0 ]
}

pi_validate_optional_file() {
    local path="$1"
    local owner links mode mode_value
    if [ ! -e "$path" ]; then
        [ ! -L "$path" ]
        return
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    owner="$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path" 2>/dev/null)" || return 1
    links="$(stat -c '%h' "$path" 2>/dev/null || stat -f '%l' "$path" 2>/dev/null)" || return 1
    mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)" || return 1
    [ "$owner" = "$(id -u)" ] || return 1
    [ "$links" = 1 ] || return 1
    mode_value=$((0$mode))
    case "$path" in
        */auth.json) [ "$mode_value" -eq 384 ] || return 1 ;;
    esac
    [ $((mode_value & 022)) -eq 0 ]
}

pi_validate_launcher() {
    local target owner links mode mode_value
    if [ -L "$pi_bin" ]; then
        target="$(readlink "$pi_bin")" || return 1
        [ "$target" = "../lib/node_modules/$PI_PACKAGE/dist/bundle/cli.js" ] ||
            return 1
        [ -x "$pi_bin" ] || return 1
        return 0
    fi
    [ -f "$pi_bin" ] || return 1
    owner="$(stat -c '%u' "$pi_bin" 2>/dev/null || stat -f '%u' "$pi_bin" 2>/dev/null)" || return 1
    links="$(stat -c '%h' "$pi_bin" 2>/dev/null || stat -f '%l' "$pi_bin" 2>/dev/null)" || return 1
    mode="$(stat -c '%a' "$pi_bin" 2>/dev/null || stat -f '%Lp' "$pi_bin" 2>/dev/null)" || return 1
    [ "$owner" = "$(id -u)" ] || return 1
    [ "$links" = 1 ] || return 1
    mode_value=$((0$mode))
    [ $((mode_value & 022)) -eq 0 ] && [ -x "$pi_bin" ]
}

pi_identity_is_healthy() {
    pi_path_is_safe "$pi_package_json" || return 1
    [ -f "$pi_package_json" ] && [ ! -L "$pi_package_json" ] || return 1
    pi_validate_launcher || return 1
    local package_identity
    package_identity="$(node -e '
const fs = require("fs");
const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
process.stdout.write(`${p.name}\t${p.version}`);
' "$pi_package_json" 2>/dev/null)" || return 1
    [ "$package_identity" = "$PI_PACKAGE	$PI_VERSION" ] || return 1
    "$pi_bin" --version >/dev/null 2>&1
}

if ! pi_identity_is_healthy; then
    if ! command -v npm >/dev/null 2>&1; then
        if [ -f /etc/alpine-release ]; then
            sudo -n apk add nodejs npm >&2 ||
                pi_fail "Alpine requires native nodejs/npm to repair the Pi installation"
        else
            command -v mise >/dev/null 2>&1 ||
                pi_fail "npm is unavailable and mise cannot repair the Pi installation"
            mise use -g "$SAFEYOLO_PI_NODE_SPEC" >/dev/null 2>&1 ||
                pi_fail "could not provision npm for the reviewed Pi installation"
        fi
    fi
    pi_path_is_safe "$pi_prefix" ||
        pi_fail "unsafe Pi install prefix; refusing to follow a symlinked path"
    mkdir -p "$pi_prefix/bin"
    pi_path_is_safe "$pi_prefix" ||
        pi_fail "unsafe Pi install prefix after creation"

    pi_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/safeyolo-pi.XXXXXX")"
    pi_tarball=""
    pi_cleanup() {
        if [ -n "$pi_tarball" ] && [ -f "$pi_tarball" ]; then
            rm -f -- "$pi_tarball"
        fi
        rmdir "$pi_tmp_dir" 2>/dev/null || true
    }
    trap pi_cleanup EXIT
    pi_pack_name="$(npm pack --ignore-scripts --pack-destination "$pi_tmp_dir" "$PI_PACKAGE@$PI_VERSION" 2>/dev/null | tail -n 1)" ||
        pi_fail "could not acquire the reviewed Pi package $PI_PACKAGE@$PI_VERSION"
    case "$pi_pack_name" in
        *.tgz) pi_tarball="$pi_tmp_dir/$pi_pack_name" ;;
        *) pi_fail "the reviewed Pi package did not produce a bounded tarball" ;;
    esac
    [ -f "$pi_tarball" ] || pi_fail "the reviewed Pi package tarball is unavailable"
    pi_digest_file="$pi_tmp_dir/digest.bin"
    openssl dgst -sha512 -binary "$pi_tarball" > "$pi_digest_file" 2>/dev/null ||
        pi_fail "cannot verify the reviewed Pi package integrity"
    pi_actual_integrity="sha512-$(openssl base64 -A "$pi_digest_file" 2>/dev/null)" ||
        pi_fail "cannot verify the reviewed Pi package integrity"
    [ "$pi_actual_integrity" = "$PI_INTEGRITY" ] ||
        pi_fail "Pi package integrity differs from the reviewed pin; refusing installation"

    npm install --global --prefix "$pi_prefix" --ignore-scripts "$pi_tarball" >/dev/null 2>&1 ||
        pi_fail "could not install the reviewed Pi package into the persistent agent home"
    pi_identity_is_healthy ||
        pi_fail "Pi installation identity or executable verification failed"
fi

pi_path_is_safe "$HOME/.safeyolo" || pi_fail "unsafe SafeYolo baseline path"
pi_validate_dir "$HOME/.safeyolo" || pi_fail "unsafe SafeYolo baseline directory"
pi_baseline="$HOME/.safeyolo/AGENTS.md"
if [ -L "$pi_baseline" ] ||
   { [ -e "$pi_baseline" ] && [ ! -f "$pi_baseline" ]; }; then
    pi_fail "unsafe SafeYolo baseline path"
fi

pi_skills="$HOME/.pi/agent/skills"
pi_path_is_safe "$HOME/.pi" || pi_fail "unsafe Pi state parent path"
pi_path_is_safe "$HOME/.pi/agent" || pi_fail "unsafe Pi agent state path"
pi_path_is_safe "$pi_skills" || pi_fail "unsafe Pi skill path"
pi_validate_dir "$HOME/.pi" || pi_fail "unsafe Pi state parent directory"
pi_validate_dir "$HOME/.pi/agent" || pi_fail "unsafe Pi agent state directory"
pi_validate_dir "$pi_skills" || pi_fail "unsafe Pi skill directory"
for pi_state_file in auth.json settings.json models.json; do
    pi_validate_optional_file "$HOME/.pi/agent/$pi_state_file" ||
        pi_fail "unsafe Pi agent state file"
done
pi_skill="$pi_skills/safeyolo"
if [ ! -L "$pi_skill" ] || [ "$(readlink "$pi_skill")" != "/safeyolo/skills/safeyolo" ]; then
    pi_fail "SafeYolo Pi skill link is missing or unsafe"
fi

args=(--approve)
if [ -f "$pi_baseline" ]; then
    args+=(--append-system-prompt "$(cat "$pi_baseline")")
fi

exec "$pi_bin" "${args[@]}" "$@"
EOF
chmod +x "$AGENT_HOME/.safeyolo-command"

echo "pi-host-setup: $SAFEYOLO_AGENT_NAME ready at $AGENT_HOME"
