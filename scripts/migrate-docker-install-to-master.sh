#!/usr/bin/env bash
# Migrate a dirty Docker-era SafeYolo checkout to current master while
# preserving a local, restartable Docker fallback.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

REPO="${HOME}/proj/safeyolo"
LEGACY_REPO="${HOME}/proj/safeyolo-docker"
DEFAULT_CONFIG="${HOME}/.safeyolo"
LEGACY_CONFIG="${HOME}/.safeyolo-docker"
STATE_HOME="${XDG_STATE_HOME:-${HOME}/.local/state}"
DEFAULT_LOGS="${STATE_HOME}/safeyolo"
LEGACY_LOGS="${STATE_HOME}/safeyolo-docker"
BACKUP_ROOT="${STATE_HOME}/safeyolo-migration-backups"
FALLBACK_BRANCH="local/docker-fallback"
REMOTE="origin"
TARGET_BRANCH="master"
ASSUME_YES=false
MIGRATION_ONLY=false
MIGRATION_STARTED=false
MIGRATION_COMPLETE=false

usage() {
    cat <<'EOF'
Usage: migrate-docker-install-to-master.sh [options]

Preserves a dirty Docker-era checkout in a separate worktree, moves its
runtime state away from the default paths, fast-forwards the original
checkout to current master, and prepares a new default-path installation.

Defaults:
  current checkout:       ~/proj/safeyolo
  Docker fallback source: ~/proj/safeyolo-docker
  Docker fallback config: ~/.safeyolo-docker
  new master config:      ~/.safeyolo

Options:
  --yes                 Do not ask for confirmation.
  --migration-only      Move/preserve state but skip uv install, build,
                        safeyolo init, setup, and doctor.
  --repo PATH           Current dirty checkout.
  --legacy-repo PATH    Destination for the Docker fallback worktree.
  --legacy-config PATH  Destination for the Docker runtime configuration.
  --legacy-logs PATH    Destination for the Docker logs.
  --backup-root PATH    Directory in which to create a timestamped backup.
  -h, --help            Show this help.

The script stops, but never removes, running Docker containers whose bind
mounts reference the old checkout or runtime paths. It does not push the
fallback branch or stash to any remote.
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

note() {
    printf '\n==> %s\n' "$*"
}

warn() {
    echo "WARNING: $*" >&2
}

expand_path() {
    local path=$1
    case "$path" in
        "~") printf '%s\n' "$HOME" ;;
        "~/"*) printf '%s/%s\n' "$HOME" "${path:2}" ;;
        *) printf '%s\n' "$path" ;;
    esac
}

home_expression() {
    local path=$1
    case "$path" in
        "$HOME") printf '%s\n' '${HOME}' ;;
        "$HOME"/*) printf '%s/%s\n' '${HOME}' "${path#"$HOME"/}" ;;
        *) printf '%s\n' "$path" ;;
    esac
}

while (($#)); do
    case "$1" in
        --yes)
            ASSUME_YES=true
            shift
            ;;
        --migration-only)
            MIGRATION_ONLY=true
            shift
            ;;
        --repo|--legacy-repo|--legacy-config|--legacy-logs|--backup-root)
            (($# >= 2)) || die "$1 requires a path"
            value=$(expand_path "$2")
            case "$1" in
                --repo) REPO=$value ;;
                --legacy-repo) LEGACY_REPO=$value ;;
                --legacy-config) LEGACY_CONFIG=$value ;;
                --legacy-logs) LEGACY_LOGS=$value ;;
                --backup-root) BACKUP_ROOT=$value ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

on_exit() {
    local rc=$?
    if ((rc != 0)) && $MIGRATION_STARTED; then
        echo >&2
        warn "Migration stopped before completing all requested steps."
        warn "No Docker containers or volumes were removed."
        warn "Inspect: ${BACKUP_DIR:-$BACKUP_ROOT}"
        if $MIGRATION_COMPLETE; then
            warn "The Docker fallback is at $LEGACY_REPO with state at $LEGACY_CONFIG."
        else
            warn "Inspect both Git worktrees and runtime directories before retrying."
        fi
    fi
}
trap on_exit EXIT

for command in git tar python3; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
if ! $MIGRATION_ONLY; then
    command -v uv >/dev/null 2>&1 || die "uv is required unless --migration-only is used"
fi

[[ -d "$REPO/.git" || -f "$REPO/.git" ]] || die "not a Git checkout: $REPO"
REPO=$(cd "$REPO" && pwd -P)
LEGACY_REPO=$(expand_path "$LEGACY_REPO")
LEGACY_CONFIG=$(expand_path "$LEGACY_CONFIG")
LEGACY_LOGS=$(expand_path "$LEGACY_LOGS")
BACKUP_ROOT=$(expand_path "$BACKUP_ROOT")

[[ "$REPO" != "$LEGACY_REPO" ]] || die "current and fallback checkout paths are identical"
[[ "$DEFAULT_CONFIG" != "$LEGACY_CONFIG" ]] || die "default and fallback config paths are identical"
[[ "$DEFAULT_LOGS" != "$LEGACY_LOGS" ]] || die "default and fallback log paths are identical"
[[ -e "$DEFAULT_CONFIG" ]] || die "Docker runtime config not found: $DEFAULT_CONFIG"
[[ ! -e "$LEGACY_REPO" ]] || die "fallback checkout already exists: $LEGACY_REPO"
[[ ! -e "$LEGACY_CONFIG" ]] || die "fallback config path already exists: $LEGACY_CONFIG"
if [[ -e "$DEFAULT_LOGS" && -e "$LEGACY_LOGS" ]]; then
    die "fallback log path already exists: $LEGACY_LOGS"
fi

git -C "$REPO" rev-parse --verify HEAD >/dev/null
git -C "$REPO" show-ref --verify --quiet "refs/heads/$TARGET_BRANCH" \
    || die "local branch not found: $TARGET_BRANCH"
git -C "$REPO" show-ref --verify --quiet "refs/heads/$FALLBACK_BRANCH" \
    && die "fallback branch already exists: $FALLBACK_BRANCH"

for marker in MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD; do
    if git -C "$REPO" rev-parse -q --verify "$marker" >/dev/null; then
        die "Git operation in progress ($marker); finish it before migrating"
    fi
done
git_dir=$(git -C "$REPO" rev-parse --absolute-git-dir)
if [[ -d "$git_dir/rebase-merge" || -d "$git_dir/rebase-apply" ]]; then
    die "Git rebase in progress; finish it before migrating"
fi

note "Fetching $REMOTE/$TARGET_BRANCH before stopping anything"
git -C "$REPO" fetch "$REMOTE" "$TARGET_BRANCH"
git -C "$REPO" rev-parse --verify "$REMOTE/$TARGET_BRANCH" >/dev/null
git -C "$REPO" merge-base --is-ancestor HEAD "$REMOTE/$TARGET_BRANCH" \
    || die "current HEAD is not an ancestor of $REMOTE/$TARGET_BRANCH; refusing automatic migration"

CURRENT_HEAD=$(git -C "$REPO" rev-parse HEAD)
TARGET_HEAD=$(git -C "$REPO" rev-parse "$REMOTE/$TARGET_BRANCH")
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"

cat <<EOF

SafeYolo Docker-to-master migration

  current checkout:  $REPO
  current commit:    $CURRENT_HEAD
  target commit:     $TARGET_HEAD
  fallback checkout: $LEGACY_REPO
  Docker config:     $DEFAULT_CONFIG -> $LEGACY_CONFIG
  Docker logs:       $DEFAULT_LOGS -> $LEGACY_LOGS
  private backup:    $BACKUP_DIR

The standard paths $DEFAULT_CONFIG and $DEFAULT_LOGS will then be used by
the new master installation. Matching Docker containers will be stopped,
not removed.
EOF

if ! $ASSUME_YES; then
    [[ -t 0 ]] || die "confirmation required; rerun interactively or pass --yes"
    read -r -p "Continue? [y/N] " answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) echo "Cancelled."; exit 0 ;;
    esac
fi

MIGRATION_STARTED=true
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

note "Creating private recovery artifacts"
git -C "$REPO" status --short --branch >"$BACKUP_DIR/git-status.txt"
git -C "$REPO" diff --binary HEAD >"$BACKUP_DIR/tracked.patch"
git -C "$REPO" ls-files --others --exclude-standard -z >"$BACKUP_DIR/untracked.list"
if [[ -s "$BACKUP_DIR/untracked.list" ]]; then
    tar --create --gzip --file="$BACKUP_DIR/untracked.tar.gz" \
        --directory="$REPO" --null --files-from="$BACKUP_DIR/untracked.list"
fi
tar --create --gzip --file="$BACKUP_DIR/docker-config.tar.gz" \
    --directory="$(dirname "$DEFAULT_CONFIG")" "$(basename "$DEFAULT_CONFIG")"

mkdir -p "$BACKUP_DIR/ignored-host-files"
for name in .env docker-compose.override.yml docker-compose.override.yaml; do
    if [[ -e "$REPO/$name" ]]; then
        cp -a "$REPO/$name" "$BACKUP_DIR/ignored-host-files/$name"
    fi
done

matching_containers=()
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue
        matched=false
        while IFS= read -r source; do
            case "$source" in
                "$REPO"|"$REPO"/*|\
                "$DEFAULT_CONFIG"|"$DEFAULT_CONFIG"/*|\
                "$DEFAULT_LOGS"|"$DEFAULT_LOGS"/*)
                    matched=true
                    break
                    ;;
            esac
        done < <(docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "$container_id")
        if $matched; then
            matching_containers+=("$container_id")
        fi
    done < <(docker ps -q)
else
    warn "Docker is unavailable; no running-container check was possible"
fi

if ((${#matching_containers[@]})); then
    note "Stopping Docker containers that use the old checkout or state"
    for container_id in "${matching_containers[@]}"; do
        container_name=$(docker inspect --format '{{.Name}}' "$container_id")
        printf '  stopping %s\n' "${container_name#/}"
    done
    docker stop "${matching_containers[@]}" >/dev/null
else
    note "No running Docker containers reference the paths being moved"
fi

note "Preserving dirty Docker source and fast-forwarding master"
git -C "$REPO" switch -c "$FALLBACK_BRANCH"
stash_before=$(git -C "$REPO" rev-parse -q --verify refs/stash 2>/dev/null || true)
git -C "$REPO" stash push --include-untracked \
    -m "SafeYolo Docker fallback migration $TIMESTAMP"
stash_after=$(git -C "$REPO" rev-parse -q --verify refs/stash 2>/dev/null || true)
stash_commit=""
if [[ -n "$stash_after" && "$stash_after" != "$stash_before" ]]; then
    stash_commit=$stash_after
    printf '%s\n' "$stash_commit" >"$BACKUP_DIR/stash-commit.txt"
fi

git -C "$REPO" switch "$TARGET_BRANCH"
git -C "$REPO" merge --ff-only "$REMOTE/$TARGET_BRANCH"
mkdir -p "$(dirname "$LEGACY_REPO")"
git -C "$REPO" worktree add "$LEGACY_REPO" "$FALLBACK_BRANCH"
if [[ -n "$stash_commit" ]]; then
    git -C "$LEGACY_REPO" stash apply "$stash_commit"
fi

# These files are ignored, so --include-untracked does not carry them to a
# new worktree. They belong to the Docker deployment, not the clean master.
for name in .env docker-compose.override.yml docker-compose.override.yaml; do
    if [[ -e "$REPO/$name" ]]; then
        [[ ! -e "$LEGACY_REPO/$name" ]] \
            || die "cannot preserve ignored file; destination exists: $LEGACY_REPO/$name"
        mv "$REPO/$name" "$LEGACY_REPO/$name"
    fi
done

note "Relocating Docker runtime state"
mkdir -p "$(dirname "$LEGACY_CONFIG")"
mv "$DEFAULT_CONFIG" "$LEGACY_CONFIG"
if [[ -e "$DEFAULT_LOGS" ]]; then
    mkdir -p "$(dirname "$LEGACY_LOGS")"
    mv "$DEFAULT_LOGS" "$LEGACY_LOGS"
fi

note "Updating embedded paths in the private Docker fallback"
LEGACY_CONFIG_HOME_EXPR=$(home_expression "$LEGACY_CONFIG")
LEGACY_LOGS_HOME_EXPR=$(home_expression "$LEGACY_LOGS")
python3 - \
    "$LEGACY_CONFIG" "$LEGACY_REPO" \
    "$DEFAULT_CONFIG" "$LEGACY_CONFIG" \
    "$DEFAULT_LOGS" "$LEGACY_LOGS" \
    "$REPO" "$LEGACY_REPO" \
    "$LEGACY_CONFIG_HOME_EXPR" "$LEGACY_LOGS_HOME_EXPR" <<'PY'
import sys
from pathlib import Path

config_root = Path(sys.argv[1])
repo_root = Path(sys.argv[2])
replacements = [
    (sys.argv[3], sys.argv[4]),
    (sys.argv[5], sys.argv[6]),
    (sys.argv[7], sys.argv[8]),
    ("${HOME}/.safeyolo", sys.argv[9]),
    ("${HOME}/.local/state/safeyolo", sys.argv[10]),
]

skip_parts = {".git", ".venv", "__pycache__", ".pytest_cache"}
changed = []
for root in (config_root, repo_root):
    if not root.exists():
        continue
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in skip_parts for part in path.parts):
            continue
        try:
            if path.stat().st_size > 16 * 1024 * 1024:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue
        updated = data
        for old, new in replacements:
            updated = updated.replace(old.encode(), new.encode())
        if updated != data:
            path.write_bytes(updated)
            changed.append(path)

print(f"  rewrote {len(changed)} text file(s)")
PY

cat >"$LEGACY_CONFIG/legacy-env.sh" <<EOF
# Source this file before using the Docker-era SafeYolo CLI.
export SAFEYOLO_CONFIG_DIR=$(printf '%q' "$LEGACY_CONFIG")
export SAFEYOLO_LOGS_DIR=$(printf '%q' "$LEGACY_LOGS")
EOF
chmod 600 "$LEGACY_CONFIG/legacy-env.sh"

MIGRATION_COMPLETE=true

if ! $MIGRATION_ONLY; then
    note "Installing and preparing current master with default paths"
    unset SAFEYOLO_CONFIG_DIR SAFEYOLO_LOGS_DIR SAFEYOLO_RUNSC_ROOT
    uv tool install --reinstall --editable "$REPO"

    SAFEYOLO_BIN=$(command -v safeyolo || true)
    if [[ -z "$SAFEYOLO_BIN" && -x "$HOME/.local/bin/safeyolo" ]]; then
        SAFEYOLO_BIN="$HOME/.local/bin/safeyolo"
    fi
    [[ -n "$SAFEYOLO_BIN" ]] || die "safeyolo was installed but is not on PATH"

    (
        cd "$REPO"
        "$SAFEYOLO_BIN" build
        "$SAFEYOLO_BIN" init --no-interactive
        "$SAFEYOLO_BIN" setup
        "$SAFEYOLO_BIN" doctor || true
    )
fi

note "Migration complete"
cat <<EOF
Current master:
  source: $REPO
  config: $DEFAULT_CONFIG
  logs:   $DEFAULT_LOGS

Docker fallback:
  source: $LEGACY_REPO
  config: $LEGACY_CONFIG
  logs:   $LEGACY_LOGS
  env:    $LEGACY_CONFIG/legacy-env.sh

Private recovery artifacts:
  $BACKUP_DIR

The Docker containers and named volumes were not removed. Review the Docker
fallback Compose files before restarting them. Start current master with:

  safeyolo start
EOF
