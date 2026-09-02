#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: lab-snapshot.sh EVIDENCE_ROOT [--socket PATH] [--label LABEL]
       lab-snapshot.sh EVIDENCE_ROOT [TMUX_SOCKET]

Capture a bounded controller-side system, tmux, process, and outer SafeYolo
health snapshot. The positional TMUX_SOCKET form is retained for compatibility.
EOF
  exit 2
}

[ "$#" -ge 1 ] || usage
evidence_root=$1
shift

tmux_socket=
snapshot_label=controller
while [ "$#" -gt 0 ]; do
  case "$1" in
    --socket)
      [ "$#" -ge 2 ] || usage
      tmux_socket=$2
      shift 2
      ;;
    --label)
      [ "$#" -ge 2 ] || usage
      snapshot_label=$2
      shift 2
      ;;
    --*) usage ;;
    *)
      [ -z "$tmux_socket" ] || usage
      tmux_socket=$1
      shift
      ;;
  esac
done

umask 077
install -d -m 700 "$evidence_root"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
safe_label=$(printf '%s' "$snapshot_label" | tr -c 'A-Za-z0-9_.-' '_')
[ -n "$safe_label" ] || safe_label=controller
snapshot_dir="$evidence_root/snapshot-$safe_label-$stamp-$$"
[ ! -e "$snapshot_dir" ] || {
  printf 'Snapshot destination already exists: %s\n' "$snapshot_dir" >&2
  exit 2
}
stage_dir=$(mktemp -d "$evidence_root/.snapshot-$safe_label-$stamp-$$.staging.XXXXXX")
chmod 700 "$stage_dir"

finalized=0
mark_incomplete() {
  local rc=$1
  trap - EXIT
  if [ "$finalized" -eq 0 ] && [ -d "$stage_dir" ]; then
    printf 'status=incomplete\nexit_code=%s\nfailed_utc=%s\n' \
      "$rc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$stage_dir/snapshot-status.txt"
    find "$stage_dir" -type f -exec chmod 600 {} +
    incomplete_dir="$snapshot_dir.incomplete"
    if [ -e "$incomplete_dir" ]; then
      incomplete_dir="$snapshot_dir.incomplete.$RANDOM"
    fi
    mv "$stage_dir" "$incomplete_dir"
    printf 'Incomplete snapshot retained at: %s\n' "$incomplete_dir" >&2
  fi
  exit "$rc"
}
trap 'mark_incomplete $?' EXIT

started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '%s\n' "$started_utc" > "$stage_dir/captured-utc.txt"
{
  printf 'label=%s\n' "$snapshot_label"
  printf 'snapshot_scope=controller-side environment\n'
  printf 'safeyolo_health_scope=outer/controller Agent API\n'
  printf 'safeyolo_health_endpoint=http://_safeyolo.proxy.internal/health\n'
  printf 'tmux_socket_argument=%s\n' "${tmux_socket:-current-environment}"
} > "$stage_dir/snapshot-context.txt"

uname -a > "$stage_dir/system.txt"

{
  for name in TMUX TMUX_PANE; do
    if [[ ! -v $name ]]; then
      printf '%s=unset\n' "$name"
    elif [ -z "${!name}" ]; then
      printf '%s=empty\n' "$name"
    else
      printf '%s=nonempty\n' "$name"
    fi
  done
  for name in HTTP_PROXY HTTPS_PROXY NO_PROXY SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS OPENAI_API_KEY CODEX_API_KEY ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN; do
    if [[ ! -v $name ]]; then
      printf '%s=unset\n' "$name"
    elif [ -z "${!name}" ]; then
      printf '%s=empty\n' "$name"
    else
      printf '%s=nonempty\n' "$name"
    fi
  done
} > "$stage_dir/environment-presence.txt"

probe_version() {
  local display_name=$1
  local command_name=$2
  local version_output
  local version_rc

  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf '%s=not-found\n' "$display_name"
    return
  fi
  if ! command -v timeout >/dev/null 2>&1; then
    printf '%s=probe-skipped-no-timeout-command\n' "$display_name"
    return
  fi
  if version_output=$(timeout -k 2s 10s "$command_name" --version 2>&1); then
    version_rc=0
  else
    version_rc=$?
  fi
  printf '%s_exit=%s\n' "$display_name" "$version_rc"
  printf '%s\n' "$version_output" | sed -n '1,3p'
}

{
  tmux -V 2>&1 || true
  probe_version safeyolo safeyolo
  probe_version codex codex
  probe_version claude claude
  probe_version nats-server nats-server
} > "$stage_dir/versions.txt"

tmux_args=()
if [ -n "$tmux_socket" ]; then
  tmux_args=(-S "$tmux_socket")
fi

if tmux "${tmux_args[@]}" list-panes -a >/dev/null 2>&1; then
  tmux "${tmux_args[@]}" list-panes -a \
    -F $'#{socket_path}\t#{session_name}:#{window_index}.#{pane_index}\t#{pane_id}\trole=#{@safeyolo_lab_role}\ttitle=#{pane_title}\tdead=#{pane_dead}\tpid=#{pane_pid}\tcmd=#{pane_current_command}\thistory=#{history_size}/#{history_limit}' \
    > "$stage_dir/tmux-panes.txt"
else
  printf 'tmux server unavailable\n' > "$stage_dir/tmux-panes.txt"
fi

ps -eo pid=,ppid=,stat=,etimes=,comm= > "$stage_dir/processes.txt"

if [ -r /app/agent_token ] && command -v curl >/dev/null 2>&1; then
  health_headers="$stage_dir/.safeyolo-health-headers.tmp"
  health_rc=0
  {
    printf 'scope=outer/controller Agent API\n'
    printf 'endpoint=http://_safeyolo.proxy.internal/health\n'
    (
      agent_token=$(cat /app/agent_token) || exit
      printf 'Authorization: Bearer %s\n' "$agent_token" |
        curl -sS \
          --connect-timeout 3 \
          --max-time 10 \
          --header @- \
          --dump-header "$health_headers" \
          --output "$stage_dir/safeyolo-health.json" \
          --write-out 'http_status=%{http_code}\ntime_total_seconds=%{time_total}\n' \
          http://_safeyolo.proxy.internal/health
    )
  } > "$stage_dir/safeyolo-health-meta.txt" 2> "$stage_dir/safeyolo-health.stderr" || health_rc=$?

  if [ -s "$health_headers" ]; then
    awk '
      {
        line=$0
        sub(/\r$/, "", line)
        lower=tolower(line)
        if (lower ~ /^(x-blocked-by|retry-after|content-type):/) print line
      }
    ' "$health_headers" > "$stage_dir/safeyolo-health-selected-headers.txt"
  fi
  rm -f "$health_headers"
  if [ "$health_rc" -ne 0 ]; then
    printf 'health_check_exit=%s\n' "$health_rc" > "$stage_dir/safeyolo-health-failure.txt"
  fi
else
  printf 'agent token or curl unavailable\n' > "$stage_dir/safeyolo-health-unavailable.txt"
fi

printf 'status=complete\nstarted_utc=%s\ncompleted_utc=%s\n' \
  "$started_utc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$stage_dir/snapshot-status.txt"
find "$stage_dir" -type f -exec chmod 600 {} +

(
  cd "$stage_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  else
    while IFS= read -r -d '' source_file; do
      shasum -a 256 "$source_file"
    done < <(find . -type f ! -name SHA256SUMS -print0 | sort -z) > SHA256SUMS
  fi
  chmod 600 SHA256SUMS
)

mv "$stage_dir" "$snapshot_dir"
finalized=1
trap - EXIT
printf '%s\n' "$snapshot_dir"
