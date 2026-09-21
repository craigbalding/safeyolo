#!/usr/bin/env bash
# Show the three supervised backlog-factory agent streams in tmux.
set -euo pipefail

repo=${SAFEYOLO_FACTORY_REPO:-/home/agent/safeyolo-rust-620}
window_name=${SAFEYOLO_FACTORY_WATCH_WINDOW:-factory-watch}
viewer="$repo/contrib/watch-agent-room.py"
nested_root=${SAFEYOLO_FACTORY_INSTANCE_ROOT:-/var/lib/nested-safeyolo-lab}

export SAFEYOLO_CONFIG_DIR=${SAFEYOLO_CONFIG_DIR:-$nested_root/state}
export SAFEYOLO_LOGS_DIR=${SAFEYOLO_LOGS_DIR:-$nested_root/logs}
export SAFEYOLO_COORD_DATA_DIR=${SAFEYOLO_COORD_DATA_DIR:-$nested_root/state/coord}
export SAFEYOLO_UPSTREAM_PROXY=${SAFEYOLO_UPSTREAM_PROXY:-http://127.0.0.1:8080}
export SAFEYOLO_RUNSC_PLATFORM=${SAFEYOLO_RUNSC_PLATFORM:-systrap}

die() { printf 'watch-backlog-factory: %s\n' "$*" >&2; exit 2; }

[[ -n ${TMUX:-} ]] || die "run this command inside the operator's tmux session"
[[ -f $viewer ]] || die "viewer not found: $viewer"
command -v uv >/dev/null 2>&1 || die "uv is required"

session=$(tmux display-message -p '#S')
target="$session:$window_name"

watch_command='room=$1; repo=$2; label=$3
printf "Watching %s (%s)\n" "$label" "$room"
while :; do
  if uv run --project "$repo" --no-sync python "$repo/contrib/watch-agent-room.py" "$room" --history 1 --once >/dev/null 2>&1; then
    uv run --project "$repo" --no-sync python "$repo/contrib/watch-agent-room.py" "$room" --history 30 --max-text 600 --show-unknown
  else
    printf "[%s] waiting for access to existing room %s\n" "$(date -u +%H:%M:%SZ)" "$room"
    sleep 5
  fi
done'

start_pane() {
  local pane=$1 room=$2 label=$3
  tmux set-option -p -t "$pane" pane-border-status top
  tmux select-pane -t "$pane" -T "$label"
  tmux respawn-pane -k -t "$pane" -c "$repo" \
    bash -lc "$watch_command" watch-factory "$room" "$repo" "$label"
}

case ${1:-start} in
  start)
    if tmux has-session -t "$target" 2>/dev/null; then
      tmux select-window -t "$target"
      exit 0
    fi
    window_id=$(tmux new-window -d -P -F '#{window_id}' -n "$window_name" -c "$repo")
    relay_pane=$(tmux list-panes -t "$window_id" -F '#{pane_id}' | head -1)
    forge_pane=$(tmux split-window -d -h -P -F '#{pane_id}' -t "$relay_pane" -c "$repo")
    lens_pane=$(tmux split-window -d -h -P -F '#{pane_id}' -t "$forge_pane" -c "$repo")
    start_pane "$relay_pane" relay-agent Relay
    start_pane "$forge_pane" forge-agent Forge
    start_pane "$lens_pane" lens-agent Lens
    tmux select-layout -t "$window_id" even-horizontal >/dev/null
    tmux select-window -t "$window_id"
    ;;
  stop)
    tmux kill-window -t "$target" 2>/dev/null || true
    ;;
  status)
    tmux list-panes -t "$target" -F '#{pane_title} pane=#{pane_id} dead=#{pane_dead} command=#{pane_current_command}'
    ;;
  *)
    die "usage: $0 [start|stop|status]"
    ;;
esac
