#!/usr/bin/env bash
set -uo pipefail

socket=
client=
pane=

usage() {
  printf '%s\n' \
    'Usage: switch-surface.sh [--socket PATH] [--client NAME] --pane PANE_ID' \
    '' \
    'Switch between the controller and lesson panes in one lab window.' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --socket)
      [ "$#" -ge 2 ] || usage
      socket=$2
      shift 2
      ;;
    --client)
      [ "$#" -ge 2 ] || usage
      client=$2
      shift 2
      ;;
    --pane)
      [ "$#" -ge 2 ] || usage
      pane=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$pane" ] || usage

tmux_cmd=(tmux)
if [ -n "$socket" ]; then
  tmux_cmd+=(-S "$socket")
fi

window=$(
  "${tmux_cmd[@]}" display-message -p -t "$pane" '#{window_id}' \
    2>/dev/null
) || exit 0

controller=
lesson=
current_role=
while IFS=$'\t' read -r listed_pane role dead; do
  [ "$dead" = 0 ] || continue
  if [ "$listed_pane" = "$pane" ]; then
    current_role=$role
  fi
  case "$role" in
    controller)
      [ -n "$controller" ] || controller=$listed_pane
      ;;
    lesson)
      [ -n "$lesson" ] || lesson=$listed_pane
      ;;
  esac
done < <(
  "${tmux_cmd[@]}" list-panes -t "$window" \
    -F $'#{pane_id}\t#{@safeyolo_lab_role}\t#{pane_dead}'
)

show_notice() {
  local message=$1
  if [ -n "$client" ]; then
    "${tmux_cmd[@]}" display-message -c "$client" "$message" \
      2>/dev/null || true
  else
    "${tmux_cmd[@]}" display-message -t "$pane" "$message" \
      2>/dev/null || true
  fi
}

if [ -z "$controller" ]; then
  show_notice 'The controller pane is not available.'
  exit 0
fi
if [ -z "$lesson" ]; then
  show_notice 'No lesson pane is open.'
  exit 0
fi

if [ "$current_role" = lesson ]; then
  target=$controller
  focus_target=controller
else
  target=$lesson
  focus_target=$lesson
fi

"${tmux_cmd[@]}" set-option -w -t "$window" \
  @safeyolo_lab_focus_target "$focus_target" || exit 0
"${tmux_cmd[@]}" select-pane -t "$target" || exit 0

if [ -n "$client" ]; then
  "${tmux_cmd[@]}" refresh-client -t "$client" 2>/dev/null || true
fi
