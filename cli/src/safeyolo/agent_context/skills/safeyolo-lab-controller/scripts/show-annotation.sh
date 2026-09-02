#!/usr/bin/env bash
set -uo pipefail

socket=
client=
pane=
action=

usage() {
  cat >&2 <<'EOF'
Usage: show-annotation.sh [--socket PATH] [--client CLIENT] [--pane PANE] \
  --toggle-highlight|--highlight|--clear-highlight|--popup
       show-annotation.sh [--socket PATH] --pane PANE --render

Highlight a pinned evidence fragment or show its lab explanation.
EOF
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
    --toggle-highlight|--highlight|--clear-highlight|--popup|--render)
      [ -z "$action" ] || usage
      action=${1#--}
      shift
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$action" ] || usage

tmux_cmd=(tmux)
if [ -n "$socket" ]; then
  tmux_cmd+=(-S "$socket")
fi

if [ -z "$pane" ]; then
  if [ -n "$client" ]; then
    pane=$("${tmux_cmd[@]}" display-message -p -c "$client" \
      '#{@safeyolo_lab_annotation_pane}' 2>/dev/null || true)
  else
    pane=$("${tmux_cmd[@]}" display-message -p \
      '#{@safeyolo_lab_annotation_pane}' 2>/dev/null || true)
  fi
fi

if [ -z "$pane" ] || ! "${tmux_cmd[@]}" display-message -p -t "$pane" \
    '#{pane_id}' >/dev/null 2>&1; then
  if [ -n "$client" ]; then
    "${tmux_cmd[@]}" display-message -c "$client" -d 1500 \
      'No active lab annotation' 2>/dev/null || true
  else
    printf 'No active lab annotation\n' >&2
  fi
  exit 2
fi

read_option() {
  "${tmux_cmd[@]}" display-message -p -t "$pane" "#{${1}}"
}

pane_session=$("${tmux_cmd[@]}" display-message -p -t "$pane" \
  '#{session_name}')
pane_window=$("${tmux_cmd[@]}" display-message -p -t "$pane" \
  '#{window_id}')

notify() {
  local message=$1
  if [ -n "$client" ]; then
    "${tmux_cmd[@]}" display-message -c "$client" -d 1500 \
      "$message" 2>/dev/null || true
  else
    printf '%s\n' "$message" >&2
  fi
}

refresh_clients() {
  local target_client
  while IFS= read -r target_client; do
    [ -n "$target_client" ] || continue
    "${tmux_cmd[@]}" refresh-client -t "$target_client" \
      2>/dev/null || true
  done < <(
    "${tmux_cmd[@]}" list-clients -t "$pane_session" \
      -F '#{client_name}' 2>/dev/null || true
  )
}

clear_highlight() {
  local owned in_mode
  owned=$(read_option '@safeyolo_lab_highlight_owned')
  if [ "$owned" != 1 ]; then
    notify 'The lab does not own an evidence highlight in this pane'
    return 0
  fi
  in_mode=$("${tmux_cmd[@]}" display-message -p -t "$pane" \
    '#{pane_in_mode}')
  if [ "$in_mode" = 1 ]; then
    "${tmux_cmd[@]}" send-keys -t "$pane" -X cancel \
      >/dev/null 2>&1 || true
  fi
  "${tmux_cmd[@]}" set-option -p -u -t "$pane" \
    @safeyolo_lab_highlight_owned 2>/dev/null || true
  "${tmux_cmd[@]}" set-option -w -u -t "$pane_window" \
    @safeyolo_lab_highlight_active 2>/dev/null || true
  refresh_clients
}

highlight() {
  local evidence in_mode regex character index
  evidence=$(read_option '@safeyolo_lab_annotation_evidence')
  if [ -z "$evidence" ]; then
    notify 'This annotation has no pinned evidence fragment'
    return 2
  fi
  in_mode=$("${tmux_cmd[@]}" display-message -p -t "$pane" \
    '#{pane_in_mode}')
  if [ "$in_mode" = 1 ]; then
    notify 'The evidence pane is already in a tmux mode'
    return 2
  fi
  if ! "${tmux_cmd[@]}" capture-pane -p -J -t "$pane" -S - | \
      grep -F -- "$evidence" >/dev/null; then
    notify 'The pinned evidence fragment is not in retained pane output'
    return 2
  fi

  regex=
  for ((index = 0; index < ${#evidence}; index++)); do
    character=${evidence:index:1}
    case "$character" in
      [\\.\^\$\*\+\?\(\)\[\]\{\}\|]) regex+="\\$character" ;;
      *) regex+="$character" ;;
    esac
  done

  "${tmux_cmd[@]}" copy-mode -t "$pane" || return
  if ! "${tmux_cmd[@]}" send-keys -t "$pane" -X \
      search-backward "$regex"; then
    "${tmux_cmd[@]}" send-keys -t "$pane" -X cancel \
      >/dev/null 2>&1 || true
    notify 'Tmux could not highlight the pinned evidence fragment'
    return 2
  fi
  "${tmux_cmd[@]}" set-option -p -t "$pane" \
    @safeyolo_lab_highlight_owned 1
  "${tmux_cmd[@]}" set-option -w -t "$pane_window" \
    @safeyolo_lab_highlight_active 1
  refresh_clients
}

render() {
  local annotation_id state note evidence explanation role width wrap colour
  annotation_id=$(read_option '@safeyolo_lab_annotation_id')
  state=$(read_option '@safeyolo_lab_state')
  note=$(read_option '@safeyolo_lab_note')
  evidence=$(read_option '@safeyolo_lab_annotation_evidence')
  explanation=$(read_option '@safeyolo_lab_annotation_explanation')
  role=$(read_option '@safeyolo_lab_role')

  case "$state" in
    INFO) colour=36 ;;
    WATCH) colour=96 ;;
    EXPLAIN) colour=35 ;;
    PASS) colour=32 ;;
    WARN) colour=33 ;;
    FAIL) colour=31 ;;
    *) colour=37 ;;
  esac

  width=$(tput cols 2>/dev/null || printf '80')
  case "$width" in
    ''|*[!0-9]*) width=80 ;;
  esac
  wrap=$((width - 6))
  [ "$wrap" -ge 36 ] || wrap=36
  [ "$wrap" -le 100 ] || wrap=100

  printf '\033[2J\033[H'
  printf '\033[1;%smLAB EXPLANATION\033[0m\n\n' "$colour"
  printf '\033[1;%sm%s  %s\033[0m\n' "$colour" \
    "${annotation_id:-ANNOTATION}" "${state:-INFO}"
  printf 'Source:   pane %s  role %s\n' "$pane" "${role:-unlabelled}"
  printf 'Finding:  %s\n' "$note" | fold -s -w "$wrap"
  if [ -n "$evidence" ]; then
    printf '\nEvidence fragment:\n'
    printf '  "%s"\n' "$evidence" | fold -s -w "$wrap"
  fi
  if [ -n "$explanation" ]; then
    printf '\nWhy it matters:\n'
    printf '  %s\n' "$explanation" | fold -s -w "$wrap"
  fi
  printf '\nThe raw pane output is unchanged.\n'
  printf 'Use C-a e outside this popup to mark or clear the evidence.\n'
  printf '\nPress any key to close.'
  IFS= read -r -n 1 _ || true
}

popup() {
  local annotation_id target_client script_path popup_command
  annotation_id=$(read_option '@safeyolo_lab_annotation_id')
  target_client=$client
  if [ -z "$target_client" ]; then
    target_client=$("${tmux_cmd[@]}" list-clients -t "$pane_session" \
      -F '#{client_name}' 2>/dev/null | sed -n '1p')
  fi
  [ -n "$target_client" ] || {
    printf 'No attached tmux client can display the explanation\n' >&2
    return 2
  }
  script_path=$(readlink -f "${BASH_SOURCE[0]}") || return
  if [ -n "$socket" ]; then
    printf -v popup_command '%q --socket %q --pane %q --render' \
      "$script_path" "$socket" "$pane"
  else
    printf -v popup_command '%q --pane %q --render' \
      "$script_path" "$pane"
  fi
  "${tmux_cmd[@]}" display-popup -c "$target_client" -t "$pane" \
    -E -w '80%' -h '60%' -T "Lab explanation ${annotation_id:-annotation}" \
    "$popup_command"
}

case "$action" in
  toggle-highlight)
    if [ "$(read_option '@safeyolo_lab_highlight_owned')" = 1 ]; then
      clear_highlight
    else
      highlight
    fi
    ;;
  highlight) highlight ;;
  clear-highlight) clear_highlight ;;
  popup) popup ;;
  render) render ;;
esac
