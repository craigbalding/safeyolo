#!/usr/bin/env bash
set -uo pipefail

resolved_script=$(readlink -f "${BASH_SOURCE[0]}") || exit 2
socket=
client=
pane=
question_id=
action=${1:-}
[ "$#" -eq 0 ] || shift

usage() {
  printf '%s\n' \
    'Usage:' \
    '  lesson-questions.sh menu [--socket PATH] [--client NAME] --pane PANE_ID' \
    '  lesson-questions.sh list [--socket PATH] --pane PANE_ID' \
    '  lesson-questions.sh submit [--socket PATH] --pane PANE_ID --id ID' >&2
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
    --id)
      [ "$#" -ge 2 ] || usage
      question_id=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

case "$action" in
  menu|list) ;;
  submit)
    [[ $question_id =~ ^[A-Z][A-Z0-9_-]{0,31}$ ]] || usage
    ;;
  *) usage ;;
esac
[ -n "$pane" ] || usage

tmux_cmd=(tmux)
if [ -n "$socket" ]; then
  tmux_cmd+=(-S "$socket")
fi

window=$(
  "${tmux_cmd[@]}" display-message -p -t "$pane" '#{window_id}' \
    2>/dev/null
) || exit 0

notice() {
  local message=$1
  if [ -n "$client" ]; then
    "${tmux_cmd[@]}" display-message -c "$client" "$message" \
      2>/dev/null || true
  else
    "${tmux_cmd[@]}" display-message -t "$pane" "$message" \
      2>/dev/null || true
  fi
}

registry=$(
  "${tmux_cmd[@]}" display-message -p -t "$pane" \
    '#{@safeyolo_lab_questions_file}' 2>/dev/null
) || registry=
if [ -z "$registry" ] || [ ! -r "$registry" ]; then
  notice 'This page has no registered questions.'
  exit 0
fi

declare -A questions=()
while IFS=$'\t' read -r registry_id question extra || \
    [ -n "${registry_id:-}${question:-}${extra:-}" ]; do
  [ -n "${registry_id:-}" ] || continue
  [[ $registry_id = \#* ]] && continue
  if ! [[ $registry_id =~ ^[A-Z][A-Z0-9_-]{0,31}$ ]] || \
      [ -z "${question:-}" ] || [ -n "${extra:-}" ] || \
      [ -n "${questions[$registry_id]+present}" ]; then
    notice 'The lesson question registry is invalid.'
    exit 0
  fi
  questions[$registry_id]=$question
done < "$registry"

page_question_ids() {
  "${tmux_cmd[@]}" capture-pane -p -t "$pane" | awk '
    {
      line=$0
      while (match(line, /\[[A-Z][A-Z0-9_-]{0,31}\]/)) {
        id=substr(line, RSTART + 1, RLENGTH - 2)
        if (!seen[id]++) print id
        line=substr(line, RSTART + RLENGTH)
      }
    }
  '
}

list_page_questions() {
  local id
  while IFS= read -r id; do
    [ -n "${questions[$id]+present}" ] || continue
    printf '%s\t%s\n' "$id" "${questions[$id]}"
  done < <(page_question_ids)
}

if [ "$action" = list ]; then
  list_page_questions
  exit 0
fi

if [ "$action" = menu ]; then
  mapfile -t entries < <(list_page_questions)
  if [ "${#entries[@]}" -eq 0 ]; then
    notice 'This page has no registered questions.'
    exit 0
  fi

  menu=(display-menu -t "$pane" -T 'Questions from this page' -x C -y C)
  if [ -n "$client" ]; then
    menu+=( -c "$client" )
  fi
  index=0
  for entry in "${entries[@]}"; do
    [ "$index" -lt 9 ] || break
    IFS=$'\t' read -r id question <<< "$entry"
    index=$((index + 1))
    menu_text=${question//#/##}
    submit_shell=$(printf '%q submit --pane %q --id %q' \
      "$resolved_script" "$pane" "$id")
    menu+=("$menu_text" "$index" "run-shell -b '$submit_shell'")
  done
  "${tmux_cmd[@]}" "${menu[@]}" 2>/dev/null || \
    notice 'The question menu could not open.'
  exit 0
fi

if [ -z "${questions[$question_id]+present}" ]; then
  notice 'The selected question is not registered.'
  exit 0
fi

controller=
while IFS=$'\t' read -r listed_pane role dead; do
  if [ "$role" = controller ] && [ "$dead" = 0 ]; then
    controller=$listed_pane
    break
  fi
done < <(
  "${tmux_cmd[@]}" list-panes -t "$window" \
    -F $'#{pane_id}\t#{@safeyolo_lab_role}\t#{pane_dead}'
)
if [ -z "$controller" ]; then
  notice 'The controller pane is not available.'
  exit 0
fi

selected_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
"${tmux_cmd[@]}" set-option -w -t "$window" \
  @safeyolo_lab_last_question_id "$question_id"
"${tmux_cmd[@]}" set-option -w -t "$window" \
  @safeyolo_lab_last_question_utc "$selected_utc"

run_token=$(
  "${tmux_cmd[@]}" display-message -p -t "$controller" \
    '#{@safeyolo_lab_controller_run}' 2>/dev/null
) || run_token=
run_pid=${run_token%%:*}
run_ticks=${run_token#*:}
controller_accepting=0
if [[ $run_token == *:* ]] && [[ $run_pid =~ ^[0-9]+$ ]] && \
    [[ $run_ticks =~ ^[0-9]+$ ]] && \
    [ -r "/proc/$run_pid/stat" ]; then
  current_ticks=$(awk '{print $22}' "/proc/$run_pid/stat" 2>/dev/null || true)
  if [ "$current_ticks" = "$run_ticks" ]; then
    controller_accepting=1
  fi
fi

"${tmux_cmd[@]}" set-option -w -t "$window" \
  @safeyolo_lab_focus_target controller
"${tmux_cmd[@]}" select-pane -t "$controller"

if [ "$controller_accepting" -ne 1 ]; then
  "${tmux_cmd[@]}" set-option -w -t "$window" \
    @safeyolo_lab_pending_question_id "$question_id"
  notice 'Question saved. The controller harness is not accepting input.'
  exit 0
fi

message="Learner selected [$question_id] from the lesson: ${questions[$question_id]}"
buffer_name="safeyolo-question-${BASHPID}"
if ! printf '%s' "$message" | \
    "${tmux_cmd[@]}" load-buffer -b "$buffer_name" -; then
  notice 'The selected question could not be prepared.'
  exit 0
fi
if ! "${tmux_cmd[@]}" paste-buffer -b "$buffer_name" -d -t "$controller"; then
  notice 'The selected question could not be submitted.'
  exit 0
fi
"${tmux_cmd[@]}" set-option -w -t "$window" \
  @safeyolo_lab_pending_question_id ''
"${tmux_cmd[@]}" send-keys -t "$controller" Enter
