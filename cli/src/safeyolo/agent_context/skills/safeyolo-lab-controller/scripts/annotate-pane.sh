#!/usr/bin/env bash
set -uo pipefail

socket=
pane=
state=INFO
annotation_id=
note=
evidence=
explanation=
clear=0

usage() {
  cat >&2 <<'EOF'
Usage: annotate-pane.sh [--socket PATH] --pane PANE \
  [--id ID] [--state INFO|WATCH|EXPLAIN|PASS|WARN|FAIL] --text TEXT \
  [--evidence TEXT] [--explain TEXT]
       annotate-pane.sh [--socket PATH] --pane PANE --clear

Attach an evidence marker, border note, and explanation to a lab pane.
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
    --pane)
      [ "$#" -ge 2 ] || usage
      pane=$2
      shift 2
      ;;
    --state)
      [ "$#" -ge 2 ] || usage
      state=${2^^}
      shift 2
      ;;
    --id)
      [ "$#" -ge 2 ] || usage
      annotation_id=${2^^}
      shift 2
      ;;
    --text)
      [ "$#" -ge 2 ] || usage
      note=$2
      shift 2
      ;;
    --evidence)
      [ "$#" -ge 2 ] || usage
      evidence=$2
      shift 2
      ;;
    --explain)
      [ "$#" -ge 2 ] || usage
      explanation=$2
      shift 2
      ;;
    --clear)
      clear=1
      shift
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

read -r pane_session pane_window < <(
  "${tmux_cmd[@]}" display-message -p -t "$pane" \
    '#{session_name} #{window_id}' 2>/dev/null
) || {
    printf 'Unknown tmux pane: %s\n' "$pane" >&2
    exit 2
  }

refresh_clients() {
  local client
  while IFS= read -r client; do
    [ -n "$client" ] || continue
    "${tmux_cmd[@]}" refresh-client -t "$client" 2>/dev/null || true
  done < <(
    "${tmux_cmd[@]}" list-clients -t "$pane_session" \
      -F '#{client_name}' 2>/dev/null || true
  )
}

adapt_ui() {
  local layout_script
  layout_script=$("${tmux_cmd[@]}" show-options -gqv \
    @safeyolo_lab_layout_script 2>/dev/null || true)
  if [ -n "$layout_script" ] && [ -x "$layout_script" ]; then
    if [ -n "$socket" ]; then
      "$layout_script" --socket "$socket" --session "$pane_session"
    else
      "$layout_script" --session "$pane_session"
    fi
  else
    refresh_clients
  fi
}

clear_pane_options() {
  local option
  for option in \
    @safeyolo_lab_state \
    @safeyolo_lab_note \
    @safeyolo_lab_annotation_id \
    @safeyolo_lab_annotation_bg \
    @safeyolo_lab_annotation_evidence \
    @safeyolo_lab_annotation_explanation; do
    "${tmux_cmd[@]}" set-option -p -u -t "$pane" "$option" \
      2>/dev/null || true
  done
}

clear_window_annotation() {
  local option
  for option in \
    @safeyolo_lab_annotation_pane \
    @safeyolo_lab_annotation_id \
    @safeyolo_lab_annotation_state \
    @safeyolo_lab_annotation_bg \
    @safeyolo_lab_annotation_text \
    @safeyolo_lab_annotation_evidence \
    @safeyolo_lab_annotation_explanation; do
    "${tmux_cmd[@]}" set-option -w -u -t "$pane_window" "$option" \
      2>/dev/null || true
  done
}

if [ "$clear" -eq 1 ]; then
  clear_pane_options
  current_annotation_pane=$("${tmux_cmd[@]}" show-options -wqv \
    -t "$pane_window" @safeyolo_lab_annotation_pane 2>/dev/null || true)
  if [ "$current_annotation_pane" = "$pane" ]; then
    clear_window_annotation
  fi
  adapt_ui
  exit 0
fi

case "$state" in
  INFO|WATCH|EXPLAIN|PASS|WARN|FAIL) ;;
  *) usage ;;
esac

[ -n "$note" ] || usage

validate_text() {
  local label=$1
  local value=$2
  local maximum=$3
  [ "${#value}" -le "$maximum" ] || {
    printf '%s exceeds %s characters\n' "$label" "$maximum" >&2
    exit 2
  }
  case "$value" in
    *$'\n'*|*$'\r'*|*'#['*|*'#{'*)
      printf '%s contains unsupported control or format text\n' "$label" >&2
      exit 2
      ;;
  esac
}

validate_text 'Pane annotation' "$note" 200
validate_text 'Evidence fragment' "$evidence" 200
validate_text 'Explanation' "$explanation" 500

if [ -n "$annotation_id" ]; then
  case "$annotation_id" in
    *[!A-Z0-9._-]*|'')
      printf 'Annotation ID must use A-Z, 0-9, dot, dash, or underscore\n' >&2
      exit 2
      ;;
  esac
  [ "${#annotation_id}" -le 12 ] || {
    printf 'Annotation ID exceeds 12 characters\n' >&2
    exit 2
  }
else
  annotation_counter=$("${tmux_cmd[@]}" show-options -wqv \
    -t "$pane_window" @safeyolo_lab_annotation_counter 2>/dev/null || true)
  case "$annotation_counter" in
    ''|*[!0-9]*) annotation_counter=0 ;;
  esac
  annotation_counter=$((annotation_counter + 1))
  annotation_id="A${annotation_counter}"
  "${tmux_cmd[@]}" set-option -w -t "$pane_window" \
    @safeyolo_lab_annotation_counter "$annotation_counter"
fi

case "$state" in
  INFO) annotation_bg=colour24 ;;
  WATCH) annotation_bg=colour31 ;;
  EXPLAIN) annotation_bg=colour61 ;;
  PASS) annotation_bg=colour22 ;;
  WARN) annotation_bg=colour166 ;;
  FAIL) annotation_bg=colour124 ;;
esac

"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_state "$state"
"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_note "$note"
"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_annotation_id "$annotation_id"
"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_annotation_bg "$annotation_bg"
"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_annotation_evidence "$evidence"
"${tmux_cmd[@]}" set-option -p -t "$pane" \
  @safeyolo_lab_annotation_explanation "$explanation"

"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_pane "$pane"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_id "$annotation_id"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_state "$state"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_bg "$annotation_bg"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_text "$note"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_evidence "$evidence"
"${tmux_cmd[@]}" set-option -w -t "$pane_window" \
  @safeyolo_lab_annotation_explanation "$explanation"

adapt_ui
printf '%s\n' "$annotation_id"
