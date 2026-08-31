#!/usr/bin/env bash
set -uo pipefail

socket=
session=lab
report=0

usage() {
  cat >&2 <<'EOF'
Usage: adapt-layout.sh [--socket PATH] [--session NAME] [--report]

Adapt SafeYolo lab windows to their current tmux dimensions.
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
    --session)
      [ "$#" -ge 2 ] || usage
      session=$2
      shift 2
      ;;
    --report)
      report=1
      shift
      ;;
    *)
      usage
      ;;
  esac
done

tmux_cmd=(tmux)
if [ -n "$socket" ]; then
  tmux_cmd+=(-S "$socket")
fi

if ! "${tmux_cmd[@]}" has-session -t "$session" 2>/dev/null; then
  exit 0
fi

refresh_clients() {
  local client
  while IFS= read -r client; do
    [ -n "$client" ] || continue
    "${tmux_cmd[@]}" refresh-client -t "$client" 2>/dev/null || true
  done < <(
    "${tmux_cmd[@]}" list-clients -t "$session" -F '#{client_name}' \
      2>/dev/null || true
  )
}

configure_annotation_rail() {
  local active_window=
  local window active width height pane_count annotation_state desired current

  while IFS=$'\t' read -r window active; do
    if [ "$active" = 1 ]; then
      active_window=$window
      break
    fi
  done < <(
    "${tmux_cmd[@]}" list-windows -t "$session" \
      -F $'#{window_id}\t#{window_active}'
  )
  [ -n "$active_window" ] || return

  read -r width height pane_count < <(
    "${tmux_cmd[@]}" display-message -p -t "$active_window" \
      '#{window_width} #{window_height} #{window_panes}'
  )
  annotation_state=$("${tmux_cmd[@]}" show-options -wqv \
    -t "$active_window" @safeyolo_lab_annotation_state 2>/dev/null || true)

  desired=on
  if [ -n "$annotation_state" ]; then
    if [ "$pane_count" -le 2 ]; then
      if { [ "$width" -ge 120 ] && [ "$height" -ge 24 ]; } || \
          { [ "$width" -ge 90 ] && [ "$height" -ge 38 ]; }; then
        desired=2
      fi
    elif { [ "$width" -ge 150 ] && [ "$height" -ge 30 ]; } || \
        { [ "$width" -ge 90 ] && [ "$height" -ge 52 ]; }; then
      desired=2
    fi
  fi

  current=$("${tmux_cmd[@]}" show-options -qv -t "$session" status \
    2>/dev/null || true)
  if [ "$current" != "$desired" ]; then
    "${tmux_cmd[@]}" set-option -t "$session" status "$desired"
  fi
  if [ "$report" -eq 1 ]; then
    printf 'session=%s annotation_status_rows=%s\n' "$session" \
      "$desired"
  fi
}

configure_annotation_rail

mapfile -t windows < <(
  "${tmux_cmd[@]}" list-windows -t "$session" -F '#{window_id}'
)

for window in "${windows[@]}"; do
  warning=none
  auto_layout=$("${tmux_cmd[@]}" show-options -w -qv \
    -t "$window" @safeyolo_lab_auto_layout 2>/dev/null || true)
  [ "$auto_layout" != off ] || continue

  read -r width height pane_count zoomed < <(
    "${tmux_cmd[@]}" display-message -p -t "$window" \
      '#{window_width} #{window_height} #{window_panes} #{window_zoomed_flag}'
  )

  controller=
  lesson=
  while IFS=$'\t' read -r pane role; do
    if [ "$role" = controller ]; then
      controller=$pane
    elif [ "$role" = lesson ] && [ -z "$lesson" ]; then
      lesson=$pane
    fi
  done < <(
    "${tmux_cmd[@]}" list-panes -t "$window" \
      -F $'#{pane_id}\t#{@safeyolo_lab_role}'
  )
  [ -n "$controller" ] || continue
  "${tmux_cmd[@]}" set-option -w -t "$window" \
    @safeyolo_lab_lesson_pane "$lesson"

  focus_target=$("${tmux_cmd[@]}" show-options -w -qv \
    -t "$window" @safeyolo_lab_focus_target 2>/dev/null || true)
  if [ -z "$focus_target" ] || [ "$focus_target" = controller ]; then
    focus_target=$controller
  elif ! "${tmux_cmd[@]}" display-message -p -t "$focus_target" \
      '#{pane_id}' >/dev/null 2>&1; then
    focus_target=$controller
  fi

  auto_zoomed=$("${tmux_cmd[@]}" show-options -w -qv \
    -t "$window" @safeyolo_lab_auto_zoomed 2>/dev/null || true)
  if [ "$zoomed" = 1 ] && [ "$auto_zoomed" != 1 ]; then
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_layout manual-zoom
    if [ "$report" -eq 1 ]; then
      printf 'window=%s size=%sx%s panes=%s layout=manual-zoom focus=unchanged\n' \
        "$window" "$width" "$height" "$pane_count"
    fi
    refresh_clients
    continue
  fi

  if [ "$pane_count" -eq 1 ]; then
    if [ "$zoomed" = 1 ] && [ "$auto_zoomed" = 1 ]; then
      "${tmux_cmd[@]}" resize-pane -Z -t "$controller"
    fi
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_auto_zoomed 0
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_size_warning ''
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_layout single
    "${tmux_cmd[@]}" select-pane -t "$focus_target"
    [ "$report" -eq 0 ] || printf \
      'window=%s size=%sx%s panes=1 layout=single focus=%s\n' \
      "$window" "$width" "$height" "$focus_target"
    refresh_clients
    continue
  fi

  layout=
  if [ "$pane_count" -eq 2 ] && [ "$width" -ge 120 ] && \
      [ "$height" -ge 20 ]; then
    layout=side-by-side
  elif [ "$pane_count" -eq 2 ] && [ "$width" -ge 80 ] && \
      [ "$height" -ge 34 ]; then
    layout=stacked
  elif [ "$pane_count" -ge 3 ] && [ "$width" -ge 150 ] && \
      [ "$height" -ge 28 ]; then
    layout=main-left
  elif [ "$pane_count" -ge 3 ] && [ "$width" -ge 90 ] && \
      [ "$height" -ge 50 ]; then
    layout=main-top
  else
    layout=focused-zoom
  fi

  if [ "$layout" = focused-zoom ]; then
    if [ "$zoomed" != 1 ]; then
      "${tmux_cmd[@]}" select-pane -t "$focus_target"
      "${tmux_cmd[@]}" resize-pane -Z -t "$focus_target"
    fi
    warning="Screen ${width}x${height} is too small for ${pane_count} lab panes; the focus pane is zoomed"
    if [ -n "$lesson" ]; then
      questions_file=$("${tmux_cmd[@]}" display-message -p -t "$lesson" \
        '#{@safeyolo_lab_questions_file}' 2>/dev/null || true)
      if [ -n "$questions_file" ]; then
        warning+=" | q: questions"
      fi
      sources_file=$("${tmux_cmd[@]}" display-message -p -t "$lesson" \
        '#{@safeyolo_lab_sources_file}' 2>/dev/null || true)
      if [ -n "$sources_file" ]; then
        warning+=" | o: source"
      fi
      warning+=" | F12: controller/lesson"
    fi
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_auto_zoomed 1
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_size_warning "$warning"
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_layout "$layout"
    "${tmux_cmd[@]}" select-pane -t "$focus_target"
  else
    if [ "$zoomed" = 1 ] && [ "$auto_zoomed" = 1 ]; then
      "${tmux_cmd[@]}" resize-pane -Z -t "$controller"
    fi
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_auto_zoomed 0
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_size_warning ''

    "${tmux_cmd[@]}" select-pane -t "$controller"
    case "$layout" in
      side-by-side)
        "${tmux_cmd[@]}" select-layout -t "$controller" even-horizontal
        ;;
      stacked)
        "${tmux_cmd[@]}" select-layout -t "$controller" even-vertical
        ;;
      main-left)
        main_width=$((width * 56 / 100))
        "${tmux_cmd[@]}" set-option -w -t "$window" \
          main-pane-width "$main_width"
        "${tmux_cmd[@]}" select-layout -t "$controller" main-vertical
        ;;
      main-top)
        main_height=$((height * 56 / 100))
        "${tmux_cmd[@]}" set-option -w -t "$window" \
          main-pane-height "$main_height"
        "${tmux_cmd[@]}" select-layout -t "$controller" main-horizontal
        ;;
    esac
    "${tmux_cmd[@]}" set-option -w -t "$window" \
      @safeyolo_lab_layout "$layout"
    "${tmux_cmd[@]}" select-pane -t "$focus_target"
  fi

  if [ "$report" -eq 1 ]; then
    printf 'window=%s size=%sx%s panes=%s layout=%s focus=%s warning=%s\n' \
      "$window" "$width" "$height" "$pane_count" "$layout" \
      "$focus_target" "$warning"
  fi
  refresh_clients
done
