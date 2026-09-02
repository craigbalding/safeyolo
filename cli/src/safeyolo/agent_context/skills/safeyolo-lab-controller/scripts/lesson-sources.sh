#!/usr/bin/env bash
set -uo pipefail

resolved_script=$(readlink -f "${BASH_SOURCE[0]}") || exit 2
socket=
client=
pane=
source_id=
action=${1:-}
[ "$#" -eq 0 ] || shift

usage() {
  printf '%s\n' \
    'Usage:' \
    '  lesson-sources.sh menu [--socket PATH] [--client NAME] --pane PANE_ID' \
    '  lesson-sources.sh list [--socket PATH] --pane PANE_ID' \
    '  lesson-sources.sh open [--socket PATH] [--client NAME] --pane PANE_ID --id ID' \
    '  lesson-sources.sh render [--socket PATH] --pane PANE_ID --id ID' >&2
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
      source_id=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

case "$action" in
  menu|list) ;;
  open|render)
    [[ $source_id =~ ^[A-Z][A-Z0-9_-]{0,31}$ ]] || usage
    ;;
  *) usage ;;
esac
[ -n "$pane" ] || usage

tmux_cmd=(tmux)
if [ -n "$socket" ]; then
  tmux_cmd+=(-S "$socket")
fi

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
    '#{@safeyolo_lab_sources_file}' 2>/dev/null
) || registry=
if [ -z "$registry" ] || [ ! -r "$registry" ]; then
  notice 'This page has no registered source files.'
  exit 0
fi

declare -A labels=()
declare -A paths=()
declare -A starts=()
declare -A ends=()
while IFS=$'\t' read -r registry_id label path start end extra || \
    [ -n "${registry_id:-}${label:-}${path:-}${start:-}${end:-}${extra:-}" ]; do
  [ -n "${registry_id:-}" ] || continue
  [[ $registry_id = \#* ]] && continue
  if ! [[ $registry_id =~ ^[A-Z][A-Z0-9_-]{0,31}$ ]] || \
      [ -z "${label:-}" ] || ! [[ ${path:-} = /* ]] || \
      ! [[ ${start:-} =~ ^[1-9][0-9]*$ ]] || \
      ! [[ ${end:-} =~ ^[1-9][0-9]*$ ]] || \
      [ "$end" -lt "$start" ] || [ -n "${extra:-}" ] || \
      [ -n "${labels[$registry_id]+present}" ]; then
    notice 'The lesson source registry is invalid.'
    exit 0
  fi
  labels[$registry_id]=$label
  paths[$registry_id]=$path
  starts[$registry_id]=$start
  ends[$registry_id]=$end
done < "$registry"

page_source_ids() {
  "${tmux_cmd[@]}" capture-pane -p -t "$pane" | awk '
    {
      line=$0
      while (match(line, /\[SRC_[A-Z0-9_-]{1,27}\]/)) {
        id=substr(line, RSTART + 1, RLENGTH - 2)
        if (!seen[id]++) print id
        line=substr(line, RSTART + RLENGTH)
      }
    }
  '
}

list_page_sources() {
  local id
  while IFS= read -r id; do
    [ -n "${labels[$id]+present}" ] || continue
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$id" "${labels[$id]}" "${paths[$id]}" \
      "${starts[$id]}" "${ends[$id]}"
  done < <(page_source_ids)
}

render_source() {
  local id=$1
  if [ -z "${labels[$id]+present}" ]; then
    notice 'The selected source file is not registered.'
    exit 0
  fi
  local path=${paths[$id]}
  local start=${starts[$id]}
  local end=${ends[$id]}
  if [ ! -f "$path" ] || [ ! -r "$path" ]; then
    notice 'The selected source file is not readable.'
    exit 0
  fi

  if [ -t 0 ] && [ -t 1 ] && command -v less >/dev/null 2>&1; then
    LESSSECURE=1 LESS='-N -R -X' exec less -j 4 "+${start}g" -- "$path"
  fi

  awk -v first="$start" -v last="$end" '
    NR >= first && NR <= last { printf "%6d  %s\n", NR, $0 }
    NR > last { exit }
  ' "$path"
}

open_source() {
  local id=$1
  if [ -z "${labels[$id]+present}" ]; then
    notice 'The selected source file is not registered.'
    exit 0
  fi
  if [ ! -f "${paths[$id]}" ] || [ ! -r "${paths[$id]}" ]; then
    notice 'The selected source file is not readable.'
    exit 0
  fi

  local -a render_command=("$resolved_script" render)
  if [ -n "$socket" ]; then
    render_command+=(--socket "$socket")
  fi
  render_command+=(--pane "$pane" --id "$id")
  local popup_command title
  printf -v popup_command '%q ' "${render_command[@]}"
  title="Source: ${labels[$id]} | q: close"
  title=${title//#/##}

  local -a popup=(display-popup -t "$pane" -E -w '92%' -h '88%' -T "$title")
  if [ -n "$client" ]; then
    popup+=( -c "$client" )
  fi
  popup+=("$popup_command")
  "${tmux_cmd[@]}" "${popup[@]}" 2>/dev/null || \
    notice 'The source viewer could not open.'
}

case "$action" in
  list)
    list_page_sources
    ;;
  render)
    render_source "$source_id"
    ;;
  open)
    open_source "$source_id"
    ;;
  menu)
    mapfile -t entries < <(list_page_sources)
    if [ "${#entries[@]}" -eq 0 ]; then
      notice 'This page has no registered source files.'
      exit 0
    fi
    if [ "${#entries[@]}" -eq 1 ]; then
      IFS=$'\t' read -r id _ <<< "${entries[0]}"
      open_source "$id"
      exit 0
    fi

    menu=(display-menu -t "$pane" -T 'Source files from this page' -x C -y C)
    if [ -n "$client" ]; then
      menu+=( -c "$client" )
    fi
    index=0
    for entry in "${entries[@]}"; do
      [ "$index" -lt 9 ] || break
      IFS=$'\t' read -r id label path start _ <<< "$entry"
      index=$((index + 1))
      menu_text="$label | ${path##*/}:$start"
      menu_text=${menu_text//#/##}
      open_args=("$resolved_script" open)
      if [ -n "$socket" ]; then
        open_args+=(--socket "$socket")
      fi
      if [ -n "$client" ]; then
        open_args+=(--client "$client")
      fi
      open_args+=(--pane "$pane" --id "$id")
      printf -v open_shell '%q ' "${open_args[@]}"
      menu+=("$menu_text" "$index" "run-shell -b '$open_shell'")
    done
    "${tmux_cmd[@]}" "${menu[@]}" 2>/dev/null || \
      notice 'The source menu could not open.'
    ;;
esac
