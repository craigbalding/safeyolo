#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

usage() {
  printf '%s\n' \
    'Usage:' \
    '  lesson-helper.sh new OUTPUT TITLE [SUBTITLE]' \
    '  lesson-helper.sh install-renderer' \
    '  lesson-helper.sh run LESSON.md' \
    '' \
    'Create a small Markdown lesson or run it in the current interactive pane.'
}

one_line() {
  local value=$1
  value=${value//$'\n'/ }
  value=${value//$'\r'/ }
  printf '%s' "$value"
}

yaml_value() {
  local value
  value=$(one_line "$1")
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '%s' "$value"
}

new_lesson() {
  [ "$#" -ge 2 ] && [ "$#" -le 3 ] || {
    usage >&2
    exit 2
  }

  local output=$1
  local title=$2
  local subtitle=${3:-A guided terminal lesson}
  local output_dir
  local questions_file="${output}.questions.tsv"
  local sources_file="${output}.sources.tsv"
  output_dir=$(dirname -- "$output")

  [ ! -e "$output" ] && [ ! -e "$questions_file" ] && \
      [ ! -e "$sources_file" ] || {
    printf 'Lesson or registry already exists: %s\n' "$output" >&2
    exit 1
  }
  mkdir -p -- "$output_dir"

  local yaml_title yaml_subtitle heading
  yaml_title=$(yaml_value "$title")
  yaml_subtitle=$(yaml_value "$subtitle")
  heading=$(one_line "$title")

  {
    printf '%s\n' '---'
    printf 'title: "%s"\n' "$yaml_title"
    printf 'sub_title: "%s"\n' "$yaml_subtitle"
    printf '%s\n' 'author: "SafeYolo lab"' '---' ''
    printf '# %s\n\n' "$heading"
    printf '%s\n' \
      'State why this question matters to the learner.' \
      '' \
      '> The controller drives this lesson. Ask questions at any time.' \
      '' \
      '<!-- end_slide -->' \
      '' \
      '# The question' \
      '' \
      'State one plain-language question.' \
      '' \
      '**Questions you might ask**' \
      '' \
      '- `[EVIDENCE]` What evidence would answer this question?' \
      '' \
      'Press `q` to choose a question.' \
      '' \
      '<!-- end_slide -->' \
      '' \
      '# The action' \
      '' \
      'Explain what the command or action will test.' \
      '' \
      '```bash' \
      '# Replace this with a reviewed, bounded command.' \
      '```' \
      '' \
      '<!-- end_slide -->' \
      '' \
      '# Evidence and meaning' \
      '' \
      '**Observed:** Replace this with the real result.' \
      '' \
      '**Meaning:** Explain the result in plain language.' \
      '' \
      '**Limit:** State what the evidence does not prove.' \
      '' \
      '**Questions you might ask**' \
      '' \
      '- `[MEANING]` What does the observed result mean?' \
      '' \
      'Press `q` to choose a question.' \
      '' \
      '<!-- end_slide -->' \
      '' \
      '# Where to go next' \
      '' \
      'Offer one useful next question. The learner can also choose another path.'
  } > "$output"

  printf '%s\n' \
    $'EVIDENCE\tWhat evidence would answer this question?' \
    $'MEANING\tWhat does the observed result mean?' \
    > "$questions_file"

  printf 'Created lesson: %s\n' "$output"
  printf 'Created question registry: %s\n' "$questions_file"
}

run_lesson() {
  [ "$#" -eq 1 ] || {
    usage >&2
    exit 2
  }

  local lesson=$1
  local questions_file="${lesson}.questions.tsv"
  local sources_file="${lesson}.sources.tsv"
  [ -r "$lesson" ] || {
    printf 'Lesson is not readable: %s\n' "$lesson" >&2
    exit 1
  }
  command -v presenterm >/dev/null 2>&1 || {
    printf 'Presenterm is not installed or is not on PATH.\n' >&2
    printf 'Install the pinned renderer with: %s install-renderer\n' "$0" >&2
    exit 127
  }

  local lesson_dir lesson_name
  lesson_dir=$(cd -- "$(dirname -- "$lesson")" && pwd -P)
  lesson_name=$(basename -- "$lesson")
  local questions_registered=0
  local sources_registered=0
  if [ -n "${TMUX:-}" ] && [ -n "${TMUX_PANE:-}" ] && \
      [ -r "$questions_file" ]; then
    if tmux set-option -p -t "$TMUX_PANE" \
        @safeyolo_lab_questions_file "$questions_file"; then
      questions_registered=1
    fi
  fi
  if [ -n "${TMUX:-}" ] && [ -n "${TMUX_PANE:-}" ] && \
      [ -r "$sources_file" ]; then
    if tmux set-option -p -t "$TMUX_PANE" \
        @safeyolo_lab_sources_file "$sources_file"; then
      sources_registered=1
    fi
  fi
  if (
      cd -- "$lesson_dir"
      presenterm \
        --image-protocol ascii-blocks \
        --enable-snippet-execution \
        --validate-overflows \
        "$lesson_name"
    ); then
    lesson_rc=0
  else
    lesson_rc=$?
  fi
  if [ "$questions_registered" -eq 1 ]; then
    tmux set-option -p -u -t "$TMUX_PANE" \
      @safeyolo_lab_questions_file 2>/dev/null || true
  fi
  if [ "$sources_registered" -eq 1 ]; then
    tmux set-option -p -u -t "$TMUX_PANE" \
      @safeyolo_lab_sources_file 2>/dev/null || true
  fi
  return "$lesson_rc"
}

case ${1:-} in
  new)
    shift
    new_lesson "$@"
    ;;
  install-renderer)
    shift
    [ "$#" -eq 0 ] || {
      usage >&2
      exit 2
    }
    "$script_dir/install-presenterm.sh"
    ;;
  run)
    shift
    run_lesson "$@"
    ;;
  -h|--help|help|'')
    usage
    ;;
  *)
    printf 'Unknown command: %s\n' "$1" >&2
    usage >&2
    exit 2
    ;;
esac
