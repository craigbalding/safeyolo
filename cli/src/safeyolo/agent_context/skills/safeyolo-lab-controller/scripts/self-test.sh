#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
skill_dir=$(cd "$script_dir/.." && pwd)
redactor="$script_dir/redact_credentials.py"
capture="$script_dir/capture-evidence.sh"
controller_runner="$script_dir/run-controller.sh"
operator_cli="$script_dir/safeyolo-lab"
entrypoint_installer="$script_dir/install-operator-entrypoint.sh"
layout_helper="$script_dir/adapt-layout.sh"
pane_annotator="$script_dir/annotate-pane.sh"
annotation_viewer="$script_dir/show-annotation.sh"
surface_switcher="$script_dir/switch-surface.sh"
questions_helper="$script_dir/lesson-questions.sh"
sources_helper="$script_dir/lesson-sources.sh"
tmux_profile="$skill_dir/assets/tmux-lab.conf"
startup_instructions="$skill_dir/assets/startup-instructions.md"

test_root=$(mktemp -d)
tmux_socket="$test_root/tmux.sock"
unrelated_socket="$test_root/unrelated-tmux.sock"
operator_home="$test_root/operator-home"
operator_lab_socket="$operator_home/.safeyolo/lab-tmux.sock"

cleanup() {
  tmux -S "$tmux_socket" kill-server >/dev/null 2>&1 || true
  tmux -S "$unrelated_socket" kill-server >/dev/null 2>&1 || true
  tmux -S "$operator_lab_socket" kill-server >/dev/null 2>&1 || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

wait_for_pane_text() {
  local pane=$1
  local pattern=$2
  local attempt
  for attempt in $(seq 1 100); do
    if tmux -S "$tmux_socket" capture-pane -p -t "$pane" -S - | grep -Fq -- "$pattern"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

for shell_script in "$capture" "$script_dir/lab-snapshot.sh" "$controller_runner" \
  "$operator_cli" "$entrypoint_installer" "$layout_helper" \
  "$pane_annotator" "$annotation_viewer" "$surface_switcher" \
  "$questions_helper" "$sources_helper" "$0"; do
  bash -n "$shell_script" || fail "shell syntax: $shell_script"
done
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' \
  "$redactor" || fail 'Python syntax'

fake_bearer='fakeBearerValue0123456789'
fake_api_key='sk-proj-FakeValue0123456789ABCDE'
redaction_input="$test_root/redaction-input.txt"
redaction_output="$test_root/redaction-output.txt"
{
  printf 'Authorization: Bearer %s\n' "$fake_bearer"
  printf '{"api_key":"%s"}\n' "$fake_api_key"
  printf '%s\n' '-----BEGIN USER NKEY SEED-----'
  printf '%s\n' 'SUFAKEVALUEFORSELFTESTONLY'
  printf '%s\n' '------END USER NKEY SEED------'
  printf 'after_private_block=visible\n'
} > "$redaction_input"
python3 "$redactor" "$redaction_input" "$redaction_output"
grep -Fq '[REDACTED_CREDENTIAL]' "$redaction_output" || fail 'credential values were not redacted'
grep -Fq 'after_private_block=visible' "$redaction_output" || fail 'redactor did not recover after private block'
if grep -Fq "$fake_bearer" "$redaction_output" || grep -Fq "$fake_api_key" "$redaction_output"; then
  fail 'credential-shaped test values survived redaction'
fi

same_path="$test_root/same-path.txt"
printf 'ordinary text\n' > "$same_path"
same_before=$(sha256sum "$same_path" | awk '{print $1}')
set +e
python3 "$redactor" "$same_path" "$same_path" >/dev/null 2>&1
same_rc=$?
set -e
[ "$same_rc" -eq 2 ] || fail "same-path refusal returned $same_rc"
same_after=$(sha256sum "$same_path" | awk '{print $1}')
[ "$same_before" = "$same_after" ] || fail 'same-path refusal modified its input'

python3 "$redactor" --check-text "$redaction_input" || fail 'valid UTF-8 text was refused'
binary_file="$test_root/binary.dat"
printf 'text\000binary\n' > "$binary_file"
set +e
python3 "$redactor" --check-text "$binary_file" >/dev/null 2>&1
binary_rc=$?
set -e
[ "$binary_rc" -eq 4 ] || fail "binary refusal returned $binary_rc"

credential_file="$test_root/AUTH.JSON"
printf '{}\n' > "$credential_file"
set +e
"$capture" --output "$test_root/denied-capture" --file "$credential_file" >/dev/null 2>&1
credential_rc=$?
set -e
[ "$credential_rc" -eq 3 ] || fail "case-insensitive credential filename refusal returned $credential_rc"
[ ! -e "$test_root/denied-capture" ] || fail 'credential preflight created a capture directory'

set +e
"$capture" --output "$test_root/missing-capture" \
  --file "$redaction_input" --file "$test_root/absent.txt" >/dev/null 2>&1
missing_rc=$?
set -e
[ "$missing_rc" -eq 2 ] || fail "missing-file preflight returned $missing_rc"
[ ! -e "$test_root/missing-capture" ] || fail 'failed preflight created a capture directory'

tmux -S "$tmux_socket" -f "$tmux_profile" new-session -d -s self-test
pane=$(tmux -S "$tmux_socket" list-panes -t self-test -F '#{pane_id}')
[ -n "$pane" ] || fail 'tmux profile did not create a pane'
[ "$(tmux -S "$tmux_socket" show-options -gv history-limit)" = 100000 ] || fail 'tmux history limit'
[ "$(tmux -S "$tmux_socket" show-window-options -gv pane-border-status)" = top ] || fail 'tmux pane border status'
[ "$(tmux -S "$tmux_socket" show-options -gv remain-on-exit)" = off ] || fail 'tmux remain-on-exit must be off'
[ "$(tmux -S "$tmux_socket" show-options -gv prefix)" = C-a ] || fail 'guest tmux primary prefix'
[ "$(tmux -S "$tmux_socket" show-options -gv prefix2)" = None ] || fail 'guest tmux secondary prefix must be unbound'
status_left=$(tmux -S "$tmux_socket" show-options -gv status-left)
case "$status_left" in
  *'SafeYolo lab'*'@safeyolo_lab_lesson_pane'*'C-a q: panes'*'C-a e: mark'*) ;;
  *) fail 'guest tmux status label' ;;
esac
pane_border_format=$(tmux -S "$tmux_socket" show-window-options -gv pane-border-format)
case "$pane_border_format" in
  *'@safeyolo_lab_annotation_id'*'@safeyolo_lab_state'*'@safeyolo_lab_note'*) ;;
  *) fail 'guest tmux pane annotation format' ;;
esac
annotation_rail_format=$(tmux -S "$tmux_socket" show-options -gqv \
  'status-format[1]')
case "$annotation_rail_format" in
  *'@safeyolo_lab_annotation_id'*'@safeyolo_lab_annotation_evidence'*'@safeyolo_lab_annotation_explanation'*) ;;
  *) fail 'guest tmux annotation rail format' ;;
esac
[ "$(tmux -S "$tmux_socket" show-options -gv display-panes-time)" = \
  3000 ] || fail 'pane-number display duration'
prefix_keys=$(tmux -S "$tmux_socket" list-keys -T prefix)
grep -Fq 'bind-key    -T prefix e' <<< "$prefix_keys" || \
  fail 'evidence highlight key binding'
grep -Fq 'bind-key    -T prefix E' <<< "$prefix_keys" || \
  fail 'explanation popup key binding'
root_keys=$(tmux -S "$tmux_socket" list-keys -T root)
grep -Eq 'bind-key +(-r )?-T root +F12 .*@safeyolo_lab_surface_script' \
  <<< "$root_keys" || fail 'one-key lesson switch binding'
grep -Eq 'bind-key +(-r )?-T root +q .*@safeyolo_lab_questions_script' \
  <<< "$root_keys" || fail 'lowercase lesson question menu key binding'
grep -Eq 'bind-key +(-r )?-T root +Q .*@safeyolo_lab_questions_script' \
  <<< "$root_keys" || fail 'uppercase lesson question menu key binding'
grep -Eq 'bind-key +(-r )?-T root +o .*@safeyolo_lab_sources_script' \
  <<< "$root_keys" || fail 'lesson source viewer key binding'
client_resize_hook=$(tmux -S "$tmux_socket" show-hooks -g client-resized)
case "$client_resize_hook" in
  *'@safeyolo_lab_layout_script'*'--session lab'*) ;;
  *) fail 'guest tmux resize hook' ;;
esac

tmux -S "$tmux_socket" set-option -g \
  @safeyolo_lab_layout_script "$layout_helper"
tmux -S "$tmux_socket" set-option -g \
  @safeyolo_lab_annotation_script "$annotation_viewer"
tmux -S "$tmux_socket" set-option -g \
  @safeyolo_lab_surface_script "$surface_switcher"
tmux -S "$tmux_socket" set-option -g \
  @safeyolo_lab_questions_script "$questions_helper"
tmux -S "$tmux_socket" set-option -g \
  @safeyolo_lab_sources_script "$sources_helper"
tmux -S "$tmux_socket" new-session -d -s layout-test
layout_controller=$(tmux -S "$tmux_socket" list-panes -t layout-test \
  -F '#{pane_id}')
tmux -S "$tmux_socket" set-option -p -t "$layout_controller" \
  @safeyolo_lab_role controller
layout_worker=$(tmux -S "$tmux_socket" split-window -d -P -F '#{pane_id}' \
  -t "$layout_controller")
tmux -S "$tmux_socket" set-option -p -t "$layout_worker" \
  @safeyolo_lab_role lesson
tmux -S "$tmux_socket" set-option -w -t layout-test window-size manual
questions_file="$test_root/lesson.questions.tsv"
printf '%s\n' \
  $'Q_ONE\tWhy did the first result occur?' \
  $'Q_TWO\tWhat does the second result prove?' \
  > "$questions_file"
source_file="$test_root/example-source.py"
printf '%s\n' 'alpha = 1' 'beta = 2' 'gamma = 3' 'delta = 4' > "$source_file"
sources_file="$test_root/lesson.sources.tsv"
printf 'SRC_ONE\tExample source\t%s\t2\t4\n' "$source_file" > "$sources_file"
tmux -S "$tmux_socket" set-option -p -t "$layout_worker" \
  @safeyolo_lab_questions_file "$questions_file"
tmux -S "$tmux_socket" set-option -p -t "$layout_worker" \
  @safeyolo_lab_sources_file "$sources_file"

tmux -S "$tmux_socket" resize-window -t layout-test -x 190 -y 57
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = side-by-side ] || fail 'wide layout choice'
read -r controller_left controller_top controller_active < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
    '#{pane_left} #{pane_top} #{pane_active}'
)
read -r worker_left worker_top < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
    '#{pane_left} #{pane_top}'
)
[ "$controller_top" -eq "$worker_top" ] || fail 'wide panes are not side by side'
[ "$worker_left" -gt "$controller_left" ] || fail 'worker is not right of controller'
[ "$controller_active" -eq 1 ] || fail 'wide layout did not return focus to controller'
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_lesson_pane)" = "$layout_worker" ] || \
  fail 'layout did not register the lesson pane'
wide_controller_status=$(tmux -S "$tmux_socket" display-message -p \
  -t "$layout_controller" '#{E:status-left}')
case "$wide_controller_status" in
  *'F12: open lesson'*) ;;
  *) fail 'controller status did not offer the lesson switch' ;;
esac

"$surface_switcher" --socket "$tmux_socket" --pane "$layout_controller"
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{pane_active}')" -eq 1 ] || fail 'F12 switch did not open the lesson'
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_focus_target)" = "$layout_worker" ] || \
  fail 'lesson switch did not preserve learner focus'
wide_lesson_status=$(tmux -S "$tmux_socket" display-message -p \
  -t "$layout_worker" '#{E:status-left}')
case "$wide_lesson_status" in
  *'Left/Right: pages'*'o: source'*'q: questions'*'F12: ask controller'*) ;;
  *) fail 'lesson status did not explain its controls' ;;
esac
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{&&:#{==:#{@safeyolo_lab_role},lesson},#{@safeyolo_lab_questions_file}}')" = 1 ] || \
  fail 'question keys were not active for a registered lesson'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{&&:#{==:#{@safeyolo_lab_role},lesson},#{@safeyolo_lab_sources_file}}')" = 1 ] || \
  fail 'source key was not active for a registered lesson'
tmux -S "$tmux_socket" set-option -p -u -t "$layout_worker" \
  @safeyolo_lab_questions_file
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{&&:#{==:#{@safeyolo_lab_role},lesson},#{@safeyolo_lab_questions_file}}')" = 0 ] || \
  fail 'question keys remained active outside a registered lesson'
tmux -S "$tmux_socket" set-option -p -t "$layout_worker" \
  @safeyolo_lab_questions_file "$questions_file"

"$surface_switcher" --socket "$tmux_socket" --pane "$layout_worker"
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
  '#{pane_active}')" -eq 1 ] || fail 'F12 switch did not return to controller'
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_focus_target)" = controller ] || \
  fail 'controller switch did not restore the default focus target'

tmux -S "$tmux_socket" send-keys -t "$layout_worker" -l -- \
  'printf "[Q_ONE] First question\n[Q_TWO] Second question\n[SRC_ONE] Example source\n"'
tmux -S "$tmux_socket" send-keys -t "$layout_worker" Enter
wait_for_pane_text "$layout_worker" '[Q_TWO] Second question' || \
  fail 'lesson question markers did not render'
listed_questions=$("$questions_helper" list --socket "$tmux_socket" \
  --pane "$layout_worker")
case "$listed_questions" in
  *$'Q_ONE\tWhy did the first result occur?'*$'Q_TWO\tWhat does the second result prove?'*) ;;
  *) fail 'visible lesson questions were not resolved from the registry' ;;
esac
listed_sources=$("$sources_helper" list --socket "$tmux_socket" \
  --pane "$layout_worker")
case "$listed_sources" in
  *$'SRC_ONE\tExample source\t'*$'\t2\t4'*) ;;
  *) fail 'visible lesson sources were not resolved from the registry' ;;
esac
rendered_source=$("$sources_helper" render --socket "$tmux_socket" \
  --pane "$layout_worker" --id SRC_ONE </dev/null)
case "$rendered_source" in
  *'2  beta = 2'*'4  delta = 4'*) ;;
  *) fail 'registered lesson source range did not render' ;;
esac

self_test_ticks=$(awk '{print $22}' "/proc/$$/stat")
tmux -S "$tmux_socket" set-option -p -t "$layout_controller" \
  @safeyolo_lab_controller_run "$$:$self_test_ticks"
tmux -S "$tmux_socket" send-keys -t "$layout_controller" -l -- \
  'printf "__WAITING_FOR_QUESTION__\n"; IFS= read -r selected_question; printf "__SELECTED_QUESTION__=%s\n" "$selected_question"'
tmux -S "$tmux_socket" send-keys -t "$layout_controller" Enter
wait_for_pane_text "$layout_controller" '__WAITING_FOR_QUESTION__' || \
  fail 'test controller did not become ready for a lesson question'
"$questions_helper" submit --socket "$tmux_socket" \
  --pane "$layout_worker" --id Q_ONE
wait_for_pane_text "$layout_controller" \
  '__SELECTED_QUESTION__=Learner selected [Q_ONE]' || \
  fail 'lesson question did not reach the active controller harness'
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_last_question_id)" = Q_ONE ] || \
  fail 'lesson question event ID was not recorded'
tmux -S "$tmux_socket" set-option -p -u -t "$layout_controller" \
  @safeyolo_lab_controller_run
"$questions_helper" submit --socket "$tmux_socket" \
  --pane "$layout_worker" --id Q_TWO
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_pending_question_id)" = Q_TWO ] || \
  fail 'inactive controller did not retain the selected question'

tmux -S "$tmux_socket" send-keys -t "$layout_worker" -l -- \
  'printf "HTTP/2 200\nX-Blocked-By: none\n"'
tmux -S "$tmux_socket" send-keys -t "$layout_worker" Enter
wait_for_pane_text "$layout_worker" 'HTTP/2 200' || \
  fail 'annotation evidence command did not complete'
annotation_id=$("$pane_annotator" --socket "$tmux_socket" \
  --pane "$layout_worker" --state PASS \
  --text 'HTTP 200 | policy allowed | trace complete' \
  --evidence 'HTTP/2 200' \
  --explain 'The website responded after SafeYolo allowed the route.')
[ "$annotation_id" = A1 ] || fail 'automatic annotation ID'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{@safeyolo_lab_state}')" = PASS ] || fail 'pane annotation state'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{@safeyolo_lab_note}')" = \
  'HTTP 200 | policy allowed | trace complete' ] || fail 'pane annotation text'
[ "$(tmux -S "$tmux_socket" show-options -qv -t layout-test status)" = \
  2 ] || fail 'wide annotation did not open the explanation rail'
rendered_border=$(tmux -S "$tmux_socket" display-message -p \
  -t "$layout_worker" '#{T:pane-border-format}')
case "$rendered_border" in
  *'bg=colour22'*'A1 PASS'*'HTTP 200 | policy allowed'*) ;;
  *) fail 'coloured annotation border did not render' ;;
esac
rendered_rail=$(tmux -S "$tmux_socket" display-message -p \
  -t "$layout_worker" '#{T:status-format[1]}')
case "$rendered_rail" in
  *'A1 PASS'*"$layout_worker | \"HTTP/2 200\" ->"*'website responded'*) ;;
  *) fail 'annotation rail did not render evidence and explanation' ;;
esac
"$annotation_viewer" --socket "$tmux_socket" --pane "$layout_worker" \
  --highlight
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{pane_in_mode}')" = 1 ] || fail 'evidence highlight did not enter copy mode'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{@safeyolo_lab_highlight_owned}')" = 1 ] || \
  fail 'evidence highlight ownership was not recorded'
"$annotation_viewer" --socket "$tmux_socket" --pane "$layout_worker" \
  --clear-highlight
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{pane_in_mode}')" = 0 ] || fail 'evidence highlight did not clear'
popup_render=$("$annotation_viewer" --socket "$tmux_socket" \
  --pane "$layout_worker" --render </dev/null)
case "$popup_render" in
  *'LAB EXPLANATION'*'Evidence fragment:'*'Why it matters:'*'raw pane output is unchanged'*) ;;
  *) fail 'annotation popup content did not render' ;;
esac

tmux -S "$tmux_socket" resize-window -t layout-test -x 100 -y 50
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = stacked ] || fail 'narrow layout choice'
read -r controller_left controller_top < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
    '#{pane_left} #{pane_top}'
)
read -r worker_left worker_top < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
    '#{pane_left} #{pane_top}'
)
[ "$controller_left" -eq "$worker_left" ] || fail 'narrow panes are not stacked'
[ "$worker_top" -gt "$controller_top" ] || fail 'worker is not below controller'

tmux -S "$tmux_socket" resize-window -t layout-test -x 79 -y 24
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" display-message -p -t layout-test \
  '#{window_zoomed_flag}')" -eq 1 ] || fail 'small layout did not zoom'
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = focused-zoom ] || fail 'small layout state'
[ -n "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_size_warning)" ] || fail 'small layout warning'
[ "$(tmux -S "$tmux_socket" show-options -qv -t layout-test status)" = \
  on ] || fail 'small layout did not collapse the annotation rail'
small_status_left=$(tmux -S "$tmux_socket" display-message -p \
  -t layout-test '#{E:status-left}')
case "$small_status_left" in
  *'Screen 79x24 is too small for 2 lab panes'*'q: questions'*'o: source'*'F12: controller/lesson'*) ;;
  *) fail 'small layout warning is not in the priority status area' ;;
esac
small_status_right=$(tmux -S "$tmux_socket" display-message -p \
  -t layout-test '#{E:status-right}')
[ -z "$small_status_right" ] || fail 'small layout retained competing right status text'

tmux -S "$tmux_socket" resize-window -t layout-test -x 190 -y 57
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" display-message -p -t layout-test \
  '#{window_zoomed_flag}')" -eq 0 ] || fail 'wide layout did not undo automatic zoom'
[ -z "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_size_warning)" ] || fail 'wide layout retained a size warning'
wide_status_left=$(tmux -S "$tmux_socket" display-message -p \
  -t layout-test '#{E:status-left}')
case "$wide_status_left" in
  *'SafeYolo lab'*'F12: open lesson'*) ;;
  *) fail 'wide layout did not restore navigation status' ;;
esac
[ "$(tmux -S "$tmux_socket" show-options -qv -t layout-test status)" = \
  2 ] || fail 'wide layout did not restore the annotation rail'

tmux -S "$tmux_socket" set-option -w -t layout-test \
  @safeyolo_lab_focus_target "$layout_worker"
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{pane_active}')" -eq 1 ] || fail 'explicit focus target'
tmux -S "$tmux_socket" set-option -w -t layout-test \
  @safeyolo_lab_focus_target controller
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
  '#{pane_active}')" -eq 1 ] || fail 'controller focus restoration'

tmux -S "$tmux_socket" resize-pane -Z -t "$layout_worker"
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = manual-zoom ] || fail 'manual zoom was not respected'
tmux -S "$tmux_socket" resize-pane -Z -t "$layout_worker"

"$pane_annotator" --socket "$tmux_socket" --pane "$layout_worker" --clear
[ -z "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{@safeyolo_lab_state}')" ] || fail 'pane annotation state was not cleared'
[ -z "$(tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
  '#{@safeyolo_lab_note}')" ] || fail 'pane annotation text was not cleared'
[ "$(tmux -S "$tmux_socket" show-options -qv -t layout-test status)" = \
  on ] || fail 'clearing annotation did not close the explanation rail'

layout_worker_two=$(tmux -S "$tmux_socket" split-window -d -P \
  -F '#{pane_id}' -t "$layout_worker")
tmux -S "$tmux_socket" set-option -p -t "$layout_worker_two" \
  @safeyolo_lab_role observer
tmux -S "$tmux_socket" resize-window -t layout-test -x 190 -y 57
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = main-left ] || fail 'wide three-pane layout choice'
read -r controller_left controller_top controller_width < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
    '#{pane_left} #{pane_top} #{pane_width}'
)
read -r worker_left worker_top worker_width < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
    '#{pane_left} #{pane_top} #{pane_width}'
)
[ "$worker_left" -gt "$controller_left" ] || fail 'three-pane support area is not right of controller'
[ "$controller_width" -gt "$worker_width" ] || fail 'three-pane controller is not the wide main pane'

tmux -S "$tmux_socket" resize-window -t layout-test -x 120 -y 55
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = main-top ] || fail 'tall three-pane layout choice'
read -r controller_left controller_top < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_controller" \
    '#{pane_left} #{pane_top}'
)
read -r worker_left worker_top < <(
  tmux -S "$tmux_socket" display-message -p -t "$layout_worker" \
    '#{pane_left} #{pane_top}'
)
[ "$worker_top" -gt "$controller_top" ] || fail 'three-pane support area is not below controller'

tmux -S "$tmux_socket" resize-window -t layout-test -x 85 -y 40
"$layout_helper" --socket "$tmux_socket" --session layout-test
[ "$(tmux -S "$tmux_socket" show-options -wqv -t layout-test \
  @safeyolo_lab_layout)" = focused-zoom ] || fail 'small three-pane layout choice'
tmux -S "$tmux_socket" kill-session -t layout-test

operator_help=$("$operator_cli" --help)
grep -Fq 'Run this command once' <<< "$operator_help" || fail 'operator help does not specify one command'
grep -Fq 'first user message is exactly `Hello.`' "$startup_instructions" || fail 'startup instructions do not define the short first message'
set +e
"$operator_cli" start >/dev/null 2>&1
extra_action_rc=$?
set -e
[ "$extra_action_rc" -eq 2 ] || fail 'operator command accepted an extra action'

fake_bin="$test_root/fake-bin"
fake_tmux_log="$test_root/fake-tmux.log"
mkdir -p "$fake_bin"
cat > "$fake_bin/tmux" <<'SH'
#!/usr/bin/env bash
printf '%q ' "$@" >> "$FAKE_TMUX_LOG"
printf '\n' >> "$FAKE_TMUX_LOG"
if [ "${1:-}" = -S ]; then
  shift 2
fi
# Use a stable process identity: most tmux queries below run in command
# substitutions, whose parent is not the operator_cli shell. PID 1 is alive
# for the duration of this fixture and lets the launcher exercise its
# start-ticks liveness check without a background process.
controller_pid=1
start_ticks=$(awk '{print $22}' "/proc/$controller_pid/stat" 2>/dev/null || printf '1')
case "${1:-}" in
  has-session)
    [ "${FAKE_TMUX_MODE:-}" = existing ]
    exit $?
    ;;
  show-options)
    case "${*: -1}" in
      @safeyolo_lab_owner) printf 'safeyolo:unknown\n' ;;
      @safeyolo_lab_agent) printf 'unknown\n' ;;
      @safeyolo_lab_controller_pane) printf '%%0\n' ;;
      @safeyolo_lab_controller_run) printf '%s:%s\n' "$controller_pid" "$start_ticks" ;;
    esac
    ;;
  list-sessions)
    exit 1
    ;;
  display-message)
    case "$*" in
      *pane_dead*) printf '0\n' ;;
      *pane_id*) printf '%%0\n' ;;
      *) printf '%%0\n' ;;
    esac
    ;;
  *) exit 0 ;;
esac
SH
chmod 700 "$fake_bin/tmux"

: > "$fake_tmux_log"
env -u TMUX -u TMUX_PANE SAFEYOLO_AGENT_NAME=unknown PATH="$fake_bin:$PATH" FAKE_TMUX_LOG="$fake_tmux_log" \
  FAKE_TMUX_MODE=create "$operator_cli"
[ "$(grep -c 'send-keys ' "$fake_tmux_log")" -eq 2 ] || fail 'new lab did not inject exactly one controller command'
grep -Fq 'startup-instructions.md' "$fake_tmux_log" || fail 'new lab did not inject the hidden startup instructions'
grep -Fq 'attach-session -t lab' "$fake_tmux_log" || fail 'new lab did not attach'

: > "$fake_tmux_log"
env -u TMUX -u TMUX_PANE SAFEYOLO_AGENT_NAME=unknown PATH="$fake_bin:$PATH" FAKE_TMUX_LOG="$fake_tmux_log" \
  FAKE_TMUX_MODE=existing "$operator_cli"
if grep -Fq 'send-keys' "$fake_tmux_log"; then
  fail 'reconnect injected another controller command'
fi
grep -Fq 'attach-session -t lab' "$fake_tmux_log" || fail 'reconnect did not attach'

mkdir -p "$operator_home"
tmux -S "$unrelated_socket" new-session -d -s unrelated
unrelated_first_pane=$(tmux -S "$unrelated_socket" list-panes -t unrelated -F '#{pane_id}')
unrelated_second_pane=$(tmux -S "$unrelated_socket" split-window -d -P -F '#{pane_id}' -t "$unrelated_first_pane")
tmux -S "$unrelated_socket" set-option -g prefix C-b
tmux -S "$unrelated_socket" set-option -g status-left UNRELATED_LEFT
tmux -S "$unrelated_socket" set-option -g status-right UNRELATED_RIGHT
tmux -S "$unrelated_socket" set-hook -g client-resized 'display-message unrelated-hook'
tmux -S "$unrelated_socket" send-keys -t "$unrelated_first_pane" -l -- \
  'printf "__UNRELATED_SCROLLBACK__\\n"'
tmux -S "$unrelated_socket" send-keys -t "$unrelated_first_pane" Enter
sleep 0.2
unrelated_panes_before=$(tmux -S "$unrelated_socket" list-panes -t unrelated \
  -F '#{pane_id}:#{pane_dead}:#{history_size}' | sort)
unrelated_text_before=$(for pane in "$unrelated_first_pane" "$unrelated_second_pane"; do
  printf 'pane=%s\n' "$pane"
  tmux -S "$unrelated_socket" capture-pane -p -t "$pane" -S -
done)
unrelated_hook_before=$(tmux -S "$unrelated_socket" show-hooks -g client-resized)

set +e
timeout 10s env -u TMUX -u TMUX_PANE HOME="$operator_home" \
  SAFEYOLO_AGENT_NAME=real-lab "$operator_cli" \
  --objective 'real dedicated socket regression' >/dev/null 2>&1
operator_rc=$?
set -e
[ "$operator_rc" -ne 125 ] || fail 'real Lab launcher timed out'
[ -S "$operator_lab_socket" ] || fail 'Lab did not create its dedicated tmux socket'
[ "$(tmux -S "$operator_lab_socket" show-options -gv prefix)" = C-a ] || \
  fail 'Lab profile did not apply on its dedicated server'
[ "$(tmux -S "$unrelated_socket" show-options -gv prefix)" = C-b ] || \
  fail 'Lab changed the unrelated server prefix'
[ "$(tmux -S "$unrelated_socket" show-options -gv status-left)" = UNRELATED_LEFT ] || \
  fail 'Lab changed the unrelated server status-left'
[ "$(tmux -S "$unrelated_socket" show-options -gv status-right)" = UNRELATED_RIGHT ] || \
  fail 'Lab changed the unrelated server status-right'
unrelated_lab_hook=$(tmux -S "$unrelated_socket" show-hooks -g client-resized)
[ "$unrelated_lab_hook" = "$unrelated_hook_before" ] || \
  fail 'Lab changed the unrelated server hooks'
lab_panes=$(tmux -S "$operator_lab_socket" list-panes -t lab -F '#{pane_id}' | wc -l)
[ "$lab_panes" -eq 1 ] || fail 'Lab created an unexpected number of controller panes'

env -u TMUX -u TMUX_PANE HOME="$operator_home" SAFEYOLO_AGENT_NAME=real-lab \
  "$operator_cli" --teardown >/dev/null 2>&1 || fail 'real Lab teardown failed'
unrelated_panes_after=$(tmux -S "$unrelated_socket" list-panes -t unrelated \
  -F '#{pane_id}:#{pane_dead}:#{history_size}' | sort)
unrelated_text_after=$(for pane in "$unrelated_first_pane" "$unrelated_second_pane"; do
  printf 'pane=%s\n' "$pane"
  tmux -S "$unrelated_socket" capture-pane -p -t "$pane" -S -
done)
[ "$unrelated_panes_after" = "$unrelated_panes_before" ] || \
  fail 'Lab changed unrelated panes or their liveness/history'
[ "$unrelated_text_after" = "$unrelated_text_before" ] || \
  fail 'Lab changed unrelated pane scrollback'
[ "$(tmux -S "$unrelated_socket" show-options -gv prefix)" = C-b ] || \
  fail 'Lab teardown changed the unrelated server prefix'
[ "$(tmux -S "$unrelated_socket" show-options -gv status-left)" = UNRELATED_LEFT ] || \
  fail 'Lab teardown changed the unrelated server status-left'
[ "$(tmux -S "$unrelated_socket" show-options -gv status-right)" = UNRELATED_RIGHT ] || \
  fail 'Lab teardown changed the unrelated server status-right'
[ "$(tmux -S "$unrelated_socket" show-hooks -g client-resized)" = "$unrelated_hook_before" ] || \
  fail 'Lab teardown changed the unrelated server hooks'

fake_home="$test_root/home"
mkdir -p "$fake_home"
HOME="$fake_home" "$entrypoint_installer" >/dev/null
HOME="$fake_home" "$entrypoint_installer" >/dev/null
[ -L "$fake_home/.local/bin/safeyolo-lab" ] || fail 'operator entry point was not installed'
[ "$(readlink -f "$fake_home/.local/bin/safeyolo-lab")" = "$operator_cli" ] || fail 'operator entry point has the wrong target'
[ "$(grep -Fxc '# >>> safeyolo-lab PATH >>>' "$fake_home/.bashrc")" -eq 1 ] || fail 'operator PATH install is not idempotent'
grep -Fq 'SafeYolo lab: run safeyolo-lab' "$fake_home/.bashrc" || fail 'operator discovery hint was not installed'
installed_help=$(HOME="$fake_home" "$fake_home/.local/bin/safeyolo-lab" --help)
grep -Fq 'Usage: safeyolo-lab' <<< "$installed_help" || fail 'installed operator entry point does not run'

tmux -S "$tmux_socket" send-keys -t "$pane" -l -- 'printf "__PERSISTENT_SHELL_OK__\\n"'
tmux -S "$tmux_socket" send-keys -t "$pane" Enter
wait_for_pane_text "$pane" '__PERSISTENT_SHELL_OK__' || fail 'persistent shell command did not complete'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$pane" '#{pane_dead}')" = 0 ] || fail 'parent tmux shell died'

fake_controller="$test_root/fake-controller.sh"
fake_startup="$test_root/fake-startup.md"
fake_runner_home="$test_root/runner-home"
expected_objective='Inspect a bounded objective.'
mkdir -p "$fake_runner_home/.safeyolo"
printf 'Base instruction test marker.\n' > "$fake_runner_home/.safeyolo/AGENTS.md"
printf 'Lab startup test instruction.\n' > "$fake_startup"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'printf "__FAKE_CONTROLLER_RAN__\\n"'
  printf '%s\n' 'controller_run=$(tmux display-message -p -t "$TMUX_PANE" "#{@safeyolo_lab_controller_run}")'
  printf '%s\n' 'if [[ "$controller_run" =~ ^[0-9]+:[0-9]+$ ]]; then printf "__FAKE_CONTROLLER_READY__=ok\\n"; else printf "__FAKE_CONTROLLER_READY__=bad\\n"; fi'
  printf '%s\n' 'if [ "${1:-}" = -c ] && [[ "${2:-}" == *"Base instruction test marker."* ]] && [[ "${2:-}" == *"Lab startup test instruction."* ]] && [[ "${2:-}" != *"$EXPECTED_OBJECTIVE"* ]] && [ "${3:-}" = "Hello." ]; then'
  printf '%s\n' '  printf "__FAKE_CONTROLLER_STARTUP__=ok\\n"'
  printf '%s\n' 'elif [ "${1:-}" = -c ] && [[ "${2:-}" == *"Base instruction test marker."* ]] && [[ "${2:-}" == *"Lab startup test instruction."* ]] && [[ "${2:-}" == *"$EXPECTED_OBJECTIVE"* ]] && [ "${3:-}" = "Hello." ]; then'
  printf '%s\n' '  printf "__FAKE_CONTROLLER_OBJECTIVE__=ok\\n"'
  printf '%s\n' 'else'
  printf '%s\n' '  printf "__FAKE_CONTROLLER_STARTUP__=bad\\n"'
  printf '%s\n' 'fi'
  printf '%s\n' 'exit 7'
} > "$fake_controller"
chmod 700 "$fake_controller"
controller_line=$(printf 'EXPECTED_OBJECTIVE=%q HOME=%q %q --command %q --startup-file %q' \
  "$expected_objective" "$fake_runner_home" "$controller_runner" "$fake_controller" "$fake_startup")
controller_line+='; self_test_rc=$?; printf "__RUN_CONTROLLER_RC__=%s\\n" "$self_test_rc"'
tmux -S "$tmux_socket" send-keys -t "$pane" -l -- "$controller_line"
tmux -S "$tmux_socket" send-keys -t "$pane" Enter
wait_for_pane_text "$pane" '__RUN_CONTROLLER_RC__=7' || fail 'controller runner did not preserve the command exit code'
wait_for_pane_text "$pane" '__FAKE_CONTROLLER_STARTUP__=ok' || fail 'controller runner did not pass hidden instructions and the short first message'
wait_for_pane_text "$pane" '__FAKE_CONTROLLER_READY__=ok' || fail 'controller runner did not publish input readiness'
[ -z "$(tmux -S "$tmux_socket" display-message -p -t "$pane" \
  '#{@safeyolo_lab_controller_run}')" ] || \
  fail 'controller runner retained input readiness after exit'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$pane" '#{@safeyolo_lab_role}')" = controller ] || fail 'controller role was not retained'
[ "$(tmux -S "$tmux_socket" display-message -p -t "$pane" '#{pane_dead}')" = 0 ] || fail 'controller runner replaced the parent shell'

printf '%s\n' "$expected_objective" > "$fake_runner_home/.safeyolo/lab-objective"
tmux -S "$tmux_socket" send-keys -t "$pane" -l -- "$controller_line"
tmux -S "$tmux_socket" send-keys -t "$pane" Enter
wait_for_pane_text "$pane" '__FAKE_CONTROLLER_OBJECTIVE__=ok' || \
  fail 'controller runner did not retain the objective in startup instructions'
wait_for_pane_text "$pane" '__RUN_CONTROLLER_RC__=7' || \
  fail 'controller runner did not complete the objective startup test'

capture_root="$test_root/evidence"
capture_dir=$("$capture" --output "$capture_root" --socket "$tmux_socket" \
  --pane "$pane" --file "$redaction_input")
[ -d "$capture_dir" ] || fail 'capture helper did not return a completed directory'
grep -Fq 'status=complete' "$capture_dir/capture-status.txt" || fail 'capture was not marked complete'
grep -Fq $'\tcontroller\t' "$capture_dir/pane-metadata.tsv" || fail 'pane role missing from metadata'
python3 - "$capture_dir/manifest.jsonl" <<'PY' || fail 'capture manifest'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    rows = [json.loads(line) for line in stream]
assert {row["kind"] for row in rows} == {"file", "pane"}
assert all(row["redaction"] == "credential-redactor" for row in rows)
PY
(
  cd "$capture_dir"
  sha256sum -c SHA256SUMS >/dev/null
) || fail 'capture integrity hashes'
if grep -R -Fq "$fake_bearer" "$capture_dir" || grep -R -Fq "$fake_api_key" "$capture_dir"; then
  fail 'credential-shaped test values survived evidence capture'
fi

printf 'PASS: safeyolo-lab-controller helper self-test\n'
