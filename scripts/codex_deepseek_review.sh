#!/usr/bin/env bash
# Start and continue the non-factory DeepSeek reviewer used by #620.
#
# Each issue gets one fresh Codex session.  Correction rounds must pass the
# explicit session id returned by `session-id`; this script deliberately has
# no --last path. The reviewer owns routine issue acceptance; Sol is reserved
# for an explicit escalation or the integrated final-release review.
set -euo pipefail

repo=${SAFEYOLO_REVIEW_REPO:-/home/agent/safeyolo-rust-620}
root=${SAFEYOLO_REVIEW_LOG_ROOT:-/home/agent/safeyolo-rust-620-evidence/deepseek-reviews}
profile=${SAFEYOLO_REVIEW_PROFILE:-opencode-go-review}
model_provider=opencode_go_review
model=deepseek-v4.1-flash
reasoning=max

usage() {
  cat >&2 <<'EOF'
usage:
  codex_deepseek_review.sh start ISSUE CANDIDATE [PROMPT...]
  codex_deepseek_review.sh resume ISSUE SESSION_ID [PROMPT...]
  codex_deepseek_review.sh session-id JSONL_LOG
  codex_deepseek_review.sh status ISSUE

start creates a fresh session. resume requires the session UUID printed by
the start log; --last is intentionally rejected.
EOF
}

die() { echo "codex-deepseek-review: $*" >&2; exit 2; }

git -C "$repo" rev-parse --show-toplevel >/dev/null 2>&1 || \
  die "review repository is not a git checkout: $repo"
mkdir -p "$root"

extract_session() {
  local log=$1
  [[ -f "$log" ]] || die "JSONL log does not exist: $log"
  python3 - "$log" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    for key in ("thread_id", "session_id"):
        value = obj.get(key)
        if value:
            print(value)
            raise SystemExit(0)
    # Some CLI versions nest the id in a thread/session object.
    for key in ("thread", "session"):
        value = obj.get(key)
        if isinstance(value, dict):
            for nested in ("id", "thread_id", "session_id"):
                if value.get(nested):
                    print(value[nested])
                    raise SystemExit(0)
raise SystemExit(1)
PY
}

base_args=(
  --profile "$profile"
  --cd "$repo"
  --sandbox read-only
  --add-dir "$root"
  --ask-for-approval never
  -c 'model_provider="opencode_go_review"'
  -c 'model="deepseek-v4.1-flash"'
  -c 'review_model="deepseek-v4.1-flash"'
  -c 'model_reasoning_effort="max"'
  -c 'plan_mode_reasoning_effort="max"'
  -c 'model_supports_reasoning_summaries=true'
)

launch() {
  local issue=$1 mode=$2 id=$3 prompt=$4
  local stamp log err last receipt meta runner tmux_session
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  log="$root/${issue}-${stamp}.jsonl"
  err="$root/${issue}-${stamp}.stderr"
  last="$root/${issue}-${stamp}.last"
  receipt="$root/${issue}-${stamp}.acceptance-receipt.md"
  meta="$root/${issue}-${stamp}.meta"
  runner="$root/${issue}-${stamp}.run.sh"
  tmux_session="ds-review-${issue}-${stamp}"
  {
    printf 'issue=%s\nmode=%s\n' "$issue" "$mode"
    [[ -n "$id" ]] && printf 'session_id=%s\n' "$id"
    printf 'candidate=%s\nprovider=%s\nmodel=%s\nreasoning=%s\n' \
      "${CANDIDATE:-unknown}" "$model_provider" "$model" "$reasoning"
    printf 'repo=%s\nstarted_utc=%s\n' "$repo" "$stamp"
  } >"$meta"
  local -a command
  if [[ "$mode" == start ]]; then
    command=(codex "${base_args[@]}" exec --json -o "$last" "$prompt")
  else
    command=(codex "${base_args[@]}" exec resume "$id" --json -o "$last" "$prompt")
  fi
  {
    printf '#!/usr/bin/env bash\nset -u -o pipefail\nset +e\n'
    printf ' %q' "${command[@]}"
    printf ' 2>%q | tee %q\n' "$err" "$log"
    printf 'status=${PIPESTATUS[0]}\n'
    printf 'if [[ -s %q ]]; then cp -- %q %q; fi\n' "$last" "$last" "$receipt"
    printf 'exit "$status"\n'
  } >"$runner"
  chmod 700 "$runner"
  local tmux_pane visible
  if [[ -n "${TMUX_PANE:-}" ]]; then
    tmux_session=$(tmux display-message -p -t "$TMUX_PANE" '#S')
    # -h gives a vertical divider (side-by-side panes) in the operator's
    # current window. Keep the completed pane visible for evidence inspection.
    tmux_pane=$(tmux split-window -h -P -F '#{pane_id}' -t "$TMUX_PANE" -c "$repo" bash "$runner")
    tmux set-option -p -t "$tmux_pane" remain-on-exit on
    visible=true
  else
    tmux new-session -d -s "$tmux_session" -c "$repo" bash "$runner"
    tmux_pane=$(tmux list-panes -t "$tmux_session" -F '#{pane_id}' | head -1)
    visible=false
  fi
  printf 'tmux_session=%s\ntmux_pane=%s\nvisible=%s\nrunner=%s\njsonl=%s\nstderr=%s\nlast=%s\nreceipt=%s\n' \
    "$tmux_session" "$tmux_pane" "$visible" "$runner" "$log" "$err" "$last" "$receipt" >>"$meta"
  printf 'tmux_session=%s\ntmux_pane=%s\nvisible=%s\nrunner=%s\nstderr=%s\njsonl=%s\nmeta=%s\nreceipt=%s\n' \
    "$tmux_session" "$tmux_pane" "$visible" "$runner" "$err" "$log" "$meta" "$receipt"
}

case "${1:-}" in
  start)
    [[ $# -ge 3 ]] || { usage; exit 2; }
    issue=$2; candidate=$3; shift 3
    [[ "$candidate" != --last ]] || die "--last is forbidden; start takes a candidate commit"
    CANDIDATE=$candidate
    prompt="Issue ${issue}, candidate commit ${candidate}. You are the independent reviewer and routine acceptance authority, not a preliminary screening layer. Review independently from the repository at ${repo}: inspect the relevant execution paths and callers, run the required builds and focused tests or probes, and verify retained evidence against every issue acceptance item. Put all disposable build/test output under ${root}/targets/${issue} and retained review evidence under ${root}; reuse that same issue target for correction rounds and keep concurrent issue targets distinct. Do not edit product source or configuration, integrate commits, change issue state, weaken assertions, or perform implementation work. Preserve reviewer containment and approval boundaries. Start one fresh reviewer session for this issue; correction rounds must resume this same session. End with exactly one of READY, CHANGES_REQUIRED, or BLOCKED. READY is an independent acceptance decision. Write a complete acceptance receipt in the response: exact candidate, each proven and unproven requirement, commands and results, evidence paths, findings corrected, limitations, and any unchecked item with a short reason. This response is persisted as the durable receipt. Sol is reserved for an explicitly escalated concrete problem or the integrated final-release acceptance milestone. ${*:-}"
    launch "$issue" start "" "$prompt"
    ;;
  resume)
    [[ $# -ge 3 ]] || { usage; exit 2; }
    issue=$2; id=$3; shift 3
    [[ "$id" != --last ]] || die "--last is forbidden; resume requires an explicit session id"
    [[ "$id" != "" ]] || die "resume requires an explicit session id"
    CANDIDATE=unknown
    prompt="Correction round for issue ${issue}, continuing the explicit reviewer session ${id}. Re-read the stable candidate and all prior findings in this same session. Inspect the repaired execution paths and callers, rerun the required builds and focused tests or probes, and verify the retained evidence and every acceptance item. Put all disposable build/test output under ${root}/targets/${issue} and retained review evidence under ${root}; reuse that same issue target and do not create a new target per candidate. Do not edit product source or configuration, integrate commits, change issue state, weaken assertions, or perform implementation work. Preserve reviewer containment and approval boundaries. End with exactly one of READY, CHANGES_REQUIRED, or BLOCKED. READY is an independent acceptance decision. Update the complete acceptance receipt in the response with exact candidate, commands/results, evidence, corrected findings, limitations, and any unchecked item with a short reason. This response is persisted as the durable receipt. Sol is reserved for an explicitly escalated concrete problem or the integrated final-release acceptance milestone. ${*:-}"
    launch "$issue" resume "$id" "$prompt"
    ;;
  session-id)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    extract_session "$2"
    ;;
  status)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    issue=$2
    shopt -s nullglob
    logs=("$root/${issue}-"*.jsonl)
    ((${#logs[@]})) || die "no logs for issue $issue"
    printf '%s\n' "${logs[@]}" | tail -1
    ;;
  *) usage; exit 2 ;;
esac
