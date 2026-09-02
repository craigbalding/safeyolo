#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: capture-evidence.sh --output DIR [--socket PATH]
                           [--pane PANE_ID]... [--file TEXT_FILE]...

Capture selected tmux pane scrollback and text files. At least one --pane or
--file is required. All inputs are preflighted; common credential files and
non-text files are refused. Successful captures include a provenance manifest.
EOF
  exit 2
}

output_root=
tmux_socket=
panes=()
files=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || usage
      output_root=$2
      shift 2
      ;;
    --socket)
      [ "$#" -ge 2 ] || usage
      tmux_socket=$2
      shift 2
      ;;
    --pane)
      [ "$#" -ge 2 ] || usage
      panes+=("$2")
      shift 2
      ;;
    --file)
      [ "$#" -ge 2 ] || usage
      files+=("$2")
      shift 2
      ;;
    *) usage ;;
  esac
done

[ -n "$output_root" ] || usage
[ "${#panes[@]}" -gt 0 ] || [ "${#files[@]}" -gt 0 ] || usage

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
redactor="$script_dir/redact_credentials.py"

tmux_args=()
if [ -n "$tmux_socket" ]; then
  tmux_args=(-S "$tmux_socket")
fi

# Preflight every requested input before creating a capture directory.
for pane in "${panes[@]}"; do
  if ! tmux "${tmux_args[@]}" display-message -p -t "$pane" '#{pane_id}' >/dev/null; then
    printf 'Unable to resolve tmux pane: %s\n' "$pane" >&2
    exit 2
  fi
done

for source in "${files[@]}"; do
  [ -f "$source" ] || {
    printf 'Not a regular file: %s\n' "$source" >&2
    exit 2
  }
  basename_source=$(basename "$source")
  lowercase_name=$(printf '%s' "$basename_source" | tr '[:upper:]' '[:lower:]')
  case "$lowercase_name" in
    auth.json|*.credentials.json|agent_token|admin_token|hmac_secret|creds|vm_ssh_key|proxy.env|*.p12|*.pfx|*.key|*-key.pem|*private*.pem|id_rsa|id_ed25519)
      printf 'Refusing credential-bearing filename: %s\n' "$source" >&2
      exit 3
      ;;
  esac
  if python3 "$redactor" --check-text "$source"; then
    :
  else
    check_rc=$?
    printf 'Refusing non-text file without a safe export: %s\n' "$source" >&2
    exit "$check_rc"
  fi
done

umask 077
install -d -m 700 "$output_root"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
capture_dir="$output_root/capture-$stamp-$$"
[ ! -e "$capture_dir" ] || {
  printf 'Capture destination already exists: %s\n' "$capture_dir" >&2
  exit 2
}
stage_dir=$(mktemp -d "$output_root/.capture-$stamp-$$.staging.XXXXXX")
chmod 700 "$stage_dir"
install -d -m 700 "$stage_dir/panes" "$stage_dir/files"

finalized=0
mark_incomplete() {
  local rc=$1
  trap - EXIT
  if [ "$finalized" -eq 0 ] && [ -d "$stage_dir" ]; then
    printf 'status=incomplete\nexit_code=%s\nfailed_utc=%s\n' \
      "$rc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$stage_dir/capture-status.txt"
    find "$stage_dir" -type f -exec chmod 600 {} +
    incomplete_dir="$capture_dir.incomplete"
    if [ -e "$incomplete_dir" ]; then
      incomplete_dir="$capture_dir.incomplete.$RANDOM"
    fi
    mv "$stage_dir" "$incomplete_dir"
    printf 'Incomplete capture retained at: %s\n' "$incomplete_dir" >&2
  fi
  exit "$rc"
}
trap 'mark_incomplete $?' EXIT

started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '%s\n' "$started_utc" > "$stage_dir/captured-utc.txt"
manifest="$stage_dir/manifest.jsonl"

manifest_append() {
  python3 - "$manifest" "$@" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
record = {}
for item in sys.argv[2:]:
    key, value = item.split("=", 1)
    record[key] = value
with open(manifest_path, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY
}

if [ "${#panes[@]}" -gt 0 ]; then
  printf 'requested_target\tsocket\tsession\twindow\tpane_id\tpane_index\trole\ttitle\tdead\tpid\tcmd\thistory\n' \
    > "$stage_dir/pane-metadata.tsv"
fi

index=0
for pane in "${panes[@]}"; do
  index=$((index + 1))
  safe_pane=$(printf '%s' "$pane" | tr -c 'A-Za-z0-9_.-' '_')
  relative_destination="panes/$(printf '%03d' "$index")-$safe_pane.txt"
  destination="$stage_dir/$relative_destination"
  tmux "${tmux_args[@]}" capture-pane -p -t "$pane" -S - |
    python3 "$redactor" > "$destination"
  {
    printf '%s\t' "$pane"
    tmux "${tmux_args[@]}" display-message -p -t "$pane" \
      $'#{socket_path}\t#{session_name}\t#{window_id}:#{window_index}\t#{pane_id}\t#{pane_index}\t#{@safeyolo_lab_role}\t#{pane_title}\t#{pane_dead}\t#{pane_pid}\t#{pane_current_command}\t#{history_size}/#{history_limit}'
  } | python3 "$redactor" >> "$stage_dir/pane-metadata.tsv"
  item_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  manifest_append \
    'kind=pane' \
    "requested_target=$pane" \
    "tmux_socket=${tmux_socket:-current-environment}" \
    "captured_path=$relative_destination" \
    "captured_bytes=$(stat -c '%s' "$destination")" \
    "captured_utc=$item_utc" \
    'redaction=credential-redactor'
done

index=0
for source in "${files[@]}"; do
  index=$((index + 1))
  basename_source=$(basename "$source")
  safe_name=$(printf '%s' "$basename_source" | tr -c 'A-Za-z0-9_.-' '_')
  relative_destination="files/$(printf '%03d' "$index")-$safe_name"
  destination="$stage_dir/$relative_destination"
  python3 "$redactor" "$source" "$destination"
  resolved_source=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$source")
  item_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  manifest_append \
    'kind=file' \
    "source_path=$resolved_source" \
    "source_bytes=$(stat -c '%s' "$source")" \
    "source_mtime=$(stat -c '%y' "$source")" \
    "captured_path=$relative_destination" \
    "captured_bytes=$(stat -c '%s' "$destination")" \
    "captured_utc=$item_utc" \
    'redaction=credential-redactor'
done

printf 'status=complete\nstarted_utc=%s\ncompleted_utc=%s\n' \
  "$started_utc" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$stage_dir/capture-status.txt"
find "$stage_dir" -type f -exec chmod 600 {} +

(
  cd "$stage_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  else
    while IFS= read -r -d '' source_file; do
      shasum -a 256 "$source_file"
    done < <(find . -type f ! -name SHA256SUMS -print0 | sort -z) > SHA256SUMS
  fi
  chmod 600 SHA256SUMS
)

mv "$stage_dir" "$capture_dir"
finalized=1
trap - EXIT
printf '%s\n' "$capture_dir"
