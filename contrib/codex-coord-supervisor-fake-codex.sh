#!/bin/sh
# Minimal observable Codex substitute for supervised factory labs.

set -eu

if [ "${1-}" = "login" ] && [ "${2-}" = "status" ]; then
    printf '%s\n' 'Logged in using ChatGPT'
    exit 0
fi

capture_dir=${SAFEYOLO_FAKE_CODEX_CAPTURE_DIR:?set SAFEYOLO_FAKE_CODEX_CAPTURE_DIR}
umask 077
mkdir -p -- "$capture_dir"
capture_prefix="$capture_dir/invocation-$$"
: > "$capture_prefix.argv"
for argument do
    printf '%s\n' "$argument" >> "$capture_prefix.argv"
done
tee "$capture_prefix.stdin" >/dev/null

printf '%s\n' "fake-codex: captured $capture_prefix.argv and $capture_prefix.stdin" >&2
if [ -n "${SAFEYOLO_FAKE_CODEX_EVENTS-}" ]; then
    while IFS= read -r event || [ -n "$event" ]; do
        printf '%s\n' "$event"
    done < "$SAFEYOLO_FAKE_CODEX_EVENTS"
else
    printf '%s\n' '{"type":"thread.started","thread_id":"thread-fake-supervisor"}'
    printf '%s\n' '{"type":"turn.started"}'
    printf '%s\n' '{"type":"turn.completed"}'
fi
