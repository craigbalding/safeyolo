#!/bin/sh
# Example: select a static socket, session, window and pane before scheduling.
set -eu
socket=/home/agent/.local/state/tmux/scheduled.sock
target='=scheduled:=input.0'
expected='scheduled:input.0'
actual=$(tmux -S "$socket" display-message -p -t "$target" \
    '#{session_name}:#{window_name}.#{pane_index}') || {
    echo "tmux target unavailable: $expected on $socket" >&2
    exit 1
}
if [ "$actual" != "$expected" ]; then
    echo "tmux target mismatch: expected $expected, got $actual" >&2
    exit 1
fi
tmux -S "$socket" send-keys -l -t "$target" -- 'Please inspect $HOME; [literal text].'
printf 'Queued literal text to %s on %s\n' "$expected" "$socket"
