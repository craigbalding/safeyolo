#!/bin/bash
# Context comes from the SafeYolo host, never from an Admin API request body.
set -eu

case "${1:-}" in
    pre_launch|post_launch|on_exit) exit 0 ;;
    # SafeYolo stops the sandbox. Leave its terminal wrapper alive to reap the
    # guest command and run on_exit; that wrapper then closes its own pane.
    stop) exit 0 ;;
esac
command -v tmux >/dev/null || { echo "tmux is not installed on this SafeYolo host" >&2; exit 1; }

session=$SAFEYOLO_TMUX_SESSION
pane=${SAFEYOLO_LAUNCH_PANE:-}
case "${1:-}" in
    launch)
        # tmux inherits the existing server's environment, which may predate
        # this installation. Pass this launch's fixed context explicitly.
        command=(env "SAFEYOLO_CONFIG_DIR=$SAFEYOLO_CONFIG_DIR"
            "SAFEYOLO_LOGS_DIR=$SAFEYOLO_LOGS_DIR"
            "$SAFEYOLO_PYTHON" -m safeyolo.cli agent shell "$SAFEYOLO_AGENT_NAME"
            --agent-command --launch-id "$SAFEYOLO_LAUNCH_ID")
        if ! tmux has-session -t "=$session" 2>/dev/null; then
            # Another agent may create the shared session concurrently.
            pane=$(tmux new-session -d -P -F '#{pane_id}' -s "$session" \
                -n "$SAFEYOLO_AGENT_NAME" "${command[@]}") || pane=
        fi
        if [ -z "$pane" ]; then
            if [ "${SAFEYOLO_TMUX_LAYOUT:-window}" = pane ]; then
                pane=$(tmux split-window -d -P -F '#{pane_id}' -t "=$session:" "${command[@]}")
            else
                pane=$(tmux new-window -d -P -F '#{pane_id}' -t "=$session:" \
                    -n "$SAFEYOLO_AGENT_NAME" "${command[@]}")
            fi
        fi
        # The entrypoint records/tag its own pane before running the agent.
        # A very short command can already have exited by this point.
        printf '{"pane_id":"%s"}\n' "$pane"
        ;;
    attach|status)
        [ -n "$pane" ] || { echo "No recorded agent pane" >&2; exit 1; }
        actual=$(tmux show-options -p -v -t "$pane" @safeyolo_launch_id 2>/dev/null) || exit 1
        [ "$actual" = "$SAFEYOLO_LAUNCH_ID" ] || { echo "The recorded agent pane no longer belongs to this run" >&2; exit 1; }
        case "$1" in
            status)
                [ "$(tmux display-message -p -t "$pane" '#{pane_dead}')" = 0 ]
                printf '{"state":"running"}\n'
                ;;
            attach)
                tmux select-pane -t "$pane"
                if [ -n "${TMUX:-}" ]; then
                    tmux switch-client -t "$pane"
                else
                    exec tmux attach-session -t "$pane"
                fi
                ;;
        esac
        ;;
    *) echo "Expected launch, attach, status, stop, pre_launch, post_launch or on_exit" >&2; exit 2 ;;
esac
