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
tmux_target=(tmux -S "$SAFEYOLO_TMUX_SOCKET")
pane=${SAFEYOLO_LAUNCH_PANE:-}
case "${1:-}" in
    launch)
        exec "$SAFEYOLO_EXECUTABLE" --config "$SAFEYOLO_NATIVE_CONFIG_PATH" \
            agent launcher-session "$SAFEYOLO_AGENT_NAME" "$SAFEYOLO_LAUNCH_ID"
        ;;
    attach|status)
        [ -n "$pane" ] || { echo "No recorded agent pane" >&2; exit 1; }
        socket=${SAFEYOLO_TMUX_SOCKET:-}
        [ -n "$socket" ] || { echo "No recorded tmux server for this agent launch" >&2; exit 1; }
        tmux_target=(tmux -S "$socket")
        actual=$("${tmux_target[@]}" show-options -p -v -t "$pane" @safeyolo_launch_id) || {
            echo "Cannot reach agent pane $pane on tmux server $socket" >&2; exit 1;
        }
        [ "$actual" = "$SAFEYOLO_LAUNCH_ID" ] || { echo "The recorded agent pane no longer belongs to this run" >&2; exit 1; }
        case "$1" in
            status)
                [ "$("${tmux_target[@]}" display-message -p -t "$pane" '#{pane_dead}')" = 0 ]
                printf '{"state":"running"}\n'
                ;;
            attach)
                "${tmux_target[@]}" select-pane -t "$pane"
                # TMUX contains socket,pid,session. Pane IDs alone are not
                # unique across servers. Switch only a client on this server.
                current_socket=${TMUX:-}
                current_socket=${current_socket%,*}
                current_socket=${current_socket%,*}
                if [ "$current_socket" = "$socket" ]; then
                    "${tmux_target[@]}" switch-client -t "$pane"
                else
                    TMUX= exec "${tmux_target[@]}" attach-session -t "$pane"
                fi
                ;;
        esac
        ;;
    *) echo "Expected launch, attach, status, stop, pre_launch, post_launch or on_exit" >&2; exit 2 ;;
esac
