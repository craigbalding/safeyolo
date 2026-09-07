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
        target=
        format=$'#{socket_path}\n#{pane_id}'
        # tmux inherits the existing server's environment, which may predate
        # this installation. Pass this launch's fixed context explicitly.
        command=(env "SAFEYOLO_CONFIG_DIR=$SAFEYOLO_CONFIG_DIR"
            "SAFEYOLO_LOGS_DIR=$SAFEYOLO_LOGS_DIR"
            "$SAFEYOLO_PYTHON" -m safeyolo.cli agent shell "$SAFEYOLO_AGENT_NAME"
            --agent-command --launch-id "$SAFEYOLO_LAUNCH_ID")
        if ! tmux has-session -t "=$session" 2>/dev/null; then
            # Another agent may create the shared session concurrently.
            target=$(tmux new-session -d -P -F "$format" -s "$session" \
                -n "$SAFEYOLO_AGENT_NAME" "${command[@]}") || target=
        fi
        if [ -z "$target" ]; then
            if [ "${SAFEYOLO_TMUX_LAYOUT:-window}" = pane ]; then
                target=$(tmux split-window -d -P -F "$format" -t "=$session:" "${command[@]}")
            else
                target=$(tmux new-window -d -P -F "$format" -t "=$session:" \
                    -n "$SAFEYOLO_AGENT_NAME" "${command[@]}")
            fi
        fi
        # Record both handles from creation, not by querying the pane later.
        # A very short command can already have exited by this point.
        "$SAFEYOLO_PYTHON" -c 'import json, sys
socket, pane = sys.argv[1].rsplit("\n", 1)
print(json.dumps({"tmux_socket": socket, "pane_id": pane}))' "$target"
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
