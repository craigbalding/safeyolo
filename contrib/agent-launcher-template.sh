#!/bin/bash
# Copy outside every guest-writable share, make executable, then select it:
# safeyolo agent config --default-launcher /absolute/host/launcher.sh
# Or: safeyolo agent config NAME --launcher /absolute/host/launcher.sh
set -euo pipefail

pre_launch() {
    : # Optional host preparation. A non-zero return prevents this new launch.
}

post_launch() {
    : # Optional host action. Failure is reported; it does not stop the agent.
}

on_exit() {
    : # Actual command exit, not the return from `tmux new-window`.
    # SAFEYOLO_AGENT_EXIT_CODE and SAFEYOLO_AGENT_EXIT_REASON describe the exit.
    # This cannot run after the host or terminal manager is forcibly killed.
}

case "${1:-}" in # DOC: contrib/agent-launcher-prompt.md
    pre_launch) pre_launch ;;
    post_launch) post_launch ;;
    on_exit) on_exit ;;
    launch|attach|status|stop)
        # One shared host session, one window per running agent. Change to
        # tmux-pane.sh for panes. The preset owns the guest-entrypoint wrapper,
        # which invokes the three functions above at the correct times.
        exec "$SAFEYOLO_LAUNCHER_PRESETS/tmux-window.sh" "$1"
        ;;
    *) echo "Expected launch, attach, status, stop, pre_launch, post_launch or on_exit" >&2; exit 2 ;;
esac
