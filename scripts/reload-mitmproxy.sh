#!/bin/bash
#
# Reload mitmproxy addons.
#
# Restarts the mitmproxy process in the local tmux session. Faster than
# a full `safeyolo stop && safeyolo start`, but drops in-flight connections.
#
# NOTE: This script re-runs the exact command from startup.
# The command is saved to /tmp/mitmproxy-cmd.sh by start-safeyolo.sh.
# This ensures reload always matches the startup configuration.
#
# WARNING: Runtime settings are reset on reload!
# Any changes made via admin API (warn/block modes, temp allowlists) are lost.
# SafeYolo returns to startup defaults (warn-only unless SAFEYOLO_BLOCK=true).

CMD_FILE="/tmp/mitmproxy-cmd.sh"

if [ ! -f "$CMD_FILE" ]; then
    echo "ERROR: $CMD_FILE not found"
    echo "This file is created by start-safeyolo.sh at startup."
    echo "Try: safeyolo stop && safeyolo start"
    exit 1
fi

echo "Restarting mitmproxy in tmux..."

# Send Ctrl-C to stop current mitmproxy
tmux send-keys -t proxy C-c
sleep 2

# Re-run the saved command
tmux send-keys -t proxy "bash $CMD_FILE" Enter

echo "mitmproxy restarted (using command from startup)"
