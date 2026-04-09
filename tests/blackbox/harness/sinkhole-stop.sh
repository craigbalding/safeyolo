#!/bin/bash
# Stop the sinkhole server via launchd.
set -e

LABEL="com.safeyolo.test.sinkhole"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"

if launchctl list "$LABEL" >/dev/null 2>&1; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    echo "Sinkhole stopped ($LABEL)"
else
    echo "Sinkhole not running"
fi

rm -f "$PLIST"
