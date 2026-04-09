#!/bin/bash
# Start the sinkhole server via launchd.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LABEL="com.safeyolo.test.sinkhole"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOG_DIR="$HOME/.config/safeyolo-test"

mkdir -p "$LOG_DIR" "$HOME/Library/LaunchAgents"

# Stop existing if running
if launchctl list "$LABEL" >/dev/null 2>&1; then
    echo "Stopping existing sinkhole..."
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    sleep 1
fi

# Find python3 (use venv if active, otherwise system)
PYTHON="${VIRTUAL_ENV:-}/bin/python3"
if [ ! -x "$PYTHON" ]; then
    PYTHON="$(which python3)"
fi

cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON}</string>
        <string>${REPO_ROOT}/tests/blackbox/sinkhole/server.py</string>
        <string>--http-port</string>
        <string>18080</string>
        <string>--https-port</string>
        <string>18443</string>
        <string>--control-port</string>
        <string>19999</string>
        <string>--cert</string>
        <string>${REPO_ROOT}/tests/blackbox/certs/sinkhole.crt</string>
        <string>--key</string>
        <string>${REPO_ROOT}/tests/blackbox/certs/sinkhole.key</string>
    </array>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/sinkhole.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/sinkhole.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
PLISTEOF

launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Sinkhole started via launchd ($LABEL)"
echo "Log: $LOG_DIR/sinkhole.log"
