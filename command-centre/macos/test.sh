#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_ROOT="${SAFEYOLO_COMMAND_CENTRE_BUILD_ROOT:-$ROOT/.build}"
TEST_APP="$BUILD_ROOT/tests/ModelTests.app"
mkdir -p "$TEST_APP/Contents/MacOS"
# Controller tests initialize UserNotifications, which requires an app bundle.
# The isolated test identity does not use Commander's saved profile or items.
cat > "$TEST_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.safeyolo.command-centre.tests</string>
<key>CFBundleExecutable</key><string>ModelTests</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST

xcrun swiftc \
  "$ROOT/Sources/Models.swift" \
  "$ROOT/Sources/Credentials.swift" \
  "$ROOT/Sources/Connection.swift" \
  "$ROOT/Sources/Client.swift" \
  "$ROOT/Sources/Diagnostics.swift" \
  "$ROOT/Sources/UI.swift" \
  "$ROOT/Sources/Controller.swift" \
  "$ROOT/Sources/SecurityNotifications.swift" \
  "$ROOT/Tests/ModelTests.swift" \
  "$ROOT/Tests/ConnectionTests.swift" \
  "$ROOT/Tests/CredentialStartupTests.swift" \
  -o "$TEST_APP/Contents/MacOS/ModelTests" \
  -framework Security -framework SwiftUI -framework AppKit -framework UserNotifications
codesign --force --sign - --timestamp=none "$TEST_APP"
"$TEST_APP/Contents/MacOS/ModelTests"

# Focused credential controls use synthetic stores, without native item changes.
if [[ "${SAFEYOLO_COMMAND_CENTRE_TEST_FILTER:-}" == "credential-startup" ]]; then
  exit 0
fi

xcrun swiftc \
  "$ROOT/Sources/Credentials.swift" \
  "$ROOT/Tests/KeychainProbe.swift" \
  -o "$BUILD_ROOT/tests/KeychainProbe" \
  -framework Security
codesign --force --sign - --timestamp=none "$BUILD_ROOT/tests/KeychainProbe"
"$BUILD_ROOT/tests/KeychainProbe"
