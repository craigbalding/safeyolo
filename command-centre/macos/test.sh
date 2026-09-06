#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_ROOT="${SAFEYOLO_COMMAND_CENTRE_BUILD_ROOT:-$ROOT/.build}"
mkdir -p "$BUILD_ROOT/tests"

xcrun swiftc \
  "$ROOT/Sources/Models.swift" \
  "$ROOT/Sources/Credentials.swift" \
  "$ROOT/Sources/Connection.swift" \
  "$ROOT/Tests/ModelTests.swift" \
  -o "$BUILD_ROOT/tests/ModelTests" \
  -framework Security
"$BUILD_ROOT/tests/ModelTests"

xcrun swiftc \
  "$ROOT/Sources/Credentials.swift" \
  "$ROOT/Tests/KeychainProbe.swift" \
  -o "$BUILD_ROOT/tests/KeychainProbe" \
  -framework Security
codesign --force --sign - --timestamp=none "$BUILD_ROOT/tests/KeychainProbe"
"$BUILD_ROOT/tests/KeychainProbe"
