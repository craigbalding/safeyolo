#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_ROOT="${SAFEYOLO_COMMAND_CENTRE_BUILD_ROOT:-$ROOT/.build}"
APP="$BUILD_ROOT/SafeYolo Command Centre.app"
EXECUTABLE="$APP/Contents/MacOS/SafeYoloCommandCentre"
ICON_SOURCE="$ROOT/Resources/AppIcon.svg"
ICONSET="$BUILD_ROOT/AppIcon.iconset"
ICON="$APP/Contents/Resources/AppIcon.icns"

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
plutil -lint "$ROOT/Info.plist"

mkdir -p "$ICONSET"
make_icon() {
  local points="$1"
  local pixels="$2"
  local suffix="$3"
  sips -s format png -z "$pixels" "$pixels" "$ICON_SOURCE" \
    --out "$ICONSET/icon_${points}x${points}${suffix}.png" >/dev/null
}
make_icon 16 16 ""
make_icon 16 32 "@2x"
make_icon 32 32 ""
make_icon 32 64 "@2x"
make_icon 128 128 ""
make_icon 128 256 "@2x"
make_icon 256 256 ""
make_icon 256 512 "@2x"
make_icon 512 512 ""
make_icon 512 1024 "@2x"
iconutil -c icns "$ICONSET" -o "$ICON"
test -s "$ICON"

xcrun swiftc -parse-as-library \
  "$ROOT/Sources/Models.swift" \
  "$ROOT/Sources/Credentials.swift" \
  "$ROOT/Sources/Connection.swift" \
  "$ROOT/Sources/Client.swift" \
  "$ROOT/Sources/UI.swift" \
  "$ROOT/Sources/Controller.swift" \
  "$ROOT/Sources/App.swift" \
  -o "$EXECUTABLE" \
  -framework SwiftUI \
  -framework AppKit \
  -framework Security
install -m 0644 "$ROOT/Info.plist" "$APP/Contents/Info.plist"
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --strict --verbose=2 "$APP"

printf 'app=%s\n' "$APP"
shasum -a 256 "$EXECUTABLE"
shasum -a 256 "$ICON"
