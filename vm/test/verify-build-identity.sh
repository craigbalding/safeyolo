#!/usr/bin/env bash
# Check production/development helpers from one source without booting a VM.
# Usage: verify-build-identity.sh PRODUCTION_HELPER DEVELOPMENT_HELPER SOURCE
set -euo pipefail
production=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
development=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
source=$3
temporary=$(mktemp -d "$(dirname "$production")/identity-test.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

"$production" verify --profile production --source "$source"
"$development" verify --profile development --source "$source"
(
    cd "$temporary"
    PATH="$(dirname "$production"):$PATH" "$(basename "$production")" verify --profile production --source "$source"
)

# Preserve the genuine bytes. Only the independently writable APFS clone is
# re-signed, adding an entitlement that does not change the checked csflags.
cp -c "$production" "$temporary/extra-entitlement"
cat > "$temporary/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.virtualization</key><true/>
<key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>
PLIST
codesign --force --sign - --options runtime --entitlements "$temporary/entitlements.plist" "$temporary/extra-entitlement"
if "$temporary/extra-entitlement" verify --profile production --source "$source" > "$temporary/direct.out" 2>&1; then
    echo 'Forbidden entitlements were accepted through the executable path' >&2; exit 1
fi
grep 'unexpected entitlements' "$temporary/direct.out"

# Perl's explicit executable form separates the file executed from argv[0].
# This is a test driver, outside the product's build/install execution.
if perl -e 'exec {$ARGV[0]} $ARGV[1], @ARGV[2..$#ARGV] or die "exec: $!"' \
    "$temporary/extra-entitlement" "$production" verify --profile production --source "$source" \
    > "$temporary/spoofed.out" 2>&1; then
    echo 'Forbidden entitlements were accepted with a substituted argv[0]' >&2; exit 1
fi
grep 'unexpected entitlements' "$temporary/spoofed.out"
echo 'PASS helper identity: PATH invocation, genuine profiles and substituted argv[0] refusal'
