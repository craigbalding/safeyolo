#!/usr/bin/env bash
# CI guard: `host.docker.internal` must not appear in current-runtime
# templates, config, docs, or source (see #328). The following are
# intentionally excluded:
#
#   - contrib/           Docker-only optional tooling (opt-in, banner)
#   - THIS script        (documents what it enforces)
#   - narrow allowlist   (comments documenting the removal / regression tests)
#
# Exits 0 if clean, 1 (with the offending file:line list) otherwise.

set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
    echo "no-docker-host: ripgrep (rg) required" >&2
    exit 2
fi

# Files where the token appears as historical/regression documentation.
# Any NEW occurrence outside this allowlist is a real regression.
ALLOWLIST=(
    "scripts/no-docker-host.sh"
    "tests/test_admin_shield.py"
)

hits=$(
    rg --line-number --with-filename 'host\.docker\.internal' \
        cli config docs tests scripts SECURITY.md README.md 2>/dev/null || true
)

if [ -z "$hits" ]; then
    echo "no host.docker.internal in current-runtime paths."
    exit 0
fi

# Filter out allowlisted paths.
unexpected=$(
    printf '%s\n' "$hits" | while IFS= read -r line; do
        path="${line%%:*}"
        allowed=0
        for a in "${ALLOWLIST[@]}"; do
            if [ "$path" = "$a" ]; then
                allowed=1
                break
            fi
        done
        if [ "$allowed" -eq 0 ]; then
            printf '%s\n' "$line"
        fi
    done
)

if [ -n "$unexpected" ]; then
    echo "host.docker.internal reintroduced (outside contrib/ and known regression sites):"
    echo "$unexpected"
    exit 1
fi

echo "no host.docker.internal in current-runtime paths (allowlisted regression sites only)."
