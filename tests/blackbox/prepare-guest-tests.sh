#!/usr/bin/env bash
# Run as guest root in an owned blackbox fixture, after the guest is ready.
set -euo pipefail
if ! python3 -m pip --version >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-pip
    elif command -v apk >/dev/null 2>&1; then
        apk add python3 py3-pip
    else
        echo 'The test fixture needs Python, pip, pytest, httpx and pytest-timeout.' >&2
        exit 1
    fi
fi
# Constrain the selected packages and their dependencies to the same lock as
# the host runner. No compiler or unrelated host test dependency is required.
constraints=$(mktemp)
trap 'rm -f -- "$constraints"' EXIT
python3 - > "$constraints" <<'PY'
import tomllib
from pathlib import Path

lock = tomllib.loads(Path('/workspace/uv.lock').read_text())
for package in lock['package']:
    print(f"{package['name']}=={package['version']}")
PY
python3 -m pip install --break-system-packages -c "$constraints" pytest httpx pytest-timeout
python3 -c 'import pytest, httpx, pytest_timeout'
