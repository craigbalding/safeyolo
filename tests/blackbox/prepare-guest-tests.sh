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
# Exported from the host runner's lock. Include hashes for each dependency and
# retain interpreter markers, wheels and source archives from that lock.
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python3 -m pip install --break-system-packages --require-hashes -r "$script_dir/guest-requirements.txt"
python3 -c 'import pytest, httpx, pytest_timeout'
