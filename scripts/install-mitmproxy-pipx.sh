#!/bin/bash
# install-mitmproxy-pipx.sh — install mitmproxy + addon deps into a pipx venv
#
# Use when `uv sync --all-packages` from the repo root doesn't install
# mitmproxy into the workspace venv (e.g. Python 3.12 resolution quirks).
# SafeYolo's `start_proxy` calls `shutil.which("mitmdump")`, so the pipx
# binary is picked up automatically once it's on PATH.
#
# The pipx mitmproxy venv needs the addons' transitive deps injected
# because mitmdump runs the addons in its own interpreter.

set -euo pipefail

if ! command -v pipx >/dev/null 2>&1; then
    echo "ERROR: pipx not found. Install with: sudo apt install pipx (or brew install pipx)" >&2
    exit 1
fi

if ! pipx runpip mitmproxy --version >/dev/null 2>&1; then
    pipx install mitmproxy
fi
pipx inject --force mitmproxy \
    'h2==4.4.1' \
    pyyaml \
    yarl \
    confusable-homoglyphs \
    pydantic \
    cryptography \
    tomlkit \
    httpx \
    tenacity

h2_version="$(pipx runpip mitmproxy show h2 | awk '$1 == "Version:" {print $2}')"
if [[ "$h2_version" != "4.4.1" ]]; then
    echo "ERROR: mitmproxy pipx environment has h2 ${h2_version:-<missing>}; expected 4.4.1" >&2
    exit 1
fi

echo
echo "mitmproxy + addon deps installed in pipx venv."
echo "Verified: h2 ${h2_version}; mitmdump --version"
