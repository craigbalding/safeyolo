#!/bin/bash
# SafeYolo install helper.
#
# Wraps `uv tool install --editable .` with the security-pin overrides that
# mitmproxy's current dependency metadata has not adopted this fix yet (see pyproject
# `[tool.uv]` — `uv tool install` does not apply that block, so the pins have
# to be passed on the CLI).
#
# Keeps the "scary" overrides line out of the user's shell history and
# doesn't require `make` (Ubuntu 24.04 cloud image and other minimal
# distros don't ship it by default; `bash` is universal).
#
# Usage:
#   ./install.sh           first install
#   ./install.sh reinstall pull in upstream changes
#   ./install.sh uninstall remove the tool env
#
# After install, run:  safeyolo bootstrap  (once, to set up guest images).

set -euo pipefail

# Security-pin overrides — MUST stay in sync with pyproject.toml
# [tool.uv] override-dependencies.
UV_OVERRIDES=(
  "h2==4.4.1"
  "flask>=3.1.3"
  "pygments>=2.20.0"
  "cryptography>=50.0.0"
  "msgpack>=1.2.1"
  "pyopenssl>=26.0.0"
  "tornado>=6.5.5"
)

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! command -v uv >/dev/null 2>&1; then
  echo "install.sh: uv not found on PATH — install it first: https://docs.astral.sh/uv/" >&2
  exit 1
fi

action="${1:-install}"

case "$action" in
  install)
    uv tool install --editable "$REPO_ROOT" \
      --overrides <(printf '%s\n' "${UV_OVERRIDES[@]}")
    ;;
  reinstall)
    uv tool install --editable "$REPO_ROOT" --reinstall \
      --overrides <(printf '%s\n' "${UV_OVERRIDES[@]}")
    ;;
  uninstall)
    uv tool uninstall safeyolo
    ;;
  -h|--help|help)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "install.sh: unknown action '$action' (use install|reinstall|uninstall)" >&2
    exit 2
    ;;
esac

echo
echo "Next: safeyolo bootstrap  (one-time — sets up guest images + host prereqs)"
