#!/bin/bash
# SafeYolo install helper.
#
# Wraps `uv tool install --editable .` with the security-pin overrides that
# mitmproxy hasn't cut a release for yet (see pyproject `[tool.uv]` —
# `uv tool install` does not apply that block, so the pins have to be passed
# on the CLI).
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
  "flask>=3.1.3"
  "pygments>=2.20.0"
  "cryptography>=50.0.0"
  "msgpack>=1.2.1"
  "pyopenssl>=26.0.0"
  "tornado>=6.5.5"
)

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

read_python_requirement() {
  local requirement

  if [[ ! -r "$REPO_ROOT/pyproject.toml" ]]; then
    echo "install.sh: cannot read the project's pyproject.toml" >&2
    return 1
  fi

  # Keep the installer bound to the PEP 621 project metadata.  Do not copy a
  # Python version here: the declared requires-python range is the support
  # boundary for the package and is also what uv resolves against.
  requirement="$(awk '
    $0 == "[project]" { in_project = 1; next }
    in_project && /^\[/ { exit }
    in_project && /^[[:space:]]*requires-python[[:space:]]*=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      quote = substr(value, 1, 1)
      if (quote != "\"" && quote != "\047") {
        next
      }
      value = substr(value, 2)
      sub("[[:space:]]*" quote "[[:space:]]*$", "", value)
      print value
      exit
    }
  ' "$REPO_ROOT/pyproject.toml")"

  if [[ -z "$requirement" ]]; then
    echo "install.sh: pyproject.toml has no readable [project] requires-python range" >&2
    return 1
  fi

  printf '%s\n' "$requirement"
}

select_supported_python() {
  local requirement="$1"
  local interpreter

  if interpreter="$(uv python find "$requirement" --resolve-links 2>/dev/null)" \
    && [[ -n "$interpreter" ]]; then
    printf '%s\n' "$interpreter"
    return 0
  fi

  echo "install.sh: no installed Python satisfies $requirement; asking uv to acquire one" >&2
  if ! uv python install "$requirement" >/dev/null 2>&1; then
    echo "install.sh: unable to acquire a Python interpreter satisfying $requirement" >&2
    echo "install.sh: install a supported Python or allow uv Python downloads, then retry" >&2
    return 1
  fi

  if ! interpreter="$(uv python find "$requirement" --resolve-links 2>/dev/null)" \
    || [[ -z "$interpreter" ]]; then
    echo "install.sh: uv acquired Python, but could not select one satisfying $requirement" >&2
    return 1
  fi

  printf '%s\n' "$interpreter"
}

install_tool() {
  local action="$1"
  local python_requirement
  local python_interpreter
  local tool_args=(--python)

  python_requirement="$(read_python_requirement)" || return 1
  python_interpreter="$(select_supported_python "$python_requirement")" || return 1
  tool_args+=("$python_interpreter" --editable "$REPO_ROOT")

  if [[ "$action" == "reinstall" ]]; then
    tool_args+=(--reinstall)
  fi
  tool_args+=(--overrides <(printf '%s\n' "${UV_OVERRIDES[@]}"))

  # Keep uv's potentially verbose failure output (which can contain host or
  # index details) out of the bounded installer diagnostic below.
  if ! uv tool install "${tool_args[@]}" >/dev/null 2>&1; then
    echo "install.sh: uv tool $action failed with a Python interpreter satisfying $python_requirement" >&2
    echo "install.sh: check uv package-index access and dependency resolution, then retry" >&2
    return 1
  fi
}

if ! command -v uv >/dev/null 2>&1; then
  echo "install.sh: uv not found on PATH — install it first: https://docs.astral.sh/uv/" >&2
  exit 1
fi

action="${1:-install}"

case "$action" in
  install)
    install_tool install
    ;;
  reinstall)
    install_tool reinstall
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
