#!/bin/bash
# Run independent installed sections after one compatible product preparation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
exec python3 "$SCRIPT_DIR/installed_sections.py" "$@"
