#!/usr/bin/env bash
# Give this private tmux its packaged libraries without changing the caller.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
case "$(uname -s)" in
  Darwin) export DYLD_LIBRARY_PATH="$root/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}";;
  Linux) export LD_LIBRARY_PATH="$root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}";;
esac
exec "$root/libexec/tmux" "$@"
