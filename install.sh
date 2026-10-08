#!/usr/bin/env bash
# Use the same fresh native installer from a source checkout or unpacked bundle.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$repository/scripts/install_native.sh" "$@"
