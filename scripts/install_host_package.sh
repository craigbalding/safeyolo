#!/usr/bin/env bash
# Install an unpacked native bundle through the ordinary native installer.
set -euo pipefail
package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$package_dir/install_native.sh" --bundle "$package_dir" "$@"
