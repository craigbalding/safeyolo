#!/bin/bash
# Invoke the maintained suite in an already prepared, owned hardware environment.
set -euo pipefail
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 CHECKOUT FULL_SHA {kvm|vz} ARTIFACTS [run-installed.sh options]" >&2
    exit 2
fi
runtime=()
for name in HOME USER PATH SHELL TMPDIR LANG LC_ALL SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy UV_CACHE_DIR CARGO_HOME RUSTUP_HOME; do
    if declare -p "$name" >/dev/null 2>&1; then runtime+=("$name=${!name}"); fi
done
exec env -i "${runtime[@]}" BASH_ENV=/dev/null /bin/bash -c '
    set -euo pipefail
    checkout=$1; selected_sha=$2; lane=$3; artifacts=$4; shift 4
    [[ "$selected_sha" =~ ^[0-9a-f]{40}$ ]]
    case "$lane" in
        kvm) ;;
        vz) export UV_OFFLINE=1 UV_PYTHON_DOWNLOADS=never CARGO_BUILD_JOBS=1 ;;
        *) exit 2 ;;
    esac
    test "$(git -C "$checkout" rev-parse HEAD)" = "$selected_sha"
    test -z "$(git -C "$checkout" status --porcelain)"
    cd "$checkout"
    exec ./tests/blackbox/run-installed.sh "$lane" --install-commit "$selected_sha" --artifacts "$artifacts" "$@"
' run-hardware-lane "$@"
