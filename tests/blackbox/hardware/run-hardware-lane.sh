#!/bin/bash
# Reuse the reviewed #889 credential filter and maintained installed sections.
set -euo pipefail
[[ $# == 6 ]] || { echo 'Usage: run-hardware-lane.sh CHECKOUT CONTROLLER_SHA LANE INPUTS SELECTION_SHA256 REPORTS' >&2; exit 64; }
runtime=()
for name in HOME USER PATH SHELL TMPDIR LANG LC_ALL SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy UV_CACHE_DIR SAFEYOLO_COORD_NATS_BINARY SAFEYOLO_GUEST_TEST_INPUTS SAFEYOLO_VZ_TEST_RUNNER SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS SAFEYOLO_BLACKBOX_STATE_PARENT; do
    if declare -p "$name" >/dev/null 2>&1; then runtime+=("$name=${!name}"); fi
done
exec env -i "${runtime[@]}" BASH_ENV=/dev/null /bin/bash -c '
    set -euo pipefail
    checkout=$1; controller=$2; lane=$3; inputs=$4; digest=$5; reports=$6
    [[ $controller =~ ^[0-9a-f]{40}$ && $digest =~ ^[0-9a-f]{64}$ ]]
    case $lane in kvm) ;; vz) export UV_OFFLINE=1 UV_PYTHON_DOWNLOADS=never ;; *) exit 64;; esac
    test "$(git -C "$checkout" rev-parse HEAD)" = "$controller"
    test -z "$(git -C "$checkout" status --porcelain)"
    "$checkout/.venv/bin/python" -c '\''import hashlib,sys; assert hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()==sys.argv[2]'\'' "$inputs/selection.json" "$digest"
    cd "$checkout"
    exec .venv/bin/python tests/blackbox/retained_inputs.py run --lane "$lane" --yes \
        --selection "$inputs/selection.json" --guest-archive "$inputs/guest.tar.zst" --artifacts "$reports"
' run-hardware-lane "$@"
