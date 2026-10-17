#!/bin/bash
# Install a supplied archive or prepare the existing source-based host witness.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
HOST_PACKAGE= EXPECTED_SHA256= LANE= GUEST_ARCHIVE= INSTALL_YES=false
INSTALL_ARGUMENTS=()
SECTIONS=()
while (($#)); do
    case "$1" in
        --package|--sha256|--platform-assets|--guest-index|--guest-archive|--lane|--section)
            (($# >= 2)) || { echo "$1 requires a value" >&2; exit 2; }
            case "$1" in
                --package) HOST_PACKAGE=$2;;
                --sha256) EXPECTED_SHA256=$2;;
                --platform-assets) INSTALL_ARGUMENTS+=(--platform-assets "$2");;
                --guest-index) INSTALL_ARGUMENTS+=(--guest-index "$2");;
                --guest-archive) GUEST_ARCHIVE=$2;;
                --lane) LANE=$2;;
                --section) SECTIONS+=(--section "$2");;
            esac
            shift 2;;
        --no-guest-download) INSTALL_ARGUMENTS+=(--no-guest-download); shift;;
        --yes) INSTALL_ARGUMENTS+=(--yes); INSTALL_YES=true; shift;;
        --help)
            echo 'Usage: run-installed-package.sh [--package HOST.tar.gz --sha256 DIGEST [--platform-assets DIR | --guest-index sha256:DIGEST | --guest-archive FILE | --no-guest-download] [--yes] [--lane systrap|kvm|vz [--section NAME ...]]]'
            echo 'Use a supported disposable host, a checksum from the release, and this checkout’s prepared Python test environment. The archive’s installer acquires the default guest unless explicit offline or proxy-only inputs are selected. No source build is used with --package. --lane also runs the maintained isolation/lifecycle sections; the host must provide that backend’s runtime prerequisites.'
            echo 'Repeat --section to select maintained sections for the lane. Omit --section to keep the lane’s isolation/lifecycle or isolation/ingress default.'
            echo '--yes accepts the installer’s host preparation changes on the supplied disposable host.'
            echo '--guest-index pins native acquisition. --guest-archive requires SAFEYOLO_BLACKBOX_INPUT_SELECTION from the retained-artifact runner.'
            echo 'Without --package, preserve the source-based proxy-only witness. Each run keeps its owned state under HOME and writes the existing smoke reports; no host-only result proves guest isolation.'
            exit 0;;
        *) echo "Unknown argument: $1" >&2; exit 2;;
    esac
done
if [[ -n $HOST_PACKAGE ]]; then
    [[ -f $HOST_PACKAGE && $EXPECTED_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo '--package requires an existing archive and --sha256 DIGEST' >&2; exit 2; }
elif [[ -n $EXPECTED_SHA256 || -n $LANE || -n $GUEST_ARCHIVE || ${#INSTALL_ARGUMENTS[@]} != 0 ]]; then
    echo 'Archive options require --package' >&2; exit 2
fi
case "$LANE:$(uname -s)" in :*|systrap:Linux|kvm:Linux|vz:Darwin) ;; *) echo 'Unsupported lane/host' >&2; exit 2;; esac
if [[ ${#SECTIONS[@]} != 0 && -z $LANE ]]; then
    echo '--section requires --package and --lane' >&2; exit 2
fi
PACKAGE_DIR="$(mktemp -d "${SAFEYOLO_BLACKBOX_STATE_PARENT:-$HOME}/sy-package.XXXXXX")"
echo "Owned package state: $PACKAGE_DIR"
# The separate test interpreter may be present even on a host with no system Python.
export PATH="$REPO_ROOT/.venv/bin:$PATH"
export SAFEYOLO_CONFIG_DIR="$PACKAGE_DIR/prepared"
export SAFEYOLO_LOGS_DIR="$SAFEYOLO_CONFIG_DIR/logs"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export CARGO_BUILD_JOBS=1
ARTIFACTS="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts/installed-package}"
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} --basetemp=$PACKAGE_DIR/p"
mkdir -p "$ARTIFACTS"
if [[ -n $HOST_PACKAGE ]]; then
    source "$REPO_ROOT/scripts/native_package.sh"
    export SAFEYOLO_PACKAGE_INSTALL_STARTED=$(date +%s)
    [[ $(file_sha256 "$HOST_PACKAGE") == "$EXPECTED_SHA256" ]] || { echo 'Host archive checksum differs' >&2; exit 1; }
    echo "Host archive: $HOST_PACKAGE sha256:$EXPECTED_SHA256"
    mkdir "$PACKAGE_DIR/archive"
    tar -xzf "$HOST_PACKAGE" -C "$PACKAGE_DIR/archive"
    packages=("$PACKAGE_DIR/archive/"*)
    [[ ${#packages[@]} == 1 && -f ${packages[0]}/install.sh ]] || { echo 'Archive must contain one native host bundle' >&2; exit 2; }
    if [[ -n $GUEST_ARCHIVE ]]; then
        verify_native_package "${packages[0]}"
        [[ -n ${SAFEYOLO_BLACKBOX_INPUT_SELECTION:-} ]] || { echo '--guest-archive requires a frozen input selection' >&2; exit 2; }
        prepare_options=()
        if $INSTALL_YES; then prepare_options+=(--yes); fi
        platform_assets=$(python3 "$SCRIPT_DIR/retained_inputs.py" prepare-guest \
            --selection "$SAFEYOLO_BLACKBOX_INPUT_SELECTION" --archive "$GUEST_ARCHIVE" \
            --bundle "${packages[0]}" --root "$SAFEYOLO_CONFIG_DIR" --directory "$PACKAGE_DIR/guest" ${prepare_options[@]+"${prepare_options[@]}"})
        INSTALL_ARGUMENTS+=(--platform-assets "$platform_assets")
    fi
    INSTALL_STARTED=$SECONDS
    "${packages[0]}/install.sh" --root "$SAFEYOLO_CONFIG_DIR" --command-dir "$SAFEYOLO_CONFIG_DIR/commands" ${INSTALL_ARGUMENTS[@]+"${INSTALL_ARGUMENTS[@]}"}
    if [[ -n ${SAFEYOLO_BLACKBOX_INPUT_SELECTION:-} ]]; then
        python3 "$SCRIPT_DIR/retained_inputs.py" verify-installed \
            --selection "$SAFEYOLO_BLACKBOX_INPUT_SELECTION" --root "$SAFEYOLO_CONFIG_DIR"
    fi
    echo "Native installation elapsed: $((SECONDS - INSTALL_STARTED)) seconds (agent readiness not yet measured)"
    "$SAFEYOLO_CONFIG_DIR/bin/safeyolo" --help >/dev/null
    cat "$SAFEYOLO_CONFIG_DIR/package-info"
    if [[ -f $SAFEYOLO_CONFIG_DIR/share/guest-selection.json ]]; then
        cat "$SAFEYOLO_CONFIG_DIR/share/guest-selection.json"
    fi
    nats=()
    [[ -z ${SAFEYOLO_COORD_NATS_BINARY:-} ]] || nats+=(--binary "$SAFEYOLO_COORD_NATS_BINARY")
    if [[ $LANE == vz ]]; then
        nats+=(--client-port 46370 --monitor-port 46372)
    fi
    "$SAFEYOLO_CONFIG_DIR/bin/safeyolo" --root "$SAFEYOLO_CONFIG_DIR" coord start ${nats[@]+"${nats[@]}"}
    "$SAFEYOLO_CONFIG_DIR/bin/safeyolo" --root "$SAFEYOLO_CONFIG_DIR" coord stop
else
    "$SCRIPT_DIR/run-lane.sh" proxy --prepare-only
fi
export PATH="$PACKAGE_DIR/prepared/bin:$PACKAGE_DIR/prepared/libexec:$REPO_ROOT/.venv/bin:$PATH"
export PYTHONPATH="$REPO_ROOT/tests/reference:$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"
REVISION=$(python3 - "$SCRIPT_DIR" "$PACKAGE_DIR/prepared/bin/safeyolo" <<'PY_IDENTITY'
import sys
sys.path.insert(0, sys.argv[1])
from installed_host_smoke import _cli_identity
print(_cli_identity(sys.argv[2])["source_revision"])
PY_IDENTITY
)
if [[ -n $LANE ]]; then
    if [[ ${#SECTIONS[@]} == 0 && ${SAFEYOLO_BLACKBOX_FULL_SECTIONS:-} != 1 ]]; then
        SECTIONS=(--section isolation --section lifecycle)
        [[ $LANE != kvm ]] || SECTIONS=(--section isolation --section ingress)
    fi
    "$SCRIPT_DIR/run-installed.sh" "$LANE" --prepared-config "$PACKAGE_DIR/prepared" \
        --install-commit "$REVISION" ${SECTIONS[@]+"${SECTIONS[@]}"} --artifacts "$ARTIFACTS/guest"
    # The nightly path uses the maintained complete lane, including continuity
    # where selected by SECTIONS. Do not append a second package/continuity run.
    if [[ ${SAFEYOLO_BLACKBOX_FULL_SECTIONS:-} == 1 ]]; then exit 0; fi
fi
export SAFEYOLO_CONFIG_DIR="$PACKAGE_DIR/instance"
export SAFEYOLO_LOGS_DIR="$SAFEYOLO_CONFIG_DIR/logs"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
unset SAFEYOLO_RUST_PROXY
python3 - "$PACKAGE_DIR/prepared" "$SAFEYOLO_CONFIG_DIR" "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from installed_sections import copy_prepared_nats, prepare_native_instance
source, root = Path(sys.argv[1]), Path(sys.argv[2])
prepare_native_instance(source, root)
copy_prepared_nats(source, root)
PY
touch "$SAFEYOLO_CONFIG_DIR/.safeyolo-platform-smoke"
python3 - "$SAFEYOLO_CONFIG_DIR/config.toml" "$LANE" <<'PY_CONFIG'
import sys
from pathlib import Path
import tomlkit
path = Path(sys.argv[1])
config = tomlkit.parse(path.read_text())
config['admin_port'] = 46371 if sys.argv[2] == 'vz' else 0
config['parent_proxy'] = ''
config['listeners'] = [{'agent_id': 'bbpackage', 'socket_path': str(path.parent / 'data/bbpackage.sock')}]
path.write_text(tomlkit.dumps(config))
PY_CONFIG
INSTALLED_BINARY="$(python3 - "$SCRIPT_DIR" "$(command -v safeyolo)" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from installed_host_smoke import _installed_rust_binary
binary, _ = _installed_rust_binary(sys.argv[2])
print(binary)
PY
)"
smoke_ports=() continuity_ports=()
if [[ $LANE == vz ]]; then
    smoke_ports=(--http-port 46373 --nats-client-port 46370 --nats-monitor-port 46372)
    continuity_ports=(--origin-bind 127.0.0.1 --http-port 46373 --https-port 46374 --oauth-port 46375 --admin-port 46371 --nats-client-port 46370 --nats-monitor-port 46372)
fi
python3 "$SCRIPT_DIR/installed_host_smoke.py" --mode smoke ${smoke_ports[@]+"${smoke_ports[@]}"} \
    --cli "$(command -v safeyolo)" --rust-bin "$INSTALLED_BINARY" \
    --rust-config "$SAFEYOLO_CONFIG_DIR/config.toml" \
    --config-dir "$SAFEYOLO_CONFIG_DIR" --agent bbpackage \
    --install-commit "$REVISION" --output "$ARTIFACTS/host-package.json"
# The full platform contract suite runs once overnight. These existing nodes
# check only the additional installed native HTTPS package claim.
if [[ $LANE != vz ]]; then
    SAFEYOLO_RUST_PROXY="$INSTALLED_BINARY" python3 -m pytest -q \
        "$REPO_ROOT/tests/proxy_contracts/test_https_contract.py::test_https_origin_verification" \
        --proxy-backend rust --junitxml="$ARTIFACTS/packaged-https.xml"
else
    # Physical VZ uses assigned fixture ports. The maintained lifecycle and
    # continuity sections cover TLS there; these hosted controls bind ephemeral ports.
    echo 'Physical VZ TLS uses the fixed-port lifecycle and continuity probes'
fi

python3 "$SCRIPT_DIR/installed_state_transition.py" --native \
    --cli "$(command -v safeyolo)" --install-commit "$REVISION" \
    --state-parent "$PACKAGE_DIR" --config-dir "$PACKAGE_DIR/continuity" \
    --prepared-config "$PACKAGE_DIR/prepared" --output "$ARTIFACTS/installed-continuity.json" ${continuity_ports[@]+"${continuity_ports[@]}"}
