#!/bin/bash
# Host package witness. No rootfs bootstrap or guest-isolation claim.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
PACKAGE_DIR="$(mktemp -d "$HOME/sy-package.XXXXXX")"
export SAFEYOLO_CONFIG_DIR="$PACKAGE_DIR/prepared"
export SAFEYOLO_LOGS_DIR="$SAFEYOLO_CONFIG_DIR/logs"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export CARGO_BUILD_JOBS=1
ARTIFACTS="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts/installed-package}"
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} --basetemp=$PACKAGE_DIR/p"
mkdir -p "$ARTIFACTS"
"$SCRIPT_DIR/run-lane.sh" proxy --prepare-only
export PATH="$PACKAGE_DIR/prepared/bin:$REPO_ROOT/.venv/bin:$PATH"
export PYTHONPATH="$REPO_ROOT/tests/reference:$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"
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
python3 - "$SAFEYOLO_CONFIG_DIR/config.toml" <<'PY_CONFIG'
import sys
from pathlib import Path
import tomlkit
path = Path(sys.argv[1])
config = tomlkit.parse(path.read_text())
config['admin_port'] = 0
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
python3 "$SCRIPT_DIR/installed_host_smoke.py" --mode smoke \
    --cli "$(command -v safeyolo)" --rust-bin "$INSTALLED_BINARY" \
    --rust-config "$SAFEYOLO_CONFIG_DIR/config.toml" \
    --config-dir "$SAFEYOLO_CONFIG_DIR" --agent bbpackage \
    --install-commit "$REVISION" --output "$ARTIFACTS/host-package.json"
# The full platform contract suite runs once overnight. These three existing
# nodes check only the additional installed native HTTPS package claim.
SAFEYOLO_RUST_PROXY="$INSTALLED_BINARY" python3 -m pytest -q \
    "$REPO_ROOT/tests/proxy_contracts/test_https_contract.py::test_https_origin_verification" \
    --proxy-backend rust --junitxml="$ARTIFACTS/packaged-https.xml"

python3 "$SCRIPT_DIR/installed_state_transition.py" --native \
    --cli "$(command -v safeyolo)" --install-commit "$REVISION" \
    --state-parent "$PACKAGE_DIR" --config-dir "$PACKAGE_DIR/continuity" \
    --prepared-config "$PACKAGE_DIR/prepared" --output "$ARTIFACTS/installed-continuity.json"
