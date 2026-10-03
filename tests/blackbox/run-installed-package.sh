#!/bin/bash
# Host package witness. No rootfs bootstrap or guest-isolation claim.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
if [ "$(uname -s)" = "Linux" ] && ! command -v runsc >/dev/null 2>&1; then
    echo "ERROR: the current installed Linux launcher requires runsc, even for this host-only witness" >&2
    exit 2
fi
REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
PACKAGE_DIR="$(mktemp -d "$HOME/sy-package.XXXXXX")"
export UV_TOOL_DIR="$PACKAGE_DIR/uv-tools"
export UV_TOOL_BIN_DIR="$PACKAGE_DIR/bin"
export SAFEYOLO_CONFIG_DIR="$PACKAGE_DIR/prepared"
export SAFEYOLO_LOGS_DIR="$SAFEYOLO_CONFIG_DIR/logs"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
export CARGO_BUILD_JOBS=1
unset SAFEYOLO_TMUX_BIN
ARTIFACTS="${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:-$SCRIPT_DIR/artifacts/installed-package}"
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} --basetemp=$PACKAGE_DIR/p"
mkdir -p "$ARTIFACTS"
"$SCRIPT_DIR/run-lane.sh" proxy --prepare-only
export PATH="$UV_TOOL_BIN_DIR:$REPO_ROOT/.venv/bin:$PATH"
export SAFEYOLO_CONFIG_DIR="$PACKAGE_DIR/instance"
export SAFEYOLO_LOGS_DIR="$SAFEYOLO_CONFIG_DIR/logs"
export SAFEYOLO_COORD_DATA_DIR="$SAFEYOLO_CONFIG_DIR/data/coord"
export SAFEYOLO_NATS_TEST_INSTANCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
unset SAFEYOLO_RUST_PROXY
safeyolo init --no-interactive
python3 - "$PACKAGE_DIR/prepared" "$SAFEYOLO_CONFIG_DIR" "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from installed_sections import copy_prepared_runtime
copy_prepared_runtime(Path(sys.argv[1]), Path(sys.argv[2]))
PY
if [ -f "$SAFEYOLO_CONFIG_DIR/bin/safeyolo-tmux" ]; then
    export SAFEYOLO_TMUX_BIN="$SAFEYOLO_CONFIG_DIR/bin/safeyolo-tmux"
fi
touch "$SAFEYOLO_CONFIG_DIR/.safeyolo-platform-smoke"
python3 - "$SAFEYOLO_CONFIG_DIR/config.yaml" <<'PY'
import sys
from pathlib import Path
import yaml
path = Path(sys.argv[1])
config = yaml.safe_load(path.read_text())
config['proxy'].update(port=0, admin_port=0, web_port=0, upstream_proxy='')
path.write_text(yaml.safe_dump(config, sort_keys=False))
PY
# Host-only registration uses the installed package's metadata writer. The
# ordinary agent-add path provisions a guest rootfs even with --no-run.
python3 - "$(command -v safeyolo)" "$SAFEYOLO_CONFIG_DIR" <<'PY'
import subprocess
import sys
from pathlib import Path
python = Path(sys.argv[1]).read_text().splitlines()[0][2:]
subprocess.run([python, '-I', '-c', '''
import json,sys
from pathlib import Path
from safeyolo.agents_store import save_agent
save_agent('bbpackage', {'agent_id':'ag-installed-package','folder':sys.argv[1]})
(Path(sys.argv[1])/'data/agent_map.json').write_text(json.dumps({'bbpackage':{'ip':'10.4.0.2'}}))
''', sys.argv[2]], check=True)
PY
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
    --rust-config "$SAFEYOLO_CONFIG_DIR/data/native.json" \
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
