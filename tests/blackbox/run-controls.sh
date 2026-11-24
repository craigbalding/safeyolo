#!/usr/bin/env bash
# Run a maintained process selection or an explicitly prepared installed driver.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(cd -- "$script_dir/../.." && pwd)
cd -- "$repository"
phase=${1:-}
[[ -n $phase ]] || { echo "Usage: $0 {named-checks|managed-feeds|before-after|mediated-services|host-execution|policy-recipe|sudo-disclosure|hyperlight-services|rootless-preparation|native-authority|tailnet} [options]" >&2; exit 2; }
shift
export SAFEYOLO_BLACKBOX_RUN_ID=${SAFEYOLO_BLACKBOX_RUN_ID:-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')}
export SAFEYOLO_BLACKBOX_LANE=process
export PYTHONPATH="$repository/tests/reference:$repository${PYTHONPATH:+:$PYTHONPATH}"
case $phase in
  native-authority)
    exec uv run --frozen python -m tests.blackbox.native_authority "$@" ;;
  tailnet)
    exec uv run --frozen python -m tests.blackbox.installed_tailnet "$@" ;;
  hyperlight-services)
    exec uv run --frozen python tests/blackbox/host/hyperlight_services.py "$@" ;;
  rootless-preparation)
    if [[ ${1:-} == --boot ]]; then
      shift
      export SAFEYOLO_BLACKBOX_LANE=systrap
      exec uv run --frozen python tests/blackbox/execution_receipt.py \
        --phase rootless-guest --lane systrap --run-id "$SAFEYOLO_BLACKBOX_RUN_ID" "$@"
    fi
    if [[ ${1:-} == --execute ]]; then
      shift
      exec uv run --frozen python tests/blackbox/execution_receipt.py \
        --phase rootless-preparation --lane process --run-id "$SAFEYOLO_BLACKBOX_RUN_ID" "$@"
    fi
    exec uv run --frozen python tests/blackbox/rootless_preparation.py "$@" ;;
  named-checks|managed-feeds|before-after|mediated-services|host-execution) selection=(--native-phase "$phase") ;;
  policy-recipe|sudo-disclosure) selection=(--phase "$phase"); set -- -- "$@" ;;
  *) echo "Unknown control selection: $phase" >&2; exit 2 ;;
esac
artifacts=${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:?Set SAFEYOLO_BLACKBOX_ARTIFACTS_DIR to a new disk-backed result directory}
exec uv run --frozen python tests/blackbox/execution_receipt.py "${selection[@]}" \
  --lane process --run-id "$SAFEYOLO_BLACKBOX_RUN_ID" --output "$artifacts/$phase.json" "$@"
