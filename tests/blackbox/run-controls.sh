#!/usr/bin/env bash
# Run one bounded process selection or the existing prepared two-engine driver.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(cd -- "$script_dir/../.." && pwd)
cd -- "$repository"
phase=${1:-}
[[ -n $phase ]] || { echo "Usage: $0 {named-checks|managed-feeds|before-after|mediated-services|policy-recipe|sudo-disclosure|hyperlight-services|rootless-preparation} [options]" >&2; exit 2; }
shift
export SAFEYOLO_BLACKBOX_RUN_ID=${SAFEYOLO_BLACKBOX_RUN_ID:-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')}
export SAFEYOLO_BLACKBOX_LANE=process
export PYTHONPATH="$repository/tests/reference:$repository${PYTHONPATH:+:$PYTHONPATH}"
case $phase in
  hyperlight-services)
    exec uv run --frozen python tests/blackbox/host/hyperlight_services.py "$@" ;;
  rootless-preparation)
    exec uv run --frozen python tests/blackbox/rootless_preparation.py "$@" ;;
  named-checks|managed-feeds|before-after|mediated-services) selection=(--native-phase "$phase") ;;
  policy-recipe|sudo-disclosure) selection=(--phase "$phase"); set -- -- "$@" ;;
  *) echo "Unknown control selection: $phase" >&2; exit 2 ;;
esac
artifacts=${SAFEYOLO_BLACKBOX_ARTIFACTS_DIR:?Set SAFEYOLO_BLACKBOX_ARTIFACTS_DIR to a new disk-backed result directory}
exec uv run --frozen python tests/blackbox/execution_receipt.py "${selection[@]}" \
  --lane process --run-id "$SAFEYOLO_BLACKBOX_RUN_ID" --output "$artifacts/$phase.json" "$@"
