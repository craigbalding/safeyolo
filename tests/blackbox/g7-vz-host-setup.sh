#!/usr/bin/env bash
# Test-local ordinary Codex setup followed by a nonsecret supervised marker.
set -euo pipefail
: "${SAFEYOLO_CONFIG_DIR:?use native agent create --host-script}"
: "${SAFEYOLO_AGENT_HOME:?use native agent create --host-script}"
fixture_dir=$(cd -- "$(dirname -- "$0")" && pwd)
"$SAFEYOLO_CONFIG_DIR/assets/contrib/codex-host-setup.sh"
install -m 0755 "$SAFEYOLO_AGENT_HOME/.safeyolo-command" "$SAFEYOLO_AGENT_HOME/.g7-codex-command"
install -m 0755 "$fixture_dir/g7-vz-marker.sh" "$SAFEYOLO_AGENT_HOME/.safeyolo-command"
