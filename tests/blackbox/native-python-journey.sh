#!/usr/bin/env bash
# Run only on an owned Ubuntu host and guest tree provisioned without Python.
# Python observers stay on the external harness host. See README.md.
set -euo pipefail
umask 077
if (($# != 4)); then
  echo 'Usage: native-python-journey.sh BUNDLE PLATFORM_ASSETS FRESH_STATE SOURCE_COMMIT' >&2
  exit 2
fi
bundle=$(realpath "$1") assets=$(realpath "$2") state=$(realpath -m "$3") revision=$4
[[ ! -e $state && $revision =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Use a fresh state directory and a full source commit' >&2; exit 2;
}
[[ -x $bundle/install.sh && -d $assets/rootfs-tree ]] || {
  echo 'A checked native bundle and prepared Python-free guest rootfs-tree are required' >&2; exit 2;
}
for tool in runsc newuidmap newgidmap setfacl unshare curl; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 2; }
done
mkdir -p "$state/workspace"
root=$state/instance
peer=$state/peer
export SAFEYOLO_RUNSC_PLATFORM=systrap
cli=$root/bin/safeyolo
agent=r5check
instance() {
  local selected=$1; shift
  SAFEYOLO_CONFIG_DIR=$selected SAFEYOLO_LOGS_DIR=$selected/logs \
    SAFEYOLO_COORD_DATA_DIR=$selected/data/coord \
    SAFEYOLO_NATS_TEST_INSTANCE="${selected##*/}-r5" \
    "$selected/bin/safeyolo" --root "$selected" "$@"
}
cleanup() {
  local original=$? failed=0
  trap - EXIT
  if [[ -x $cli && -f $root/config.toml ]]; then
    if [[ -d $root/agents/$agent ]]; then
      instance "$root" agent stop "$agent" || failed=1
      instance "$root" agent status "$agent" > "$state/guest-after-stop.json" || failed=1
      grep -q '"runtime_state": *"stopped"' "$state/guest-after-stop.json" || failed=1
      for file in container.pid vm.pid; do
        [[ ! -e $root/agents/$agent/$file ]] || failed=1
      done
    fi
    instance "$root" stop || failed=1
    instance "$root" status > "$state/host-after-stop.json" || failed=1
    grep -q '"proxy_state": "unavailable"' "$state/host-after-stop.json" || failed=1
    [[ ! -e $root/data/coord/nats/process.json ]] || failed=1
  fi
  if [[ -x $peer/bin/safeyolo && -f $peer/config.toml ]]; then
    if [[ -f $state/peer-process.json ]]; then
      instance "$peer" status > "$state/peer-after.json" || failed=1
      grep -q '"proxy_state": "running"' "$state/peer-after.json" || failed=1
      cmp "$state/peer-process.json" "$peer/data/proxy-process.json" || failed=1
      cmp "$state/peer-policy.toml" "$peer/policy.toml" || failed=1
      instance "$peer" approvals list --json > "$state/peer-admin-after.json" || failed=1
    fi
    instance "$peer" stop || failed=1
    instance "$peer" status > "$state/peer-stopped.json" || failed=1
    grep -q '"proxy_state": "unavailable"' "$state/peer-stopped.json" || failed=1
    [[ ! -e $peer/data/coord/nats/process.json ]] || failed=1
  fi
  printf 'original_exit=%s cleanup_failed=%s\n' "$original" "$failed" > "$state/cleanup.txt"
  if ((original)); then exit "$original"; fi
  if ((failed)); then exit 2; fi
}
trap cleanup EXIT
for selected in "$root" "$peer"; do
  "$bundle/install.sh" --root "$selected" --platform-assets "$assets"
  # Each disposable instance selects an available endpoint.
  sed 's/^admin_port = .*/admin_port = 0/' "$selected/config.toml" > "$state/config.new"
  mv "$state/config.new" "$selected/config.toml"
  if [[ -n ${SAFEYOLO_COORD_NATS_BINARY:-} ]]; then
    instance "$selected" coord start --binary "$SAFEYOLO_COORD_NATS_BINARY"
  fi
done
"$cli" --version | tee "$state/host-identity.txt" | grep -F "commit=$revision profile="
# Coord is installed on the host. Harness setup stages its guest executable
# under /home/agent/.safeyolo; this ordinary agent does not select a harness.
"$root/bin/safeyolo-coord" --version | tee "$state/coord-identity.txt" | grep -F "commit=$revision profile="
instance "$peer" start
cp "$peer/data/proxy-process.json" "$state/peer-process.json"
cp "$peer/policy.toml" "$state/peer-policy.toml"
instance "$peer" approvals list --json > "$state/peer-admin-before.json"
instance "$root" agent create "$agent" --workspace "$state/workspace"
instance "$root" start
instance "$root" status | tee "$state/host-status.json" | grep '"proxy_state": "running"'
instance "$root" doctor | tee "$state/host-doctor.json" | grep '"proxy_state": "running"'
instance "$root" agent start "$agent" --sandbox-only
instance "$root" agent status "$agent" > "$state/guest-status.json"
grep -q '"runtime_state": *"running"' "$state/guest-status.json"
# Keep this deliberate violation outside the clean guest observation window.
if instance "$root" agent shell "$agent" -c 'exec strace -f -s 4096 -e trace=execve,execveat -o /home/agent/r5-control.exec /usr/bin/env python3 -c "pass"' \
    > "$state/guest-control.stdout" 2> "$state/guest-control.stderr"; then
  echo 'Python ran in the selected guest boundary' >&2; exit 1
else
  control_exit=$?
  [[ $control_exit == 127 ]] || { echo "Guest detector control exited $control_exit, expected 127" >&2; exit 1; }
fi
test -s "$root/agents/$agent/home/r5-control.exec"
# This command uses the maintained native shell transport. Its execution trace
# covers the selected guest shell/helper/API lineage, not PID-1 boot or recovery.
instance "$root" agent shell "$agent" -c 'exec strace -f -s 4096 -e trace=execve,execveat -o /home/agent/r5-guest.exec /bin/bash -c '\''
  set -euo pipefail
  test "$(id -u)" = 1000
  /safeyolo/safeyolo-guest --version
  agent_token=$(cat /app/agent_token)
  printf "Authorization: Bearer %s\n" "$agent_token" |
    curl --fail --silent --show-error --header @- http://_safeyolo.proxy.internal/health
'\''' | tee "$state/guest-api.txt"
[[ $(grep -Fc "commit=$revision profile=" "$state/guest-api.txt") == 1 ]] || exit 1
grep -q '"agent_api": *"ok"' "$state/guest-api.txt"
test -s "$root/agents/$agent/home/r5-guest.exec"
echo 'Completed native installation, host readiness, guest identity and authenticated API request; cleanup follows'
