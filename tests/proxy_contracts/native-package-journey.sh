#!/usr/bin/env bash
# Finite package/install/start witness. The test driver stays outside the bundle.
set -euo pipefail
package=$1 state=$2 occupied_port=$3
mkdir -p "$state"
a=$state/a b=$state/b
cleanup() {
  for root in "$a" "$b"; do
    if [[ -x $root/bin/safeyolo && -f $root/config.toml ]]; then
      "$root/bin/tmux" -S "$root/data/package-tmux.sock" kill-server 2>/dev/null || true
      "$root/bin/safeyolo" --root "$root" stop
    fi
  done
}
trap cleanup EXIT
configure() {
  local root=$1 port=$2
  awk -v port="$port" '{if ($1 == "admin_port") print "admin_port = " port; else print}' "$root/config.toml" > "$root/config.new"
  mv "$root/config.new" "$root/config.toml"
}
instance() {
  local root=$1; shift
  SAFEYOLO_NATS_TEST_INSTANCE="${root##*/}-native-package" "$root/bin/safeyolo" --root "$root" "$@"
}

"$package/install.sh" --root "$b"
configure "$b" "$occupied_port"
instance "$b" start
instance "$b" status | grep '"proxy_state": "running"'
instance "$b" policy show > "$state/b-policy-before.json"
cp "$b/data/proxy-process.json" "$state/b-process-before.json"

# A missing input is rejected before creating the instance, then the same
# ordinary install command succeeds when that input is restored.
mv "$package/bin/safeyolo-proxy" "$state/missing-proxy"
if "$package/install.sh" --root "$a" > "$state/missing.stdout" 2> "$state/missing.stderr"; then
  echo 'Missing proxy was incorrectly accepted' >&2; exit 1
fi
grep 'required artifact is missing.*safeyolo-proxy' "$state/missing.stderr"
[[ ! -e $a ]]
mv "$state/missing-proxy" "$package/bin/safeyolo-proxy"
"$package/install.sh" --root "$a"
configure "$a" "$occupied_port"
if instance "$a" start > "$state/occupied.stdout" 2> "$state/occupied.stderr"; then
  echo 'Occupied Admin endpoint was incorrectly accepted' >&2; exit 1
fi
tail -80 "$a/logs/proxy.log" | grep -i -E 'address already in use|address in use'
instance "$a" stop
instance "$b" status | grep '"proxy_state": "running"'
instance "$b" policy show > "$state/b-policy-after.json"
cmp "$state/b-process-before.json" "$b/data/proxy-process.json"
cmp "$state/b-policy-before.json" "$state/b-policy-after.json"

# Restore the occupied prerequisite without replacing either installation.
configure "$a" 0
instance "$a" start
instance "$a" status | grep '"proxy_state": "running"'
instance "$a" doctor | grep '"proxy_state": "running"'
instance "$a" policy show > "$state/a-policy.json"
for binary in safeyolo safeyolo-proxy safeyolo-coord; do "$a/bin/$binary" --version; done
"$a/bin/tmux" -V
"$a/bin/tmux" -S "$a/data/package-tmux.sock" new-session -d -s package-check 'sleep 60'
"$a/bin/tmux" -S "$a/data/package-tmux.sock" display-message -p -t package-check '#{session_name}' | grep '^package-check$'
"$a/bin/tmux" -S "$a/data/package-tmux.sock" kill-server
instance "$a" stop
instance "$a" status | grep '"proxy_state": "unavailable"'
instance "$b" policy show > "$state/b-policy-final.json"
cmp "$state/b-policy-before.json" "$state/b-policy-final.json"
instance "$b" stop
instance "$b" status | grep '"proxy_state": "unavailable"'
echo 'PASS native package: installation, missing input/restoration, occupied endpoint, independent live instance, status/identity/doctor and owned stop'
