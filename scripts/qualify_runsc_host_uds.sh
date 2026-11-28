#!/usr/bin/env bash
# Qualify --host-uds-paths in an owned disposable runtime: a sandboxed process
# reaches a host Unix socket under the listed path and no other host socket.
# The host listeners record what they receive, so a refusal is observed on the
# host as well as in the guest.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/native_package.sh"
(($# == 2)) || { package_error 'Usage: qualify_runsc_host_uds.sh RUNTIME_DIRECTORY NEW_WORK_DIRECTORY'; exit 2; }
runtime=$(cd -- "$1" && pwd)
mkdir -m 0700 -- "$2"
work=$(cd -- "$2" && pwd)
mkdir "$work/reports" "$work/bundle" "$work/bundle/rootfs" "$work/workspace" "$work/proxy"
# The gofer connects with reduced host credentials.
chmod 0755 "$work" "$work/workspace" "$work/proxy"
verify_runsc_payload "$runtime" "$(host_platform)"
(cd "$runtime"; sha256sum runsc gvisor-bin/*) > "$work/reports/SHA256SUMS"
version=$("$runtime/runsc" --version)
[[ ${version%%$'\n'*} == 'runsc version release-20261005.0-safeyolo.2' ]] || { package_error "unexpected runtime: $version"; exit 1; }
printf '%s\n' "$version" > "$work/reports/version.txt"
privileged=()
(($(id -u) == 0)) || privileged=(sudo -n)

listeners=()
active=
cleanup() {
  local result=$? listener
  if [[ -n $active ]]; then "${privileged[@]}" "$runtime/runsc" --root="$work/state" delete --force "$active" || result=1; fi
  for listener in "${listeners[@]}"; do kill "$listener" 2>/dev/null || true; done
  for listener in "${listeners[@]}"; do wait "$listener" 2>/dev/null || true; done
  return "$result"
}
trap cleanup EXIT
for name in workspace proxy; do
  python3 - "$work/$name/host.sock" "$work/reports/$name-listener.log" <<'PY' &
import os
import socket
import sys

path, log = sys.argv[1], sys.argv[2]
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
os.chmod(path, 0o666)
listener.listen(8)
open(log, "w").write("listening\n")
while True:
    connection, _ = listener.accept()
    with open(log, "a") as record:
        record.write("received:" + connection.recv(100).decode(errors="replace") + "\n")
    connection.sendall(b"host-reply")
    connection.close()
PY
  listeners+=($!)
done
listener_deadline=$((SECONDS + 10))
until [[ -f $work/reports/workspace-listener.log && -f $work/reports/proxy-listener.log ]]; do
  (( SECONDS < listener_deadline )) || { package_error 'host socket listeners did not become ready'; exit 1; }
  for listener in "${listeners[@]}"; do
    kill -0 "$listener" 2>/dev/null || { package_error 'host socket listener exited before readiness'; exit 1; }
  done
  sleep 0.1
done

cat > "$work/workspace/probe.py" <<'PY'
import json
import socket
import sys

results = {}
for name, path in (("workspace", "/workspace/host.sock"), ("proxy", "/safeyolo/proxy/host.sock")):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    try:
        client.connect(path)
        client.sendall(("canary-" + sys.argv[1] + "-" + name).encode())
        results[name] = "connected" if client.recv(100) == b"host-reply" else "no-reply"
    except OSError as error:
        results[name] = "refused:" + str(error.errno)
print(json.dumps(results))
PY

python3 - "$work" <<'PY'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])
read_only = lambda path: {"destination": path, "type": "bind", "source": path, "options": ["rbind", "ro"]}
for case in ("restricted", "unrestricted"):
    config = {
        "ociVersion": "1.0.2",
        "process": {"terminal": False, "user": {"uid": 0, "gid": 0}, "cwd": "/",
                    "args": ["/usr/bin/python3", "/workspace/probe.py", case],
                    "env": ["PATH=/usr/bin:/bin"]},
        "root": {"path": "rootfs", "readonly": False},
        "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                   *[read_only(path) for path in ("/usr", "/lib", "/lib64", "/bin", "/etc") if Path(path).exists()],
                   # The same options SafeYolo uses for the workspace and proxy binds.
                   {"destination": "/workspace", "type": "bind", "source": str(work / "workspace"),
                    "options": ["rbind", "rw", "nosuid", "nodev", "dcache=0"]},
                   {"destination": "/safeyolo/proxy", "type": "bind", "source": str(work / "proxy"),
                    "options": ["rbind", "ro", "nosuid", "nodev"]}],
        "linux": {"namespaces": [{"type": name} for name in ["pid", "ipc", "uts", "mount", "network"]]},
    }
    (work / f"bundle/{case}.json").write_text(json.dumps(config, indent=2) + "\n")
PY

run_case() {
  local case=$1 pid actual expected; shift
  cp "$work/bundle/$case.json" "$work/bundle/config.json"
  local runsc=("${privileged[@]}" "$runtime/runsc" --root="$work/state" --platform=systrap --network=sandbox
    --ignore-cgroups=true --host-uds=open --sidecar-usage-policy=STRICT
    --sidecar-release-enforcement-policy=ALWAYS "$@")
  active="host-uds-$case"
  "${runsc[@]}" create --bundle "$work/bundle" "$active" > "$work/reports/$case.json"
  "${runsc[@]}" state "$active" > "$work/reports/$case-state.json"
  pid=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["pid"]))' "$work/reports/$case-state.json")
  "${privileged[@]}" sha256sum "/proc/$pid/exe" > "$work/reports/$case-sentry-sha256.txt"
  expected=$(file_sha256 "$runtime/gvisor-bin/gvisor_sentry")
  read -r actual _ < "$work/reports/$case-sentry-sha256.txt"
  [[ $actual == "$expected" ]] || { package_error 'running sentry differs from the selected bundle'; exit 1; }
  "${runsc[@]}" start "$active"
  "${runsc[@]}" wait "$active" > "$work/reports/$case-wait.json"
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["exitStatus"] == 0' "$work/reports/$case-wait.json"
  "${runsc[@]}" delete "$active"
  active=
  cat "$work/reports/$case.json"
}
run_case restricted --host-uds-paths=/safeyolo/proxy
run_case unrestricted

python3 - "$work/reports" <<'PY'
import json
import sys
from pathlib import Path

reports = Path(sys.argv[1])
restricted = json.loads((reports / "restricted.json").read_text().splitlines()[-1])
unrestricted = json.loads((reports / "unrestricted.json").read_text().splitlines()[-1])
workspace = (reports / "workspace-listener.log").read_text()
proxy = (reports / "proxy-listener.log").read_text()
# The listed path stays reachable; the workspace socket is refused and the
# host listener confirms that no restricted-case bytes arrived.
assert restricted["proxy"] == "connected", restricted
assert restricted["workspace"].startswith("refused:"), restricted
assert "canary-restricted-proxy" in proxy and "canary-restricted-workspace" not in workspace
# Control: without the list, the same probe reaches both, so a refusal above
# is the flag's effect and not a broken fixture.
assert unrestricted == {"workspace": "connected", "proxy": "connected"}, unrestricted
assert "canary-unrestricted-workspace" in workspace
print("host-uds-paths qualified:", restricted)
PY
