#!/usr/bin/env bash
# Run the nofollow controls in an owned disposable Linux runtime on a Docker host.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/native_package.sh"
(($# == 2)) || { package_error 'Usage: qualify_runsc_nofollow.sh RUNTIME_DIRECTORY NEW_WORK_DIRECTORY'; exit 2; }
runtime=$(cd -- "$1" && pwd)
mkdir -m 0700 -- "$2"
work=$(cd -- "$2" && pwd)
mkdir "$work/reports" "$work/bundle" "$work/bundle/rootfs" "$work/home"
# The gofer uses reduced host credentials; this owned canary directory must
# permit the guest to create its controls without granting access elsewhere.
chmod 1777 "$work/home"
version=$("$runtime/runsc" --version)
[[ ${version%%$'\n'*} == 'runsc version release-20261005.0-safeyolo.1' ]] || { package_error "unexpected runtime: $version"; exit 1; }
while IFS= read -r name; do native_executable "$runtime/$name" "$(host_platform)"; done < <(runsc_files)
(cd "$runtime"; sha256sum runsc gvisor-bin/*) > "$work/reports/SHA256SUMS"
printf '%s\n' "$version" > "$work/reports/version.txt"
uname -a > "$work/reports/host.txt"

container=
created=false
id=nofollow-1352
runsc=(sudo -n "$runtime/runsc" --root="$work/state" --platform=systrap
  --network=none --ignore-cgroups=true --sidecar-usage-policy=STRICT
  --sidecar-release-enforcement-policy=ALWAYS --debug=true
  --debug-log="$work/reports/runsc.%COMMAND%.log")
cleanup() {
  local result=$?
  if $created && ! "${runsc[@]}" delete --force "$id"; then result=1; fi
  if [[ -n $container ]] && ! docker rm "$container" >/dev/null; then result=1; fi
  return "$result"
}
trap cleanup EXIT

# Export a stock Python image without executing it. Retain its immutable digest.
docker pull python:3.13-slim
docker image inspect python:3.13-slim > "$work/reports/python-image.json"
image=$(docker image inspect --format '{{.Id}}' python:3.13-slim)
container=$(docker create "$image")
docker export "$container" | tar -xf - -C "$work/bundle/rootfs"
docker rm "$container" >/dev/null
container=
mkdir -p "$work/bundle/rootfs/home/agent"
cp "$script_dir/probe_runsc_nofollow.py" "$work/bundle/rootfs/probe.py"
cp "$script_dir/probe_runsc_nofollow.py" "$work/reports/"
python3 - "$work" <<'PY'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])
config = {
    "ociVersion": "1.0.2",
    "process": {
        "terminal": False,
        "user": {"uid": 0, "gid": 0},
        "args": ["/usr/local/bin/python3", "/probe.py", "/tmp", "/home/agent"],
        "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1"],
        "cwd": "/",
    },
    "root": {"path": "rootfs", "readonly": True},
    "hostname": "nofollow-1352",
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
         "options": ["nosuid", "nodev", "mode=1777"]},
        {"destination": "/home/agent", "type": "bind", "source": str(work / "home"),
         "options": ["rbind", "rw", "nosuid", "nodev"]},
    ],
    "linux": {"namespaces": [{"type": name} for name in
                              ["pid", "ipc", "uts", "mount", "network"]]},
}
(work / "bundle/config.json").write_text(json.dumps(config, indent=2) + "\n")
(work / "reports/config.json").write_text(json.dumps(config, indent=2) + "\n")
PY
printf '%q ' "${runsc[@]}" create --bundle "$work/bundle" "$id" > "$work/reports/invocation.txt"
printf '\n' >> "$work/reports/invocation.txt"
created=true
"${runsc[@]}" create --bundle "$work/bundle" "$id" > "$work/reports/probe.json"
"${runsc[@]}" state "$id" > "$work/reports/state.json"
pid=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["pid"]))' "$work/reports/state.json")
sudo -n readlink "/proc/$pid/exe" > "$work/reports/sentry-executable.txt"
sudo -n sha256sum "/proc/$pid/exe" > "$work/reports/sentry-sha256.txt"
expected=$(file_sha256 "$runtime/gvisor-bin/gvisor_sentry")
read -r actual _ < "$work/reports/sentry-sha256.txt"
[[ $actual == "$expected" ]] || { package_error 'running sentry differs from the selected bundle'; exit 1; }
"${runsc[@]}" start "$id"
"${runsc[@]}" wait "$id" | tee "$work/reports/wait.json"
cat "$work/reports/probe.json"
python3 - "$work/reports" <<'PY'
import json
import sys
from pathlib import Path

reports = Path(sys.argv[1])
assert json.loads((reports / "wait.json").read_text())["exitStatus"] == 0
result = json.loads((reports / "probe.json").read_text())
assert result["passed"] and len(result["cases"]) == 20
assert all(case["passed"] for case in result["cases"])
PY
