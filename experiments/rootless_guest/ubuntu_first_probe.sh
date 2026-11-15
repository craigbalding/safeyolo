#!/usr/bin/env bash
# Run through Sylab's existing owned native Ubuntu route as UID/GID1000.
# Supply the retained published archive and a NEW disk-backed output directory.
# Effects: inventory JSON and one temporary delegated user namespace. No tar
# extraction, backend, sudo, host preparation, policy change or guest build.
# The holder is reaped by import_namespace even if the observation fails.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: ubuntu_first_probe.sh ARCHIVE NEW_OUTPUT' >&2; exit 64; }
archive1553=$1
output1553=$2
source1553=$(cd -- "$(dirname -- "$0")" && pwd)
root1553=/home/agent/1562-b682-installed
[[ $(id -u) == 1000 && $(id -g) == 1000 && -f $archive1553 ]]
[[ $(sha256sum "$root1553/host/namespace-entry" | cut -d ' ' -f 1) == 7f812349eb1017d2122230d2daf3592fc5952efee881ffc42585d876687a97ee ]]
mkdir -m 700 -- "$output1553"
python3 "$source1553/import_guest.py" inventory --archive "$archive1553" \
    --sha256 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe \
    > "$output1553/archive-inventory.json"
python3 - "$source1553" "$root1553" > "$output1553/normal-mapping.json" <<'PY'
import json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from import_guest import import_namespace
with import_namespace(Path(sys.argv[2]), 100000, 100000) as (prefix, maps):
    result = subprocess.run(prefix + ['id'], capture_output=True, text=True, check=False, timeout=15)
    print(json.dumps({'host_uid': os.getuid(), 'host_gid': os.getgid(), 'maps': maps,
                      'command': prefix + ['id'], 'exit': result.returncode,
                      'stdout': result.stdout, 'stderr': result.stderr}, indent=2))
    if result.returncode:
        raise SystemExit(result.returncode)
PY
printf 'Retained archive-inventory.json and normal-mapping.json in %s\n' "$output1553"
