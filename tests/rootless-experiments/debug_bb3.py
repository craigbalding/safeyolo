#!/usr/bin/env python3
import sys, os, subprocess
os.environ["SAFEYOLO_CONFIG_DIR"] = os.path.expanduser("~/.safeyolo-test")
sys.path.insert(0, "cli/src")

from safeyolo.platform.linux import (
    _find_runsc, _detect_runsc_platform, _runsc_root,
    _container_id, _start_userns, _nsenter_cmd, _kill_userns,
    _wrap_in_systemd_scope, get_agents_dir,
)

name = "bbtest"
runsc = _find_runsc()
platform = _detect_runsc_platform()
root = _runsc_root()
cid = _container_id(name)
agent_dir = str(get_agents_dir() / name)
os.chmod(root, 0o777)

# Clean stale
subprocess.run([runsc, "--root", root, "delete", "--force", cid],
               capture_output=True, check=False)

upid = _start_userns(name)
print(f"userns={upid}")

inner = (
    f"ip link set lo up && "
    f"{runsc} --root {root} --host-uds=open --ignore-cgroups "
    f"--network=host --platform={platform} "
    f"create --bundle {agent_dir} {cid} 2>&1 && "
    f"{runsc} --root {root} --ignore-cgroups --network=host "
    f"start {cid} 2>&1"
)

cmd = _wrap_in_systemd_scope(
    _nsenter_cmd(upid) + ["bash", "-c", inner],
    name, 4096, 4,
)
print(f"cmd={' '.join(cmd)}")

r = subprocess.run(cmd, capture_output=True, text=True)
print(f"rc={r.returncode}")
print(f"stdout={r.stdout[:500]}")
print(f"stderr={r.stderr[:500]}")

# Check state
r2 = subprocess.run(
    _nsenter_cmd(upid) + [runsc, "--root", root, "state", cid],
    capture_output=True, text=True, check=False,
)
print(f"state_rc={r2.returncode}")
print(f"state={r2.stdout[:200]}")

_kill_userns(name)
