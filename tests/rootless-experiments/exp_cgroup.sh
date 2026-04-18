#!/bin/bash
# Test cgroup delegation via systemd-run --user --scope -p Delegate=yes
cat > /tmp/cgroup_test.py << 'PYEOF'
import os, pathlib

cg_raw = open("/proc/self/cgroup").read().strip()
cg_path = cg_raw.split("::")[1]
p = pathlib.Path("/sys/fs/cgroup" + cg_path)

print(f"cgroup={p}")
print(f"exists={p.exists()}")

# Check ownership
import stat
st = p.stat()
print(f"uid={st.st_uid} gid={st.st_gid}")
print(f"my_uid={os.getuid()}")

# List writable files
for f in sorted(p.iterdir()):
    try:
        if os.access(f, os.W_OK):
            print(f"  writable: {f.name}")
    except:
        pass

# Try creating a child cgroup
child = p / "safeyolo-test"
try:
    child.mkdir(exist_ok=True)
    print(f"mkdir OK: {child}")
    child.rmdir()
    print("rmdir OK")
except PermissionError as e:
    print(f"mkdir FAILED: {e}")
PYEOF

systemd-run --user --scope -p Delegate=yes -- python3 /tmp/cgroup_test.py 2>&1
