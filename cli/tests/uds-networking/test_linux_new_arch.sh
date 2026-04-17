#!/bin/bash
# test_linux_new_arch.sh — full new-architecture end-to-end on Linux.
#
# Verifies:
#   1. Loopback-only netns (no veth, no IP, no firewall)
#   2. proxy_bridge daemon running on host with UDS
#   3. mitmproxy listening on host:8080
#   4. gVisor container with --host-uds=open + UDS bind-mounted at /safeyolo/proxy.sock
#   5. guest-proxy-forwarder inside container listening on 127.0.0.1:8080
#   6. Full HTTP CONNECT path: container curl -> forwarder -> UDS -> bridge -> mitmproxy -> internet
#   7. No external TCP/UDP/ICMP reachable from container
#
# Requires: runsc, fuse-overlayfs, mitmdump, python3, base rootfs extracted.
# Usage: sudo bash test_linux_new_arch.sh

set -u

OPERATOR="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
OPERATOR_UID=$(id -u "$OPERATOR")
OPERATOR_GID=$(id -g "$OPERATOR")
HOME_DIR=$(eval echo "~$OPERATOR")
SHARE_DIR="$HOME_DIR/.safeyolo/share"
BASE_DIR="$SHARE_DIR/rootfs-base"
WORK_DIR="$HOME_DIR/.safeyolo/agents/arch-test"
RUNSC_ROOT="/run/safeyolo"
CID="safeyolo-arch-test"
NETNS="safeyolo-arch-test"
DATA_DIR="$HOME_DIR/.safeyolo/data"
SOCK="$DATA_DIR/proxy.sock"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_BRIDGE_PY="$SCRIPT_DIR/proxy_bridge.py"
GUEST_FORWARDER_PY="$SCRIPT_DIR/guest-proxy-forwarder.py"
PROXY_PORT=18182

PASS=0
FAIL=0
RESULTS=()
pass() { PASS=$((PASS+1)); RESULTS+=("PASS: $1"); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL: $1"); echo "  FAIL: $1"; }

cleanup() {
    echo ""
    echo "=== CLEANUP ==="
    runsc --root "$RUNSC_ROOT" kill "$CID" SIGKILL 2>/dev/null
    sleep 0.5
    runsc --root "$RUNSC_ROOT" delete --force "$CID" 2>/dev/null
    su -s /bin/bash "$OPERATOR" -c "fusermount3 -u $WORK_DIR/rootfs 2>/dev/null"
    ip netns del "$NETNS" 2>/dev/null
    kill $(cat /tmp/test-bridge.pid 2>/dev/null) 2>/dev/null
    kill $(cat /tmp/test-mitm.pid 2>/dev/null) 2>/dev/null
    rm -f /tmp/test-bridge.pid /tmp/test-mitm.pid "$SOCK"
    echo "  done"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
if [ ! -d "$BASE_DIR" ]; then echo "ERROR: no base rootfs"; exit 2; fi
# mitmdump is typically installed via pipx, i.e., in the operator's ~/.local/bin
MITMDUMP="$(sudo -u "$OPERATOR" bash -lc 'command -v mitmdump')"
if [ -z "$MITMDUMP" ] || [ ! -x "$MITMDUMP" ]; then
    # Fallback to well-known pipx location
    if [ -x "$HOME_DIR/.local/bin/mitmdump" ]; then
        MITMDUMP="$HOME_DIR/.local/bin/mitmdump"
    else
        echo "ERROR: mitmdump not installed (install with: pipx install mitmproxy)"
        exit 2
    fi
fi

PLATFORM="systrap"
[ -r /dev/kvm ] && [ -w /dev/kvm ] && PLATFORM="kvm"

echo "=== SETUP ==="

# Start mitmproxy on 127.0.0.1:$PROXY_PORT (as operator, not root)
mkdir -p "$DATA_DIR"
chown "$OPERATOR_UID:$OPERATOR_GID" "$DATA_DIR"
su -s /bin/bash "$OPERATOR" -c "$MITMDUMP -q --listen-host 127.0.0.1 -p $PROXY_PORT > /tmp/test-mitm.log 2>&1 & echo \$! > /tmp/test-mitm.pid"
sleep 1.5
if ! kill -0 $(cat /tmp/test-mitm.pid) 2>/dev/null; then
    fail "mitmdump failed to start"
    cat /tmp/test-mitm.log
    exit 1
fi
pass "mitmdump running on 127.0.0.1:$PROXY_PORT"

# Start proxy_bridge daemon (as operator)
su -s /bin/bash "$OPERATOR" -c "python3 $PROXY_BRIDGE_PY $SOCK 127.0.0.1:$PROXY_PORT > /tmp/test-bridge.log 2>&1 & echo \$! > /tmp/test-bridge.pid"
sleep 0.5
if ! [ -S "$SOCK" ]; then
    fail "proxy_bridge did not create UDS at $SOCK"
    cat /tmp/test-bridge.log
    exit 1
fi
pass "proxy_bridge running with UDS at $SOCK"

# Loopback-only netns
ip netns del "$NETNS" 2>/dev/null
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up
pass "loopback-only netns created ($NETNS)"

# Rootfs prep (fuse-overlayfs)
su -s /bin/bash "$OPERATOR" -c "fusermount3 -u $WORK_DIR/rootfs 2>/dev/null"
su -s /bin/bash "$OPERATOR" -c "rm -rf $WORK_DIR; mkdir -p $WORK_DIR/{rootfs-upper/safeyolo-test,rootfs-work,rootfs,config-share}"
cp "$GUEST_FORWARDER_PY" "$WORK_DIR/rootfs-upper/safeyolo-test/guest-proxy-forwarder.py"
chown "$OPERATOR_UID:$OPERATOR_GID" "$WORK_DIR/rootfs-upper/safeyolo-test/guest-proxy-forwarder.py"
chmod +x "$WORK_DIR/rootfs-upper/safeyolo-test/guest-proxy-forwarder.py"

# Also place a test script for the container to run
cat > "$WORK_DIR/rootfs-upper/safeyolo-test/run_tests.py" << 'PYEOF'
import os, socket, sys, subprocess, time

results = []
def test(name, ok, msg=""):
    status = "PASS" if ok else "FAIL"
    results.append((status, name, msg))
    print(f"  {status}: {name} {msg}", flush=True)

# 1. UDS should be visible via bind mount
test("UDS bind-mounted", os.path.exists("/safeyolo/proxy.sock"))

# 2. No eth0 (loopback only)
try:
    r = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=5)
    has_eth = "eth0" in r.stdout
    test("no eth0 interface", not has_eth, f"(ip addr: {r.stdout.strip()[:100]})" if has_eth else "")
except Exception as e:
    test("no eth0 interface", False, f"error: {e}")

# 3. Start guest-proxy-forwarder in background
fwd = subprocess.Popen(
    [sys.executable, "/safeyolo-test/guest-proxy-forwarder.py"],
    stderr=open("/tmp/fwd.log", "w"), stdout=subprocess.DEVNULL,
)
time.sleep(0.8)
if fwd.poll() is not None:
    with open("/tmp/fwd.log") as f:
        log = f.read()
    test("forwarder started", False, f"exited rc={fwd.returncode}: {log[:300]}")
    print("FORWARDER_DIED", flush=True)
    sys.exit(1)
test("forwarder started", True)

# 4. HTTP CONNECT via proxy -> mitmproxy -> internet
os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"
import urllib.request
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = urllib.request.urlopen("https://httpbin.org/ip", timeout=15, context=ctx)
    body = r.read().decode()
    test("HTTPS via full chain", r.status == 200 and "origin" in body,
         f"status={r.status} body={body[:80]}")
except Exception as e:
    test("HTTPS via full chain", False, f"error: {type(e).__name__}: {e}")

# 5. Direct external access should be blocked
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("1.1.1.1", 443))
    test("direct external TCP blocked", False, "connected (bad!)")
    s.close()
except (OSError, socket.timeout) as e:
    test("direct external TCP blocked", True, f"({type(e).__name__})")

# 6. Clean up forwarder
fwd.terminate()
fwd.wait(timeout=2)

# Exit code reflects results
if any(r[0] == "FAIL" for r in results):
    sys.exit(1)
PYEOF
chown "$OPERATOR_UID:$OPERATOR_GID" "$WORK_DIR/rootfs-upper/safeyolo-test/run_tests.py"

# fuse-overlayfs
if [ "$(stat -c %u "$BASE_DIR/bin/bash")" = "0" ]; then
    chown -R "${OPERATOR_UID}:${OPERATOR_GID}" "$BASE_DIR"
fi
su -s /bin/bash "$OPERATOR" -c "
    fuse-overlayfs \
        -o lowerdir=$BASE_DIR,upperdir=$WORK_DIR/rootfs-upper,workdir=$WORK_DIR/rootfs-work,allow_other,squash_to_uid=$OPERATOR_UID,squash_to_gid=$OPERATOR_GID \
        $WORK_DIR/rootfs
"
if ! mountpoint -q "$WORK_DIR/rootfs"; then
    fail "fuse-overlayfs mount failed"
    exit 1
fi
pass "fuse-overlayfs rootfs mounted"

# OCI config with --host-uds=open via runsc flag + bind-mounted proxy.sock
cat > "$WORK_DIR/config.json" << OCIJSON
{
  "ociVersion": "1.0.0",
  "root": {"path": "$WORK_DIR/rootfs", "readonly": false},
  "hostname": "arch-test",
  "process": {
    "terminal": false, "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sleep", "600"],
    "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "TERM=dumb"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "effective": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "permitted": ["CAP_CHOWN","CAP_DAC_OVERRIDE"],
      "ambient": ["CAP_CHOWN","CAP_DAC_OVERRIDE"]
    },
    "noNewPrivileges": false
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","nodev","mode=1777"]},
    {"destination": "/safeyolo", "type": "bind", "source": "$WORK_DIR/config-share", "options": ["rbind","rw"]},
    {"destination": "/safeyolo/proxy.sock", "type": "bind", "source": "$SOCK", "options": ["bind","rw"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
      {"type": "network", "path": "/var/run/netns/$NETNS"}
    ],
    "resources": {"memory": {"limit": 268435456}, "pids": {"limit": 256}}
  }
}
OCIJSON

# Ensure the mount destination exists in the overlay so runsc can attach.
# /safeyolo is created by the rbind mount above; /safeyolo/proxy.sock
# needs a placeholder file. Create it on the host side via the merged view.
su -s /bin/bash "$OPERATOR" -c "touch $WORK_DIR/config-share/proxy.sock"

# Create and start container with --host-uds=open. `runsc create` forks
# daemons (runsc-sandbox, runsc-gofer) that inherit stdout/stderr; if we
# don't fully detach from those pipes, the shell command blocks forever
# waiting for EOF. Redirect to /dev/null and log.
mkdir -p "$RUNSC_ROOT"
runsc --root "$RUNSC_ROOT" --host-uds=open --platform="$PLATFORM" \
    create --bundle "$WORK_DIR" "$CID" </dev/null >/tmp/test-runsc-create.log 2>&1
CREATE_RC=$?
if [ "$CREATE_RC" -ne 0 ]; then
    fail "runsc create failed (rc=$CREATE_RC)"
    cat /tmp/test-runsc-create.log
    exit 1
fi
runsc --root "$RUNSC_ROOT" start "$CID" </dev/null >/tmp/test-runsc-start.log 2>&1
START_RC=$?
if [ "$START_RC" -ne 0 ]; then
    fail "runsc start failed (rc=$START_RC)"
    cat /tmp/test-runsc-start.log
    exit 1
fi
pass "container started (network=loopback-only netns, --host-uds=open)"

echo ""
echo "=== IN-CONTAINER TESTS ==="
runsc --root "$RUNSC_ROOT" exec --user 0:0 --cwd / "$CID" \
    /usr/bin/python3 /safeyolo-test/run_tests.py 2>&1 | sed 's/^/  /'
IN_CONTAINER_RC=$?
if [ "$IN_CONTAINER_RC" -eq 0 ]; then
    pass "in-container test suite passed"
else
    fail "in-container tests failed (rc=$IN_CONTAINER_RC)"
fi

echo ""
echo "=== RESULTS ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
echo ""
echo "ALL ARCHITECTURE TESTS PASSED"
