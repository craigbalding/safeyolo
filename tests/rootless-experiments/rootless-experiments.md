# Rootless gVisor experiments

## Goal
Run gVisor with loopback-only networking, no real root, no sudo.

## Environment
- Ubuntu 24.04, kernel 6.8, x86_64
- runsc release-20260406.0
- AppArmor restricts unprivileged userns (workaround: aa-exec -p runsc-userns)
- /dev/kvm accessible via ACL

## Experiments

### Exp 1-2: unshare -Urn netns creation
- `aa-exec -p runsc-userns -- unshare -Urn` creates userns+netns
- lo comes up, 10.200.0.1/32 added — all without sudo
- PASS: unprivileged netns with agent IP works

### Exp 3: runsc --rootless inside unshare, sandbox networking
- Warning: "sandbox network not supported with --rootless, switching to host"
- BUT "host" = the unshare'd netns (loopback-only). Container sees 127.0.0.1 + 10.200.0.1
- PASS for isolation: no real host interfaces leak

### Exp 4: verify no host interface leakage
- Only lo visible inside gVisor. No eth0/docker0/tailscale0
- PASS: unshare provides the isolation, gVisor inherits it

### Exp 5: UDS socket via runsc do --volume
- FAIL: "unsupported file type 49152" — runsc do can't mount sockets
- Not relevant: our real path uses OCI bind-mount + --host-uds=open

### Exp 6: runsc create --rootless
- FAIL: "Rootless mode not supported with create"
- HARD BLOCKER: --rootless only works with `runsc do`, not the OCI create/start path

### Exp 7: runsc create (no --rootless) inside unshare -Urn
- FAIL: cgroup permission denied — userns doesn't own cgroup hierarchy

### Exp 8: runsc create with --ignore-cgroups
- create: PASS
- start: FAIL — "error opening /proc/<pid>/ns/net: permission denied"
- runsc's sandbox networking tries to join the creator's netns via procfs

### Exp 9: --network=host + --ignore-cgroups inside unshare -Urn
- CREATE: PASS
- START: PASS
- Container sees: 127.0.0.1/8 + 10.200.0.1/32 + HELLO_FROM_GVISOR
- Only lo visible — unshare provides isolation, --network=host inherits it
- No sudo. No --rootless flag. KVM platform.
- **THIS IS THE PATH.**

### Key flags for rootless OCI path:
- `aa-exec -p runsc-userns --` (AppArmor allow userns)
- `unshare -Urn` (user+net namespace, maps root)
- `runsc --platform=kvm --host-uds=open --ignore-cgroups --network=host`
- No --rootless flag (it blocks create)

### Exp 10: UDS proxy socket via bind-mount
- Container connected to /safeyolo/proxy.sock, sent HELLO, host received it
- --host-uds=open works in rootless path
- PASS

### Exp 11b: runsc exec
- exec as root: sees 10.200.0.1 on lo — PASS
- exec as uid 1000: runs as agent — PASS  
- kill + delete: clean — PASS

### Exp 12: Full guest-init integration
- Container went to stopped before exec could run
- Status signals written (static-init-done, per-run-started, vm-ip)
- Likely guest-init exited — needs debugging separately

### Exp 13: Simple container with CAP_NET_ADMIN inside
- Container stays running (sleep 300)
- ip addr add inside container works with CAP_NET_ADMIN
- exec, curl available — PASS

### Exp 14: NO CAP_NET_ADMIN — IP from unshare only
- IP configured in unshare'd netns BEFORE runsc create
- --network=host inherits the unshare'd (loopback-only) netns  
- Container sees 10.200.0.1/32 WITHOUT any capability grant
- No sudo, no CAP_NET_ADMIN, no CAP_SYS_ADMIN
- **THIS IS THE FULL PATH: unshare -Urn + --network=host + --ignore-cgroups**

### Summary: the rootless recipe
```
aa-exec -p runsc-userns -- \
  unshare -Urn bash -c "
    ip link set lo up
    ip addr add 10.200.0.1/32 dev lo
    runsc --platform=kvm --host-uds=open \
          --ignore-cgroups --network=host \
          --root <state> create --bundle <bundle> <cid>
    runsc --ignore-cgroups --network=host \
          --root <state> start <cid>
  "
```

### Exp 15: runsc create with delegated cgroups (no --ignore-cgroups)
- FAIL: runsc opens /sys/fs/cgroup/cgroup.subtree_control (root cgroup)
  before looking at the delegated subtree. Permission denied.

### Exp 16: --systemd-cgroup
- FAIL: expects systemd slice format path, not OCI cgroupsPath

### Exp 17: --ignore-cgroups + systemd-run for external limits
- CREATE: PASS, START: PASS, EXEC: PASS
- systemd-run --user --scope -p MemoryMax=256M -p TasksMax=4096
  enforces limits from OUTSIDE via the delegated cgroup scope
- runsc --ignore-cgroups means runsc doesn't touch cgroups at all
- systemd's scope applies memory/pids/cpu limits to the entire
  process tree (runsc + sandbox + gofer)
- Container sees 10.200.0.1/32, KVM platform, no sudo

### FINAL RECIPE — zero sudo at runtime:
```
systemd-run --user --scope \
  -p Delegate=yes \
  -p MemoryMax=256M \
  -p TasksMax=4096 \
  -- \
aa-exec -p safeyolo-runsc -- \
  unshare -Urn bash -c "
    ip link set lo up
    ip addr add 10.200.0.1/32 dev lo
    runsc --platform=kvm --host-uds=open \
          --ignore-cgroups --network=host \
          --root <state> create --bundle <bundle> <cid>
    runsc ... start <cid>
  "
```

One-time setup (requires sudo):
- Install AppArmor profile: sudo apparmor_parser -r /etc/apparmor.d/safeyolo-runsc
- Install fuse2fs: sudo apt install fuse2fs (for rootfs extraction)

Runtime sudo: ZERO.

## Second-order testing

### T1: runsc exec from outside userns
- Direct `runsc --root <state> exec` works WITHOUT nsenter
- runsc connects to sandbox via state dir, not namespace membership
- PASS — simplifies CLI integration significantly

### T2: runsc kill from outside userns
- `runsc kill` works from outside, no nsenter, no sudo
- `runsc delete` cleans up
- PASS

### T3: sandbox survives unshare exit
- Container stays `running` after unshare bash exits
- exec still works from outside
- PASS — unshare is fire-and-forget, not a persistent session

### T4: rootfs uid mapping — THE PROBLEM
- `unshare -Urn` maps container root(0) → host uid 1000
- Container uid 1000 (agent) → unmapped (nobody/65534)
- /home/agent owned by host uid 1000 → appears as root inside container
- Agent user can't access /home/agent (Permission denied)
- chown inside container fails (gofer can't chown to unmapped uid)
- Attempted newuidmap with proper multi-uid mapping: gVisor can't
  access rootfs (owned by host 1000, but container root maps to 100000)

### T4 tension:
With unshare -Urn: root works, agent(1000) is broken
With newuidmap 0→100000: agent could work but root can't access rootfs
Need BOTH root and 1000 to map to host 1000 — impossible (one-to-one mapping)

### T5: KVM platform
- `platform=kvm` confirmed in sandbox process flags
- PASS

### T6: signal delivery
- `kill -0` from host to sandbox PID works
- PASS

### T4 fix attempts 5-8: newuidmap with subordinate ranges
- Various multi-uid mapping attempts all hit secondary issues:
  - KVM access: /dev/kvm ACL is for host uid 1000, not 100000
  - State dir: owned by container root (host 100000), exec from outside fails
  - Rootfs: needs to be re-owned to match the mapping
- Conclusion: multi-uid mapping creates more problems than it solves

### T4 fix9: THE FIX — CAP_CHOWN with unshare -Urn
- Add CAP_CHOWN to OCI capability set
- guest-init does `chown -R 1000:1000 /home/agent` at boot
- gVisor sentry handles chown internally — it doesn't need the
  host uid to be mapped. CAP_CHOWN grants the container root
  permission to change ownership within gVisor's virtual kernel.
- Agent user (1000) can then read/write /home/agent normally
- chown on tmpfs: PASS
- chown on rootfs: PASS
- agent write to /home/agent: PASS
- No newuidmap, no subordinate ranges, simple -r flag

### Exp 18: proper multi-uid mapping — THE REAL FIX
- newuidmap: container 0 → host 100000, container 1000 → host 1000
- /dev/kvm: chmod 666 or setfacl for uid 100000 (one-time)
- State dir: chmod 777 (shared between userns root and host user)
- nsenter --user --target <userns-pid> required for exec/kill/delete
- KVM platform: PASS
- workspace write as uid 1000: PASS
- /home/agent write as uid 1000: PASS
- Agent runs as uid 1000, not root

### FINAL RECIPE (updated — proper uid separation):
```
systemd-run --user --scope -p Delegate=yes -p MemoryMax=X -p TasksMax=Y --
  aa-exec -p safeyolo-runsc --
    unshare -Urn bash -c "
      ip link set lo up
      ip addr add 10.200.0.1/32 dev lo
      runsc --platform=kvm --host-uds=open \
            --ignore-cgroups --network=host \
            --root <state> create --bundle <bundle> <cid>
      runsc ... start <cid>
    "
```
OCI spec includes: CAP_CHOWN (for guest-init chown /home/agent)
guest-init: chown -R 1000:1000 /home/agent at boot
One-time setup: AppArmor profile + fuse2fs
Runtime sudo: ZERO

## Workspace write investigation (post-KVM-ACL discussion)

### T19: unshare -Urn workspace permissions
- Workspace is 775 root:root inside container (host operator = container root)
- Agent (uid 1000) gets "other" permissions (r-x), CANNOT write
- chown /workspace inside sentry accepted but write still denied —
  gofer does host-level DAC check independently
- CONFIRMED: unshare -Urn blocks workspace writes for uid 1000

### T20: fuse-overlayfs squash_to_uid on workspace
- Same result — sentry DAC check denies before reaching the gofer
- FAILED

### T21: --directfs=false
- Gofer mediates all access but still enforces container-level DAC
- FAILED

### T22: OCI uidMappings (container 1000 → host 0)
- "invalid argument" — kernel rejects two container uids → same host uid
- FAILED

### Workspace write conclusion:
With unshare -Urn, container uid 1000 CANNOT write to host bind mounts.
The sentry enforces container-level DAC where workspace is root-owned.
Only the newuidmap approach (container 1000 → host operator) gives
the agent proper filesystem access to host bind mounts.

The KVM ACL question remains: granting /dev/kvm to subordinate uid
100000 relies on non-overlapping subuid allocation (tooling convention,
not kernel guarantee).

### T23: KVM fd passing via /proc/self/fd — WORKS
- Open /dev/kvm as operator (host uid 1000, has ACL) on fd 9
- nsenter --user preserves the fd
- runsc --platform_device_path=/proc/self/fd/9 opens the inherited fd
- KVM platform: PASS
- Agent uid 1000 workspace write: PASS
- No ACL on subordinate uid needed
- No udev rule needed
- **THIS IS THE FINAL PATH**

### FINAL RECIPE (v3 — fd passing, no KVM ACL):
```
exec 9</dev/kvm  # open as operator (has access)
systemd-run --user --scope -p Delegate=yes -p MemoryMax=X --
  nsenter --user --net --target <userns-pid> -- bash -c "
    runsc --platform=kvm --platform_device_path=/proc/self/fd/9 \
          --host-uds=open --ignore-cgroups --network=host \
          --root <state> create --bundle <bundle> <cid>
    runsc ... start <cid>
  "
exec 9<&-
```
One-time setup: AppArmor profile + fuse2fs
Runtime sudo: ZERO
KVM ACL changes: ZERO

## Second-order tests (continued)

### T7: resource limits
- T7a/b: MemoryMax enforced by systemd scope — 100MB alloc works
  inside 256MB scope, 300MB alloc OOMs the scope. PASS.
- T7c: TasksMax NOT enforced — gVisor virtual PIDs are invisible
  to host cgroups. --ignore-cgroups skips internal PID limits too.
- T7d/e: OCI pids.limit with cgroups — gVisor opens root cgroup,
  permission denied. Can't use delegated subtree.
- Conclusion: memory/CPU limits work via systemd scope. PID limits
  don't. Fork bombs hit the memory limit instead. Acceptable for
  coding agents.

### T8: full proxy UDS flow (rootless)
- Forwarder: /safeyolo/proxy.sock → bridge → mitmproxy
- curl http://ifconfig.co: 200
- port-identity: port=30001 → agent=udsecond ip=10.200.0.1
- PASS — complete egress chain, zero sudo

### T9: two agents simultaneously (rootless)
- agent-a: 10.200.0.1 port 30001, agent-b: 10.200.0.2 port 30002
- Both curl 200, correct attribution in mitmproxy
- No crosstalk
- PASS

