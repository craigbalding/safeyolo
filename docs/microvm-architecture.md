# MicroVM Architecture

SafeYolo runs AI coding agents in persistent Linux microVMs with hardware-level isolation and structural egress control.

The microVM approach — guest image build, vsock terminal, openpty/setsid/TIOCSCTTY PTY pattern — was informed by [Shuru](https://github.com/superhq-ai/shuru/), an open-source microVM sandbox for AI agents.

## Architecture

On an Apple Silicon Mac, the guest forwarder sends proxy traffic over vsock
port 1080. The `safeyolo-vm` helper relays those bytes to the agent's host
Unix domain socket (UDS). The Rust proxy owns that listener.

```text
Agent microVM -> guest forwarder -> vsock:1080 -> VSockProxyRelay
                                                   -> per-agent host UDS
                                                   -> Rust proxy -> upstream
```

The helper also bridges the separate operator shell UDS to guest SSH over
vsock port 2220. The interactive terminal uses its own vsock
pseudo-terminal (PTY) channels.
The guest has no external network interface; its workspace and configuration
shares use VirtioFS.

## Network Isolation

The microVM has no virtio-net attachment. Its guest forwarder listens on
`127.0.0.1:8080`. Agent HTTP clients use
`HTTP_PROXY=http://127.0.0.1:8080`. The guest forwarder, the
`VSockProxyRelay` in `safeyolo-vm`, and the host UDS carry the connection to
the Rust proxy.

The host command-line interface (CLI) derives a private socket path for the
agent, writes its identity to
`agent_map.json`, and puts `agent_id`, `source_id`, and `socket_path` in the
native listener configuration. The Rust proxy binds the UDS and fixes the
configured identity when it accepts a connection. It does not use a
guest-supplied header or a mitmproxy mode to select the agent. Removing proxy
environment variables does not create another external route from the guest.

For the host and guest hops, listener reload, and diagnostics, see
[agent networking](networking-vsock-uds.md). This describes the implemented
macOS bridge; the physical Virtualization.framework (VZ) release pilot remains open under
[issue #640](https://github.com/craigbalding/safeyolo/issues/640).

## Connection admission on macOS

The shipped bridges reserve capacity before opening VZ connections:

| Path | Maximum pending or established connections | Excess connections |
| --- | --- | --- |
| Proxy | 232 proxy connections | Wait in the guest TCP listen backlog, configured to 128; clients can time out |
| Shell | 6 shell connections | The helper closes the incoming host socket and records a connection-limit error |
| Terminal | One data connection and one resize connection | A retry waits until the previous attempt completes or its connection closes |

These discrete limits allow at most 240 connections through these paths.
They reserve shell and terminal capacity even when the proxy is full. The
host control Unix socket does not open a VZ connection. Linux UDS forwarding
does not use the macOS proxy limit.

Proxy admission happens in the guest because VZ allocates a connection before
the host listener can accept or reject it. Shell and terminal admission happens
in the helper before it calls VZ. A caller timeout does not release a slot for
an unresolved VZ callback. A late successful callback closes its connection
before releasing the slot. A callback that never arrives retains its slot
until the helper exits.

The limits address ordinary workload overload through the shipped bridges.
They do not restrict guest programs that create vsock connections directly.
The connection counts also exclude framework descriptors, so native acceptance
must include the full guest and its configured shares. A framework resource
limit or allocation failure can still stop the VM.

## Terminal

The VM terminal uses vsock (virtio socket) with a proper PTY:

**Guest side (`vsock-term`)**: Listens on vsock port 1024 (data) and 1025 (resize). On host connection: `openpty()` with the host's window dimensions, `fork()`, `setsid()`, `TIOCSCTTY`, `dup2` slave to 0/1/2, drop privileges, `execvp` the agent binary directly. No shell wrapper — this preserves `process.stdout.isTTY` for Node.js TUI apps.

Before command execution, the child changes directory, sets the primary group,
loads the `agent` user's supplementary groups, and sets the user ID. If any
of these four operations fails, the child reports the operation and system
error through the PTY and exits with status 1. It does not execute the command.

`make -C vm guest-tools` builds this Linux ARM64 executable with static glibc.
Linux builds use `aarch64-linux-gnu-gcc`; macOS builds use the same compiler
inside the Debian Lima builder. The default Debian guest selects `group: files`
in `/etc/nsswitch.conf`, so `initgroups` reads the local `/etc/group` database.
The static build includes glibc's files backend. Keep the linker's `initgroups`
warning visible: a static ELF file alone does not establish compatibility with
other Name Service Switch (NSS) backends. A custom guest that selects external
NSS modules needs those modules and shared libraries from the glibc version
used to link the terminal executable. The macOS package carries this guest
executable with its source and checksum receipts; the guest init selects the
config-share copy before the rootfs fallback.

**Host side (`VSockTerminal.swift`)**: Connects to vsock after VM boots. Full `cfmakeraw` terminal mode. `write_all()` with retry to prevent split ANSI sequences. SIGWINCH → 4-byte resize message on control channel. Drains PTY output before closing.

For persistent agents (`safeyolo agent start NAME`), a configured host launcher owns the agent terminal, or an explicit supervisor owns headless harness turns. `--sandbox-only` boots without a coding agent. The separate `safeyolo agent shell` route uses SSH through `VSockShellBridge` → `vsock:2220` → `guest-shell-bridge` → sshd; see [agent launchers](agent-launchers.md).

## Config Share Architecture

The CLI stages guest boot scripts and environment on the VirtioFS configuration share:

```
~/.safeyolo/agents/<name>/config-share/
├── guest-init          # The real init script (written by CLI on every run)
├── vsock-term          # Terminal daemon (cross-compiled ARM64 binary)
├── guest-proxy-forwarder
├── guest-shell-bridge
├── proxy.env           # HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, etc.
├── agent.env           # SAFEYOLO_AGENT_CMD, MISE_PACKAGE, auto_args, etc.
├── network.env         # GUEST_IP=127.0.0.1, GATEWAY_IP=127.0.0.1
├── mitmproxy-ca-cert.pem
├── authorized_keys     # SSH public key for `agent shell`
├── agent_token         # Agent API bearer token
├── instructions.md     # CLAUDE.md or equivalent (injected to guest path)
├── host-mounts         # VirtioFS mount manifest (tag:guest_path)
├── host-files-manifest # Individual file copy manifest
├── agent-name          # Written by CLI; read by guest-init + forwarders
└── vm-status           # "installing" during first-run install
```

The rootfs has a 30-line stub at `/usr/local/bin/safeyolo-guest-init` that mounts VirtioFS and execs `/safeyolo/guest-init`.

**Iteration loop**: Change guest-init.sh → instant. Change vsock-term.c → `make install` (10s cross-compile). Change rootfs packages → full rebuild (rare).

## Trust Boundaries

The host owns the Rust proxy, per-agent UDS listeners, policy and evidence,
the Python CLI, the Swift VM helper, and the VirtioFS configuration share.
The guest and its coding agent can be compromised. The helper's relay can
reach only the host UDS selected for that VM; the Rust listener attaches
the host-configured identity. The guest has no external network interface,
so unsetting proxy variables or opening a raw socket does not create
general outbound network access.

## Guest Image

Sizes below use binary units: a mebibyte (MiB) is 1,048,576 bytes; a
gibibyte (GiB) is 1,073,741,824 bytes.

Built via a Lima VM on macOS for ARM64 cross-compilation (see `guest/README.md`):

- **Kernel**: Linux 6.12, minimal defconfig. Virtio-vsock built in; virtio-net still available for local development but not attached by the runtime.
- **Rootfs**: Debian trixie base in a sparse 2048 MiB (2 GiB) ext4 image.
  VZ mounts this shared base read-only. A separate writable overlay stores
  root filesystem changes. The base includes Git, curl, SSH client/server
  support, mise, fd, gh, guest sudo and package-manager proxy/cache support.
  Language runtimes and development tools are installed on demand.
- **Initramfs**: busybox-static + e2fsck + resize2fs. Mounts root, `switch_root` to stub init. Network configuration is a no-op — there is no eth0.

Artifacts stored at `~/.safeyolo/share/`: `Image`, `initramfs.cpio.gz`, `rootfs-base.ext4`.

## Persistence

The default macOS agent writes root filesystem changes to
`~/.safeyolo/agents/<name>/overlay.img`. The native launcher creates this
256 GiB sparse file on first start. The initramfs formats it as ext4 and
layers its writable files over the read-only base. Sparse means that the
file allocates host blocks as needed; its logical size remains a limit.
The 2 GiB base image size does not limit this writable layer.
A per-agent `rootfs.ext4`, when present, selects a custom read-only base.
It does not replace the writable overlay.

On Linux, gVisor reads the shared `~/.safeyolo/share/rootfs-tree/` directory.
The launcher selects a per-agent file-backed overlay under
`~/.safeyolo/agents/<name>/overlay/`. Linux does not use the 2 GiB ext4
image or create the macOS overlay disk. Its backing filesystem supplies
the disk space. This Linux upper belongs to the current sandbox run.
Recreating the sandbox discards its root changes; the home, workspace and
cache mounts provide persistent storage.

On both platforms, `/home/agent` and `/workspace` are separate writable
host mounts. The home lives in `~/.safeyolo/agents/<name>/home/`; the
workspace is the operator-selected project directory. mise runtimes, shell
history and agent state in the home persist across stops. Project files
remain in the workspace. These mounts use their host filesystem's capacity,
outside the macOS root overlay's ext4 limit. The mounts can share one host
filesystem with each other and with the root overlay's backing file. Their
free space is shared; do not add their reported capacities. Linux also mounts
the paths in `cache-paths.txt` from per-agent host cache directories.

With `--ephemeral`, root changes use a memory-backed overlay and disappear
on stop. The persistent home and workspace remain separate mounts.

Source: [native platform launch](../proxy/src/host_platform.rs),
[boot mounts](../proxy/src/host_boot.rs), and
[VZ initramfs](../guest/initramfs/init).

### macOS host file-table pressure

Choose a repository or worktree for `/workspace`, rather than a parent
containing unrelated projects. Explicit broader shares remain supported.
VirtioFS traversal can retain a host file handle for each visited file or
directory, even after guest commands close their files. Several VMs can retain
handles for the same host tree independently. Read-only shares also consume
host handles; read-only access limits writes, not this pressure.

Current-source macOS `agent launch` and `agent start` warn about writable
shares of the operator's home, the filesystem root, or a directory with at
least two immediate Git repositories or worktrees. A repository or worktree
root is not classified by its nested repositories. This shallow check does
not inventory the tree or detect every large share. The warning permits the
launch and recommends narrower access; it changes no mount permissions.

Repository scope reduces the files each VM can traverse. It does not bound a
large repository or the independent `/home/agent` package and tool caches.
Guest cache reclamation can release retained handles, but idle time alone is
not a reliable release condition. Stopping an unused VM releases its handles
while preserving its workspace and persistent home. No host file-table limit
or guest cache-reclamation setting is changed by this mitigation.

For `ENFILE` (`Too many open files in system`, errno 23), run this on the
macOS host:

```sh
sysctl kern.num_files kern.maxfiles kern.maxfilesperproc
```

Compare `kern.num_files` with the host-wide `kern.maxfiles` ceiling. Stop
unused agents to recover handles, and select narrower workspaces before
starting them again. Raising the host ceiling only postpones exhaustion if
the workload keeps retaining handles. Guest `EMFILE` (`Too many open files`,
errno 24) concerns a process's open-file limit; raising that guest limit does
not repair host-wide `ENFILE`. The guest limit is tracked separately in
[#379](https://github.com/craigbalding/safeyolo/issues/379).

### Check available space

In a running agent shell, check the root and the two writable host mounts
separately. On Linux, root capacity and inode counts can be synthetic. Use
the Linux host check below to find the backing filesystem's free space.

```sh
df -h / /home/agent /workspace
df -i / /home/agent /workspace
```

`/home` alone can report the root filesystem. The persistent home mount is
`/home/agent`. `df -i` reports free inodes, which the filesystem needs to
create files even when data blocks remain.

On a macOS host, replace `NAME` with the agent name. For the default
installation, compare the overlay's logical length with its allocated blocks:

```sh
ls -lh ~/.safeyolo/agents/NAME/overlay.img
du -h ~/.safeyolo/agents/NAME/overlay.img
```

`ls` reports the provisioned length. `du` reports blocks allocated to the
file. Apple File System (APFS) clones can share blocks, so adding `du`
results does not give exclusive physical space used. The host volume can
also run out of free space before the guest reaches its ext4 limit.

On a Linux host with the default installation, replace `NAME` with the
agent name and `WORKSPACE` with its host project path. Check the filesystems
that hold the writable upper, persistent home and workspace:

```sh
df -h ~/.safeyolo/agents/NAME/overlay ~/.safeyolo/agents/NAME/home "WORKSPACE"
```

These host results show backing filesystem capacity and free space. Linux
guest root `df` can report synthetic capacity. It does not establish a disk
limit or the host's available space. Directory `du` alone can also miss
gVisor's open, unlinked backing file, as the Linux measurement below shows.

### Measured macOS footprint

On 20 October 2026, an owned Apple Silicon VZ guest used the qualified
`guest-2026-10-17.39055525961001` image and host package source
`acdd7b4bdb19f72a84dfbf0f2ca434950650cadb`. The guest image source was
`51e2e3da38517edaf48a95d3f04f952681699345`. The storage construction and
mounts were checked against source at
`a8e04e461705efe31f7c8aeac761a5798f9577f7`.
These are observations from one workload, not reservations or quotas.

The offline workload selected prepared Node 22.23.2 and Python 3.12.12 with
mise. It installed Make 4.4.1 and copied the SafeYolo source at `87382b0a`.
It installed pytest 8.4.2 and httpx 0.28.1 in a project virtual environment,
installed TypeScript 5.9.3, then compiled and ran a small TypeScript program.
Runtime files came from prepared archives; Node's executable aliases were
restored after copying. The project copy omitted two editor skill aliases.
This measured installed tools and project files, rather than live downloads
or a complete Rust build.

| Host storage | Fresh boot | After workload | Highest recorded allocation |
| --- | ---: | ---: | ---: |
| Shared 2 GiB base image | 403.75 MiB | 403.75 MiB | 403.75 MiB |
| Per-agent 256 GiB overlay image | 6.93 MiB | 10.25 MiB | 10.27 MiB, after stop |
| Persistent home | 16 KiB | 295.93 MiB | 301.43 MiB |
| Project, including virtual environment and TypeScript | Absent | 91.70 MiB | 91.70 MiB |

The staged offline inputs used another 99.13 MiB in the workspace and
remained unchanged. They are separate from the project figures. The root
filesystem reported 250.92 GiB capacity and 238.11 GiB available at fresh
boot. ext4 metadata and reserved blocks account for space that is not
available to the ordinary guest user. Root `df` describes the writable
layer; it does not include the read-only base's contents in its used count.
`/home/agent` and `/workspace` both reported the 926.35 GiB host volume,
with 25.06 GiB available at the start. They did not report root capacity.

The observer recorded 26 samples, with a 0.5-second pause plus probe time
between samples, and snapshots before, after and after stop. The highest
recorded values can miss a shorter transient peak.

### Measured Linux footprint

On 20 October 2026, an owned AMD64 Linux VM ran production CLI and proxy
source `c5ce76019b6c997e282ab05cea0212b492e945d2`, gVisor
`release-20261005.0` and guest `guest-2026-10-16.1082`. Its storage launch
and mount code is unchanged at source
`a8e04e461705efe31f7c8aeac761a5798f9577f7`. The figures below describe
the installed packages named here.

The same prepared Node, Python, Make, pytest, httpx and TypeScript workload
completed with exit status 0. It used the same project source and offline
setup described for macOS. The observer recorded 36 live samples, with a
0.5-second pause plus probe time between samples, and before, after and
stopped snapshots. These observations can miss shorter transient peaks.

| Host storage | Fresh boot | After workload | Highest recorded allocation |
| --- | ---: | ---: | ---: |
| Shared rootfs tree | 378.59 MiB | 378.59 MiB | 378.59 MiB |
| Persistent home | 16 KiB | 313.50 MiB | 331.10 MiB |
| Workspace, including offline inputs and project | 100.46 MiB | 194.00 MiB | 194.00 MiB |

The workspace included 100.46 MiB of unchanged offline inputs and a
93.53 MiB project after the workload. The project is already in the
workspace total. Per-agent host cache directories stayed at 28 KiB.
`/home/agent` and `/workspace` reported the same 18.33 GiB backing volume,
with 8.56 GiB available before the workload and 8.16 GiB after it. These
figures describe one shared volume, not two independent disks.

Guest root `df` reported a synthetic 9,223,372,036,854,771,712-byte
capacity. Its used count rose from 3,821,568 to 4,718,592 bytes. The
normal-user observer missed the live backing file during the full workload;
an empty overlay directory did not prove zero allocation.

A separate root-only observation restarted the same stopped instance and
installed cached Make. It did not repeat the full toolchain workload. The
observer verified the owned runtime's process identity and read its open,
unlinked filestore descriptor. The file had a 1,073,741,824-byte logical
length at both observations. Allocated blocks occupied 3,821,568 bytes
(3.64 MiB) fresh and 4,718,592 bytes (4.50 MiB) after Make. That logical
length alone does not establish a fixed disk limit. No Linux volume was
filled to test exhaustion.

Both platform workloads and the separate probes completed owned-runtime
cleanup. The Linux measurement VM was shut down. The observations and their
limits are recorded in [issue #355](https://github.com/craigbalding/safeyolo/issues/355).

### When storage fills

The macOS root overlay has a finite ext4 capacity even though its backing
file is sparse. Root package files and other writes outside host mounts
consume that capacity. Home, project and Linux cache writes consume space
on their respective host filesystems. The Linux file-backed upper also
needs space on its backing filesystem. A full filesystem or exhausted inodes
can prevent new files and package installation. `/tmp` and an ephemeral
root upper use memory-backed storage. Check the affected mount before
removing unneeded files, and check host free space for a file-backed upper.

A separate VZ guest with a deliberately smaller 128 MiB test overlay
demonstrated root exhaustion without filling the host volume. A bounded
write stopped after 105,852,928 bytes with `No space left on device` and
exit status 1. Root `df` reported zero available bytes. Removing the test
file allowed a new write. The default 256 GiB overlay was not filled;
Linux exhaustion, host-volume exhaustion and memory-overlay exhaustion
were not induced. The failure and recovery observation applies to the
small macOS test overlay.

## Agent map and native listeners

The CLI writes the host-controlled `~/.safeyolo/data/agent_map.json` before
starting a VM. A running agent entry identifies its attribution IP and
private socket, for example
`~/.safeyolo/data/sockets/10.200.0.1_test/proxy.sock`. The CLI derives the
managed native listener from this map. When an agent starts or stops, the CLI
reconciles its managed listeners, sends SIGHUP to the Rust proxy, and waits
for the matching readiness reload marker. Operator-defined listeners remain
intact. The current package has no `PUT /admin/proxy/mode` route.

## Components

| Component | Language | Purpose |
| --- | --- | --- |
| `safeyolo-vm` | Swift | VM lifecycle, proxy and shell vsock relays |
| `vsock-term` | C | Guest terminal daemon and PTY bridge |
| `guest-proxy-forwarder` | Shell and socat | Guest loopback proxy port to vsock:1080 |
| `guest-shell-bridge` | Shell and socat | vsock:2220 to guest `sshd` |
| `proxy/src/lib.rs` | Rust | Per-agent UDS listeners and fixed accept identity |
| `rust_proxy.py` | Python | Native process launch, listener reconciliation, reload acknowledgement |
| `sockets.py` | Python | Private socket paths under `<ip>_<agent>/proxy.sock` |
| `vm.py` | Python | VM lifecycle and configuration share |
| `guest-init.sh` | Shell | Guest init staged on the configuration share |

## Limitations

1. **macOS only** (Apple Silicon) for the microVM path. Linux runs gVisor containers via `runsc`; see `docs/linux-port-design.md`.
2. **No general raw TCP/UDP egress path.** There is no external interface for those connections; the proxy forwarder and operator shell use their explicit bridges.
3. **No guest snapshots by default.** The native start command has no snapshot flag. Corrupted rootfs → re-create agent.
4. **Guest image build requires Lima on macOS** (for cross-compilation). Runtime itself has no Lima dependency.
