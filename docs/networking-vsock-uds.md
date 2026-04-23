# Agent networking: vsock / UDS architecture

End-to-end reference for how an agent's outbound HTTP request travels
from inside the sandbox to `mitmproxy`, and how `safeyolo agent shell`
reaches it — on both Linux and macOS.

Use this doc when debugging "connection reset", "attribution wrong",
"agent can't reach proxy" — and when extending the stack (cross-host
agent comms, team proxy, fleet PDP).

---

## TL;DR

The sandbox has **no external network interface**. All agent-initiated
traffic is routed through a per-agent socket pair to a host-side
`proxy_bridge` daemon, which stamps agent identity by prepending a
**PROXY protocol v2 header** (RFC) on every upstream TCP connection
to mitmproxy. The header carries the agent's attribution IP
(`10.200.X.Y`) and a SafeYolo-specific TLV (type `0xE0`) carrying the
agent name. A `proxy-protocol` mitmproxy addon parses the header in
the `next_layer` hook, rewrites `peername` with the attribution IP,
and strips the header bytes before the HTTP parser sees them.
`service_discovery` and all downstream addons see per-agent identity
for audit, policy, and rate limiting.

On macOS, a Swift `VSockProxyRelay` in the `safeyolo-vm` helper bridges
the guest's vsock endpoint to a host UDS; on Linux, the guest's socket
IS a bind-mounted host UDS (via gVisor `--host-uds=open`). Everything
downstream of the platform-specific bridge is identical.

Shell access uses the same shape in reverse: a `VSockShellBridge` (on
macOS) or `runsc exec` (on Linux) reaches the guest's `sshd` for
`safeyolo agent shell`.

---

## Hop-by-hop

### Outbound (agent → Internet)

```
┌──────────────────────────────────┐
│  Guest (sandbox)                 │
│                                  │
│  agent (curl, claude-code, …)    │
│       │  HTTP_PROXY=127.0.0.1:8080
│       ▼                          │
│  guest-proxy-forwarder (Python)  │
│       │  AF_UNIX or AF_VSOCK     │
└───────┼──────────────────────────┘
        │
        │ (Linux: bind-mounted UDS at /safeyolo/proxy.sock)
        │ (macOS: vsock cid=2 port=1080)
        │
┌───────▼──────────────────────────┐
│  Host                            │
│                                  │
│  safeyolo-vm (macOS only)        │
│    └── VSockProxyRelay           │
│         (vsock → per-agent UDS)  │
│       │                          │
│       ▼                          │
│  proxy_bridge (cross-platform)   │
│    └── listen: sockets/<N>.sock  │
│        bind: 127.0.0.1:<30000+N> │
│        connect: 127.0.0.1:<port> │
│       │                          │
│       ▼                          │
│  mitmproxy                       │
│    └── port-identity addon maps  │
│        port 3000N → agent name,  │
│        rewrites peername →       │
│        127.0.0.<N>               │
│    └── service_discovery maps    │
│        127.0.0.<N> → agent name  │
└──────────────────────────────────┘
```

### Shell (operator → agent)

```
safeyolo agent shell <name>
       │
       ▼
ssh -o ProxyCommand='nc -U <shell.sock>' agent@sandbox    (macOS vsock)
ssh -o ProxyCommand='runsc exec <cid>'   agent@sandbox    (Linux)
       │
       ▼ (macOS only)
VSockShellBridge  (UDS → vsock:2220)
       │
       ▼
guest-shell-bridge  (vsock:2220 → 127.0.0.1:22)
       │
       ▼
sshd (inside guest)
```

---

## Attribution

Each agent is assigned a **deterministic attribution IP** at
`agent run` time, derived from the agent's index in the sorted list:

| Agent index | Attribution IP   |
|-------------|------------------|
| 0           | `10.200.0.1`     |
| 1           | `10.200.0.2`     |
| 255         | `10.200.1.0`     |
| 511         | `10.200.2.0`     |

The IP is `10.200.{(N+1) / 256}.{(N+1) % 256}` from the `10.200.0.0/16`
range — `/16` supports ~65k agents. It's configured on the guest's
loopback (for in-sandbox visibility) and carried on every upstream
TCP connection via a PROXY protocol v2 header the bridge prepends.

Identity mechanism:

1. Bridge accepts an agent's UDS connection, reads the agent name
   from `agent_map.json` (keyed on socket path).
2. Bridge opens a fresh TCP connection to mitmproxy on an ephemeral
   local port.
3. Bridge writes a PROXY-v2 header (binary, RFC-compliant) containing
   the attribution IP + a custom TLV (type `0xE0`) carrying the agent
   name.
4. Bridge pumps bytes between the two sockets.
5. mitmproxy's `proxy_protocol` addon (loaded as the first layer via
   `next_layer`) parses the header on each flow, rewrites
   `flow.client_conn.peername` to the attribution IP, and strips the
   header bytes from the buffered events so the HTTP parser sees
   clean data.
6. `service_discovery` sees the attribution IP as the client address
   and resolves it to the agent name via `agent_map.json`.

Attribution IP + agent name are written to `agent_map.json` by the
CLI at `agent run` time so the bridge and mitmproxy agree on the
mapping. No sudo, no lo0 aliases, no per-agent listen ports — one
bridge daemon, ephemeral upstream ports, PROXY-v2 identity on each
flow.

This means:

- **Identity is enforced by the host bridge**, never trusted from the
  guest. A compromised agent cannot forge another agent's port because
  the bridge binds the outbound socket itself.
- **Structural isolation**: agent A's bridge socket (`sockets/A.sock`)
  is only bind-mounted into agent A's sandbox. Agent A literally cannot
  address agent B's socket.
- **Userspace-only**. The bridge binds to `127.0.0.1` on a userspace
  port — no elevated privileges or kernel interface configuration
  required on any platform.

---

## Per-agent sockets

```
~/.safeyolo/data/sockets/<agent>.sock      # proxy bridge listener (one per agent)
~/.safeyolo/data/shell-sockets/<agent>.sock # shell bridge listener (macOS only)
```

The proxy socket is bind-mounted into the guest at `/safeyolo/proxy.sock`
(Linux, via gVisor `--host-uds=open`) or reached via `vsock:1080` (macOS,
via `VSockProxyRelay`). In both cases the agent's in-guest forwarder
sends bytes to "its" socket, and there's no cross-agent socket visibility.

The bridge watches `~/.safeyolo/data/agent_map.json` and dynamically
adds/removes listeners as agents start/stop. No restart required when
adding an agent.

---

## Logs

Every hop emits timestamped, grep-friendly lines in a common logfmt-ish
shape:

```
<ts> [<hop>] done flow=<N> agent=<name> bytes_in=<X> bytes_out=<Y> duration_ms=<ms>
<ts> [<hop>] warn <any error context, with flow+agent>
<ts> [<hop>] accept flow=<N> agent=<name> src=… upstream=…   (DEBUG-gated)
```

| Hop                    | Log file                                           |
|------------------------|----------------------------------------------------|
| guest-proxy-forwarder  | VM console / `serial.log` on host                  |
| guest-shell-bridge     | VM console / `serial.log` on host                  |
| VSockProxyRelay (mac)  | `~/.safeyolo/agents/<name>/serial.log`             |
| VSockShellBridge (mac) | `~/.safeyolo/agents/<name>/serial.log`             |
| proxy_bridge           | `~/.safeyolo/logs/proxy-bridge.log`                |
| mitmproxy + addons     | `~/.local/state/safeyolo/safeyolo.jsonl`           |

**Cross-hop correlation.** All hops tag each flow with the agent name;
`grep 'agent=syone'` across the log files above reconstructs a single
flow's journey. `done` lines carry byte counts and durations, so the
question "where did the time / the bytes go?" has a one-grep answer.

**Debug mode.** Set `SAFEYOLO_VM_DEBUG=1` before starting `safeyolo` to
emit the `accept` lines (per-flow start events). `done` and `warn` are
always on — they carry the load-bearing diagnostic data and are low
enough volume for production (~3 lines/sec under active Claude Code
usage).

---

## Troubleshooting

### First port of call: `safeyolo agent diag <name>`

Probes every hop and reports pass/fail with actionable remediation. Run
this before grepping logs — usually tells you exactly which link is
broken:

```
$ safeyolo agent diag syone

  PASS  Agent config: /Users/…/agents/syone
  PASS  Agent map: ip=127.0.0.2 socket=/Users/…/sockets/syone.sock
  PASS  Attribution IP: 127.0.0.2 (port 30002)
  PASS  Bridge socket: /Users/…/syone.sock mode=0o600
  PASS  Bridge process: pid=35520
  PASS  Sandbox/VM: running
  PASS  End-to-end probe: mitmproxy answered (292B)
```

Exit code 0 on all-pass, 1 on any fail.

### Common symptoms

| Symptom                                   | Most likely cause                                        | Check / fix                                                   |
|-------------------------------------------|----------------------------------------------------------|---------------------------------------------------------------|
| `curl: (56) Recv failure: Connection reset by peer` inside agent | `proxy_bridge` not running | `safeyolo agent diag`                                         |
| Agent traffic shows in mitmproxy as `unknown` | Bridge didn't pick up agent's entry in `agent_map.json`, or port-identity addon not loaded | `cat ~/.safeyolo/data/agent_map.json` — entry with `port` present? Check mitmproxy log for `port-identity` |
| `safeyolo agent shell` hangs              | Shell-bridge relay not firing, or `sshd` not in guest   | `ls ~/.safeyolo/data/shell-sockets/<name>.sock`; serial.log for `listen agent=…` |
| `VM running (detached)` but dies seconds later | Helper process `proc_exit`ed silently (historically SIGPIPE, RunLoop exit) | `sudo log show --last 60s --predicate 'processID == <pid>'` — shows exit reason |
| "bind(127.0.0.1, 3000X) failed: EADDRINUSE" | Port conflict — another process is using that port | `lsof -i :3000X` to find the conflict |

### Reading logs

For a failing flow, start at the agent-map side and walk outward:

```
# All events for syone across every hop, in chronological order:
( cat ~/.safeyolo/agents/syone/serial.log \
  ~/.safeyolo/logs/proxy-bridge.log \
  ~/.local/state/safeyolo/safeyolo.jsonl
) | grep 'agent=syone\|"agent":"syone"' | sort
```

The `flow=N` id is per-process-monotonic; grep `flow=<N>` on a single
hop to see one specific connection's accept + done pair.

---

## Platform differences at a glance

|                        | Linux                          | macOS                                     |
|------------------------|--------------------------------|-------------------------------------------|
| Isolation runtime      | gVisor (`runsc`) in rootless userns | Virtualization.framework             |
| Guest sees sandbox as  | loopback-only netns            | no network interface (vsock only)         |
| Agent → bridge path    | UDS via `--host-uds=open`     | vsock (1080) → VSockProxyRelay → UDS      |
| Shell access           | `runsc exec`                  | ssh via VSockShellBridge (UDS → vsock → sshd) |
| Attribution mechanism  | PROXY protocol v2 header      | PROXY protocol v2 header                  |
| Host firewall          | none (structural)             | none (structural)                         |
| Sudo at runtime        | none                          | none                                      |

---

## Configuration knobs

| Env var                      | Default      | Effect                                            |
|------------------------------|--------------|---------------------------------------------------|
| `SAFEYOLO_CONFIG_DIR`        | `~/.safeyolo`| Instance root (isolated from prod when set)       |
| `SAFEYOLO_SUBNET_BASE`       | `65`         | Linux netns slot offset — shift to run a second instance (e.g. blackbox tests) without colliding with prod netns names |
| `SAFEYOLO_VM_HELPER`         | unset        | Override `safeyolo-vm` binary path for single runs |
| `SAFEYOLO_VM_DEBUG`          | unset (off)  | Enable per-flow `accept` logs on all hops         |

---

## See also

- `docs/microvm-architecture.md` — how the VM boots, snapshots, mounts
- `docs/SERVICE_DISCOVERY.md` — how the `service_discovery` addon maps IP→agent
- Source: `cli/src/safeyolo/proxy_bridge.py`, `addons/proxy_protocol.py`, `vm/Sources/SafeYoloVM/VSockProxyRelay.swift`, `vm/Sources/SafeYoloVM/VSockShellBridge.swift`
