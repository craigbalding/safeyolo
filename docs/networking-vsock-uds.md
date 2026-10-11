# Agent networking: vsock and Unix sockets

This is the current request path for the Rust proxy. It describes the host
transport used by Linux gVisor sandboxes and macOS Virtualization.framework
microVMs. Release acceptance is recorded in
[issue #640](https://github.com/craigbalding/safeyolo/issues/640).

## Request and shell paths

Each sandbox has no direct external network interface. Agent HTTP clients use
the guest forwarder at `127.0.0.1:8080`. The host gives each agent a private
Unix domain socket (UDS) at
`~/.safeyolo/data/sockets/<ip>_<agent>/proxy.sock`. The native Rust proxy binds
that socket; it has no public TCP traffic listener.

```text
Agent HTTP client -> guest forwarder -> per-agent host UDS -> Rust proxy -> upstream
                       Linux: /safeyolo/proxy/proxy.sock through gVisor --host-uds=open
                       macOS: vsock port 1080 -> safeyolo-vm VSockProxyRelay -> host UDS
```

On Linux, gVisor mounts only that agent's socket directory into the guest and
allows the host UDS connection. On macOS, the Swift `VSockProxyRelay` connects
each guest vsock stream to that agent's host UDS. The relay transports bytes;
the Rust listener supplies the trusted agent identity.

`safeyolo agent shell <name>` uses a separate route. Linux runs the command
through `runsc exec`. On macOS, the host SSH client uses the agent's shell UDS;
`VSockShellBridge` forwards it through vsock port 2220 to the guest shell
bridge and `sshd`. The shell socket is
`~/.safeyolo/data/shell-sockets/<agent>.sock`. It is separate from the proxy
socket.

## Agent identity and listener updates

The host command-line interface (CLI) assigns each running agent an
attribution Internet Protocol (IP) address from
`10.200.0.0/16`. The CLI reserves a stable `network_slot` in the agent's
configuration. It uses the lowest free slot for a new agent and preserves a
running legacy agent's address when possible. For network slot `N`, the
address is `10.200.{(N+1) / 256}.{(N+1) % 256}`, using integer division.
Slot 0 has `10.200.0.1`. The live `~/.safeyolo/data/agent_map.json` entry is
authoritative for an agent's assigned IP and socket path. The CLI creates a
listener entry with
`agent_id`, `source_id`, and `socket_path` in the native configuration.

The Rust proxy binds each configured path with `tokio::net::UnixListener`.
On accept, it attaches the configured agent and source identity to the
connection. An HTTP header cannot choose another agent. The private mount or
vsock relay also prevents a guest from addressing a different agent's host
socket. The socket directory is a host-controlled convention for the CLI;
Rust uses the listener entry for identity. Host-local Admin application
programming interface (API) traffic uses a separate listener.

When the CLI starts or stops an agent sandbox, it updates `agent_map.json` and
reconciles its managed listener entries with the running Rust proxy.
After writing the updated native configuration, the CLI signals a running
proxy with SIGHUP. It waits up to five seconds for the matching `reload_id`
in the readiness marker. Listener synchronization fails if the proxy does not
acknowledge the update. If the proxy is unavailable, the CLI saves the
configuration for its next start. Operator-defined listener entries remain intact.
There is no `PUT /admin/proxy/mode` route or mitmproxy mode list in the current
package.
Built-in support for operator-created external ingress bindings is proposed in
[issue #580](https://github.com/craigbalding/safeyolo/issues/580).

## Diagnose a broken path

On the host, use the installed native CLI for the selected instance and named
agent. These observations remain available when the proxy or listener is absent:

```sh
safeyolo agent diagnostics syone
```

The native diagnostic reports runtime, control, coding-agent, terminal, and
proxy attachment state separately. On macOS, it also queries private helper
control and tests the shell bridge for an SSH banner. On Linux, shell readiness
uses exec control in the recorded namespaces. Inspect the failed dimension and
its next action; a missing proxy attachment does not mean that the runtime stopped.

A ready proxy attachment confirms that the host can connect to the configured
UDS. It does not verify guest egress or Agent API health. From inside the agent
guest, use the authenticated [first health check](AGENTS.md#first-health-check)
and require `"agent_api": "ok"` in the response. A generic HTTP response does
not prove API health. See [agent debugging](agent-debugging.md) for the native
failed-shell workflow.

For decision and audit events on the host, run:

```sh
safeyolo logs --lines 50
```

`safeyolo logs` reads the JSON Lines file selected by `audit_log_path` in the
native configuration. The default is `logs/audit.jsonl` under the instance root.
It is not a complete packet capture or a substitute for the diagnostic probes.
On macOS, the VM helper's guest console and relay messages are in
`~/.safeyolo/agents/<name>/serial.log`. On Linux, guest boot output is in
`~/.safeyolo/agents/<name>/status/boot.log`. Setting `SAFEYOLO_VM_DEBUG=1`
before starting the macOS helper enables its extra relay debug messages;
it does not enable tracing across every proxy stage.

| Symptom | First check |
| --- | --- |
| Agent cannot connect to the proxy | Run `safeyolo agent diagnostics <name>`; inspect proxy state and the agent's proxy attachment separately from runtime state. |
| Proxy transport passes but Agent API fails | Run the authenticated [first health check](AGENTS.md#first-health-check) inside the agent guest and require `"agent_api": "ok"`. Socket reachability or a generic HTTP response does not prove API health. |
| Agent request is attributed to the wrong identity | Compare the host `agent_map.json` entry with the native listener and the named socket. Do not rely on a guest-supplied header. |
| macOS shell hangs | Run `safeyolo agent diagnostics <name>`; inspect private control and the shell SSH-banner result before choosing recovery. |

## Platform and configuration notes

| | Linux | macOS |
| --- | --- | --- |
| Sandbox | Rootless gVisor with systrap or KVM | Apple Virtualization.framework microVM |
| Guest egress bridge | Bind-mounted UDS via `--host-uds=open` | vsock port 1080 through `VSockProxyRelay` |
| Operator shell | `runsc exec` | SSH through `VSockShellBridge` and vsock port 2220 |
| Agent identity at proxy | Configured Rust listener for the private UDS | Configured Rust listener for the private UDS |

`SAFEYOLO_CONFIG_DIR` selects a separate instance root, including its agent
map and socket directories. `SAFEYOLO_VM_HELPER` can select a macOS helper
binary for a development run. `SAFEYOLO_VM_DEBUG` controls the helper's
extra relay logging.

For the current component overview, see
[architecture](ARCHITECTURE.md#sandbox-runtime-and-networking) and
[developer architecture](DEVELOPERS.md#architecture-overview). For isolation
checks, see [security verification](security-verification.md). Relevant
sources are [native instance paths](../proxy/src/host_platform.rs),
[native listener reconciliation](../proxy/src/host_lifecycle.rs),
[Rust listener ownership](../proxy/src/lib.rs), and the
[macOS proxy relay](../vm/Sources/SafeYoloVM/VSockProxyRelay.swift).
